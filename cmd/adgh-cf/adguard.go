package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Rewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type adGuardClient struct {
	config Config
	client *http.Client
}

func loadAdGuardCredentials(path string, lookup func(string) (string, bool)) (string, string, error) {
	v, err := loadEnvValues(path, lookup)
	if err != nil {
		return "", "", err
	}
	user, password, file := v["ADGH_USERNAME"], v["ADGH_PASSWORD"], v["ADGH_PASSWORD_FILE"]
	if password != "" && file != "" {
		return "", "", fmt.Errorf("set ADGH_PASSWORD or ADGH_PASSWORD_FILE, not both")
	}
	if file != "" {
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		f, err := os.Open(file)
		if err != nil {
			return "", "", fmt.Errorf("open ADGH_PASSWORD_FILE: %w", err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(data) > 4096 {
			return "", "", fmt.Errorf("ADGH_PASSWORD_FILE unreadable or exceeds 4096 bytes")
		}
		password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	if strings.ContainsAny(user, ":\r\n") || strings.ContainsAny(password, "\r\n") {
		return "", "", fmt.Errorf("invalid AdGuard Home authentication characters")
	}
	return user, password, nil
}

func validateDNSEndpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.Is4() || portErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("adguardHomeDns must be IPv4:port")
	}
	return nil
}

func newAdGuardClient(c Config) (*adGuardClient, error) {
	if c.AdGuardHomeURL == "" || c.adghUsername == "" || c.adghPassword == "" {
		return nil, fmt.Errorf("run requires adguardHomeUrl, adguardHomeDns and ADGH_USERNAME/ADGH_PASSWORD (or ADGH_PASSWORD_FILE)")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	}
	return &adGuardClient{c, &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("AdGuard Home redirect rejected") }}}, nil
}

func (a *adGuardClient) request(ctx context.Context, method, path string, body any, result any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.config.AdGuardHomeURL, "/")+"/control/"+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("invalid AdGuard Home request")
	}
	req.SetBasicAuth(a.config.adghUsername, a.config.adghPassword)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("AdGuard Home %s %s failed: %s", method, path, transportError(ctx, err))
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("AdGuard Home %s %s HTTP %d", method, path, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return fmt.Errorf("AdGuard Home response unreadable or exceeds 1 MiB")
	}
	if result != nil && json.Unmarshal(data, result) != nil {
		return fmt.Errorf("AdGuard Home %s returned invalid JSON", path)
	}
	return nil
}

func (a *adGuardClient) current(ctx context.Context) (Rewrite, error) {
	var list []Rewrite
	if err := a.request(ctx, "GET", "rewrite/list", nil, &list); err != nil {
		return Rewrite{}, err
	}
	return findRewrite(list, a.config.Domain)
}

func findRewrite(list []Rewrite, domain string) (Rewrite, error) {
	var matches []Rewrite
	for _, rule := range list {
		if strings.EqualFold(strings.TrimSuffix(rule.Domain, "."), domain) {
			matches = append(matches, rule)
		}
	}
	if len(matches) != 1 {
		return Rewrite{}, fmt.Errorf("expected exactly one existing rewrite for %s; found %d; create or resolve it manually", domain, len(matches))
	}
	r := matches[0]
	if !publicIPv4(r.Answer) || (r.Enabled != nil && !*r.Enabled) {
		return Rewrite{}, fmt.Errorf("target rewrite must be an enabled public IPv4 rule")
	}
	return r, nil
}

func sameRewrite(a, b Rewrite) bool {
	enabled := func(r Rewrite) bool { return r.Enabled == nil || *r.Enabled }
	return a.Domain == b.Domain && a.Answer == b.Answer && enabled(a) == enabled(b)
}

func sameDomain(a, b string) bool { return strings.EqualFold(strings.TrimSuffix(a, "."), b) }

func (a *adGuardClient) update(ctx context.Context, old, next Rewrite) error {
	// Do not include enabled in the update: preserve the user's setting.
	return a.request(ctx, "PUT", "rewrite/update", map[string]any{"target": Rewrite{Domain: old.Domain, Answer: old.Answer}, "update": Rewrite{Domain: next.Domain, Answer: next.Answer}}, nil)
}

func resolveAdGuard(ctx context.Context, c Config) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		// Returning a TCP connection makes the Go resolver use DNS-over-TCP framing.
		return (&net.Dialer{}).DialContext(ctx, "tcp4", c.AdGuardHomeDNS)
	}}
	ips, err := resolver.LookupIP(ctx, "ip4", c.Domain)
	if err != nil {
		return nil, fmt.Errorf("AdGuard Home DNS lookup: %s", transportError(ctx, err))
	}
	result := []string{}
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return unique(result), nil
}

func verifyTarget(ctx context.Context, c Config, ip string) error {
	ips, err := resolveAdGuard(ctx, c)
	if err != nil {
		return err
	}
	if len(ips) != 1 || ips[0] != ip {
		return fmt.Errorf("AdGuard Home DNS did not return exclusively expected IPv4 %s", ip)
	}
	s := probeHTTPS(ctx, ips[0], c, nil)
	if !s.Usable {
		return fmt.Errorf("DNS-selected target failed health verification: %s", s.Classification)
	}
	return nil
}
