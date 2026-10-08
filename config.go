package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	candidateProxy        *url.URL
	adghUsername          string
	adghPassword          string
	AdGuardHomeURL        string   `json:"adguardHomeUrl,omitempty"`
	AdGuardHomeDNS        string   `json:"adguardHomeDns,omitempty"`
	StateFile             string   `json:"stateFile"`
	ConfirmRuns           int      `json:"confirmRuns"`
	CooldownMinutes       int      `json:"cooldownMinutes"`
	MinImprovement        float64  `json:"minImprovement"`
	MaxTTFBMs             int      `json:"maxTtfbMs"`
	Domain                string   `json:"domain"`
	HealthPath            string   `json:"healthPath"`
	HealthMode            string   `json:"healthMode"`
	ExpectedStatusCodes   []int    `json:"expectedStatusCodes,omitempty"`
	ExpectedBodyContains  string   `json:"expectedBodyContains,omitempty"`
	Port                  int      `json:"port"`
	CandidateFile         string   `json:"candidateFile"`
	MaxCandidates         int      `json:"maxCandidates"`
	SampleOffset          int      `json:"sampleOffset"`
	TCPConcurrency        int      `json:"tcpConcurrency"`
	TCPTimeoutMs          int      `json:"tcpTimeoutMs"`
	HTTPSTimeoutMs        int      `json:"httpsTimeoutMs"`
	Finalists             int      `json:"finalists"`
	SamplesPerIP          int      `json:"samplesPerIp"`
	RequestIntervalMs     int      `json:"requestIntervalMs"`
	MaxResponseBytes      int      `json:"maxResponseBytes"`
	MinSuccessRate        float64  `json:"minSuccessRate"`
	BaselineDNSServers    []string `json:"baselineDnsServers"`
	CandidateSources      []string `json:"candidateSources"`
	CandidateSnapshotFile string   `json:"candidateSnapshotFile,omitempty"`
	CandidateCacheDir     string   `json:"candidateCacheDir"`
	SourceRefreshHours    int      `json:"sourceRefreshHours"`
	CloudflareRangesFile  string   `json:"cloudflareRangesFile"`
	PinnedIPs             []string `json:"pinnedIps"`
}

func parseConfig(data []byte, base string) (Config, error) {
	c := Config{HealthPath: "/v1/sys/health", Port: 443, MaxCandidates: 24, TCPConcurrency: 4, TCPTimeoutMs: 3000, HTTPSTimeoutMs: 5000, Finalists: 5, SamplesPerIP: 5, RequestIntervalMs: 300, MaxResponseBytes: 16384, MinSuccessRate: 1, BaselineDNSServers: []string{}}
	c.CandidateSources = []string{}
	c.PinnedIPs = []string{}
	c.CandidateCacheDir = "state/candidate-sources"
	c.CloudflareRangesFile = "candidates/cloudflare-ipv4.txt"
	c.SourceRefreshHours = 24
	c.StateFile = "state/optimizer.json"
	c.ConfirmRuns = 2
	c.CooldownMinutes = 30
	c.MinImprovement = .15
	c.HealthMode = "openbao"
	// Reject null as well as unknown fields; null must not silently retain defaults.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return c, fmt.Errorf("config JSON: %w", err)
	}
	if fields == nil {
		return c, fmt.Errorf("config must be a JSON object")
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return c, fmt.Errorf("%s cannot be null", key)
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("config must contain exactly one JSON object")
	}
	if c.HealthMode != "openbao" && c.HealthMode != "http" {
		return c, fmt.Errorf("healthMode must be openbao or http")
	}
	if c.HealthMode == "http" {
		if _, ok := fields["healthPath"]; !ok {
			return c, fmt.Errorf("http healthMode requires an explicit healthPath")
		}
		if len(c.ExpectedStatusCodes) == 0 || len(c.ExpectedStatusCodes) > 5 || strings.TrimSpace(c.ExpectedBodyContains) == "" || len(c.ExpectedBodyContains) > 256 {
			return c, fmt.Errorf("http healthMode requires 1..5 expectedStatusCodes and a nonempty expectedBodyContains of at most 256 bytes")
		}
		for _, code := range c.ExpectedStatusCodes {
			if code < 200 || code > 299 {
				return c, fmt.Errorf("expectedStatusCodes must be successful HTTP status codes (200..299)")
			}
		}
	} else if len(c.ExpectedStatusCodes) > 0 || c.ExpectedBodyContains != "" {
		return c, fmt.Errorf("expected HTTP response fields require healthMode http")
	}
	if _, present := fields["finalists"]; !present {
		c.Finalists = min(5, c.MaxCandidates)
	}
	label := regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	if len(c.Domain) > 253 || !strings.Contains(c.Domain, ".") {
		return c, fmt.Errorf("domain must be a DNS hostname")
	}
	if _, err := netip.ParseAddr(c.Domain); err == nil {
		return c, fmt.Errorf("domain must be a DNS hostname")
	}
	for _, part := range strings.Split(c.Domain, ".") {
		if !label.MatchString(part) {
			return c, fmt.Errorf("domain must be a DNS hostname")
		}
	}
	u, err := url.ParseRequestURI(c.HealthPath)
	if err != nil || u.IsAbs() || !strings.HasPrefix(c.HealthPath, "/") || strings.HasPrefix(c.HealthPath, "//") || strings.ContainsAny(c.HealthPath, "\\# \t\r\n") {
		return c, fmt.Errorf("healthPath must be a relative HTTP path")
	}
	if strings.TrimSpace(c.CandidateFile) == "" {
		return c, fmt.Errorf("candidateFile is required")
	}
	limits := []struct {
		name             string
		value, low, high int
	}{
		{"port", c.Port, 1, 65535}, {"maxCandidates", c.MaxCandidates, 1, 256}, {"sampleOffset", c.SampleOffset, 0, 1000000},
		{"tcpConcurrency", c.TCPConcurrency, 1, 16}, {"tcpTimeoutMs", c.TCPTimeoutMs, 100, 30000}, {"httpsTimeoutMs", c.HTTPSTimeoutMs, 100, 30000},
		{"finalists", c.Finalists, 1, c.MaxCandidates}, {"samplesPerIp", c.SamplesPerIP, 1, 20}, {"requestIntervalMs", c.RequestIntervalMs, 100, 10000}, {"maxResponseBytes", c.MaxResponseBytes, 256, 65536},
		{"sourceRefreshHours", c.SourceRefreshHours, 1, 168},
		{"confirmRuns", c.ConfirmRuns, 2, 10}, {"cooldownMinutes", c.CooldownMinutes, 0, 10080}, {"maxTtfbMs", c.MaxTTFBMs, 0, 30000},
	}
	for _, v := range limits {
		if v.value < v.low || v.value > v.high {
			return c, fmt.Errorf("%s must be between %d and %d", v.name, v.low, v.high)
		}
	}
	if c.MinSuccessRate <= 0 || c.MinSuccessRate > 1 {
		return c, fmt.Errorf("minSuccessRate must be >0 and <=1")
	}
	if c.MinImprovement < 0 || c.MinImprovement >= 1 {
		return c, fmt.Errorf("minImprovement must be >=0 and <1")
	}
	if c.AdGuardHomeURL != "" {
		u, err := url.Parse(c.AdGuardHomeURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return c, fmt.Errorf("adguardHomeUrl must be an HTTP(S) origin without credentials, path or query")
		}
		if err := validateDNSEndpoint(c.AdGuardHomeDNS); err != nil {
			return c, err
		}
	}
	if strings.TrimSpace(c.StateFile) == "" {
		return c, fmt.Errorf("stateFile cannot be empty")
	}
	if !filepath.IsAbs(c.StateFile) {
		c.StateFile = filepath.Join(base, c.StateFile)
	}
	if len(c.BaselineDNSServers) > 4 {
		return c, fmt.Errorf("at most four baselineDnsServers are allowed")
	}
	for _, server := range c.BaselineDNSServers {
		if addr, err := netip.ParseAddr(server); err != nil || !addr.Is4() {
			return c, fmt.Errorf("baselineDnsServers must be IPv4 addresses")
		}
	}
	if len(c.CandidateSources) > 4 {
		return c, fmt.Errorf("at most four candidateSources are allowed")
	}
	for _, source := range c.CandidateSources {
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return c, fmt.Errorf("candidateSources must be HTTPS URLs without credentials or fragments")
		}
	}
	if (len(c.CandidateSources) > 0 || c.CandidateSnapshotFile != "") && c.Port != 443 {
		return c, fmt.Errorf("public candidateSources require target port 443")
	}
	if len(c.PinnedIPs) > min(4, c.MaxCandidates) {
		return c, fmt.Errorf("pinnedIps must contain at most four addresses and fit maxCandidates")
	}
	for _, ip := range c.PinnedIPs {
		if !publicIPv4(ip) {
			return c, fmt.Errorf("pinnedIps must be public IPv4 addresses")
		}
	}
	if strings.TrimSpace(c.CandidateCacheDir) == "" || strings.TrimSpace(c.CloudflareRangesFile) == "" {
		return c, fmt.Errorf("candidate cache and Cloudflare ranges paths cannot be empty")
	}
	c.Domain = strings.ToLower(c.Domain)
	if !filepath.IsAbs(c.CandidateFile) {
		c.CandidateFile = filepath.Join(base, c.CandidateFile)
	}
	if !filepath.IsAbs(c.CandidateCacheDir) {
		c.CandidateCacheDir = filepath.Join(base, c.CandidateCacheDir)
	}
	if !filepath.IsAbs(c.CloudflareRangesFile) {
		c.CloudflareRangesFile = filepath.Join(base, c.CloudflareRangesFile)
	}
	if c.CandidateSnapshotFile != "" && !filepath.IsAbs(c.CandidateSnapshotFile) {
		c.CandidateSnapshotFile = filepath.Join(base, c.CandidateSnapshotFile)
	}
	return c, nil
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	c, err := parseConfig(data, filepath.Dir(abs))
	if err != nil {
		return c, err
	}
	c.candidateProxy, err = loadCandidateProxy(filepath.Join(filepath.Dir(abs), ".env"), os.LookupEnv)
	if err != nil {
		return c, err
	}
	c.adghUsername, c.adghPassword, err = loadAdGuardCredentials(filepath.Join(filepath.Dir(abs), ".env"), os.LookupEnv)
	return c, err
}
