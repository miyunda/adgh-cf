package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sourceByteLimit = 128 * 1024

// JSON metadata and quoting make a cache larger than the downloaded list.
const sourceCacheByteLimit = sourceByteLimit * 2

type SourceStatus struct {
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	FetchedAt *time.Time `json:"fetchedAt,omitempty"`
	Accepted  int        `json:"accepted"`
	Rejected  int        `json:"rejected"`
	Error     string     `json:"error,omitempty"`
}

type sourceCache struct {
	URL       string    `json:"url"`
	FetchedAt time.Time `json:"fetchedAt"`
	IPs       []string  `json:"ips"`
}

func readSourceCache(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read one extra byte so callers can reject oversized files without loading them fully.
	return io.ReadAll(io.LimitReader(f, sourceCacheByteLimit+1))
}

type SnapshotStatus struct {
	File     string `json:"file"`
	Accepted int    `json:"accepted"`
	Rejected int    `json:"rejected"`
}

func loadCandidateSnapshot(c Config) ([]string, *SnapshotStatus, error) {
	if c.CandidateSnapshotFile == "" {
		return []string{}, nil, nil
	}
	ranges, err := loadCloudflareRanges(c.CloudflareRangesFile)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(c.CandidateSnapshotFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read candidate snapshot: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, sourceByteLimit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read candidate snapshot: %w", err)
	}
	if len(data) > sourceByteLimit {
		return nil, nil, fmt.Errorf("candidate snapshot exceeds 128 KiB limit")
	}
	ips, rejected := parsePublicSource(data, ranges)
	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("candidate snapshot has no eligible Cloudflare IPv4 addresses")
	}
	return ips, &SnapshotStatus{File: c.CandidateSnapshotFile, Accepted: len(ips), Rejected: rejected}, nil
}

func exportSnapshot(ips []string, statuses []SourceStatus) []byte {
	var body strings.Builder
	fmt.Fprintf(&body, "# Cloudflare IPv4 candidate snapshot\n# Generated-At: %s\n# Revalidate locally before selecting an IP; this file is not a ranking.\n", time.Now().UTC().Format(time.RFC3339))
	for _, s := range statuses {
		fmt.Fprintf(&body, "# Source: %s (%s", s.URL, s.Status)
		if s.FetchedAt != nil {
			fmt.Fprintf(&body, ", fetched %s", s.FetchedAt.UTC().Format(time.RFC3339))
		}
		body.WriteString(")\n")
	}
	for _, ip := range unique(ips) {
		body.WriteString(ip + "\n")
	}
	return []byte(body.String())
}

func loadCloudflareRanges(path string) ([]netip.Prefix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Cloudflare ranges: %w", err)
	}
	ranges := []netip.Prefix{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, fmt.Errorf("invalid Cloudflare IPv4 range: %s", line)
		}
		for _, block := range reserved {
			if p.Overlaps(block) {
				return nil, fmt.Errorf("Cloudflare range overlaps reserved addresses: %s", line)
			}
		}
		ranges = append(ranges, p)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("Cloudflare ranges file is empty")
	}
	return ranges, nil
}

func inCloudflare(ip string, ranges []netip.Prefix) bool {
	if !publicIPv4(ip) {
		return false
	}
	addr, _ := netip.ParseAddr(ip)
	for _, p := range ranges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Public feeds may contain proxy addresses, IPv6, labels, or alternate ports.
// Only official-range IPv4 on 443 becomes a candidate; no feed can choose a winner.
func parsePublicSource(body []byte, ranges []netip.Prefix) ([]string, int) {
	ips := []string{}
	rejected := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		ip := line
		if strings.Contains(line, ":") {
			host, port, err := net.SplitHostPort(line)
			if err != nil || port != "443" {
				rejected++
				continue
			}
			ip = host
		}
		if !inCloudflare(ip, ranges) {
			rejected++
			continue
		}
		ips = append(ips, ip)
	}
	return unique(ips), rejected
}

func fetchSource(ctx context.Context, client *http.Client, source string, ranges []netip.Prefix) ([]string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("source download failed: %s", transportError(ctx, err))
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, 0, fmt.Errorf("source HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, sourceByteLimit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("source body read failed: %s", transportError(ctx, err))
	}
	if len(body) > sourceByteLimit {
		return nil, 0, fmt.Errorf("source exceeds 128 KiB limit")
	}
	ips, rejected := parsePublicSource(body, ranges)
	if len(ips) == 0 {
		return nil, rejected, fmt.Errorf("source has no eligible Cloudflare IPv4 addresses")
	}
	return ips, rejected, nil
}

func publicCandidates(ctx context.Context, c Config, force bool) ([]string, []SourceStatus, error) {
	transport := candidateTransport(c)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: sourceRedirect}
	return loadPublicCandidates(ctx, c, force, client)
}

// Only list downloads receive this proxy; probes construct their own direct transport.
func candidateTransport(c Config) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if c.candidateProxy != nil {
		transport.Proxy = http.ProxyURL(c.candidateProxy)
	}
	// A proxy's CONNECT response text is untrusted and may echo authentication.
	transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("candidate proxy CONNECT status %d", response.StatusCode)
		}
		return nil
	}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	}
	return transport
}

func sourceRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
		return fmt.Errorf("source redirect rejected")
	}
	return nil
}

func loadPublicCandidates(ctx context.Context, c Config, force bool, client *http.Client) ([]string, []SourceStatus, error) {
	statuses := []SourceStatus{}
	if len(c.CandidateSources) == 0 {
		return []string{}, statuses, nil
	}
	ranges, err := loadCloudflareRanges(c.CloudflareRangesFile)
	if err != nil {
		return nil, nil, err
	}
	pools := [][]string{}
	for _, source := range unique(c.CandidateSources) {
		if ctx.Err() != nil {
			return nil, statuses, ctx.Err()
		}
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
		path := filepath.Join(c.CandidateCacheDir, key+".json")
		status := SourceStatus{URL: source}
		var cached sourceCache
		data, readErr := readSourceCache(path)
		if readErr == nil {
			if len(data) > sourceCacheByteLimit || json.Unmarshal(data, &cached) != nil || cached.URL != source || cached.FetchedAt.IsZero() {
				status.Error = "invalid source cache"
				cached = sourceCache{}
			}
			valid := []string{}
			for _, ip := range cached.IPs {
				if inCloudflare(ip, ranges) {
					valid = append(valid, ip)
				}
			}
			cached.IPs = unique(valid)
		} else if !os.IsNotExist(readErr) {
			status.Error = "source cache could not be read"
		}
		now := time.Now().UTC()
		age := now.Sub(cached.FetchedAt)
		if !force && len(cached.IPs) > 0 && age >= 0 && age < time.Duration(c.SourceRefreshHours)*time.Hour {
			status.Status = "cached"
			status.FetchedAt = &cached.FetchedAt
			status.Accepted = len(cached.IPs)
			pools = append(pools, cached.IPs)
			statuses = append(statuses, status)
			continue
		}
		ips, rejected, fetchErr := fetchSource(ctx, client, source, ranges)
		status.Rejected = rejected
		if fetchErr == nil {
			status.Status = "downloaded"
			status.Accepted = len(ips)
			status.FetchedAt = &now
			encoded, marshalErr := json.Marshal(sourceCache{URL: source, FetchedAt: now, IPs: ips})
			if marshalErr != nil {
				return nil, statuses, fmt.Errorf("encode source cache: %w", marshalErr)
			}
			if err := writeReport(path, encoded); err != nil {
				status.Error = "download valid but cache write failed: " + err.Error()
			}
			pools = append(pools, ips)
		} else {
			status.Error = fetchErr.Error()
			if len(cached.IPs) > 0 {
				status.Status = "stale-cache"
				status.FetchedAt = &cached.FetchedAt
				status.Accepted = len(cached.IPs)
				pools = append(pools, cached.IPs)
			} else {
				status.Status = "unavailable"
			}
		}
		statuses = append(statuses, status)
	}
	// Interleave providers so a longer list cannot crowd out the other source.
	merged := []string{}
	for n := 0; ; n++ {
		added := false
		for _, pool := range pools {
			if n < len(pool) {
				merged = append(merged, pool[n])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return unique(merged), statuses, nil
}

func selectCandidates(local, public, pinned []string, limit, offset int) []string {
	result := unique(pinned)
	quota := 0
	if len(public) > 0 {
		quota = min(16, max(0, limit-len(result)))
	}
	if len(public) > 0 {
		start := offset % len(public)
		for n := 0; n < len(public) && len(result) < limit-quota; n++ {
			result = unique(append(result, public[(start+n)%len(public)]))
		}
	}
	for _, ip := range local {
		if len(result) >= limit {
			break
		}
		result = unique(append(result, ip))
	}
	// Fill any unused local quota from the public pool (e.g. a small explicit local list).
	for _, ip := range public {
		if len(result) >= limit {
			break
		}
		result = unique(append(result, ip))
	}
	return result
}
