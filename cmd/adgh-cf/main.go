package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code, err := runCLI(ctx, os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Probe failed:", err)
	}
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, out, log io.Writer) (int, error) {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		_, err := fmt.Fprintf(out, "adgh-cf %s (commit %s)\n", version, commit)
		return 0, err
	}
	usage := "Usage: adgh-cf <probe|refresh|export|run> --config <file> [--output <file>] [--dry-run]"
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, usage)
		return 0, nil
	}
	if args[0] != "probe" && args[0] != "refresh" && args[0] != "export" && args[0] != "run" {
		return 1, fmt.Errorf("available commands: probe, refresh, export and run; use --version for build information")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(log)
	configPath := flags.String("config", "", "JSON configuration file")
	outputPath := flags.String("output", "", "write report atomically")
	dryRun := flags.Bool("dry-run", false, "read and measure without changing DNS or optimizer state")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0, nil
		}
		return 1, err
	}
	if flags.NArg() != 0 || *configPath == "" {
		return 1, fmt.Errorf("%s", usage)
	}
	c, err := loadConfig(*configPath)
	if err != nil {
		return 1, err
	}
	if *dryRun && args[0] != "run" {
		return 1, fmt.Errorf("--dry-run is only valid with run")
	}
	if args[0] == "run" {
		return runOptimizer(ctx, c, *dryRun, *outputPath, out, log)
	}
	if args[0] == "refresh" || args[0] == "export" {
		if len(c.CandidateSources) == 0 {
			return 1, fmt.Errorf("candidateSources is empty; configure public HTTPS lists first")
		}
		ips, statuses, err := publicCandidates(ctx, c, true)
		if err != nil {
			return 1, err
		}
		if args[0] == "export" {
			if len(ips) == 0 {
				return 2, fmt.Errorf("no valid public candidates available to export")
			}
			encoded := exportSnapshot(ips, statuses)
			if *outputPath != "" {
				if err := writeReport(*outputPath, encoded); err != nil {
					return 1, err
				}
			}
			for _, s := range statuses {
				fmt.Fprintf(log, "Source %s: %s %s\n", s.URL, s.Status, s.Error)
			}
			if _, err := out.Write(encoded); err != nil {
				return 1, err
			}
			return 0, nil
		}
		encoded, err := json.MarshalIndent(map[string]any{"mode": "source-refresh", "candidateSources": statuses}, "", "  ")
		if err != nil {
			return 1, err
		}
		encoded = append(encoded, '\n')
		if *outputPath != "" {
			if err := writeReport(*outputPath, encoded); err != nil {
				return 1, err
			}
		}
		if _, err := out.Write(encoded); err != nil {
			return 1, err
		}
		for _, s := range statuses {
			if s.Status == "downloaded" {
				return 0, nil
			}
		}
		return 2, nil
	}
	return runProbe(ctx, c, *outputPath, out, log)
}

func runProbe(ctx context.Context, c Config, outputPath string, out, log io.Writer) (int, error) {
	data, err := os.ReadFile(c.CandidateFile)
	if err != nil {
		return 1, fmt.Errorf("read candidates: %w", err)
	}
	candidates, err := sampleCandidates(string(data), c.MaxCandidates, c.SampleOffset)
	if err != nil {
		return 1, err
	}
	public, statuses, err := publicCandidates(ctx, c, false)
	if err != nil {
		return 1, err
	}
	snapshot, snapshotStatus, err := loadCandidateSnapshot(c)
	if err != nil {
		return 1, err
	}
	public = unique(append(public, snapshot...))
	if snapshotStatus != nil {
		fmt.Fprintf(log, "Local snapshot: accepted=%d rejected=%d\n", snapshotStatus.Accepted, snapshotStatus.Rejected)
	}
	for _, s := range statuses {
		fmt.Fprintf(log, "Source %s: %s, accepted=%d rejected=%d %s\n", s.URL, s.Status, s.Accepted, s.Rejected, s.Error)
	}
	if len(c.CandidateSources) > 0 || c.CandidateSnapshotFile != "" {
		ranges, err := loadCloudflareRanges(c.CloudflareRangesFile)
		if err != nil {
			return 1, err
		}
		filtered := []string{}
		for _, ip := range candidates {
			if inCloudflare(ip, ranges) {
				filtered = append(filtered, ip)
			}
		}
		candidates = filtered
		for _, ip := range c.PinnedIPs {
			if !inCloudflare(ip, ranges) {
				return 1, fmt.Errorf("pinned IP is outside Cloudflare ranges: %s", ip)
			}
		}
	}
	candidates = selectCandidates(candidates, public, c.PinnedIPs, c.MaxCandidates, c.SampleOffset)
	started := time.Now().UTC()
	baseline, baselineErr := resolveBaseline(ctx, c)
	ips := unique(append(append([]string{}, baseline...), candidates...))
	fmt.Fprintf(log, "TCP screening %d IPs; domain=%s\n", len(ips), c.Domain)
	tcp := make([]TCPResult, len(ips))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < c.TCPConcurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				tcp[i] = probeTCP(ctx, ips[i], c)
			}
		}()
	}
	for i := range ips {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return 1, ctx.Err()
	}
	connected := []TCPResult{}
	for _, result := range tcp {
		if result.OK {
			connected = append(connected, result)
		}
	}
	sort.SliceStable(connected, func(i, j int) bool { return connected[i].ElapsedMs < connected[j].ElapsedMs })
	finalists := unique(append(append([]string{}, baseline...), c.PinnedIPs...))
	for _, r := range connected[:min(len(connected), c.Finalists)] {
		finalists = append(finalists, r.IP)
	}
	finalists = unique(finalists)
	collected := make(map[string][]Sample)
	eliminated := make(map[string]string)
	for _, ip := range finalists {
		collected[ip] = []Sample{}
	}
	for round := 0; round < c.SamplesPerIP; round++ {
		for n := range finalists {
			if ctx.Err() != nil {
				return 1, ctx.Err()
			}
			ip := finalists[(n+round)%len(finalists)]
			if eliminated[ip] != "" {
				continue
			}
			s := probeHTTPS(ctx, ip, c, nil)
			collected[ip] = append(collected[ip], s)
			fmt.Fprintf(log, "Sample %d/%d: %s %s %.0fms\n", round+1, c.SamplesPerIP, ip, s.Classification, s.TotalMs)
			if reason := eliminationReason(collected[ip], c); reason != "" {
				eliminated[ip] = reason
				fmt.Fprintf(log, "Eliminated %s: %s\n", ip, reason)
			}
			select {
			case <-ctx.Done():
				return 1, ctx.Err()
			case <-time.After(time.Duration(c.RequestIntervalMs) * time.Millisecond):
			}
		}
	}
	results := []Summary{}
	for _, ip := range finalists {
		summary := summarize(ip, collected[ip], c.MinSuccessRate)
		summary.EliminatedReason = eliminated[ip]
		if summary.EliminatedReason != "" {
			summary.Eligible = false
		}
		results = append(results, summary)
	}
	ranked := rank(results)
	ranking := []string{}
	var suggested *string
	for _, r := range ranked {
		ranking = append(ranking, r.IP)
	}
	if len(ranking) > 0 {
		suggested = &ranking[0]
	}
	sort.Slice(tcp, func(i, j int) bool { return tcp[i].IP < tcp[j].IP })
	source := "system-resolver"
	if len(c.BaselineDNSServers) > 0 {
		source = "configured-resolver"
	}
	var baselineError any
	if baselineErr != nil {
		baselineError = baselineErr.Error()
	}
	report := map[string]any{
		"schemaVersion": 1, "mode": "read-only", "startedAt": started, "finishedAt": time.Now().UTC(),
		"target":   map[string]any{"domain": c.Domain, "port": c.Port, "healthPath": c.HealthPath, "protocol": "HTTP/1.1"},
		"baseline": map[string]any{"ips": baseline, "error": baselineError, "dnsServers": c.BaselineDNSServers, "source": source},
		"settings": c, "tcp": tcp, "results": results, "ranking": ranking, "suggestedIp": suggested,
		"candidateSources":  statuses,
		"candidateSnapshot": snapshotStatus,
		"notes":             []string{"One run measures current reachability and latency, not long-term stability.", "System DNS may include an existing rewrite; configure baselineDnsServers for an independent baseline. Empty dnsServers means system resolver configuration.", "HTTPS uses fresh TCP/TLS connections and HTTP/1.1; connection reuse and HTTP/2 are not measured.", "Standby is reachable but authenticated operations and forwarding are not verified.", "PT traffic and upload saturation may affect latency; compare multiple time windows.", "No AdGuard Home API calls or DNS changes were made."},
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return 1, err
	}
	encoded = append(encoded, '\n')
	if outputPath != "" {
		if err := writeReport(outputPath, encoded); err != nil {
			return 1, err
		}
		fmt.Fprintln(log, "Report saved:", outputPath)
	}
	if _, err := out.Write(encoded); err != nil {
		return 1, err
	}
	if suggested == nil {
		return 2, nil
	}
	return 0, nil
}

func unique(ips []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}

func resolveBaseline(parent context.Context, c Config) ([]string, error) {
	servers := c.BaselineDNSServers
	if len(servers) == 0 {
		servers = []string{""}
	}
	var last error
	for _, server := range servers {
		resolver := &net.Resolver{PreferGo: true}
		if server != "" {
			resolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			}
		}
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		values, err := resolver.LookupIP(ctx, "ip4", c.Domain)
		cancel()
		if err != nil {
			last = err
			continue
		}
		result := []string{}
		for _, ip := range values {
			if publicIPv4(ip.String()) {
				result = append(result, ip.String())
			}
		}
		result = unique(result)
		if len(result) > 0 {
			return result[:min(len(result), 4)], nil
		}
		last = fmt.Errorf("DNS returned no public IPv4 addresses")
	}
	return []string{}, last
}

func writeReport(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".adgh-cf-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { f.Close(); os.Remove(name) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open output directory for sync: %w", err)
	}
	defer directory.Close()
	if err = os.Rename(name, path); err != nil {
		return err
	}
	// File Sync persists the contents; directory Sync persists the replacement.
	// A pending DNS change must be durable before the API write starts.
	if err = directory.Sync(); err != nil {
		return fmt.Errorf("output replaced but directory sync failed: %w", err)
	}
	return nil
}
