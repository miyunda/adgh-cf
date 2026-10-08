package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicListFiltering(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("104.16.0.0/13"), netip.MustParsePrefix("103.31.4.0/22")}
	body := []byte("# timestamp\nipv4.list.updated.at#Upd20261007\n104.18.43.147:443#SG\n104.18.43.147:443#duplicate\n103.31.4.18\n104.18.41.123:8443#bad port\n[2606:4700::1]:443\n1.2.3.4:443#proxy\n127.0.0.1:443\ninvalid\n104.18.41.123:443\n")
	ips, rejected := parsePublicSource(body, ranges)
	if !reflect.DeepEqual(ips, []string{"104.18.43.147", "103.31.4.18", "104.18.41.123"}) || rejected != 6 {
		t.Fatalf("filtering %v rejected=%d", ips, rejected)
	}
}

func TestSourceCacheReadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	for _, size := range []int64{sourceCacheByteLimit, sourceCacheByteLimit + 1, 64 * 1024 * 1024} {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := readSourceCache(path)
		if err != nil {
			t.Fatal(err)
		}
		want := min(size, sourceCacheByteLimit+1)
		if int64(len(data)) != want {
			t.Fatalf("cache size %d: read %d bytes, want %d", size, len(data), want)
		}
	}
}

func TestSourceRefreshAndCacheFallback(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Write([]byte("104.18.43.147:443#SG\n1.2.3.4:443#proxy"))
	}))
	defer server.Close()
	dir := t.TempDir()
	rangesFile := filepath.Join(dir, "ranges.txt")
	os.WriteFile(rangesFile, []byte("104.16.0.0/13"), 0600)
	c := Config{CandidateSources: []string{server.URL}, CandidateCacheDir: filepath.Join(dir, "cache"), CloudflareRangesFile: rangesFile, SourceRefreshHours: 24}
	client := server.Client()
	client.CheckRedirect = sourceRedirect
	ips, statuses, err := loadPublicCandidates(context.Background(), c, false, client)
	if err != nil || len(ips) != 1 || statuses[0].Status != "downloaded" || statuses[0].Rejected != 1 {
		t.Fatalf("initial: %v %+v %v", ips, statuses, err)
	}
	_, statuses, err = loadPublicCandidates(context.Background(), c, false, client)
	if err != nil || statuses[0].Status != "cached" || calls.Load() != 1 {
		t.Fatalf("fresh cache: %+v %v calls=%d", statuses, err, calls.Load())
	}
	files, _ := os.ReadDir(c.CandidateCacheDir)
	cachePath := filepath.Join(c.CandidateCacheDir, files[0].Name())
	old, _ := os.ReadFile(cachePath)
	fail.Store(true)
	ips, statuses, err = loadPublicCandidates(context.Background(), c, true, client)
	after, _ := os.ReadFile(cachePath)
	if err != nil || len(ips) != 1 || statuses[0].Status != "stale-cache" || statuses[0].Error == "" || string(after) != string(old) {
		t.Fatalf("failed refresh: %v %+v %v", ips, statuses, err)
	}
	var cache sourceCache
	json.Unmarshal(old, &cache)
	cache.FetchedAt = time.Now().Add(-25 * time.Hour)
	encoded, _ := json.Marshal(cache)
	os.WriteFile(cachePath, encoded, 0600)
	_, statuses, err = loadPublicCandidates(context.Background(), c, false, client)
	if err != nil || statuses[0].Status != "stale-cache" || calls.Load() != 3 {
		t.Fatalf("expired cache: %+v %v", statuses, err)
	}
	// Revalidate cached addresses against the current official ranges, not only at download.
	os.WriteFile(rangesFile, []byte("103.31.4.0/22"), 0600)
	ips, statuses, err = loadPublicCandidates(context.Background(), c, false, client)
	if err != nil || len(ips) != 0 || statuses[0].Status != "unavailable" {
		t.Fatalf("range revalidation: %v %+v %v", ips, statuses, err)
	}
	// A valid JSON cache at the limit remains usable, but an oversized cache
	// cannot become a fallback when the source is unavailable.
	if err := os.WriteFile(rangesFile, []byte("104.16.0.0/13"), 0600); err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte{}, old...), []byte(strings.Repeat(" ", sourceCacheByteLimit-len(old)))...)
	for _, extra := range []string{"", " "} {
		if err := os.WriteFile(cachePath, append(append([]byte{}, padded...), extra...), 0600); err != nil {
			t.Fatal(err)
		}
		ips, statuses, err = loadPublicCandidates(context.Background(), c, false, client)
		if err != nil {
			t.Fatal(err)
		}
		if extra == "" && (len(ips) != 1 || statuses[0].Status != "cached") {
			t.Fatalf("rejected cache at limit: %v %+v", ips, statuses)
		}
		if extra != "" && (len(ips) != 0 || statuses[0].Status != "unavailable") {
			t.Fatalf("used oversized cache: %v %+v", ips, statuses)
		}
	}
}

func TestSourceDownloadLimits(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write([]byte(strings.Repeat("x", sourceByteLimit+1)))
		case "/bad":
			w.Write([]byte("<html>not a list</html>"))
		case "/redirect":
			http.Redirect(w, r, "http://example.com/list", 302)
		case "/stall":
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = sourceRedirect
	ranges := []netip.Prefix{netip.MustParsePrefix("104.16.0.0/13")}
	for _, path := range []string{"/big", "/bad", "/redirect"} {
		if _, _, err := fetchSource(context.Background(), client, server.URL+path, ranges); err == nil {
			t.Errorf("accepted %s", path)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := fetchSource(ctx, client, server.URL+"/stall", ranges); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("download timeout: %v", err)
	}
	other, _ := url.Parse("https://other.test/list")
	origin, _ := http.NewRequest("GET", "https://example.com/list", nil)
	if sourceRedirect(&http.Request{URL: other}, []*http.Request{origin}) == nil {
		t.Fatal("accepted cross-host redirect")
	}
}

func TestCandidateMergeBudget(t *testing.T) {
	local := []string{"103.31.4.18", "104.16.0.18"}
	public := []string{"104.18.1.1", "104.18.1.2", "103.31.4.18"}
	pinned := []string{"103.31.4.18"}
	merged := selectCandidates(local, public, pinned, 4, 0)
	if len(merged) != 4 || merged[0] != pinned[0] || len(unique(merged)) != 4 {
		t.Fatalf("merge %v", merged)
	}
	fallback := selectCandidates(local, nil, pinned, 4, 0)
	if !reflect.DeepEqual(fallback, local) {
		t.Fatalf("local fallback %v", fallback)
	}
}

func TestIPv4AndSourceConfig(t *testing.T) {
	for _, field := range []string{`"baselineDnsServers":["::1"]`, `"pinnedIps":["2606:4700::1"]`, `"candidateSources":["http://example.com/list"]`, `"candidateSources":["https://user:pass@example.com/list"]`, `"candidateSources":["https://example.com/list"],"port":8443`} {
		if _, err := parseConfig([]byte(`{"domain":"example.com","candidateFile":"ips.txt",`+field+`}`), t.TempDir()); err == nil {
			t.Errorf("accepted %s", field)
		}
	}
}

func TestOfflineSnapshotAndExport(t *testing.T) {
	dir := t.TempDir()
	rangesPath := filepath.Join(dir, "ranges.txt")
	snapshotPath := filepath.Join(dir, "snapshot.txt")
	if err := os.WriteFile(rangesPath, []byte("104.16.0.0/13"), 0600); err != nil {
		t.Fatal(err)
	}
	statuses := []SourceStatus{{URL: "https://example.com/list", Status: "cached"}}
	data := exportSnapshot([]string{"104.18.43.147", "104.18.43.147"}, statuses)
	if err := os.WriteFile(snapshotPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{CloudflareRangesFile: rangesPath, CandidateSnapshotFile: snapshotPath}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	public, sourceStatus, err := publicCandidates(ctx, c, false)
	if err != nil || len(public) != 0 || len(sourceStatus) != 0 {
		t.Fatalf("offline path attempted download: %v", err)
	}
	ips, status, err := loadCandidateSnapshot(c)
	if err != nil || len(ips) != 1 || status.Accepted != 1 {
		t.Fatalf("snapshot load: %v %+v %v", ips, status, err)
	}
	if !strings.Contains(string(data), "Generated-At:") || !strings.Contains(string(data), "https://example.com/list") {
		t.Fatal("export lacks provenance")
	}
	if err := os.WriteFile(snapshotPath, []byte("[2606:4700::1]:443\n1.2.3.4:443"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCandidateSnapshot(c); err == nil {
		t.Fatal("accepted invalid snapshot")
	}
	if err := os.WriteFile(snapshotPath, []byte(strings.Repeat("x", sourceByteLimit+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCandidateSnapshot(c); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
}

func TestBundledPTProfile(t *testing.T) {
	c, err := loadConfig("config.pt.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.CandidateSources) != 0 {
		t.Fatal("PT profile must not download remote sources")
	}
	ips, status, err := loadCandidateSnapshot(c)
	if err != nil || len(ips) == 0 || status.Rejected != 0 {
		t.Fatalf("bundled snapshot invalid: %v %+v %v", ips, status, err)
	}
}
