package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCandidateProxyEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	lookup := func(string) (string, bool) { return "", false }
	if p, err := loadCandidateProxy(path, lookup); err != nil || p != nil {
		t.Fatal("missing .env should use direct downloads")
	}
	text := "# comment\nCANDIDATE_PROXY_ADDR=192.168.2.1:7893\nCANDIDATE_PROXY_USERNAME=user\nCANDIDATE_PROXY_PASSWORD='p@ss:#=$word'\n"
	os.WriteFile(path, []byte(text), 0600)
	p, err := loadCandidateProxy(path, lookup)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := p.User.Password()
	if password != "p@ss:#=$word" || p.Host != "192.168.2.1:7893" {
		t.Fatal("literal credentials not preserved")
	}
	encoded, _ := json.Marshal(Config{candidateProxy: p})
	if strings.Contains(string(encoded), "word") || strings.Contains(string(encoded), "7893") {
		t.Fatal("proxy leaked into report config")
	}
	p, err = loadCandidateProxy(path, func(key string) (string, bool) { return "127.0.0.1:8080", key == "CANDIDATE_PROXY_ADDR" })
	if err != nil || p.Host != "127.0.0.1:8080" {
		t.Fatal("process environment must override file")
	}
	for _, invalid := range []string{
		"CANDIDATE_PROXY_ADDR=http://192.168.2.1:7893",
		"CANDIDATE_PROXY_ADDR=[::1]:7893",
		"CANDIDATE_PROXY_ADDR=192.168.2.1:0",
		"CANDIDATE_PROXY_USERNAME=user",
		"CANDIDATE_PROXY_PASSWORD='SECRET",
		"CANDIDATE_PROXY_ADDR=127.0.0.1:7893\nCANDIDATE_PROXY_ADDR=127.0.0.1:7894",
	} {
		os.WriteFile(path, []byte(invalid), 0600)
		if _, err := loadCandidateProxy(path, lookup); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal("invalid .env accepted or credential leaked")
		}
	}
}

func TestCandidateProxyTunnelAndFailure(t *testing.T) {
	var originCalls, proxyCalls atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached source")
		}
		io.WriteString(w, "104.18.43.147\n")
	}))
	defer origin.Close()
	var fail atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:p@ss:#=$word"))
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != expected {
			t.Error("missing CONNECT authentication")
			w.WriteHeader(407)
			return
		}
		if fail.Load() {
			w.WriteHeader(407)
			return
		}
		upstream, err := net.Dial("tcp4", strings.TrimPrefix(origin.URL, "https://"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			t.Error(err)
			return
		}
		defer downstream.Close()
		defer upstream.Close()
		buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buffered.Flush()
		go func() { io.Copy(upstream, buffered); upstream.Close() }()
		io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	p, _ := url.Parse(proxy.URL)
	p.User = url.UserPassword("user", "p@ss:#=$word")
	dir := t.TempDir()
	ranges := filepath.Join(dir, "ranges.txt")
	os.WriteFile(ranges, []byte("104.16.0.0/13"), 0600)
	c := Config{candidateProxy: p, CandidateSources: []string{origin.URL}, CloudflareRangesFile: ranges, CandidateCacheDir: filepath.Join(dir, "cache"), SourceRefreshHours: 24}
	transport := candidateTransport(c)
	defer transport.CloseIdleConnections()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: transport, CheckRedirect: sourceRedirect}
	ips, statuses, err := loadPublicCandidates(context.Background(), c, true, client)
	if err != nil || len(ips) != 1 || statuses[0].Status != "downloaded" || proxyCalls.Load() != 1 || originCalls.Load() != 1 {
		t.Fatalf("proxy download failed: %v %+v", err, statuses)
	}
	transport.CloseIdleConnections()
	fail.Store(true)
	ips, statuses, err = loadPublicCandidates(context.Background(), c, true, client)
	if err != nil || len(ips) != 1 || statuses[0].Status != "stale-cache" || !strings.Contains(statuses[0].Error, "407") {
		t.Fatalf("proxy failure did not preserve cache: %v %+v", err, statuses)
	}
	if strings.Contains(statuses[0].Error, "word") {
		t.Fatal("credentials leaked")
	}
	// The default downloader deliberately ignores global proxy environment variables.
	t.Setenv("HTTPS_PROXY", proxy.URL)
	direct := candidateTransport(Config{})
	defer direct.CloseIdleConnections()
	if direct.Proxy != nil {
		t.Fatal("global proxy environment used")
	}
	if !inCloudflare(ips[0], []netip.Prefix{netip.MustParsePrefix("104.16.0.0/13")}) {
		t.Fatal("invalid exported candidate")
	}
}
