package main

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPSPinningAndTLS(t *testing.T) {
	var host, sni string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		sni = r.TLS.ServerName
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	c := Config{Domain: "example.com", Port: port, HealthPath: "/health", HTTPSTimeoutMs: 1000, MaxResponseBytes: 1024}
	// An unreachable download proxy and global proxy settings must not affect probes.
	c.candidateProxy, _ = url.Parse("http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
	if !s.Usable || host != net.JoinHostPort(c.Domain, portText) || sni != c.Domain || s.TCPMs == nil || s.TLSMs == nil || s.TTFBMs == nil {
		t.Fatalf("pinning: %+v host=%s sni=%s", s, host, sni)
	}
	s = probeHTTPS(context.Background(), "127.0.0.1", c, nil)
	if s.Usable || s.Classification != "transport-error" {
		t.Fatal("accepted untrusted certificate")
	}
	c.Domain = "wrong.test"
	s = probeHTTPS(context.Background(), "127.0.0.1", c, roots)
	if s.Usable || !strings.Contains(s.Error, "wrong.test") {
		t.Fatalf("hostname verification: %+v", s)
	}
}

func TestHTTPSResponseBoundaries(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stall":
			<-r.Context().Done()
		case "/redirect":
			http.Redirect(w, r, "https://other.test/", 302)
		case "/oversize":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(strings.Repeat("x", 2048)))
		case "/invalid":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{"))
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("challenge"))
		case "/body-stall":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	c := Config{Domain: "example.com", Port: port, HTTPSTimeoutMs: 100, MaxResponseBytes: 1024}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, path := range []string{"/stall", "/body-stall", "/redirect", "/oversize", "/invalid", "/html"} {
		c.HealthPath = path
		s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
		if s.Usable {
			t.Errorf("accepted %s", path)
		}
		if strings.Contains(path, "stall") && (s.Classification != "transport-error" || s.TotalMs > 1000 || !strings.Contains(s.Error, "deadline")) {
			t.Errorf("deadline: %+v", s)
		}
		if path == "/oversize" && !strings.Contains(s.Error, "byte limit") {
			t.Errorf("byte cap: %+v", s)
		}
		if path == "/redirect" && s.StatusCode != 302 {
			t.Error("redirect followed")
		}
	}
}

func TestTCPProbe(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	c := Config{Port: port, TCPTimeoutMs: 100}
	r := probeTCP(context.Background(), "127.0.0.1", c)
	listener.Close()
	if !r.OK {
		t.Fatal(r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if probeTCP(ctx, "127.0.0.1", c).OK {
		t.Fatal("ignored cancellation")
	}
}
