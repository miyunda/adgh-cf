package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestV2HTTPSModesRedirectsAndBudget(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			fmt.Fprint(w, strings.Repeat("x", 2048))
		case "/marker":
			fmt.Fprint(w, "ready"+strings.Repeat("x", 2048))
		case "/late-marker":
			fmt.Fprint(w, strings.Repeat("x", 1024)+"ready")
		case "/empty":
			w.WriteHeader(204)
		case "/redirect":
			time.Sleep(20 * time.Millisecond)
			http.Redirect(w, r, "/empty", 302)
		case "/loop":
			http.Redirect(w, r, "/loop", 302)
		case "/cross":
			http.Redirect(w, r, "https://other.example.com/", 302)
		case "/downgrade":
			http.Redirect(w, r, "http://example.com/", 302)
		case "/port":
			http.Redirect(w, r, "https://"+r.Host+"0/", 302)
		case "/bad-location":
			w.Header().Set("Location", "%invalid")
			w.WriteHeader(302)
		case "/chain":
			http.Redirect(w, r, "/chain?x="+r.URL.Query().Get("x")+"x", 302)
		case "/challenge":
			w.Header().Set("Cf-Mitigated", "challenge")
		case "/forbidden":
			w.WriteHeader(403)
		case "/rate":
			w.WriteHeader(429)
		case "/error":
			w.WriteHeader(503)
		case "/broken":
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "short")
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer server.Close()
	_, p, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := Config{SchemaVersion: 2, Domain: "example.com", Port: port, HealthMode: "https", HTTPSTimeoutMs: 1000, MaxResponseBytes: 256}
	for _, tc := range []struct {
		path, class string
		usable      bool
	}{{"/large", "https-available", true}, {"/empty", "https-available", true}, {"/redirect", "https-available", true}, {"/loop", "redirect-rejected", false}, {"/cross", "redirect-rejected", false}, {"/downgrade", "redirect-rejected", false}, {"/port", "redirect-rejected", false}, {"/bad-location", "redirect-rejected", false}, {"/chain", "redirect-rejected", false}, {"/challenge", "cloudflare-challenge", false}, {"/forbidden", "forbidden", false}, {"/rate", "rate-limited", false}, {"/error", "server-error", false}, {"/broken", "transport-error", false}} {
		t.Run(tc.path, func(t *testing.T) {
			c.HealthPath = tc.path
			s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
			if s.Usable != tc.usable || s.Classification != tc.class {
				t.Fatalf("%+v", s)
			}
			if tc.path == "/large" && !s.BodyTruncated {
				t.Fatal("missing truncation")
			}
			if tc.path == "/redirect" && (len(s.Hops) != 2 || s.TTFBMs == nil || *s.TTFBMs < 20) {
				t.Fatalf("redirect timing: %+v", s)
			}
		})
	}
	c.HealthMode = "http"
	c.ExpectedStatusCodes = []int{200}
	c.ExpectedBodyContains = "ready"
	for _, path := range []string{"/marker", "/late-marker"} {
		c.HealthPath = path
		s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
		if s.Usable != (path == "/marker") {
			t.Fatalf("marker %+v", s)
		}
	}
	c.ExpectedBodyContains = ""
	c.HealthPath = "/large"
	if !probeHTTPS(context.Background(), "127.0.0.1", c, roots).Usable {
		t.Fatal("status-only HTTP failed")
	}
	c.HealthMode = "https"
	c.HealthPath = "/redirect"
	c.budget = &requestBudget{Limit: 1}
	s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
	if s.Usable || s.Classification != "budget-exhausted" || c.budget.Used != 1 {
		t.Fatalf("budget: %+v %+v", s, c.budget)
	}
	c.budget = &requestBudget{Limit: 4}
	c.HealthPath = "/chain"
	s = probeHTTPS(context.Background(), "127.0.0.1", c, roots)
	if s.Usable || c.budget.Used != 4 {
		t.Fatalf("redirect cap: %+v %+v", s, c.budget)
	}
	c.budget = nil
	c.HealthPath = "/"
	s = probeHTTPS(context.Background(), "127.0.0.1", c, nil)
	if s.Classification != "certificate-error" {
		t.Fatalf("TLS: %+v", s)
	}
}
