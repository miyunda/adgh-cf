package main

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestGenericHealthConfigRequiresExplicitCriteria(t *testing.T) {
	base := `"domain":"service.example.com","candidateFile":"ips.txt",`
	valid := `"healthMode":"http","healthPath":"/health","expectedStatusCodes":[200],"expectedBodyContains":"service-ready"`
	c, err := parseConfig([]byte("{"+base+valid+"}"), t.TempDir())
	if err != nil || c.HealthMode != "http" {
		t.Fatal("valid generic config failed", err)
	}
	for _, fields := range []string{
		`"healthMode":"unknown"`,
		`"healthMode":"http"`,
		`"healthMode":"http","healthPath":"/health","expectedStatusCodes":[200]`,
		`"healthMode":"http","healthPath":"/health","expectedStatusCodes":[503],"expectedBodyContains":"ok"`,
		`"healthMode":"http","expectedStatusCodes":[200],"expectedBodyContains":"ok"`,
		`"expectedBodyContains":"ok"`,
	} {
		if _, err := parseConfig([]byte("{"+base+fields+"}"), t.TempDir()); err == nil {
			t.Fatal("unsafe health config accepted", fields)
		}
	}
	legacy, err := parseConfig([]byte(`{"domain":"example.com","candidateFile":"ips.txt"}`), t.TempDir())
	if err != nil || legacy.HealthMode != "openbao" || legacy.HealthPath != "/v1/sys/health" {
		t.Fatal("legacy behavior changed")
	}
}

func TestGenericHTTPSHealthRejectsChallengeAndWrongStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/health":
			w.Write([]byte("service-ready"))
		case "/challenge":
			w.Write([]byte("<html>please verify you are human</html>"))
		case "/bad":
			w.WriteHeader(503)
			w.Write([]byte("service-ready"))
		case "/redirect":
			http.Redirect(w, r, "/health", 302)
		}
	}))
	defer server.Close()
	_, p, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	c := Config{Domain: "example.com", HealthMode: "http", HealthPath: "/health", ExpectedStatusCodes: []int{200}, ExpectedBodyContains: "service-ready", Port: port, HTTPSTimeoutMs: 1000, MaxResponseBytes: 1024}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	s := probeHTTPS(context.Background(), "127.0.0.1", c, roots)
	if !s.Usable || s.Classification != "http-healthy" || s.Health != nil || s.TTFBMs == nil {
		t.Fatal("generic check failed", s)
	}
	for _, path := range []string{"/challenge", "/bad", "/redirect"} {
		c.HealthPath = path
		if s := probeHTTPS(context.Background(), "127.0.0.1", c, roots); s.Usable {
			t.Fatal("unhealthy response accepted", path)
		}
	}
	c.HealthPath = "/health"
	if s := probeHTTPS(context.Background(), "127.0.0.1", c, nil); s.Usable {
		t.Fatal("generic mode disabled certificate checks")
	}
}
