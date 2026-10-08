package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"
)

type TCPResult struct {
	IP        string  `json:"ip"`
	ElapsedMs float64 `json:"elapsedMs"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
}
type Health struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Standby     bool `json:"standby"`
}
type Sample struct {
	IP             string   `json:"ip"`
	Classification string   `json:"classification"`
	Usable         bool     `json:"usable"`
	TCPMs          *float64 `json:"tcpMs,omitempty"`
	TLSMs          *float64 `json:"tlsMs,omitempty"`
	TTFBMs         *float64 `json:"ttfbMs,omitempty"`
	TotalMs        float64  `json:"totalMs"`
	StatusCode     int      `json:"statusCode,omitempty"`
	Health         *Health  `json:"health,omitempty"`
	Error          string   `json:"error,omitempty"`
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func classifyHealth(status int, body []byte) Sample {
	s := Sample{Classification: "invalid-response"}
	var fields struct {
		Initialized *bool `json:"initialized"`
		Sealed      *bool `json:"sealed"`
		Standby     *bool `json:"standby"`
	}
	if err := json.Unmarshal(body, &fields); err != nil || fields.Initialized == nil || fields.Sealed == nil || fields.Standby == nil {
		return s
	}
	h := &Health{*fields.Initialized, *fields.Sealed, *fields.Standby}
	s.Health = h
	switch {
	case !h.Initialized && status == 501:
		s.Classification = "uninitialized"
	case h.Sealed && status == 503:
		s.Classification = "sealed"
	case h.Initialized && !h.Sealed && h.Standby && (status == 429 || status == 200):
		s.Classification = "standby"
		s.Usable = true
	case h.Initialized && !h.Sealed && !h.Standby && status == 200:
		s.Classification = "active"
		s.Usable = true
	default:
		s.Classification = "http-error"
	}
	return s
}

func probeTCP(ctx context.Context, ip string, c Config) TCPResult {
	start := time.Now()
	d := net.Dialer{Timeout: time.Duration(c.TCPTimeoutMs) * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(c.Port)))
	r := TCPResult{IP: ip, ElapsedMs: milliseconds(time.Since(start)), OK: err == nil}
	if err != nil {
		r.Error = err.Error()
	} else {
		conn.Close()
	}
	return r
}

func probeHTTPS(parent context.Context, ip string, c Config, roots *x509.CertPool) (s Sample) {
	start := time.Now()
	s = Sample{IP: ip, Classification: "transport-error"}
	// Trace hooks may finish on transport goroutines after a deadline. Snapshot their
	// measurements under a lock rather than letting them mutate the returned sample.
	var traceMu sync.Mutex
	var tcpMs, tlsMs, ttfbMs *float64
	defer func() {
		traceMu.Lock()
		defer traceMu.Unlock()
		s.TCPMs, s.TLSMs, s.TTFBMs = tcpMs, tlsMs, ttfbMs
		s.TotalMs = milliseconds(time.Since(start))
	}()
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.HTTPSTimeoutMs)*time.Millisecond)
	defer cancel()
	var connectStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { traceMu.Lock(); connectStart = time.Now(); traceMu.Unlock() },
		ConnectDone: func(_, _ string, err error) {
			traceMu.Lock()
			defer traceMu.Unlock()
			if err == nil {
				v := milliseconds(time.Since(connectStart))
				tcpMs = &v
			}
		},
		TLSHandshakeStart: func() { traceMu.Lock(); tlsStart = time.Now(); traceMu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			traceMu.Lock()
			defer traceMu.Unlock()
			if err == nil {
				v := milliseconds(time.Since(tlsStart))
				tlsMs = &v
			}
		},
		GotFirstResponseByte: func() { traceMu.Lock(); defer traceMu.Unlock(); v := milliseconds(time.Since(start)); ttfbMs = &v },
	}
	// URL/Host remain the domain. Only the TCP destination is pinned; proxy env is deliberately ignored.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(c.Port)))
		},
		TLSClientConfig:   &tls.Config{ServerName: c.Domain, RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	host := c.Domain
	if c.Port != 443 {
		host = net.JoinHostPort(c.Domain, strconv.Itoa(c.Port))
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+host+c.HealthPath, nil)
	if err != nil {
		s.Error = "invalid health request"
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		s.Error = transportError(ctx, err)
		return
	}
	defer response.Body.Close()
	s.StatusCode = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(c.MaxResponseBytes)+1))
	if err != nil {
		s.Error = transportError(ctx, err)
		return
	}
	if len(body) > c.MaxResponseBytes {
		s.Classification = "invalid-response"
		s.Error = "response exceeds configured byte limit"
		return
	}
	if c.HealthMode == "http" {
		result := classifyHTTPHealth(response.StatusCode, body, c)
		s.Classification = result.Classification
		s.Usable = result.Usable
		s.Error = result.Error
		return
	}
	typeName, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" {
		s.Classification = "invalid-response"
		s.Error = "expected JSON content type"
		return
	}
	result := classifyHealth(response.StatusCode, body)
	s.Classification = result.Classification
	s.Usable = result.Usable
	s.Health = result.Health
	if result.Classification == "invalid-response" {
		s.Error = "invalid OpenBao health JSON"
	}
	return
}

func classifyHTTPHealth(status int, body []byte, c Config) Sample {
	matched := false
	for _, code := range c.ExpectedStatusCodes {
		if code == status {
			matched = true
			break
		}
	}
	if !matched {
		return Sample{Classification: "http-error", Error: "unexpected health HTTP status"}
	}
	if c.ExpectedBodyContains == "" || !bytes.Contains(body, []byte(c.ExpectedBodyContains)) {
		return Sample{Classification: "invalid-response", Error: "expected health response marker not found"}
	}
	return Sample{Classification: "http-healthy", Usable: true}
}

func transportError(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return fmt.Sprintf("HTTPS request: %s", ctx.Err())
	}
	// Avoid logging request URLs, query parameters or arbitrary server bodies.
	for {
		v, ok := err.(interface{ Unwrap() error })
		if !ok || v.Unwrap() == nil {
			break
		}
		err = v.Unwrap()
	}
	return err.Error()
}
