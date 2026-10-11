package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
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
type HTTPHop struct {
	StatusCode int     `json:"statusCode"`
	ElapsedMs  float64 `json:"elapsedMs"`
}
type Sample struct {
	BodyTruncated bool      `json:"bodyTruncated,omitempty"`
	Guarantee     string    `json:"guarantee,omitempty"`
	Hops          []HTTPHop `json:"hops,omitempty"`
	ConnectedIP   string    `json:"connectedIp,omitempty"`

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
	if c.SchemaVersion == 2 {
		s.Guarantee = "basic-https-response"
		if c.HealthMode == "http" {
			s.Guarantee = "configured-http-conditions"
		}
		if c.HealthMode == "openbao" {
			s.Guarantee = "openbao-health"
		}
	}
	// Trace hooks may finish on transport goroutines after a deadline. Snapshot their
	// measurements under a lock rather than letting them mutate the returned sample.
	var traceMu sync.Mutex
	var tcpMs, tlsMs, ttfbMs *float64
	var connectedIP string
	defer func() {
		traceMu.Lock()
		defer traceMu.Unlock()
		s.TCPMs, s.TLSMs, s.TTFBMs = tcpMs, tlsMs, ttfbMs
		s.TotalMs = milliseconds(time.Since(start))
		if c.SchemaVersion == 2 {
			s.ConnectedIP = connectedIP
		}
	}()
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.HTTPSTimeoutMs)*time.Millisecond)
	defer cancel()
	var connectStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			traceMu.Lock()
			defer traceMu.Unlock()
			connectedIP, _, _ = net.SplitHostPort(info.Conn.RemoteAddr().String())
		},
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
	host := c.Domain
	if c.Port != 443 {
		host = net.JoinHostPort(c.Domain, strconv.Itoa(c.Port))
	}
	requestURL := "https://" + host + c.HealthPath
	visited := map[string]bool{}
	var response *http.Response
	var err error
	for hop := 0; ; hop++ {
		if c.budget != nil && !c.budget.take() {
			s.Classification = "budget-exhausted"
			s.Error = "HTTP request budget exhausted"
			return
		}
		visited[requestURL] = true
		req, requestErr := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, requestURL, nil)
		if requestErr != nil {
			s.Error = "invalid health request"
			return
		}
		req.Header.Set("Accept", "application/json")
		if c.SchemaVersion == 2 && c.HealthMode != "openbao" {
			req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
		}
		req.Header.Set("Accept-Encoding", "identity")
		hopStart := time.Now()
		response, err = transport.RoundTrip(req)
		if err != nil {
			s.Error = transportError(ctx, err)
			var certErr *tls.CertificateVerificationError
			if c.SchemaVersion == 2 && errors.As(err, &certErr) {
				s.Classification = "certificate-error"
			}
			return
		}
		if c.SchemaVersion == 2 {
			s.Hops = append(s.Hops, HTTPHop{response.StatusCode, milliseconds(time.Since(hopStart))})
		}
		s.StatusCode = response.StatusCode
		redirect := response.StatusCode == 301 || response.StatusCode == 302 || response.StatusCode == 303 || response.StatusCode == 307 || response.StatusCode == 308
		if !redirect || c.SchemaVersion != 2 || c.HealthMode == "openbao" {
			break
		}
		location := response.Header.Get("Location")
		base, _ := url.Parse(requestURL)
		next, parseErr := url.Parse(location)
		response.Body.Close()
		if parseErr == nil {
			next = base.ResolveReference(next)
		}
		if parseErr != nil || location == "" || strings.ContainsAny(location, "\\#") || strings.IndexFunc(location, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 || next.Scheme != "https" || next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Hostname(), c.Domain) || effectivePort(next) != strconv.Itoa(c.Port) || hop >= 3 || visited[next.String()] {
			s.Classification = "redirect-rejected"
			s.Error = "configure the final URL: redirect must be same-origin HTTPS, at most 3 hops without loops"
			return
		}
		requestURL = next.String()
	}
	defer response.Body.Close()
	s.StatusCode = response.StatusCode
	limit := int64(c.MaxResponseBytes) + 1
	prefix := c.SchemaVersion == 2 && c.HealthMode != "openbao"
	if prefix {
		limit = int64(c.MaxResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if prefix && len(body) == c.MaxResponseBytes {
		s.BodyTruncated = response.ContentLength < 0 || response.ContentLength > int64(c.MaxResponseBytes)
	}
	if err != nil {
		s.Error = transportError(ctx, err)
		return
	}
	if len(body) > c.MaxResponseBytes {
		s.Classification = "invalid-response"
		s.Error = "response exceeds configured byte limit"
		return
	}
	if c.SchemaVersion == 2 && (c.HealthMode == "http" || c.HealthMode == "https") {
		switch {
		case strings.EqualFold(response.Header.Get("Cf-Mitigated"), "challenge"):
			s.Classification = "cloudflare-challenge"
		case response.StatusCode == 403:
			s.Classification = "forbidden"
		case response.StatusCode == 429:
			s.Classification = "rate-limited"
		case response.StatusCode >= 500:
			s.Classification = "server-error"
		case c.HealthMode == "https" && response.StatusCode >= 200 && response.StatusCode < 300:
			s.Classification = "https-available"
			s.Usable = true
		case c.HealthMode == "http":
			result := classifyHTTPHealth(response.StatusCode, body, c)
			s.Classification, s.Usable, s.Error = result.Classification, result.Usable, result.Error
		default:
			s.Classification = "http-error"
		}
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
	if (c.SchemaVersion != 2 && c.ExpectedBodyContains == "") || !bytes.Contains(body, []byte(c.ExpectedBodyContains)) {
		return Sample{Classification: "invalid-response", Error: "expected health response marker not found within configured byte limit"}
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

func effectivePort(u *url.URL) string {
	if u.Port() == "" {
		return "443"
	}
	return u.Port()
}
