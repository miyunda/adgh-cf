package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Read a small literal .env beside the JSON config without executing shell code
// or changing process-wide environment variables. Process variables take priority.
func loadCandidateProxy(path string, lookup func(string) (string, bool)) (*url.URL, error) {
	values, err := loadEnvValues(path, lookup)
	if err != nil {
		return nil, err
	}
	return parseCandidateProxy(values)
}

func loadEnvValues(path string, lookup func(string) (string, bool)) (map[string]string, error) {
	values := map[string]string{}
	f, err := os.Open(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read proxy .env: %w", err)
	}
	if err == nil {
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || len(data) > 65536 {
			return nil, fmt.Errorf("proxy .env unreadable or exceeds 64 KiB")
		}
		for n, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			if !strings.HasPrefix(key, "CANDIDATE_PROXY_") && !strings.HasPrefix(key, "ADGH_") {
				continue
			}
			if !ok || (key != "CANDIDATE_PROXY_ADDR" && key != "CANDIDATE_PROXY_USERNAME" && key != "CANDIDATE_PROXY_PASSWORD" && key != "ADGH_USERNAME" && key != "ADGH_PASSWORD" && key != "ADGH_PASSWORD_FILE") {
				return nil, fmt.Errorf("invalid proxy .env key at line %d", n+1)
			}
			if _, exists := values[key]; exists {
				return nil, fmt.Errorf("duplicate proxy .env key at line %d", n+1)
			}
			value = strings.TrimSpace(value)
			if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
				if len(value) < 2 || value[len(value)-1] != value[0] {
					return nil, fmt.Errorf("unclosed proxy .env quote at line %d", n+1)
				}
				value = value[1 : len(value)-1]
			}
			values[key] = value
		}
	}
	for _, key := range []string{"CANDIDATE_PROXY_ADDR", "CANDIDATE_PROXY_USERNAME", "CANDIDATE_PROXY_PASSWORD", "ADGH_USERNAME", "ADGH_PASSWORD", "ADGH_PASSWORD_FILE"} {
		if value, ok := lookup(key); ok {
			values[key] = value
		}
	}
	return values, nil
}

func parseCandidateProxy(values map[string]string) (*url.URL, error) {
	address, user, password := values["CANDIDATE_PROXY_ADDR"], values["CANDIDATE_PROXY_USERNAME"], values["CANDIDATE_PROXY_PASSWORD"]
	if address == "" && user == "" && password == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.Is4() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("CANDIDATE_PROXY_ADDR must be IPv4:port (1..65535)")
	}
	if (user == "") != (password == "") || strings.ContainsAny(user, ":\r\n") || strings.ContainsAny(password, "\r\n") {
		return nil, fmt.Errorf("candidate proxy requires both username and password, or neither; invalid authentication characters")
	}
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(portNumber))}
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	return u, nil
}
