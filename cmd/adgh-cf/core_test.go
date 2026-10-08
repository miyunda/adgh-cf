package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublicExampleConfigurations(t *testing.T) {
	files, err := filepath.Glob("../../examples/config*.example.json")
	if err != nil || len(files) == 0 {
		t.Fatal("missing configuration templates")
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c, err := parseConfig(data, ".")
		if err != nil {
			t.Fatalf("invalid template %s: %v", path, err)
		}
		if !strings.HasSuffix(c.Domain, ".example.com") {
			t.Fatalf("template %s must use a public placeholder domain", path)
		}
	}
}

func TestCandidateSampling(t *testing.T) {
	text := "# source\n104.16.0.0/13\n172.64.0.0/13\n"
	first, err := sampleCandidates(text, 6, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := sampleCandidates(text, 6, 0)
	rotated, _ := sampleCandidates(text, 6, 1)
	if len(first) != 6 || len(unique(first)) != 6 || !reflect.DeepEqual(first, again) || reflect.DeepEqual(first, rotated) {
		t.Fatalf("invalid sampling: %v", first)
	}
	for _, input := range []string{"127.0.0.1", "10.0.0.0/8", "104.16.0.1/13", "104.16.0.0/", "104.16.0.0/0", "192.0.0.0/12", "104.16.0.0/13/32", "", "999.1.1.1", "::1"} {
		if _, err := sampleCandidates(input, 3, 0); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	single, err := sampleCandidates("104.16.0.1\n104.16.0.1", 5, 0)
	if err != nil || len(single) != 1 {
		t.Fatalf("deduplication: %v %v", single, err)
	}
	if !publicIPv4("172.64.0.1") || publicIPv4("172.16.0.1") {
		t.Fatal("public/private boundary")
	}
}

func TestConfigValidation(t *testing.T) {
	c, err := parseConfig([]byte(`{"domain":"example.com","candidateFile":"ips.txt","maxCandidates":1}`), "/tmp/probe")
	if err != nil || c.Finalists != 1 || c.CandidateFile != "/tmp/probe/ips.txt" {
		t.Fatalf("defaults/path: %+v %v", c, err)
	}
	for _, text := range []string{
		`null`, `[]`,
		`{"domain":"127.0.0.1","candidateFile":"ips.txt"}`,
		`{"domain":"example.com/evil","candidateFile":"ips.txt"}`,
		`{"domain":"example.com","candidateFile":"ips.txt","healthPath":"//evil.test/"}`,
		`{"domain":"example.com","candidateFile":"ips.txt","tcpConcurrency":99}`,
		`{"domain":"example.com","candidateFile":"ips.txt","minSuccessRate":0}`,
		`{"domain":"example.com","candidateFile":"ips.txt","typo":true}`,
		`{"domain":"example.com","candidateFile":"ips.txt","port":null}`,
		`{"domain":"example.com","candidateFile":"ips.txt","baselineDnsServers":["bad"]}`,
		`{"domain":"example.com","candidateFile":"ips.txt"} {}`,
	} {
		if _, err := parseConfig([]byte(text), "/tmp"); err == nil {
			t.Errorf("accepted %s", text)
		}
	}
}

func TestHealthClassification(t *testing.T) {
	cases := []struct {
		status               int
		body, classification string
		usable               bool
	}{
		{200, `{"initialized":true,"sealed":false,"standby":false}`, "active", true},
		{429, `{"initialized":true,"sealed":false,"standby":true}`, "standby", true},
		{200, `{"initialized":true,"sealed":false,"standby":true}`, "standby", true},
		{429, `{"errors":["rate limited"]}`, "invalid-response", false},
		{503, `{"initialized":true,"sealed":true,"standby":false}`, "sealed", false},
		{501, `{"initialized":false,"sealed":true,"standby":false}`, "uninitialized", false},
		{200, `{"initialized":"true","sealed":false,"standby":false}`, "invalid-response", false},
		{200, `{"initialized":true,"sealed":true,"standby":false}`, "http-error", false},
		{302, `{"initialized":true,"sealed":false,"standby":false}`, "http-error", false},
	}
	for _, c := range cases {
		s := classifyHealth(c.status, []byte(c.body))
		if s.Classification != c.classification || s.Usable != c.usable {
			t.Errorf("%d %s: %+v", c.status, c.body, s)
		}
	}
}

func TestRanking(t *testing.T) {
	good := func(v float64) Sample { return Sample{Usable: true, TTFBMs: &v} }
	stable := summarize("104.16.0.1", []Sample{good(100), good(120), good(110)}, 1)
	unstable := summarize("104.16.0.2", []Sample{good(5), {Usable: false}}, 1)
	ranked := rank([]Summary{unstable, stable})
	if len(ranked) != 1 || ranked[0].IP != stable.IP || *stable.MedianTTFBMs != 110 || stable.P95TTFBMs != nil {
		t.Fatalf("ranking: %+v", ranked)
	}
	even := summarize("x", []Sample{good(100), good(120)}, 1)
	if *even.MedianTTFBMs != 110 {
		t.Fatal("even median")
	}
	if summarize("x", nil, 1).Eligible {
		t.Fatal("empty sample eligible")
	}
	samples := []Sample{}
	for n := 1; n <= 20; n++ {
		samples = append(samples, good(float64(n)))
	}
	if *summarize("x", samples, 1).P95TTFBMs != 19 {
		t.Fatal("P95 calculation")
	}
}

func TestAtomicReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "result.json")
	if err := writeReport(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatal("replacement failed", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report permission", info.Mode())
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Fatal("temporary file leaked")
	}
}

func TestAtomicReportRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing-directory")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "keep")
	if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(path, []byte("replacement")); err == nil {
		t.Fatal("accepted replacement of a nonempty directory")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "original" {
		t.Fatal("original output damaged", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("temporary file leaked after failed rename", err)
	}
}

func TestCLIValidationAndCancellation(t *testing.T) {
	var out, log bytes.Buffer
	for _, args := range [][]string{{"run"}, {"probe"}, {"probe", "--unknown"}, {"probe", "--config", "missing.json"}} {
		code, err := runCLI(context.Background(), args, &out, &log)
		if code != 1 || err == nil {
			t.Errorf("args %v: %d %v", args, code, err)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ips.txt"), []byte("104.16.0.1"), 0600)
	config := filepath.Join(dir, "config.json")
	os.WriteFile(config, []byte(`{"domain":"example.com","candidateFile":"ips.txt"}`), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := runCLI(ctx, []string{"probe", "--config", config}, &out, &log)
	if code != 1 || err != context.Canceled {
		t.Fatalf("cancellation: %d %v", code, err)
	}
}
