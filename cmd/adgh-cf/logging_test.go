package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptimizerReportOutput(t *testing.T) {
	for _, tc := range []struct {
		name, mode, decision, action string
		pending                      bool
	}{
		{name: "keep", mode: "run", decision: "no eligible candidate; keep current rewrite"},
		{name: "switch", mode: "run", decision: "confirmed improvement", action: "switched"},
		{name: "rollback", mode: "run", decision: "confirmed improvement", action: "rolled-back"},
		{name: "pending dry-run", mode: "dry-run", decision: "pending transaction requires reconciliation by run; no changes made", pending: true},
		{name: "recovery", mode: "run", decision: "reconciled pending change: switched", pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := map[string]any{"mode": tc.mode, "results": []Summary{testSummary("104.17.128.164", 500)}}
			if tc.pending {
				report["decision"] = tc.decision
				report["pending"] = pendingChange{Next: Rewrite{Answer: "104.17.128.164"}}
			} else {
				report["optimizer"] = map[string]any{"currentIp": "103.31.4.18", "suggestedIp": "104.17.128.164", "nextIp": "", "reason": tc.decision, "action": tc.action, "confirmations": 1}
			}
			var full bytes.Buffer
			if code, err := emitOptimizer("", &full, report); err != nil || code != 0 || !json.Valid(full.Bytes()) {
				t.Fatalf("stdout JSON: code=%d err=%v output=%s", code, err, &full)
			}
			path := filepath.Join(t.TempDir(), "last-run.json")
			var concise bytes.Buffer
			if code, err := emitOptimizer(path, &concise, report); err != nil || code != 0 {
				t.Fatalf("file output: code=%d err=%v", code, err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, full.Bytes()) {
				t.Fatal("file report differs from full stdout report", err)
			}
			if strings.Count(concise.String(), "\n") != 1 || !strings.Contains(concise.String(), tc.decision) || strings.Contains(concise.String(), "medianTtfbMs") || !strings.Contains(concise.String(), path) {
				t.Fatalf("unexpected summary: %s", &concise)
			}
			if !tc.pending && (!strings.Contains(concise.String(), "current=103.31.4.18") || !strings.Contains(concise.String(), "confirmations=1") || !strings.Contains(concise.String(), `action="`+tc.action+`"`)) {
				t.Fatalf("missing optimizer outcome: %s", &concise)
			}
		})
	}
}

type failedLogWriter struct{}

func (failedLogWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOptimizerReportOutputFailures(t *testing.T) {
	report := map[string]any{"mode": "run", "decision": "keep current rewrite"}
	dir := t.TempDir()
	var out bytes.Buffer
	// A directory cannot be replaced by a report; never claim it was saved.
	if code, err := emitOptimizer(dir, &out, report); code != 1 || err == nil || out.Len() != 0 {
		t.Fatalf("write failure hidden: code=%d err=%v output=%s", code, err, &out)
	}
	for _, path := range []string{"", filepath.Join(dir, "report.json")} {
		if code, err := emitOptimizer(path, failedLogWriter{}, report); code != 1 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stdout failure hidden: code=%d err=%v", code, err)
		}
	}
}

func TestProbeConciseAndVerboseLogs(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	input := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(input, []byte("104.16.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Direct configuration keeps all network traffic on the local TLS fixture.
	// Its untrusted certificate gives a deterministic failed sample and elimination.
	c := Config{Domain: "127.0.0.1", CandidateFile: input, PinnedIPs: []string{"127.0.0.1"}, MaxCandidates: 1, Port: server.Listener.Addr().(*net.TCPAddr).Port, TCPConcurrency: 1, TCPTimeoutMs: 1000, HTTPSTimeoutMs: 1000, MaxResponseBytes: 1024, SamplesPerIP: 5, MinSuccessRate: 1}
	for _, verbose := range []bool{false, true} {
		for _, fileOutput := range []bool{false, true} {
			var out, logs bytes.Buffer
			path := ""
			if fileOutput {
				path = filepath.Join(dir, "probe.json")
			}
			code, err := runProbe(context.Background(), c, path, &out, &logs, verbose)
			if err != nil || code != 2 {
				t.Fatalf("probe: code=%d err=%v", code, err)
			}
			data := out.Bytes()
			if fileOutput {
				if out.Len() != 0 {
					t.Fatal("file report duplicated to stdout")
				}
				data, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			var report struct{ Results []Summary }
			if err := json.Unmarshal(data, &report); err != nil || len(report.Results) != 1 || len(report.Results[0].Samples) != 1 || report.Results[0].EliminatedReason == "" {
				t.Fatalf("sample detail lost: %s err=%v", data, err)
			}
			for _, message := range []string{"Sample 1/5:", "Eliminated 127.0.0.1:"} {
				if strings.Contains(logs.String(), message) != verbose {
					t.Fatalf("verbose=%v logs=%s", verbose, &logs)
				}
			}
			if !strings.Contains(logs.String(), "Probe complete: tcp=1/1 finalists=1 samples=1 eligible=0 suggested=none") || !strings.Contains(logs.String(), "Baseline DNS failed:") {
				t.Fatalf("summary or DNS warning missing: %s", &logs)
			}
		}
	}
}
