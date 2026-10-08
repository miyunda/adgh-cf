package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSummary(ip string, ms float64) Summary {
	return Summary{IP: ip, Eligible: true, SampleCount: 5, SuccessRate: 1, MedianTTFBMs: &ms}
}

func TestOptimizerDryRunThenConfirmedUpdateAndRecovery(t *testing.T) {
	c := Config{Domain: "example.com", AdGuardHomeURL: "http://127.0.0.1:3000", AdGuardHomeDNS: "127.0.0.1:53", StateFile: filepath.Join(t.TempDir(), "optimizer.json"), ConfirmRuns: 2, CooldownMinutes: 30, MinImprovement: .15}
	api := &fakeRewriteAPI{rule: Rewrite{Domain: c.Domain, Answer: "103.31.4.18"}, errorAfterWrite: true}
	measures := 0
	d := optimizerDependencies{api: api, resolve: func(context.Context) ([]string, error) { return []string{api.rule.Answer}, nil }, verify: func(context.Context, string) error { return nil }, healthy: func(context.Context, string) bool { return true }, measure: func(_ context.Context, measured Config, _ string, out, log io.Writer) (int, error) {
		measures++
		if len(measured.PinnedIPs) == 0 || measured.PinnedIPs[0] != api.rule.Answer {
			t.Error("current address not preserved for measurement")
		}
		return 0, json.NewEncoder(out).Encode(map[string]any{"results": []Summary{testSummary("104.17.128.164", 500), testSummary("103.31.4.18", 700)}})
	}}
	var out, log bytes.Buffer
	code, err := executeOptimizer(context.Background(), c, true, "", &out, &log, d)
	if err != nil || code != 0 || api.writes != 0 {
		t.Fatal("dry-run wrote rule", err)
	}
	if _, err := os.Stat(c.StateFile); !os.IsNotExist(err) {
		t.Fatal("dry-run advanced state")
	}
	out.Reset()
	reportPath := filepath.Join(filepath.Dir(c.StateFile), "last-run.json")
	if _, err := executeOptimizer(context.Background(), c, false, reportPath, &out, &log, d); err != nil || api.writes != 0 {
		t.Fatal("first confirmation wrote", err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil || !json.Valid(data) || !bytes.Contains(data, []byte(`"results"`)) || !strings.Contains(out.String(), "confirmations=1") || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("confirmation summary or full file report missing", err, out.String())
	}
	s, err := loadOptimizerState(c)
	if err != nil || s.Streak != 1 {
		t.Fatal("observation not saved")
	}
	s.LastRun = time.Now().Add(-time.Hour)
	saveOptimizerState(c, s)
	out.Reset()
	if _, err := executeOptimizer(context.Background(), c, false, reportPath, &out, &log, d); err != nil || api.writes != 1 || api.rule.Answer != "104.17.128.164" {
		t.Fatal("confirmed switch failed", err)
	}
	if !strings.Contains(out.String(), `action="switched"`) || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("actual switch missing from summary", out.String())
	}
	s, err = loadOptimizerState(c)
	if err != nil || s.Pending != nil || s.LastSwitch.IsZero() {
		t.Fatal("transaction not finalized", err)
	}
	// Simulate a crash after a successful PUT; recovery must verify, not repeat it.
	s.Pending = &pendingChange{Old: Rewrite{Domain: c.Domain, Answer: "103.31.4.18"}, Next: api.rule, StartedAt: time.Now()}
	saveOptimizerState(c, s)
	before := measures
	out.Reset()
	if _, err := executeOptimizer(context.Background(), c, false, reportPath, &out, &log, d); err != nil || api.writes != 1 || measures != before {
		t.Fatal("recovery repeated measurement/write", err)
	}
	if !strings.Contains(out.String(), "reconciled pending change: switched") || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("recovery missing from summary", out.String())
	}
	s, _ = loadOptimizerState(c)
	if s.Pending != nil {
		t.Fatal("journal not cleared")
	}
	if _, err := executeOptimizer(context.Background(), c, false, c.StateFile, &out, &log, d); err == nil {
		t.Fatal("report overwrote optimizer state")
	}
}

func TestSelectionConfirmCooldownAndManualEdit(t *testing.T) {
	c := Config{ConfirmRuns: 2, CooldownMinutes: 30, MinImprovement: .15}
	now := time.Now().UTC()
	s := optimizerState{}
	results := []Summary{testSummary("104.17.128.164", 500), testSummary("103.31.4.18", 700)}
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now); next != "" || s.Streak != 1 {
		t.Fatal("first run must observe")
	}
	s.LastRun = now
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now.Add(time.Minute)); next != "" || s.Streak != 1 {
		t.Fatal("rapid repeats counted")
	}
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now.Add(time.Hour)); next != "104.17.128.164" {
		t.Fatal("confirmation missing")
	}
	s.LastSwitch = now
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now.Add(10*time.Minute)); next != "" {
		t.Fatal("cooldown ignored")
	}
	s.LastSwitch = time.Time{}
	s.Observed = "104.17.139.37"
	s.Streak = 2
	s.Winner = "104.17.128.164"
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now.Add(time.Hour)); next != "" || s.Streak != 1 {
		t.Fatal("manual change did not reset streak")
	}
	s.LastRun = now
	if next, _ := chooseChange(c, &s, "103.31.4.18", results, now.Add(4*time.Hour)); next != "" || s.Streak != 1 {
		t.Fatal("stale confirmation reused")
	}
	closeResults := []Summary{testSummary("104.17.128.164", 699), testSummary("103.31.4.18", 700)}
	if next, _ := chooseChange(c, &s, "103.31.4.18", closeResults, now.Add(time.Hour)); next != "" || s.Streak != 0 {
		t.Fatal("tiny improvement switched")
	}
	if next, _ := chooseChange(c, &s, "103.31.4.18", nil, now); next != "" {
		t.Fatal("empty result switched")
	}
}

func TestEliminationAndRelaxedSuccessRate(t *testing.T) {
	c := Config{SamplesPerIP: 5, MinSuccessRate: 1, MaxTTFBMs: 1000}
	ms := 1001.0
	if eliminationReason([]Sample{{Usable: true, TTFBMs: &ms}}, c) == "" {
		t.Fatal("slow sample survived")
	}
	ms = 1000
	if eliminationReason([]Sample{{Usable: true, TTFBMs: &ms}}, c) != "" {
		t.Fatal("threshold equality rejected")
	}
	if eliminationReason([]Sample{{Usable: false}}, c) == "" {
		t.Fatal("impossible success rate survived")
	}
	c.MinSuccessRate = .8
	if eliminationReason([]Sample{{Usable: false}}, c) != "" {
		t.Fatal("one failure prematurely eliminated")
	}
	if eliminationReason([]Sample{{Usable: false}, {Usable: false}}, c) == "" {
		t.Fatal("two failures allowed at .8")
	}
}

type fakeRewriteAPI struct {
	rule            Rewrite
	writes          int
	errorAfterWrite bool
	onRead          func(int, *fakeRewriteAPI)
	reads           int
}

func (f *fakeRewriteAPI) current(context.Context) (Rewrite, error) {
	f.reads++
	if f.onRead != nil {
		f.onRead(f.reads, f)
	}
	return f.rule, nil
}
func (f *fakeRewriteAPI) update(_ context.Context, old, next Rewrite) error {
	if !sameRewrite(f.rule, old) {
		return fmt.Errorf("conflict")
	}
	f.rule = next
	f.writes++
	if f.errorAfterWrite {
		return fmt.Errorf("timeout")
	}
	return nil
}

func TestUncertainWriteRollbackAndManualChanges(t *testing.T) {
	p := pendingChange{Old: Rewrite{Domain: "example.com", Answer: "103.31.4.18"}, Next: Rewrite{Domain: "example.com", Answer: "104.17.128.164"}, StartedAt: time.Now()}
	good := func(context.Context, string) error { return nil }
	healthy := func(context.Context, string) bool { return true }
	api := &fakeRewriteAPI{rule: p.Old, errorAfterWrite: true}
	api.update(context.Background(), p.Old, p.Next)
	action, err := finishChange(context.Background(), api, p, good, healthy)
	if err != nil || action != "switched" || api.writes != 1 {
		t.Fatal("uncertain committed update was repeated", action, err)
	}
	badNew := func(_ context.Context, ip string) error {
		if ip == p.Next.Answer {
			return fmt.Errorf("DNS failure")
		}
		return nil
	}
	action, err = finishChange(context.Background(), api, p, badNew, healthy)
	if err != nil || action != "rolled-back" || api.rule.Answer != p.Old.Answer || api.writes != 2 {
		t.Fatal("conditional rollback failed", action, err)
	}
	api = &fakeRewriteAPI{rule: p.Next, onRead: func(n int, f *fakeRewriteAPI) {
		if n == 2 {
			f.rule.Answer = "104.17.139.37"
		}
	}}
	if _, err := finishChange(context.Background(), api, p, badNew, healthy); err == nil || api.writes != 0 {
		t.Fatal("manual change overwritten")
	}
	api = &fakeRewriteAPI{rule: p.Next}
	if _, err := finishChange(context.Background(), api, p, badNew, func(context.Context, string) bool { return false }); err == nil || api.writes != 0 {
		t.Fatal("rolled back to unhealthy old target")
	}
}

func TestAdGuardAPIAuthExactUpdateAndValidation(t *testing.T) {
	var updates int
	rule := Rewrite{Domain: "example.com", Answer: "103.31.4.18"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/control/rewrite/list":
			json.NewEncoder(w).Encode([]Rewrite{rule, {Domain: "unrelated.example.com", Answer: "1.1.1.1"}})
		case "/control/rewrite/update":
			if r.Method != "PUT" {
				t.Error("wrong update method")
			}
			var b struct {
				Target Rewrite `json:"target"`
				Update Rewrite `json:"update"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil || !sameRewrite(b.Target, rule) || b.Update.Domain != rule.Domain {
				t.Error("wrong exact update target")
			}
			updates++
			rule = b.Update
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := Config{Domain: "example.com", AdGuardHomeURL: server.URL, adghUsername: "admin", adghPassword: "secret"}
	api, err := newAdGuardClient(c)
	if err != nil {
		t.Fatal(err)
	}
	defer api.client.CloseIdleConnections()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	r, err := api.current(context.Background())
	if err != nil || r.Answer != rule.Answer {
		t.Fatal("read failed", err)
	}
	if err := api.update(context.Background(), r, Rewrite{Domain: r.Domain, Answer: "104.17.128.164"}); err != nil || updates != 1 {
		t.Fatal("update failed", err)
	}
	for _, list := range [][]Rewrite{nil, {rule, rule}, {{Domain: "example.com", Answer: "alias.example.com"}}, {{Domain: "example.com", Answer: "::1"}}} {
		if _, err := findRewrite(list, "example.com"); err == nil {
			t.Fatal("unsafe rule accepted")
		}
	}
	no := false
	rule.Enabled = &no
	if _, err := findRewrite([]Rewrite{rule}, "example.com"); err == nil {
		t.Fatal("disabled rule accepted")
	}
	api.config.adghPassword = "wrong"
	if _, err := api.current(context.Background()); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong") {
		t.Fatal("authentication failure not sanitized")
	}
}

func TestOptimizerStateLockAndCredentialFile(t *testing.T) {
	dir := t.TempDir()
	c := Config{StateFile: filepath.Join(dir, "state.json"), Domain: "example.com", AdGuardHomeURL: "http://127.0.0.1:3000", AdGuardHomeDNS: "127.0.0.1:53"}
	unlock, err := lockOptimizer(c.StateFile + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockOptimizer(c.StateFile + ".lock"); err == nil {
		second()
		t.Fatal("concurrent lock acquired")
	}
	unlock()
	unlock, err = lockOptimizer(c.StateFile + ".lock")
	if err != nil {
		t.Fatal("lock not released")
	}
	unlock()
	s, err := loadOptimizerState(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Pending = &pendingChange{Old: Rewrite{Domain: c.Domain, Answer: "103.31.4.18"}, Next: Rewrite{Domain: c.Domain, Answer: "104.17.128.164"}, StartedAt: time.Now()}
	if err := saveOptimizerState(c, s); err != nil {
		t.Fatal(err)
	}
	s, err = loadOptimizerState(c)
	if err != nil || s.Pending == nil {
		t.Fatal("pending journal lost")
	}
	c.Domain = "different.example.com"
	if _, err := loadOptimizerState(c); err == nil {
		t.Fatal("cross-target state reused")
	}
	os.WriteFile(c.StateFile, []byte("corrupted"), 0600)
	if _, err := loadOptimizerState(c); err == nil {
		t.Fatal("corrupted state accepted")
	}
	env := filepath.Join(dir, ".env")
	os.WriteFile(filepath.Join(dir, "password"), []byte("p@ss$word\n"), 0600)
	os.WriteFile(env, []byte("ADGH_USERNAME=admin\nADGH_PASSWORD_FILE=password\n"), 0600)
	u, p, err := loadAdGuardCredentials(env, func(string) (string, bool) { return "", false })
	if err != nil || u != "admin" || p != "p@ss$word" {
		t.Fatal("password file failed", err)
	}
	_, _, err = loadAdGuardCredentials(env, func(k string) (string, bool) { return "othersecret", k == "ADGH_PASSWORD" })
	if err == nil {
		t.Fatal("conflicting password sources accepted")
	}
	b, _ := json.Marshal(Config{adghUsername: "admin", adghPassword: "secret"})
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "admin") {
		t.Fatal("credentials in report")
	}
}
