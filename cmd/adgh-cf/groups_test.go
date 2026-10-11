package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func groupFixture(t *testing.T) (Config, map[string]*fakeRewriteAPI, groupDependencies) {
	t.Helper()
	c, err := parseGroupMap(t, groupConfigData(2))
	if err != nil {
		t.Fatal(err)
	}
	c.AdGuardHomeURL = "http://127.0.0.1:3000"
	c.AdGuardHomeDNS = "127.0.0.1:53"
	c.prepared = &candidatePool{}
	apis := map[string]*fakeRewriteAPI{}
	for i, m := range c.Groups[0].Members {
		apis[m.Domain] = &fakeRewriteAPI{rule: Rewrite{Domain: m.Domain, Answer: []string{"103.31.4.18", "104.17.139.37"}[i]}, errorAfterWrite: true}
	}
	d := groupDependencies{
		api: func(mc Config) (rewriteAPI, error) { return apis[mc.Domain], nil },
		resolve: func(ctx context.Context, mc Config) ([]string, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return []string{apis[mc.Domain].rule.Answer}, nil
		},
		probe: func(ctx context.Context, ip string, mc Config) Sample {
			ok := ctx.Err() == nil
			if mc.budget != nil && !mc.budget.take() {
				ok = false
			}
			return Sample{IP: ip, ConnectedIP: ip, Usable: ok}
		},
		measure: func(ctx context.Context, mc Config, out, log io.Writer) (int, error) {
			return 0, json.NewEncoder(out).Encode(map[string]any{"ranking": []string{"104.17.128.164", "104.17.142.212"}, "results": []Summary{testSummary("104.17.128.164", 100), testSummary("104.17.142.212", 150), testSummary("103.31.4.18", 300)}})
		},
		save: saveGroupsState,
	}
	return c, apis, d
}
func runGroupTest(t *testing.T, c Config, d groupDependencies, command, selected string, dry bool) (int, groupsReport, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := executeGroups(context.Background(), c, command, selected, dry, "", &out, io.Discard, d)
	var r groupsReport
	if out.Len() > 0 {
		if e := json.Unmarshal(out.Bytes(), &r); e != nil {
			t.Fatal(e, out.String())
		}
	}
	return code, r, err
}
func TestGroupsDryRunConfirmationUpdate(t *testing.T) {
	c, apis, d := groupFixture(t)
	code, r, err := runGroupTest(t, c, d, "run", "", true)
	if err != nil || code != 0 || r.Groups[0].Confirmations != 1 {
		t.Fatal(code, r, err)
	}
	if _, err := os.Stat(c.StateFile); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote state")
	}
	for _, a := range apis {
		if a.writes != 0 {
			t.Fatal("dry-run wrote DNS")
		}
	}
	code, _, err = runGroupTest(t, c, d, "run", "", false)
	if err != nil || code != 0 {
		t.Fatal(code, err)
	}
	s, err := loadGroupsState(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Groups["g0"].LastRun = time.Now().Add(-time.Hour)
	if err := saveGroupsState(c, s); err != nil {
		t.Fatal(err)
	}
	code, r, err = runGroupTest(t, c, d, "run", "", false)
	if err != nil || code != 0 || r.Groups[0].Status != "switched" {
		t.Fatal(code, r, err)
	}
	for _, a := range apis {
		if a.writes != 1 || a.rule.Answer != "104.17.128.164" {
			t.Fatal("uncertain response repeated or not resolved", a)
		}
	}
	s, err = loadGroupsState(c)
	if err != nil || s.Pending != nil || s.Groups["g0"].LastSwitch.IsZero() {
		t.Fatal(s, err)
	}
}
func TestGroupFallbackNoSharedAndBudget(t *testing.T) {
	for _, mode := range []string{"fallback", "no-shared", "budget"} {
		t.Run(mode, func(t *testing.T) {
			c, _, d := groupFixture(t)
			base := d.probe
			d.probe = func(ctx context.Context, ip string, mc Config) Sample {
				s := base(ctx, ip, mc)
				if mc.Domain == c.Groups[0].Members[1].Domain && (mode == "no-shared" || ip == "104.17.128.164") {
					s.Usable = false
				}
				return s
			}
			if mode == "budget" {
				c.MaxRequestsPerGroup = 1
			}
			code, r, err := runGroupTest(t, c, d, "probe", "", false)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "fallback" {
				if code != 0 || r.Groups[0].Suggested != "104.17.142.212" || r.Groups[0].PrimarySuggestion != "104.17.128.164" {
					t.Fatal(code, r)
				}
			} else if code != 2 || r.Groups[0].Suggested != "" {
				t.Fatal(code, r)
			}
		})
	}
}
func TestGroupAlignmentFingerprintAndCooldown(t *testing.T) {
	c, apis, _ := groupFixture(t)
	g := c.Groups[0]
	current := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
	s := groupState{}
	now := time.Now()
	results := []Summary{testSummary(current[0].Answer, 100)}
	next, reason := chooseGroup(c, g, &s, current, results, current[0].Answer, now)
	if next != "" || !strings.Contains(reason, "alignment") {
		t.Fatal(next, reason)
	}
	next, _ = chooseGroup(c, g, &s, current, results, current[0].Answer, now.Add(6*time.Minute))
	if next != current[0].Answer {
		t.Fatal("alignment not confirmed")
	}
	reordered := g
	reordered.Members = []GroupMember{g.Members[1], g.Members[0]}
	if groupFingerprint(c, g) != groupFingerprint(c, reordered) {
		t.Fatal("order changed fingerprint")
	}
	s.LastSwitch = now
	c.SamplesPerIP++
	next, reason = chooseGroup(c, g, &s, current, results, current[0].Answer, now.Add(7*time.Minute))
	if next != "" || reason != "switch cooldown active" {
		t.Fatal("config bypassed cooldown")
	}
}
func TestPendingRecoveryAtEachWriteBoundary(t *testing.T) {
	for written := 0; written <= 2; written++ {
		t.Run(fmt.Sprint(written), func(t *testing.T) {
			c, apis, d := groupFixture(t)
			g := c.Groups[0]
			old := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
			p := newGroupPending(c, g, old, "104.17.128.164", time.Now())
			s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: p}
			if err := saveGroupsState(c, s); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < written; i++ {
				apis[g.Members[i].Domain].rule = p.Members[i].Next
			} // Simulate crash before progress was saved.
			code, report, err := runGroupTest(t, c, d, "run", "", false)
			if err != nil || code != 0 {
				t.Fatal(code, report, err)
			}
			for i, m := range g.Members {
				want := old[i].Answer
				if written == 2 {
					want = p.Members[i].Next.Answer
				}
				if apis[m.Domain].rule.Answer != want {
					t.Fatal("wrong recovered value")
				}
				if written == 2 && apis[m.Domain].writes != 0 {
					t.Fatal("replayed PUT")
				}
			}
			loaded, err := loadGroupsState(c)
			if err != nil || loaded.Pending != nil {
				t.Fatal(loaded, err)
			}
		})
	}
}
func TestPendingManualChangeUnhealthyAndTimeout(t *testing.T) {
	for _, mode := range []string{"manual", "unhealthy", "timeout", "dns"} {
		t.Run(mode, func(t *testing.T) {
			c, apis, d := groupFixture(t)
			g := c.Groups[0]
			old := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
			p := newGroupPending(c, g, old, "104.17.128.164", time.Now())
			s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: p}
			apis[g.Members[0].Domain].rule = p.Members[0].Next
			if mode == "manual" {
				apis[g.Members[0].Domain].rule.Answer = "104.17.142.212"
			}
			if mode == "unhealthy" {
				d.probe = func(context.Context, string, Config) Sample { return Sample{Usable: false} }
			}
			if mode == "dns" {
				d.resolve = func(context.Context, Config) ([]string, error) { return nil, fmt.Errorf("DNS failure") }
			}
			ctx := context.Background()
			if mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := recoverGroup(ctx, c, &s, d)
			if err == nil || s.Pending == nil {
				t.Fatal("pending lost", err)
			}
			if mode == "manual" && apis[g.Members[0].Domain].rule.Answer != "104.17.142.212" {
				t.Fatal("manual overwrite")
			}
			if mode == "unhealthy" && apis[g.Members[0].Domain].writes != 0 {
				t.Fatal("unhealthy compensation")
			}
			disk, err := loadGroupsState(c)
			if err != nil || disk.Pending == nil {
				t.Fatal("pending not durable", err)
			}
		})
	}
}
func TestGroupPersistenceFailureBeforeWrite(t *testing.T) {
	c, apis, d := groupFixture(t)
	_, _, err := runGroupTest(t, c, d, "run", "", false)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := loadGroupsState(c)
	s.Groups["g0"].LastRun = time.Now().Add(-time.Hour)
	if err := saveGroupsState(c, s); err != nil {
		t.Fatal(err)
	}
	d.save = func(Config, groupsState) error { return fmt.Errorf("disk full") }
	code, _, err := runGroupTest(t, c, d, "run", "", false)
	if code != 1 || err == nil {
		t.Fatal("save failure ignored")
	}
	for _, a := range apis {
		if a.writes != 0 {
			t.Fatal("DNS written before durable pending")
		}
	}
}
func TestPendingDryRunFilterAndFingerprint(t *testing.T) {
	c, apis, d := groupFixture(t)
	g := c.Groups[0]
	old := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
	s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: newGroupPending(c, g, old, "104.17.128.164", time.Now())}
	if err := saveGroupsState(c, s); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.StateFile)
	code, report, err := runGroupTest(t, c, d, "run", "g0", true)
	if code != 1 || err == nil || report.Recovery == nil {
		t.Fatal("pending not reported")
	}
	after, _ := os.ReadFile(c.StateFile)
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run changed pending")
	}
	c.Groups[0].Members[0].URL += "changed"
	if _, err := loadGroupsState(c); err == nil {
		t.Fatal("pending fingerprint ignored")
	}
}

type failingGroupAPI struct {
	*fakeRewriteAPI
	fail bool
}

func (a *failingGroupAPI) update(ctx context.Context, old, next Rewrite) error {
	if a.fail {
		return fmt.Errorf("injected PUT failure")
	}
	return a.fakeRewriteAPI.update(ctx, old, next)
}
func TestNthWriteFailureCompensatesInReverse(t *testing.T) {
	c, apis, d := groupFixture(t)
	g := c.Groups[0]
	old := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
	s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: newGroupPending(c, g, old, "104.17.128.164", time.Now())}
	if err := saveGroupsState(c, s); err != nil {
		t.Fatal(err)
	}
	ordered := []rewriteAPI{apis[g.Members[0].Domain], &failingGroupAPI{apis[g.Members[1].Domain], true}}
	if err := applyGroup(context.Background(), c, &s, ordered, d); err == nil {
		t.Fatal("failure ignored")
	}
	if _, err := recoverGroup(context.Background(), c, &s, d); err != nil {
		t.Fatal(err)
	}
	for i, m := range g.Members {
		if apis[m.Domain].rule.Answer != old[i].Answer {
			t.Fatal("partial switch left behind")
		}
	}
	if apis[g.Members[0].Domain].writes != 2 || apis[g.Members[1].Domain].writes != 0 {
		t.Fatal("unexpected write count")
	}
}
func TestCrashAtEveryGroupPersistenceBoundary(t *testing.T) {
	// Two progress saves, plus the final commit. A crash is injected after each
	// durable save; the recovered process starts with only on-disk state.
	for boundary := 1; boundary <= 3; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			c, apis, d := groupFixture(t)
			g := c.Groups[0]
			old := []Rewrite{apis[g.Members[0].Domain].rule, apis[g.Members[1].Domain].rule}
			s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: newGroupPending(c, g, old, "104.17.128.164", time.Now())}
			if err := saveGroupsState(c, s); err != nil {
				t.Fatal(err)
			}
			saves := 0
			base := d.save
			d.save = func(c Config, s groupsState) error {
				if err := base(c, s); err != nil {
					return err
				}
				saves++
				if saves == boundary {
					panic("simulated process death")
				}
				return nil
			}
			func() {
				defer func() {
					if r := recover(); r != "simulated process death" {
						t.Fatalf("unexpected panic: %v", r)
					}
				}()
				if err := applyGroup(context.Background(), c, &s, []rewriteAPI{apis[g.Members[0].Domain], apis[g.Members[1].Domain]}, d); err != nil {
					t.Fatal(err)
				}
				if _, err := recoverGroup(context.Background(), c, &s, d); err != nil {
					t.Fatal(err)
				}
			}()
			d.save = base
			loaded, err := loadGroupsState(c)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Pending != nil {
				if _, err := recoverGroup(context.Background(), c, &loaded, d); err != nil {
					t.Fatal(err)
				}
			}
			want := "104.17.128.164"
			if boundary == 1 {
				want = old[0].Answer
			}
			if apis[g.Members[0].Domain].rule.Answer != want {
				t.Fatal("incorrect post-crash recovery")
			}
		})
	}
}
func TestGroupSelectionIsolationAndPendingBeforeFilter(t *testing.T) {
	c, apis, d := groupFixture(t)
	second := DomainGroup{ID: "g1", Primary: "other.example.com", Members: []GroupMember{{Domain: "other.example.com", URL: "https://other.example.com/", Mode: "https"}}}
	c.Groups = append(c.Groups, second)
	apis[second.Primary] = &fakeRewriteAPI{rule: Rewrite{Domain: second.Primary, Answer: "103.31.4.18"}}
	measured := []string{}
	base := d.measure
	d.measure = func(ctx context.Context, c Config, out, log io.Writer) (int, error) {
		measured = append(measured, c.Domain)
		return base(ctx, c, out, log)
	}
	code, r, err := runGroupTest(t, c, d, "probe", "g1", false)
	if err != nil || code != 0 || len(r.Groups) != 1 || len(measured) != 1 || measured[0] != second.Primary {
		t.Fatal(code, r, err, measured)
	}
	old := []Rewrite{}
	for _, m := range c.Groups[0].Members {
		old = append(old, apis[m.Domain].rule)
	}
	s := groupsState{Version: 2, Groups: map[string]*groupState{}, Pending: newGroupPending(c, c.Groups[0], old, "104.17.128.164", time.Now())}
	if err := saveGroupsState(c, s); err != nil {
		t.Fatal(err)
	}
	measured = nil
	code, r, err = runGroupTest(t, c, d, "run", "g1", false)
	if err != nil || code != 0 || r.Recovery == nil || len(measured) != 0 {
		t.Fatal("filter bypassed pending", code, r, err)
	}
}
func TestGroupStateVersionSizeAndLock(t *testing.T) {
	c, _, d := groupFixture(t)
	if err := writeReport(c.StateFile, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGroupsState(c); err == nil {
		t.Fatal("v1 state accepted")
	}
	large := groupsState{Version: 2, Groups: map[string]*groupState{"g0": {Fingerprint: strings.Repeat("x", 4*1024*1024)}}}
	if err := saveGroupsState(c, large); err == nil {
		t.Fatal("oversized state accepted")
	}
	unlock, err := lockOptimizer(c.StateFile + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	code, _, err := runGroupTest(t, c, d, "run", "", true)
	if err == nil || code != 1 {
		t.Fatal("concurrent run accepted")
	}
}

func TestGroupReconfigurationKeepsStateBoundedAndCooldown(t *testing.T) {
	c, apis, _ := groupFixture(t)
	last := time.Now()
	s := groupsState{Version: 2, Groups: map[string]*groupState{"old-id": {LastSwitch: last, Observed: []Rewrite{apis[c.Groups[0].Primary].rule}}}}
	alignGroupStates(c, &s)
	if len(s.Groups) != 1 || !s.Groups["g0"].LastSwitch.Equal(last) {
		t.Fatal("rename bypassed cooldown or leaked group state")
	}
	for _, data := range []string{`{}`, `null`, `{"groups":{}}`, `{"version":null,"groups":{}}`, `{"version":2}`} {
		if err := writeReport(c.StateFile, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadGroupsState(c); err == nil {
			t.Fatalf("accepted incomplete state %s", data)
		}
	}
}

func TestGroupDeadlineDuringDNSIsBudgetFailure(t *testing.T) {
	c, apis, d := groupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.resolve = func(context.Context, Config) ([]string, error) { cancel(); return nil, context.Canceled }
	var out bytes.Buffer
	code, err := executeGroups(ctx, c, "run", "", false, "", &out, io.Discard, d)
	if code != 2 || err != nil || !strings.Contains(out.String(), "budget-exhausted") {
		t.Fatal(code, err, out.String())
	}
	for _, a := range apis {
		if a.writes != 0 {
			t.Fatal("deadline wrote DNS")
		}
	}
}
