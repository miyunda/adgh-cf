package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type groupHistory struct {
	At        time.Time `json:"at"`
	Suggested string    `json:"suggested,omitempty"`
	Decision  string    `json:"decision"`
}
type groupState struct {
	Fingerprint string         `json:"fingerprint"`
	Observed    []Rewrite      `json:"observed"`
	Winner      string         `json:"winner"`
	Streak      int            `json:"streak"`
	LastRun     time.Time      `json:"lastRun"`
	LastSwitch  time.Time      `json:"lastSwitch"`
	History     []groupHistory `json:"history"`
}
type memberChange struct {
	Old      Rewrite  `json:"old"`
	Next     Rewrite  `json:"next"`
	Actual   *Rewrite `json:"actual,omitempty"`
	Progress string   `json:"progress"`
	Error    string   `json:"error,omitempty"`
}
type groupPending struct {
	ID          string         `json:"transactionId"`
	GroupID     string         `json:"groupId"`
	Fingerprint string         `json:"fingerprint"`
	StartedAt   time.Time      `json:"startedAt"`
	Members     []memberChange `json:"members"`
	Outcome     string         `json:"outcome"`
}
type groupsState struct {
	Version int                    `json:"version"`
	Groups  map[string]*groupState `json:"groups"`
	Pending *groupPending          `json:"pending,omitempty"`
}

func groupFingerprint(c Config, g DomainGroup) string {
	g.Members = append([]GroupMember{}, g.Members...)
	sort.Slice(g.Members, func(i, j int) bool { return g.Members[i].Domain < g.Members[j].Domain })
	// Include measurement/selection settings and backend identity, never secrets.
	payload := []any{g, c.AdGuardHomeURL, c.AdGuardHomeDNS, c.SamplesPerIP, c.Finalists, c.MinSuccessRate, c.MaxTTFBMs, c.MinImprovement, c.ConfirmRuns, c.CooldownMinutes, c.HTTPSTimeoutMs, c.TCPTimeoutMs, c.MaxResponseBytes, c.RequestIntervalMs, c.MaxCandidates, c.MaxRequestsPerGroup, c.MaxRunSeconds, c.BaselineDNSServers, c.PinnedIPs, c.SampleOffset, c.TCPConcurrency}
	data, _ := json.Marshal(payload)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func loadGroupsState(c Config) (groupsState, error) {
	s := groupsState{Version: 2, Groups: map[string]*groupState{}}
	f, err := os.Open(c.StateFile)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return s, fmt.Errorf("state unreadable or exceeds 4 MiB")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return s, fmt.Errorf("invalid v2 state JSON")
	}
	if string(fields["version"]) != "2" || len(fields["groups"]) == 0 || bytes.Equal(bytes.TrimSpace(fields["groups"]), []byte("null")) {
		return s, fmt.Errorf("v2 requires explicit version 2 and groups state; use a separate stateFile after v1 recovery")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return s, fmt.Errorf("invalid v2 state; v1 requires a separate new stateFile: %w", err)
	}
	if s.Version != 2 || s.Groups == nil {
		return s, fmt.Errorf("v2 requires version 2 state; finish v1 pending with old config and use a new stateFile")
	}
	if len(s.Groups) > 4 {
		return s, fmt.Errorf("state contains more than 4 groups")
	}
	for id, g := range s.Groups {
		if g == nil || g.Streak < 0 || g.Streak > 10 || len(g.History) > 48 || len(g.Observed) > 8 || g.LastRun.After(time.Now().Add(time.Minute)) || g.LastSwitch.After(time.Now().Add(time.Minute)) {
			return s, fmt.Errorf("invalid state bounds for %s", id)
		}
	}
	if p := s.Pending; p != nil {
		var group *DomainGroup
		for i := range c.Groups {
			if c.Groups[i].ID == p.GroupID {
				group = &c.Groups[i]
			}
		}
		if group == nil || p.Fingerprint != groupFingerprint(c, *group) {
			return s, fmt.Errorf("pending configuration differs; restore original configuration before recovery")
		}
		if p.ID == "" || p.StartedAt.IsZero() || p.StartedAt.After(time.Now().Add(time.Minute)) || len(p.Members) != len(group.Members) {
			return s, fmt.Errorf("invalid pending transaction")
		}
		seen := map[string]bool{}
		next := ""
		for _, m := range p.Members {
			domain := normalizeDomain(m.Old.Domain)
			exists := false
			for _, member := range group.Members {
				if member.Domain == domain {
					exists = true
				}
			}
			if !exists || seen[domain] || !publicIPv4(m.Old.Answer) || !publicIPv4(m.Next.Answer) || m.Old.Domain != m.Next.Domain || (m.Old.Enabled != nil && !*m.Old.Enabled) || (m.Next.Enabled != nil && !*m.Next.Enabled) || (next != "" && next != m.Next.Answer) {
				return s, fmt.Errorf("invalid pending member")
			}
			seen[domain] = true
			next = m.Next.Answer
		}
	}
	return s, nil
}
func saveGroupsState(c Config, s groupsState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > 4*1024*1024 {
		return fmt.Errorf("state exceeds 4 MiB; no further DNS writes permitted")
	}
	return writeReport(c.StateFile, append(data, '\n'))
}
func resetGroupConfirmation(s *groupsState, id string) {
	if g := s.Groups[id]; g != nil {
		g.Streak = 0
		g.Winner = ""
	}
}
func equalObserved(a, b []Rewrite) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if sameRewrite(x, y) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func chooseGroup(c Config, g DomainGroup, s *groupState, current []Rewrite, results []Summary, winner string, now time.Time) (string, string) {
	fp := groupFingerprint(c, g)
	if s.Fingerprint != fp || !equalObserved(s.Observed, current) || now.Sub(s.LastRun) > 3*time.Hour || now.Before(s.LastRun) {
		s.Streak = 0
		s.Winner = ""
	}
	lastRun := s.LastRun
	s.LastRun = now
	s.Fingerprint = fp
	s.Observed = append([]Rewrite{}, current...)
	reject := func(reason string) (string, string) { s.Streak = 0; s.Winner = ""; return "", reason }
	if winner == "" {
		return reject("no shared candidate; keep all rewrites")
	}
	primaryIP := ""
	aligned := true
	for _, r := range current {
		if sameDomain(r.Domain, g.Primary) {
			primaryIP = r.Answer
		}
		if r.Answer != winner {
			aligned = false
		}
	}
	if aligned {
		return reject("group already uses shared candidate")
	}
	if now.Sub(s.LastSwitch) < time.Duration(c.CooldownMinutes)*time.Minute {
		return reject("switch cooldown active")
	}
	reason := "candidate confirmed"
	if winner == primaryIP {
		reason = "group alignment; no primary performance improvement claimed"
	} else {
		var old, best *Summary
		for i := range results {
			if results[i].IP == primaryIP {
				old = &results[i]
			}
			if results[i].IP == winner {
				best = &results[i]
			}
		}
		if old == nil || best == nil {
			return reject("primary current/candidate measurement missing")
		}
		if old.Eligible && (old.MedianTTFBMs == nil || best.MedianTTFBMs == nil || *old.MedianTTFBMs <= 0 || 1 - *best.MedianTTFBMs / *old.MedianTTFBMs < c.MinImprovement) {
			return reject("primary improvement below threshold")
		}
	}
	if s.Winner != winner {
		s.Winner = winner
		s.Streak = 1
	} else if now.Sub(lastRun) >= 5*time.Minute {
		s.Streak = min(c.ConfirmRuns, s.Streak+1)
	}
	if s.Streak < c.ConfirmRuns {
		return "", fmt.Sprintf("awaiting confirmation %d/%d: %s", s.Streak, c.ConfirmRuns, reason)
	}
	return winner, reason
}
func newGroupPending(c Config, g DomainGroup, current []Rewrite, next string, now time.Time) *groupPending {
	p := &groupPending{ID: fmt.Sprintf("%s-%d", g.ID, now.UnixNano()), GroupID: g.ID, Fingerprint: groupFingerprint(c, g), StartedAt: now, Outcome: "pending", Members: []memberChange{}}
	for _, old := range current {
		target := old
		target.Answer = next
		progress := "prepared"
		if old.Answer == next {
			progress = "unchanged"
		}
		p.Members = append(p.Members, memberChange{Old: old, Next: target, Progress: progress})
	}
	return p
}
func applyGroup(ctx context.Context, c Config, s *groupsState, apis []rewriteAPI, d groupDependencies) error {
	for i := range s.Pending.Members {
		m := &s.Pending.Members[i]
		actual, err := apis[i].current(ctx)
		if err != nil {
			return err
		}
		m.Actual = &actual
		if !sameRewrite(actual, m.Old) {
			return fmt.Errorf("%s changed before its update", m.Old.Domain)
		}
		if sameRewrite(m.Old, m.Next) {
			continue
		}
		writeErr := apis[i].update(ctx, m.Old, m.Next)
		actual, err = apis[i].current(ctx)
		if err != nil {
			return fmt.Errorf("%s write outcome unknown: %w", m.Old.Domain, err)
		}
		m.Actual = &actual
		if !sameRewrite(actual, m.Next) {
			if writeErr != nil {
				return writeErr
			}
			return fmt.Errorf("%s update not applied", m.Old.Domain)
		}
		m.Progress = "written"
		if err := d.save(c, *s); err != nil {
			return err
		}
	}
	return nil
}

// Reconstruct outcomes from old/next/actual, never trust a saved progress label.
// New-address verification is at most once per member. Compensation uses one
// old-address health check followed by DNS-only confirmation (no third probe).
func recoverGroup(ctx context.Context, c Config, s *groupsState, d groupDependencies) (int, error) {
	p := s.Pending
	var group DomainGroup
	for _, g := range c.Groups {
		if g.ID == p.GroupID {
			group = g
		}
	}
	budget := &requestBudget{Limit: 8 * len(p.Members)}
	rc := c
	rc.budget = budget
	configs := make([]Config, len(p.Members))
	apis := make([]rewriteAPI, len(p.Members))
	allNext := true
	for i := range p.Members {
		m := &p.Members[i]
		for _, member := range group.Members {
			if sameDomain(m.Old.Domain, member.Domain) {
				configs[i] = memberConfig(rc, member)
			}
		}
		api, err := d.api(configs[i])
		if err != nil {
			return budget.Used, err
		}
		apis[i] = api
		if a, ok := api.(*adGuardClient); ok {
			defer a.client.CloseIdleConnections()
		}
		actual, err := api.current(ctx)
		if err != nil {
			m.Error = err.Error()
			allNext = false
			continue
		}
		m.Actual = &actual
		if !sameRewrite(actual, m.Next) {
			allNext = false
		}
	}
	if allNext {
		for i := range p.Members {
			m := &p.Members[i]
			if err := confirmGroupDNS(ctx, configs[i], m.Next.Answer, d); err != nil {
				m.Error = err.Error()
				allNext = false
				continue
			}
			sample := d.probe(ctx, m.Next.Answer, configs[i])
			if !sample.Usable || sample.ConnectedIP != m.Next.Answer {
				m.Error = "DNS-selected new address failed HTTPS verification"
				allNext = false
			}
		}
		// Catch edits made while another member was being verified.
		for i := range p.Members {
			actual, err := apis[i].current(ctx)
			if err != nil || !sameRewrite(actual, p.Members[i].Next) {
				allNext = false
			} else {
				p.Members[i].Actual = &actual
			}
		}
	}
	outcome := "switched"
	if !allNext {
		outcome = "rolled-back"
		complete := true
		for i := len(p.Members) - 1; i >= 0; i-- {
			m := &p.Members[i]
			actual, err := apis[i].current(ctx)
			if err != nil {
				m.Error = err.Error()
				complete = false
				continue
			}
			m.Actual = &actual
			if sameRewrite(actual, m.Old) {
				if err := confirmGroupDNS(ctx, configs[i], m.Old.Answer, d); err != nil {
					m.Error = err.Error()
					complete = false
				} else {
					m.Progress = "old"
				}
				continue
			}
			if !sameRewrite(actual, m.Next) {
				m.Error = "manual change preserved"
				complete = false
				continue
			}
			sample := d.probe(ctx, m.Old.Answer, configs[i])
			if !sample.Usable {
				m.Error = "old IP unhealthy; compensation refused"
				complete = false
				continue
			}
			actual, err = apis[i].current(ctx)
			if err != nil || !sameRewrite(actual, m.Next) {
				m.Error = "changed before compensation; no overwrite"
				complete = false
				continue
			}
			writeErr := apis[i].update(ctx, m.Next, m.Old)
			actual, err = apis[i].current(ctx)
			if err != nil || !sameRewrite(actual, m.Old) {
				m.Error = "compensation outcome unknown"
				complete = false
				continue
			}
			_ = writeErr
			m.Actual = &actual
			if err := confirmGroupDNS(ctx, configs[i], m.Old.Answer, d); err != nil {
				m.Error = err.Error()
				complete = false
				continue
			}
			m.Progress = "rolled-back"
			m.Error = ""
			if err := d.save(c, *s); err != nil {
				return budget.Used, err
			}
		}
		if !complete {
			p.Outcome = "recovery-required"
			if err := d.save(c, *s); err != nil {
				return budget.Used, err
			}
			return budget.Used, fmt.Errorf("group %s partial/recovery-required; pending retained", p.GroupID)
		}
	}
	p.Outcome = outcome
	gs := s.Groups[p.GroupID]
	if gs == nil {
		gs = &groupState{}
		s.Groups[p.GroupID] = gs
	}
	gs.Streak = 0
	gs.Winner = ""
	gs.LastSwitch = time.Now().UTC()
	gs.Observed = []Rewrite{}
	for _, m := range p.Members {
		if outcome == "switched" {
			gs.Observed = append(gs.Observed, m.Next)
		} else {
			gs.Observed = append(gs.Observed, m.Old)
		}
	}
	s.Pending = nil
	if err := d.save(c, *s); err != nil {
		s.Pending = p
		return budget.Used, err
	}
	return budget.Used, nil
}

// Keep state bounded when groups are removed/renamed. Carry cooldown across
// overlapping domains so editing group membership cannot evade a recent switch.
func alignGroupStates(c Config, s *groupsState) {
	next := map[string]*groupState{}
	for _, g := range c.Groups {
		gs := s.Groups[g.ID]
		if gs == nil {
			gs = &groupState{}
		}
		for _, old := range s.Groups {
			overlap := false
			for _, observed := range old.Observed {
				for _, member := range g.Members {
					if sameDomain(observed.Domain, member.Domain) {
						overlap = true
					}
				}
			}
			if overlap && old.LastSwitch.After(gs.LastSwitch) {
				gs.LastSwitch = old.LastSwitch
			}
		}
		next[g.ID] = gs
	}
	s.Groups = next
}

func previewGroupRecovery(ctx context.Context, c Config, p groupPending, d groupDependencies) (groupPending, error) {
	p.Members = append([]memberChange{}, p.Members...)
	p.Outcome = "dry-run-recovery-required"
	for i := range p.Members {
		m := &p.Members[i]
		mc := c
		mc.Domain = normalizeDomain(m.Old.Domain)
		api, err := d.api(mc)
		if err != nil {
			return p, err
		}
		if a, ok := api.(*adGuardClient); ok {
			defer a.client.CloseIdleConnections()
		}
		actual, err := api.current(ctx)
		if err != nil {
			return p, err
		}
		m.Actual = &actual
		switch {
		case sameRewrite(actual, m.Old):
			m.Progress = "would-keep-old-and-confirm-DNS"
		case sameRewrite(actual, m.Next):
			m.Progress = "would-verify-group-or-conditionally-restore-healthy-old"
		default:
			m.Progress = "manual-change-requires-resolution-no-overwrite"
		}
	}
	return p, nil
}
