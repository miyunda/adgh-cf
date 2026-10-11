package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"time"
)

type candidatePool struct {
	ranges   []netip.Prefix
	ips      []string
	sources  []SourceStatus
	snapshot *SnapshotStatus
}
type requestBudget struct {
	Limit     int  `json:"limit"`
	Used      int  `json:"used"`
	Estimated int  `json:"estimated"`
	Exhausted bool `json:"exhausted"`
	Reserved  int  `json:"-"`
}

func (b *requestBudget) take() bool {
	if b.Used >= b.Limit {
		b.Exhausted = true
		return false
	}
	b.Used++
	return true
}

type memberCheck struct {
	Domain  string `json:"domain"`
	Purpose string `json:"purpose"`
	Sample  Sample `json:"sample"`
}
type groupReport struct {
	TCP               []TCPResult     `json:"tcp,omitempty"`
	Baseline          json.RawMessage `json:"baseline,omitempty"`
	ID                string          `json:"id"`
	Primary           string          `json:"primary"`
	Status            string          `json:"status"`
	Error             string          `json:"error,omitempty"`
	Ranking           []string        `json:"ranking"`
	Results           []Summary       `json:"results"`
	PrimarySuggestion string          `json:"primarySuggestion,omitempty"`
	Suggested         string          `json:"suggestedIp,omitempty"`
	Checks            []memberCheck   `json:"memberChecks"`
	Budget            *requestBudget  `json:"budget"`
	Current           []Rewrite       `json:"current,omitempty"`
	Reason            string          `json:"reason,omitempty"`
	Confirmations     int             `json:"confirmations"`
	Next              string          `json:"nextIp,omitempty"`
	Transaction       *groupPending   `json:"transaction,omitempty"`
}
type groupsReport struct {
	CandidateSources  []SourceStatus  `json:"candidateSources,omitempty"`
	CandidateSnapshot *SnapshotStatus `json:"candidateSnapshot,omitempty"`
	SchemaVersion     int             `json:"schemaVersion"`
	Mode              string          `json:"mode"`
	OverallStatus     string          `json:"overallStatus"`
	Groups            []*groupReport  `json:"groups"`
	Recovery          *groupPending   `json:"recovery,omitempty"`
	RecoveryRequests  int             `json:"recoveryRequests"`
	Error             string          `json:"error,omitempty"`
}
type groupDependencies struct {
	api     func(Config) (rewriteAPI, error)
	resolve func(context.Context, Config) ([]string, error)
	probe   func(context.Context, string, Config) Sample
	measure func(context.Context, Config, io.Writer, io.Writer) (int, error)
	save    func(Config, groupsState) error
}

func defaultGroupDependencies(verbose bool) groupDependencies {
	return groupDependencies{
		api:     func(c Config) (rewriteAPI, error) { return newAdGuardClient(c) },
		resolve: resolveAdGuard,
		probe: func(ctx context.Context, ip string, c Config) Sample {
			select {
			case <-ctx.Done():
				return Sample{IP: ip, Classification: "budget-exhausted", Error: "execution deadline or cancellation"}
			case <-time.After(time.Duration(c.RequestIntervalMs) * time.Millisecond):
			}
			return probeHTTPS(ctx, ip, c, nil)
		},
		measure: func(ctx context.Context, c Config, out, log io.Writer) (int, error) {
			return runProbe(ctx, c, "", out, log, verbose)
		},
		save: saveGroupsState,
	}
}
func runGroups(ctx context.Context, c Config, command, selected string, dry bool, path string, out, log io.Writer, verbose bool) (int, error) {
	return executeGroups(ctx, c, command, selected, dry, path, out, log, defaultGroupDependencies(verbose))
}
func executeGroups(parent context.Context, c Config, command, selected string, dry bool, path string, out, log io.Writer, d groupDependencies) (int, error) {
	found := selected == ""
	for _, g := range c.Groups {
		if g.ID == selected {
			found = true
		}
	}
	if !found {
		return 1, fmt.Errorf("unknown group %q", selected)
	}
	if path != "" {
		a, _ := filepath.Abs(path)
		b, _ := filepath.Abs(c.StateFile)
		if a == b || a == b+".lock" {
			return 1, fmt.Errorf("report must not overwrite state or lock")
		}
	}
	mode := command
	if dry {
		mode = "dry-run"
	}
	report := groupsReport{SchemaVersion: 2, Mode: mode, OverallStatus: "complete", Groups: []*groupReport{}}
	code := 0
	recoveryRemaining := 120 * time.Second
	emit := func(err error) (int, error) {
		if err != nil {
			code = 1
			report.Error = err.Error()
		}
		if code == 1 {
			report.OverallStatus = "error"
		} else if code == 2 {
			report.OverallStatus = "no-shared-candidate-or-budget-exhausted"
		}
		data, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			return 1, e
		}
		data = append(data, '\n')
		if path != "" {
			e = writeReport(path, data)
			if e == nil {
				_, e = fmt.Fprintf(out, "Groups %s: status=%s groups=%d; report=%q\n", mode, report.OverallStatus, len(report.Groups), path)
			}
		} else {
			_, e = out.Write(data)
		}
		if e != nil {
			return 1, fmt.Errorf("save group report: %w", e)
		}
		return code, err
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.MaxRunSeconds)*time.Second)
	defer cancel()
	state := groupsState{Version: 2, Groups: map[string]*groupState{}}
	if command == "run" {
		if c.AdGuardHomeURL == "" || c.AdGuardHomeDNS == "" {
			return emit(fmt.Errorf("run/dry-run requires adguardHomeUrl and adguardHomeDns"))
		}
		unlock, err := lockOptimizer(c.StateFile + ".lock")
		if err != nil {
			return emit(err)
		}
		defer unlock()
		state, err = loadGroupsState(c)
		if err != nil {
			return emit(err)
		}
		if state.Pending != nil {
			report.Recovery = state.Pending
			if dry {
				preview, err := previewGroupRecovery(ctx, c, *state.Pending, d)
				report.Recovery = &preview
				if err != nil {
					return emit(err)
				}
				return emit(fmt.Errorf("recovery-required: pending transaction; run with original configuration to reconcile; dry-run makes no changes"))
			}
			recovery, cancel := context.WithTimeout(context.WithoutCancel(parent), 120*time.Second)
			used, err := recoverGroup(recovery, c, &state, d)
			cancel()
			report.RecoveryRequests = used
			if err != nil {
				return emit(err)
			}
			// Recovery is a complete run; no new transaction shares its recovery window.
			return emit(nil)
		}
	}
	if command == "run" {
		alignGroupStates(c, &state)
	}
	pool := c.prepared
	if pool == nil {
		var err error
		pool, err = prepareCandidates(ctx, c, log)
		if err != nil && ctx.Err() == nil {
			return emit(err)
		}
		if pool == nil {
			pool = &candidatePool{}
		}

	}
	c.prepared = pool
	report.CandidateSources, report.CandidateSnapshot = pool.sources, pool.snapshot
	markBudgetStopped := func(g DomainGroup, r *groupReport) error {
		r.Status = "budget-exhausted"
		r.Next = ""
		r.Error = "maxRunSeconds or cancellation reached"
		code = max(code, 2)
		if command == "run" && !dry {
			resetGroupConfirmation(&state, g.ID)
			return d.save(c, state)
		}
		return nil
	}
groupsLoop:
	for _, g := range c.Groups {
		if selected != "" && g.ID != selected {
			continue
		}
		r := &groupReport{ID: g.ID, Primary: g.Primary, Status: "measuring", Budget: &requestBudget{Limit: c.MaxRequestsPerGroup}, Checks: []memberCheck{}, Ranking: []string{}, Results: []Summary{}}
		report.Groups = append(report.Groups, r)
		if ctx.Err() != nil {
			r.Status = "budget-exhausted"
			if command == "run" && !dry {
				resetGroupConfirmation(&state, g.ID)
				if err := d.save(c, state); err != nil {
					return emit(err)
				}
			}
			r.Error = "maxRunSeconds or cancellation reached"
			code = max(code, 2)
			continue
		}
		gc := c
		gc.budget = r.Budget
		apis := make([]rewriteAPI, len(g.Members))
		current := make([]Rewrite, 0, len(g.Members))
		primaryIP := ""
		if command == "run" {
			for i, m := range g.Members {
				mc := memberConfig(gc, m)
				api, err := d.api(mc)
				if err != nil {
					r.Status = "error"
					return emit(err)
				}
				apis[i] = api
				if a, ok := api.(*adGuardClient); ok {
					defer a.client.CloseIdleConnections()
				}
				old, err := api.current(ctx)
				if err != nil && ctx.Err() != nil {
					if e := markBudgetStopped(g, r); e != nil {
						return emit(e)
					}
					continue groupsLoop
				}
				if err != nil {
					r.Status = "error"
					return emit(err)
				}
				if err := confirmGroupDNS(ctx, mc, old.Answer, d); err != nil {
					if ctx.Err() != nil {
						if e := markBudgetStopped(g, r); e != nil {
							return emit(e)
						}
						continue groupsLoop
					}
					r.Status = "error"
					return emit(err)
				}
				current = append(current, old)
				if m.Domain == g.Primary {
					primaryIP = old.Answer
				}
			}
			r.Current = current
		}
		var primary GroupMember
		for _, m := range g.Members {
			if m.Domain == g.Primary {
				primary = m
			}
		}
		pc := memberConfig(gc, primary)
		if primaryIP != "" {
			pc.PinnedIPs = unique(append(append([]string{}, pc.PinnedIPs...), primaryIP))
		}
		r.Budget.Reserved = 7 * len(g.Members)
		if command == "run" {
			r.Budget.Reserved += len(g.Members)
		}
		var measured bytes.Buffer
		_, err := d.measure(ctx, pc, &measured, log)
		var measurement struct {
			Results  []Summary       `json:"results"`
			Ranking  []string        `json:"ranking"`
			TCP      []TCPResult     `json:"tcp"`
			Baseline json.RawMessage `json:"baseline"`
		}
		if measured.Len() > 0 {
			if decodeErr := json.Unmarshal(measured.Bytes(), &measurement); decodeErr != nil {
				return emit(fmt.Errorf("decode primary report: %w", decodeErr))
			}
			r.Results, r.Ranking, r.TCP, r.Baseline = measurement.Results, measurement.Ranking, measurement.TCP, measurement.Baseline
		}

		if err != nil {
			if r.Budget.Exhausted || ctx.Err() != nil {
				r.Status = "budget-exhausted"
				r.Error = err.Error()
				code = max(code, 2)
				if command == "run" && !dry {
					resetGroupConfirmation(&state, g.ID)
					if e := d.save(c, state); e != nil {
						return emit(e)
					}
				}
				continue
			}
			r.Status = "error"
			return emit(err)
		}
		if len(r.Ranking) > 0 {
			r.PrimarySuggestion = r.Ranking[0]
		}
		if command == "run" {
			for i, m := range g.Members {
				sample := d.probe(ctx, current[i].Answer, memberConfig(gc, m))
				r.Checks = append(r.Checks, memberCheck{m.Domain, "current", sample})
			}
		}
		for _, ip := range r.Ranking[:min(3, len(r.Ranking))] {
			passed := true
			for _, m := range g.Members {
				for attempt := 0; attempt < 2; attempt++ {
					sample := d.probe(ctx, ip, memberConfig(gc, m))
					r.Checks = append(r.Checks, memberCheck{m.Domain, "candidate", sample})
					if !sample.Usable {
						passed = false
					}
				}
			}
			if passed {
				r.Suggested = ip
				break
			}
			if r.Budget.Exhausted || ctx.Err() != nil {
				break
			}
		}
		if r.Budget.Exhausted || ctx.Err() != nil {
			r.Suggested = ""
			r.Status = "budget-exhausted"
			code = max(code, 2)
		} else if r.Suggested == "" {
			r.Status = "no-shared-candidate"
			code = max(code, 2)
		} else {
			r.Status = "complete"
		}
		if command == "probe" {
			continue
		}
		gs := state.Groups[g.ID]
		if gs == nil {
			gs = &groupState{}
			state.Groups[g.ID] = gs
		}
		now := time.Now().UTC()
		r.Next, r.Reason = chooseGroup(c, g, gs, current, r.Results, r.Suggested, now)
		r.Confirmations = gs.Streak
		gs.History = append(gs.History, groupHistory{At: now, Suggested: r.Suggested, Decision: r.Reason})
		if len(gs.History) > 48 {
			gs.History = gs.History[len(gs.History)-48:]
		}
		if dry {
			continue
		}
		if r.Next != "" {
			nextIP := r.Next
			for _, m := range g.Members {
				sample := d.probe(ctx, nextIP, memberConfig(gc, m))
				r.Checks = append(r.Checks, memberCheck{m.Domain, "pre-write", sample})
				if !sample.Usable {
					r.Status = "pre-write-failed"
					r.Next = ""
				}
			}
			if r.Budget.Exhausted || ctx.Err() != nil {
				r.Status = "budget-exhausted"
				r.Next = ""
				code = max(code, 2)
			}
			if r.Next == "" {
				gs.Streak = 0
				gs.Winner = ""
				if err := d.save(c, state); err != nil {
					return emit(err)
				}
				if r.Status == "pre-write-failed" {
					return emit(fmt.Errorf("group %s failed pre-write validation", g.ID))
				}
				continue
			}
			for i, api := range apis {
				actual, err := api.current(ctx)
				if ctx.Err() != nil {
					if e := markBudgetStopped(g, r); e != nil {
						return emit(e)
					}
					continue groupsLoop
				}
				if err != nil || !sameRewrite(actual, current[i]) {
					gs.Streak = 0
					gs.Winner = ""
					if e := d.save(c, state); e != nil {
						return emit(e)
					}
					return emit(fmt.Errorf("group %s changed before write or could not be reread", g.ID))
				}
			}
			if recoveryRemaining <= 0 || ctx.Err() != nil {
				r.Status = "budget-exhausted"
				resetGroupConfirmation(&state, g.ID)
				if err := d.save(c, state); err != nil {
					return emit(err)
				}
				code = max(code, 2)
				continue
			}
			p := newGroupPending(c, g, current, r.Next, now)
			state.Pending = p
			r.Transaction = p
			if err := d.save(c, state); err != nil {
				return emit(err)
			}
			// Once the journal is durable, writes and reconciliation have a separate,
			// bounded context; normal measurement deadlines cannot strand cleanup.
			recoveryStarted := time.Now()
			recovery, stop := context.WithTimeout(context.WithoutCancel(parent), recoveryRemaining)
			writeErr := applyGroup(recovery, c, &state, apis, d)
			used, recoveryErr := recoverGroup(recovery, c, &state, d)
			stop()
			recoveryRemaining -= time.Since(recoveryStarted)
			report.RecoveryRequests += used
			if recoveryErr != nil {
				r.Status = "recovery-required"
				return emit(recoveryErr)
			}
			if p.Outcome != "switched" {
				r.Status = "rolled-back"
				if writeErr == nil {
					writeErr = fmt.Errorf("group update did not pass verification")
				}
				return emit(writeErr)
			}
			r.Status = "switched"
			if writeErr != nil {
				return emit(writeErr)
			}
		} else if err := d.save(c, state); err != nil {
			return emit(err)
		}
	}
	return emit(nil)
}
func confirmGroupDNS(ctx context.Context, c Config, ip string, d groupDependencies) error {
	ips, err := d.resolve(ctx, c)
	if err != nil {
		return err
	}
	if len(ips) != 1 || ips[0] != ip {
		return fmt.Errorf("%s: AdGuard DNS must return exclusively expected IPv4 %s", c.Domain, ip)
	}
	return nil
}
