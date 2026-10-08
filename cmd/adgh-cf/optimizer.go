package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type pendingChange struct {
	Old       Rewrite   `json:"old"`
	Next      Rewrite   `json:"next"`
	StartedAt time.Time `json:"startedAt"`
}

type runHistory struct {
	At        time.Time `json:"at"`
	Current   string    `json:"current"`
	Suggested string    `json:"suggested,omitempty"`
	Decision  string    `json:"decision"`
	Results   []Summary `json:"results"`
}

type optimizerState struct {
	Version     int            `json:"version"`
	Domain      string         `json:"domain"`
	API         string         `json:"api"`
	DNS         string         `json:"dns"`
	Observed    string         `json:"observed"`
	Winner      string         `json:"winner"`
	Streak      int            `json:"streak"`
	LastRun     time.Time      `json:"lastRun"`
	LastSwitch  time.Time      `json:"lastSwitch"`
	Pending     *pendingChange `json:"pending,omitempty"`
	History     []runHistory   `json:"history"`
	HealthCheck string         `json:"healthCheck,omitempty"`
}

func loadOptimizerState(c Config) (optimizerState, error) {
	s := optimizerState{Version: 1, Domain: c.Domain, API: c.AdGuardHomeURL, DNS: c.AdGuardHomeDNS, History: []runHistory{}}
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
		return s, fmt.Errorf("optimizer state unreadable or exceeds 4 MiB")
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("invalid optimizer state JSON; restore a valid backup before running")
	}
	if s.Version != 1 || s.Domain != c.Domain || s.API != c.AdGuardHomeURL || s.DNS != c.AdGuardHomeDNS || s.Streak < 0 || s.Streak > 10 || len(s.History) > 48 || (!s.LastRun.IsZero() && s.LastRun.After(time.Now().Add(time.Minute))) || (!s.LastSwitch.IsZero() && s.LastSwitch.After(time.Now().Add(time.Minute))) {
		return s, fmt.Errorf("optimizer state version, target or bounds invalid; use a separate stateFile for a different target")
	}
	if s.Pending != nil {
		p := s.Pending
		if !publicIPv4(p.Old.Answer) || !publicIPv4(p.Next.Answer) || p.Old.Answer == p.Next.Answer || p.Old.Domain != p.Next.Domain || !sameDomain(p.Old.Domain, c.Domain) || p.StartedAt.IsZero() {
			return s, fmt.Errorf("invalid pending change in optimizer state")
		}
	}
	return s, nil
}

func saveOptimizerState(c Config, s optimizerState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeReport(c.StateFile, append(data, '\n'))
}

// A confirmation must come from a separate run at least five minutes later;
// gaps over three hours, manual edits, and clock reversal break the streak.
func chooseChange(c Config, s *optimizerState, current string, results []Summary, now time.Time) (string, string) {
	check, _ := json.Marshal([]any{c.HealthMode, c.HealthPath, c.ExpectedStatusCodes, c.ExpectedBodyContains, c.MaxTTFBMs, c.MinSuccessRate, c.MinImprovement, c.ConfirmRuns, c.CooldownMinutes})
	checkID := fmt.Sprintf("%x", sha256.Sum256(check))
	if s.HealthCheck != checkID {
		s.Winner = ""
		s.Streak = 0
		s.HealthCheck = checkID
	}
	if s.Observed != current || now.Sub(s.LastRun) > 3*time.Hour || now.Before(s.LastRun) {
		s.Winner = ""
		s.Streak = 0
	}
	s.Observed = current
	ranked := rank(results)
	if len(ranked) == 0 {
		s.Winner = ""
		s.Streak = 0
		return "", "no eligible candidate; keep current rewrite"
	}
	winner := ranked[0]
	if winner.IP == current {
		s.Winner = ""
		s.Streak = 0
		return "", "current address remains best"
	}
	var old *Summary
	for i := range results {
		if results[i].IP == current {
			old = &results[i]
			break
		}
	}
	// A missing current sample is an execution error, not proof of a bad address.
	if old == nil {
		s.Winner = ""
		s.Streak = 0
		return "", "current address not measured; keep current rewrite"
	}
	if old.Eligible && old.MedianTTFBMs != nil {
		if winner.MedianTTFBMs == nil || *old.MedianTTFBMs <= 0 || 1 - *winner.MedianTTFBMs / *old.MedianTTFBMs < c.MinImprovement {
			s.Winner = ""
			s.Streak = 0
			return "", "improvement below threshold"
		}
		if now.Sub(s.LastSwitch) < time.Duration(c.CooldownMinutes)*time.Minute {
			s.Winner = ""
			s.Streak = 0
			return "", "switch cooldown active"
		}
	}
	if s.Winner != winner.IP {
		s.Winner = winner.IP
		s.Streak = 1
	} else if now.Sub(s.LastRun) >= 5*time.Minute {
		s.Streak = min(c.ConfirmRuns, s.Streak+1)
	}
	if s.Streak < c.ConfirmRuns {
		return "", fmt.Sprintf("awaiting confirmation %d/%d for %s", s.Streak, c.ConfirmRuns, winner.IP)
	}
	return winner.IP, "candidate confirmed"
}

type rewriteAPI interface {
	current(context.Context) (Rewrite, error)
	update(context.Context, Rewrite, Rewrite) error
}

// Never repeat an uncertain PUT. Inspect its outcome, verify it, and only roll
// back while the rule still equals our write and the old address is healthy.
func finishChange(ctx context.Context, api rewriteAPI, p pendingChange, verify func(context.Context, string) error, healthy func(context.Context, string) bool) (string, error) {
	actual, err := api.current(ctx)
	if err != nil {
		return "pending", fmt.Errorf("change outcome unknown; pending journal retained: %w", err)
	}
	if sameRewrite(actual, p.Old) {
		return "not-applied", nil
	}
	if !sameRewrite(actual, p.Next) {
		return "pending", fmt.Errorf("rewrite changed outside this transaction; pending journal retained, no automatic overwrite")
	}
	if err := verify(ctx, p.Next.Answer); err == nil {
		return "switched", nil
	}
	if !healthy(ctx, p.Old.Answer) {
		return "pending", fmt.Errorf("new DNS/health verification failed and old address is unhealthy; pending journal retained")
	}
	actual, err = api.current(ctx)
	if err != nil || !sameRewrite(actual, p.Next) {
		return "pending", fmt.Errorf("rollback stopped: rewrite changed or could not be read; pending journal retained")
	}
	writeErr := api.update(ctx, p.Next, p.Old)
	actual, err = api.current(ctx)
	if err != nil || !sameRewrite(actual, p.Old) {
		return "pending", fmt.Errorf("rollback outcome unknown; pending journal retained")
	}
	if err := verify(ctx, p.Old.Answer); err != nil {
		return "pending", fmt.Errorf("rollback rule restored but DNS/health verification failed; pending journal retained")
	}
	_ = writeErr // A successful read-back and verification resolve an uncertain response.
	return "rolled-back", nil
}

type optimizerDependencies struct {
	api     rewriteAPI
	resolve func(context.Context) ([]string, error)
	measure func(context.Context, Config, string, io.Writer, io.Writer) (int, error)
	verify  func(context.Context, string) error
	healthy func(context.Context, string) bool
}

func runOptimizer(ctx context.Context, c Config, dryRun bool, outputPath string, out, log io.Writer) (int, error) {
	api, err := newAdGuardClient(c)
	if err != nil {
		return 1, err
	}
	defer api.client.CloseIdleConnections()
	d := optimizerDependencies{api: api, resolve: func(ctx context.Context) ([]string, error) { return resolveAdGuard(ctx, c) }, measure: runProbe, verify: func(ctx context.Context, ip string) error { return verifyTarget(ctx, c, ip) }, healthy: func(ctx context.Context, ip string) bool { return probeHTTPS(ctx, ip, c, nil).Usable }}
	return executeOptimizer(ctx, c, dryRun, outputPath, out, log, d)
}

func executeOptimizer(ctx context.Context, c Config, dryRun bool, outputPath string, out, log io.Writer, d optimizerDependencies) (int, error) {
	if outputPath != "" {
		a, _ := filepath.Abs(outputPath)
		b, _ := filepath.Abs(c.StateFile)
		if a == b || a == b+".lock" {
			return 1, fmt.Errorf("report output must not overwrite optimizer state or lock")
		}
	}
	api := d.api
	unlock, err := lockOptimizer(c.StateFile + ".lock")
	if err != nil {
		return 1, err
	}
	defer unlock()
	state, err := loadOptimizerState(c)
	if err != nil {
		return 1, err
	}
	verify, healthy := d.verify, d.healthy
	if state.Pending != nil {
		if dryRun {
			return emitOptimizer(outputPath, out, map[string]any{"mode": "dry-run", "decision": "pending transaction requires reconciliation by run; no changes made", "pending": state.Pending})
		}
		action, err := finishChange(ctx, api, *state.Pending, verify, healthy)
		if err != nil {
			return 1, err
		}
		if action == "switched" || action == "rolled-back" {
			state.LastSwitch = time.Now().UTC()
		}
		if action == "switched" {
			state.Observed = state.Pending.Next.Answer
		} else {
			state.Observed = state.Pending.Old.Answer
		}
		state.Pending = nil
		state.Streak = 0
		state.Winner = ""
		if err := saveOptimizerState(c, state); err != nil {
			return 1, err
		}
		return emitOptimizer(outputPath, out, map[string]any{"mode": "run", "decision": "reconciled pending change: " + action})
	}
	current, err := api.current(ctx)
	if err != nil {
		return 1, err
	}
	// Refuse to write if rewrites are globally disabled or DNS does not currently
	// apply this rule. Older AdGuard versions need only the tested list/update API.
	ips, err := d.resolve(ctx)
	if err != nil || len(ips) != 1 || ips[0] != current.Answer {
		return 1, fmt.Errorf("current rewrite is not confirmed by configured AdGuard Home DNS; check DNS address, rewrite enablement and client policy")
	}
	measured := c
	measured.PinnedIPs = unique(append(append([]string{}, c.PinnedIPs...), current.Answer))
	var probeOutput bytes.Buffer
	_, err = d.measure(ctx, measured, "", &probeOutput, log)
	if err != nil {
		return 1, err
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(probeOutput.Bytes(), &report); err != nil {
		return 1, err
	}
	var results []Summary
	if err := json.Unmarshal(report["results"], &results); err != nil {
		return 1, err
	}
	now := time.Now().UTC()
	next, reason := chooseChange(c, &state, current.Answer, results, now)
	state.LastRun = now
	var suggested string
	ranked := rank(results)
	if len(ranked) > 0 {
		suggested = ranked[0].IP
	}
	historyResults := append([]Summary{}, results...)
	for i := range historyResults {
		historyResults[i].Samples = nil
	}
	state.History = append(state.History, runHistory{At: now, Current: current.Answer, Suggested: suggested, Decision: reason, Results: historyResults})
	if len(state.History) > 48 {
		state.History = state.History[len(state.History)-48:]
	}
	decision := map[string]any{"dryRun": dryRun, "currentIp": current.Answer, "suggestedIp": suggested, "nextIp": next, "reason": reason, "confirmations": state.Streak}
	if !dryRun {
		if next != "" {
			if !healthy(ctx, next) {
				return 1, fmt.Errorf("candidate failed immediate pre-write health check; no write made")
			}
			actual, err := api.current(ctx)
			if err != nil || !sameRewrite(actual, current) {
				return 1, fmt.Errorf("rewrite changed during measurement or could not be read; no write made")
			}
			if ctx.Err() != nil {
				return 1, ctx.Err()
			}
			pending := pendingChange{Old: current, Next: Rewrite{Domain: current.Domain, Answer: next, Enabled: current.Enabled}, StartedAt: now}
			state.Pending = &pending
			if err := saveOptimizerState(c, state); err != nil {
				return 1, err
			}
			writeErr := api.update(ctx, pending.Old, pending.Next)
			// Finish read-back even when cancellation interrupted the write response.
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
			action, err := finishChange(recoveryCtx, api, pending, verify, healthy)
			cancel()
			if err != nil {
				return 1, err
			}
			state.Pending = nil
			state.Winner = ""
			state.Streak = 0
			if action == "switched" || action == "rolled-back" {
				state.LastSwitch = now
			}
			if action == "switched" {
				state.Observed = next
			}
			decision["action"] = action
			state.History[len(state.History)-1].Decision = action
			if err := saveOptimizerState(c, state); err != nil {
				return 1, err
			}
			if action == "not-applied" || action == "rolled-back" {
				decision["writeFailed"] = true
				if writeErr != nil {
					decision["error"] = writeErr.Error()
				}
				report["optimizer"], _ = json.Marshal(decision)
				_, emitErr := emitOptimizerReport(outputPath, out, report, dryRun)
				if emitErr != nil {
					return 1, emitErr
				}
				return 1, fmt.Errorf("change %s; current rewrite retained/restored", action)
			}
		} else if err := saveOptimizerState(c, state); err != nil {
			return 1, err
		}
	}
	report["optimizer"], _ = json.Marshal(decision)
	return emitOptimizerReport(outputPath, out, report, dryRun)
}

func emitOptimizerReport(path string, out io.Writer, report map[string]json.RawMessage, dry bool) (int, error) {
	mode := "run"
	if dry {
		mode = "dry-run"
	}
	report["mode"], _ = json.Marshal(mode)
	report["notes"], _ = json.Marshal([]string{"Only the configured existing IPv4 rewrite is managed.", "DNS verification queries the configured AdGuard Home server; client caches and HTTPS/SVCB behavior require client-side verification."})
	return emitOptimizer(path, out, report)
}

func emitOptimizer(path string, out io.Writer, report any) (int, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return 1, err
	}
	data = append(data, '\n')
	if path != "" {
		if err := writeReport(path, data); err != nil {
			return 1, err
		}
	}
	_, err = out.Write(data)
	if err != nil {
		return 1, err
	}
	return 0, nil
}
