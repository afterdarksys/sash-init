// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"sort"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// Reconcile pauses desired dependents while a required provider is unavailable,
// then resumes only those paused services after their providers become ready.
// A failed service itself stays failed until its restart policy or an operator
// starts it; reconciliation never bypasses restart limits.
func (sup *Supervisor) Reconcile(ctx context.Context) error {
	if !sup.transaction.TryRLock() {
		return nil
	}
	defer sup.transaction.RUnlock()
	if sup.shuttingDown.Load() {
		return nil
	}
	catalog := make(map[string]*unit.Service, len(sup.runtimes()))
	for name, s := range sup.runtimes() {
		catalog[name] = s.svc
	}
	waves, err := graph.ShutdownPlan(catalog)
	if err != nil {
		return err
	}
	var first error
	for _, wave := range waves {
		for _, name := range wave {
			s, _ := sup.runtime(name)
			s.mu.Lock()
			desired, state := s.desired, s.state
			s.mu.Unlock()
			if !desired || state == "failed" || state == "stopped" || state == "exited" || state == "blocked" {
				continue
			}
			if err := sup.needsGate(s); err != nil {
				if stopErr := sup.stop(ctx, name, false); stopErr != nil {
					if first == nil {
						first = stopErr
					}
					continue
				}
				s.mu.Lock()
				if s.desired {
					s.state = "blocked"
					s.lastError = fail.Token(err)
					s.eventLocked("blocked", s.lastError, nil)
				}
				s.mu.Unlock()
			}
		}
	}
	for i := len(waves) - 1; i >= 0; i-- {
		for _, name := range waves[i] {
			s, _ := sup.runtime(name)
			s.mu.Lock()
			desired, state := s.desired, s.state
			s.mu.Unlock()
			if desired && state == "blocked" && sup.needsGate(s) == nil {
				if err := sup.start(ctx, name, "", s.svc.Type == "oneshot", false); err != nil && first == nil {
					first = err
				}
			}
		}
	}
	return first
}

// EssentialFailure identifies terminal failures, including failed transitive
// needs. After boot (boot false) a unit or provider in its restart delay is
// transient, not a host failure; at the end of boot (boot true) an
// essential unit waiting out a delay after a crash counts as not ready.
func (sup *Supervisor) EssentialFailure(boot bool) string {
	if !sup.transaction.TryRLock() {
		return ""
	}
	defer sup.transaction.RUnlock()
	var terminal func(string, map[string]bool) bool
	terminal = func(name string, seen map[string]bool) bool {
		if seen[name] {
			return false
		}
		seen[name] = true
		s, ok := sup.runtime(name)
		if !ok {
			return true
		}
		s.mu.Lock()
		state, desired, ready, backoff := s.state, s.desired, s.ready, s.backoff
		s.mu.Unlock()
		if !desired {
			return false
		}
		// At the end of boot a unit that already crashed and waits out its
		// restart delay is not ready: boot fails now rather than waiting.
		if boot && backoff {
			return true
		}
		if state == "failed" || state == "stopped" {
			return true
		}
		if boot && !ready && state != "starting" {
			return true
		}
		if state == "blocked" {
			for _, dep := range s.svc.Needs {
				if terminal(dep, seen) {
					return true
				}
			}
		}
		return false
	}
	var names []string
	for name, s := range sup.runtimes() {
		if s.svc.Essential && s.svc.Boot {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if terminal(name, map[string]bool{}) {
			return name
		}
	}
	return ""
}

type Explanation struct {
	Name      string   `json:"name"`
	Desired   bool     `json:"desired"`
	State     string   `json:"state"`
	Reason    string   `json:"reason"`
	BlockedBy []string `json:"blocked_by"`
}

func (sup *Supervisor) Explain(name string) (*Explanation, error) {
	s, err := sup.lookup(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	e := &Explanation{Name: name, Desired: s.desired, State: s.state, Reason: s.lastError, BlockedBy: []string{}}
	s.mu.Unlock()
	for _, dep := range s.svc.Needs {
		other, ok := sup.runtime(dep)
		if !ok {
			e.BlockedBy = append(e.BlockedBy, dep)
			continue
		}
		other.mu.Lock()
		ready := other.ready && (other.state == "running" || other.state == "exited")
		other.mu.Unlock()
		if !ready {
			e.BlockedBy = append(e.BlockedBy, dep)
		}
	}
	if !e.Desired {
		e.Reason = "administratively_stopped"
	}
	sort.Strings(e.BlockedBy)
	return e, nil
}
