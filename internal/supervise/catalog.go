// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func (sup *Supervisor) runtimes() map[string]*runtime {
	sup.catalogMu.RLock()
	defer sup.catalogMu.RUnlock()
	out := make(map[string]*runtime, len(sup.rt))
	for name, s := range sup.rt {
		out[name] = s
	}
	return out
}
func (sup *Supervisor) runtime(name string) (*runtime, bool) {
	sup.catalogMu.RLock()
	defer sup.catalogMu.RUnlock()
	s, ok := sup.rt[name]
	return s, ok
}
func (sup *Supervisor) Catalog() map[string]*unit.Service {
	out := map[string]*unit.Service{}
	for name, s := range sup.runtimes() {
		out[name] = s.svc
	}
	return out
}

type CatalogDiff struct {
	Added      []string `json:"added"`
	Removed    []string `json:"removed"`
	Changed    []string `json:"changed"`
	Affected   []string `json:"affected"`
	Generation uint64   `json:"generation"`
	RolledBack bool     `json:"rolled_back"`
}

func Diff(old, next map[string]*unit.Service) CatalogDiff {
	d := CatalogDiff{Added: []string{}, Removed: []string{}, Changed: []string{}, Affected: []string{}}
	affected := map[string]bool{}
	for name, s := range old {
		n, ok := next[name]
		if !ok {
			d.Removed = append(d.Removed, name)
			affected[name] = true
		} else if !reflect.DeepEqual(s, n) {
			d.Changed = append(d.Changed, name)
			affected[name] = true
		}
	}
	for name := range next {
		if _, ok := old[name]; !ok {
			d.Added = append(d.Added, name)
			affected[name] = true
		}
	}
	// A changed provider requires its transitive needs dependents to stop.
	for changed := true; changed; {
		changed = false
		for _, catalog := range []map[string]*unit.Service{old, next} {
			for name, s := range catalog {
				if affected[name] {
					continue
				}
				for _, dep := range s.Needs {
					if affected[dep] {
						affected[name] = true
						changed = true
						break
					}
				}
			}
		}
	}
	for name := range affected {
		d.Affected = append(d.Affected, name)
	}
	for _, list := range [][]string{d.Added, d.Removed, d.Changed, d.Affected} {
		sort.Strings(list)
	}
	return d
}

// Apply changes the running catalog under an exclusive transaction. The new
// graph is validated before stopping anything. Unaffected runtimes retain PIDs,
// output and restart budgets. Rollback restores configuration and desired state;
// it cannot undo application side effects or promise recovery if old exec fails.
func (sup *Supervisor) Apply(ctx context.Context, next map[string]*unit.Service) (CatalogDiff, error) {
	if !sup.transaction.TryLock() {
		return CatalogDiff{}, fail.E("busy")
	}
	defer sup.transaction.Unlock()
	if sup.Signed {
		return CatalogDiff{}, fail.E("signed_activation_required")
	}
	return sup.apply(ctx, next, nil, true, nil)
}
func (sup *Supervisor) Rollback(ctx context.Context) (CatalogDiff, error) {
	if !sup.transaction.TryLock() {
		return CatalogDiff{}, fail.E("busy")
	}
	defer sup.transaction.Unlock()
	if sup.previous == nil {
		return CatalogDiff{}, fail.E("no_previous_catalog")
	}
	if sup.Signed {
		return CatalogDiff{}, fail.E("new_policy_required")
	}
	return sup.apply(ctx, sup.previous, sup.previousDesired, true, nil)
}

// SetAdmission is configured before Boot. The callback must bind to the active
// generation, not to a separately renewed pending cache.
func (sup *Supervisor) SetAdmission(admit func(string, bool) error) {
	sup.admit = admit
	sup.Signed = true
}

func (sup *Supervisor) ApplyAuthorized(ctx context.Context, next map[string]*unit.Service, admit func(string, bool) error, commit func() error) (CatalogDiff, error) {
	if !sup.transaction.TryLock() {
		return CatalogDiff{}, fail.E("busy")
	}
	defer sup.transaction.Unlock()
	for name := range next {
		if err := admit(name, false); err != nil {
			return CatalogDiff{}, err
		}
	}
	oldAdmit := sup.admit
	old := sup.Catalog()
	oldDesired := map[string]bool{}
	for name, s := range sup.runtimes() {
		s.mu.Lock()
		oldDesired[name] = s.desired
		s.mu.Unlock()
	}
	sup.admit = admit
	diff, err := sup.apply(ctx, next, nil, true, func() { sup.admit = oldAdmit })
	if err != nil {
		sup.admit = oldAdmit
		return diff, err
	}
	if err := commit(); err != nil {
		// The active pointer was renamed but its directory fsync failed. Its
		// current value is the candidate: rolling back only memory would split
		// runtime and disk. Report uncertain durability and retain candidate.
		if fail.Token(err) == "deployment_durability" {
			return diff, err
		}
		sup.admit = oldAdmit
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, restoreErr := sup.apply(restoreCtx, old, oldDesired, false, nil)
		diff.RolledBack = true
		if restoreErr != nil {
			return diff, fail.E("rollback_failed")
		}
		return diff, fail.E("activation_commit")
	}
	return diff, nil
}
func (sup *Supervisor) apply(ctx context.Context, next map[string]*unit.Service, wanted map[string]bool, remember bool, restoreAdmission func()) (CatalogDiff, error) {
	old := sup.Catalog()
	diff := Diff(old, next)
	if hasSash(old) || hasSash(next) {
		return diff, fail.E("catalog_sash")
	}
	if sup.shuttingDown.Load() {
		return diff, fail.E("shutting_down")
	}
	if ctx.Err() != nil {
		return diff, fail.E("timeout")
	}
	if _, err := graph.Plan(next); err != nil {
		return diff, err
	}
	for _, svc := range next {
		if svc.Limits.Any() && (sup.Cgroups == nil || sup.Cgroups.Supports(svc.Limits) != nil) {
			return diff, fail.E("cgroup_controller")
		}
	}
	nextSup, err := New(next, sup.self)
	if err != nil {
		return diff, err
	}
	nextSup.SetJournal(sup.journal)
	oldRT := sup.runtimes()
	oldDesired := map[string]bool{}
	for name, s := range oldRT {
		s.mu.Lock()
		oldDesired[name] = s.desired
		s.mu.Unlock()
	}
	affected := map[string]bool{}
	for _, name := range diff.Affected {
		affected[name] = true
	}
	waves, _ := graph.ShutdownPlan(old)
	for _, wave := range waves {
		for _, name := range wave {
			if affected[name] {
				if err := sup.stop(ctx, name, false); err != nil {
					if restoreAdmission != nil {
						restoreAdmission()
					}
					restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					restoreErr := sup.startDesired(restoreCtx, affected)
					cancel()
					diff.RolledBack = true
					if restoreErr != nil {
						return diff, fail.E("rollback_failed")
					}
					return diff, fail.E("apply_rolled_back")
				}
			}
		}
	}
	if sup.shuttingDown.Load() {
		return diff, fail.E("shutting_down")
	}
	for name, s := range nextSup.rt {
		if !affected[name] {
			nextSup.rt[name] = oldRT[name]
			continue
		}
		s.desired = s.svc.Boot
		if _, ok := old[name]; ok {
			s.desired = oldDesired[name]
			if old[name].Boot != s.svc.Boot {
				s.desired = s.svc.Boot
			}
		}
		if wanted != nil {
			s.desired = wanted[name]
		}
	}
	sup.catalogMu.Lock()
	sup.rt = nextSup.rt
	sup.catalogMu.Unlock()
	err = sup.startDesired(ctx, affected)
	if err != nil {
		// Invalidate any partially started replacement before restoring old.
		if restoreAdmission != nil {
			restoreAdmission()
		}
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		waves, _ := graph.ShutdownPlan(next)
		var restoreErr error
		for _, wave := range waves {
			for _, name := range wave {
				if affected[name] {
					if e := sup.stop(restoreCtx, name, false); e != nil {
						restoreErr = e
					}
				}
			}
		}
		if restoreErr != nil {
			return diff, fail.E("rollback_failed")
		}
		sup.catalogMu.Lock()
		sup.rt = oldRT
		sup.retireLocked(nextSup.rt, affected)
		sup.catalogMu.Unlock()
		for name, s := range oldRT {
			s.mu.Lock()
			s.desired = oldDesired[name]
			s.mu.Unlock()
		}
		diff.RolledBack = true
		if sup.shuttingDown.Load() {
			return diff, fail.E("shutting_down")
		}
		if e := sup.startDesired(restoreCtx, affected); e != nil {
			return diff, fail.E("rollback_failed")
		}
		return diff, fail.E("apply_rolled_back")
	}
	sup.catalogMu.Lock()
	sup.retireLocked(oldRT, affected)
	sup.catalogMu.Unlock()
	if remember {
		sup.previous = old
		sup.previousDesired = oldDesired
	}
	sup.generation++
	diff.Generation = sup.generation
	return diff, nil
}
func (sup *Supervisor) startDesired(ctx context.Context, affected map[string]bool) error {
	catalog := sup.Catalog()
	all := map[string]*unit.Service{}
	for name, s := range catalog {
		copy := *s
		copy.Boot = true
		all[name] = &copy
	}
	waves, err := graph.Plan(all)
	if err != nil {
		return err
	}
	for _, wave := range waves {
		for _, name := range wave {
			if !affected[name] {
				continue
			}
			s, _ := sup.runtime(name)
			s.mu.Lock()
			desired, state := s.desired, s.state
			s.mu.Unlock()
			if desired && state != "running" && state != "starting" {
				if err := sup.start(ctx, name, "", s.svc.Type == "oneshot", false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Retain residual process-group identities across catalog replacement so a
// removed service cannot acquire control-socket authority. Close empty groups'
// pidfds and discard their runtimes; called with catalogMu held.
func (sup *Supervisor) retireLocked(old map[string]*runtime, affected map[string]bool) {
	for name, s := range old {
		if affected[name] {
			sup.retired = append(sup.retired, s)
		}
	}
	kept := sup.retired[:0]
	for _, s := range sup.retired {
		s.mu.Lock()
		s.retireGroupLocked()
		alive := len(s.led) > 0
		s.mu.Unlock()
		if alive {
			kept = append(kept, s)
		}
	}
	sup.retired = kept
}
func (sup *Supervisor) peerRuntimes() []*runtime {
	sup.catalogMu.RLock()
	defer sup.catalogMu.RUnlock()
	out := append([]*runtime{}, sup.retired...)
	for _, s := range sup.rt {
		out = append(out, s)
	}
	return out
}

// hasSash reports whether a catalog has a sash unit. A live catalog change
// replaces runtimes, and a sash runtime holds a described script, a grant
// and mounts that are not carried across: catalogs with sash units change
// only by restarting the supervisor.
func hasSash(c map[string]*unit.Service) bool {
	for _, svc := range c {
		if svc.Sash != nil {
			return true
		}
	}
	return false
}
