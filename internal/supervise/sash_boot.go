// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

// The boot verbs' host side (sash's boot verbs contract, phase 2): the
// catalog facts the start and stop rules read. The kernel operations and
// the supervisor's start and stop are phase 3; until then each answers
// unsupported, after the verb server's checks, so a boot script fails
// closed.
//
// Threats: Unit reports what the catalog says about a unit and nothing a
// script chose: boot, boot_ops, essential, and its needs and after edges.

import (
	"context"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
)

// bootState is this boot's record for the boot verbs, shared by every
// session. Its window closes when SetBooted(true) is called.
func (sup *Supervisor) bootState() *sash.BootState {
	sup.bootOnce.Do(func() { sup.bootRec = sash.NewBootState(sup.Booted) })
	return sup.bootRec
}

func (h *sashHost) Unit(name string) (sash.UnitInfo, error) {
	s, ok := h.sup.runtime(name)
	if !ok {
		return sash.UnitInfo{}, fail.E("not_found")
	}
	svc := s.svc
	return sash.UnitInfo{Boot: svc.Boot, BootOps: svc.Sash != nil && svc.Sash.BootOps, Essential: svc.Essential,
		Needs: append([]string(nil), svc.Needs...), After: append([]string(nil), svc.After...)}, nil
}

func (h *sashHost) LoadModule(context.Context, string) (sash.ModuleResult, error) {
	return sash.ModuleResult{}, fail.E("unsupported")
}

func (h *sashHost) WaitDevice(context.Context, string, sash.DeviceDecl, time.Duration) (sash.DevID, error) {
	return sash.DevID{}, fail.E("unsupported")
}

func (h *sashHost) EnsureMount(context.Context, sash.HostMountPlan) (string, error) {
	return "", fail.E("unsupported")
}

func (h *sashHost) ApplyNetwork(context.Context, string, sash.NetworkDecl) (sash.NetResult, error) {
	return sash.NetResult{}, fail.E("unsupported")
}

func (h *sashHost) StartUnit(context.Context, string) (sash.Row, bool, error) {
	return nil, false, fail.E("unsupported")
}

func (h *sashHost) StopUnit(context.Context, string) (sash.Row, bool, error) {
	return nil, false, fail.E("unsupported")
}

var _ sash.BootHost = (*sashHost)(nil)
