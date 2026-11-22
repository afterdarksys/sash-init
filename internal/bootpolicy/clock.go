package bootpolicy

import (
	"sync"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

type Clock interface{ Now() (time.Time, bool) }
type ClockFunc func() (time.Time, bool)

func (f ClockFunc) Now() (time.Time, bool) { return f() }

type State string

const (
	Valid          State = "valid"
	Grace          State = "grace"
	Expired        State = "expired"
	NotYetValid    State = "not_yet_valid"
	ClockUncertain State = "clock_uncertain"
	Missing        State = "missing"
	Revoked        State = "revoked" // Below the revocation floor; reported by the CLI.
)

func (d *Document) State(c Clock) State {
	if d == nil {
		return Missing
	}
	// A never-policy has no deadlines and not_before equals issued_at, so the
	// clock is not read: a clock jump forward or back cannot end it.
	if d.policy.Lifetime == LifetimeNever {
		return Valid
	}
	if c == nil {
		return ClockUncertain
	}
	now, trusted := c.Now()
	if !trusted {
		return ClockUncertain
	}
	p := d.policy
	switch n := now.Unix(); {
	case n < p.NotBefore:
		return NotYetValid
	case n < p.ExpiresAt:
		return Valid
	case n < p.OfflineUntil:
		return Grace
	default:
		return Expired
	}
}
func (d *Document) CheckFresh(c Clock) error {
	switch d.State(c) {
	case Valid:
		return nil
	case ClockUncertain:
		return fail.E("policy_clock_uncertain")
	case NotYetValid:
		return fail.E("policy_not_yet_valid")
	case Missing:
		return fail.E("policy_missing")
	default:
		return fail.E("policy_expired")
	}
}

// AnchoredClock requires an externally trusted UTC anchor. It never treats a
// signed policy timestamp or the wall clock as proof of current time.
type AnchoredClock struct {
	mu          sync.Mutex
	elapsed     func() (time.Duration, error)
	anchor      time.Time
	origin      time.Duration
	lastElapsed time.Duration
	last        time.Time
	trusted     bool
}

// NewClock uses suspend-inclusive boot time on Linux. Unsupported platforms
// return an uncertain clock; tests can supply an explicit elapsed-time source.
func NewClock(anchor time.Time) *AnchoredClock { return NewClockWithElapsed(anchor, bootElapsed) }
func NewClockWithElapsed(anchor time.Time, elapsed func() (time.Duration, error)) *AnchoredClock {
	c := &AnchoredClock{elapsed: elapsed}
	if elapsed == nil || anchor.IsZero() {
		return c
	}
	n, err := elapsed()
	if err != nil || n < 0 {
		return c
	}
	c.anchor = anchor
	c.origin = n
	c.lastElapsed = n
	c.last = anchor
	c.trusted = true
	return c
}
func (c *AnchoredClock) Now() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.trusted {
		return time.Time{}, false
	}
	n, err := c.elapsed()
	if err != nil || n < c.lastElapsed {
		c.trusted = false
		return time.Time{}, false
	}
	c.lastElapsed = n
	now := c.anchor.Add(n - c.origin)
	if now.Before(c.last) {
		now = c.last
	}
	c.last = now
	return now, true
}

// Advance accepts only an externally authenticated forward correction. It cannot
// restore lost clock confidence; construct a new anchor after time recovery.
func (c *AnchoredClock) Advance(trustedUTC time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.trusted {
		return fail.E("policy_clock_uncertain")
	}
	n, err := c.elapsed()
	if err != nil || n < c.lastElapsed {
		c.trusted = false
		return fail.E("policy_clock_uncertain")
	}
	now := c.anchor.Add(n - c.origin)
	if trustedUTC.Before(now) {
		return fail.E("policy_clock_rollback")
	}
	c.anchor = trustedUTC
	c.origin = n
	c.lastElapsed = n
	c.last = trustedUTC
	return nil
}
