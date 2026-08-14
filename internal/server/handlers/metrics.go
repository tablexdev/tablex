package handlers

import (
	"net/http"
	"sync/atomic"
)

// Counters are the process-wide numbers the handlers are in a position to see.
// The server package renders them at /metrics, and mostly cannot count them
// itself: a login rejection and a spent query budget are both invisible from the
// middleware (the first re-renders a form at 200, the second surfaces as one
// statement's error inside an otherwise ordinary response).
//
// The one exception is a login refused by the session-creation throttle, which
// happens IN the middleware before any handler runs — hence the single exported
// RecordLoginThrottled below. It is deliberately the only mutator that crosses
// the boundary.
//
// A nil *Counters is a valid disabled set — every method tolerates it — so the
// many tests that build a bare &Handlers{} do not have to wire one up.
type Counters struct {
	loginOK        atomic.Int64
	loginDenied    atomic.Int64
	loginThrottled atomic.Int64

	queryBudgetRefused atomic.Int64

	// restrictedRefused counts policy refusals made by a HANDLER rather than by
	// the middleware — today only saveProgram, whose route cannot see which
	// action the form carries. The server sums this into the same
	// tablex_restricted_refused_total series its own counter feeds, so the metric
	// stays one number: an operator watching refusals should not have to know
	// which layer said no.
	restrictedRefused atomic.Int64
}

// CounterSnapshot is a consistent-enough read of the counters: each value is read
// atomically, but not all together, which is the right trade for monotonic
// counters a scraper differentiates anyway.
type CounterSnapshot struct {
	LoginsOK        int64
	LoginsDenied    int64
	LoginsThrottled int64

	QueryBudgetRefused int64
	RestrictedRefused  int64
}

// Snapshot reads every counter. A nil receiver reads as all zeros.
func (c *Counters) Snapshot() CounterSnapshot {
	if c == nil {
		return CounterSnapshot{}
	}
	return CounterSnapshot{
		LoginsOK:           c.loginOK.Load(),
		LoginsDenied:       c.loginDenied.Load(),
		LoginsThrottled:    c.loginThrottled.Load(),
		QueryBudgetRefused: c.queryBudgetRefused.Load(),
		RestrictedRefused:  c.restrictedRefused.Load(),
	}
}

// restrictedRefusal counts one request refused by a handler-level restricted-mode
// check. See Counters.restrictedRefused.
func (c *Counters) restrictedRefusal() {
	if c == nil {
		return
	}
	c.restrictedRefused.Add(1)
}

// recordLoginSuccess counts an authenticated login.
func (c *Counters) recordLoginSuccess() {
	if c == nil {
		return
	}
	c.loginOK.Add(1)
}

// recordLoginRejected counts a refused login attempt, splitting "the credential
// was rejected" from "the attempt was throttled" by the status the rejection
// funnel already chose. The split is the point: a rising denied count is somebody
// guessing passwords, while a rising throttled count is the limiter holding, and
// an operator alarms on them differently.
func (c *Counters) recordLoginRejected(status int) {
	if c == nil {
		return
	}
	if status == http.StatusTooManyRequests {
		c.loginThrottled.Add(1)
		return
	}
	c.loginDenied.Add(1)
}

// RecordLoginThrottled counts one login attempt turned away by a throttle
// enforced OUTSIDE this package — the session-creation cap, which refuses in the
// middleware before any handler runs. The `Record…` name matches the mutators
// above; a bare LoginThrottled() would read as an accessor.
//
// This is the ONLY thing that had to cross the package boundary for that cap:
// package server already emits audit events directly, so the refusal event needs
// no API.
func (c *Counters) RecordLoginThrottled() {
	if c == nil {
		return
	}
	c.loginThrottled.Add(1)
}

// recordQueryBudgetRefused counts one statement turned away by a session's query
// budget.
func (c *Counters) recordQueryBudgetRefused() {
	if c == nil {
		return
	}
	c.queryBudgetRefused.Add(1)
}
