// Package audit is TableX's audit trail: a durable, structured record of who did
// what, to which object, from where, and whether it worked.
//
// It is distinct from the access log, which the server has always had. The access
// log answers "what HTTP traffic did this process serve" and goes to stderr with
// everything else; this answers "who changed my database", is emitted only for
// the events that matter, and is written somewhere an auditor can keep.
//
// # What is recorded, and what is never
//
// Recorded: the identity the DATABASE reports for the connection (an account
// name, and on MySQL its host), the predefined server or engine it belongs to,
// the client address, the object acted on, the outcome, and how long it took.
//
// Never recorded: a password, a DSN, a CSRF token, or a session id. The identity
// here is an account NAME — the thing a grant is written against — not a
// credential. Nothing in an Event can be replayed to gain access.
//
// # Off by default
//
// With no [audit] destination configured, Logger is nil, Emit is a no-op on a nil
// receiver, and nothing is written or allocated. Turning it on is one config
// block.
//
// # The honest limit of the guarantee
//
// A sink that fails is reported at ERROR level (throttled) and the request still
// proceeds. TableX does not refuse to serve when its audit sink is unwritable,
// because a full disk would then be a total outage. An operator who needs
// write-or-refuse semantics does not have it yet, and this comment is the place
// that says so rather than a doc that implies otherwise.
package audit

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Kind classifies an event. Kept small and closed: an auditor greps on it.
type Kind string

const (
	// KindAuth is a login or a logout, successful or not. The most important
	// events in the log, and the only ones recorded for an unauthenticated
	// request.
	KindAuth Kind = "auth"
	// KindAction is a state-changing request: every POST that reaches a handler.
	KindAction Kind = "action"
	// KindStatement is one SQL statement TableX ran on the user's behalf.
	KindStatement Kind = "statement"
)

// Outcome is how an event ended.
type Outcome string

const (
	OutcomeOK      Outcome = "ok"
	OutcomeDenied  Outcome = "denied" // refused by policy: auth, CSRF, throttle
	OutcomeError   Outcome = "error"
	OutcomeInvalid Outcome = "invalid" // the request was malformed or rejected
)

// Event is one audit record. Empty fields are omitted from the JSON so a line
// stays readable; Time, Kind and Outcome are always present.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    Kind      `json:"kind"`
	Outcome Outcome   `json:"outcome"`

	// Request is the request id, shared with the access log's "id" field, so an
	// audit line can be tied back to the full HTTP context.
	Request string `json:"request,omitempty"`

	// Identity. Account is what the SERVER reports for the connection
	// ("root@localhost", "tablex"), which is the truthful answer to "whose
	// privileges did this run under" — not what was typed at the login form.
	Account string `json:"account,omitempty"`

	// Subject/Email are the PERSON, when an SSO gate is configured — the
	// provider's stable subject and the address it reported. They sit beside
	// Account rather than replacing it: the statement really did run under that
	// database account, and the value of having both is being able to join "which
	// person" to "which privileges". Empty when no gate is configured, which is
	// also how a reader tells the two deployments apart.
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`

	Server string `json:"server,omitempty"`
	Engine string `json:"engine,omitempty"`
	Remote string `json:"remote,omitempty"`

	// What. Target is the object in engine-neutral dotted form ("sales.orders"),
	// so the log can be queried by object rather than by URL shape.
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
	Status int    `json:"status,omitempty"`

	// Statement fields (KindStatement). Rows is affected rows for a mutation and
	// rows returned for a read; UserSQL marks SQL the user WROTE (the console, an
	// import) as opposed to SQL TableX generated for them (the Drop button, the
	// structure editor) — reading "DROP TABLE orders" in the trail, that is the
	// first thing worth knowing.
	Statement string `json:"statement,omitempty"`
	Rows      int64  `json:"rows,omitempty"`
	UserSQL   bool   `json:"user_sql,omitempty"`

	// Detail is a sanitized explanation when the outcome is not ok. It carries an
	// engine error message, which is why it goes through the same redaction the
	// UI uses before it reaches here.
	Detail string `json:"detail,omitempty"`

	// Millis is the duration in milliseconds.
	Millis int64 `json:"ms,omitempty"`
}

// Sink is one destination for audit events. Implementations must be safe for
// concurrent use: every request may emit.
type Sink interface {
	Write(Event) error
	Close() error
}

// Logger fans an event out to every configured sink. A nil *Logger is a valid
// disabled logger — every method tolerates it — so callers never have to guard.
type Logger struct {
	sinks []Sink
	log   *slog.Logger

	// Sink failures are throttled the same way and for the same reason as the
	// session store's degradation warning: one line per failed write would bury
	// the log during an outage.
	mu       sync.Mutex
	reported time.Time
	failures int

	// Monotonic totals for /metrics, kept separately because the two fields above
	// are ZEROED by the throttle: they count "occurrences since the last line",
	// which is what the log line needs and the opposite of what a scraper needs.
	// A trail that has silently stopped recording is the failure this whole
	// package exists to make visible, so an operator has to be able to alarm on
	// it without reading logs.
	emitted atomic.Int64
	dropped atomic.Int64
}

// Stats reports the totals since startup: events written, and writes that failed.
// dropped counts SINK failures, so one event failing on two sinks counts twice —
// the question it answers is "is the trail losing records", and it errs toward
// saying yes.
func (l *Logger) Stats() (emitted, dropped int64) {
	if l == nil {
		return 0, 0
	}
	return l.emitted.Load(), l.dropped.Load()
}

// failureReportEvery throttles the "could not write the audit trail" report.
const failureReportEvery = 30 * time.Second

// New returns a Logger over the given sinks, or nil when there are none — so
// "audit is off" and "audit has no destinations" are the same state, and there is
// no half-enabled configuration to reason about.
func New(log *slog.Logger, sinks ...Sink) *Logger {
	if len(sinks) == 0 {
		return nil
	}
	return &Logger{sinks: sinks, log: log}
}

// Enabled reports whether events are being recorded. Callers use it to skip
// assembling an Event at all, not for correctness — Emit is already a no-op when
// disabled.
func (l *Logger) Enabled() bool { return l != nil && len(l.sinks) > 0 }

// Emit writes an event to every sink. Time is stamped here when the caller left
// it zero, so no caller has to remember.
func (l *Logger) Emit(e Event) {
	if !l.Enabled() {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeOK
	}
	l.emitted.Add(1)
	for _, s := range l.sinks {
		if err := s.Write(e); err != nil {
			l.dropped.Add(1)
			l.reportFailure(err)
		}
	}
}

// reportFailure surfaces a sink error. An audit trail that has silently stopped
// recording is worse than one that never started, so this is ERROR rather than
// WARN even though the request itself succeeded.
func (l *Logger) reportFailure(err error) {
	if l.log == nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	l.failures++
	if !l.reported.IsZero() && now.Sub(l.reported) < failureReportEvery {
		l.mu.Unlock()
		return
	}
	n := l.failures
	l.reported, l.failures = now, 0
	l.mu.Unlock()
	l.log.Error("the audit trail could not be written; events are being LOST", "err", err, "occurrences", n)
}

// Close closes every sink, returning the first error. Called once at shutdown.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	var first error
	for _, s := range l.sinks {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
