package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Pending carries what is known about a request while it is still being handled.
//
// It exists because of the shape of the middleware chain. The audit event is
// emitted by the OUTERMOST middleware, which is the only layer that sees the
// final status and the total duration — but the identity is not known until the
// session has been loaded several layers deeper, and each layer passes a DERIVED
// request whose context the outer one never sees. A pointer stashed on the way in
// is the one thing every layer can write to and the outer layer can still read.
//
// It is also the hook a handler uses to say something the status code cannot: a
// login knows WHICH account it authenticated, and a failure knows why.
type Pending struct {
	mu      sync.Mutex
	account string
	server  string
	engine  string
	remote  string
	outcome Outcome
	detail  string
}

type ctxKey struct{}

// NewContext stashes p in ctx.
func NewContext(ctx context.Context, p *Pending) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the pending record for this request, or nil. A nil
// *Pending is usable — every method tolerates it — so no caller needs to check.
func FromContext(ctx context.Context) *Pending {
	p, _ := ctx.Value(ctxKey{}).(*Pending)
	return p
}

// SetIdentity records who the request is acting as. Called once the session is
// known; safe to call again if it changes mid-request, which is exactly what a
// login does.
func (p *Pending) SetIdentity(account, server, engine string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.account, p.server, p.engine = account, server, engine
}

// SetOutcome overrides the outcome the status code would imply, and gives a
// reason. Use it where the status is misleading: a failed login re-renders the
// form with 200, which as an audit record would read as a successful one.
func (p *Pending) SetOutcome(o Outcome, detail string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outcome, p.detail = o, detail
}

// SetOutcomeIfUnset records outcome/detail only when no layer has said
// anything more specific yet. The GENERIC failure responders use it —
// renderError's htmx arm answers at wire 200 so the panel swaps, and
// redirectTo answers 303/204 — where OutcomeForStatus would file a failed
// mutation as ok. The layers that know more (capacity and policy refusals
// pre-set OutcomeDenied) always win: SetOutcome overwrites, this never does.
func (p *Pending) SetOutcomeIfUnset(o Outcome, detail string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.outcome != "" {
		return
	}
	p.outcome, p.detail = o, detail
}

// SetRemote records the resolved client address. It is set once, on the way in,
// so a statement observer deep in the driver can name the client without every
// layer between having to pass it along.
func (p *Pending) SetRemote(remote string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remote = remote
}

// Identity returns what has been recorded so far.
func (p *Pending) Identity() (account, server, engine string) {
	if p == nil {
		return "", "", ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.account, p.server, p.engine
}

// Remote returns the recorded client address.
func (p *Pending) Remote() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.remote
}

// Outcome returns the override, if a layer set one.
func (p *Pending) Outcome() (Outcome, string) {
	if p == nil {
		return "", ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.outcome, p.detail
}

// OutcomeForStatus maps an HTTP status onto an outcome, for the events where no
// layer said anything more specific. (See SetOutcomeIfUnset's precedence test.)
//
// 401/403 are separated from the rest of the 4xx range on purpose: "refused by
// policy" is the class an auditor filters on, and lumping it in with a malformed
// form would bury it.
func OutcomeForStatus(status int) Outcome {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return OutcomeDenied
	case status >= 500:
		return OutcomeError
	case status >= 400:
		return OutcomeInvalid
	default:
		return OutcomeOK
	}
}

// maxNameBytes bounds a recorded identity.
const maxNameBytes = 128

// Name bounds a caller-supplied identity before it is recorded.
//
// A REJECTED login carries whatever username was posted, so this field is
// attacker-controlled on exactly the events an auditor most needs to read. An
// unbounded one lets a sprayer inflate the trail at will. The cut is made valid
// UTF-8 again afterwards, so a name split mid-rune cannot leave a mangled byte in
// the record.
func Name(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxNameBytes {
		return s
	}
	return strings.ToValidUTF8(s[:maxNameBytes], "") + "…"
}

// maxStatementBytes bounds a recorded statement.
const maxStatementBytes = 4096

// Statement bounds the SQL text before it is recorded, and collapses the
// whitespace so one statement stays one line an auditor can read.
//
// The bound is not optional: a single INSERT from a SQL import can be megabytes,
// and a trail whose lines are that long is one nobody will grep. The truncation is
// marked, so a reader is never misled about having the whole statement — and the
// cut is made valid UTF-8 again, since SQL carries arbitrary string literals.
func Statement(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxStatementBytes {
		return s
	}
	return strings.ToValidUTF8(s[:maxStatementBytes], "") + fmt.Sprintf(" …[truncated, %d bytes total]", len(s))
}

// Target names the object a request acts on, in engine-neutral dotted form
// ("sales", "sales.orders", "sales.public.orders"), so the trail can be queried
// by object instead of by URL shape.
//
// It parses the path rather than reading ServeMux path values, because the audit
// event is assembled by a middleware that runs BEFORE routing — there are no path
// values yet. The two shapes are all TableX has:
//
//	/db/{db}[/...]
//	/db/{db}/table/{table}[/...]
//
// A PostgreSQL schema arrives as a query parameter rather than a path segment, so
// it is spliced in between when present. Anything else — /server/*, /login — has
// no single object and returns "".
// Like restrict.databaseOf, it segments the ESCAPED path and unescapes each
// segment itself, because it too runs before routing. Splitting the decoded
// path made a %2F look like a real separator, so /db/app%2Fbackup logged the
// target as "app" while the handler operated on "app/backup" — and it is the
// literal seg[0] != "db" and seg[2] == "table" tests that force EVERY segment
// to be unescaped rather than just the two extracted: net/http compares its
// literal pattern segments against the unescaped value, so /%64b/main really
// does route to /db/{db}. A segment that fails to unescape is used unchanged,
// matching net/http's own fallback.
func Target(r *http.Request) string {
	seg := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	for i, s := range seg {
		if u, err := url.PathUnescape(s); err == nil {
			seg[i] = u
		}
	}
	if len(seg) < 2 || seg[0] != "db" || seg[1] == "" {
		return ""
	}
	parts := []string{seg[1]}
	if schema := r.URL.Query().Get("schema"); schema != "" {
		parts = append(parts, schema)
	}
	if len(seg) >= 4 && seg[2] == "table" && seg[3] != "" {
		parts = append(parts, seg[3])
	}
	return strings.Join(parts, ".")
}
