package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/server/handlers"
)

// Restricted mode (config [restrict], docs/security.md §9) enforced where it has
// to be: on the request, before the handler, keyed on the route.
//
// The policy is a table, declared route by route in router.go, rather than a
// check scattered through the handlers — for the same reason the audit action
// log is one middleware: a route added tomorrow must not quietly escape it. The
// DEFAULT below is therefore the restrictive one — a state-changing request that
// resolves to no policy entry is treated as needing DDL permission, so a new
// route is refused under `allow_ddl = false` until somebody declares its needs
// deliberately.
//
// What this is not: a replacement for database grants. It is the layer that
// covers what grants cannot express — an operator who must use a privileged
// account and wants TableX itself to refuse the dangerous half.

// need describes what a route requires.
type need struct {
	// write is set for anything that changes state. Refused by read_only.
	write bool
	// console is set for the routes that run SQL TableX did not write: the
	// console and SQL import. Refused by allow_console = false. Two more paths are
	// the same class but cannot be expressed here, because each shares an endpoint
	// with something that must keep working — the stored-program EDITOR (save vs.
	// drop) and a partial index's WHERE predicate (one field of one structure
	// action). saveProgram and runStructureOp carry those checks themselves.
	console bool
	// ddl is set for schema and access-control changes. Refused by
	// allow_ddl = false. Row edits are deliberately NOT ddl.
	ddl bool
}

// needFor resolves what a request needs, by asking the policy mux which pattern
// the request matches. A middleware cannot read r.Pattern — ServeMux stamps it
// inside its own ServeHTTP, long after every middleware has run — so the policy
// is registered on a parallel mux with identical patterns and consulted here.
//
// Fail closed on anything that is not a policy entry. Two shapes reach this that
// are not:
//
//   - A redirect handler. GET /static (no trailing slash) is not public, and the
//     mux answers it with the subtree-redirect handler; a path needing cleaning
//     (GET //db/main) gets the cleaned-path redirect. Both are *redirectHandler,
//     not policyEntry, and the first arrives with a NON-empty pattern — which is
//     exactly what a bare type assertion would panic on.
//   - No match at all: an unregistered path, or a registered path with an
//     unregistered method. Both come back with an empty pattern.
//
// The comma-ok covers the first and the empty-pattern test the second, and the
// default below is what TestAnUnclassifiedRouteFailsClosed pins.
func (s *Server) needFor(r *http.Request) need {
	unsafe := !isSafeRequest(r)
	nd := need{write: unsafe, ddl: unsafe}
	h, pat := s.policy.Handler(r)
	if entry, ok := h.(policyEntry); ok && pat != "" {
		nd = entry.need
	}
	return nd
}

// isSafeRequest reports whether the method cannot change state. It defers to
// auth.SafeMethod so this gate and the CSRF gate share ONE definition — see the
// comment there for what went wrong when they did not.
func isSafeRequest(r *http.Request) bool { return auth.SafeMethod(r.Method) }

// databaseOf returns the database a path addresses, or "" for the server level.
// It parses the path because this runs before routing, so there are no ServeMux
// path values yet — the same reason audit.Target does. No dialect is in scope
// at either site, so the split stays engine-agnostic.
//
// It takes the ESCAPED path and unescapes each segment itself, which is exactly
// what net/http's router does (firstSegment → pathUnescape). Splitting the
// DECODED path was the bug: a %2F has already become a real separator there, so
// /db/app%2Fbackup/… reads as database "app" while the router hands the handler
// PathValue("db") == "app/backup". Unescaping the decoded path a second time
// would not be a fix but a corruption — /db/a%2525b decodes to a%25b, which a
// second pass turns into a%b.
//
// EVERY segment is unescaped, not only the one returned. The seg[0] == "db"
// test compares a LITERAL, and net/http matches its literal pattern segments
// against the UNESCAPED segment — so GET /%64b/main routes to GET /db/{db} with
// PathValue("db") == "main". Unescaping just seg[1] would leave seg[0] as
// "%64b", return "", and skip the allowlist check altogether: a new bypass, in
// a case the code gets right today.
//
// A segment that fails to unescape is used UNCHANGED, matching net/http's
// pathUnescape fallback. Returning "" there would diverge from the router in
// the unsafe direction, and rejecting %2F outright is not a fix.
func databaseOf(escaped string) string {
	seg := strings.Split(strings.Trim(escaped, "/"), "/")
	for i, s := range seg {
		if u, err := url.PathUnescape(s); err == nil {
			seg[i] = u
		}
	}
	if len(seg) >= 2 && seg[0] == "db" {
		return seg[1]
	}
	return ""
}

// restrict enforces the [restrict] policy. It runs INSIDE the auth gate, so an
// unauthenticated request is still sent to the login page rather than told which
// routes exist.
func (s *Server) restrict(next http.Handler) http.Handler {
	rc := s.cfg.Restrict
	if !rc.Restricted() {
		return next // nothing configured: not even a path split per request
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// Two readings of the path, one line apart, and that is deliberate:
		// isPublicPath above compares exact literals against the DECODED path,
		// this one segments the ESCAPED path the way the router will. The
		// divergence is fail-safe — a %2F that makes the decoded path look public
		// (or static) matches no pattern at all and 404s, and it is that 404, not
		// any agreement between the two readings, that makes it safe.
		if db := databaseOf(r.URL.EscapedPath()); db != "" && !rc.DatabaseAllowed(db) {
			s.refuse(w, r, "This TableX is limited to a fixed set of databases, and "+db+" is not one of them.")
			return
		}
		nd := s.needFor(r)
		switch {
		case nd.console && !rc.AllowConsole:
			s.refuse(w, r, "Running SQL directly is disabled on this TableX (restrict.allow_console).")
		case nd.write && rc.ReadOnly:
			// Stated as read-only rather than as the specific operation: under
			// read_only nothing is writable, and naming the operation would imply
			// some other one might be.
			s.refuse(w, r, "This TableX is read-only (restrict.read_only). Nothing can be changed through it.")
		case nd.ddl && !rc.AllowDDL:
			s.refuse(w, r, "Changing schemas, accounts and privileges is disabled on this TableX (restrict.allow_ddl). Editing rows is still available.")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// refuse answers a request the policy forbids.
//
// 403, and the message names the setting responsible: the person who hits this is
// usually the operator who configured it, and "forbidden" alone sends them
// looking for a database grant that is not the cause. It carries no information
// an authenticated user did not already have — they are past the auth gate, and
// the policy is the operator's own.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, msg string) {
	s.log.Warn("refused by restricted mode",
		"path", r.URL.Path, "method", r.Method, "reqid", handlers.RequestID(r.Context()))
	s.metrics.refusedByPolicy()
	// The audit trail should show a policy refusal as a refusal, not as whatever
	// the status code implies.
	audit.FromContext(r.Context()).SetOutcome(audit.OutcomeDenied, msg)
	s.handlers.RenderRestricted(w, r, msg)
}
