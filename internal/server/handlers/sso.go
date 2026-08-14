package handlers

// The SSO gate: two routes that stand in front of the login form.
//
// What this does NOT do is log anyone in. TableX opens every database connection
// with the user's own credentials, and that is what makes the audit trail's
// account field the truthful answer to whose privileges a statement ran under. So
// passing the provider gets you to the login form and nothing more; the verified
// subject is recorded alongside the database account, not instead of it.

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/session"
)

// SSOStart begins the authorization-code flow: mint a handshake, remember it on
// this browser's session, and redirect to the provider.
func (h *Handlers) SSOStart(w http.ResponseWriter, r *http.Request) {
	if h.SSO == nil {
		http.NotFound(w, r)
		return
	}
	// Throttle only a request that MINTED state, which is the unbounded
	// resource an anonymous GET loop consumes: sessionMW has already run
	// Sessions.Start for this request, so a fresh arrival costs a whole new
	// session (bounded otherwise only by the session-CREATION throttle, which
	// is off by default). A request that arrived WITH a session is exempt,
	// because its marginal cost is O(1) — the handshake below overwrites that
	// session's own slot in place rather than appending, no session is created,
	// and this route never contacts the provider: the token exchange is the
	// callback's, budgeted separately under sso:cb.
	//
	// That exemption is required for the gate to work at all, not a nicety:
	// ssoGate redirects EVERY unverified request for every human route here, so
	// a budget charged on each arrival is spent by ordinary page loads — and
	// behind one NAT egress address a handful of colleagues arriving together,
	// or one person with several restored tabs, would lock the whole office out
	// of the sign-in entry point, a refusal /login's GET traffic never causes.
	//
	// Sessions.Load(r) is the creation-accurate test, and the reason this is
	// not a cookie-presence check: Load returns nil for a missing, invalid OR
	// expired cookie — the same condition Start mints on — so sending garbage
	// cannot buy an exemption (session.Manager.Start documents this trap).
	// Reading it again here is safe and correct: sessionMW sets the new cookie
	// on the RESPONSE, leaving this request's headers untouched, so Load still
	// reports what the browser actually presented.
	//
	// The key is namespaced ("sso:start|<ip>") because the limiter's keyspace
	// is flat and /login reserves the bare IP: sharing it would put start,
	// callback and the login POST on one budget and let an anonymous start loop
	// exhaust an IP's password-login capacity. The window/max are
	// login_rate_window/login_rate_max — an operator who disables login
	// throttling (max <= 0) disables this with it — and the key is NEVER Reset,
	// the same reason login retains its coarse IP hit.
	if h.Sessions.Load(r) == nil && !h.Rate.Reserve("sso:start|"+auth.ClientIP(r, h.Proxy)) {
		h.ssoRateLimited(w, r)
		return
	}
	// A session is needed BEFORE the redirect, because the nonce that binds the
	// returned token to this browser has to be stored somewhere the callback can
	// read it back from.
	s := h.currentSession(r)
	if s == nil {
		s = h.Sessions.Start(w, r)
	}
	if s == nil {
		h.ssoFailure(w, r, "The server is at session capacity; try again shortly.", "no session")
		return
	}

	hs, err := auth.NewHandshake()
	if err != nil {
		h.ssoFailure(w, r, "Could not start single sign-on.", err.Error())
		return
	}
	// The VERIFIED half is carried across, not replaced. Overwriting the whole
	// struct signed out anyone who reached this route with an identity already
	// established — a stray click, an htmx HX-Redirect, a bookmarked /auth/sso —
	// and made them re-run the whole flow. The handshake half below is minted
	// fresh every time, so a stale one is never reused.
	//
	// This is only safe because every DENIAL path in the callback clears the
	// struct: preserving here without clearing there would turn "locked out" into
	// "keeps access until the session expires", since ssoGate re-checks
	// Verified() and never re-checks the allowlist.
	prev := s.SSO()
	s.SetSSO(session.SSO{
		State: hs.State, Nonce: hs.Nonce, Verifier: hs.Verifier,
		Subject: prev.Subject, Email: prev.Email, Name: prev.Name,
	})
	http.Redirect(w, r, h.SSO.AuthCodeURL(hs), http.StatusSeeOther)
}

// SSOCallback completes the flow. Every failure below lands on the same generic
// page: the differences matter to the operator's log, not to whoever is holding
// a bad callback.
func (h *Handlers) SSOCallback(w http.ResponseWriter, r *http.Request) {
	if h.SSO == nil {
		http.NotFound(w, r)
		return
	}
	s := h.currentSession(r)
	if s == nil {
		// No session means no handshake, so there is nothing this callback could
		// be completing. Send them back to the start rather than erroring.
		http.Redirect(w, r, urlSSOStart(), http.StatusSeeOther)
		return
	}

	// The ordering below is load-bearing: VALIDATE (non-mutating) → RESERVE →
	// COMPARE-AND-CONSUME → EXCHANGE. Validating first is safe because it
	// mutates nothing; reserving before consuming matters because Reserve
	// records nothing when refused — consuming first would spend the
	// handshake and then 429, leaving the user unable to retry without
	// restarting the whole flow. The consume remains the single serialization
	// point, so the concurrent-callback race stays closed; the accepted trade
	// is that a racing loser may spend rate budget, but never reaches
	// Exchange, and a limiter refusal leaves the handshake intact.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// The provider itself refused (consent denied, and so on).
		h.ssoFailure(w, r, "Single sign-on was not completed.", "provider returned error="+errParam)
		return
	}
	if !h.Rate.Reserve("sso:cb|" + auth.ClientIP(r, h.Proxy)) {
		h.ssoRateLimited(w, r)
		return
	}
	// Single-use, atomically: the handshake is returned ONLY on a state match
	// and consumed in the same lock scope, so two concurrent callbacks on one
	// session cookie cannot both reach Exchange (SSO()+SetSSO were two lock
	// acquisitions, and both racers passed the check against their own
	// copies). A mismatch leaves the handshake INTACT — before the state
	// check this request is unauthenticated, and anyone can point a victim's
	// browser at ?state=garbage.
	state, nonce, verifier, ok := s.ConsumeSSOHandshake(func(stored string) bool {
		return auth.StateMatches(stored, r.URL.Query().Get("state"))
	})
	if !ok {
		// Either this browser never started a flow, or the state was forged —
		// which is exactly the CSRF this parameter exists to stop.
		h.ssoFailure(w, r, "Single sign-on could not be verified. Start again.", "state mismatch")
		return
	}
	// PAST THE STATE CHECK, and that boundary is what decides whether a denial
	// may clear the verified identity. Before it, this request is unauthenticated
	// — so clearing above would be a logout CSRF. The paths above therefore
	// never clear (no session, provider error=, throttled, state mismatch);
	// every path from here down always does, because it is a denial this
	// browser really did earn.
	//
	// It is a rule, not a list: a new failure path added below inherits it.
	deny := func(userMessage, detail string) {
		s.SetSSO(session.SSO{})
		h.ssoFailure(w, r, userMessage, detail)
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		deny("Single sign-on could not be verified. Start again.", "no authorization code")
		return
	}

	id, err := h.SSO.Exchange(r.Context(), code, auth.Handshake{
		State: state, Nonce: nonce, Verifier: verifier,
	})
	if err != nil {
		deny("Single sign-on could not be verified. Start again.", err.Error())
		return
	}
	if h.Cfg.SSO.HasAllowlist() && !id.EmailVerified {
		// The allowlist admits by EMAIL, and an email the provider has not
		// verified is an attacker-choosable string on any self-service
		// provider (CVE-2024-27918 is this exact class). Absent counts as
		// unverified — some providers never send the claim — so such a
		// deployment must either enable verification at the IdP or drop the
		// allowlist. With no allowlist configured nothing is matched on the
		// email, and nothing changes.
		h.auditSSO(r, audit.OutcomeDenied, id.Subject, id.Email, "email is not verified by the provider, but an allowlist is configured")
		deny("Your email address is not verified by the identity provider, so it cannot be checked against this instance's allowlist. Verify it with the provider, or ask the operator to remove sso.allowed_emails/allowed_domains.",
			"unverified email with an allowlist configured: "+id.Email)
		return
	}
	if !h.Cfg.SSO.PermitsIdentity(id.Email) {
		// Verified by the provider, but outside the set of people this deployment
		// admits. Logged with the identity, because an operator debugging "why
		// can't Dana in?" needs to see who was turned away.
		h.auditSSO(r, audit.OutcomeDenied, id.Subject, id.Email, "identity is not in sso.allowed_emails/allowed_domains")
		deny("Your account is not permitted to use this TableX instance.", "identity not allowed: "+id.Email)
		return
	}

	s.SetSSO(session.SSO{Subject: id.Subject, Email: id.Email, Name: id.Name})
	h.auditSSO(r, audit.OutcomeOK, id.Subject, id.Email, "")
	http.Redirect(w, r, urlLogin(), http.StatusSeeOther)
}

// ssoRateLimited answers an SSO route the limiter refused. Neither existing
// responder fits: ssoFailure files OutcomeError when this is a DENIAL, and it
// renders through renderError, whose htmx arm for a not-logged-in caller —
// exactly this case — emits HX-Redirect /login at HTTP 200, which ssoGate
// bounces straight back to the start route: a redirect loop. So both normal
// and htmx callers get the real 429 with Retry-After (the same reasoning
// refuseSessionCreate documents), the denial is recorded directly, and the
// refused path mutates no handshake and reaches no token exchange.
func (h *Handlers) ssoRateLimited(w http.ResponseWriter, r *http.Request) {
	h.Log.Warn("single sign-on throttled",
		"remote", auth.ClientIP(r, h.Proxy), "path", r.URL.Path, "reqid", RequestID(r.Context()))
	h.auditSSO(r, audit.OutcomeDenied, "", "", "refused: too many single sign-on requests from this address")
	w.Header().Set("Retry-After", strconv.Itoa(auth.RetryAfterSeconds(h.Cfg.Security.LoginRateWindow)))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintln(w, "Too many single sign-on attempts from this address. Please wait and try again.")
}

// ssoFailure logs the real reason and shows the user a generic one. The detail is
// an operator's diagnostic — "state mismatch", a provider error code — and
// handing it to the browser would tell an attacker which check they tripped.
func (h *Handlers) ssoFailure(w http.ResponseWriter, r *http.Request, userMessage, detail string) {
	h.Log.Warn("single sign-on failed",
		"reason", detail, "remote", auth.ClientIP(r, h.Proxy), "path", r.URL.Path)
	h.auditSSO(r, audit.OutcomeError, "", "", detail)
	// 403, not 401: 401 invites a credential prompt, and no credential of the
	// user's would help here. The guidance rides in the MESSAGE, not the detail
	// argument: the error page renders a detail as the offending SQL, under a
	// "Statement:" heading in a code block, and this page is reached routinely
	// (a stale handshake is the common, innocent case) by people who typed no
	// SQL at all.
	h.renderError(w, r, http.StatusForbidden,
		userMessage+" Single sign-on is required before you can reach the login form. "+
			"Start again at "+urlSSOStart()+".", "")
}

// auditSSO records a gate decision. It names the PERSON (subject/email) and
// deliberately carries no account: nobody has logged into a database yet, and
// filling Account here would make the trail claim a privilege context that does
// not exist.
func (h *Handlers) auditSSO(r *http.Request, outcome audit.Outcome, subject, email, detail string) {
	if !h.Audit.Enabled() {
		return
	}
	h.Audit.Emit(audit.Event{
		Kind:    audit.KindAuth,
		Outcome: outcome,
		Request: RequestID(r.Context()),
		Subject: audit.Name(subject),
		Email:   audit.Name(email),
		Remote:  auth.ClientIP(r, h.Proxy),
		Method:  r.Method,
		Path:    r.URL.Path,
		Detail:  detail,
	})
}
