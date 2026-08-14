// Server-side confirmation for destructive actions.
//
// The gap this closes: confirmation used to be an `hx-confirm` attribute and
// nothing else, so with JavaScript disabled a Drop button acted on the first
// click. docs/security.md called that out as a known gap and warned against
// describing the prompt as a server-side control.
//
// What this is, precisely: an ACCIDENTAL-CLICK guard, not an authorization
// control. Authorization is the CSRF token plus each handler's own re-checks
// (the object must exist in fresh introspection, the account must be allowed).
// A caller that wants to skip the interstitial can always send the field —
// which is exactly what the htmx path does, having already shown a dialog.

package handlers

import (
	"net/http"
	"sort"
)

// confirmField is the form field that says a confirmation step happened. Its
// value is not a secret and is not checked against anything: a request that
// carries it has either been through the interstitial below or through the
// client-side dialog (app.js adds it when htmx's hx-confirm is accepted).
const confirmField = "tx_confirm"

type confirmFieldVM struct{ Name, Value string }

type confirmBody struct {
	Prompt      string
	PostURL     string
	CancelURL   string
	ActionLabel string
	Fields      []confirmFieldVM
	ConfirmName string
}

// requireConfirm reports whether the request may proceed. When it may not, the
// confirmation page has already been written and the caller must return.
//
// Call it LAST, immediately before the mutation: every existence and authority
// check should have run first, so the operator is never asked to confirm
// something that would have failed anyway, and a rejection stays a rejection
// rather than becoming a confirmation prompt.
//
// prompt is the sentence shown to the operator; it should name the object.
// backURL is where Cancel goes. uc is the already-resolved user — every
// destructive route is behind the auth gate, so there is always one. sc is the
// request scope, used only to build the breadcrumb: the page used to render
// with an empty breadcrumb and an empty tab strip. Tabs are DELIBERATELY
// omitted — a terminal confirmation page has no sibling tabs — and the layout
// hides the (always-emitted) tab container when there are none, so no bare
// bordered strip is left on either the full-page or the htmx path.
func (h *Handlers) requireConfirm(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, prompt, backURL, actionLabel string) bool {
	if r.PostFormValue(confirmField) != "" {
		return true
	}
	body := confirmBody{
		Prompt: prompt,
		// Re-post to exactly this target, query string included — several
		// destructive routes carry their object in the query (?schema=, ?name=).
		PostURL:     r.URL.RequestURI(),
		CancelURL:   backURL,
		ActionLabel: actionLabel,
		ConfirmName: confirmField,
	}
	for name, values := range r.PostForm {
		// The CSRF token is re-issued by the template, never echoed. Nothing
		// destructive carries a password, but a form field named like one is
		// dropped rather than round-tripped through a rendered page.
		if name == "csrf_token" || name == confirmField || name == "password" {
			continue
		}
		for _, v := range values {
			body.Fields = append(body.Fields, confirmFieldVM{Name: name, Value: v})
		}
	}
	// Deterministic order: map iteration is random, and an unstable page is
	// unstable to diff and to test.
	sort.Slice(body.Fields, func(i, j int) bool {
		if body.Fields[i].Name != body.Fields[j].Name {
			return body.Fields[i].Name < body.Fields[j].Name
		}
		return body.Fields[i].Value < body.Fields[j].Value
	})

	p := h.newLoggedPage(r, uc, "Confirm")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	// No p.Tabs: a confirmation is a terminal page with no sibling tabs. This
	// is the deliberate contrast with an error panel (see renderError), which
	// preserves the previous page's chrome.
	p.Body = body
	h.render(w, r, "confirm", p)
	return false
}
