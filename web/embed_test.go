package web

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestAppJSCSPHardening guards the front-end CSP/cookie hardening that has no JS
// test runner to cover it. These are content assertions (a regression guard for
// the specific lines), not a behavioral check: the browser-side effect is
// verified manually per docs/security.md.
func TestAppJSCSPHardening(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		// #57: htmx aligned with the strict CSP (no eval, no script-in-swap).
		"allowEval = false",
		"allowScriptTags = false",
		// #15: theme value whitelisted before it is applied/persisted.
		`saved === "dark" || saved === "light"`,
		// #27: cookies carry Secure over https.
		`window.location.protocol === "https:"`,
		// #1: nav highlight keys on path + the normalized schema param only.
		`.get("schema")`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing hardening marker %q", want)
		}
	}
}

// TestLoadingFeedback guards the loading feedback. The behaviour is a browser one and there is no
// JS runner, so these are content assertions on the three signals: the in-flight
// counter that drives the bar, the aria-busy attribute on the swapped region,
// and the submit lock that stops a double POST. The CSS half matters as much —
// the bar is invisible without it, and a fix that forgot prefers-reduced-motion
// would animate for people who asked it not to.
func TestLoadingFeedback(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		// Counted, not toggled: overlapping requests must not end the bar early.
		"inflight++",
		"if (inflight === 1) progressStart()",
		"inflight = Math.max(0, inflight - 1)",
		"if (inflight === 0) progressDone()",
		// Both events, or the counter leaks / the bar never clears.
		`"htmx:beforeRequest"`,
		`"htmx:afterRequest"`,
		// The non-visual signal.
		`setAttribute("aria-busy", "true")`,
		`removeAttribute("aria-busy")`,
		// Double-submit protection. Both halves, named separately: recording
		// what was disabled and releasing it are different lines, and a marker
		// that matched either would let the other one go missing.
		"controls[i].disabled = true",
		"e.detail.elt.txLocked = locked",
		"elt.txLocked[i].disabled = false",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing loading-feedback marker %q", want)
		}
	}

	// The CSS half is checked rule by rule rather than by substring: the same
	// selector appears in more than one block (the reduced-motion override
	// repeats .tx-progress.is-loading), so a substring search for the selector
	// can be satisfied by the wrong block while the real rule is gone.
	css := loadCSS(t)
	rules := cssRules(css)
	declares := func(match func(string) bool, decl string) bool {
		for _, r := range rules {
			if match(r.sel) && strings.Contains(r.body, decl) {
				return true
			}
		}
		return false
	}
	exact := func(s string) func(string) bool {
		return func(sel string) bool { return sel == s }
	}
	within := func(s string) func(string) bool {
		return func(sel string) bool { return strings.Contains(sel, s) }
	}
	for _, want := range []struct {
		what  string
		match func(string) bool
		decl  string
	}{
		{".tx-progress is a fixed bar", exact(".tx-progress"), "position: fixed"},
		{".tx-progress uses the accent token", exact(".tx-progress"), "background: var(--tx-progress)"},
		{".tx-progress starts hidden", exact(".tx-progress"), "opacity: 0"},
		{"the loading state creeps", exact(".tx-progress.is-loading"), "width: 90%"},
		{"the loading state animates", exact(".tx-progress.is-loading"), "transition: width"},
		{"the done state completes", exact(".tx-progress.is-done"), "width: 100%"},
		{"the requesting control shows a wait cursor", exact(".htmx-request"), "cursor: progress"},
		{"the stale region dims", within(`[aria-busy="true"]`), "opacity: 0.6"},
		{"the dim is delayed so fast swaps do not flicker", within(`[aria-busy="true"]`), "linear 400ms"},
	} {
		if !declares(want.match, want.decl) {
			t.Errorf("tablex.css: %s — no rule declares %q", want.what, want.decl)
		}
	}
	// A reduced-motion block has to actually cover the bar; blocks that only
	// mentioned other selectors would satisfy the check above. There is more than
	// one such block, so look inside each rather than assuming an order.
	var pinned bool
	for _, after := range strings.Split(css, "@media (prefers-reduced-motion: reduce) {")[1:] {
		body, _, _ := strings.Cut(after, "\n}")
		if strings.Contains(body, ".tx-progress.is-loading { width: 100%; }") {
			pinned = true
		}
	}
	if !pinned {
		t.Error("no prefers-reduced-motion block pins the progress bar to a static width")
	}
}

// TestDrawerAccessibility guards the drawer. The closed off-canvas sidebar used to be
// hidden by transform alone, which moves it off-screen but leaves the whole
// database tree in the tab order and in the accessibility tree — focus would
// walk into content nobody could see. The fix is half CSS (visibility, which
// tracks the media query with no JS) and half the rest of the modal contract:
// focus into the drawer on open, back to the toggle on dismiss, and Tab kept
// inside while it is an overlay.
func TestDrawerAccessibility(t *testing.T) {
	css := loadCSS(t)
	drawer, _, found := strings.Cut(css, "body.tx-nav-open .tx-nav {")
	if !found {
		t.Fatal("tablex.css: no open-drawer rule; the responsive block has moved")
	}
	// The closed state must leave the tab order, not merely leave the viewport.
	i := strings.LastIndex(drawer, ".tx-nav {")
	if i < 0 || !strings.Contains(drawer[i:], "visibility: hidden") {
		t.Error("tablex.css: the closed drawer is not visibility:hidden, so the " +
			"database tree stays focusable off-screen")
	}
	if !strings.Contains(css, "visibility: visible") {
		t.Error("tablex.css: the open drawer never becomes visible again")
	}

	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		// Only trap when the drawer is an overlay: on a wide screen the sidebar is
		// permanent furniture and trapping focus in it would be the bug.
		"function navIsOverlay()",
		"if (!navIsOverlay()) return;",
		`if (e.key !== "Tab" || !navIsOverlay()) return;`,
		// Focus in on open, back out on dismiss.
		"navReturnFocus = document.activeElement",
		"if (back && back.focus) back.focus();",
		// Following a tree link opts out of the restore, so it cannot fight the
		// navigation that is about to replace the page.
		"setNavOpen(false, false)",
		// The trap itself, both directions.
		"e.shiftKey && document.activeElement === first",
		"!e.shiftKey && document.activeElement === last",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing drawer-accessibility marker %q", want)
		}
	}
}

// TestUITailFixes covers the UI-tail items whose effect only a browser can show.
func TestUITailFixes(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []struct{ what, marker string }{
		// Query results were being written to sessionStorage — in an admin tool
		// those pages ARE the data, and they outlived the session that fetched them.
		{"htmx history cache disabled", "historyCacheSize = 0"},
		// A first visit ignored the OS setting entirely. Assert the predicate's own
		// body and its call site: the media-query string alone also appears in the
		// change listener below, so matching it proves nothing about the first paint.
		{"prefers-color-scheme is actually read", `!!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches)`},
		{"and consulted when no choice exists", "} else if (prefersDark()) {"},
		{"an explicit choice still wins", "if (chosenTheme()) return;"},
		{"the OS is followed while no choice exists", `mq.addEventListener("change", onSchemeChange)`},
		// The nav filter matched database names only and lost its effect on refresh.
		{"the filter is a function the swap can re-apply", "function applyNavFilter()"},
		{"the filter matches tables too", `".tx-node-table, .tx-node-view"`},
		{"a matching table keeps its database visible", "dbHit || kidHit"},
		{"the filter survives a tree refresh", "applyNavFilter();"},
		// Running SQL required the mouse.
		{"Ctrl-Enter runs the query", `"Ctrl-Enter": submitEditorForm`},
		{"Cmd-Enter does too", `"Cmd-Enter": submitEditorForm`},
		{"the plain textarea gets the shortcut", `if (e.key !== "Enter" || !(e.ctrlKey || e.metaKey)) return;`},
		// requestSubmit, so htmx still sees the submit event and swaps.
		{"submitting goes through requestSubmit", "form.requestSubmit()"},
		// The lazily-loaded editor files get the same immutable caching.
		{"lazy loads are fingerprinted", `path + "?v=" + m.content`},
	} {
		if !strings.Contains(js, want.marker) {
			t.Errorf("app.js: %s — missing %q", want.what, want.marker)
		}
	}

	css := loadCSS(t)
	rules := cssRules(css)
	has := func(sel, decl string) bool {
		for _, r := range rules {
			if strings.Contains(r.sel, sel) && strings.Contains(r.body, decl) {
				return true
			}
		}
		return false
	}
	for _, want := range []struct{ what, sel, decl string }{
		// text-overflow does nothing while the text is free to wrap.
		{"truncated cells can actually ellipsize", ".tx-cell", "white-space: nowrap"},
		// A wide table's column list was cut off with no way to reach the rest.
		{"designer cards scroll instead of clipping", ".tx-designer-table", "overflow: auto"},
		{"and are capped so one table cannot fill the screen", ".tx-designer-table", "max-height"},
	} {
		if !has(want.sel, want.decl) {
			t.Errorf("tablex.css: %s — no %s rule declares %q", want.what, want.sel, want.decl)
		}
	}

	// The breadcrumb overflowed from 768px down, but only the 576px tier let it
	// wrap. Check the wrap is declared in the wider block, not just the phone one.
	tablet, _, found := strings.Cut(css, "@media (max-width: 575.98px)")
	if !found {
		t.Fatal("tablex.css: the phone-tier media query has moved")
	}
	i := strings.Index(tablet, "@media (max-width: 767.98px)")
	if i < 0 || !strings.Contains(tablet[i:], ".tx-breadcrumb .breadcrumb { flex-wrap: wrap; }") {
		t.Error("tablex.css: the breadcrumb only wraps at the phone tier, but it " +
			"overflows as soon as the nav toggle takes the top bar's width")
	}
}

// classFromGo are the .tx-* classes emitted by Go rather than by markup —
// currently just the one the icon helper puts on every <svg>
// (internal/view/icons.go). Listed explicitly so a genuinely dead hook cannot
// hide behind "something must use it somewhere".
var classFromGo = []string{"tx-icon"}

// TestNoDeadStyleHooks keeps the stylesheet honest: a rule for a class nothing
// renders is a promise about an element that does not exist, and reading the CSS
// to find out what the UI does becomes unreliable. There were 12 such rules;
// the UI-polish pass removed them, and this is what stops them coming back.
func TestNoDeadStyleHooks(t *testing.T) {
	css := loadCSS(t)
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`\.(tx-[a-z0-9-]+)`).FindAllStringSubmatch(css, -1) {
		defined[m[1]] = true
	}
	if len(defined) < 100 {
		t.Fatalf("only %d tx-* classes found in the stylesheet; the pattern has stopped matching", len(defined))
	}

	used := map[string]bool{}
	for _, c := range classFromGo {
		used[c] = true
	}
	ref := regexp.MustCompile(`tx-[a-z0-9-]+`)
	for _, dir := range []string{"templates", "static/js"} {
		err := fs.WalkDir(FS, dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, rerr := FS.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for _, m := range ref.FindAllString(string(b), -1) {
				used[m] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	var dead []string
	for c := range defined {
		if !used[c] {
			dead = append(dead, c)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("tablex.css styles %d class(es) nothing renders: %s\n"+
			"Delete the rules, or add the class to the markup that was meant to carry it.",
			len(dead), strings.Join(dead, ", "))
	}
}

// TestUnsavedChangesGuard covers the unsaved-changes guard. Nothing protected typed-in work: an htmx
// swap replaces the form without unloading the page, so the browser never got to
// ask, and a written query or a filled row went silently.
func TestUnsavedChangesGuard(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		// Opt-in per form, and the flag lives on the form so the swap clears it.
		`var GUARDED = "[data-tx-guard]"`,
		`form.classList.add("tx-dirty")`,
		// Both paths: a real unload and an htmx swap.
		`window.addEventListener("beforeunload"`,
		"e.returnValue = \"\"",
		`document.addEventListener("htmx:confirm"`,
		// Saving the dirty form must not prompt about leaving it.
		"if (elt && (elt === form || form.contains(elt))) return;",
		// Only a swap of the main region loses the form.
		`if (!target || target.id !== "page_content") return;`,
		// No argument: passing true would skip an hx-confirm dialog, and
		// configRequest would still send tx_confirm.
		"e.detail.issueRequest();",
		// The console is the case that needs the CodeMirror hook.
		`if (!chg || chg.origin !== "setValue") markDirty(ta);`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing unsaved-changes marker %q", want)
		}
	}
	if strings.Contains(js, "issueRequest(true)") {
		t.Error("app.js calls issueRequest(true), which skips the hx-confirm dialog " +
			"while configRequest still adds tx_confirm — destructive actions would " +
			"run unconfirmed")
	}
}

// TestAnnouncementsAreLive guards the announcement region's JS half: the region is useless if nothing
// writes to it, and writing the same string twice is not a change — so a second
// identical message would be silent without the clear-then-set.
func TestAnnouncementsAreLive(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		`document.getElementById("tx-announce")`,
		`region.textContent = "";`,
		"region.textContent = msg;",
		"announce(msg);", // toasts
		"announce(flash.textContent.trim())",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing announcement marker %q", want)
		}
	}
}

// TestConfirmFieldFollowsTheDialogNotTheAttribute covers #9.
//
// tx_confirm=1 tells the server "the user has already been asked", so sending it
// when no dialog was shown converts a guarded destructive action into an
// unguarded one. The old test was el.closest("[hx-confirm]"), which is wrong
// twice: hx-confirm is INHERITED, so a descendant that never prompted matches a
// parent's attribute; and hx-confirm="unset" — the documented way to CANCEL an
// inherited attribute — is itself an [hx-confirm] attribute, so the two links in
// table_browse.html that use it were matching as well.
//
// The value is not available where the parameter is set: htmx's configRequest
// detail carries no confirmation data (verified in the vendored bundle, not just
// in the docs), while htmx:confirm carries `question`. Hence the one-shot
// handoff these markers pin.
func TestConfirmFieldFollowsTheDialogNotTheAttribute(t *testing.T) {
	b, err := FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		// The handoff itself: written where the question is visible, read and
		// cleared where the parameter is set.
		"var confirmed = new WeakMap();",
		"if (e.detail.question) {",
		"confirmed.set(elt, true);",
		"confirmed.delete(elt);",
		"if (el && confirmed.get(el)) {",
		`e.detail.parameters["tx_confirm"] = "1";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing confirmation-handoff marker %q", want)
		}
	}
	// The attribute test must be gone: it is the bug.
	if strings.Contains(js, `closest("[hx-confirm]")`) {
		t.Error("app.js still decides tx_confirm from the hx-confirm ATTRIBUTE, " +
			"which is inherited and which hx-confirm=\"unset\" also satisfies")
	}
	// The write must precede dirtyForm()'s early return, or a page with no dirty
	// form records nothing and every confirmed action becomes an interstitial.
	set := strings.Index(js, "confirmed.set(elt, true);")
	guard := strings.Index(js, "var form = dirtyForm();")
	if set < 0 || guard < 0 || set > guard {
		t.Error("the confirmation is recorded after dirtyForm()'s early return; " +
			"on a page with no dirty form nothing would be recorded at all")
	}
}

// TestUnsetConfirmLinksStayUnconfirmed is the live regression case: these two
// links are GETs that never prompt, and they carried tx_confirm=1 purely because
// hx-confirm="unset" is spelled with the attribute it cancels.
func TestUnsetConfirmLinksStayUnconfirmed(t *testing.T) {
	b, err := FS.ReadFile("templates/pages/table_browse.html")
	if err != nil {
		t.Fatalf("read embedded table_browse.html: %v", err)
	}
	tpl := string(b)
	if n := strings.Count(tpl, `hx-confirm="unset"`); n != 2 {
		t.Errorf(`table_browse.html has %d hx-confirm="unset" links, want 2 (Edit and Copy)`, n)
	}
	// The bulk-delete form is the counter-example, and the reason a naive
	// "descendant of a form with hx-confirm" fixture would prove nothing here:
	// it disinherits, so its row buttons never inherited the confirmation.
	if !strings.Contains(tpl, `hx-disinherit="hx-confirm"`) {
		t.Error("the bulk-delete form no longer disinherits hx-confirm; " +
			"its row controls would start inheriting a dialog they do not show")
	}
}
