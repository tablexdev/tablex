package view

import (
	"html/template"

	"github.com/tablexdev/tablex/internal/driver"
)

// Page is the data passed to every template. It carries the shared "chrome"
// (breadcrumb, context tabs, navigation tree, flashes, server identity) plus a
// page-specific Body. Handlers build a Page, set Body, and call Render.
type Page struct {
	Title    string
	BodyID   string // stable per-page <body id>, for page-scoped CSS/JS hooks
	LoggedIn bool
	CSRF     string
	Theme    string // "light" | "dark"

	// NavWidthStyle is a pre-validated `--tx-nav-width:<n>px` custom-property
	// declaration rendered inline on <html> so the persisted sidebar width is in
	// effect on the first paint (no flash of the default width before JS runs).
	// It is template.CSS (trusted) only after server-side validation; empty
	// otherwise.
	NavWidthStyle template.CSS

	// Current connection identity (when logged in).
	ServerName string
	Info       driver.ServerInfo
	Caps       driver.Capabilities

	// Allow mirrors the [restrict] policy so a template does not OFFER what the
	// middleware would refuse. It reads alongside Caps and for the same reason:
	// Caps says what the engine can do, Allow says what this deployment permits.
	//
	// It is not the enforcement and must never be treated as such — every
	// restriction is applied to the request in internal/server/restrict.go, and
	// stays applied whether or not a template consulted this. What it buys is
	// only that a user is not shown a button that answers 403.
	Allow Allowance

	// Chrome.
	Breadcrumb []Crumb
	Tabs       []Tab
	Nav        *NavView
	Flashes    []Flash

	// NeedsEditor makes the layout load CodeMirror up front. It is 242 KB —
	// well over a third of the whole asset payload — and only the SQL console,
	// the import form and the stored-program editor carry a
	// `textarea.tx-sql-editor`, so every other page paid for it. An htmx
	// navigation ONTO one of those pages swaps only
	// #page_content and never re-runs <head>, so app.js injects the assets on
	// demand there; this flag covers the full-page render (and a no-JS client,
	// which then gets a plain textarea either way).
	NeedsEditor bool

	// Page-specific payload.
	Body any
}

// Flash is a one-shot alert (success/error/info/warning) shown above content.
type Flash struct {
	Kind    string // success | error | info | warning
	Message string
	Detail  string // optional secondary text (e.g. the offending SQL)
}

// Crumb is one item in the Server » Database » Table breadcrumb.
type Crumb struct {
	Label  string
	URL    string
	Icon   string
	Active bool
}

// Tab is one context tab in the #topmenu bar.
type Tab struct {
	Key    string
	Label  string
	URL    string
	Icon   string
	Active bool
}

// NavView backs the left navigation tree. The tree is loaded incrementally:
// databases render up-front; expanding a node fetches its children via htmx.
type NavView struct {
	Databases []NavNode
}

// NavNode is one node (database, schema, table or view) in the tree.
type NavNode struct {
	Kind       string // database | schema | table | view
	Name       string
	Label      string
	Icon       string
	Href       string // navigation target (browse/structure)
	LoadURL    string // htmx URL to load children lazily
	Expandable bool
	Expanded   bool
	Active     bool
	IsSystem   bool
	IsError    bool // a non-navigable leaf shown when children couldn't be loaded
	Children   []NavNode
}

// NewPage returns a Page seeded with sensible defaults.
func NewPage(title string) *Page {
	// Allow starts PERMISSIVE, matching the unrestricted default. A zero
	// Allowance would forbid everything, which sounds like the safe direction and
	// is the wrong one here: this struct does not enforce anything, so a
	// zero-value default would only hide every button on pages whose requests are
	// perfectly permitted — including on the login page and the error page, which
	// carry no policy at all.
	return &Page{Title: title, BodyID: "page", Theme: "light", Allow: AllowAll}
}
