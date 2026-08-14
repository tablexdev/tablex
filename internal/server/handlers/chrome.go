package handlers

import (
	"context"
	"slices"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/view"
)

// Breadcrumb and context-tab construction. Tab sets are filtered by the engine's
// Capabilities so unsupported features (Users/Routines/Events on SQLite, Events
// on PostgreSQL, …) never appear as dead links — hidden, not disabled — and
// then by the [restrict] policy so this deployment's
// own refusals are not offered either (see finishTabs).

func (h *Handlers) buildBreadcrumb(uc *UserContext, sc reqScope) []view.Crumb {
	crumbs := []view.Crumb{{
		Label: serverLabel(uc),
		URL:   urlServer(""),
		Icon:  "server",
	}}
	if sc.DB != "" {
		crumbs = append(crumbs, view.Crumb{
			Label: sc.DB,
			URL:   urlDB(sc.DB, "", ""),
			Icon:  "database",
		})
	}
	if sc.Schema != "" && uc.Capabilities().HasSchemas {
		crumbs = append(crumbs, view.Crumb{
			Label: sc.Schema,
			URL:   urlDB(sc.DB, sc.Schema, ""),
			Icon:  "schema",
		})
	}
	if sc.Table != "" {
		crumbs = append(crumbs, view.Crumb{
			Label: sc.Table,
			URL:   urlTable(sc.DB, sc.Schema, sc.Table, ""),
			Icon:  "table",
		})
	}
	if len(crumbs) > 0 {
		crumbs[len(crumbs)-1].Active = true
	}
	return crumbs
}

func serverLabel(uc *UserContext) string {
	if uc.ServerName != "" {
		return uc.ServerName
	}
	info := uc.ServerConn().Info()
	if info.Host != "" {
		return info.Host
	}
	return info.Flavor
}

// serverTabs returns the base server tabs. The active tab is marked by the sole
// caller (serverTabsCaps) after it appends the capability-gated tabs, so this
// builder does not take an active key itself.
func (h *Handlers) serverTabs() []view.Tab {
	return []view.Tab{
		{Key: "databases", Label: "Databases", Icon: "database", URL: urlServer("databases")},
		{Key: "sql", Label: "SQL", Icon: "sql", URL: urlServer("sql")},
		{Key: "status", Label: "Status", Icon: "info", URL: urlServer("status")},
		{Key: "variables", Label: "Variables", Icon: "settings", URL: urlServer("variables")},
		{Key: "processes", Label: "Processes", Icon: "operations", URL: urlServer("processes")},
	}
}

func (h *Handlers) serverTabsCaps(uc *UserContext, active string) []view.Tab {
	tabs := h.serverTabs()
	if uc.Capabilities().HasUsers {
		tabs = append(tabs, view.Tab{Key: "users", Label: "Users", Icon: "users", URL: urlServer("users")})
	}
	tabs = append(tabs,
		view.Tab{Key: "export", Label: "Export", Icon: "export", URL: urlServer("export")},
		view.Tab{Key: "import", Label: "Import", Icon: "import", URL: urlServer("import")},
	)
	return h.finishTabs(tabs, active)
}

// levelChrome resolves the level → (postURL, title, tabs) dispatch shared by
// the pages that exist at every scope (export, import, SQL console) — three
// hand-rolled copies of this switch used to drift apart. tab is both the
// active-tab key and the URL suffix ("export", "import", "sql"); titleWord is
// the human title segment ("Export", "Import", "SQL"). conn is the caller's
// already-resolved connection, forwarded to tableTabs for the read-only-view
// check (nil at db/server scope, where tableTabs is not reached, and degrades
// open where the caller holds none — see tableTabs).
func (h *Handlers) levelChrome(ctx context.Context, uc *UserContext, sc reqScope, level, tab, titleWord string, conn *driver.Connection) (postURL, title string, tabs []view.Tab) {
	switch level {
	case "server":
		return urlServer(tab), "Server · " + titleWord, h.serverTabsCaps(uc, tab)
	case "table":
		return urlTable(sc.DB, sc.Schema, sc.Table, tab), sc.Table + " · " + titleWord, h.tableTabs(ctx, uc, sc, tab, conn)
	default:
		return urlDB(sc.DB, sc.Schema, tab), sc.DB + " · " + titleWord, h.dbTabs(uc, sc, tab)
	}
}

func (h *Handlers) dbTabs(uc *UserContext, sc reqScope, active string) []view.Tab {
	caps := uc.Capabilities()
	tabs := []view.Tab{
		{Key: "structure", Label: "Structure", Icon: "structure", URL: urlDB(sc.DB, sc.Schema, "structure")},
		{Key: "sql", Label: "SQL", Icon: "sql", URL: urlDB(sc.DB, sc.Schema, "sql")},
		{Key: "search", Label: "Search", Icon: "search", URL: urlDB(sc.DB, sc.Schema, "search")},
		{Key: "qbe", Label: "Query", Icon: "search", URL: urlDB(sc.DB, sc.Schema, "qbe")},
		{Key: "export", Label: "Export", Icon: "export", URL: urlDB(sc.DB, sc.Schema, "export")},
		{Key: "import", Label: "Import", Icon: "import", URL: urlDB(sc.DB, sc.Schema, "import")},
		{Key: "operations", Label: "Operations", Icon: "operations", URL: urlDB(sc.DB, sc.Schema, "operations")},
		{Key: "designer", Label: "Designer", Icon: "structure", URL: urlDB(sc.DB, sc.Schema, "designer")},
	}
	if caps.HasUsers {
		tabs = append(tabs, view.Tab{Key: "privileges", Label: "Privileges", Icon: "privileges", URL: urlDB(sc.DB, sc.Schema, "privileges")})
	}
	if caps.HasStoredRoutines {
		tabs = append(tabs, view.Tab{Key: "routines", Label: "Routines", Icon: "routines", URL: urlDB(sc.DB, sc.Schema, "routines")})
	}
	if caps.HasEvents {
		tabs = append(tabs, view.Tab{Key: "events", Label: "Events", Icon: "events", URL: urlDB(sc.DB, sc.Schema, "events")})
	}
	if caps.HasTriggers {
		tabs = append(tabs, view.Tab{Key: "triggers", Label: "Triggers", Icon: "triggers", URL: urlDB(sc.DB, sc.Schema, "triggers")})
	}
	return h.finishTabs(tabs, active)
}

// tableTabs builds the per-table context tabs. For a VIEW the Insert and Import
// tabs are suppressed — TableX does not write rows through a view (the read-only
// -view policy; the SQL console is the documented escape hatch, and the mutating
// routes are rejected server-side by requireWritableTable regardless of the
// tabs). The view check uses the request-memoized listing via the caller's
// ALREADY-RESOLVED conn: it never dials, because ConnFor caches pools only on
// success, so a tableTabs-internal ConnFor after a caller's failed one would
// repeat a 15-second dial on a broken backend. A nil conn (caller resolved none,
// or the dial failed) skips the lookup and degrades OPEN — the tab set is
// cosmetic; requireWritableTable is the enforcement.
func (h *Handlers) tableTabs(ctx context.Context, uc *UserContext, sc reqScope, active string, conn *driver.Connection) []view.Tab {
	caps := uc.Capabilities()
	isView := false
	if conn != nil && sc.Table != "" {
		if tbl, found, err := h.lookupTable(ctx, conn, sc); err == nil && found {
			isView = tbl.IsView()
		}
	}
	tabs := []view.Tab{
		{Key: "browse", Label: "Browse", Icon: "browse", URL: urlTable(sc.DB, sc.Schema, sc.Table, "browse")},
		{Key: "structure", Label: "Structure", Icon: "structure", URL: urlTable(sc.DB, sc.Schema, sc.Table, "structure")},
		{Key: "sql", Label: "SQL", Icon: "sql", URL: urlTable(sc.DB, sc.Schema, sc.Table, "sql")},
		{Key: "search", Label: "Search", Icon: "search", URL: urlTable(sc.DB, sc.Schema, sc.Table, "search")},
	}
	if !isView {
		tabs = append(tabs, view.Tab{Key: "insert", Label: "Insert", Icon: "insert", URL: urlTable(sc.DB, sc.Schema, sc.Table, "insert")})
	}
	tabs = append(tabs, view.Tab{Key: "export", Label: "Export", Icon: "export", URL: urlTable(sc.DB, sc.Schema, sc.Table, "export")})
	if !isView {
		tabs = append(tabs, view.Tab{Key: "import", Label: "Import", Icon: "import", URL: urlTable(sc.DB, sc.Schema, sc.Table, "import")})
	}
	tabs = append(tabs, view.Tab{Key: "operations", Label: "Operations", Icon: "operations", URL: urlTable(sc.DB, sc.Schema, sc.Table, "operations")})
	if caps.HasTriggers {
		tabs = append(tabs, view.Tab{Key: "triggers", Label: "Triggers", Icon: "triggers", URL: urlTable(sc.DB, sc.Schema, sc.Table, "triggers")})
	}
	if caps.HasUsers {
		tabs = append(tabs, view.Tab{Key: "privileges", Label: "Privileges", Icon: "privileges", URL: urlTable(sc.DB, sc.Schema, sc.Table, "privileges")})
	}
	return h.finishTabs(tabs, active)
}

// finishTabs is the single exit every tab set passes through: it drops the tabs
// this deployment would refuse, then marks the active one.
//
// The filtering lives HERE, not in the three builders, for the same reason the
// audit action log is one middleware: a tab added tomorrow is covered the day it
// is added, instead of depending on somebody remembering to gate it.
func (h *Handlers) finishTabs(tabs []view.Tab, active string) []view.Tab {
	allow := h.allowance()
	if allow.Restricted() {
		tabs = slices.DeleteFunc(tabs, func(t view.Tab) bool { return !tabPermitted(t.Key, allow) })
	}
	for i := range tabs {
		if tabs[i].Key == active {
			tabs[i].Active = true
		}
	}
	return tabs
}

// tabPermitted reports whether a tab is worth offering under the policy. A key
// absent from the switch is a read and is always offered.
//
// This has to agree with the per-route policy table in internal/server/router.go,
// which is the ENFORCEMENT — a tab offered for a route that refuses it is a
// button that 403s, and a tab withheld for a route that would have allowed it is
// a feature lost to a UI bug. Three things make the pairing readable rather than
// a coincidence:
//
//   - The keys here are the tab names, which are also the final segment of the
//     route each tab links to, so the two tables read in the same vocabulary.
//   - Tabs whose PAGE is a read stay, even when every action on the page is
//     withheld: `structure` still lists the columns, and `processes` still shows
//     who is connected. Those pages gate their own buttons on $.Allow — dropping
//     the tab instead would take away the reading with the writing.
//   - The stored-program tabs are DDL here because their LIST and DROP are DDL.
//     Their editor additionally needs Console, which is not a tab-level decision:
//     it is gated on the pages themselves (programAdmin.CanEdit) and enforced in
//     saveProgram, because save and drop share one endpoint.
func tabPermitted(key string, allow view.Allowance) bool {
	switch key {
	case "sql", "import":
		// The console and SQL import are refused at the ROUTE, whatever the
		// method — offering a console that will not run anything is worse than not
		// offering one — so the tab has to go with them.
		return allow.Console
	case "insert":
		return allow.Write
	case "operations", "privileges", "users", "routines", "events", "triggers":
		return allow.DDL
	}
	return true
}
