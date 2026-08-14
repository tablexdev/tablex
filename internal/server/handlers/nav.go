package handlers

import (
	"context"
	"net/http"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/view"
)

// Navigation tree construction. The sidebar lists databases up front; the active
// database is pre-expanded so its tables (or schemas, for PostgreSQL) show
// immediately. Other nodes load their children lazily via htmx fragments
// (the NavChildren handler; buildNav below is the full-page entry point).

// buildNav assembles the sidebar tree for a full-page render.
func (h *Handlers) buildNav(r *http.Request, uc *UserContext) *view.NavView {
	ctx := r.Context()
	sc := h.resolveScope(r)
	nav := &view.NavView{}
	dbs, err := h.databaseNames(ctx, uc)
	if err != nil {
		h.Log.Warn("nav: list databases", "err", err, "reqid", RequestID(ctx))
		// Surface the failure as an explicit tree leaf instead of an empty sidebar
		// that looks like "no databases".
		nav.Databases = navErrorNode("could not list databases")
		return nav
	}
	for _, db := range dbs {
		node := view.NavNode{
			Kind:       "database",
			Name:       db.Name,
			Label:      db.Name,
			Icon:       "database",
			Href:       urlDB(db.Name, "", "structure"),
			LoadURL:    urlNavChildren(db.Name, ""),
			Expandable: true,
			Active:     db.Name == sc.DB,
			IsSystem:   db.IsSystem,
		}
		if db.Name == sc.DB {
			node.Expanded = true
			node.Children = h.navChildren(ctx, uc, db.Name, sc.Schema, sc.Table)
		}
		nav.Databases = append(nav.Databases, node)
	}
	return nav
}

// navChildren returns the children of a database node: schemas for engines with
// a schema level, otherwise tables/views. For an active schema, its tables are
// expanded inline.
func (h *Handlers) navChildren(ctx context.Context, uc *UserContext, db, activeSchema, activeTable string) []view.NavNode {
	if uc.Capabilities().HasSchemas {
		return h.navSchemas(ctx, uc, db, activeSchema, activeTable)
	}
	return h.navTables(ctx, uc, db, "", activeTable)
}

// navErrorNode is a non-navigable leaf surfaced in the tree when a node's
// children can't be loaded (open failure, permission/connectivity error), so a
// failure shows as an explicit message instead of an empty/missing subtree.
func navErrorNode(label string) []view.NavNode {
	return []view.NavNode{{Kind: "error", Label: label, Icon: "warning", IsError: true}}
}

func (h *Handlers) navSchemas(ctx context.Context, uc *UserContext, db, activeSchema, activeTable string) []view.NavNode {
	conn, err := uc.ConnFor(ctx, db)
	if err != nil {
		h.Log.Warn("nav: open connection for schemas", "db", db, "err", uc.redactErr(err), "reqid", RequestID(ctx))
		return navErrorNode("could not open database")
	}
	schemas, err := conn.ListSchemas(ctx, db)
	if err != nil {
		h.Log.Warn("nav: list schemas", "db", db, "err", err, "reqid", RequestID(ctx))
		return navErrorNode("could not list schemas")
	}
	var out []view.NavNode
	for _, s := range schemas {
		node := view.NavNode{
			Kind:       "schema",
			Name:       s.Name,
			Label:      s.Name,
			Icon:       "schema",
			Href:       urlDB(db, s.Name, "structure"),
			LoadURL:    urlNavChildren(db, s.Name),
			Expandable: true,
			Active:     s.Name == activeSchema,
			IsSystem:   s.IsSystem,
		}
		if s.Name == activeSchema {
			node.Expanded = true
			node.Children = h.navTables(ctx, uc, db, s.Name, activeTable)
		}
		out = append(out, node)
	}
	return out
}

func (h *Handlers) navTables(ctx context.Context, uc *UserContext, db, schema, activeTable string) []view.NavNode {
	conn, err := uc.ConnFor(ctx, db)
	if err != nil {
		h.Log.Warn("nav: open connection for tables", "db", db, "schema", schema, "err", uc.redactErr(err), "reqid", RequestID(ctx))
		return navErrorNode("could not open database")
	}
	tables, err := h.tableNames(ctx, conn, driver.Scope{Database: db, Schema: schema})
	if err != nil {
		h.Log.Warn("nav: list tables", "db", db, "schema", schema, "err", err, "reqid", RequestID(ctx))
		return navErrorNode("could not list tables")
	}
	var out []view.NavNode
	for _, t := range tables {
		if t.IsSequence() {
			continue // MariaDB sequences are not browsable data tables
		}
		icon := "table"
		kind := "table"
		if t.IsView() {
			icon, kind = "view", "view"
		}
		out = append(out, view.NavNode{
			Kind:   kind,
			Name:   t.Name,
			Label:  t.Name,
			Icon:   icon,
			Href:   urlTable(db, schema, t.Name, "browse"),
			Active: t.Name == activeTable,
		})
	}
	return out
}

// NavTree is the htmx endpoint that re-renders the whole top-level database tree
// (GET /nav), used to refresh the sidebar after a structural change (create /
// drop a database, create / drop / rename a table) that only swapped
// #page_content.
func (h *Handlers) NavTree(w http.ResponseWriter, r *http.Request) {
	uc, _, ok := h.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nav := h.buildNav(r, uc)
	if err := h.View.RenderNamed(w, "home", "nav_tree", nav); err != nil {
		h.renderFailed(w, r, err, "nav tree")
	}
}

// NavChildren is the htmx endpoint that lazily loads a node's children
// (GET /nav/children?db=&schema=).
func (h *Handlers) NavChildren(w http.ResponseWriter, r *http.Request) {
	uc, _, ok := h.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	db := r.URL.Query().Get("db")
	schema := r.URL.Query().Get("schema")
	if db == "" {
		http.Error(w, "missing db", http.StatusBadRequest)
		return
	}
	// The allowlist, checked here rather than in the middleware. The middleware
	// reads the database out of the PATH (/db/{db}/...), and this route carries
	// it in a QUERY parameter — so its check is skipped for exactly the same
	// reason it is skipped for /server. Without this, GET /nav/children?db=X on
	// an excluded X answered 200 with X's schemas and tables, and opened a pool
	// to it, while GET /db/X answered 403.
	if !h.Cfg.Restrict.DatabaseAllowed(db) {
		h.RenderRestricted(w, r, "This TableX is limited to a fixed set of databases, and "+db+" is not one of them.")
		return
	}
	var nodes []view.NavNode
	if schema == "" && uc.Capabilities().HasSchemas {
		nodes = h.navSchemas(r.Context(), uc, db, "", "")
	} else {
		nodes = h.navTables(r.Context(), uc, db, schema, "")
	}
	if err := h.View.RenderNamed(w, "home", "nav_children", nodes); err != nil {
		h.renderFailed(w, r, err, "nav children")
	}
}
