package handlers

import (
	"net/url"
	"strconv"
	"strings"
)

// URL builders keep link construction consistent across handlers and the view
// models they populate. Path segments are escaped; the schema (PostgreSQL) rides
// as a query parameter so the same routes serve every engine.

func urlLogin() string { return "/login" }

// The SSO gate's paths. Exported because three places name them — the route
// table, the middleware that must let them through, and the handlers that
// redirect to them — and three literals would drift apart. Both are GET: the
// provider completes the flow by redirecting the browser, and a redirect cannot
// be a POST.
const (
	SSOStartPath    = "/auth/sso/start"
	SSOCallbackPath = "/auth/sso/callback"
)

func urlSSOStart() string { return SSOStartPath }
func urlHome() string     { return "/" }

func urlServer(tab string) string {
	if tab == "" || tab == "databases" {
		return "/server"
	}
	return "/server/" + tab
}

func seg(s string) string { return url.PathEscape(s) }

func schemaQuery(schema string) string {
	if schema == "" {
		return ""
	}
	return "?schema=" + url.QueryEscape(schema)
}

func urlDB(db, schema, tab string) string {
	var b strings.Builder
	b.WriteString("/db/")
	b.WriteString(seg(db))
	if tab != "" && tab != "structure" {
		b.WriteByte('/')
		b.WriteString(tab)
	}
	b.WriteString(schemaQuery(schema))
	return b.String()
}

func urlTable(db, schema, table, tab string) string {
	var b strings.Builder
	b.WriteString("/db/")
	b.WriteString(seg(db))
	b.WriteString("/table/")
	b.WriteString(seg(table))
	if tab != "" && tab != "browse" {
		b.WriteByte('/')
		b.WriteString(tab)
	}
	b.WriteString(schemaQuery(schema))
	return b.String()
}

// urlDefinition is the htmx endpoint backing one object's lazy definition
// panel. i is the object's position in the list the page rendered, and table
// is set only by the per-table triggers page, whose list is filtered (both are
// re-derived server-side — see ObjectDefinition).
func urlDefinition(db, schema, table, kind, name string, i int) string {
	v := url.Values{}
	v.Set("kind", kind)
	v.Set("name", name)
	v.Set("i", strconv.Itoa(i))
	if schema != "" {
		v.Set("schema", schema)
	}
	if table != "" {
		v.Set("table", table)
	}
	return "/db/" + seg(db) + "/definition?" + v.Encode()
}

// urlRoutinePrivileges addresses one routine's privileges page. It carries the
// same (name, position) pair every other per-routine link does — see the
// addressing rule in programs.go — because a name alone cannot pick one of
// PostgreSQL's overloads.
func urlRoutinePrivileges(sc reqScope, name string, i int) string {
	v := url.Values{}
	if sc.Schema != "" {
		v.Set("schema", sc.Schema)
	}
	v.Set("name", name)
	v.Set("i", strconv.Itoa(i))
	return "/db/" + seg(sc.DB) + "/routines/privileges?" + v.Encode()
}

// urlProgramEditor builds a link to the stored-program definition editor. An
// empty name opens the "new object" skeleton; routineType ("procedure") picks
// which skeleton on the routines page. The per-table triggers page keeps its own
// path so the editor returns there, and so its skeleton names that table.
func urlProgramEditor(sc reqScope, kind, name string, i int, routineType string) string {
	base := "/db/" + seg(sc.DB) + "/" + kind + "s/edit"
	if sc.Table != "" {
		base = "/db/" + seg(sc.DB) + "/table/" + seg(sc.Table) + "/triggers/edit"
	}
	v := url.Values{}
	if sc.Schema != "" {
		v.Set("schema", sc.Schema)
	}
	if name != "" {
		v.Set("name", name)
		v.Set("i", strconv.Itoa(i))
	}
	if routineType != "" {
		v.Set("type", routineType)
	}
	if q := v.Encode(); q != "" {
		return base + "?" + q
	}
	return base
}

// urlNavChildren is the htmx endpoint that lazily loads a node's children.
func urlNavChildren(db, schema string) string {
	v := url.Values{}
	if db != "" {
		v.Set("db", db)
	}
	if schema != "" {
		v.Set("schema", schema)
	}
	q := v.Encode()
	if q == "" {
		return "/nav/children"
	}
	return "/nav/children?" + q
}
