package handlers

import (
	"context"
	"slices"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// Per-request memoization of the identity-only database/table listings. A full
// page render needs the same lists several times — the sidebar tree, existence
// checks, and the page body each used to issue their own introspection query.
// The memo lives in the request context (installed by the server's request
// middleware), so one request runs each listing query at most once.
//
// Handlers process a request on a single goroutine, and every mutating action
// that changes these lists (CREATE/DROP/RENAME) redirects before re-rendering,
// so a memo never outlives or races the catalog state it caches.

type listingMemoKey struct{}

type listingMemo struct {
	dbNames    []model.Database
	hasDBNames bool
	tables     map[string][]model.Table // keyed by database \x00 schema
}

// WithListingMemo installs a fresh per-request listing memo (called by the
// server's request middleware alongside the request id).
func WithListingMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, listingMemoKey{}, &listingMemo{})
}

// memoFrom returns the request's memo, or nil outside the middleware (direct
// handler tests), in which case the helpers below simply skip caching.
func memoFrom(ctx context.Context) *listingMemo {
	m, _ := ctx.Value(listingMemoKey{}).(*listingMemo)
	return m
}

// allowedDatabases drops the databases restrict.database_allowlist excludes.
//
// Every path that shows the user a list of databases goes through this, so the
// allowlist is one predicate rather than a check each lister remembers: the
// sidebar tree, the home page, the Databases page, and the server-scope
// export's object list.
//
// That last one is the reason this is not purely cosmetic. The allowlist refuses
// ROUTES, and /server/export names no database in its path — so without this a
// user could dump, in one click, every database the sidebar had just declined to
// show them. A UI that hides what the next request hands over is worse than one
// that hides nothing.
//
// An empty allowlist returns the input untouched, allocating nothing.
func (h *Handlers) allowedDatabases(dbs []model.Database) []model.Database {
	rc := h.Cfg.Restrict
	if len(rc.Databases) == 0 {
		return dbs
	}
	return slices.DeleteFunc(slices.Clone(dbs), func(d model.Database) bool {
		return !rc.DatabaseAllowed(d.Name)
	})
}

// databaseNames returns the identity-only database listing (Name/IsSystem; no
// sizes or table counts), memoized for the request and narrowed to the
// allowlist.
func (h *Handlers) databaseNames(ctx context.Context, uc *UserContext) ([]model.Database, error) {
	m := memoFrom(ctx)
	if m != nil && m.hasDBNames {
		return m.dbNames, nil
	}
	dbs, err := uc.ServerConn().ListDatabaseNames(ctx)
	if err != nil {
		return nil, err
	}
	// Narrowed BEFORE the memo, so every later reader of the cached list sees the
	// same set and nothing can accidentally read the unfiltered one.
	dbs = h.allowedDatabases(dbs)
	if m != nil {
		m.dbNames, m.hasDBNames = dbs, true
	}
	return dbs, nil
}

// tableNames returns the identity-only table listing (Name/Schema/Type; no
// statistics) for a scope, memoized for the request.
func (h *Handlers) tableNames(ctx context.Context, conn *driver.Connection, scope driver.Scope) ([]model.Table, error) {
	key := scope.Database + "\x00" + scope.Schema
	m := memoFrom(ctx)
	if m != nil {
		if ts, ok := m.tables[key]; ok {
			return ts, nil
		}
	}
	ts, err := conn.ListTableNames(ctx, scope)
	if err != nil {
		return nil, err
	}
	if m != nil {
		if m.tables == nil {
			m.tables = map[string][]model.Table{}
		}
		m.tables[key] = ts
	}
	return ts, nil
}
