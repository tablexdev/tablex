package handlers

import (
	"context"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestTableNamesMemo confirms one request re-uses its first table listing: the
// second call inside the same memo context returns the cached list even after
// the catalog changed, while a fresh context sees the new state.
func TestTableNamesMemo(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER)")
	h := &Handlers{}
	scope := driver.Scope{}

	ctx := WithListingMemo(context.Background())
	first, err := h.tableNames(ctx, conn, scope)
	if err != nil || len(first) != 1 || first[0].Name != "t1" {
		t.Fatalf("first listing = %+v, %v", first, err)
	}

	mustExec(t, conn, "CREATE TABLE t2 (id INTEGER)")
	cached, err := h.tableNames(ctx, conn, scope)
	if err != nil || len(cached) != 1 {
		t.Errorf("memoized listing = %+v, %v; want the cached single table", cached, err)
	}

	fresh, err := h.tableNames(WithListingMemo(context.Background()), conn, scope)
	if err != nil || len(fresh) != 2 {
		t.Errorf("fresh listing = %+v, %v; want both tables", fresh, err)
	}

	// Without the middleware-installed memo (direct handler tests), the helper
	// still works — it just skips caching.
	bare, err := h.tableNames(context.Background(), conn, scope)
	if err != nil || len(bare) != 2 {
		t.Errorf("memo-less listing = %+v, %v", bare, err)
	}
}
