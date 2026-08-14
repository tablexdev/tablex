package handlers

import (
	"context"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// TestSearchTableColsFallsBackWhenBulkMissesATable: a table present in the
// listing but absent from the bulk-columns map (dropped/renamed between the
// two catalog reads, or a zero-column relation) used to yield nil columns
// with a nil error, so the whole-database search silently dropped it — no
// hit, no Skipped, no Partial. The resolver must fall back to the per-table
// read for exactly that case, while still honoring the bulk map when it does
// cover the table.
func TestSearchTableColsFallsBackWhenBulkMissesATable(t *testing.T) {
	ctx := context.Background()
	conn := openTestConn(t)
	if _, err := conn.DB().ExecContext(ctx, "CREATE TABLE bulkmiss (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ref := driver.TableRef{Database: "main", Table: "bulkmiss"}

	// The bulk map covers the table: its (sentinel) entry is used verbatim.
	sentinel := []model.Column{{Name: "sentinel"}}
	cols, err := searchTableCols(ctx, conn, map[string][]model.Column{"bulkmiss": sentinel}, true, ref)
	if err != nil || len(cols) != 1 || cols[0].Name != "sentinel" {
		t.Fatalf("bulk-covered table = %v, %v; want the map's entry used verbatim", cols, err)
	}

	// The bulk map MISSES the table: the per-table read must answer, not a
	// silent nil.
	cols, err = searchTableCols(ctx, conn, map[string][]model.Column{}, true, ref)
	if err != nil {
		t.Fatalf("fallback read: %v", err)
	}
	if len(cols) != 2 {
		t.Fatalf("bulk-missed table columns = %v, want the real 2 via the per-table fallback", cols)
	}

	// No bulk at all: the per-table read, unchanged.
	cols, err = searchTableCols(ctx, conn, nil, false, ref)
	if err != nil || len(cols) != 2 {
		t.Fatalf("per-table path = %v, %v; want the real 2 columns", cols, err)
	}
}
