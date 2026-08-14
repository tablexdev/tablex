package handlers

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// TestRequireDataTable pins the sequence route policy (#4): a MariaDB SEQUENCE
// object resolved through a data-table route is rejected with a clear error,
// while base tables, views and unknown names pass through (the handler then
// surfaces its own not-found handling). The listing is seeded through the
// request memo, so no live MariaDB is needed and the connection is never
// dialed.
func TestRequireDataTable(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}

	ctx := WithListingMemo(context.Background())
	memoFrom(ctx).tables = map[string][]model.Table{"db\x00": {
		{Name: "seq1", Type: model.TableSequence},
		{Name: "t1", Type: model.TableBase},
		{Name: "v1", Type: model.TableView},
	}}

	check := func(table string, wantPass bool) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/db/db/table/"+table, nil).WithContext(ctx)
		got := h.requireDataTable(w, r, nil, reqScope{DB: "db", Table: table})
		if got != wantPass {
			t.Errorf("requireDataTable(%q) = %v, want %v", table, got, wantPass)
		}
		if !wantPass {
			if w.Code != http.StatusBadRequest {
				t.Errorf("sequence rejection status = %d, want 400", w.Code)
			}
			if body := w.Body.String(); !strings.Contains(body, "sequence") {
				t.Errorf("rejection page should say the object is a sequence:\n%.500s", body)
			}
		}
	}
	check("seq1", false)
	check("t1", true)
	check("v1", true)
	check("missing", true) // handler surfaces its own 404
	// An empty table scope (db-level callers) is a no-op pass.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/db/db", nil).WithContext(ctx)
	if !h.requireDataTable(w, r, nil, reqScope{DB: "db"}) {
		t.Error("empty table scope must pass")
	}
}
