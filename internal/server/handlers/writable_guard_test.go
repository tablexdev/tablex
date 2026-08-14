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

// TestRequireWritableTable pins the read-only-view write guard (H1): the mutating
// table routes (insert/edit/delete, table-scoped import) reject a VIEW and a
// MariaDB SEQUENCE with a clear 400, a missing table with 404, and let base
// tables through. Unlike requireDataTable it FAILS CLOSED on a missing target
// (404 instead of pass-through), because a write must not proceed unverified. The
// listing is seeded through the request memo, so no live backend is needed and
// the (nil) connection is never dialed.
func TestRequireWritableTable(t *testing.T) {
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

	cases := []struct {
		table    string
		wantPass bool
		wantCode int
		wantWord string
	}{
		{"t1", true, 0, ""},
		{"v1", false, http.StatusBadRequest, "view"},
		{"seq1", false, http.StatusBadRequest, "sequence"},
		{"missing", false, http.StatusNotFound, "not found"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/db/db/table/"+c.table+"/insert", nil).WithContext(ctx)
		got := h.requireWritableTable(w, r, nil, reqScope{DB: "db", Table: c.table})
		if got != c.wantPass {
			t.Errorf("requireWritableTable(%q) = %v, want %v", c.table, got, c.wantPass)
		}
		if c.wantPass {
			continue
		}
		if w.Code != c.wantCode {
			t.Errorf("%q rejection status = %d, want %d", c.table, w.Code, c.wantCode)
		}
		if body := w.Body.String(); !strings.Contains(strings.ToLower(body), c.wantWord) {
			t.Errorf("%q rejection page should mention %q:\n%.400s", c.table, c.wantWord, body)
		}
	}

	// An empty table scope (db-level callers) is a no-op pass — the guard only
	// applies to a concrete table.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/db/db", nil).WithContext(ctx)
	if !h.requireWritableTable(w, r, nil, reqScope{DB: "db"}) {
		t.Error("empty table scope must pass")
	}
}
