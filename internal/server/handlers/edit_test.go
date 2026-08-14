package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// TestRowKeyForFailSafe covers Theme J: a missing key column (or a binary key
// cell) yields no token, so the row renders without unsafe Edit/Delete actions
// instead of a partial key that could target the wrong row(s).
func TestRowKeyForFailSafe(t *testing.T) {
	full := map[string]driver.Value{"a": {Str: "1"}, "b": {Str: "2"}}
	if got := rowKeyFor([]string{"a", "b"}, full); got == "" {
		t.Error("a complete key should yield a token")
	}
	// One key column missing from the row → no token (would be a partial key).
	if got := rowKeyFor([]string{"a", "b"}, map[string]driver.Value{"a": {Str: "1"}}); got != "" {
		t.Errorf("missing key column should yield no token, got %q", got)
	}
	// A binary key cell carries only a placeholder, not the real bytes → no token.
	bin := map[string]driver.Value{"a": {Str: "[BLOB 3]", Binary: true}, "b": {Str: "2"}}
	if got := rowKeyFor([]string{"a", "b"}, bin); got != "" {
		t.Errorf("binary key cell should yield no token, got %q", got)
	}
}

// TestReadRowValuesDirtyTracking pins the edit form's update-only-what-changed
// contract: fields whose submitted state equals their orig_ marker are skipped,
// so lossy display round-trips (timestamptz offsets, CRLF textareas) never
// rewrite untouched values.
func TestReadRowValuesDirtyTracking(t *testing.T) {
	cols := []model.Column{
		{Name: "id", BaseType: "integer"},
		{Name: "name", BaseType: "varchar"},
		{Name: "notes", BaseType: "text"},
		{Name: "ts", BaseType: "timestamptz"},
	}
	r := &http.Request{PostForm: url.Values{
		"v_id": {"7"}, "orig_id": {"7"}, // unchanged
		"v_name": {"new"}, "orig_name": {"old"}, // changed
		// Unchanged multi-line textarea: browsers CRLF-normalize on submit while
		// the rendered original keeps LF — must not count as dirty.
		"v_notes": {"a\r\nb"}, "orig_notes": {"a\nb"},
		// Unchanged timestamptz: rewriting this lossy display text would shift
		// the stored instant.
		"v_ts": {"2024-03-01 12:30:45+05:30"}, "orig_ts": {"2024-03-01 12:30:45+05:30"},
	}}
	names, values := readRowValues(r.PostForm, "", cols, false)
	if len(names) != 1 || names[0] != "name" || values[0] != "new" {
		t.Errorf("dirty fields = %v %v, want only name=new", names, values)
	}
}

func TestReadRowValuesNullTransitions(t *testing.T) {
	cols := []model.Column{
		{Name: "a", BaseType: "text"},
		{Name: "b", BaseType: "text"},
		{Name: "c", BaseType: "text"},
	}
	r := &http.Request{PostForm: url.Values{
		"null_a": {"1"}, "orig_a": {""}, "orignull_a": {"1"}, // NULL → NULL: untouched
		"null_b": {"1"}, "orig_b": {"x"}, // value → NULL: written
		"v_c": {"set now"}, "orig_c": {""}, "orignull_c": {"1"}, // NULL → value: written
	}}
	names, values := readRowValues(r.PostForm, "", cols, false)
	if len(names) != 2 {
		t.Fatalf("written columns = %v, want b and c", names)
	}
	got := map[string]any{names[0]: values[0], names[1]: values[1]}
	if v, ok := got["b"]; !ok || v != nil {
		t.Errorf("b = %v, want NULL write", v)
	}
	if v, ok := got["c"]; !ok || v != "set now" {
		t.Errorf("c = %v, want \"set now\"", v)
	}
}

// TestReadRowValuesWithoutOrigMarkers confirms the pre-dirty-tracking behavior
// is preserved when no orig_ inputs ride along (insert form, older clients):
// every submitted field is written.
func TestReadRowValuesWithoutOrigMarkers(t *testing.T) {
	cols := []model.Column{{Name: "name", BaseType: "varchar"}}
	r := &http.Request{PostForm: url.Values{"v_name": {"same"}}}
	names, _ := readRowValues(r.PostForm, "", cols, false)
	if len(names) != 1 || names[0] != "name" {
		t.Errorf("no-marker submit = %v, want name written", names)
	}

	// And the insert path ignores orig markers entirely.
	r2 := &http.Request{PostForm: url.Values{"v_name": {"same"}, "orig_name": {"same"}}}
	names2, _ := readRowValues(r2.PostForm, "", cols, true)
	if len(names2) != 1 {
		t.Errorf("insert with markers = %v, want name written", names2)
	}
}

// TestInsertFormCopyPrefill covers the ?copy=1 path, whose two failures used
// to fall through to a BLANK insert form the user would silently retype into:
// a malformed row token now refuses like the edit form does, a row deleted
// since the page was loaded gets its own message (a normal race, not a
// failure), and a live row still prefills.
func TestInsertFormCopyPrefill(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d, _ := driver.Get("sqlite")
	conn := openTestConn(t)
	ctx := t.Context()
	for _, stmt := range []string{
		`CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`INSERT INTO widgets (id, name) VALUES (1, 'bolt')`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, conn, nil)

	get := func(t *testing.T, where string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet,
			"/db/main/table/widgets/insert?copy=1&where="+url.QueryEscape(where), nil)
		r.SetPathValue("db", "main")
		r.SetPathValue("table", "widgets")
		r = authedRequest(t, r, uc)
		w := httptest.NewRecorder()
		h.TableInsertForm(w, r)
		return w
	}

	t.Run("malformed token refuses", func(t *testing.T) {
		w := get(t, "!!not-a-token!!")
		if w.Code != http.StatusBadRequest {
			t.Errorf("copy with a malformed token = %d, want 400 — not a blank insert form", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid row reference.") {
			t.Error("the refusal does not name the invalid row reference")
		}
	})

	t.Run("vanished row gets its own message", func(t *testing.T) {
		gone := "2"
		w := get(t, encodeRowKey([]rowKeyEntry{{Col: "id", Val: &gone}}))
		if w.Code != http.StatusNotFound {
			t.Errorf("copy of a deleted row = %d, want 404 — not a blank insert form", w.Code)
		}
		if !strings.Contains(w.Body.String(), "no longer exists") {
			t.Error("the vanished-row race does not get its own message")
		}
	})

	t.Run("live row still prefills", func(t *testing.T) {
		alive := "1"
		w := get(t, encodeRowKey([]rowKeyEntry{{Col: "id", Val: &alive}}))
		if w.Code != http.StatusOK {
			t.Fatalf("copy of a live row = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), "bolt") {
			t.Error("the live row's values did not prefill the form")
		}
	})
}
