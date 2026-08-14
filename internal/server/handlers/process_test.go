package handlers

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

func processSet(idCol string, ids ...string) *driver.ResultSet {
	rs := &driver.ResultSet{Columns: []driver.ResultColumn{
		{Name: "User"}, {Name: idCol, Numeric: true}, {Name: "Command"},
	}}
	for _, id := range ids {
		rs.Rows = append(rs.Rows, []driver.Value{
			{Str: "app"}, {Str: id}, {Str: "Query"},
		})
	}
	return rs
}

func TestResultColumnIndex(t *testing.T) {
	rs := processSet("Id", "7")
	if got := resultColumnIndex(rs, "Id"); got != 1 {
		t.Errorf("resultColumnIndex(Id) = %d, want 1", got)
	}
	// Case-insensitive: neither engine promises the case its dialect declared.
	if got := resultColumnIndex(rs, "id"); got != 1 {
		t.Errorf("resultColumnIndex(id) = %d, want 1 — the match must not be case-sensitive", got)
	}
	if got := resultColumnIndex(rs, "pid"); got != -1 {
		t.Errorf("resultColumnIndex(pid) = %d, want -1 for an absent column", got)
	}
}

// TestProcessListed is the gate that stands between a form value and a KILL.
// The property under test is that a pid NOT in the current listing is refused —
// the failure to avoid is killing an arbitrary session id somebody posted.
func TestProcessListed(t *testing.T) {
	rs := processSet("Id", "7", "42", "1001")
	for _, id := range []int64{7, 42, 1001} {
		if !processListed(rs, "Id", id) {
			t.Errorf("processListed(%d) = false, want true — it is in the listing", id)
		}
	}
	for _, id := range []int64{8, 0, -1, 100, 10011} {
		if processListed(rs, "Id", id) {
			t.Errorf("processListed(%d) = true, want false — it is NOT in the listing", id)
		}
	}
	// Numeric, not textual: a server that pads or spaces the value still
	// matches, and "7 " does not accidentally become a different session.
	padded := processSet("Id", " 7 ")
	if !processListed(padded, "Id", 7) {
		t.Error("a padded id must still match; the comparison is numeric")
	}
	// A listing with no identifier column can authorize nothing.
	if processListed(processSet("Id", "7"), "pid", 7) {
		t.Error("processListed matched on a column the listing does not have")
	}
	// A short or NULL row is skipped, not treated as a match.
	ragged := processSet("Id", "7")
	ragged.Rows = append(ragged.Rows, []driver.Value{{Str: "app"}}, []driver.Value{{Str: "app"}, {Null: true}, {Str: "Q"}})
	if processListed(ragged, "Id", 0) {
		t.Error("a NULL or missing id cell must not match")
	}
}

// TestKillIDGuardsTheRow covers the render side of the same rule: a row the
// listing cannot address gets no button, rather than one that posts a blank.
func TestKillIDGuardsTheRow(t *testing.T) {
	row := []driver.Value{{Str: "app"}, {Str: "42"}, {Str: "Query"}}
	b := processesBody{CanKill: true, IDIndex: 1}
	if got := b.KillID(row); got != "42" {
		t.Errorf("KillID = %q, want 42", got)
	}
	for name, body := range map[string]processesBody{
		"kill unsupported":    {CanKill: false, IDIndex: 1},
		"no id column":        {CanKill: true, IDIndex: -1},
		"index past the row":  {CanKill: true, IDIndex: 9},
		"index is the string": {CanKill: true, IDIndex: 0}, // "app": rendered, but the handler refuses it
	} {
		got := body.KillID(row)
		if name != "index is the string" && got != "" {
			t.Errorf("%s: KillID = %q, want empty", name, got)
		}
	}
	null := []driver.Value{{Str: "app"}, {Null: true}, {Str: "Query"}}
	if got := b.KillID(null); got != "" {
		t.Errorf("KillID on a NULL id = %q, want empty", got)
	}
}
