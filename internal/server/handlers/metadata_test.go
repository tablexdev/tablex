package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
)

// TestListMetaSingleDial pins the metadata dial-count fix (H1 tail): listMeta no
// longer dials ConnFor itself — it takes the caller's already-resolved
// (conn, connErr) — so a metadata page dials exactly once per request
// (TableTriggers previously dialed twice: once for its sequence guard, once
// inside listMeta, repeating a ~15s connect on a broken backend). The refactored
// signature makes a second dial STRUCTURALLY impossible (listMeta has no ConnFor
// path). It also pins the TYPED tiers: a failing connection or list error must
// land in the error return and never in Empty — wording used to be the only
// thing separating a failure from an empty database — and Empty is reserved
// for a successful zero-result query.
func TestListMetaSingleDial(t *testing.T) {
	d, _ := driver.Get("mysql")
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, nil, nil)

	// connErr short-circuits: the list fn must never run (it would nil-deref
	// conn), and the failure lands in errMsg, never Empty.
	calls := 0
	items, empty, errMsg := listMeta(uc, "none", nil, errors.New("dial refused"),
		func(*driver.Connection) ([]int, error) { calls++; return []int{1}, nil })
	if calls != 0 {
		t.Errorf("list fn ran %d times on a connErr; want 0 (no work on a failed dial)", calls)
	}
	if items != nil || empty != "" || !strings.Contains(errMsg, "Database unreachable") {
		t.Errorf("connErr result = items %v empty %q err %q; the failure must land in the error tier, never Empty", items, empty, errMsg)
	}

	// Success: the list fn runs exactly once and its items pass through.
	calls = 0
	items, empty, errMsg = listMeta(uc, "none", nil, nil,
		func(*driver.Connection) ([]int, error) { calls++; return []int{7, 8}, nil })
	if calls != 1 {
		t.Errorf("list fn ran %d times, want exactly 1", calls)
	}
	if empty != "" || errMsg != "" || len(items) != 2 {
		t.Errorf("success result = items %v empty %q err %q", items, empty, errMsg)
	}

	// A list error surfaces verbatim in the ERROR tier; a clean zero-result
	// becomes emptyMsg with no error.
	if _, empty, errMsg = listMeta(uc, "none", nil, nil,
		func(*driver.Connection) ([]int, error) { return nil, errors.New("boom") }); errMsg != "boom" || empty != "" {
		t.Errorf("list-error result = empty %q err %q, want the error tier to carry %q", empty, errMsg, "boom")
	}
	if _, empty, errMsg = listMeta(uc, "nothing here", nil, nil,
		func(*driver.Connection) ([]int, error) { return nil, nil }); empty != "nothing here" || errMsg != "" {
		t.Errorf("empty-clean result = empty %q err %q, want the emptyMsg and no error", empty, errMsg)
	}
}

// TestGroupCollations pins the create-database collation grouping (H5): the flat
// introspected list (already charset-then-name sorted) collapses into one group
// per charset, preserving order, so the select's optgroups render correctly.
func TestGroupCollations(t *testing.T) {
	in := []driver.Collation{
		{Name: "utf8mb4_general_ci", Charset: "utf8mb4", Default: true},
		{Name: "utf8mb4_bin", Charset: "utf8mb4"},
		{Name: "latin1_swedish_ci", Charset: "latin1", Default: true},
	}
	got := groupCollations(in)
	if len(got) != 2 {
		t.Fatalf("groups = %d, want 2 (one per charset)", len(got))
	}
	if got[0].Charset != "utf8mb4" || len(got[0].Collations) != 2 {
		t.Errorf("group 0 = %q with %d collations, want utf8mb4 with 2", got[0].Charset, len(got[0].Collations))
	}
	if got[1].Charset != "latin1" || len(got[1].Collations) != 1 {
		t.Errorf("group 1 = %q with %d collations, want latin1 with 1", got[1].Charset, len(got[1].Collations))
	}
	if got[0].Collations[0].Name != "utf8mb4_general_ci" {
		t.Errorf("intra-group order not preserved: %q", got[0].Collations[0].Name)
	}

	if groupCollations(nil) != nil {
		t.Error("groupCollations(nil) should be nil")
	}
}
