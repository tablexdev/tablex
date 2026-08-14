package handlers

// The (schema, table) checkbox token. It is length-prefixed rather than joined
// with a separator because a SQL identifier may legally contain any character —
// including the separator. These tests pin exactly that: the pairs that a
// "schema.table" or "schema:table" encoding would confuse must stay distinct.

import (
	"net/url"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/dump"
)

// TestParseRowRange pins the FORM-side rule. dump.RowRange.clauseFor guards the
// same non-positive-limit case, and that redundancy is deliberate — but it also
// means an end-to-end test cannot tell which layer refused. This one can.
func TestParseRowRange(t *testing.T) {
	rng := func(limit, offset string) *dump.RowRange {
		return parseRowRange(url.Values{"row_limit": {limit}, "row_offset": {offset}})
	}

	// A missing, zero, negative or unparseable limit is NO LIMIT — never zero
	// rows. Reading a fat-fingered field as "export nothing" would hand back a
	// silently empty dump.
	for _, limit := range []string{"", "0", "-1", "abc", "1e3", " "} {
		if got := rng(limit, ""); got != nil {
			t.Errorf("row_limit=%q gave %+v, want no range", limit, got)
		}
	}
	// Surrounding whitespace is tolerated; browsers and paste both produce it.
	if got := rng(" 25 ", " 50 "); got == nil || got.Limit != 25 || got.Offset != 50 {
		t.Errorf("padded input gave %+v, want limit 25 offset 50", got)
	}
	// An unusable offset falls back to 0 rather than discarding the limit with it.
	for _, offset := range []string{"", "-4", "nope"} {
		got := rng("10", offset)
		if got == nil || got.Limit != 10 || got.Offset != 0 {
			t.Errorf("row_offset=%q gave %+v, want limit 10 offset 0", offset, got)
		}
	}
	// The offset is int64 end-to-end: a table past 2^31 rows must not truncate.
	if got := rng("5", "3000000000"); got == nil || got.Offset != 3000000000 {
		t.Errorf("large offset gave %+v; it must not truncate through a 32-bit int", got)
	}
}

func TestObjectTokenRoundTrip(t *testing.T) {
	for _, tc := range []struct{ schema, table string }{
		{"", "orders"},
		{"public", "orders"},
		{"", ""},
		// The pairs a naive separator loses.
		{"a.b", "c"},
		{"a", "b.c"},
		{"a:b", "c"},
		{"a", "1:b"},
		{"weird\ntable", "with spaces"},
	} {
		schema, table, ok := parseObjectToken(objectToken(tc.schema, tc.table))
		if !ok {
			t.Errorf("(%q,%q) did not decode", tc.schema, tc.table)
			continue
		}
		if schema != tc.schema || table != tc.table {
			t.Errorf("(%q,%q) round-tripped as (%q,%q)", tc.schema, tc.table, schema, table)
		}
	}

	// The ambiguity a '.' join would create, stated as an equality that must NOT hold.
	if objectToken("a.b", "c") == objectToken("a", "b.c") {
		t.Error(`"a.b"+"c" and "a"+"b.c" encode identically; the token is ambiguous`)
	}

	for _, bad := range []string{"", "nope", "abc:x", "-1:x", "99:short"} {
		if _, _, ok := parseObjectToken(bad); ok {
			t.Errorf("malformed token %q decoded", bad)
		}
	}
}

func TestFilterGroupsBySelection(t *testing.T) {
	groups := []dump.SchemaGroup{
		{Schema: "public", Tables: []driver.TableRef{
			{Schema: "public", Table: "orders"},
			{Schema: "public", Table: "customers"},
		}},
		{Schema: "archive", Tables: []driver.TableRef{
			{Schema: "archive", Table: "orders"}, // same NAME, other schema
		}},
	}
	count := func(gs []dump.SchemaGroup) int {
		n := 0
		for _, g := range gs {
			n += len(g.Tables)
		}
		return n
	}

	// Nothing selected means everything — the pre-existing behaviour, and what
	// keeps an ordinary whole-database export unchanged.
	if got := count(filterGroupsBySelection(groups, nil)); got != 3 {
		t.Errorf("empty selection kept %d tables, want all 3", got)
	}

	// A same-named table in another schema must NOT ride along.
	got := filterGroupsBySelection(groups, []string{objectToken("public", "orders")})
	if count(got) != 1 {
		t.Fatalf("selecting public.orders kept %d tables, want 1: %+v", count(got), got)
	}
	if got[0].Schema != "public" || got[0].Tables[0].Table != "orders" {
		t.Errorf("selected the wrong table: %+v", got)
	}

	// An unknown name is dropped, never trusted into existence.
	if got := count(filterGroupsBySelection(groups, []string{objectToken("public", "ghost")})); got != 0 {
		t.Errorf("an unknown table survived the filter (%d kept)", got)
	}

	// A schema left with no selected tables disappears rather than lingering empty.
	got = filterGroupsBySelection(groups, []string{objectToken("archive", "orders")})
	if len(got) != 1 || got[0].Schema != "archive" {
		t.Errorf("empty groups were not dropped: %+v", got)
	}
}
