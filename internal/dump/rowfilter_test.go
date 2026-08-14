package dump

// RowFilter's one rule: a filter narrows the table it names and NEVER widens
// anything else. The handler only ever builds a filter for a single-table
// export, so the non-target branch is a safety net rather than a live path —
// which is exactly why it needs its own test. If it ever regressed to "no
// filter, carry on", a sibling table in the plan would silently dump in full.

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

func TestRowFilterClauseFor(t *testing.T) {
	target := driver.TableRef{Database: "app", Schema: "public", Table: "orders"}
	f := &RowFilter{Target: target, Where: "(id = $1)", Args: []any{int64(7)}}

	t.Run("target", func(t *testing.T) {
		where, args, allowed := f.clauseFor(target)
		if !allowed {
			t.Fatal("the filter refused its own table")
		}
		if where != " WHERE (id = $1)" {
			t.Errorf("where = %q", where)
		}
		if len(args) != 1 || args[0] != int64(7) {
			t.Errorf("args = %v, want [7]", args)
		}
	})

	// Each field on its own must be enough to disqualify a table: a same-named
	// table in another schema or database is a DIFFERENT table, and the row keys
	// would silently match rows in it.
	for name, other := range map[string]driver.TableRef{
		"other table":    {Database: "app", Schema: "public", Table: "customers"},
		"other schema":   {Database: "app", Schema: "archive", Table: "orders"},
		"other database": {Database: "reporting", Schema: "public", Table: "orders"},
	} {
		t.Run(name, func(t *testing.T) {
			where, args, allowed := f.clauseFor(other)
			if allowed {
				t.Error("a non-target table was allowed to contribute data; it would dump IN FULL")
			}
			if where != "" || args != nil {
				t.Errorf("a refused table still got a clause: %q %v", where, args)
			}
		})
	}

	t.Run("row range", func(t *testing.T) {
		// clauseFor guards Limit <= 0 itself rather than trusting its caller:
		// RowRange is exported, so a value this package did not construct can
		// reach it, and "LIMIT 0" would silently export nothing. The handler
		// checks the same thing when parsing the form; both are tested, because
		// a guard that only ever runs behind another guard is a guard nobody
		// notices losing.
		d, ok := driver.Get("sqlite")
		if !ok {
			t.Fatal("sqlite dialect not registered")
		}
		for _, rr := range []*RowRange{nil, {Limit: 0}, {Limit: -3}, {Limit: 0, Offset: 50}} {
			if got := rr.clauseFor(d); got != "" {
				t.Errorf("%+v rendered %q, want no clause", rr, got)
			}
		}
		if got := (&RowRange{Limit: 10, Offset: 20}).clauseFor(d); got != " LIMIT 10 OFFSET 20" {
			t.Errorf("clause = %q", got)
		}
	})

	t.Run("no filter", func(t *testing.T) {
		// The unfiltered path must be completely untouched: every table allowed,
		// no clause, no args.
		var nilFilter *RowFilter
		for _, f := range []*RowFilter{nilFilter, {Target: target}} {
			where, args, allowed := f.clauseFor(target)
			if !allowed || where != "" || args != nil {
				t.Errorf("unfiltered export got (%q, %v, %v), want (\"\", nil, true)", where, args, allowed)
			}
		}
	})
}
