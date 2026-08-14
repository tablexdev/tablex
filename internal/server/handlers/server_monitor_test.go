package handlers

// The process list under restrict.database_allowlist.
//
// The listing is an allowlisted ROUTE showing un-allowlisted METADATA: a process
// list names every database on the server, and on MySQL/MariaDB the whole
// statement text of every connection. Both engines leak it, which is why the
// filter lives here — applied once to the shared list — rather than in either
// dialect's query.

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// procSet builds a result set in one engine's shape. cols names the columns;
// each row is the matching values, with "" meaning NULL.
func procSet(cols []string, rows ...[]string) *driver.ResultSet {
	rs := &driver.ResultSet{}
	for _, c := range cols {
		rs.Columns = append(rs.Columns, driver.ResultColumn{Name: c})
	}
	for _, r := range rows {
		var row []driver.Value
		for _, v := range r {
			row = append(row, driver.Value{Str: v, Null: v == ""})
		}
		rs.Rows = append(rs.Rows, row)
	}
	return rs
}

func rowStrings(rs *driver.ResultSet, col string) []string {
	i := resultColumnIndex(rs, col)
	var out []string
	for _, row := range rs.Rows {
		if i < 0 || i >= len(row) || row[i].Null {
			out = append(out, "<null>")
			continue
		}
		out = append(out, row[i].Str)
	}
	return out
}

func TestNarrowProcessList(t *testing.T) {
	// PostgreSQL: pid, usename, datname, state, wait_event_type, query.
	pg := func() *driver.ResultSet {
		return procSet([]string{"pid", "usename", "datname", "state", "wait_event_type", "query"},
			[]string{"1", "app", "shop", "active", "", "SELECT * FROM orders"},
			[]string{"2", "app", "secrets", "active", "", "SELECT * FROM salaries"},
			[]string{"3", "postgres", "", "idle", "", ""}, // a background worker: datname NULL
		)
	}
	// MySQL/MariaDB: SHOW FULL PROCESSLIST. The database column is `db` and the
	// statement column is `Info`, so a filter that only knew PostgreSQL's names
	// would silently pass every row through.
	my := func() *driver.ResultSet {
		return procSet([]string{"Id", "User", "Host", "db", "Command", "Time", "State", "Info"},
			[]string{"1", "app", "h", "shop", "Query", "0", "", "SELECT * FROM orders"},
			[]string{"2", "app", "h", "secrets", "Query", "0", "", "SELECT * FROM salaries"},
			[]string{"3", "repl", "h", "", "Binlog Dump", "0", "", ""}, // no USE
		)
	}

	t.Run("no allowlist changes nothing", func(t *testing.T) {
		var h Handlers
		for name, build := range map[string]func() *driver.ResultSet{"postgres": pg, "mysql": my} {
			in := build()
			out := h.narrowProcessList(in)
			if out != in {
				t.Errorf("%s: the set was rebuilt with no allowlist configured", name)
			}
		}
	})

	t.Run("rows outside the allowlist are hidden", func(t *testing.T) {
		h := &Handlers{}
		h.Cfg.Restrict.Databases = []string{"shop"}
		for _, tc := range []struct {
			name, dbCol string
			build       func() *driver.ResultSet
		}{
			{"postgres", "datname", pg},
			{"mysql", "db", my},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out := h.narrowProcessList(tc.build())
				got := rowStrings(out, tc.dbCol)
				if len(got) != 1 || got[0] != "shop" {
					t.Errorf("visible databases = %v, want only [shop] — a NULL row cannot be attributed to an allowlisted database either", got)
				}
			})
		}
	})

	t.Run("the query text is blanked even on a visible row", func(t *testing.T) {
		// The db column names the connection's DEFAULT database, not what the
		// statement touches, so an allowlisted connection can still name another
		// database's tables in its SQL.
		h := &Handlers{}
		h.Cfg.Restrict.Databases = []string{"shop"}
		for _, tc := range []struct {
			name, qCol string
			build      func() *driver.ResultSet
		}{
			{"postgres", "query", pg},
			{"mysql", "Info", my},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out := h.narrowProcessList(tc.build())
				if got := rowStrings(out, tc.qCol); len(got) != 1 || got[0] != "(hidden)" {
					t.Errorf("query column = %v, want [(hidden)]", got)
				}
			})
		}
	})

	t.Run("the caller's rows are not mutated", func(t *testing.T) {
		h := &Handlers{}
		h.Cfg.Restrict.Databases = []string{"shop"}
		in := pg()
		h.narrowProcessList(in)
		if got := rowStrings(in, "query"); got[0] != "SELECT * FROM orders" {
			t.Errorf("the input set was modified in place: %v", got)
		}
	})

	t.Run("an unrecognised database column hides everything", func(t *testing.T) {
		// Fail closed: a row that cannot be attributed to an allowlisted database
		// is what the allowlist refuses, and a listing with no database column at
		// all cannot attribute any of them.
		h := &Handlers{}
		h.Cfg.Restrict.Databases = []string{"shop"}
		out := h.narrowProcessList(procSet([]string{"pid", "state"}, []string{"1", "active"}))
		if len(out.Rows) != 0 {
			t.Errorf("rows = %d, want 0", len(out.Rows))
		}
	})

	t.Run("a hidden session cannot be killed", func(t *testing.T) {
		// processListed runs against the SAME narrowed set, which is what makes
		// the allowlist a control rather than a display filter.
		h := &Handlers{}
		h.Cfg.Restrict.Databases = []string{"shop"}
		out := h.narrowProcessList(pg())
		if processListed(out, "pid", 2) {
			t.Error("a session on a non-allowlisted database is still addressable by pid")
		}
		if !processListed(out, "pid", 1) {
			t.Error("a session on the allowlisted database became unkillable")
		}
	})
}
