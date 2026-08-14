package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

func (d dialect) Indexes(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Index, error) {
	prefix := d.schemaPrefix(t.Database)
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA %sindex_list(%s)", prefix, d.QuoteIdent(t.Table)))
	if err != nil {
		return nil, err
	}
	type idxMeta struct {
		name    string
		unique  bool
		primary bool
		partial bool
	}
	var metas []idxMeta
	for rows.Next() {
		var seq int
		var name, origin sql.NullString
		var unique, partial sql.NullInt64
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			return nil, err
		}
		metas = append(metas, idxMeta{
			name: name.String, unique: unique.Int64 == 1,
			primary: origin.String == "pk", partial: partial.Int64 == 1,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []model.Index
	havePrimary := false
	for _, m := range metas {
		idx := model.Index{Name: m.name, Unique: m.unique, Primary: m.primary, Type: "BTREE"}
		// index_xinfo (vs index_info) reports the sort direction (desc) and marks
		// key vs. auxiliary (rowid) columns (key), and a NULL name denotes an
		// expression index part.
		ir, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA %sindex_xinfo(%s)", prefix, d.QuoteIdent(m.name)))
		if err != nil {
			return nil, err
		}
		for ir.Next() {
			var seqno, cid, desc, key int
			var col, coll sql.NullString
			if err := ir.Scan(&seqno, &cid, &col, &desc, &coll, &key); err != nil {
				ir.Close()
				return nil, err
			}
			if key != 1 {
				continue // skip the trailing rowid/PK columns index_xinfo appends
			}
			var ic model.IndexColumn
			if col.Valid && col.String != "" {
				ic.Name = col.String
			} else {
				ic.Expr = "(expression)" // index on an expression; PRAGMA gives no text
			}
			ic.Descending = desc == 1
			idx.Columns = append(idx.Columns, ic)
		}
		ir.Close()
		if err := ir.Err(); err != nil {
			return nil, err
		}
		// A partial index carries a WHERE predicate only in its CREATE statement;
		// PRAGMA does not expose it, so recover it from sqlite_master.
		//
		// This read HARD-FAILS on a real error, deliberately unlike tableDDL,
		// which degrades to "". The asymmetry is not an oversight, but the reason
		// is NOT the dump: SQLite's dump replays the verbatim sqlite_master text
		// (see DumpObjects), so a lost Predicate cannot widen a restored index.
		// What it costs is what the structure page SHOWS. tableDDL feeds display
		// heuristics (WITHOUT ROWID, inline PK DESC) where a wrong guess is
		// cosmetic; presenting a partial index as though it indexed EVERY row is a
		// false statement about the schema, and this read failing is the only
		// evidence available that it would be false. Losing the index list is
		// recoverable; silently mis-describing an index is not.
		//
		// ErrNoRows is the one tolerable outcome: the index was in index_list a
		// moment ago and is gone from sqlite_master now, so concurrent DDL
		// dropped it and its predicate is moot.
		if m.partial {
			var ddl sql.NullString
			q := fmt.Sprintf("SELECT sql FROM %ssqlite_master WHERE type='index' AND name = ?", prefix)
			switch err := db.QueryRowContext(ctx, q, m.name).Scan(&ddl); {
			case errors.Is(err, sql.ErrNoRows):
				// dropped underneath us — leave the predicate empty
			case err != nil:
				return nil, fmt.Errorf("sqlite: reading the predicate of partial index %q: %w", m.name, err)
			default:
				idx.Predicate = partialIndexPredicate(ddl.String)
			}
		}
		if m.primary {
			havePrimary = true
		}
		out = append(out, idx)
	}

	// Synthesize a PRIMARY index for INTEGER PRIMARY KEY (rowid) tables, which
	// have no entry in index_list.
	if !havePrimary {
		cols, err := d.Columns(ctx, db, t)
		if err != nil {
			return nil, err
		}
		var pk model.Index
		pk.Name = "PRIMARY"
		pk.Primary = true
		pk.Unique = true
		pk.Type = "BTREE"
		for _, c := range cols {
			if c.IsPrimaryKey {
				pk.Columns = append(pk.Columns, model.IndexColumn{Name: c.Name})
			}
		}
		if len(pk.Columns) > 0 {
			out = append([]model.Index{pk}, out...)
		}
	}
	return out, nil
}

func (d dialect) ForeignKeys(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.ForeignKey, error) {
	prefix := d.schemaPrefix(t.Database)
	q := fmt.Sprintf("PRAGMA %sforeign_key_list(%s)", prefix, d.QuoteIdent(t.Table))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g := driver.NewGrouper[int, model.ForeignKey]()
	for rows.Next() {
		var id, seq int
		var refTable, from, to, onUpd, onDel, match sql.NullString
		if err := rows.Scan(&id, &seq, &refTable, &from, &to, &onUpd, &onDel, &match); err != nil {
			return nil, err
		}
		fk := g.GetOrAdd(id, func() model.ForeignKey {
			return model.ForeignKey{
				// PRAGMA foreign_key_list has no name column — SQLite identifies
				// a foreign key only by its ordinal — so this name is invented
				// for display and grouping and exists nowhere in the schema.
				// Synthetic says so; see model.ForeignKey.
				Name:      fmt.Sprintf("fk_%s_%d", t.Table, id),
				Synthetic: true,
				RefTable:  refTable.String,
				OnUpdate:  onUpd.String,
				OnDelete:  onDel.String,
			}
		})
		fk.Columns = append(fk.Columns, from.String)
		fk.RefColumns = append(fk.RefColumns, to.String) // NULL when the FK targets the parent's PK implicitly
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := g.Slice()
	// A FK written as `REFERENCES parent` (no column list) targets the parent's
	// primary key, and foreign_key_list reports each referenced column as NULL.
	// Resolve those from the parent PK, by position, so display and the dumped
	// DDL carry the real column names (a composite PK maps position-for-position).
	for i := range out {
		fk := &out[i]
		missing := false
		for _, rc := range fk.RefColumns {
			if rc == "" {
				missing = true
				break
			}
		}
		if !missing {
			continue
		}
		pk, err := d.primaryKeyColumns(ctx, db, prefix, fk.RefTable)
		if err != nil {
			return nil, err
		}
		for j := range fk.RefColumns {
			if fk.RefColumns[j] == "" && j < len(pk) {
				fk.RefColumns[j] = pk[j]
			}
		}
	}
	return out, nil
}

// primaryKeyColumns returns the referenced table's primary-key columns in key
// order (PRAGMA table_info's pk field is the 1-based position within the PK, 0
// for non-key columns). Used to resolve implicit-PK foreign-key references.
func (d dialect) primaryKeyColumns(ctx context.Context, db *sql.DB, prefix, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA %stable_info(%s)", prefix, d.QuoteIdent(table)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byPos := map[int]string{}
	maxPos := 0
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ, dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		if pk > 0 {
			byPos[pk] = name.String
			if pk > maxPos {
				maxPos = pk
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, maxPos)
	for p := 1; p <= maxPos; p++ {
		out = append(out, byPos[p])
	}
	return out, nil
}

func (d dialect) CreateSQL(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	q := fmt.Sprintf(`SELECT sql FROM %ssqlite_master WHERE type IN ('table','view') AND name = ?`,
		d.schemaPrefix(t.Database))
	var ddl sql.NullString
	if err := db.QueryRowContext(ctx, q, t.Table).Scan(&ddl); err != nil {
		return "", err
	}
	if ddl.Valid {
		return ddl.String + ";", nil
	}
	return "", nil
}

func (d dialect) ListViews(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.View, error) {
	q := fmt.Sprintf(`SELECT name, COALESCE(sql,'') FROM %ssqlite_master WHERE type='view' ORDER BY name`,
		d.schemaPrefix(scope.Database))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.View
	for rows.Next() {
		var v model.View
		if err := rows.Scan(&v.Name, &v.Definition); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (dialect) ListRoutines(context.Context, *sql.DB, driver.Scope) ([]model.Routine, error) {
	return nil, nil
}

func (d dialect) ListTriggers(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Trigger, error) {
	q := fmt.Sprintf(`SELECT name, tbl_name, COALESCE(sql,'') FROM %ssqlite_master WHERE type='trigger' ORDER BY name`,
		d.schemaPrefix(scope.Database))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Trigger
	for rows.Next() {
		var tr model.Trigger
		if err := rows.Scan(&tr.Name, &tr.Table, &tr.Definition); err != nil {
			return nil, err
		}
		tr.Timing, tr.Event = parseTriggerDef(tr.Definition)
		out = append(out, tr)
	}
	return out, rows.Err()
}

func parseTriggerDef(def string) (timing, event string) {
	// Only the header (up to "... ON <table>") carries the timing and event; the
	// trigger body may contain INSERT/UPDATE/DELETE statements that would
	// otherwise be misread. Blank out quoted/bracketed identifiers first so a
	// quoted trigger or table name containing " ON " or an event keyword (e.g.
	// CREATE TRIGGER "audit ON delete" ...) cannot truncate the header early or
	// masquerade as the clause. Pad with spaces so the " KEYWORD " matches still
	// hit the truncated tail.
	u := " " + strings.ToUpper(blankSQLiteQuoted(def)) + " "
	if i := strings.Index(u, " ON "); i >= 0 {
		u = u[:i] + " "
	}
	for _, t := range []string{"INSTEAD OF", "BEFORE", "AFTER"} {
		if strings.Contains(u, " "+t+" ") {
			timing = t
			break
		}
	}
	if timing == "" {
		timing = "BEFORE" // SQLite defaults to BEFORE when the clause is omitted
	}
	for _, e := range []string{"INSERT", "UPDATE", "DELETE"} {
		if strings.Contains(u, " "+e+" ") {
			event = e
			break
		}
	}
	return timing, event
}

// partialIndexPredicate extracts the WHERE expression from a partial index's
// CREATE INDEX DDL, or "" if there is none: it neutralizes comments and
// quoted/bracketed spans so neither can contribute a spurious paren or a
// spurious "WHERE", then finds the clause after the top-level column-list
// parenthesis.
//
// EVERY offset here indexes the ORIGINAL ddl, which is why the skeleton it
// scans is byte-length-preserving and why the keyword is matched byte-wise
// rather than through strings.ToUpper. ToUpper is not length-preserving —
// U+017F 'ſ' folds to a one-byte 'S', U+0250 'ɐ' to a three-byte 'Ɐ' — so an
// uppercased copy's indices do not address the original at all. Adding a bounds
// GUARD instead would only convert the panic that exposed this into a silently
// misaligned predicate, which is strictly worse: a wrong predicate displayed as
// fact, with nothing to notice it by.
func partialIndexPredicate(ddl string) string {
	blanked := blankSQLiteInert(ddl)
	depth, closeIdx := 0, -1
	for i := 0; i < len(blanked) && closeIdx < 0; i++ {
		switch blanked[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				closeIdx = i
			}
		}
	}
	if closeIdx < 0 {
		return ""
	}
	tail := blanked[closeIdx+1:]
	for i := 0; i+len("WHERE") <= len(tail); i++ {
		if !hasFoldedWordAt(tail, i, "WHERE") {
			continue
		}
		start := closeIdx + 1 + i + len("WHERE")
		if start > len(ddl) { // cheap belt-and-braces; the pass above preserves length
			return ""
		}
		return strings.TrimSpace(ddl[start:])
	}
	return ""
}

// hasFoldedWordAt reports whether the ASCII word occurs at s[i], matched
// case-insensitively BYTE-WISE (never via strings.ToUpper, which changes byte
// length) and bounded by non-identifier bytes on BOTH sides — so neither
// "NOWHERE" nor "WHERECLAUSE" can match, and neither could the tail of an
// identifier that merely ends in "where".
func hasFoldedWordAt(s string, i int, word string) bool {
	if i+len(word) > len(s) {
		return false
	}
	if i > 0 && isIdentByte(s[i-1]) {
		return false
	}
	for k := 0; k < len(word); k++ {
		c := s[i+k]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != word[k] {
			return false
		}
	}
	return i+len(word) == len(s) || !isIdentByte(s[i+len(word)])
}

// blankSQLiteInert replaces every comment, string literal and quoted/bracketed
// identifier in s (delimiters included) with spaces, preserving byte length and
// therefore the position of every token outside them. SQLite quotes identifiers
// with double quotes, brackets or backticks, and string literals with single
// quotes; a doubled delimiter inside any of the quoted forms is an escaped
// literal, not a close ([] has no escape — the first ] ends it).
//
// Comments and quoted spans are decided in ONE INTERLEAVED pass: at each
// position a comment wins if one opens, ELSE a quoted span. A comments-first
// pass is not equivalent, it is a silent regression — in
//
//	CREATE INDEX ix ON t(lower('a--b')) WHERE y > 0
//
// the `--` INSIDE the literal would elide to end of input, destroying the `))`,
// so no top-level close-paren is found and a working predicate comes back empty.
//
// elideDDLTail has the right interleaved shape but writes one space per elided
// REGION, so it is not length-preserving: the shape and skipDDLComment are
// reused here, the function deliberately is not. blankSQLiteQuoted stays for
// the trigger parse, which uppercases the whole skeleton and only tests
// Contains, so no offset survives into the original there.
func blankSQLiteInert(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		// s[i] is still the original byte here: the loop only blanks positions it
		// has already consumed and then advances past them.
		if j, ok := skipDDLComment(s, i); ok {
			for ; i <= j; i++ {
				b[i] = ' '
			}
			i-- // the loop's own i++ steps past the comment's last byte
			continue
		}
		var closer byte
		switch b[i] {
		case '"', '\'', '`':
			closer = b[i]
		case '[':
			closer = ']'
		default:
			continue
		}
		b[i] = ' '
		for i++; i < len(b); i++ {
			if b[i] != closer {
				b[i] = ' '
				continue
			}
			if closer != ']' && i+1 < len(b) && b[i+1] == closer {
				b[i], b[i+1] = ' ', ' '
				i++ // an escaped delimiter; the loop's i++ steps past the second
				continue
			}
			b[i] = ' '
			break
		}
	}
	return string(b)
}

// blankSQLiteQuoted replaces every quoted/bracketed span in s (including its
// delimiters) with spaces, preserving byte length and the positions of the
// unquoted keywords. SQLite quotes identifiers with double quotes, brackets or
// backticks, and string literals with single quotes; a doubled delimiter inside
// any of the quoted forms is an escaped literal, not a close ([] has no escape —
// the first ] ends it).
func blankSQLiteQuoted(s string) string {
	b := []byte(s)
	i := 0
	for i < len(b) {
		var closer byte
		switch b[i] {
		case '"', '\'', '`':
			closer = b[i]
		case '[':
			closer = ']'
		default:
			i++
			continue
		}
		b[i] = ' '
		i++
		for i < len(b) {
			if b[i] == closer {
				if closer != ']' && i+1 < len(b) && b[i+1] == closer {
					b[i], b[i+1] = ' ', ' '
					i += 2
					continue
				}
				b[i] = ' '
				i++
				break
			}
			b[i] = ' '
			i++
		}
	}
	return string(b)
}

func (dialect) ListEvents(context.Context, *sql.DB, driver.Scope) ([]model.Event, error) {
	return nil, nil
}

func (dialect) ListUsers(context.Context, *sql.DB) ([]model.User, error) {
	return nil, nil
}
