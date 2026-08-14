package dump

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// CSVNullSentinel is the textual marker a CSV cell carries for SQL NULL,
// distinguishing it from an empty string. It is the de-facto industry marker
// (MySQL LOAD DATA, PostgreSQL text COPY, Snowflake, Redshift, Hive all use
// \N). A literal value that begins with a backslash is escaped on export and
// un-escaped on import so it can never collide with the sentinel.
const CSVNullSentinel = `\N`

// escapeCSVCell protects a literal value that could otherwise be read back as
// the \N NULL sentinel: any value beginning with a backslash gets one extra
// leading backslash, which UnescapeCSVCell strips on import.
func escapeCSVCell(s string) string {
	if strings.HasPrefix(s, `\`) {
		return `\` + s
	}
	return s
}

// UnescapeCSVCell reverses escapeCSVCell. The exact \N sentinel is handled by
// the caller (→ NULL) before this; any remaining backslash-leading cell was
// escaped on export, so strip one leading backslash.
func UnescapeCSVCell(s string) string {
	if strings.HasPrefix(s, `\`) {
		return s[1:]
	}
	return s
}

// isBooleanResultColumn reports whether a result column is a SQL boolean (so a
// "true"/"false" value is emitted as a real JSON boolean). Only engines with a
// genuine boolean type (PostgreSQL BOOL) report it; MySQL booleans are TINYINT
// and stay numeric.
func isBooleanResultColumn(c driver.ResultColumn) bool {
	switch strings.ToUpper(strings.TrimSpace(c.DBType)) {
	case "BOOL", "BOOLEAN":
		return true
	}
	return false
}

// WriteCSV streams the given tables as CSV. Each table is emitted sequentially:
// a "# <table>" comment line, that table's header row, then its
// data rows, with a blank line separating consecutive tables.
//
// Cell values are written near-verbatim: binary as lowercase hex, NULL as the
// \N sentinel (so it is distinct from an empty string on re-import), and a
// literal value that begins with a backslash gets one escaping backslash. We
// deliberately do NOT neutralize "CSV formula injection" (cells beginning with
// = + - @ tab/CR that a spreadsheet may evaluate on open): the only safe
// neutralization mutates the data (prefixing a quote/tab), which would corrupt a
// faithful export and break TableX's own CSV re-import round-trip. The risk
// lives in the spreadsheet that opens the file, not in TableX; it is documented
// in docs/security.md so the operator can decide.
func WriteCSV(ctx context.Context, w io.Writer, conn *driver.Connection, plan []CSVTable) error {
	cw := csv.NewWriter(w)
	prevSchema, haveSchema := "", false
	for ti, td := range plan {
		// Flush buffered rows before writing the raw comment/separator lines so
		// they land in the right order relative to the csv.Writer's buffer.
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
		if ti > 0 {
			fmt.Fprintln(w)
		}
		// Label unambiguously: an identifier may legally contain '.', so a single
		// "schema.table" line would be ambiguous. Emit a separate "# schema:" line
		// (only when it changes) and a "# table:" line; schema-less engines keep the
		// simple "# <table>" form. All are '#'-comments the CSV importer skips.
		if td.scope.Schema != "" {
			if !haveSchema || td.scope.Schema != prevSchema {
				fmt.Fprintf(w, "# schema: %s\n", CommentSafe(td.scope.Schema))
				prevSchema, haveSchema = td.scope.Schema, true
			}
			fmt.Fprintf(w, "# table: %s\n", CommentSafe(td.scope.Table))
		} else {
			fmt.Fprintf(w, "# %s\n", CommentSafe(td.scope.Table))
		}
		if td.selectSQL == "" {
			// Nothing to stream. Two reasons, and the file must say WHICH: every
			// column is generated (only reachable in a multi-table export —
			// BuildCSVPlan makes the single-table case a rendered preflight
			// error), or a row filter that does not target this table. Either
			// way, name it instead of omitting the table silently.
			if td.skipNote != "" {
				fmt.Fprintf(w, "# %s\n", td.skipNote)
			} else {
				fmt.Fprintln(w, "# no exportable columns (every column is generated)")
			}
			continue
		}
		// The header comes from the preflighted plan, not lazily from the first
		// row: a zero-row table must still emit its header line, or the exported
		// CSV cannot be re-imported (the reader hits EOF looking for a header).
		if err := cw.Write(td.header); err != nil {
			return err
		}
		rowNum := 0
		err := conn.StreamArgs(ctx, td.selectSQL, td.args, func(cols []driver.ResultColumn, row []driver.Value) error {
			rowNum++
			rec := make([]string, len(row))
			for i, v := range row {
				cell, err := csvCell(cols[i].Name, rowNum, i < len(td.binaryCols) && td.binaryCols[i], v)
				if err != nil {
					return err
				}
				rec[i] = cell
			}
			return cw.Write(rec)
		})
		if err != nil {
			cw.Flush()
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvCell renders one CSV cell. Hexing is decided by the COLUMN's binary type
// (the exact predicate importCSV hex-decodes by), never by the value's Binary
// flag alone, so export and import can't disagree:
//
//   - binary column: always hex. When the engine returned a string instead of
//     bytes (SQLite's dynamic typing can store text in a BLOB-declared column:
//     Binary=false, Bytes=nil), hex the string's bytes — hexing the nil Bytes
//     would silently write "".
//   - text column whose value was classified binary (>1 MiB text or
//     NUL/control chars; MySQL returns text as []byte) but is valid UTF-8:
//     write it as text — it is perfectly representable in CSV, and v.Str only
//     holds the "[BLOB n B]" placeholder. formatValue never truncates
//     (keepBytes copies everything), so this is lossless.
//   - text column with genuinely non-UTF-8 bytes: a clear error. Hex would
//     re-import as literal hex text (silent corruption); only the SQL format
//     can round-trip these bytes.
func csvCell(colName string, rowNum int, binaryCol bool, v driver.Value) (string, error) {
	switch {
	case v.Null:
		return CSVNullSentinel, nil // distinguish NULL from an empty string
	case binaryCol:
		if v.Binary {
			return hex.EncodeToString(v.Bytes), nil
		}
		return hex.EncodeToString([]byte(v.Str)), nil
	case v.Binary:
		if utf8.Valid(v.Bytes) {
			return escapeCSVCell(string(v.Bytes)), nil
		}
		return "", fmt.Errorf("column %q, row %d: value is not valid UTF-8; export this table as SQL instead", colName, rowNum)
	default:
		return escapeCSVCell(v.Str), nil
	}
}

// CSVTable is one table's preflighted CSV state.
type CSVTable struct {
	scope     driver.TableRef
	selectSQL string   // explicit non-generated SELECT; "" => no exportable columns
	header    []string // non-generated column names, aligned 1:1 with the SELECT (written even for zero rows)
	// binaryCols[i] is whether the i-th streamed SELECT column is binary-typed,
	// by the exact predicate importCSV uses (isBinaryColumn on the introspected
	// model.Column). Export hex-encodes exactly these columns so the two sides
	// can never disagree — deciding per VALUE (v.Binary) would hex a text
	// column's non-UTF8 bytes that import then re-inserts as literal hex text.
	binaryCols []bool
	// args are the values bound by selectSQL — non-nil only under a row filter.
	args []any
	// skipNote replaces the default "every column is generated" explanation when
	// selectSQL is empty for a different reason (a row filter aimed elsewhere).
	skipNote string
}

// BuildCSVPlan resolves each table's exportable (non-generated) column list and
// SELECT up front, BEFORE the download headers go out, so a
// column-introspection failure is a clean rendered error instead of a corrupt,
// already-committed download. The all-generated degenerate case is a rendered
// preflight error for a single-table export; in a multi-table export the table
// is skipped with an explicit comment instead (WriteCSV), since failing the
// whole download over one degenerate table would lose every other table.
//
// Generated columns are excluded: a CSV whose header carries one is unimportable
// by construction (importCSV refuses generated headers), so an explicit
// non-generated column list is used instead of SELECT *. (JSON keeps all columns
// — it is export-only, so the importability rationale does not apply and dropping
// generated values would be silent loss.)
func BuildCSVPlan(ctx context.Context, conn *driver.Connection, tables []driver.TableRef, filter *RowFilter, rng *RowRange) ([]CSVTable, error) {
	d := conn.Dialect()
	// Bulk prefetch per distinct schema (the flat list may span several PG
	// schemas, and bulk maps are keyed by bare table name — one shared map
	// would collide same-named tables across schemas). A nil entry means the
	// engine has no bulk support (or it failed): fall back per table.
	bulkBySchema := map[string]map[string][]model.Column{}
	if len(tables) > 1 {
		perSchema := map[string]int{}
		for _, t := range tables {
			perSchema[t.Schema]++
		}
		for _, t := range tables {
			// A schema contributing a single table gains nothing from a bulk
			// whole-schema scan — the per-table Columns fallback is one query too.
			if _, seen := bulkBySchema[t.Schema]; !seen && perSchema[t.Schema] > 1 {
				bulkBySchema[t.Schema] = bulkColumnsOrNil(ctx, conn, scopeOf(t))
			}
		}
	}
	plan := make([]CSVTable, 0, len(tables))
	for _, t := range tables {
		cols, ok := bulkBySchema[t.Schema][t.Table]
		if !ok {
			var err error
			cols, err = conn.Columns(ctx, t)
			if err != nil {
				return nil, fmt.Errorf("columns of %s: %w", t.Table, err)
			}
		}
		quoted := quotedInsertableCols(d, cols)
		td := CSVTable{scope: t}
		where, args, allowed := filter.clauseFor(t)
		td.args = args
		// Same insertableColumns filter as quotedInsertableCols, so binaryCols and
		// header align 1:1 with the streamed SELECT columns (a generated column
		// before a binary one must not shift the indexes).
		for _, c := range insertableColumns(cols) {
			td.binaryCols = append(td.binaryCols, IsBinaryColumn(c))
			td.header = append(td.header, c.Name)
		}
		switch {
		case !allowed:
			// A row filter aimed at another table: this one contributes a labelled
			// comment and nothing else. Dumping it in full would hand back rows the
			// user never selected, and omitting it silently would read as empty.
			td.skipNote = "no rows: not covered by the selected-row filter"
		case len(quoted) > 0:
			td.selectSQL = "SELECT " + strings.Join(quoted, ", ") + " FROM " + conn.QualifiedName(t) + where + rng.clauseFor(d)
		case len(tables) == 1:
			// A single-table all-generated export would download nothing usable;
			// fail before the headers go out. Multi-table exports keep the other
			// tables and mark this one with a comment (WriteCSV).
			return nil, fmt.Errorf("table %s has no exportable columns (every column is generated); use the SQL or JSON format instead", t.Table)
		}
		plan = append(plan, td)
	}
	return plan, nil
}

// IsBinaryColumn reports whether the column holds raw binary bytes (CSV/JSON
// export emits these as lowercase hex; CSV import hex-decodes them). The CSV importer consults it too — edit-form binary cells are read-only, so coerceValue
// never sees them.
//
// It is deliberately kept separate from driver.isBinaryDBType (NOT merged):
// this works on the normalized model.Column.BaseType (exact match), while the
// driver helper uppercases an arbitrary raw DB-type string and adds a
// Contains("BLOB"/"BINARY") substring fallback this one doesn't need. Different
// inputs, different matching — a single Column-only method couldn't serve the
// driver's raw-string caller.
func IsBinaryColumn(c model.Column) bool {
	switch c.BaseType {
	case "blob", "tinyblob", "mediumblob", "longblob", "bytea",
		"binary", "varbinary", "image":
		return true
	}
	return false
}
