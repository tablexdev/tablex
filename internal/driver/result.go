package driver

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ResultSet is an engine-neutral table of results, produced by scanning any
// *sql.Rows generically. It backs both the browse grid and the SQL console, so
// every engine's output renders through the same template path.
type ResultSet struct {
	Columns []ResultColumn
	Rows    [][]Value
	// Truncated is the AGGREGATE "rows were omitted" flag: set when the row cap
	// OR the byte budget stopped the scan short. Every consumer that asks "is
	// this the whole result?" reads this one flag, so both causes keep it
	// correct with no per-site change.
	Truncated bool
	// BudgetTruncated is the CAUSE discriminator, set only when the byte budget
	// (Pagination.ByteBudget) stopped the scan — the rows themselves were large,
	// not merely numerous. The browse banner reads it to choose its wording;
	// Truncated stays the flag everything else consults.
	BudgetTruncated bool
}

// ResultColumn is the metadata for one result column.
type ResultColumn struct {
	Name    string
	DBType  string // DatabaseTypeName(), e.g. "VARCHAR", "INT4", "BLOB"
	Numeric bool
	Binary  bool
}

// Value is one scanned cell. Null is rendered specially; Binary cells present a
// short placeholder in Str and carry the raw bytes (for hex export) only on the
// streaming path — buffered results drop them so a page of BLOBs cannot pin
// hundreds of megabytes.
type Value struct {
	Null   bool
	Binary bool
	// Numeric records that the driver returned this cell as a NATIVE numeric
	// Go value (int64/float64) — the value's runtime storage class, distinct
	// from the column's DECLARED type (ResultColumn.Numeric). A dialect with
	// per-value dynamic typing (DynamicTyper — SQLite) has the dump writers
	// trust this over the declared type; statically typed engines return
	// DECIMAL and out-of-range integers as text, so their bare-vs-quoted
	// decision must stay with the declared type.
	Numeric bool
	// Truncated records that Str is a PREFIX of the stored value — capCell cut
	// it at MaxCellBytes. A prefix is fine to DISPLAY but must never be treated
	// as the exact cell: rowKeyFor refuses to build an invertible row-identity
	// token from a truncated component (it would match a different row sharing
	// the prefix), the same fail-safe it already applies to a binary cell.
	Truncated bool
	Str       string
	Bytes     []byte // raw binary content; populated only by StreamResult
}

// String returns the textual form (empty for NULL).
func (v Value) String() string {
	if v.Null {
		return ""
	}
	return v.Str
}

const defaultRowCap = 100000 // hard safety cap on rows held in memory

// MaxCellBytes bounds how much of one text cell a DISPLAY result retains. It
// mirrors the []byte branch's existing 1 MiB heuristic, which never covered the
// string branch — and pgx returns PostgreSQL text/json as string, so those cells
// were entirely uncapped: one 100 MB `text` value, times a 500-row page, is an
// unbounded allocation driven purely by row content.
//
// Every display consumer renders at most a couple of hundred characters per cell
// (`truncate 200` in the browse and result grids), so 1 MiB is five thousand
// times more than any of them can show and the cap is never observable. The one
// consumer that needs the exact value — the row-edit prefill, which is submitted
// back as the new value — scans through ScanResultVerbatim instead, so a long
// TEXT column can never be truncated on save.
const MaxCellBytes = 1 << 20 // 1 MiB

// ScanResult reads up to limit rows from rows into a ResultSet, eliding text
// cells beyond MaxCellBytes. A limit <= 0 uses the default safety cap. The
// caller retains ownership of rows and must not have consumed them yet;
// ScanResult closes them.
func ScanResult(rows *sql.Rows, limit int) (*ResultSet, error) {
	return scanResult(rows, limit, MaxCellBytes, 0)
}

// ScanResultVerbatim is ScanResult with no per-cell size cap, for the one
// caller that must round-trip a cell rather than display it: the row-edit form,
// whose prefilled inputs are posted back as the row's new values. Everything
// else must use ScanResult.
func ScanResultVerbatim(rows *sql.Rows, limit int) (*ResultSet, error) {
	return scanResult(rows, limit, 0, 0)
}

// ScanResultBudget is ScanResult with an additional cumulative byte budget: it
// stops at a whole-ROW boundary once the retained text exceeds byteBudget (>0),
// always retaining at least one row so the grid is never empty. It sets both
// Truncated (the aggregate flag) and BudgetTruncated (the cause). Used only by
// Browse's "Show all", where the 20x row ceiling would otherwise let one page's
// retained text grow unbounded; the paginated and console paths stay unbudgeted.
func ScanResultBudget(rows *sql.Rows, limit, byteBudget int) (*ResultSet, error) {
	return scanResult(rows, limit, MaxCellBytes, byteBudget)
}

// scanResult is the shared implementation; cellCap <= 0 disables the per-cell
// cap and byteBudget <= 0 disables the cumulative row budget.
func scanResult(rows *sql.Rows, limit, cellCap, byteBudget int) (*ResultSet, error) {
	defer rows.Close()
	// defaultRowCap is an absolute ceiling on rows buffered in memory: a
	// non-positive limit means "use the cap", and any caller-supplied limit is
	// clamped down to it so no single request can exhaust memory.
	if limit <= 0 || limit > defaultRowCap {
		limit = defaultRowCap
	}

	columns, binaryCol, err := resultColumns(rows)
	if err != nil {
		return nil, err
	}
	rs := &ResultSet{Columns: columns}

	retained := 0 // cumulative retained text bytes, for byteBudget
	for rows.Next() {
		if len(rs.Rows) >= limit {
			rs.Truncated = true
			break
		}
		holders := make([]any, len(columns))
		for i := range holders {
			holders[i] = new(any)
		}
		if err := rows.Scan(holders...); err != nil {
			return nil, err
		}
		row := make([]Value, len(columns))
		rowBytes := 0
		for i := range holders {
			raw := *(holders[i].(*any))
			// keepBytes=false: buffered consumers (browse grid, console) only ever
			// render the placeholder, so retaining BLOB contents here would buffer
			// the entire page of binary data in memory for nothing.
			row[i] = formatValue(raw, binaryCol[i], rs.Columns[i].DBType, false)
			// A capped cell is a prefix of the stored value; flag it so the row
			// grid degrades its edit/delete actions rather than building a WHERE
			// from a truncated value. capCell only ever shortens, so a shorter
			// result is an exact truncation signal.
			full := row[i].Str
			row[i].Str = capCell(full, cellCap)
			if len(row[i].Str) < len(full) {
				row[i].Truncated = true
			}
			rowBytes += len(row[i].Str) + len(row[i].Bytes)
		}
		// Whole-row byte budget: stop BEFORE appending a row that would push the
		// retained text past byteBudget, so every retained cell stays byte-exact.
		// Always keep at least one row (the len check), even one larger than the
		// whole budget, so the grid is never empty.
		if byteBudget > 0 && len(rs.Rows) > 0 && retained+rowBytes > byteBudget {
			rs.Truncated = true
			rs.BudgetTruncated = true
			break
		}
		retained += rowBytes
		rs.Rows = append(rs.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rs, nil
}

// resultColumns builds the column metadata for a *sql.Rows.
func resultColumns(rows *sql.Rows) ([]ResultColumn, []bool, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, nil, err
	}
	out := make([]ResultColumn, len(cols))
	binaryCol := make([]bool, len(cols))
	for i := range cols {
		dbType := ""
		if i < len(types) {
			dbType = types[i].DatabaseTypeName()
		}
		binaryCol[i] = isBinaryDBType(dbType)
		out[i] = ResultColumn{
			Name: cols[i], DBType: dbType,
			Numeric: isNumericDBType(dbType), Binary: binaryCol[i],
		}
	}
	return out, binaryCol, nil
}

// StreamResult iterates rows one at a time, calling perRow for each, without
// buffering the whole result set — used by streaming export. It closes rows.
func StreamResult(rows *sql.Rows, perRow func(cols []ResultColumn, row []Value) error) error {
	defer rows.Close()
	cols, binaryCol, err := resultColumns(rows)
	if err != nil {
		return err
	}
	for rows.Next() {
		holders := make([]any, len(cols))
		for i := range holders {
			holders[i] = new(any)
		}
		if err := rows.Scan(holders...); err != nil {
			return err
		}
		row := make([]Value, len(cols))
		for i := range holders {
			// keepBytes=true: exporters need the real binary content for hex/X''
			// literals, and the streaming path holds only one row at a time.
			row[i] = formatValue(*(holders[i].(*any)), binaryCol[i], cols[i].DBType, true)
		}
		if err := perRow(cols, row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// formatValue converts a driver-native scanned value into a display Value. The
// column DB type drives temporal rendering (a DATETIME at midnight must not be
// collapsed to a date). keepBytes controls whether binary content is copied into
// Value.Bytes: only the streaming export path reads it, so buffered results pass
// false and keep just the placeholder.
func formatValue(raw any, binaryCol bool, dbType string, keepBytes bool) Value {
	switch v := raw.(type) {
	case nil:
		return Value{Null: true}
	case []byte:
		if binaryCol || !isPrintableUTF8(v) {
			val := Value{Binary: true, Str: fmt.Sprintf("[BLOB %s]", HumanBytesIEC(int64(len(v))))}
			if keepBytes {
				val.Bytes = append([]byte(nil), v...)
			}
			return val
		}
		return Value{Str: string(v)}
	case string:
		return Value{Str: v}
	case bool:
		if v {
			return Value{Str: "true"}
		}
		return Value{Str: "false"}
	case int64:
		return Value{Numeric: true, Str: strconv.FormatInt(v, 10)}
	case float64:
		return Value{Numeric: true, Str: strconv.FormatFloat(v, 'g', -1, 64)}
	case time.Time:
		return Value{Str: formatTime(v, dbType)}
	default:
		return Value{Str: fmt.Sprintf("%v", v)}
	}
}

// capCell trims a display cell to at most maxBytes bytes, backing up to a UTF-8
// rune boundary so the cut can never leave a half-rune the template would render
// as U+FFFD. maxBytes <= 0 disables the cap (ScanResultVerbatim).
//
// The prefix is CLONED rather than resliced: a Go substring shares its backing
// array, so s[:cut] would pin the whole oversized original for the lifetime of
// the ResultSet — exactly the retention the cap exists to prevent.
func capCell(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && cut > maxBytes-utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.Clone(s[:cut])
}

// formatTime renders a temporal value using the column type: DATE → date only,
// TIME → time only, everything else (DATETIME/TIMESTAMP/unknown) → full
// timestamp, preserving sub-second precision when present. Offset-bearing
// types (PostgreSQL TIMESTAMPTZ/TIMETZ) keep their UTC offset: a naive
// wall-clock rendering would be reinterpreted in the restore session's time
// zone, silently shifting every value.
func formatTime(t time.Time, dbType string) string {
	switch strings.ToUpper(strings.TrimSpace(dbType)) {
	case "DATE":
		return t.Format("2006-01-02")
	case "TIME":
		if t.Nanosecond() != 0 {
			return t.Format("15:04:05.999999999")
		}
		return t.Format("15:04:05")
	case "TIMESTAMPTZ":
		if t.Nanosecond() != 0 {
			return t.Format("2006-01-02 15:04:05.999999999-07:00")
		}
		return t.Format("2006-01-02 15:04:05-07:00")
	case "TIMETZ":
		if t.Nanosecond() != 0 {
			return t.Format("15:04:05.999999999-07:00")
		}
		return t.Format("15:04:05-07:00")
	}
	if t.Nanosecond() != 0 {
		return t.Format("2006-01-02 15:04:05.999999999")
	}
	return t.Format("2006-01-02 15:04:05")
}

// isNumericDBType reports whether a column's DB type is a plain number, which is
// exported as an *unquoted* SQL literal. It deliberately excludes types that are
// number-adjacent but not bare numerals — MONEY (carries a currency symbol/commas),
// BIT (a bit string), and INTERVAL — since emitting those unquoted produces an
// invalid dump.
func isNumericDBType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	// go-sql-driver reports unsigned integers with a leading "UNSIGNED " (e.g.
	// "UNSIGNED INT"); strip it so the base type is classified, not left unmatched.
	t = strings.TrimPrefix(t, "UNSIGNED ")
	switch t {
	case "INT", "INTEGER", "TINYINT", "SMALLINT", "MEDIUMINT", "BIGINT",
		"INT2", "INT4", "INT8", "SERIAL", "BIGSERIAL", "SMALLSERIAL",
		"DECIMAL", "NUMERIC", "DEC", "FIXED", "FLOAT", "DOUBLE", "REAL",
		"FLOAT4", "FLOAT8", "DOUBLE PRECISION", "YEAR":
		return true
	}
	// Driver-reported names sometimes carry a width/precision or unsigned suffix
	// ("INT(11)", "DECIMAL(10,2)", "INT UNSIGNED"). Accept a known numeric prefix
	// only when what follows is end-of-string, '(', a space, or digits running to
	// end-of-string — never a letter — so INTERVAL (starts with INT) and the
	// PostgreSQL range types (INT4RANGE, INT8MULTIRANGE: digits then letters) are
	// not misclassified, while SQLite declared types like INT64 (INTEGER
	// affinity) still are.
	for _, p := range []string{"INT", "DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL"} {
		if rest, ok := strings.CutPrefix(t, p); ok {
			if rest == "" || rest[0] == '(' || rest[0] == ' ' {
				return true
			}
			if rest[0] >= '0' && rest[0] <= '9' && strings.TrimLeft(rest, "0123456789") == "" {
				return true
			}
		}
	}
	return false
}

// isBinaryDBType classifies an arbitrary raw DB-type string (from
// rows.ColumnTypes) as binary. It is intentionally separate from the handlers'
// isBinaryColumn, which matches a normalized model.Column.BaseType exactly: this
// uppercases free-form type text and adds a substring fallback for vendor
// spellings (e.g. "LONG BLOB"). Different inputs — not merged.
func isBinaryDBType(t string) bool {
	t = strings.ToUpper(t)
	switch t {
	case "BLOB", "TINYBLOB", "MEDIUMBLOB", "LONGBLOB", "BYTEA",
		"BINARY", "VARBINARY", "IMAGE":
		return true
	}
	return strings.Contains(t, "BLOB") || strings.Contains(t, "BINARY")
}

// isPrintableUTF8 reports whether b looks like human-readable text rather than
// binary data. Used to decide whether a []byte cell (MySQL returns most text as
// bytes) should be shown verbatim or treated as a BLOB.
//
// The 1 MiB cap is a deliberate heuristic, not a correctness boundary: a TEXT/JSON
// cell larger than this is classified as binary, so it shows as "[BLOB …]" in the
// browse grid and dumps as a hex literal (X'…' / '\x…') rather than a quoted
// string. That still round-trips the bytes losslessly (and pgx never returns text
// as []byte, so PostgreSQL text is unaffected); the only cost is dump readability
// and a BLOB label in the UI for very large text values. Raising the cap for
// known-text DB types is possible future polish.
func isPrintableUTF8(b []byte) bool {
	if len(b) > 1<<20 {
		return false
	}
	if !utf8.Valid(b) {
		return false
	}
	nonPrint := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			nonPrint++
		}
	}
	return nonPrint == 0
}

// ExecResult is the engine-neutral outcome of a non-query statement.
type ExecResult struct {
	RowsAffected int64
}

// HumanBytesIEC formats a non-negative byte count using IEC units (B, KiB, MiB,
// …). It is the shared core; internal/view's HumanBytes wraps it with an
// em-dash guard for the negative "unknown" sentinel.
func HumanBytesIEC(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
