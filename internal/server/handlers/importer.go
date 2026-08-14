package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/dump"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/sqlscript"
)

type importBody struct {
	Scope   reqScope
	Level   string // db | table
	PostURL string
	IsTable bool
	Ran     bool
	Summary *importSummary
}

// importSummary is the aggregate outcome shown after an import (CSV or SQL). It
// holds O(1) state regardless of statement/row count — a large single-row-INSERT
// import would otherwise buffer a full-SQL per-statement result and render a
// tens-of-MB page. Failed drives the tx-alert-error vs tx-alert-success class.
type importSummary struct {
	Message string
	Failed  bool
	Detail  string // failing statement, when known
	// Warnings is a bounded sample of best-effort advisories (db-collation
	// marker mismatches); WarningCount is the exact total, which may exceed
	// the sample — the O(1)-result invariant caps what is retained, never
	// what is counted.
	Warnings     []string
	WarningCount int
}

// maxImportWarningSamples bounds how many warning texts an import retains;
// the count keeps running past it (the O(1)-result invariant).
const maxImportWarningSamples = 5

// importResult accumulates a restore script's running totals across sections.
type importResult struct {
	Statements int
	Affected   int64
	Failed     bool
	Error      string
	ErrorSQL   string
	// Warning aggregation: exact total plus a fixed sample of the first few.
	WarningCount   int
	WarningSamples []string
}

// addWarning records one best-effort advisory, retaining at most
// maxImportWarningSamples texts while counting all of them.
func (res *importResult) addWarning(msg string) {
	res.WarningCount++
	if len(res.WarningSamples) < maxImportWarningSamples {
		res.WarningSamples = append(res.WarningSamples, msg)
	}
}

// MaxImportBytes caps an import upload. The server package's route-aware
// limitBody applies this same cap to import routes *before* CSRF parses the
// multipart body, so the cap holds even on the no-JS path (token in the form
// field, not a header) where csrf would otherwise parse the whole body under the
// looser global limit first.
const MaxImportBytes = 32 << 20 // 32 MiB

// ServerImport / DBImport / TableImport: GET renders the form, POST runs the SQL
// script (and, for tables, CSV import). Server scope runs the script against the
// server connection (so CREATE DATABASE / USE work).
func (h *Handlers) ServerImport(w http.ResponseWriter, r *http.Request) { h.importer(w, r, "server") }
func (h *Handlers) DBImport(w http.ResponseWriter, r *http.Request)     { h.importer(w, r, "db") }
func (h *Handlers) TableImport(w http.ResponseWriter, r *http.Request)  { h.importer(w, r, "table") }

func (h *Handlers) importer(w http.ResponseWriter, r *http.Request, level string) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	// The table-scoped importer's CSV path builds INSERT INTO on the scoped
	// table, so a view (or sequence) is rejected server-side here — hiding the
	// Import tab alone would leave the registered route writable. DB/server-level
	// import is unaffected (no table scope).
	if level == "table" && !h.requireWritableTable(w, r, conn, sc) {
		return
	}

	postURL, title, tabs := h.levelChrome(r.Context(), uc, sc, level, "import", "Import", conn)
	body := importBody{Scope: sc, Level: level, PostURL: postURL, IsTable: level == "table"}

	if r.Method == http.MethodPost {
		// Cap the upload body before parsing so a multipart form can't spill an
		// unbounded amount to temp files.
		r.Body = http.MaxBytesReader(w, r.Body, MaxImportBytes)
		// BoundedParseForm picks the parser by content-type: multipart goes
		// through ParseMultipartForm (whose argument is the in-memory spill
		// threshold, NOT a size cap — the cap is the MaxBytesReader above and
		// limitBody upstream), everything else through ParseForm. Calling
		// ParseMultipartForm unconditionally and filtering ErrNotMultipart —
		// the previous shape — swallowed the size error on a urlencoded body:
		// Go returns ErrNotMultipart INSTEAD of the ParseForm error it hit
		// first, so an over-cap no-JS import with a header token rendered an
		// empty import page at 200 instead of this 413. On the htmx path the
		// CSRF token rides a header, so this is the FIRST parse and no earlier
		// bounded parse has spilled it.
		if err := BoundedParseForm(r); err != nil {
			if bodyTooLarge(err) {
				h.renderError(w, r, http.StatusRequestEntityTooLarge, "Upload too large.", "")
				return
			}
			h.renderError(w, r, http.StatusBadRequest, "Upload too large or invalid.", "")
			return
		}
		content, filename, err := readImportSource(r)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, "Could not read the upload: "+err.Error(), "")
			return
		}
		format := r.PostFormValue("format")
		if format == "" {
			format = importFormatFromName(filename)
		}
		if level == "table" && format == "csv" {
			n, err := h.importCSV(r, conn, sc, content)
			if err != nil {
				body.Summary = &importSummary{Failed: true, Message: "CSV import failed: " + err.Error()}
			} else {
				body.Summary = &importSummary{Message: fmt.Sprintf("Imported %d row(s) from CSV.", n)}
			}
			body.Ran = true
		} else {
			script := strings.TrimSpace(content)
			if script != "" {
				// The restore runs on pinned connections (one per \connect
				// section), which are private and sit outside PoolBudget; reserve
				// an in-flight slot so parallel imports cannot exhaust the
				// database's max_connections.
				release, ok := h.acquireDBOp(w, r)
				if !ok {
					return
				}
				defer release()
				// \connect sections exist only in dumps whose framer declares
				// UsesConnectMarkers (TableX's own PostgreSQL server-scope
				// dumps) — the same flag the export side frames with. A db- or
				// table-scoped import must never switch databases (a scope
				// violation), so the import level gates recognition together
				// with the dialect flag; this is the only place that knows the
				// level.
				allowConnect := false
				if f, ok := uc.Dialect().(driver.ServerDumpFramer); ok {
					allowConnect = f.ServerDumpProfile().UsesConnectMarkers && level == "server"
				}
				res := h.runRestoreScript(r.Context(), uc, sc.DB, script, allowConnect)
				body.Summary = summarizeImport(res)
				body.Ran = true
			} else {
				// Empty submission (no file, blank textarea): the CSV path
				// above always sets a summary, so match it rather than
				// re-rendering the form with no feedback at all.
				body.Summary = &importSummary{Failed: true, Message: "Nothing to import — choose a file or paste a script."}
				body.Ran = true
			}
		}
	}

	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = tabs
	p.NeedsEditor = true // this page carries a textarea.tx-sql-editor
	p.Body = body
	h.render(w, r, "import", p)
}

// runRestoreScript executes a (possibly multi-database) SQL script. Sections
// delimited by psql-style \connect markers — which TableX's own PostgreSQL
// server-scope dumps emit — each run on a dedicated pinned connection bound to
// that database, never the shared pools, so session preambles apply per
// database exactly as they would under psql. Markers are honored only when
// allowConnect (PostgreSQL server-scope imports); otherwise — and for a script
// without markers — the whole script is a single section against db (the
// import target), which also gives every import the pinned-connection
// semantics (preamble SETs stick to the script and die with it).
func (h *Handlers) runRestoreScript(ctx context.Context, uc *UserContext, db, script string, allowConnect bool) importResult {
	var res importResult
	max := h.Cfg.MaxScriptStatements
	sections, err := sqlscript.SplitRestoreSections(script, allowConnect, max)
	if err != nil {
		res.Failed = true
		res.Error = h.scriptTooLong(err).Error
		return res
	}
	// PREFLIGHT the whole script before opening a connection. A per-section cap
	// is not enough: the loop below executes each section as it goes and breaks
	// only on failure, so an over-limit section 3 would abort AFTER sections 1
	// and 2 had already run and committed — a half-applied restore, which is the
	// outcome the cap exists to avoid rather than cause. The aggregate is what
	// the memory bound is about anyway: the sections are lexed into one process.
	// EventBudget carries ONE event-counted cap across the sections — a local
	// remaining counter used to disable itself when a section landed exactly on
	// the boundary (SplitLimit reads 0 as "no cap") and undercounted scripts
	// whose events include markers.
	if max > 0 {
		budget := sqlscript.NewEventBudget(max)
		for _, sec := range sections {
			if err := budget.Consume(sec.Script, driver.ProfileOf(uc.Dialect())); err != nil {
				res.Failed = true
				res.Error = h.scriptTooLong(err).Error
				return res
			}
		}
	}
	for _, sec := range sections {
		target := sec.DB
		if target == "" {
			target = db
		}
		h.runRestoreSection(ctx, uc, target, sec.Script, &res)
		if res.Failed {
			break // stop-at-first-error, matching single-section behavior
		}
	}
	return res
}

// runRestoreSection runs one restore section on a dedicated pinned connection,
// accumulating running totals into res (never a per-statement slice, so a huge
// import stays O(1) in memory). The pinned connection is closed via defer so a
// panic mid-section cannot leak it, and per-section close keeps defers from
// piling up across a many-section restore.
//
// TableX db-collation markers in the script are verified at their position in
// the stream: a read-only lookup on the same pinned connection (the dialect's
// CollationProbeSQL — position matters, because a MySQL server-scope dump
// switches databases via executable USE) compares the recorded source
// collation with the target database's, and a difference becomes a bounded
// warning. Warnings are best-effort by design: a failed lookup degrades to a
// "could not verify" note, no marker-supplied SQL is ever executed, and the
// target database is never altered.
func (h *Handlers) runRestoreSection(ctx context.Context, uc *UserContext, target, script string, res *importResult) {
	pinned, err := uc.PinnedFor(ctx, target)
	if err != nil {
		res.Failed = true
		// A failed dial (unlike a statement error) may echo the DSN; redact it
		// before it lands on the import-result page.
		res.Error = uc.redactErr(err)
		res.ErrorSQL = `\connect ` + target
		return
	}
	defer pinned.Close()
	// The preflight in runRestoreScript already refused an over-limit script, so
	// this cap is the backstop for the single-section path that skips it.
	if _, err := forEachStatement(ctx, pinned, script, h.Cfg.MaxScriptStatements, h.budgeted(uc, execConsoleStatement), func(r consoleResult) {
		res.Statements++
		res.Affected += r.Affected
		if r.Error != "" {
			res.Failed = true
			res.Error = r.Error
			res.ErrorSQL = r.SQL
		}
	}, func(m driver.DumpMarker) {
		verifyCollationMarker(ctx, pinned, m, res)
	}); err != nil {
		res.Failed = true
		res.Error = h.scriptTooLong(err).Error
	}
}

// verifyCollationMarker checks one db-collation disclosure marker against the
// pinned session's current database (bounded read-only lookup, dialect-gated
// via driver.CollationProber — engines whose dumps carry no markers skip it).
func verifyCollationMarker(ctx context.Context, conn scriptConn, m driver.DumpMarker, res *importResult) {
	prober, ok := conn.Dialect().(driver.CollationProber)
	if !ok {
		return
	}
	rs, err := conn.Query(ctx, prober.CollationProbeSQL(), 1)
	if err != nil || len(rs.Rows) != 1 || len(rs.Rows[0]) < 2 {
		detail := "no result"
		if err != nil {
			detail = err.Error()
		}
		res.addWarning(fmt.Sprintf("could not verify database collation for %s %q: %s", m.Kind, m.Name, detail))
		return
	}
	dbName, target := rs.Rows[0][0].String(), rs.Rows[0][1].String()
	if target != "" && target != m.Collation {
		res.addWarning(fmt.Sprintf(
			"%s %q was dumped from a database with collation %s; target database %q uses %s (charset-typed declarations without an explicit collation resolve under the target's)",
			m.Kind, m.Name, m.Collation, dbName, target))
	}
}

// summarizeImport formats a restore result's aggregate totals into the summary
// the template renders — a single alert (plus a bounded warning alert), never
// a per-statement list.
func summarizeImport(res importResult) *importSummary {
	s := &importSummary{
		Warnings:     res.WarningSamples,
		WarningCount: res.WarningCount,
	}
	if res.Failed {
		s.Failed = true
		s.Message = fmt.Sprintf("Import failed after %d statement(s): %s", res.Statements, res.Error)
		s.Detail = res.ErrorSQL
		return s
	}
	s.Message = fmt.Sprintf("Import complete: %d statement(s) executed, %d row(s) affected.", res.Statements, res.Affected)
	return s
}

// readImportSource returns the uploaded file content (preferred) or the pasted
// script, plus the filename when uploaded. A genuine mid-read I/O failure is
// returned rather than swallowed, so a truncated upload is surfaced instead of
// silently executing a partial script/CSV. (The size cap is enforced separately
// by MaxBytesReader, not here.)
func readImportSource(r *http.Request) (content, filename string, err error) {
	if f, hdr, ferr := r.FormFile("file"); ferr == nil {
		defer f.Close()
		b, rerr := io.ReadAll(io.LimitReader(f, MaxImportBytes))
		if rerr != nil {
			return "", hdr.Filename, fmt.Errorf("reading uploaded file: %w", rerr)
		}
		// Decompress before the BOM strip: a gzipped export's BOM (if any) is
		// inside the compressed stream, not in front of it.
		b, rerr = gunzipIfCompressed(b)
		if rerr != nil {
			return "", hdr.Filename, rerr
		}
		return stripBOM(string(b)), hdr.Filename, nil
	}
	// A pasted script is text the user typed; it cannot be a gzip stream.
	return stripBOM(r.PostFormValue("sql_script")), "", nil
}

// MaxImportExpandedBytes bounds a compressed upload AFTER decompression. The
// upload cap is not itself a bound on the work: gzip's ratio is unbounded in
// principle, so 32 MiB of well-chosen input expands to many gigabytes — the
// classic decompression bomb — and the importer holds the whole script in
// memory. This constant is therefore a memory budget, not a formality.
//
// It is deliberately larger than MaxImportBytes: a compressed upload that could
// only expand to its own uploaded size would make the option pointless, since
// the whole reason to gzip a dump is that it is much bigger than the wire.
const MaxImportExpandedBytes = 4 * MaxImportBytes

// gunzipIfCompressed decompresses an upload that begins with the gzip magic
// number, and returns anything else untouched — so the format stays sniffed from
// the bytes rather than trusted from the filename.
//
// The size guard reads ONE BYTE PAST the cap and refuses if it arrives. It
// deliberately does not consult the gzip trailer's ISIZE: that field is written
// by whoever built the file, and it records the size modulo 2^32, so a bomb can
// both lie about it and wrap around it.
func gunzipIfCompressed(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("the upload looks gzip-compressed but could not be opened: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, MaxImportExpandedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompressing the upload: %w", err)
	}
	if len(out) > MaxImportExpandedBytes {
		return nil, fmt.Errorf("the upload expands to more than %d MiB; import it uncompressed, or split it into smaller files",
			MaxImportExpandedBytes>>20)
	}
	return out, nil
}

// importFormatFromName picks the import format from a filename, seeing through a
// .gz suffix — "orders.csv.gz" is a CSV, and without this it would fall through
// to the SQL path and fail on the header row.
func importFormatFromName(filename string) string {
	name := strings.ToLower(filename)
	name = strings.TrimSuffix(name, ".gz")
	if strings.HasSuffix(name, ".csv") {
		return "csv"
	}
	return "sql"
}

// skipLeadingCSVComments drops leading '#'-comment lines (TableX's own CSV export
// emits "# schema:" / "# table:" / "# <table>" labels before the header). Only
// leading comment lines are stripped, so a data row whose first cell begins with
// '#' is preserved — unlike csv.Reader.Comment, which would drop it.
func skipLeadingCSVComments(content string) string {
	for {
		line, rest, found := strings.Cut(content, "\n")
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return content
		}
		if !found {
			return "" // nothing but comments
		}
		content = rest
	}
}

// stripBOM removes a leading UTF-8 byte-order mark. Excel and many Windows tools
// prepend one to CSV/SQL exports; left in place it breaks header-to-column
// matching (TrimSpace does not strip U+FEFF) and is meaningless in a SQL script.
func stripBOM(s string) string {
	if len(s) >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		return s[3:]
	}
	return s
}

// decodeHexCell decodes a CSV binary cell — lowercase hex as exportCSV emits,
// tolerating an optional 0x / \x prefix from other tools — into raw bytes.
// Invalid hex is a (row-numbered, by the caller) error rather than a silent
// text insert that would corrupt the column.
func decodeHexCell(s string) ([]byte, error) {
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"),
		strings.HasPrefix(s, `\x`), strings.HasPrefix(s, `\X`):
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in binary column: %w", err)
	}
	return b, nil
}

// importCSV loads CSV rows into the table, mapping header columns to validated
// table columns and binding values as parameters (never concatenated).
func (h *Handlers) importCSV(r *http.Request, conn *driver.Connection, sc reqScope, content string) (int, error) {
	cols, err := conn.Columns(r.Context(), sc.tableRef())
	if err != nil {
		return 0, err
	}
	byName := colSet(cols)
	// Skip leading '#'-comment lines so TableX's own CSV export (whose first lines
	// are "# schema:" / "# table:" / "# <table>" labels) round-trips: without this
	// the comment line is read as the header. Only LEADING comments are stripped;
	// csv.Reader.Comment is deliberately NOT used because it would also drop a data
	// row whose first cell begins with '#'.
	cr := csv.NewReader(strings.NewReader(skipLeadingCSVComments(content)))
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return 0, fmt.Errorf("reading header: %w", err)
	}
	// Validate headers map to real, writable, distinct columns. A duplicate
	// header would otherwise build INSERT INTO t (id, id, …) and surface a
	// low-signal engine error.
	seen := make(map[string]bool, len(header))
	for _, hname := range header {
		name := strings.TrimSpace(hname)
		col, ok := byName[name]
		if !ok {
			return 0, fmt.Errorf("CSV column %q does not exist in the table", hname)
		}
		if col.IsGenerated {
			return 0, fmt.Errorf("CSV column %q is a generated column and cannot be imported into", hname)
		}
		if seen[name] {
			return 0, fmt.Errorf("duplicate CSV column %q", hname)
		}
		seen[name] = true
	}
	d := conn.Dialect()
	qualified := conn.QualifiedName(sc.tableRef())

	// The statement shape is fixed by the header (short rows bind NULL for the
	// missing trailing fields, so the placeholder count never varies): build the
	// INSERT once and prepare it on the transaction, instead of re-parsing and
	// re-planning the same SQL for every row of the file.
	sb := newSQLBuilder(d)
	sb.raw("INSERT INTO ")
	sb.raw(qualified)
	sb.raw(" (")
	for i, hname := range header {
		if i > 0 {
			sb.raw(", ")
		}
		sb.ident(strings.TrimSpace(hname))
	}
	sb.raw(") VALUES (")
	for i := range header {
		if i > 0 {
			sb.raw(", ")
		}
		sb.param(nil) // placeholder only; real values bind per row below
	}
	sb.raw(")")

	// Observed, so the import's INSERT reaches the audit trail — as ONE
	// aggregate event with the summed row count (per-row events would bury
	// the trail), the SQL text only, never the bound cell values.
	tx, err := conn.BeginObserved(r.Context())
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(r.Context(), sb.String())
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	args := make([]any, len(header))
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("row %d: %w", count+1, err)
		}
		for i := range header {
			// A short row binds NULL for the missing trailing fields rather than an
			// empty string; extra fields beyond the header are ignored.
			if i >= len(rec) {
				args[i] = nil
				continue
			}
			col := byName[strings.TrimSpace(header[i])]
			cell := rec[i]
			switch {
			case cell == dump.CSVNullSentinel:
				args[i] = nil // \N round-trips to NULL (before binary decode, so a
				//                NULL binary cell stays NULL, not an empty blob)
			case dump.IsBinaryColumn(col):
				// export emits lowercase hex; bind raw bytes, not the hex text.
				b, err := decodeHexCell(cell)
				if err != nil {
					return count, fmt.Errorf("row %d, column %q: %w", count+1, header[i], err)
				}
				args[i] = b
			default:
				val := dump.UnescapeCSVCell(cell)
				// A foreign CSV's empty cell in a numeric/temporal/boolean column
				// cannot bind as the string "" (strict engines reject it; non-strict
				// MySQL silently inserts 0). Bind SQL NULL when the column is
				// nullable; a NOT NULL column keeps today's visible engine error (a
				// bound NULL can never fall back to a DEFAULT — the prepared INSERT
				// names every header column). Text columns keep "" (a valid value);
				// \N is the explicit NULL sentinel handled above.
				if val == "" && col.Nullable && blankToNullType(col) {
					args[i] = nil
				} else {
					args[i] = coerceValue(col, val)
				}
			}
		}
		if _, err := stmt.Exec(r.Context(), args...); err != nil {
			return count, fmt.Errorf("row %d: %w", count+1, err)
		}
		count++
	}
	if err := tx.Commit(); err != nil {
		return count, err
	}
	return count, nil
}

// blankToNullType reports whether an empty CSV cell in a column of this type
// family should bind SQL NULL (when the column is nullable) rather than the
// string "": numeric, temporal and boolean columns reject "" on strict engines,
// so an empty cell in a foreign CSV would hard-fail. Text and binary columns are
// excluded — an empty string / empty blob is a valid value there — and the \N
// sentinel remains the explicit NULL marker for round-tripped exports.
func blankToNullType(c model.Column) bool {
	if c.IsNumeric() {
		return true
	}
	switch c.BaseType {
	case "bool", "boolean",
		"date", "time", "datetime", "timestamp", "timestamptz", "year",
		"timestamp with time zone", "timestamp without time zone",
		"time with time zone", "time without time zone", "interval":
		return true
	}
	return false
}
