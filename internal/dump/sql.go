package dump

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// writeSchemaSection writes one schema's dump through the unified planner —
// the single-section entry, reached only through writeSQLDump, whose callers are
// the SQL-dump tests. Real view dumping runs through ViewDumper /
// Connection.DumpView, NOT here (the old "view-dump path" attribution was
// documentation drift). The named-schema banner survives for the single-schema
// case.
func writeSchemaSection(ctx context.Context, w io.Writer, conn *driver.Connection, schema string, plan *Plan, o Options) {
	sections := []Section{{schema, plan}}
	dbp, err := ResolveDB(ctx, conn, sections, o)
	if err != nil {
		// Unreachable for a preflighted caller (streamExport resolves before the
		// download commits); kept as a visible in-dump failure, never silence.
		fmt.Fprintf(w, "-- ERROR: %s\n", CommentSafe(err.Error()))
		return
	}
	WriteDB(ctx, w, conn, dbp, o)
}

// postDataRank orders the post-data phase. Lower runs first. The buckets: 0 the
// sequence setval (a matview consuming nextval must refresh against synced
// counters); 1 object creation (constraints, triggers, rules, indexes, events,
// owned-sequence linkage, staged defaults, policies); 2 metadata (comments,
// enable states, replica identity, sequence persistence); 3 matview REFRESH; 4
// RLS state, which must engage only after the data phase and every refresh
// (FORCE RLS subjects even the owner). An unranked kind defaults to the
// creation bucket.
func postDataRank(kind string) int {
	switch kind {
	case "sequence":
		return 0
	case "constraint", "trigger", "rule", "index", "event", "sequence-own", "staged-default", "policy":
		return 1
	case "replica-identity", "trigger-comment", "constraint-comment", "sequence-comment",
		"rule-comment", "trigger-state", "rule-state", "sequence-persistence":
		return 2
	case "refresh":
		return 3
	case "rls-state":
		return 4
	default:
		return 1
	}
}

// writeTableCreate emits one table's `-- Table:` banner and its CREATE DDL,
// terminated. Shared by the single-schema and cross-schema writers.
func writeTableCreate(w io.Writer, td tableDump) {
	fmt.Fprintf(w, "-- ----------------------------\n-- Table: %s\n-- ----------------------------\n", CommentSafe(td.scope.Table))
	ddl := strings.TrimRight(strings.TrimSpace(td.create), "\n")
	if !strings.HasSuffix(ddl, ";") {
		ddl += ";"
	}
	fmt.Fprintln(w, ddl)
	fmt.Fprintln(w)
}

// writeTableData streams one table's rows as extended multi-row INSERTs (one
// statement per ~512 KiB, so a per-row autocommit import is not pathologically
// slow). A stream failure is written as an in-dump comment and returned so the
// caller can add it to the trailing error summary. A table with no insertable
// columns (selectSQL == "") emits nothing. Shared by both SQL writers.
func writeTableData(ctx context.Context, w io.Writer, conn *driver.Connection, td tableDump) error {
	if td.excluded {
		// A row-filtered export that does not target this table. Its rows are
		// deliberately absent; a silent omission would read as an empty table.
		fmt.Fprintf(w, "-- Data: %s omitted (not covered by the selected-row filter)\n\n", CommentSafe(td.scope.Table))
		return nil
	}
	if td.selectSQL == "" {
		// L10: a zero-insertable-column table with rows — emit that many
		// all-defaults INSERTs (batched under the same budget) so its rows are not
		// silently lost. countSQL is empty for a table that genuinely has no data.
		if td.countSQL == "" {
			return nil
		}
		return writeDefaultRowData(ctx, w, conn, td)
	}
	fmt.Fprintf(w, "-- Data: %s\n", CommentSafe(td.scope.Table))
	prefix := "INSERT INTO " + td.qualified + " (" + td.insertCols + ")"
	if td.overriding {
		prefix += " OVERRIDING SYSTEM VALUE"
	}
	prefix += " VALUES "
	const insertBatchBudget = 512 << 10
	var batch strings.Builder
	rowsInBatch := 0
	flush := func() error {
		if rowsInBatch == 0 {
			return nil
		}
		batch.WriteString(";\n")
		_, err := io.WriteString(w, batch.String())
		batch.Reset()
		rowsInBatch = 0
		return err
	}
	err := conn.StreamArgs(ctx, td.selectSQL, td.args, func(cols []driver.ResultColumn, row []driver.Value) error {
		lits := make([]string, len(row))
		for i, v := range row {
			lits[i] = conn.ValueLiteral(cols[i], v)
		}
		if rowsInBatch == 0 {
			batch.WriteString(prefix)
		} else {
			batch.WriteString(",\n")
		}
		batch.WriteByte('(')
		batch.WriteString(strings.Join(lits, ", "))
		batch.WriteByte(')')
		rowsInBatch++
		if batch.Len() >= insertBatchBudget {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush() // emit the trailing partial batch
	}
	if err != nil {
		fmt.Fprintf(w, "-- data export error: %v\n", CommentSafe(err.Error()))
	}
	fmt.Fprintln(w)
	return err
}

// writeDefaultRowData handles the L10 zero-insertable-column case: it counts the
// table's rows and emits that many all-defaults INSERTs (batched under the same
// budget). A count failure becomes an in-dump comment and is returned, like a
// row-stream error.
func writeDefaultRowData(ctx context.Context, w io.Writer, conn *driver.Connection, td tableDump) error {
	var n int64
	if err := conn.DB().QueryRowContext(ctx, td.countSQL, td.args...).Scan(&n); err != nil {
		fmt.Fprintf(w, "-- data export error: %v\n", CommentSafe(err.Error()))
		return err
	}
	if n == 0 {
		return nil
	}
	fmt.Fprintf(w, "-- Data: %s (%d all-defaults row(s))\n", CommentSafe(td.scope.Table), n)
	stmt := conn.Dialect().InsertDefaultRowSQL(td.qualified)
	const insertBatchBudget = 512 << 10
	var batch strings.Builder
	for i := int64(0); i < n; i++ {
		batch.WriteString(stmt)
		batch.WriteString(";\n")
		if batch.Len() >= insertBatchBudget {
			if _, err := io.WriteString(w, batch.String()); err != nil {
				return err
			}
			batch.Reset()
		}
	}
	if batch.Len() > 0 {
		if _, err := io.WriteString(w, batch.String()); err != nil {
			return err
		}
	}
	fmt.Fprintln(w)
	return nil
}

// writeSQLDump writes one schema-less/section-less dump through the unified
// planner — a test seam whose only callers are the SQL-dump tests (real view
// dumping runs through ViewDumper / Connection.DumpView, not this; the old
// "single-view path" attribution was documentation drift). Callers with a real
// HTTP preflight resolve first via ResolveDB; here a (practically impossible for
// graph-less plans) resolution failure becomes a visible in-dump error rather
// than silence.
func writeSQLDump(ctx context.Context, w io.Writer, conn *driver.Connection, plan *Plan, o Options) {
	writeSchemaSection(ctx, w, conn, "", plan, o)
}

// WriteDB writes one database's resolved dump: schemas, warnings, teardown
// (post-data constraint drops + the reversed pre-data stream, so no DROP is
// blocked by a dependent in any schema), the topo-ordered pre-data stream, the
// data phase (a hard barrier), then post-data in postDataRank buckets with
// cross-schema matview REFRESHes topo-ordered by ViewEdges. Data-phase errors
// become in-dump comments plus a trailing summary; structure was preflighted
// (ResolveDB) and cannot fail here.
func WriteDB(ctx context.Context, w io.Writer, conn *driver.Connection, dbp *DBPlan, o Options) {
	d := conn.Dialect()
	sections := dbp.sections

	// 1. The single named-schema banner (cosmetic continuity with the historic
	//    per-schema writer), then hoisted CREATE SCHEMA + schema comments
	//    (structure-gated) so every namespace exists before any object.
	if len(sections) == 1 && sections[0].Schema != "" && sections[0].Schema != "public" {
		fmt.Fprintf(w, "\n-- ----------------------------\n-- Schema: %s\n-- ----------------------------\n", CommentSafe(sections[0].Schema))
	}
	if o.Structure {
		printed := false
		for _, sec := range sections {
			if sec.Schema != "" && sec.Schema != "public" {
				fmt.Fprintf(w, "CREATE SCHEMA IF NOT EXISTS %s;\n", d.QuoteIdent(sec.Schema))
				printed = true
			}
		}
		for _, sec := range sections {
			if sec.Plan.objects.SchemaComment != "" {
				name := sec.Schema
				if name == "" {
					name = "public"
				}
				fmt.Fprintf(w, "COMMENT ON SCHEMA %s IS %s;\n", d.QuoteIdent(name), d.QuoteString(sec.Plan.objects.SchemaComment))
				printed = true
			}
		}
		if printed {
			fmt.Fprintln(w)
		}
	}

	// 2. Warnings (all sections), CommentSafe so a hostile object name cannot
	//    smuggle an executable statement onto the next line.
	warned := false
	for _, sec := range sections {
		for _, warn := range sec.Plan.objects.Warnings {
			fmt.Fprintf(w, "-- WARNING: %s\n", CommentSafe(warn))
			warned = true
		}
	}
	if dbp.teardown != nil && o.Structure {
		for _, warn := range dbp.teardown.warnings {
			fmt.Fprintf(w, "-- WARNING: %s\n", CommentSafe(warn))
			warned = true
		}
	}
	if warned {
		fmt.Fprintln(w)
	}

	// The post-data scripts, assembled once and read by both emitters below: the
	// teardown's constraint drops (step 3) and the creates (step 6). extraPost is
	// filled during resolution, so it is already complete here.
	var postData []driver.DumpScript
	for _, sec := range sections {
		postData = append(postData, sec.Plan.objects.PostData...)
	}
	postData = append(postData, dbp.extraPost...)

	// 3. Teardown: the REVERSED pre-data stream drops dependents before their
	//    dependencies (views before tables, tables before the types/collations
	//    they use, sequences right after their tables). The post-data FK
	//    constraint drops are emitted just before the first DROP TABLE — a
	//    cyclic/cross-schema FK would otherwise block it. Routine drops are NOT
	//    part of teardown for engines that drop them inline before each CREATE
	//    (mysqldump parity, DumpScript.DropInline); PostgreSQL's DO ride here,
	//    ahead of the types their signatures name.
	//
	//    The teardown plan overrides individual drops where the restored catalog has a
	//    dependency cycle: a grouped multi-object DROP replaces its members'
	//    (emitted once, at the latest-created member's position), and a retained
	//    object's drop is omitted entirely with a warning above.
	//
	//    The constraint drops and step 6's creates read ONE list, assembled just
	//    above. They used to be assembled separately, and the teardown copy left
	//    out dbp.extraPost — reachable only for a validated CHECK or EXCLUDE
	//    constraint (stripConstraints is fed from DeferrableConstraints, whose
	//    query selects contype 'c'/'x' only; a stripped FK goes into its own
	//    section's PostData), and harmless either way because the constraint's
	//    own table's DROP TABLE removes it. Aligned anyway: two emitters that
	//    disagree about what "the post-data constraints" are is a defect waiting
	//    for the day one of them matters.
	if o.Structure && o.DropFirst {
		emitConstraintDrops := func() {
			for _, s := range postData {
				if s.Kind == "constraint" && s.Drop != "" {
					fmt.Fprintf(w, "%s;\n", s.Drop)
				}
			}
		}
		td := dbp.teardown
		// dropSQL returns the statement to emit for one item's own drop ("" =
		// none: retained, or covered by a group emitted at another position).
		dropSQL := func(it *predataItem, own string) string {
			if td == nil {
				return own
			}
			id := teardownID(it)
			if g, ok := td.grouped[id]; ok {
				return g
			}
			if td.omit[id] || td.covered[id] {
				return ""
			}
			return own
		}
		constraintsDone := false
		for i := len(dbp.preOrder) - 1; i >= 0; i-- {
			it := dbp.preOrder[i]
			switch {
			case it.table != nil:
				if it.table.create == "" {
					continue // a data-only leaf: the parent's drop covers it
				}
				stmt := dropSQL(it, "DROP TABLE IF EXISTS "+it.table.qualified)
				if stmt == "" {
					continue
				}
				if !constraintsDone {
					// A cyclic/cross-schema FK would block the first DROP TABLE.
					emitConstraintDrops()
					constraintsDone = true
				}
				fmt.Fprintf(w, "%s;\n", stmt)
			case it.finalOf != "" || it.script == nil:
				// A "-final" stage carries no drop of its own (its base does).
			case !it.script.DropInline && it.script.Drop != "":
				if stmt := dropSQL(it, it.script.Drop); stmt != "" {
					fmt.Fprintf(w, "%s;\n", stmt)
				}
			}
		}
		if !constraintsDone {
			emitConstraintDrops()
		}
		fmt.Fprintln(w)
	}

	// 4. Pre-data: the resolved topological stream.
	if o.Structure {
		for _, it := range dbp.preOrder {
			switch {
			case it.table != nil:
				if it.table.create == "" {
					continue // a data-only leaf: its DDL rides the tree's root
				}
				writeTableCreate(w, *it.table)
			case it.finalOf != "":
				for _, s := range it.bundle {
					writeDumpScript(w, s, false)
				}
			default:
				s := *it.script
				s.SQL = it.sqlText
				// Only a dialect that declares an inline drop emits one here
				// (mysqldump parity for routines); every other kind's drop already
				// ran in the reverse teardown.
				writeDumpScript(w, s, o.DropFirst && s.DropInline)
			}
		}
	}

	// 5. Data across all sections — the hard barrier between pre- and post-data.
	var dataErrs []string
	if o.Data {
		for _, sec := range sections {
			for _, td := range sec.Plan.tables {
				if err := writeTableData(ctx, w, conn, td); err != nil {
					dataErrs = append(dataErrs, fmt.Sprintf("%s: %v", td.scope.Table, err))
				}
			}
		}
	}

	// 6. Post-data: every section's scripts plus the resolver's deferred DDL,
	//    ordered by the global Kind rank (setval → creation → metadata → refresh
	//    → RLS state). Within the refresh rank, cross-schema matview chains are
	//    additionally topo-ordered via the DB-wide ViewEdges graph — a dependent
	//    matview in schema A must refresh after its source in schema B.
	refreshPos := refreshOrder(sections)
	sort.SliceStable(postData, func(i, j int) bool {
		ri, rj := postDataRank(postData[i].Kind), postDataRank(postData[j].Kind)
		if ri != rj {
			return ri < rj
		}
		if ri == 3 {
			return refreshPos(postData[i].Name) < refreshPos(postData[j].Name)
		}
		return false
	})
	for _, s := range postData {
		// A data-only dump still syncs sequences (setval, Kind "sequence") and
		// refreshes matviews (Kind "refresh") — their targets exist in the
		// destination. All other post-data is structure, including the sequence
		// OWNED BY linkage (Kind "sequence-own"), which is correctly dropped here.
		if !o.Structure && s.Kind != "sequence" && s.Kind != "refresh" {
			continue
		}
		// The symmetric gate — setval and REFRESH are DATA-state (pg_dump
		// carries both in its data section), so a structure-only dump skips
		// them: its matviews restore WITH NO DATA, and a REFRESH would run the
		// view query against empty base tables and mark the matview populated
		// with wrong (empty) contents.
		if !o.Data && (s.Kind == "sequence" || s.Kind == "refresh") {
			continue
		}
		// Constraint teardown already ran; trigger/index drops are no-ops right
		// after their tables were recreated. Objects living outside the table
		// graph (MySQL events) declare an inline drop, which rides along here.
		writeDumpScript(w, s, o.DropFirst && s.DropInline)
	}

	if len(dataErrs) > 0 {
		fmt.Fprintf(w, "\n-- WARNING: %d table(s) failed during data export:\n", len(dataErrs))
		for _, e := range dataErrs {
			fmt.Fprintf(w, "--   %s\n", CommentSafe(e))
		}
	}
}

// refreshOrder builds the rank-3 ordering function from the sections' DB-wide
// ViewEdges: a topological position per qualified relation (sources before
// dependents). A refresh script's Name is "refresh:<qualified>"; scripts
// without one (or relations outside the edge graph) share a stable sentinel so
// their collection order is preserved.
func refreshOrder(sections []Section) func(name string) int {
	seen := map[string]bool{}
	var names []string
	deps := map[string][]string{}
	for _, sec := range sections {
		for _, e := range sec.Plan.objects.ViewEdges {
			from, to := e[0], e[1]
			deps[from] = append(deps[from], to)
			for _, n := range [...]string{from, to} {
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
		}
	}
	if len(names) == 0 {
		return func(string) int { return 0 }
	}
	pos := make(map[string]int, len(names))
	for i, n := range driver.TopoOrder(names, deps) {
		pos[n] = i + 1
	}
	return func(name string) int {
		q, ok := strings.CutPrefix(name, "refresh:")
		if !ok {
			return len(pos) + 2 // not a graph-named refresh: stable tail
		}
		if p, ok := pos[q]; ok {
			return p
		}
		return len(pos) + 2
	}
}

// writeDumpScript emits one dump object: comment, disclosure markers,
// optional drop, creation-context guards, and the DDL — ';'-terminated,
// wrapped in mysql-client DELIMITER directives when the body itself contains
// semicolons, or framed as an opaque TableX frame when the body is
// binary-fetched raw bytes. Guards sit OUTSIDE the DELIMITER wrap, and their
// save variables use object-local @saved_* names (never the preamble's
// @OLD_*), so the postamble's final session restore stays intact.
func writeDumpScript(w io.Writer, s driver.DumpScript, withDrop bool) {
	if s.Comment != "" {
		fmt.Fprintf(w, "-- %s\n", CommentSafe(s.Comment))
	}
	for _, m := range s.Markers {
		// Pre-formatted, grammar-validated marker lines — emitted verbatim
		// (CommentSafe would corrupt the lossless field encoding).
		fmt.Fprintf(w, "%s\n", m)
	}
	if withDrop && s.Drop != "" {
		fmt.Fprintf(w, "%s;\n", s.Drop)
	}
	for _, p := range s.Pre {
		fmt.Fprintf(w, "%s;\n", p)
	}
	switch {
	case s.OpaqueFrame:
		// The body is emitted byte-exact — no trimming — between a frame
		// marker and a body-derived DELIMITER token on its own line, so
		// TableX's splitter replays it verbatim and external clients split on
		// a token that provably does not occur in the body.
		delim := driver.ChooseFrameDelimiter(s.SQL)
		fmt.Fprintf(w, "%s\nDELIMITER %s\n%s\n%s\nDELIMITER ;\n", driver.FormatFrameMarker(delim), delim, s.SQL, delim)
	case s.NeedsDelimiter:
		fmt.Fprintf(w, "DELIMITER $$\n%s$$\nDELIMITER ;\n", trimDumpSQL(s.SQL))
	default:
		fmt.Fprintf(w, "%s;\n", trimDumpSQL(s.SQL))
	}
	for _, p := range s.Post {
		fmt.Fprintf(w, "%s;\n", p)
	}
}

// trimDumpSQL normalizes a non-opaque dump statement: surrounding whitespace
// and any trailing ';' go, because the writer adds its own terminator.
func trimDumpSQL(sql string) string {
	return strings.TrimSuffix(strings.TrimSpace(sql), ";")
}

// WritePreamble pins the session state a restore needs; the matching
// WritePostamble restores it for sessions that outlive the script. What
// each engine pins lives with its Dumper (a non-Dumper dialect needs no
// session pinning).
func WritePreamble(w io.Writer, d driver.Dialect) {
	if du, ok := d.(driver.Dumper); ok {
		du.DumpPreamble(w)
	}
}

func WritePostamble(w io.Writer, d driver.Dialect) {
	if du, ok := d.(driver.Dumper); ok {
		du.DumpPostamble(w)
	}
}
