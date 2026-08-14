package driver

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

// DumpScript is one self-contained piece of dump DDL. SQL holds one complete
// statement (or, for multi-statement bodies, a script) WITHOUT a trailing
// terminator — the exporter appends ';' or wraps in DELIMITER directives.
type DumpScript struct {
	// Kind classifies the object: "routine", "view", "matview", "trigger",
	// "event", "index", "constraint", "sequence", "sequence-def",
	// "sequence-own", "refresh". The exporter uses it for teardown ordering
	// (constraints drop before tables) and to keep the data-section items
	// (setval "sequence" / matview "refresh") in data-only dumps while dropping
	// structure-only items ("sequence-def" CREATE SEQUENCE lives in DumpPlan.
	// Sequences; "sequence-own" ALTER SEQUENCE … OWNED BY is post-data structure).
	Kind           string
	Comment        string // short human label for the dump ("Trigger trg_audit")
	Drop           string // optional teardown statement (DROP ... IF EXISTS), emitted when the user asked to drop first
	SQL            string
	NeedsDelimiter bool // MySQL routine/trigger/event body: internal ';' needs DELIMITER wrapping

	// DropInline marks an object whose Drop is emitted INLINE, immediately
	// before its own CREATE (mysqldump parity for routines and events), instead
	// of in the reverse-ordered teardown block. PostgreSQL leaves it false for
	// every class: a routine's drop must precede the DROP TYPE of a type in its
	// signature, which only the reverse teardown order guarantees.
	DropInline bool
	// StageOf, on a script that is one CREATION STAGE of a larger logical object
	// (a shell type and the CREATE that completes it), is that object's
	// canonical node id. Creation ordering uses the per-stage Name — the whole
	// point of staging is that the stages sort separately — but TEARDOWN
	// collapses them back onto this id: the RESTORED catalog holds one object
	// whose dependencies close the very cycle staging broke, so the drop graph
	// must see it as one node.
	StageOf string
	// DropForm describes how this object's Drop may be merged into a
	// multi-object DROP — the only non-CASCADE way to drop a dependency cycle
	// (see DropForm). Zero value: ungroupable.
	DropForm DropForm

	// Name is this script's node id in the dump dependency graph:
	// "<catalog-kind>:<qualified name>[(identity args)]" — e.g.
	// "type:public.mood", "relation:public.emp", "routine:public.f(integer)".
	// Identity arguments / operand types / access method are part of the id so
	// overloads and cross-type members never collapse. A staged object's later
	// stage appends "-final" ("type-final:…", "routine…-final"). Empty means the
	// script takes no part in graph ordering (MySQL/SQLite plans) and keeps its
	// stable class-priority position.
	Name string
	// DependsOn lists node ids this script requires created first. An id
	// missing from the emitted set is a BOUNDARY edge (a reference to an
	// out-of-scope object): the topological sort ignores it and the planner
	// surfaces it as a restore-prerequisite diagnostic, never a failure.
	DependsOn []string
	// Clauses are deferrable trailing clauses (a domain's DEFAULT / CHECK):
	// normally each Text is appended to SQL in order, but when a clause's Deps
	// close a dependency cycle the planner CUTS it — the clause text is omitted
	// and its Finalize scripts (ALTER … SET DEFAULT / ADD CONSTRAINT, plus any
	// moved COMMENT) run later in the lane PreData selects.
	Clauses []DumpClause
	// Stub, when non-empty, is a dependency-reduced replacement create for a
	// routine caught in a dependency cycle: the same signature with every
	// argument default omitted (the whole trailing default group — a partial
	// omission would be invalid DDL) and an unchecked placeholder body
	// (check_function_bodies=false stores string bodies verbatim, and
	// CREATE OR REPLACE may change language/body/defaults, so the original SQL
	// — already CREATE OR REPLACE — restores the real object as the "-final"
	// stage). StubDeps are the edges the stub RETAINS (signature types); if
	// those still form a cycle the plan preflight-fails.
	Stub     string
	StubDeps []string

	// OpaqueFrame marks SQL as raw bytes fetched under
	// character_set_results=binary (MySQL object bodies): the writer wraps it
	// in a TableX opaque frame — a frame marker plus a body-derived DELIMITER
	// — and the splitter replays the framed bytes verbatim with no
	// string/comment interpretation, so a non-UTF-8 or NO_BACKSLASH_ESCAPES
	// body cannot be mangled or mis-split. Implies DELIMITER wrapping.
	OpaqueFrame bool
	// Pre/Post are complete session-guard statements the writer emits around
	// SQL (outside any DELIMITER wrap): mysqldump-style save/set/restore of
	// the object's creation context (sql_mode, character_set_client,
	// collation_connection, event time_zone). Save variables MUST use
	// object-local @saved_* names, never the preamble's @OLD_* names, which
	// the postamble restores last.
	Pre  []string
	Post []string
	// Markers are pre-formatted inert TableX marker lines (FormatCollationMarker)
	// emitted verbatim before the script — disclosure comments to external
	// clients, warning events to TableX's own importer.
	Markers []string
}

// DumpClause is one deferrable trailing clause of a DumpScript (see
// DumpScript.Clauses). PostgreSQL's clause grammar composes by appending, so
// keeping a clause is exactly `SQL += Text` in declaration order.
type DumpClause struct {
	Text     string       // appended to the script's SQL when the clause is kept
	Deps     []string     // node ids this clause (and only this clause) requires
	Finalize []DumpScript // the deferred DDL emitted instead when the clause is cut
	PreData  bool         // true: Finalize runs in the pre-data finalizer lane (domain defaults/constraints must precede consuming types/tables and data); false: post-data
}

// DropForm describes how one object's teardown DROP may be merged into a
// MULTI-OBJECT drop command. A dependency cycle on the RESTORED catalog (a
// mutually-recursive routine pair, a base type and its I/O functions) cannot be
// linearized into individual reverse-ordered DROPs — each one fails under
// RESTRICT while the other member still references it, and the importer stops
// at the first error. A single DROP command listing every member drops them as
// a group, so mutual dependencies AMONG them do not trigger RESTRICT (exactly
// like `DROP TABLE a, b` for circular foreign keys). CASCADE is never used: it
// would strip objects outside the export's knowledge.
type DropForm struct {
	// Class is the DROP command class whose grammar accepts a comma-separated
	// object list ("FUNCTION", "TYPE", …). "" — the zero value — means the
	// object's DROP has single-object syntax only (COLLATION, CAST, OPERATOR
	// CLASS, USER MAPPING) and can never be grouped: such a cycle is RETAINED
	// (drops omitted + warned) instead.
	Class string
	// Ref is this object's reference inside such a list: everything the command
	// needs after the class keyword and IF EXISTS.
	Ref string
	// RoutineRef, when non-empty, is this object's reference inside a grouped
	// DROP ROUTINE — the FLAT input signature (IN/INOUT/VARIADIC types only, no
	// ORDER BY split), which is the one spelling that matches functions,
	// procedures and aggregates alike, so an all-routine cycle of mixed kinds
	// drops in ONE statement. It is NOT interchangeable with Ref: an ordered-set
	// aggregate's identity arguments render an `ORDER BY` split that only DROP
	// AGGREGATE accepts.
	RoutineRef string
}

// groupableDropClasses is the explicit capability table gating grouped
// multi-object DROPs: only a class whose DROP grammar takes a comma-separated
// list may be rendered as one. A same-class cycle in a LIST-LESS class is
// retained rather than emitted as invalid SQL, so this table is the authority —
// a dialect setting DropForm.Class to anything else gets no grouping.
var groupableDropClasses = map[string]bool{
	"FUNCTION": true, "PROCEDURE": true, "AGGREGATE": true, "ROUTINE": true,
	"TYPE": true, "DOMAIN": true, "SEQUENCE": true, "VIEW": true,
	"OPERATOR": true, "TABLE": true,
}

// GroupableDropClass reports whether class may be rendered as a multi-object
// DROP (see groupableDropClasses).
func GroupableDropClass(class string) bool { return groupableDropClasses[class] }

// TeardownDrop is one planned teardown DROP handed to a TeardownAuditor: the
// object's graph node id (in the dialect's own id spelling — the auditor is the
// dialect that minted it) and the exact statement, so a warning can name the
// precise blocked drop.
type TeardownDrop struct {
	Node string
	SQL  string
}

// TeardownAuditor is an optional Dialect capability: a WARN-ONLY,
// non-destructive audit of a drop-first teardown, run once per database when
// the user asked to drop first. It probes the SOURCE catalog for objects that
// depend on a planned DROP but are NOT themselves dropped by this dump — an
// external view over a dumped table, an out-of-scope index using a dumped
// operator class, an out-of-scope inheritance/partition child of a dumped
// parent — and returns advisory warnings naming the blocked statement.
//
// It is best-effort by construction: the audit runs on the source connection,
// so blockers that exist only in the RESTORE TARGET are unknowable. It never
// fails the export, never escalates a DROP to CASCADE, and never suppresses a
// drop; a fresh target no-ops every `DROP … IF EXISTS` regardless.
type TeardownAuditor interface {
	AuditTeardown(ctx context.Context, db *sql.DB, planned []TeardownDrop) ([]string, error)
}

// AuditTeardown returns the drop-first teardown advisories (see
// TeardownAuditor); no warnings for a dialect without the capability.
func (c *Connection) AuditTeardown(ctx context.Context, planned []TeardownDrop) ([]string, error) {
	d, ok := c.dialect.(TeardownAuditor)
	if !ok || len(planned) == 0 {
		return nil, nil
	}
	return d.AuditTeardown(ctx, c.db, planned)
}

// DumpPlan is the non-table DDL a restore-equivalent SQL dump emits around the
// table CREATEs and data. Each slice is already ordered for restore.
type DumpPlan struct {
	// Types are user-defined types (PostgreSQL enums, domains, composites)
	// emitted BEFORE routines and tables, which may reference them — without
	// this pass a restore into an empty server fails at the first CREATE TABLE
	// naming an enum/domain. Their Drops run in teardown AFTER the tables, so a
	// column using the type is already gone. Only PostgreSQL populates this, and
	// the writer emits it only when structure is dumped.
	Types []DumpScript
	// Collations are user-defined collations (PostgreSQL) emitted BEFORE the types
	// and tables — a domain, composite attribute or column COLLATE may reference
	// one. Their Drops run in teardown AFTER the types (a domain over a collated
	// base type drops first). Only PostgreSQL populates this, structure-gated.
	Collations []DumpScript
	// Routines are emitted before the tables: functions/procedures may be
	// referenced by views, triggers or generated columns.
	Routines []DumpScript
	// Sequences (CREATE SEQUENCE) are emitted after teardown, before the
	// tables, so a serial/standalone column DEFAULT nextval(...) resolves at
	// CREATE TABLE time. Their Drops run in teardown AFTER the DROP TABLEs:
	// an owned sequence is auto-dropped with its table, and an OWNED BY /
	// default dependency would block an earlier DROP. Only PostgreSQL populates
	// this; the writer emits it only when structure is dumped.
	Sequences []DumpScript
	// ForeignData holds foreign-table creates (schema plans) and rides
	// the pre-data slot between sequences and tables (pg_dump's foreign-data
	// priority; a foreign table can INHERIT a local parent — the edge hoists
	// the parent). Structure-only: foreign tables have NO data pass — their
	// rows live on the remote server.
	ForeignData []DumpScript
	// Views (and materialized views) are emitted after the tables,
	// dependency-ordered so a view referencing another view restores.
	Views []DumpScript
	// PostData is emitted after all rows: foreign-key ALTERs (PostgreSQL),
	// NOT VALID constraints, secondary indexes (SQLite), triggers (so restored
	// INSERTs do not fire them), events, materialized-view refreshes and
	// sequence synchronization, in that order.
	PostData []DumpScript
	// Warnings are best-effort advisories (skipped objects, unsynchronized
	// external state, dependency hazards) the writer emits as inert `-- WARNING:`
	// comment lines — routed through commentSafe — at the top of the dump body in
	// every mode. They never fail the export.
	Warnings []string
	// SchemaComment is the COMMENT ON SCHEMA text (PostgreSQL), emitted in the
	// structure phase INDEPENDENTLY of the CREATE SCHEMA line (the default/public
	// section writes no CREATE SCHEMA, but a comment on it must still round-trip).
	SchemaComment string
	// ViewEdges are the DATABASE-WIDE (dependent, source) edges among
	// views/matviews, as qualified "schema.name" pairs resolved by relation OID
	// through pg_rewrite — the planner topo-orders cross-schema matview
	// REFRESHes with them. Only PostgreSQL populates this.
	ViewEdges [][2]string
	// TableNodes maps each dumped table's BARE name to its dependency-graph
	// metadata (tables are not DumpScripts — the handler owns their emission —
	// so their edges ride here). Only PostgreSQL populates this.
	TableNodes map[string]DumpTableNode
	// DataOnlyTables names tables whose ROWS are dumped but whose
	// STRUCTURE is not: the local leaves of a partition tree containing a
	// FOREIGN leaf. The tree's root emits every child's structure recursively,
	// but its data scan cannot run (a plain FROM on the root would query the
	// foreign leaf's REMOTE server), so the local leaves are read individually
	// (FROM ONLY) instead — emitting their creates too would duplicate the DDL.
	DataOnlyTables []string
	// SuppressedRelations names relations classified state (c) —
	// unreproducible under the redaction policy, emitted only as inert
	// templates — whose dependents (triggers/comments/rules) were suppressed
	// with them.
	SuppressedRelations []string
	// StructureOnlyTables names tables whose STRUCTURE is dumped but
	// whose DATA scan must not run: a mixed local/foreign partition tree's
	// ROOT (its plain FROM would recurse into the foreign leaf and query the
	// remote server; the local leaves in DataOnlyTables carry the rows).
	StructureOnlyTables []string
	// SequenceRewrites maps an out-of-scope source sequence (keyed
	// SeqRefKey(schema, name)) to the replacement sequence materialized in its
	// place (a SeqRefKey-shaped value). The handler routes every emitted table's
	// DDL through RewriteSequenceRefs so early-bound ('s'::regclass) and
	// resolvable late-bound ('s'::text) default references bind to the
	// replacement. Only PostgreSQL populates this, and only for scoped
	// (non-database) exports — a database-scope dump emits every sequence.
	SequenceRewrites map[string]string
	// StagedDefaultColumns names, per BARE table, columns whose inline
	// DEFAULT must be suppressed at CREATE time and re-established post-data
	// (Kind "staged-default"): the multi-parent divergent-default conflict —
	// CREATE … INHERITS fails on conflicting parent defaults before any staged
	// DDL could run, so every affected hierarchy member creates default-less
	// and re-emits its own state via ALTER TABLE ONLY. The handler renders
	// these tables through StagedTableDumper. Only PostgreSQL populates this.
	StagedDefaultColumns map[string][]string
}

// DumpTableNode is one table's dependency-graph metadata (see
// DumpPlan.TableNodes): hard edges plus the deferrable per-column DEFAULT and
// per-constraint expression edges the planner may CUT to break a cycle —
// cutting re-renders the CREATE without the clause via StagedTableDumper and
// re-adds it post-data (data INSERTs name every column explicitly, so a
// post-data SET DEFAULT never changes restored rows, and a re-added CHECK
// validates them).
type DumpTableNode struct {
	Name                  string // the table's node id ("relation:<schema>\x00<name>")
	Deps                  []string
	DeferrableDefaults    map[string][]string // column name → node ids its DEFAULT expression references
	DeferrableConstraints map[string][]string // constraint name → node ids its expression references
}

// Dumper is an optional Dialect capability producing restore-equivalent dump
// DDL (discovered by type assertion, mirroring SchemaEditor/Monitor). The
// plain CreateSQL is display-oriented; these methods are restore-oriented:
// PostgreSQL strips foreign keys from the CREATE (returning them as post-data
// ALTERs so cyclic/self-referencing schemas restore), preserves PARTITION BY,
// and emits partition children with the parent; MySQL wraps procedural bodies
// for DELIMITER handling; SQLite returns the extra sqlite_master rows
// (indexes, triggers) the table's own row does not carry.
//
// Fallback contract (asymmetric, by design): when a Dialect does NOT implement
// Dumper, the Connection passthroughs (DumpTableCreate/DumpDataTables/DumpObjects)
// degrade differently. DumpTableCreate hard-fails with ErrUnsupported — a table's
// restore DDL cannot be faked from the display-oriented CreateSQL without
// silently dropping restore-critical detail — while DumpDataTables returns the
// tables unchanged and DumpObjects returns an empty plan, so a minimal future
// dialect that implements no Dumper still exports its rows (data phase) and
// simply omits the extra objects. Implementers keep this split: the data/object
// passes degrade gracefully; the structure-DDL pass fails loudly.
type Dumper interface {
	// DumpTableCreate returns the restore-oriented CREATE statement(s) for one
	// table, ending without a trailing terminator on the last statement.
	DumpTableCreate(ctx context.Context, db *sql.DB, t TableRef) (string, error)

	// DumpDataTables returns the subset of tables whose rows the data phase
	// reads directly, preserving order. PostgreSQL excludes partition children:
	// their structure rides with the parent and a SELECT on the parent already
	// returns their rows (dumping both would duplicate every row).
	DumpDataTables(ctx context.Context, db *sql.DB, scope Scope, tables []string) ([]string, error)

	// DumpObjects returns everything beyond table DDL and data for the given
	// tables. dbScope, structure and data are independent: dbScope=false
	// (table-scope export) returns only objects belonging to the listed tables
	// (triggers, indexes, constraints, owned sequences), while dbScope=true
	// also covers database-scope objects (routines, views, events, standalone
	// sequences). structure=false (data-only export) suppresses ALL
	// structure-only DDL (routines/views/triggers/indexes/constraints/sequence
	// ownership) so a data-only dump neither fails on nor wastes introspection
	// it would discard, while still collecting the data-section items (sequence
	// setval, matview refresh) pg_dump emits in a --data-only run. data=true
	// collects the data-phase planning facts (PostgreSQL's mixed local/foreign
	// partition-tree split, whose StructureOnlyTables/DataOnlyTables halves
	// keep a tree's rows from dumping twice) and their data-facing warnings;
	// data=false (structure-only export) suppresses both.
	DumpObjects(ctx context.Context, db *sql.DB, scope Scope, tables []string, dbScope, structure, data bool) (DumpPlan, error)

	// ValueLiteral renders a scanned cell as an engine-correct SQL literal for
	// the dump's INSERT statements: the binary form (X'…' vs '\x…'), MySQL's
	// zero-date sentinel, and non-finite float handling all live here rather
	// than in engine switches at the call site.
	ValueLiteral(col ResultColumn, v Value) string

	// DumpPreamble writes the session state a restore needs pinned before the
	// script body (FK checks, sql_mode, string-escape settings, time zone);
	// DumpPostamble restores it for sessions that outlive the script. Either
	// may write nothing.
	DumpPreamble(w io.Writer)
	DumpPostamble(w io.Writer)
}

// ServerDumpProfile describes the framing shape of an engine's SERVER-scope
// SQL dump. These are framing-owned flags on purpose: capability bits like
// DatabasesShareConnection describe connection topology, and any truth-value
// match with framing needs is coincidence — a new dialect sets its framing
// here and stays correct.
type ServerDumpProfile struct {
	// PerSectionPreamble: the session preamble/postamble must be re-emitted
	// inside each database section (PostgreSQL: session SETs do not survive
	// \connect) instead of once globally.
	PerSectionPreamble bool
	// UsesConnectMarkers: sections switch databases via psql-style \connect
	// meta-commands, which the server-scope import honors (the import-side
	// mirror of this flag — export and import share it).
	UsesConnectMarkers bool
	// FormNote is the plain-text help sentence the export form shows for a
	// server-scope dump ("" = none).
	FormNote string
}

// ServerDumpFramer is an optional Dialect capability owning everything
// engine-specific about a server-scope SQL dump's framing: which databases a
// single script can address, how a database section is introduced, whether
// the preamble is global or per-section, and the dump-header help text. The
// handler loops over databases and delegates; it never branches on an engine
// name.
type ServerDumpFramer interface {
	ServerDumpProfile() ServerDumpProfile
	// WriteServerDumpHeader writes the engine's help comment lines for the
	// dump header (may write nothing).
	WriteServerDumpHeader(w io.Writer)
	// WriteDatabaseSectionHeader introduces one database's section: the
	// executable CREATE DATABASE …/USE pair (MySQL, preserving the
	// introspected default collation), the \connect meta-command (PostgreSQL),
	// or nothing (SQLite). collation is the database's introspected default
	// collation ("" when unknown/unsupported).
	WriteDatabaseSectionHeader(w io.Writer, name, collation string)
	// UnaddressableDatabase reports a human-readable reason the named database
	// cannot be addressed by this dump format ("" = addressable). PostgreSQL
	// skips names containing \r or \n: a psql \connect argument cannot
	// continue past end-of-line, and the residual fragment would leak into the
	// next section as executable SQL (the pg_dumpall CVE-2016-5424 class).
	UnaddressableDatabase(name string) string
}

// ValueLiteralHooks parameterize RenderValueLiteral with the two things the
// engines genuinely disagree on:
//
//   - binary spelling: X'…' (MySQL/SQLite/fallback) vs '\x…' (PostgreSQL);
//   - non-finite floats: NULL (MySQL, SQLite NaN), quoted tokens
//     ('NaN'/'Infinity', PostgreSQL), overflowing exponents (SQLite ±Inf), or
//     the fallback's quote-the-text finite guard.
//
// TextSpecial is a PRE-PASS hook that runs on the text path BEFORE the
// numeric check (MySQL's zero-date sentinel lives on a temporal column's text
// path), while NonFinite runs INSIDE the numeric branch — two distinct
// insertion points by design.
type ValueLiteralHooks struct {
	// BinaryLiteral spells a binary cell's raw bytes as an SQL literal.
	BinaryLiteral func(b []byte) string
	// TextSpecial, when non-nil, may short-circuit a non-null, non-binary
	// value with an engine literal (ok=true) before any numeric handling.
	TextSpecial func(col ResultColumn, s string) (lit string, ok bool)
	// NonFinite maps a NonFiniteFloat class ("nan", "+inf", "-inf") to the
	// engine literal. nil applies the fallback finite guard: a non-finite
	// token is not a valid bare numeric literal, so it is emitted as quoted
	// text.
	NonFinite func(class string) string
	// PreferValueKind: the bare-vs-quoted decision trusts the value's RUNTIME
	// kind (Value.Numeric) instead of the declared column type. Set only by a
	// DynamicTyper dialect (SQLite); see that interface for why a statically
	// typed engine must leave it false.
	PreferValueKind bool
}

// DynamicTyper is an optional Dialect capability for an engine whose storage
// class lives on each VALUE rather than on the column — SQLite's per-cell
// dynamic typing. The dump writers (the SQL bare-vs-quoted literal decision,
// JSON's number-vs-string) then trust the scanned value's runtime kind
// (Value.Numeric) over the column's DECLARED type, which misclassifies
// dynamically typed cells in both directions: a no-affinity column's INTEGER
// would dump quoted and restore as TEXT (typeof() changes and `WHERE v = 1`
// stops matching), while a declared-numeric column's text would be trusted as
// a number.
//
// A statically typed engine must NOT implement this: its DECIMAL and
// out-of-int64-range integers scan as text — no numeric runtime kind — yet
// must stay bare to keep full precision, which only the declared type can
// decide.
type DynamicTyper interface {
	// DynamicValueTyping is a marker (implementing the interface is the
	// signal); it exists because a method-less interface would be satisfied
	// by every dialect.
	DynamicValueTyping()
}

// PrefersValueKind reports whether d's dump emission trusts a value's runtime
// kind over the declared column type (see DynamicTyper). The JSON writer uses
// it; the SQL writers get the same answer through the dialect's own
// ValueLiteralHooks.PreferValueKind.
func PrefersValueKind(d Dialect) bool {
	_, ok := d.(DynamicTyper)
	return ok
}

// IsNumericLiteral reports whether s is a syntactically valid bare numeric
// literal, by the strict JSON-number grammar (json.Valid): optional minus, no
// leading zeros, optional fraction and exponent. It is THE shared gate for
// emitting a numeric column's textual value unquoted — the SQL dump's bare
// literals and the JSON export's json.Number both call it, so the two writers
// cannot drift apart.
//
// Strictness is safe in exactly one direction: a value that fails (PostgreSQL
// NaN/Infinity, MySQL ZEROFILL's leading zeros, text smuggled into a
// declared-numeric column) is emitted QUOTED, which every engine accepts for
// a numeric column via implicit cast — while emitting it bare would let a
// crafted cell terminate the INSERT and execute the remainder on restore.
// The cheap first-byte guard rejects the common non-numeric shapes before
// json.Valid rejects leading zeros, trailing garbage, etc.
func IsNumericLiteral(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; c != '-' && (c < '0' || c > '9') {
		return false
	}
	return json.Valid([]byte(s))
}

// XHexLiteral spells binary content as the X'…' hex literal MySQL, SQLite and
// the non-Dumper fallback share (PostgreSQL spells '\x…').
func XHexLiteral(b []byte) string { return "X'" + hex.EncodeToString(b) + "'" }

// RenderValueLiteral is the shared dump-literal scaffold behind every
// ValueLiteral implementation: NULL, binary, the optional text pre-pass, the
// numeric passthrough with non-finite handling, and the quoted-text fallback.
func RenderValueLiteral(quote func(string) string, hooks ValueLiteralHooks, col ResultColumn, v Value) string {
	if v.Null {
		return "NULL"
	}
	if v.Binary {
		return hooks.BinaryLiteral(v.Bytes)
	}
	if hooks.TextSpecial != nil {
		if lit, ok := hooks.TextSpecial(col, v.Str); ok {
			return lit
		}
	}
	numeric := col.Numeric
	if hooks.PreferValueKind {
		// A DynamicTyper engine: the value's runtime storage class decides.
		// The declared type misclassifies dynamically typed cells in both
		// directions (see DynamicTyper).
		numeric = v.Numeric
	}
	if numeric && v.Str != "" {
		if class := NonFiniteFloat(v.Str); class != "" {
			if hooks.NonFinite != nil {
				return hooks.NonFinite(class)
			}
			return quote(v.Str)
		}
		// The syntactic gate: a declared-numeric column can still hold text
		// (dynamic typing, engine quirks), and emitting it bare would let a
		// crafted cell break out of its INSERT on restore. Quoting a genuine
		// number is always restore-safe; a bare non-number never is.
		if IsNumericLiteral(v.Str) {
			return v.Str
		}
	}
	return quote(v.Str)
}

// NonFiniteFloat classifies a numeric column's textual value as a non-finite
// float token — "nan", "+inf" or "-inf" (as strconv.FormatFloat emits them,
// plus PostgreSQL's Infinity spellings) — or "" for an ordinary finite value.
// A non-finite value rendered bare is not a valid unquoted SQL numeric literal
// and would fail on restore, so each dialect's ValueLiteral maps these to an
// engine-correct literal (or NULL when the engine cannot store them).
func NonFiniteFloat(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "nan":
		return "nan"
	case "inf", "+inf", "infinity", "+infinity":
		return "+inf"
	case "-inf", "-infinity":
		return "-inf"
	}
	return ""
}

// TopoOrder orders names so every dependency precedes its dependents:
// deps[v] lists the names v depends on. The sort is stable (ties keep the
// input order) and cycle-tolerant — a cycle's members are still all emitted
// (never dropped), in DFS-completion order rather than input order: for a
// 2-cycle A→B→A with input [A,B] the output is [B,A] (visiting A recurses into
// B, which completes first). Dialects use it to dependency-order view DDL,
// where a mutually-recursive cycle cannot be perfectly ordered but every member
// must still appear. The self-edge guard (dep != n) means a single node with a
// self-dependency is NOT reordered, so callers needing to detect a self-cycle
// must inspect the edges directly.
func TopoOrder(names []string, deps map[string][]string) []string {
	index := make(map[string]int, len(names))
	for i, n := range names {
		index[n] = i
	}
	visited := make(map[string]int, len(names)) // 0 unvisited, 1 in progress, 2 done
	out := make([]string, 0, len(names))
	var visit func(n string)
	visit = func(n string) {
		if visited[n] != 0 {
			return // done, or a cycle back-edge — either way, stop
		}
		visited[n] = 1
		for _, dep := range deps[n] {
			if _, ok := index[dep]; ok && dep != n {
				visit(dep)
			}
		}
		visited[n] = 2
		out = append(out, n)
	}
	for _, n := range names {
		visit(n)
	}
	return out
}

// SCC returns the strongly-connected components of the (names, deps) graph —
// Tarjan's algorithm, iterative-free depth-first (the graphs are small catalog
// object sets). deps[v] lists the nodes v depends on; edges to names outside
// the set are ignored (boundary edges). Components are returned in reverse
// topological order of the condensation (a component precedes the components
// that depend on it), each with its members in visit order. A single node is
// its own component; it is a GENUINE cycle only when len > 1 or it carries a
// self-edge — callers use SCC to find the cycles TopoOrder merely tolerates.
func SCC(names []string, deps map[string][]string) [][]string {
	index := make(map[string]int, len(names))
	for i, n := range names {
		index[n] = i
	}
	const unvisited = -1
	num := make(map[string]int, len(names))     // discovery index
	lowlink := make(map[string]int, len(names)) // Tarjan lowlink
	onStack := make(map[string]bool, len(names))
	for _, n := range names {
		num[n] = unvisited
	}
	var stack []string
	var out [][]string
	counter := 0
	var strongconnect func(v string)
	strongconnect = func(v string) {
		num[v] = counter
		lowlink[v] = counter
		counter++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range deps[v] {
			if _, ok := index[w]; !ok {
				continue // boundary edge: target not in the node set
			}
			if num[w] == unvisited {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] && num[w] < lowlink[v] {
				lowlink[v] = num[w]
			}
		}
		if lowlink[v] == num[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			out = append(out, comp)
		}
	}
	for _, n := range names {
		if num[n] == unvisited {
			strongconnect(n)
		}
	}
	return out
}

// HasSelfEdge reports whether deps[name] contains name itself — the one cycle
// shape SCC's single-member components cannot distinguish from an acyclic node.
func HasSelfEdge(name string, deps map[string][]string) bool {
	for _, d := range deps[name] {
		if d == name {
			return true
		}
	}
	return false
}

// StagedTableDumper is an optional Dialect capability the cycle resolver
// uses: re-render one table's create with the named columns' DEFAULT clauses
// and the named inline constraints OMITTED, returning the reduced create plus
// the deferred post-data scripts (ALTER … SET DEFAULT / ADD CONSTRAINT, with
// any constraint comment moved along — a comment cannot ride a create that no
// longer declares its constraint). parents mirrors DumpInheritsChildCreate
// (nil for a standalone/plain table).
type StagedTableDumper interface {
	DumpTableCreateStaged(ctx context.Context, db *sql.DB, t TableRef, parents []string, stripDefaults, stripConstraints []string) (string, []DumpScript, error)
}

// DumpTableCreateStaged re-renders a table create with deferred clauses (see
// StagedTableDumper). ErrUnsupported for dialects without the capability —
// the resolver only calls it for dialects that emitted deferrable table edges.
func (c *Connection) DumpTableCreateStaged(ctx context.Context, t TableRef, parents []string, stripDefaults, stripConstraints []string) (string, []DumpScript, error) {
	d, ok := c.dialect.(StagedTableDumper)
	if !ok {
		return "", nil, ErrUnsupported
	}
	return d.DumpTableCreateStaged(ctx, c.db, t, parents, stripDefaults, stripConstraints)
}

// GlobalDumper is an optional Dialect capability collecting DATABASE-GLOBAL
// (non-schema-owned) objects once per database, before the per-schema
// DumpObjects passes — the architectural hook the object breadth (casts,
// foreign-data wrappers/servers/user mappings) plugs its producers into.
// Globals live per database, so a server-scope export runs it once per
// database section.
type GlobalDumper interface {
	DumpGlobalObjects(ctx context.Context, db *sql.DB, structure bool) (DumpPlan, error)
}

// DumpGlobalObjects collects the database-global objects (see GlobalDumper).
// An empty plan for dialects without the capability.
func (c *Connection) DumpGlobalObjects(ctx context.Context, structure bool) (DumpPlan, error) {
	d, ok := c.dialect.(GlobalDumper)
	if !ok {
		return DumpPlan{}, nil
	}
	return d.DumpGlobalObjects(ctx, c.db, structure)
}

// Dumper passthroughs on Connection. Each returns ErrUnsupported when the
// dialect does not implement Dumper.

func (c *Connection) DumpTableCreate(ctx context.Context, t TableRef) (string, error) {
	d, ok := c.dialect.(Dumper)
	if !ok {
		return "", ErrUnsupported
	}
	return d.DumpTableCreate(ctx, c.db, t)
}

func (c *Connection) DumpDataTables(ctx context.Context, scope Scope, tables []string) ([]string, error) {
	d, ok := c.dialect.(Dumper)
	if !ok {
		return tables, nil
	}
	return d.DumpDataTables(ctx, c.db, scope, tables)
}

func (c *Connection) DumpObjects(ctx context.Context, scope Scope, tables []string, dbScope, structure, data bool) (DumpPlan, error) {
	d, ok := c.dialect.(Dumper)
	if !ok {
		return DumpPlan{}, nil
	}
	return d.DumpObjects(ctx, c.db, scope, tables, dbScope, structure, data)
}

// DataScoper is an optional Dialect capability reporting, per table, whether its
// data SELECT must use `FROM ONLY` instead of `FROM`. PostgreSQL returns true for
// an ordinary relkind='r' table so an INHERITS parent scans only its OWN rows —
// its separately-dumped children then contribute their rows exactly once, instead
// of every child row being duplicated inside the parent (silent data corruption).
// A partitioned parent (relkind='p') returns false: its descendant rows ride the
// parent scan while the children are excluded from the data list.
type DataScoper interface {
	DataSelectOnly(ctx context.Context, db *sql.DB, scope Scope, tables []string) (map[string]bool, error)
}

// DataSelectOnly returns the set of tables whose data SELECT must use FROM ONLY.
// A nil map (dialect without DataScoper, or MySQL/SQLite) means every table uses
// a plain FROM — today's behavior.
func (c *Connection) DataSelectOnly(ctx context.Context, scope Scope, tables []string) (map[string]bool, error) {
	d, ok := c.dialect.(DataScoper)
	if !ok {
		return nil, nil
	}
	return d.DataSelectOnly(ctx, c.db, scope, tables)
}

// ViewDumper is an optional Dialect capability: dump a SINGLE view or
// materialized view's restore-oriented DDL. A table-scope SQL export whose
// target is a view needs this because the schema-wide view pass inside
// DumpObjects runs only for a whole-database dump (dbScope) — without it, the
// table path emits a physical CREATE TABLE snapshot (PostgreSQL), errors
// (SQLite), or mis-scans the object (MySQL). The returned plan populates Views
// with the CREATE [MATERIALIZED] VIEW (plus its object/column comments and,
// for SQLite, the view's INSTEAD OF triggers); for a populated materialized
// view with withData set it appends a REFRESH to PostData. The caller emits no
// CREATE TABLE and no row INSERTs for the object.
type ViewDumper interface {
	DumpView(ctx context.Context, db *sql.DB, scope Scope, name string, withData bool) (DumpPlan, error)
}

// DumpView dumps a single view/matview when the dialect supports it (ok true).
// ok is false for a dialect without ViewDumper, letting the caller fall back to
// the table path.
func (c *Connection) DumpView(ctx context.Context, scope Scope, name string, withData bool) (plan DumpPlan, ok bool, err error) {
	d, ok := c.dialect.(ViewDumper)
	if !ok {
		return DumpPlan{}, false, nil
	}
	plan, err = d.DumpView(ctx, c.db, scope, name, withData)
	return plan, true, err
}

// ForeignTableDumper is an optional Dialect capability for the
// SQL-export-only foreign-table path: IsForeignTable resolves a name the
// ordinary relation listings deliberately exclude (foreign tables never enter
// ListTables/ListTableNames — no browsing, CSV/JSON or data pass), and
// DumpForeignTable builds its STRUCTURE-ONLY plan (create + triggers + rules +
// comments + restore-prerequisite warnings; never any row read).
type ForeignTableDumper interface {
	IsForeignTable(ctx context.Context, db *sql.DB, scope Scope, name string) (bool, error)
	DumpForeignTable(ctx context.Context, db *sql.DB, scope Scope, name string) (DumpPlan, error)
}

// IsForeignTable reports whether name is a foreign table (false for dialects
// without the capability).
func (c *Connection) IsForeignTable(ctx context.Context, scope Scope, name string) (bool, error) {
	d, ok := c.dialect.(ForeignTableDumper)
	if !ok {
		return false, nil
	}
	return d.IsForeignTable(ctx, c.db, scope, name)
}

// DumpForeignTable builds a single foreign table's structure-only plan (see
// ForeignTableDumper).
func (c *Connection) DumpForeignTable(ctx context.Context, scope Scope, name string) (DumpPlan, error) {
	d, ok := c.dialect.(ForeignTableDumper)
	if !ok {
		return DumpPlan{}, ErrUnsupported
	}
	return d.DumpForeignTable(ctx, c.db, scope, name)
}

// Inheritor is an optional Dialect capability for ordinary (INHERITS,
// non-partition) table inheritance. PostgreSQL implements it; MySQL/SQLite have
// no equivalent. InheritanceParents reports, per same-schema ordinary
// inheritance child among the given tables, its parent bare-names (ordered by
// inhseqno) — used to order parents before children and to decide the linked
// create. DumpInheritsChildCreate emits a child's CREATE TABLE with an INHERITS
// clause and local-only columns/constraints so the link and provenance survive.
type Inheritor interface {
	InheritanceParents(ctx context.Context, db *sql.DB, scope Scope, tables []string) (map[string][]string, error)
	DumpInheritsChildCreate(ctx context.Context, db *sql.DB, t TableRef, parents []string) (string, error)
}

// InheritanceParents returns the same-schema ordinary-inheritance parent map (see
// Inheritor). A nil map — dialect without Inheritor — means no table links, so
// every table dumps standalone (today's behavior).
func (c *Connection) InheritanceParents(ctx context.Context, scope Scope, tables []string) (map[string][]string, error) {
	d, ok := c.dialect.(Inheritor)
	if !ok {
		return nil, nil
	}
	return d.InheritanceParents(ctx, c.db, scope, tables)
}

// DumpInheritsChildCreate emits a linked INHERITS child's CREATE (see Inheritor).
// It is only called for a dialect that returned parents from InheritanceParents,
// so the capability is always present here.
func (c *Connection) DumpInheritsChildCreate(ctx context.Context, t TableRef, parents []string) (string, error) {
	d, ok := c.dialect.(Inheritor)
	if !ok {
		return "", ErrUnsupported
	}
	return d.DumpInheritsChildCreate(ctx, c.db, t, parents)
}

// ValueLiteral renders a cell through the dialect's Dumper. The fallback for a
// non-Dumper dialect covers the generic shapes (NULL, X'…' hex, bare numerics
// with the finite guard, quoted text) so the data phase still emits something
// restorable.
func (c *Connection) ValueLiteral(col ResultColumn, v Value) string {
	if d, ok := c.dialect.(Dumper); ok {
		return d.ValueLiteral(col, v)
	}
	return RenderValueLiteral(c.dialect.QuoteString, ValueLiteralHooks{BinaryLiteral: XHexLiteral}, col, v)
}
