package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// livePG opens the test PostgreSQL from the TABLEX_TEST_POSTGRES_* environment,
// skipping when it is not configured. It exists because a few dump internals
// are unexported and so cannot be reached from the server package's live
// suite; anything testable through the public surface belongs there instead.
func livePG(t *testing.T) *sql.DB {
	t.Helper()
	host := os.Getenv("TABLEX_TEST_POSTGRES_HOST")
	if host == "" {
		t.Skip("TABLEX_TEST_POSTGRES_HOST not set; skipping live PostgreSQL test")
	}
	dsn := "postgres://" + os.Getenv("TABLEX_TEST_POSTGRES_USER") + ":" +
		os.Getenv("TABLEX_TEST_POSTGRES_PASSWORD") + "@" + host + ":" +
		os.Getenv("TABLEX_TEST_POSTGRES_PORT") + "/postgres?sslmode=disable"
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// freshSchema drops and recreates name, running ddl inside it, and schedules
// the drop for cleanup.
func freshSchema(t *testing.T, db *sql.DB, name, ddl string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+name+` CASCADE; CREATE SCHEMA `+name+`;`+ddl); err != nil {
		t.Fatalf("seed schema %s: %v", name, err)
	}
	t.Cleanup(func() {
		db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+name+` CASCADE`)
	})
}

// TestLiveSyntheticSeqName pins syntheticSeqName against a real catalog. The
// one-round-trip-per-candidate loop was replaced with a single
// `relname = ANY($2)` query, and nothing else in the suite reaches this path —
// a scoped export that references an out-of-scope sequence — so without this
// the array binding and the collision walk would both go unexercised.
func TestLiveSyntheticSeqName(t *testing.T) {
	db := livePG(t)
	ctx := context.Background()
	freshSchema(t, db, "tablex_seqname_test", "")

	d := dialect{major: 18}
	seed := identitySeqSeed("src_schema", "src_seq", "tablex_seqname_test", "child")
	cands := syntheticSeqCandidates(seed)

	got, err := d.syntheticSeqName(ctx, db, "tablex_seqname_test", seed)
	if err != nil {
		t.Fatalf("syntheticSeqName: %v", err)
	}
	if got != cands[0] {
		t.Fatalf("empty schema: got %q, want the first candidate %q", got, cands[0])
	}

	// Occupy the first two candidates with TABLES, not sequences: the check is
	// against the whole relation namespace, because an out-of-scope relation of
	// any kind will still collide in a matching restore target.
	for _, name := range cands[:2] {
		if _, err := db.ExecContext(ctx,
			`CREATE TABLE tablex_seqname_test.`+d.QuoteIdent(name)+` (x int)`); err != nil {
			t.Fatalf("occupy %s: %v", name, err)
		}
	}
	got, err = d.syntheticSeqName(ctx, db, "tablex_seqname_test", seed)
	if err != nil {
		t.Fatalf("syntheticSeqName after collision: %v", err)
	}
	if got != cands[2] {
		t.Fatalf("after two collisions: got %q, want the third candidate %q", got, cands[2])
	}
}

// TestLivePartitionChildObjects pins the per-level batched reads
// in writePartitionChildObjects. The server package's partition round-trip
// seeds only a child TABLE comment — which comes from a different query — so
// the child column comments and child-only secondary indexes these two reads
// produce had no assertion behind them at all.
//
// The tree deliberately straddles TWO schemas, with a decoy relation named like
// the child in the other schema. That is what pins the grouping key: batching
// means the rows for every child come back in one result set and are grouped by
// (schema, name), and a name-only key would attribute the decoy's comment and
// index to the real child. (The queries' row-wise `(nspname, relname) IN
// unnest` match is a precision choice on top of that — matching schemas and
// names as independent sets would only over-FETCH, since the grouped lookup
// discards anything that is not a child.)
func TestLivePartitionChildObjects(t *testing.T) {
	db := livePG(t)
	freshSchema(t, db, "tablex_part_other", `
		-- part_a here is NOT part of the tree; it only shares the name of the
		-- child that lives in the other schema.
		CREATE TABLE tablex_part_other.part_a (id int, amt int);
		COMMENT ON COLUMN tablex_part_other.part_a.amt IS 'DECOY column comment';
		CREATE INDEX decoy_idx ON tablex_part_other.part_a (amt)`)
	freshSchema(t, db, "tablex_part_test", `
		CREATE TABLE tablex_part_test.part (id int, region int, amt int) PARTITION BY LIST (region);
		CREATE TABLE tablex_part_test.part_a PARTITION OF tablex_part_test.part FOR VALUES IN (1);
		-- part_b lives in the OTHER schema, so the child list spans both.
		CREATE TABLE tablex_part_other.part_b PARTITION OF tablex_part_test.part FOR VALUES IN (2);
		COMMENT ON COLUMN tablex_part_test.part_a.amt IS 'amount on A';
		CREATE INDEX pa_amt_idx ON tablex_part_test.part_a (amt);
		COMMENT ON INDEX tablex_part_test.pa_amt_idx IS 'index comment on A';
		CREATE INDEX pb_region_idx ON tablex_part_other.part_b (region)`)

	var b strings.Builder
	d := dialect{major: 18}
	if err := d.writePartitionChildObjects(context.Background(), db, &b, "tablex_part_test", "part", nil); err != nil {
		t.Fatalf("writePartitionChildObjects: %v", err)
	}
	got := b.String()
	for _, want := range []string{
		`COMMENT ON COLUMN "tablex_part_test"."part_a"."amt" IS 'amount on A'`,
		`CREATE INDEX pa_amt_idx ON tablex_part_test.part_a`,
		`COMMENT ON INDEX "tablex_part_test"."pa_amt_idx" IS 'index comment on A'`,
		`CREATE INDEX pb_region_idx ON tablex_part_other.part_b`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"DECOY column comment", "decoy_idx"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("leaked %q from the same-named non-child relation in:\n%s", unwanted, got)
		}
	}
}

// TestLiveIdentityOptionsMemoized checks that the memoized schema-wide reads
// still answer per table: each table gets its own clauses, a table with no
// identity gets none, and the map handed back is a copy, so a caller mutating
// it cannot poison the next table's answer out of the shared memo.
func TestLiveIdentityOptionsMemoized(t *testing.T) {
	db := livePG(t)
	freshSchema(t, db, "tablex_ident_test", `
		CREATE TABLE tablex_ident_test.a (id int GENERATED ALWAYS AS IDENTITY (START WITH 7 INCREMENT BY 3), v text);
		CREATE TABLE tablex_ident_test.b (id bigint GENERATED BY DEFAULT AS IDENTITY, v text);
		CREATE TABLE tablex_ident_test.c (id int, v text)`)

	d := dialect{major: 18}
	ctx := driver.WithDumpMemo(context.Background())
	for _, tc := range []struct {
		table    string
		wantCol  string
		wantPart string
	}{
		{"a", "id", "START WITH 7 INCREMENT BY 3"},
		{"b", "id", "START WITH 1 INCREMENT BY 1"},
		{"c", "", ""},
	} {
		opts, err := d.identityOptions(ctx, db, "tablex_ident_test", tc.table)
		if err != nil {
			t.Fatalf("identityOptions(%s): %v", tc.table, err)
		}
		if tc.wantCol == "" {
			if len(opts) != 0 {
				t.Errorf("table %s: want no identity options, got %v", tc.table, opts)
			}
			continue
		}
		clause, ok := opts[tc.wantCol]
		if !ok {
			t.Fatalf("table %s: no options for column %s (got %v)", tc.table, tc.wantCol, opts)
		}
		if !strings.Contains(clause, tc.wantPart) {
			t.Errorf("table %s: clause %q does not contain %q", tc.table, clause, tc.wantPart)
		}
		opts["injected"] = "x"
		again, err := d.identityOptions(ctx, db, "tablex_ident_test", tc.table)
		if err != nil {
			t.Fatalf("identityOptions(%s) second call: %v", tc.table, err)
		}
		if _, leaked := again["injected"]; leaked {
			t.Errorf("table %s: mutating a returned map leaked into the memo", tc.table)
		}
	}
}

// TestLivePreflightReadsMemoized covers #45: the table-dump preflight reads
// (pg_class facts, named NOT NULLs, inline-constraint comments and column
// physical settings) are now SCHEMA-WIDE and memoized, so a dump of N tables
// makes one query each instead of N. The test checks the two properties that
// makes safe: each table still gets its OWN answer out of the shared memo, and
// the schema-wide read is genuinely cached (the same map instance comes back).
func TestLivePreflightReadsMemoized(t *testing.T) {
	db := livePG(t)
	schema := "tablex_preflight_test"
	freshSchema(t, db, schema, `
		CREATE UNLOGGED TABLE tablex_preflight_test.a (
			id  int NOT NULL,
			v   text,
			CONSTRAINT a_pos CHECK (id > 0)
		);
		COMMENT ON TABLE tablex_preflight_test.a IS 'table a';
		COMMENT ON CONSTRAINT a_pos ON tablex_preflight_test.a IS 'positive id';
		ALTER TABLE tablex_preflight_test.a ALTER COLUMN v SET STORAGE EXTERNAL;
		CREATE TABLE tablex_preflight_test.b (id int, v text)`)

	d := dialect{major: 18}
	ctx := driver.WithDumpMemo(context.Background())

	// tableMeta: a is UNLOGGED and carries a comment; b is plain; a name with no
	// row is sql.ErrNoRows, exactly as the old per-table QueryRow reported it.
	metaA, err := d.tableMeta(ctx, db, schema, "a")
	if err != nil {
		t.Fatalf("tableMeta a: %v", err)
	}
	if metaA.relpersistence != "u" || metaA.tableComment != "table a" {
		t.Errorf("a meta = %+v, want unlogged (u) with comment 'table a'", metaA)
	}
	metaB, err := d.tableMeta(ctx, db, schema, "b")
	if err != nil {
		t.Fatalf("tableMeta b: %v", err)
	}
	if metaB.relpersistence == "u" || metaB.tableComment != "" {
		t.Errorf("b meta = %+v, want a plain logged table with no comment", metaB)
	}
	if _, err := d.tableMeta(ctx, db, schema, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("tableMeta(nope) = %v, want sql.ErrNoRows", err)
	}

	// inlineConstraintComments: a has the CHECK comment; b has none.
	qa := d.QualifyTable(driver.TableRef{Schema: schema, Table: "a"})
	ca, err := d.inlineConstraintComments(ctx, db, schema, "a", qa, nil)
	if err != nil {
		t.Fatalf("inlineConstraintComments a: %v", err)
	}
	if len(ca) != 1 || !strings.Contains(ca[0], "positive id") {
		t.Errorf("a constraint comments = %v, want one 'positive id' comment", ca)
	}
	if cb, err := d.inlineConstraintComments(ctx, db, schema, "b", "b", nil); err != nil || len(cb) != 0 {
		t.Errorf("b constraint comments = %v (err %v), want none", cb, err)
	}

	// columnPhysicalSettings: a's v column was SET STORAGE EXTERNAL; b has none.
	sa, err := d.columnPhysicalSettings(ctx, db, schema, "a", "ALTER TABLE ONLY x")
	if err != nil {
		t.Fatalf("columnPhysicalSettings a: %v", err)
	}
	storageSet := false
	for _, s := range sa {
		if strings.Contains(s, "SET STORAGE") {
			storageSet = true
		}
	}
	if !storageSet {
		t.Errorf("a physical settings = %v, want a SET STORAGE line", sa)
	}
	if sb, err := d.columnPhysicalSettings(ctx, db, schema, "b", "ALTER TABLE ONLY x"); err != nil || len(sb) != 0 {
		t.Errorf("b physical settings = %v (err %v), want none", sb, err)
	}

	// namedNotNulls (PG18): a has a named NOT NULL on id; b has none.
	if nnA, err := d.namedNotNulls(ctx, db, schema, "a"); err != nil || len(nnA) == 0 {
		t.Errorf("a named NOT NULLs = %v (err %v), want at least one", nnA, err)
	}
	if nnB, err := d.namedNotNulls(ctx, db, schema, "b"); err != nil || len(nnB) != 0 {
		t.Errorf("b named NOT NULLs = %v (err %v), want none", nnB, err)
	}

	// The read is genuinely cached: a second schema-wide fetch returns the SAME
	// map instance, not a fresh query. Without the memo it would recompute.
	m1, err := d.tableMetaBySchema(ctx, db, schema, "")
	if err != nil {
		t.Fatalf("tableMetaBySchema 1: %v", err)
	}
	m2, err := d.tableMetaBySchema(ctx, db, schema, "")
	if err != nil {
		t.Fatalf("tableMetaBySchema 2: %v", err)
	}
	if reflect.ValueOf(m1).Pointer() != reflect.ValueOf(m2).Pointer() {
		t.Error("tableMetaBySchema is not memoized: two calls returned different maps")
	}

	// A dump with ONE table attaches no memo, and the preflight then narrows
	// each read to the relation being asked about instead of scanning the whole
	// schema for it (dump.BuildPlan / preflightOnly). The narrowing is an
	// optimization only if it is answer-for-answer identical to the schema-wide
	// read, so that is what is asserted — for a table WITH facts and one
	// without, since an empty slice is how "no rows" and "wrong scope" would
	// both look.
	narrow := context.Background() // no memo => narrowed reads
	if driver.HasDumpMemo(narrow) {
		t.Fatal("the bare context reports a dump memo; this test is not exercising the narrow path")
	}
	// The DECISION itself, asserted before its consequences: every equivalence
	// check below passes the scope explicitly, so none of them would notice
	// preflightOnly always answering "" (the schema-wide scan this exists to
	// stop). Assert the two answers directly.
	if got := preflightOnly(narrow, "a"); got != "a" {
		t.Errorf("preflightOnly with no memo = %q, want the table name — a single-table dump would scan the whole schema", got)
	}
	if got := preflightOnly(ctx, "a"); got != "" {
		t.Errorf("preflightOnly under a dump memo = %q, want \"\" (the amortized schema-wide read)", got)
	}
	for _, tbl := range []string{"a", "b"} {
		wide, err := d.tableMeta(ctx, db, schema, tbl)
		if err != nil {
			t.Fatalf("tableMeta %s (schema-wide): %v", tbl, err)
		}
		got, err := d.tableMeta(narrow, db, schema, tbl)
		if err != nil {
			t.Fatalf("tableMeta %s (narrowed): %v", tbl, err)
		}
		if got != wide {
			t.Errorf("tableMeta %s narrowed = %+v, schema-wide = %+v", tbl, got, wide)
		}

		wideNN, err := d.namedNotNulls(ctx, db, schema, tbl)
		if err != nil {
			t.Fatalf("namedNotNulls %s (schema-wide): %v", tbl, err)
		}
		gotNN, err := d.namedNotNulls(narrow, db, schema, tbl)
		if err != nil {
			t.Fatalf("namedNotNulls %s (narrowed): %v", tbl, err)
		}
		if !reflect.DeepEqual(gotNN, wideNN) {
			t.Errorf("namedNotNulls %s narrowed = %v, schema-wide = %v", tbl, gotNN, wideNN)
		}

		q := d.QualifyTable(driver.TableRef{Schema: schema, Table: tbl})
		wideCC, err := d.inlineConstraintComments(ctx, db, schema, tbl, q, nil)
		if err != nil {
			t.Fatalf("inlineConstraintComments %s (schema-wide): %v", tbl, err)
		}
		gotCC, err := d.inlineConstraintComments(narrow, db, schema, tbl, q, nil)
		if err != nil {
			t.Fatalf("inlineConstraintComments %s (narrowed): %v", tbl, err)
		}
		if !reflect.DeepEqual(gotCC, wideCC) {
			t.Errorf("inlineConstraintComments %s narrowed = %v, schema-wide = %v", tbl, gotCC, wideCC)
		}

		widePS, err := d.columnPhysicalSettings(ctx, db, schema, tbl, "ALTER TABLE ONLY x")
		if err != nil {
			t.Fatalf("columnPhysicalSettings %s (schema-wide): %v", tbl, err)
		}
		gotPS, err := d.columnPhysicalSettings(narrow, db, schema, tbl, "ALTER TABLE ONLY x")
		if err != nil {
			t.Fatalf("columnPhysicalSettings %s (narrowed): %v", tbl, err)
		}
		if !reflect.DeepEqual(gotPS, widePS) {
			t.Errorf("columnPhysicalSettings %s narrowed = %v, schema-wide = %v", tbl, gotPS, widePS)
		}
	}
	// The narrow read must not turn a genuinely absent relation into a silent
	// empty answer either.
	if _, err := d.tableMeta(narrow, db, schema, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("narrowed tableMeta(nope) = %v, want sql.ErrNoRows", err)
	}
	// A narrowed read really is narrow: asking for "a" must not carry b's row.
	onlyA, err := d.tableMetaBySchema(narrow, db, schema, "a")
	if err != nil {
		t.Fatalf("tableMetaBySchema narrowed: %v", err)
	}
	if _, leaked := onlyA["b"]; leaked || len(onlyA) != 1 {
		t.Errorf("a narrowed read returned %d rows (%v); it should scan only the named relation", len(onlyA), onlyA)
	}
}
