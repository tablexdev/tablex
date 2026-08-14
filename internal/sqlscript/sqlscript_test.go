package sqlscript

import (
	"errors"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// lexProfile resolves an engine name to its dialect's lexer profile (the
// dialects register via this package's test blank imports), so the table
// tests exercise the exact grammar production code uses.
func lexProfile(engine string) driver.LexerProfile {
	d, ok := driver.Get(engine)
	if !ok {
		panic("dialect not registered: " + engine)
	}
	return driver.ProfileOf(d)
}

func TestSplitStatements(t *testing.T) {
	const (
		pg  = "postgres"
		my  = "mysql"
		lit = "sqlite"
	)
	cases := []struct {
		in     string
		engine string
		want   int
	}{
		{"SELECT 1;", pg, 1},
		{"SELECT 1; SELECT 2;", pg, 2},
		{"SELECT 1; SELECT 2", pg, 2},
		{"SELECT ';'; SELECT 2;", pg, 2},                   // semicolon inside a string is not a separator
		{"INSERT INTO t VALUES ('a;b'); SELECT 1;", pg, 2}, // quoted semicolon
		{"-- a comment; not a split\nSELECT 1;", pg, 1},    // line comment
		{"/* block; comment */ SELECT 1;", pg, 1},          // block comment
		{`SELECT "a;b";`, pg, 1},                           // double-quoted identifier
		{"   ;  ;  ", pg, 0},                               // only empty statements
		{"CREATE FUNCTION f() RETURNS int AS $$ BEGIN x := 1; RETURN x; END $$ LANGUAGE plpgsql;", pg, 1}, // dollar-quoted body
		{"DO $tag$ BEGIN; PERFORM 1; END $tag$;", pg, 1},                                                  // tagged dollar quote
		{"SELECT * FROM t WHERE a = $1; SELECT 2;", pg, 2},                                                // $1 placeholder still splits
		// `#` is a comment in MySQL only.
		{"SELECT 1 # c; not split\nFROM t;", my, 1},
		{"SELECT '#' AS h # tail; x\n;", my, 1},
		// In PostgreSQL `#` is an operator, so the `;` after it still splits.
		{"SELECT a # b; SELECT 2;", pg, 2},
		// "/*/" is not a complete comment: the `;` inside it must not split.
		{"SELECT 1 /*/ still; comment */;", pg, 1},

		// Comment-only chunks are dropped (drivers may return a nil result).
		{"-- just a comment", pg, 0},
		{"/* header */;", my, 0},
		{"# mysql comment\n;", my, 0},

		// MySQL backslash escapes inside strings: the quote in 'It\'s' does not
		// close the string, so the embedded ';' must not split.
		{`INSERT INTO t VALUES ('It\'s; fine'); SELECT 1;`, my, 2},
		{`SELECT "a\";b"; SELECT 2;`, my, 2},
		// PostgreSQL standard strings treat backslash literally: 'a\' is complete.
		{`SELECT 'a\'; SELECT 'b';`, pg, 2},
		// Backslash is NOT an escape inside backtick identifiers.
		{"SELECT `a\\`; SELECT 2;", my, 2},

		// `$` is an identifier character in MySQL/SQLite — never a dollar quote.
		{"SELECT a$$b; SELECT 2;", my, 2},
		{"SELECT a$$b; SELECT 2;", lit, 2},

		// PostgreSQL E'…' escape strings honor backslash escapes (R3): the
		// escaped quote must not close the literal, so its ';' stays inside.
		{`SELECT E'It\'s; ok'; SELECT 2;`, pg, 2},
		{`SELECT e'a\\'; SELECT 2;`, pg, 2},     // \\ is one literal backslash; the string closes
		{`SELECT E'a''b; c'; SELECT 2;`, pg, 2}, // '' doubling coexists with \-escapes
		// An identifier merely ending in e keeps plain-string semantics.
		{`SELECT une'a\'; SELECT 2;`, pg, 2},
		// E-strings are postgres-only; SQLite strings stay backslash-literal.
		{`SELECT E'a\'; SELECT 2;`, lit, 2},

		// Block comments nest in PostgreSQL only (R5b); MySQL/SQLite close at
		// the first */ (pinned unchanged).
		{"/* a /* b; */ c; */ SELECT 1;", pg, 1},
		{"/* a /* b; */ c; */ SELECT 1;", my, 2},
		{"/* a /* b; */ c; */ SELECT 1;", lit, 2},

		// DELIMITER takes the first token, never the rest of the line (R5e).
		{"DELIMITER $$ -- x\nSELECT 1$$SELECT 2$$", my, 2},
		{"DELIMITER `//`\nSELECT 1//SELECT 2//", my, 2},

		// MySQL's "-- needs whitespace" rule also decides comment-only chunks
		// (R5f): --x is content in MySQL, a comment in PostgreSQL.
		{"--x", my, 1},
		{"-- x", my, 0},
		{"--x", pg, 0},

		// mysql-client DELIMITER directives round-trip dumped routine bodies.
		{"DELIMITER $$\nCREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND$$\nDELIMITER ;\nSELECT 3;", my, 2},
		{"DELIMITER //\nCREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW\nBEGIN\n  SET @x = 1;\nEND//\nDELIMITER ;", my, 1},

		// MySQL procedural blocks without DELIMITER: body semicolons do not split.
		{"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET @x = 1; END; SELECT 1;", my, 2},
		{"CREATE PROCEDURE p() BEGIN IF @x THEN SET @y = 1; END IF; END;", my, 1},
		{"CREATE PROCEDURE p() BEGIN WHILE @i < 10 DO SET @i = @i + 1; END WHILE; END;", my, 1},
		{"CREATE DEFINER=`root`@`localhost` PROCEDURE p() BEGIN SELECT 1; END;", my, 1},
		// Nested blocks and CASE expressions inside a body.
		{"CREATE PROCEDURE p() BEGIN BEGIN SET @x = 1; END; SET @y = 2; END;", my, 1},
		{"CREATE TRIGGER tr AFTER INSERT ON t FOR EACH ROW BEGIN UPDATE u SET v = CASE WHEN 1 THEN 2 ELSE 3 END; END; SELECT 1;", my, 2},
		// A FUNCTION whose body is a bare CASE expression (no BEGIN).
		{"CREATE FUNCTION f(x INT) RETURNS INT RETURN CASE WHEN x > 0 THEN 1 ELSE 0 END; SELECT 1;", my, 2},

		// SQLite triggers: the BEGIN...END body holds complete statements.
		{"CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); END;", lit, 1},
		{"CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); UPDATE c SET n = n + 1; END; SELECT 1;", lit, 2},
		{"CREATE TEMP TRIGGER tr AFTER DELETE ON t BEGIN DELETE FROM log WHERE id = old.id; END;", lit, 1},
		// A top-level BEGIN (transaction) is not a routine body.
		{"BEGIN; SELECT 1; COMMIT;", lit, 3},
		{"BEGIN; SELECT 1; COMMIT;", my, 3},
		// CASE in a plain SELECT is not a block either.
		{"SELECT CASE WHEN a THEN 1 ELSE 2 END FROM t; SELECT 2;", lit, 2},
	}
	for _, c := range cases {
		got := Split(c.in, lexProfile(c.engine))
		if len(got) != c.want {
			t.Errorf("Split(%q, %s) = %d statements %v, want %d", c.in, c.engine, len(got), got, c.want)
		}
	}
}

// TestSplitStatementsBodies asserts the content of split statements, not just
// the count: routine bodies must keep their internal semicolons, and DELIMITER
// directives must not leak into the emitted statements.
func TestSplitStatementsBodies(t *testing.T) {
	script := "DELIMITER $$\nCREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND$$\nDELIMITER ;\nSELECT 3;"
	got := Split(script, lexProfile("mysql"))
	if len(got) != 2 {
		t.Fatalf("got %d statements %v, want 2", len(got), got)
	}
	if !strings.Contains(got[0], "SELECT 1;") || !strings.Contains(got[0], "SELECT 2;") {
		t.Errorf("routine body lost internal statements: %q", got[0])
	}
	if strings.Contains(strings.ToUpper(got[0]), "DELIMITER") {
		t.Errorf("DELIMITER directive leaked into statement: %q", got[0])
	}
	if got[1] != "SELECT 3" {
		t.Errorf("statement after DELIMITER reset = %q, want SELECT 3", got[1])
	}

	lit := Split("CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); END;", lexProfile("sqlite"))
	if len(lit) != 1 {
		t.Fatalf("sqlite trigger split into %d statements %v, want 1", len(lit), lit)
	}
	if !strings.Contains(lit[0], "VALUES (new.id);") || !strings.HasSuffix(strings.TrimSpace(lit[0]), "END") {
		t.Errorf("sqlite trigger body mangled: %q", lit[0])
	}
}

// frameScript wraps body in a TableX opaque frame exactly as writeDumpScript
// emits it (marker line, DELIMITER wrap, terminator on its own line).
func frameScript(body string) string {
	d := driver.ChooseFrameDelimiter(body)
	return driver.FormatFrameMarker(d) + "\nDELIMITER " + d + "\n" + body + "\n" + d + "\nDELIMITER ;\n"
}

// TestSplitStatementsBytePreservation: statements are spans of the ORIGINAL
// script bytes — invalid UTF-8 must pass through unreplaced (the rune-based
// splitter substituted U+FFFD).
func TestSplitStatementsBytePreservation(t *testing.T) {
	stmt := "INSERT INTO t VALUES ('\xff\xfe raw bytes')"
	got := Split(stmt+";\nSELECT 1;", lexProfile("mysql"))
	if len(got) != 2 {
		t.Fatalf("got %d statements %v, want 2", len(got), got)
	}
	if got[0] != stmt {
		t.Errorf("invalid UTF-8 bytes not preserved:\ngot  %q\nwant %q", got[0], stmt)
	}
}

// TestScanScriptOpaqueFrames pins the frame contract: framed bytes replay
// VERBATIM as one statement — no string/comment interpretation, no trimming,
// no re-encoding — for exactly the bodies ordinary lexing would mangle.
func TestScanScriptOpaqueFrames(t *testing.T) {
	my := lexProfile("mysql")
	bodies := []string{
		// NBE trailing-backslash literal: ordinary MySQL lexing reads \' as an
		// escaped quote and would mis-split at the wrong ';'.
		"CREATE PROCEDURE p() BEGIN SET @x = 'a\\'; SET @y = 'b'; END",
		// cp932/Shift_JIS: 0x83 0x5C is one character whose TRAIL byte is a
		// backslash — routine and view variants.
		"CREATE PROCEDURE p() COMMENT '\x83\x5c' BEGIN SELECT 1; SELECT 2; END",
		"CREATE VIEW v1 AS SELECT '\x83\x5c' AS c",
		// A body ending in '$' must not splice into a '$$' terminator.
		"CREATE VIEW v2 AS SELECT 'ends in dollar: $",
		// A '$js$'-style body full of '$' runs (forces a non-$$ delimiter).
		"CREATE FUNCTION f() RETURNS INT BEGIN /* $$ ;; $$ */ RETURN 1; END",
	}
	for _, body := range bodies {
		script := "SELECT 0;\n" + frameScript(body) + "SELECT 9;"
		got := Split(script, my)
		if len(got) != 3 {
			t.Fatalf("frame for %q: got %d statements %v, want 3", body, len(got), got)
		}
		if got[1] != body {
			t.Errorf("frame body not byte-exact:\ngot  %q\nwant %q", got[1], body)
		}
		if got[0] != "SELECT 0" || got[2] != "SELECT 9" {
			t.Errorf("statements around the frame mangled: %q", got)
		}
	}

	// A frame marker whose DELIMITER line is missing degrades to an ordinary
	// comment — no opaque handling, ordinary lexing continues (the comment
	// line rides with the following statement, as leading comments always do).
	degraded := Split("-- tablex:v1 frame delimiter=$$\nSELECT 1;", my)
	if len(degraded) != 1 || !strings.HasSuffix(degraded[0], "SELECT 1") {
		t.Errorf("malformed frame did not degrade to a comment: %v", degraded)
	}

	// An unterminated frame (truncated dump) surfaces the remaining bytes so
	// the truncation fails loudly instead of vanishing.
	trunc := Split("-- tablex:v1 frame delimiter=$$\nDELIMITER $$\nCREATE PROCEDURE p() BEGIN", my)
	if len(trunc) != 1 || trunc[0] != "CREATE PROCEDURE p() BEGIN" {
		t.Errorf("unterminated frame = %v", trunc)
	}

	// Frames are DELIMITER-family machinery: engines without DelimiterDirectives
	// treat the marker as a plain comment.
	pgGot := Split("-- tablex:v1 frame delimiter=$$\nSELECT 1;", lexProfile("postgres"))
	if len(pgGot) != 1 || !strings.HasSuffix(pgGot[0], "SELECT 1") {
		t.Errorf("postgres profile mis-handled a frame marker: %v", pgGot)
	}
}

// TestSplitStatementsExternalDelimiterQuoteAware pins that ordinary (non-frame)
// DELIMITER blocks KEEP quote-aware lexing: an uploaded script may legally
// carry its delimiter inside a string literal.
func TestSplitStatementsExternalDelimiterQuoteAware(t *testing.T) {
	script := "DELIMITER //\nINSERT INTO t VALUES ('a//b')//\nSELECT 1//\nDELIMITER ;\nSELECT 2;"
	got := Split(script, lexProfile("mysql"))
	if len(got) != 3 {
		t.Fatalf("got %d statements %v, want 3", len(got), got)
	}
	if !strings.Contains(got[0], "'a//b'") {
		t.Errorf("quoted delimiter split the statement: %q", got[0])
	}
}

// TestScanScriptCollationMarkers: validated db-collation markers between
// statements become events at their stream position; marker-like text inside
// statements, strings, block comments or opaque frames never does.
func TestScanScriptCollationMarkers(t *testing.T) {
	my := lexProfile("mysql")
	marker := driver.FormatCollationMarker("routine", "r1", "utf8mb4_general_ci")

	// The marker line stays in place as an inert comment (it rides with the
	// following statement, like any leading comment); only the event is added,
	// at its position in the stream.
	events := Scan("SELECT 1;\n-- Procedure r1\n"+marker+"\nSELECT 2;", my)
	var kinds []string
	for _, ev := range events {
		if ev.Marker != nil {
			kinds = append(kinds, "marker:"+ev.Marker.Name)
		} else if strings.HasSuffix(ev.Stmt, "SELECT 1") {
			kinds = append(kinds, "SELECT 1")
		} else if strings.HasSuffix(ev.Stmt, "SELECT 2") {
			kinds = append(kinds, "SELECT 2")
		} else {
			kinds = append(kinds, ev.Stmt)
		}
	}
	want := []string{"SELECT 1", "marker:r1", "SELECT 2"}
	if strings.Join(kinds, "|") != strings.Join(want, "|") {
		t.Errorf("events = %v, want %v", kinds, want)
	}
	// CRLF input still recognizes the marker.
	if !hasMarkerEvent(Scan("SELECT 1;\r\n"+marker+"\r\nSELECT 2;", my)) {
		t.Error("CRLF marker line not recognized")
	}

	noEvent := []string{
		"SELECT '" + marker + "';",                                          // inside a string literal
		"SELECT 1,\n" + marker + "\n2;",                                     // mid-statement (line comment content)
		"/*\n" + marker + "\n*/ SELECT 1;",                                  // inside a block comment
		frameScript(marker),                                                 // inside an opaque frame body
		"-- tablex:v1 db-collation kind=routine name=0 value=00\nSELECT 1;", // malformed (odd hex)
	}
	for _, script := range noEvent {
		if hasMarkerEvent(Scan(script, my)) {
			t.Errorf("unexpected marker event in %q", script)
		}
	}
}

func hasMarkerEvent(events []Event) bool {
	for _, ev := range events {
		if ev.Marker != nil {
			return true
		}
	}
	return false
}

// TestEventBudgetAggregate pins the two failure modes the import preflight's
// hand-rolled remaining counter had: a section landing EXACTLY on the
// boundary must leave the budget exhausted (feeding the 0 remainder back into
// SplitLimit meant "no cap", disabling the preflight for every later
// section), and the unit is scanner EVENTS — a marker line consumes budget
// exactly as ScanLimit's own cap counts it, where a statement count
// undercounts.
func TestEventBudgetAggregate(t *testing.T) {
	p := lexProfile("postgres")

	// Boundary: the first section consumes the whole budget; the next
	// section's single statement must overflow, never run uncapped.
	b := NewEventBudget(2)
	if err := b.Consume("SELECT 1; SELECT 2;", p); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	if err := b.Consume("SELECT 3", p); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("exhausted budget must refuse the next event, got %v", err)
	}

	// A section lexing to nothing still passes on an exhausted budget.
	b = NewEventBudget(1)
	if err := b.Consume("SELECT 1", p); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	if err := b.Consume("-- only a comment\n", p); err != nil {
		t.Errorf("a no-event section must pass on an exhausted budget: %v", err)
	}

	// Events, not statements: a collation marker consumes budget too, exactly
	// as ScanLimit counts it.
	my := lexProfile("mysql")
	script := driver.FormatCollationMarker("routine", "f", "utf8mb4_general_ci") + "\nSELECT 1;"
	events, err := ScanLimit(script, my, 0)
	if err != nil || len(events) != 2 || events[0].Marker == nil {
		t.Fatalf("marker fixture lexes to %d events (err %v); this test needs a marker + a statement", len(events), err)
	}
	b = NewEventBudget(1)
	if err := b.Consume(script, my); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("a marker event must consume budget (statement-counting undercounts), got %v", err)
	}

	// max <= 0: no cap, nothing consumed.
	b = NewEventBudget(0)
	if err := b.Consume(strings.Repeat("SELECT 1;", 500), p); err != nil {
		t.Errorf("uncapped budget must accept anything: %v", err)
	}
}

func TestIsQueryStatement(t *testing.T) {
	queries := []string{"SELECT 1", "  select * from t", "WITH x AS (SELECT 1) SELECT * FROM x",
		"SHOW TABLES", "EXPLAIN SELECT 1", "PRAGMA table_info(t)", "-- c\nSELECT 1", "/* c */ select 1",
		"INSERT INTO t VALUES (1) RETURNING id", // RETURNING yields rows
		"UPDATE t SET x=1 RETURNING *",
		"WITH d AS (DELETE FROM t RETURNING id) SELECT * FROM d",
		// #14: a data-modifying CTE whose MAIN statement returns rows is a
		// query — the DML inside the CTE body must not route it to Exec (the
		// INSERT would run but the outer result set would be discarded).
		"WITH w AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM other",
		"WITH ins AS (UPDATE t SET x=1) TABLE other",
		"WITH ins AS (DELETE FROM t) VALUES (1)",
		// CTE header column list before the body paren.
		"WITH w (a, b) AS (INSERT INTO t VALUES (1,2)) SELECT * FROM w2",
		// A statement may OPEN with parentheses — '(' doubles as a keyword
		// separator in leadingKeyword, which used to truncate the keyword to ""
		// and run the query through Exec, discarding its rows.
		"(SELECT 1) UNION (SELECT 2)",
		"( SELECT 1 ) EXCEPT (SELECT 2)",
		"((SELECT 1))"}
	for _, q := range queries {
		if !IsQuery(q, lexProfile("postgres")) {
			t.Errorf("IsQuery(%q) = false, want true", q)
		}
	}
	nonQueries := []string{"INSERT INTO t VALUES (1)", "UPDATE t SET x=1", "DELETE FROM t",
		"CREATE TABLE t (id int)", "DROP TABLE t", "BEGIN",
		"WITH moved AS (DELETE FROM t) INSERT INTO archive SELECT 1", // data-modifying main stmt, no RETURNING
		"WITH w AS (SELECT 1) DELETE FROM t",                         // row-returning CTE feeding a DELETE
		"WITH w AS NOT MATERIALIZED (SELECT 1) UPDATE t SET x=1"}
	for _, q := range nonQueries {
		if IsQuery(q, lexProfile("postgres")) {
			t.Errorf("IsQuery(%q) = true, want false", q)
		}
	}
	// `#` only strips as a leading comment in MySQL.
	if IsQuery("# c\nSELECT 1", lexProfile("mysql")) != true {
		t.Error("MySQL: leading # comment then SELECT should be a query")
	}
}

// TestIsQueryStatementLiteralBlind pins R5(c): the RETURNING/DML keyword
// regexes must not match inside string literals or comments — an INSERT whose
// VALUES holds the word 'RETURNING' is an exec (mis-routing it to Query loses
// the affected-row count), and a WITH whose literal holds 'DELETE' stays a
// query.
func TestIsQueryStatementLiteralBlind(t *testing.T) {
	for _, c := range []struct {
		stmt   string
		engine string
		want   bool
	}{
		{"INSERT INTO t VALUES ('RETURNING')", "postgres", false},
		{"INSERT INTO t VALUES ('RETURNING')", "mysql", false},
		{"INSERT INTO t VALUES ('x') /* RETURNING */", "postgres", false},
		{"INSERT INTO t VALUES ('x') -- RETURNING", "postgres", false},
		{"INSERT INTO t VALUES ($$RETURNING$$)", "postgres", false},
		{"INSERT INTO t VALUES (E'RETURNING\\'s')", "postgres", false},
		{"WITH x AS (SELECT 'DELETE FROM t') SELECT * FROM x", "postgres", true},
		// Real clauses outside literals still classify as before.
		{"INSERT INTO t VALUES ('x') RETURNING id", "postgres", true},
		{"WITH moved AS (DELETE FROM t) INSERT INTO a SELECT 1", "postgres", false},
	} {
		if got := IsQuery(c.stmt, lexProfile(c.engine)); got != c.want {
			t.Errorf("IsQuery(%q, %s) = %v, want %v", c.stmt, c.engine, got, c.want)
		}
	}
}

// TestIsQueryStatementReturningGate pins the L2 capability + deny-set
// classification: an identifier named `returning` never routes a statement to
// the grid, a genuine RETURNING clause does (where the engine supports it), and
// MERGE … RETURNING gates on the version-populated capability.
func TestIsQueryStatementReturningGate(t *testing.T) {
	pg := lexProfile("postgres")         // INSERT/UPDATE/DELETE RETURNING; MERGE gated off (registered major 0)
	my := lexProfile("mysql")            // MySQL proper (registered): no RETURNING
	pg17 := driver.DefaultLexerProfile() // all-true Returning incl. MERGE, PG grammar

	// Identifiers named `returning` (table/column/CTE/ON CONFLICT target) must
	// NOT be treated as a RETURNING clause, even where the leading keyword IS
	// returning-capable (so the deny-set/depth logic is what blocks them).
	notClause := []string{
		"INSERT INTO returning VALUES (1)",
		"UPDATE returning SET x=1",
		"UPDATE t SET returning=1",
		"DELETE FROM t WHERE returning=5",
		"INSERT INTO t(returning) VALUES (1)",
		"INSERT INTO t VALUES (1) ON CONFLICT (returning) DO NOTHING",
		"WITH returning AS (SELECT 1) DELETE FROM t",
		"DELETE FROM t ORDER BY returning",
	}
	for _, q := range notClause {
		if IsQuery(q, pg) {
			t.Errorf("identifier `returning`: IsQuery(%q) = true, want false", q)
		}
	}
	if !IsQuery("SELECT returning FROM t", pg) {
		t.Error("SELECT of a column named returning should still be a query (via SELECT)")
	}

	// Genuine RETURNING clauses (predecessor is a value token / keyword outside
	// the deny set: VALUES, ), DEFAULT, NOTHING, a blanked literal's value).
	clause := []string{
		"INSERT INTO t VALUES (1) RETURNING id",
		"UPDATE t SET x=1 RETURNING *",
		"DELETE FROM t RETURNING id",
		"INSERT INTO t DEFAULT VALUES RETURNING id",
		"INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING RETURNING id",
		"UPDATE t SET a=DEFAULT RETURNING a",
		"UPDATE t SET a='x' RETURNING id",
		"WITH w AS (SELECT 1) INSERT INTO t VALUES (1) RETURNING id",
	}
	for _, q := range clause {
		if !IsQuery(q, pg) {
			t.Errorf("genuine RETURNING: IsQuery(%q) = false, want true", q)
		}
	}

	// MERGE … RETURNING gates on the capability: a query on the all-true profile
	// (PG 17+), a plain Exec on MySQL proper (no RETURNING anywhere).
	for _, q := range []string{
		"MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1 RETURNING id",
		"WITH w AS (SELECT 1) MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DELETE RETURNING id",
	} {
		if !IsQuery(q, pg17) {
			t.Errorf("MERGE RETURNING (PG17): IsQuery(%q) = false, want true", q)
		}
	}
	if IsQuery("INSERT INTO t VALUES (1) RETURNING id", my) {
		t.Error("MySQL proper: INSERT ... RETURNING has no support; should be Exec, not a query")
	}

	// Documented residual class (both cosmetic — the statement still executes):
	// a false positive (expression `returning`) and a false negative (a blanked
	// literal leaves a deny-set predecessor). Pinned as intentional.
	if !IsQuery("UPDATE t SET a = returning", pg) {
		t.Error("residual false positive should classify as a clause (accepted)")
	}
	if IsQuery("DELETE FROM t WHERE a AND 'yes' RETURNING id", pg) {
		t.Error("residual false negative should NOT classify (accepted)")
	}
}

// TestSplitStatementsBracketIdentifiers covers the B5 addition of
// LexerProfile.BracketIdentifiers. SQLite accepts [name] as a quoted identifier
// (the MS Access convention it kept for compatibility), so a separator inside
// one belongs to the name, not to the script. Engines where '[' is an operator
// (PostgreSQL array subscripts) leave the flag off and see no change.
func TestSplitStatementsBracketIdentifiers(t *testing.T) {
	sqlite, _ := driver.Get("sqlite")
	p := driver.ProfileOf(sqlite)
	if !p.BracketIdentifiers {
		t.Fatal("the SQLite profile should enable bracket identifiers")
	}

	got := Split(`CREATE TABLE t ([a;b] TEXT); SELECT 1`, p)
	want := []string{`CREATE TABLE t ([a;b] TEXT)`, `SELECT 1`}
	if len(got) != len(want) {
		t.Fatalf("split = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d = %q, want %q", i, got[i], want[i])
		}
	}

	// ]] is an escaped ']' and does not close the identifier.
	if got := Split(`SELECT [a]]b;c] FROM t`, p); len(got) != 1 {
		t.Errorf("escaped ]] split the statement: %q", got)
	}

	// An UNTERMINATED bracket must not swallow the rest of the script: a syntax
	// error has to stay a syntax error rather than silently truncating the run.
	if got := Split(`SELECT [oops; SELECT 2`, p); len(got) != 2 {
		t.Errorf("unterminated bracket swallowed the script: %q", got)
	}

	// PostgreSQL leaves the flag off, so '[' stays an array subscript.
	pg, _ := driver.Get("postgres")
	pgProfile := driver.ProfileOf(pg)
	if pgProfile.BracketIdentifiers {
		t.Error("PostgreSQL must not enable bracket identifiers: '[' is an array subscript there")
	}
	if got := Split(`SELECT a[1]; SELECT 2`, pgProfile); len(got) != 2 {
		t.Errorf("array subscript broke PostgreSQL splitting: %q", got)
	}
}

// TestSplitStatementsBatchSeparator covers the B5 addition of
// LexerProfile.BatchSeparator with a T-SQL-shaped profile. This is the point of
// the finding: an engine with `GO` batches and [bracket] identifiers is now
// expressible entirely from a dialect's LexerProfile, with no change to
// internal/driver or to the splitter. No built-in engine sets it, so the
// profile here is what a fifth dialect would return.
func TestSplitStatementsBatchSeparator(t *testing.T) {
	tsql := driver.LexerProfile{
		BracketIdentifiers: true,
		BatchSeparator:     "GO",
	}

	script := "CREATE TABLE [dbo].[t] (id int)\nGO\nSELECT 1\ngo\nSELECT 2\n"
	got := Split(script, tsql)
	want := []string{"CREATE TABLE [dbo].[t] (id int)", "SELECT 1", "SELECT 2"}
	if len(got) != len(want) {
		t.Fatalf("split = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The separator is client-side: it must never reach the server.
	for _, s := range got {
		if strings.EqualFold(strings.TrimSpace(s), "GO") {
			t.Errorf("the batch separator was emitted as a statement: %q", got)
		}
	}

	// Only a line of its own separates. `GO` as an identifier or inside a
	// statement is ordinary text.
	if got := Split("SELECT go FROM t\nGO\n", tsql); len(got) != 1 || got[0] != "SELECT go FROM t" {
		t.Errorf("a GO used as an identifier split the statement: %q", got)
	}

	// An engine with no batch separator (every built-in one) is unaffected.
	plain := driver.LexerProfile{}
	if got := Split("SELECT 1\nGO\nSELECT 2\n", plain); len(got) != 1 {
		t.Errorf("GO separated statements for a profile that declares none: %q", got)
	}
}

// TestSplitStatementsBackslashMode pins that BackslashStrings alone decides the
// string grammar the splitter lexes with. The script below is legal
// NO_BACKSLASH_ESCAPES MySQL: each backslash is a literal character, so 'a\' is
// a complete string and the script holds two statements. A profile that keeps
// backslash escapes reads the same \' as an escaped quote, the first string
// swallows the real boundary, and the whole script lexes as one statement (the
// trailing unterminated string still emits — pinned by the plain-profile case
// above).
func TestSplitStatementsBackslashMode(t *testing.T) {
	script := `INSERT INTO t VALUES ('a\');` + "\n" + `INSERT INTO t VALUES ('b');`

	nbe := driver.LexerProfile{BackslashStrings: false}
	got := Split(script, nbe)
	want := []string{`INSERT INTO t VALUES ('a\')`, `INSERT INTO t VALUES ('b')`}
	if len(got) != len(want) {
		t.Fatalf("NBE split = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NBE statement %d = %q, want %q", i, got[i], want[i])
		}
	}

	// Under default backslash escaping no top-level separator survives: both
	// semicolons sit inside string literals as this grammar reads them.
	esc := driver.LexerProfile{BackslashStrings: true}
	got = Split(script, esc)
	if len(got) != 1 || got[0] != script {
		t.Errorf("escape-mode split = %q, want the whole script as one statement", got)
	}
}

// TestScanLimit — Scan materializes the WHOLE event slice before anything runs,
// so a pathological script is a memory failure rather than a slow request, and
// Go cannot recover from an allocation failure the way the panic middleware
// recovers from a panic.
func TestScanLimit(t *testing.T) {
	p := driver.DefaultLexerProfile()
	script := strings.Repeat("SELECT 1;", 10)

	if _, err := ScanLimit(script, p, 4); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("over-limit scan err = %v, want ErrTooManyStatements", err)
	}
	// Fails rather than truncating: a prefix of an import is a partial restore.
	if evs, _ := ScanLimit(script, p, 4); evs != nil {
		t.Errorf("an over-limit scan returned %d events; it must return none", len(evs))
	}
	// Exactly at the limit is accepted; above it and uncapped are equivalent.
	for _, max := range []int{10, 11, 0, -1} {
		evs, err := ScanLimit(script, p, max)
		if err != nil || len(evs) != 10 {
			t.Errorf("ScanLimit(max=%d) = %d events, err %v; want 10, nil", max, len(evs), err)
		}
	}
	// Split and Scan keep their signatures, which is what leaves every existing
	// caller — including the index predicate — compiling untouched.
	if got := len(Split(script, p)); got != 10 {
		t.Errorf("Split = %d statements, want 10", got)
	}
	if _, err := SplitLimit(script, p, 4); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("SplitLimit over the limit did not report ErrTooManyStatements")
	}
}

// TestScanLimitCountsEveryEvent: the cap is applied at the APPEND, not per
// statement, because frame bodies and collation markers consume entries too — a
// script of nothing but markers would otherwise be uncapped.
func TestScanLimitCountsEveryEvent(t *testing.T) {
	p := driver.DefaultLexerProfile()
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteString("-- tablex:v1 db-collation kind=routine name=6162 value=6364\n")
	}
	markers := 0
	for _, ev := range Scan(b.String(), p) {
		if ev.Marker != nil {
			markers++
		}
	}
	// Not a Skip: a fixture that stopped parsing would make this test vacuous
	// while still reporting PASS, which is the failure mode it exists to prevent.
	if markers != 8 {
		t.Fatalf("the marker fixture produced %d marker events, want 8 — it no longer parses, so this test would prove nothing", markers)
	}
	if _, err := ScanLimit(b.String(), p, markers-1); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("a marker-only script was not capped: %d markers slipped past a limit of %d", markers, markers-1)
	}
}
