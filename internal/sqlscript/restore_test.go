package sqlscript

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSplitRestoreSections covers the \connect coordinator for PostgreSQL
// server-scope dumps.
func TestSplitRestoreSections(t *testing.T) {
	script := "SET x = 1;\n\\connect \"app db\"\nCREATE TABLE t (id int);\n\\c other\nSELECT 1;"
	secs, err := SplitRestoreSections(script, true, 0)
	if err != nil {
		t.Fatalf("SplitRestoreSections: %v", err)
	}
	if len(secs) != 3 {
		t.Fatalf("got %d sections, want 3: %+v", len(secs), secs)
	}
	if secs[0].DB != "" || !strings.Contains(secs[0].Script, "SET x = 1") {
		t.Errorf("section 0 = %+v", secs[0])
	}
	if secs[1].DB != "app db" || !strings.Contains(secs[1].Script, "CREATE TABLE t") {
		t.Errorf("section 1 = %+v", secs[1])
	}
	if secs[2].DB != "other" || !strings.Contains(secs[2].Script, "SELECT 1") {
		t.Errorf("section 2 = %+v", secs[2])
	}

	// No markers → one section against the import target.
	plain, err := SplitRestoreSections("SELECT 1;", true, 0)
	if err != nil || len(plain) != 1 || plain[0].DB != "" {
		t.Errorf("plain script sections = %+v (err %v)", plain, err)
	}
}

// TestSplitRestoreSectionsGatedAndQuoteAware covers R2: without allowConnect
// (any non-PG engine, or a db/table-scoped import) a \connect line is inert
// content — never a database switch (the scope violation the gate removes) —
// and with it, a \connect inside a string/dollar-quote/comment is content,
// while an unterminated quoted name on a real marker is a hard error.
func TestSplitRestoreSectionsGatedAndQuoteAware(t *testing.T) {
	script := "SET x = 1;\n\\connect other\nSELECT 1;"
	secs, err := SplitRestoreSections(script, false, 0)
	if err != nil {
		t.Fatalf("gated split: %v", err)
	}
	if len(secs) != 1 || secs[0].DB != "" || !strings.Contains(secs[0].Script, `\connect other`) {
		t.Fatalf("allowConnect=false must yield one target-bound section with the line intact: %+v", secs)
	}

	// \connect inside literals/comments must not split (quote-aware scan).
	for _, in := range []string{
		"INSERT INTO t VALUES ('a\n\\connect other\nb');\nSELECT 1;",
		"INSERT INTO t VALUES (E'a\\'\n\\connect other\n');\nSELECT 1;",
		"CREATE FUNCTION f() RETURNS void AS $$\n\\connect other\n$$ LANGUAGE sql;\nSELECT 1;",
		"/* docs:\n\\connect other\n*/\nSELECT 1;",
	} {
		secs, err := SplitRestoreSections(in, true, 0)
		if err != nil {
			t.Errorf("split(%q): %v", in, err)
			continue
		}
		if len(secs) != 1 || secs[0].DB != "" {
			t.Errorf("literal-embedded \\connect split the script: %q → %+v", in, secs)
		}
	}

	// Whitespace-indented markers still split; the marker line is consumed.
	secs, err = SplitRestoreSections("SELECT 1;\n  \\c other\nSELECT 2;", true, 0)
	if err != nil || len(secs) != 2 || secs[1].DB != "other" {
		t.Errorf("indented marker: %+v (err %v)", secs, err)
	}

	// A \connect that follows a same-line block comment is NOT line-leading, so
	// it stays content (a block comment is content on its line) — consistent
	// with `SELECT 1; \connect x` on one line not splitting.
	secs, err = SplitRestoreSections("/* c */\\connect other\nSELECT 1;", true, 0)
	if err != nil || len(secs) != 1 || secs[0].DB != "" {
		t.Errorf("block-comment-then-\\connect on one line must not split: %+v (err %v)", secs, err)
	}

	// Unterminated quoted name on a recognized marker: hard error, no guess.
	if _, err := SplitRestoreSections("SELECT 1;\n\\connect \"broken\nSELECT 2;", true, 0); err == nil {
		t.Error("unterminated quoted \\connect name should be a hard import error")
	}
}

func TestParseConnectLine(t *testing.T) {
	cases := []struct {
		in      string
		db      string
		ok      bool
		wantErr bool
	}{
		{`\connect mydb`, "mydb", true, false},
		{`\c mydb`, "mydb", true, false},
		{`  \connect "quoted db"  `, "quoted db", true, false},
		{`\connect "with""quote"`, `with"quote`, true, false},
		// psql tokenization: the name ends at the first unquoted whitespace;
		// trailing username/host/port arguments are ignored.
		{`\connect "db" user`, "db", true, false},
		{`\connect mydb admin localhost 5432`, "mydb", true, false},
		{`\connect "a b"c`, "a bc", true, false}, // quoted splices with adjacent text
		{`\connect`, "", false, false},
		{`\cd mydb`, "", false, false}, // \cd is not \c with argument d
		{`-- \connect mydb`, "", false, false},
		{`SELECT 1;`, "", false, false},
		{`\connect "broken`, "", false, true}, // unterminated quote: hard error
	}
	for _, c := range cases {
		db, ok, err := ParseConnectLine(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseConnectLine(%q) expected an error, got (%q,%v)", c.in, db, ok)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseConnectLine(%q): %v", c.in, err)
			continue
		}
		if db != c.db || ok != c.ok {
			t.Errorf("ParseConnectLine(%q) = (%q,%v), want (%q,%v)", c.in, db, ok, c.db, c.ok)
		}
	}
}

// TestSplitRestoreSectionsBounded — the section list was built without a bound,
// so millions of tiny \connect lines produced an unbounded []Section before a
// single statement was lexed. Same exhaustion ScanLimit closes one level down.
func TestSplitRestoreSectionsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "\\connect db%d\nSELECT %d;\n", i, i)
	}
	script := b.String()

	if _, err := SplitRestoreSections(script, true, 4); !errors.Is(err, ErrTooManyStatements) {
		t.Errorf("over-limit split err = %v, want ErrTooManyStatements", err)
	}
	// Nothing partial comes back: a prefix of a restore is a half-applied one.
	if secs, _ := SplitRestoreSections(script, true, 4); secs != nil {
		t.Errorf("an over-limit split returned %d sections; it must return none", len(secs))
	}
	// At the limit exactly, and above it, the split succeeds.
	if secs, err := SplitRestoreSections(script, true, 10); err != nil || len(secs) != 10 {
		t.Errorf("at the limit: %d sections, err %v; want 10, nil", len(secs), err)
	}
	if secs, err := SplitRestoreSections(script, true, 0); err != nil || len(secs) != 10 {
		t.Errorf("uncapped: %d sections, err %v; want 10, nil", len(secs), err)
	}

	// allowConnect is NOT droppable, and the cap must not weaken it: with the
	// gate off the whole script is ONE inert section, markers and all, however
	// many \connect lines it carries.
	secs, err := SplitRestoreSections(script, false, 4)
	if err != nil {
		t.Fatalf("allowConnect=false with a cap: %v", err)
	}
	if len(secs) != 1 || secs[0].DB != "" {
		t.Fatalf("allowConnect=false yielded %d sections (first db %q); want exactly 1 targeting the import database", len(secs), secs[0].DB)
	}
	if !strings.Contains(secs[0].Script, `\connect db0`) {
		t.Error("the marker was consumed rather than left inert as script content")
	}
}
