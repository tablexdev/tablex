package handlers

// Index options. Two things are worth testing here rather than through HTTP:
// the key-part rows, whose whole reason for existing is that a multi-select
// could not express ORDER; and the partial-index predicate, which is the second
// and last place TableX puts user-written SQL into a statement it builds.

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

var idxCols = []model.Column{{Name: "a"}, {Name: "b"}, {Name: "c"}}

// defProf is the grammar these tests split under unless a case needs another
// one. DefaultLexerProfile already carries dollar quoting and E'…' escape
// strings, so most engine-specific cases below need no dialect import; the two
// that do (bracket identifiers, a routine-body regex) build a literal profile.
func defProf() driver.LexerProfile { return driver.DefaultLexerProfile() }

func allOpts() driver.IndexOptions {
	return driver.IndexOptions{
		Methods:         []string{"btree", "gin"},
		SupportsDesc:    true,
		SupportsPrefix:  true,
		SupportsPartial: true,
	}
}

// TestIndexKeyPartsOrder: the rows are read in FORM order, and that order IS
// the key order. A composite index on (b, a) means something different from one
// on (a, b), and the multi-select this replaced could only ever submit DOM
// order.
func TestIndexKeyPartsOrder(t *testing.T) {
	form := url.Values{
		"index_columns":  {"b", "", "a"}, // row 1 left blank
		"index_prefix_0": {"5"},
		"index_desc_2":   {"1"},
	}
	got, err := indexKeyParts(form, allOpts(), idxCols)
	if err != nil {
		t.Fatalf("indexKeyParts: %v", err)
	}
	want := []driver.IndexColumn{{Name: "b", Prefix: 5}, {Name: "a", Desc: true}}
	if len(got) != len(want) {
		t.Fatalf("got %d key parts, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key part %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestIndexKeyPartsPairsByRow is the subtle one: a blank row still occupies its
// index, so index_prefix_N must pair with the Nth SUBMITTED select, not the Nth
// non-empty one. Getting this wrong silently attaches a prefix to a different
// column.
func TestIndexKeyPartsPairsByRow(t *testing.T) {
	got, err := indexKeyParts(url.Values{
		"index_columns":  {"", "a", "b"},
		"index_prefix_1": {"7"},
		"index_prefix_2": {"9"},
	}, allOpts(), idxCols)
	if err != nil {
		t.Fatalf("indexKeyParts: %v", err)
	}
	if len(got) != 2 || got[0] != (driver.IndexColumn{Name: "a", Prefix: 7}) || got[1] != (driver.IndexColumn{Name: "b", Prefix: 9}) {
		t.Errorf("a blank leading row shifted the prefixes: %+v", got)
	}
}

func TestIndexKeyPartsRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
		opts driver.IndexOptions
		want string
	}{
		{"no columns", url.Values{"index_columns": {"", ""}}, allOpts(), "at least one column"},
		{"unknown column", url.Values{"index_columns": {"nope"}}, allOpts(), "Unknown column"},
		{"repeated column", url.Values{"index_columns": {"a", "a"}}, allOpts(), "listed twice"},
		{"prefix unsupported", url.Values{"index_columns": {"a"}, "index_prefix_0": {"5"}},
			driver.IndexOptions{}, "prefix"},
		{"desc unsupported", url.Values{"index_columns": {"a"}, "index_desc_0": {"1"}},
			driver.IndexOptions{}, "descending"},
		{"prefix not a number", url.Values{"index_columns": {"a"}, "index_prefix_0": {"10)"}},
			allOpts(), "Invalid prefix"},
		{"prefix zero", url.Values{"index_columns": {"a"}, "index_prefix_0": {"0"}}, allOpts(), "Invalid prefix"},
		{"prefix negative", url.Values{"index_columns": {"a"}, "index_prefix_0": {"-1"}}, allOpts(), "Invalid prefix"},
		{"prefix absurd", url.Values{"index_columns": {"a"}, "index_prefix_0": {"999999"}}, allOpts(), "Invalid prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := indexKeyParts(tc.form, tc.opts, idxCols)
			if err == nil {
				t.Fatalf("accepted %v → %+v", tc.form, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestIndexMethodIsAllowlisted — the method is emitted as a bare keyword, so
// only an exact entry from the engine's own list may reach the statement.
func TestIndexMethodIsAllowlisted(t *testing.T) {
	opts := allOpts()
	if got, err := indexMethod(url.Values{"index_method": {"gin"}}, opts); err != nil || got != "gin" {
		t.Errorf("gin = %q, %v", got, err)
	}
	if got, err := indexMethod(url.Values{}, opts); err != nil || got != "" {
		t.Errorf("unset = %q, %v; want the engine default", got, err)
	}
	// Surrounding whitespace is form noise and is trimmed; the value itself
	// still has to match exactly.
	if got, err := indexMethod(url.Values{"index_method": {"  btree "}}, opts); err != nil || got != "btree" {
		t.Errorf("padded method = %q, %v", got, err)
	}
	for _, bad := range []string{"GIN", "hash", "btree) WHERE (1=1", "; DROP TABLE t", "bt ree"} {
		if got, err := indexMethod(url.Values{"index_method": {bad}}, opts); err == nil {
			t.Errorf("accepted method %q → %q", bad, got)
		}
	}
	// An engine offering no methods accepts none.
	if _, err := indexMethod(url.Values{"index_method": {"btree"}}, driver.IndexOptions{}); err == nil {
		t.Error("a method was accepted for an engine that offers none")
	}
}

// TestIndexPredicateGuard covers the one place besides the SQL console where
// user-written SQL is placed into a statement TableX builds. The guard does not
// try to be a parser: it establishes that the clause cannot END the CREATE
// INDEX and start something else, which is the property that matters.
func TestIndexPredicateGuard(t *testing.T) {
	opts := allOpts()
	for _, ok := range []string{
		"qty > 0",
		"status = 'active'",
		"(a IS NOT NULL AND b > 1) OR c = 'x'",
		"name LIKE 'a''b%'", // an escaped quote inside a literal
		"deleted_at IS NULL",
	} {
		got, err := indexPredicate(url.Values{"index_where": {ok}}, opts, defProf())
		if err != nil {
			t.Errorf("indexPredicate(%q): %v", ok, err)
			continue
		}
		if got != ok {
			t.Errorf("indexPredicate(%q) = %q; a valid predicate must pass through unchanged", ok, got)
		}
	}

	for _, tc := range []struct{ in, want string }{
		{"1=1; DROP TABLE users", "single expression"},
		{"1=1 -- hide the rest", "comment"},
		{"1=1 /* hide */", "comment"},
		{"1=1 # hide", "comment"},
		{"a > 0)", "unbalanced"},
		{"(a > 0", "unbalanced"},
		{"a = 'unterminated", "unterminated"},
		{strings.Repeat("a", indexPredicateMaxLen+1), "too long"},
	} {
		if got, err := indexPredicate(url.Values{"index_where": {tc.in}}, opts, defProf()); err == nil {
			t.Errorf("accepted %q → %q", tc.in, got)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("indexPredicate(%q) error = %q, want it to mention %q", tc.in, err, tc.want)
		}
	}

	// A ';' or a comment marker INSIDE a string literal is data, not structure:
	// the guard must not reject a legitimate predicate over such a value.
	for _, ok := range []string{"note = 'a;b'", "note = '-- not a comment'", "note = '/*'"} {
		if _, err := indexPredicate(url.Values{"index_where": {ok}}, opts, defProf()); err != nil {
			t.Errorf("indexPredicate(%q) rejected a literal containing structure characters: %v", ok, err)
		}
	}

	// And an engine without partial indexes refuses the clause outright.
	if _, err := indexPredicate(url.Values{"index_where": {"a > 0"}}, driver.IndexOptions{}, defProf()); err == nil {
		t.Error("a predicate was accepted for an engine with no partial indexes")
	}
	if got, err := indexPredicate(url.Values{}, driver.IndexOptions{}, defProf()); err != nil || got != "" {
		t.Errorf("an absent predicate must be fine everywhere: %q, %v", got, err)
	}
}

// TestIndexPredicateSplitsUnderTheDialectGrammar pins the guarantee the
// hand-rolled scan could not make. Every payload here ended that scan with
// inStr=false and depth=0 and was returned UNCHANGED, because it tracked only
// the plain single quote — so the quoting form the engine actually uses hid the separators from
// it. The splitter reads them, and the clause is appended last, so a payload
// that survived became statement 2..n of a CREATE INDEX batch.
func TestIndexPredicateSplitsUnderTheDialectGrammar(t *testing.T) {
	opts := allOpts()
	for _, tc := range []struct{ name, in, want string }{
		{
			// Four quotes in total, all inside dollar-quoted spans: the ' tracker
			// saw them pair up and read every ';' '(' ')' as literal content.
			"dollar-quoted payload",
			`id > 0 AND 'x' <> $$'$$ ; CREATE TABLE public.pwned(a int) ; SELECT $$'$$`,
			"single expression",
		},
		{
			// The same trick spelled with double quotes, which is the form that
			// reaches SQLite (its profile makes '$' an ordinary word rune, so the
			// payload above is not the one that would be aimed at it).
			"double-quoted payload",
			`a <> "'" ; DROP TABLE t ; SELECT "'"`,
			"single expression",
		},
		// Split strips a trailing separator before returning, so len==1 alone
		// would have quietly ACCEPTED this. Comparing against the input is what
		// keeps today's answer.
		{"trailing separator", "a > 0;", "single expression"},
		// The profile is load-bearing in both directions: without a RoutineBodyRe
		// the splitter never tracks BEGIN…END depth, so the ';' is top level.
		{"routine body with no routine regex", "CREATE FUNCTION f() BEGIN ; END", "single expression"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := indexPredicate(url.Values{"index_where": {tc.in}}, opts, defProf())
			if err == nil {
				t.Fatalf("accepted %q → %q", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestIndexPredicateMessageChanges pins the two inputs whose refusal MESSAGE
// moved when the naive ';' check was deleted. Both are still refused; neither
// was covered by a test before, which is why they are written down here rather
// than discovered later as a behaviour change.
func TestIndexPredicateMessageChanges(t *testing.T) {
	opts := allOpts()
	for _, tc := range []struct{ name, in, want string }{
		// Reached the comment error before. The splitter drops a comment-only
		// chunk to ZERO statements, so it is refused one check earlier.
		{"comment only", "-- x", "single expression"},
		// The backslash escapes the first closing quote, so the trailing one
		// OPENS a literal that never closes — which is what the ' tracker reports
		// now that it is no longer pre-empted by the ';'.
		{"escaped quote in an escape string", `E'a\';b'`, "unterminated string literal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := indexPredicate(url.Values{"index_where": {tc.in}}, opts, defProf())
			if err == nil {
				t.Fatalf("accepted %q → %q", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestIndexPredicateAcceptsSeparatorsInsideQuotedSpans records the six classes
// that flip refused → accepted, deliberately rather than by discovery. Each is
// a ';' inside a span the ENGINE considers quoted — the identical rule that
// already applied to '…' (pinned above as note = 'a;b'). None is exploitable:
// the predicate is appended LAST, so statement 1 is always the CREATE INDEX
// itself, and an unterminated span or a bare routine body makes that statement
// a parse error before anything runs.
//
// The engine qualifier on each case is load-bearing, so the contrast table
// below asserts the other grammar still refuses it.
func TestIndexPredicateAcceptsSeparatorsInsideQuotedSpans(t *testing.T) {
	opts := allOpts()
	// SQLite: '[' quotes an identifier. PostgreSQL uses it for array subscripts
	// and leaves the flag off.
	brackets := driver.LexerProfile{BracketIdentifiers: true}
	// The shape both PostgreSQL and SQLite carry, spelled here as a literal so
	// this stays a handlers-package unit test with no dialect import.
	routines := driver.LexerProfile{
		RoutineBodyRe: regexp.MustCompile(`(?is)^CREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE)\b`),
	}
	for _, tc := range []struct {
		name string
		in   string
		prof driver.LexerProfile
	}{
		// sqlscript's quote case is `case '\'', '"', '`':` — unconditional, so
		// these two hold under every profile.
		{"double-quoted identifier", `"a;b" > 0`, defProf()},
		{"backquoted identifier", "`a;b` > 0", defProf()},
		{"bracket-quoted identifier", "[a;b] > 0", brackets},
		{"dollar-quoted literal", "note = $$a;b$$", defProf()},
		{"escape-string literal", `E'\';\''`, defProf()},
		// The skip functions run to end-of-input, so the whole clause comes back
		// as one statement. Harmless: it cannot prepare on either engine.
		{"unterminated quoted span", `a = "x ; DROP TABLE t`, defProf()},
		// The one case where the splitter's verdict disagrees with the engine's
		// own parser — and the CREATE INDEX in front of it fails first.
		{"routine body", "CREATE FUNCTION f() BEGIN ; END", routines},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := indexPredicate(url.Values{"index_where": {tc.in}}, opts, tc.prof)
			if err != nil {
				t.Fatalf("indexPredicate(%q): %v", tc.in, err)
			}
			if got != tc.in {
				t.Errorf("indexPredicate(%q) = %q; an accepted predicate passes through unchanged", tc.in, got)
			}
		})
	}

	// Same inputs, the grammar that does NOT enable the construct: still refused.
	for _, tc := range []struct {
		name string
		in   string
		prof driver.LexerProfile
	}{
		{"bracket identifier without the flag", "[a;b] > 0", defProf()},
		{"dollar quote where $ is a word rune", "note = $$a;b$$", driver.LexerProfile{DollarInWords: true}},
		{"escape string without EscapeStringE", `E'\';\''`, driver.LexerProfile{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := indexPredicate(url.Values{"index_where": {tc.in}}, opts, tc.prof); err == nil {
				t.Errorf("accepted %q under a grammar that does not enable it → %q", tc.in, got)
			}
		})
	}
}
