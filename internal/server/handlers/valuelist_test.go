package handlers

// ENUM/SET value lists. These are the only user-supplied strings that reach a
// TYPE definition, where no placeholder can carry them, so the quoting is the
// whole security story — and the parse that prefills the editor is deliberately
// never trusted to round-trip (an untouched list is carried through as the
// original type string), which these tests pin from both ends.

import (
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	"github.com/tablexdev/tablex/internal/model"
)

func mysqlEditor(t *testing.T) (driver.Dialect, driver.SchemaEditor) {
	t.Helper()
	d, ok := driver.Get("mysql")
	if !ok {
		t.Fatal("mysql dialect is not registered")
	}
	return d, d.(driver.SchemaEditor)
}

func TestColumnTypeValueList(t *testing.T) {
	d, editor := mysqlEditor(t)
	build := func(base, values string) (string, error) {
		return columnType(d, editor, url.Values{"col_values": {values}}, base, nil)
	}

	if got, err := build("ENUM", "a\nb\nc"); err != nil || got != `ENUM('a','b','c')` {
		t.Errorf("ENUM(a,b,c) = %q, %v", got, err)
	}
	if got, err := build("SET", "read\nwrite"); err != nil || got != `SET('read','write')` {
		t.Errorf("SET = %q, %v", got, err)
	}
	// A comma inside a value is not a problem, because the list is
	// newline-separated rather than comma-separated.
	if got, err := build("ENUM", "a,b\nc"); err != nil || got != `ENUM('a,b','c')` {
		t.Errorf("value containing a comma = %q, %v", got, err)
	}
	// The quoting is the point: a value that tries to close the literal must be
	// escaped, not honoured.
	for _, hostile := range []string{
		`x'),('injected`,
		`a' , (SELECT 1)) -- `,
		`back\slash`,
		"new\nline", // cannot arrive through the form, but the builder is public
	} {
		got, err := build("ENUM", strings.ReplaceAll(hostile, "\n", "\\n"))
		if err != nil {
			t.Errorf("ENUM(%q): %v", hostile, err)
			continue
		}
		if !strings.HasPrefix(got, "ENUM('") || !strings.HasSuffix(got, "')") {
			t.Errorf("ENUM(%q) = %q; the value escaped its literal", hostile, got)
		}
		// Exactly one member: an unescaped quote would have produced more.
		if n := strings.Count(got, "','"); n != 0 {
			t.Errorf("ENUM(%q) = %q; it became %d members", hostile, got, n+1)
		}
	}

	for _, tc := range []struct{ name, base, values, want string }{
		{"no values", "ENUM", "", "at least one value"},
		{"blank lines only", "ENUM", "\n\n  \n", "at least one value"},
		{"duplicate", "ENUM", "a\nb\na", "duplicate"},
		// MySQL compares members case-insensitively under the usual collations,
		// so these two would collide on the server.
		{"case duplicate", "SET", "a\nA", "duplicate"},
		{"NUL byte", "ENUM", "a\x00b", "NUL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := build(tc.base, tc.values)
			if err == nil {
				t.Fatalf("accepted %q → %q", tc.values, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}

	// A SET holds at most 64 members; the 65th is refused here rather than by
	// the server.
	var many []string
	for i := range 65 {
		many = append(many, string(rune('a'+i%26))+strings.Repeat("x", i))
	}
	if _, err := build("SET", strings.Join(many, "\n")); err == nil {
		t.Error("a 65-member SET was accepted")
	}
	if _, err := build("SET", strings.Join(many[:64], "\n")); err != nil {
		t.Errorf("a 64-member SET was refused: %v", err)
	}

	// A non-list type ignores col_values entirely and still reads col_length.
	if got, err := columnType(d, editor, url.Values{
		"col_length": {"20"}, "col_values": {"a\nb"},
	}, "VARCHAR", nil); err != nil || got != "VARCHAR(20)" {
		t.Errorf("VARCHAR with a stray value list = %q, %v", got, err)
	}
}

// TestColumnTypeValueListUnchangedIsVerbatim is the safety property behind the
// best-effort prefill parse: if the user does not edit the list, the column's
// ORIGINAL type string is reused, so a member columnValuesForForm displayed
// imperfectly can never be written back imperfectly.
func TestColumnTypeValueListUnchangedIsVerbatim(t *testing.T) {
	d, editor := mysqlEditor(t)
	existing := model.Column{BaseType: "enum", DataType: `enum('small','medium','large')`}

	got, err := columnType(d, editor, url.Values{
		"col_values": {columnValuesForForm(existing)},
	}, "ENUM", &existing)
	if err != nil {
		t.Fatalf("unchanged list: %v", err)
	}
	if got != existing.DataType {
		t.Errorf("unchanged list rebuilt the type as %q; want the original %q verbatim", got, existing.DataType)
	}

	// An EDITED list is rebuilt, canonically cased, through the dialect.
	got, err = columnType(d, editor, url.Values{"col_values": {"small\nlarge"}}, "ENUM", &existing)
	if err != nil {
		t.Fatalf("edited list: %v", err)
	}
	if got != `ENUM('small','large')` {
		t.Errorf("edited list = %q", got)
	}
}

// TestColumnTypeValueListBaseTypeChangeIsHonoured: the verbatim shortcut above
// keys on the MEMBERS, and ENUM and SET carry the same members — so switching
// one to the other without touching the textarea used to return the ORIGINAL
// type, leaving the column exactly as it was while the UI reported success.
// The base type has to agree before the shortcut applies.
func TestColumnTypeValueListBaseTypeChangeIsHonoured(t *testing.T) {
	d, editor := mysqlEditor(t)
	for _, tc := range []struct{ name, from, to, dataType, want string }{
		{"enum to set", "enum", "SET", `enum('read','write')`, `SET('read','write')`},
		{"set to enum", "set", "ENUM", `set('read','write')`, `ENUM('read','write')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := model.Column{BaseType: tc.from, DataType: tc.dataType}
			got, err := columnType(d, editor, url.Values{
				"col_values": {columnValuesForForm(existing)}, // untouched
			}, tc.to, &existing)
			if err != nil {
				t.Fatalf("%s with an untouched member list: %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("%s with an untouched member list = %q, want %q — the type change was silently dropped", tc.name, got, tc.want)
			}
		})
	}

	// The shortcut still applies when only the SPELLING of the base type
	// differs: the form posts the allowlist casing ("ENUM") while introspection
	// reports "enum", and that must not count as a type change.
	existing := model.Column{BaseType: "enum", DataType: `enum('small','medium','large')`}
	got, err := columnType(d, editor, url.Values{
		"col_values": {columnValuesForForm(existing)},
	}, "ENUM", &existing)
	if err != nil {
		t.Fatalf("same type in the allowlist's casing: %v", err)
	}
	if got != existing.DataType {
		t.Errorf("same type in the allowlist's casing = %q; want the original %q verbatim", got, existing.DataType)
	}
}

func TestColumnValuesForForm(t *testing.T) {
	for _, tc := range []struct{ dataType, want string }{
		{`enum('a','b','c')`, "a\nb\nc"},
		{`set('read','write')`, "read\nwrite"},
		{`enum('a''b')`, "a'b"},         // doubled quote
		{`enum('a\\b')`, `a\b`},         // backslash escape
		{`enum('x, y','z')`, "x, y\nz"}, // a comma inside a member
		{`varchar(255)`, ""},            // not a value list at all
		{`decimal(10,2)`, ""},           //
		{`timestamp`, ""},               // no parentheses
		{`enum('a`, ""},                 // unterminated: offer nothing
		{`timestamp(3) with tz`, ""},    // parenthesised but not closing
		{`enum('a','b'`, ""},            // truncated
		{`enum()`, ""},                  // empty list
		{`enum('')`, ""},                // one empty member renders as nothing
		{`enum('a','','b')`, "a\n\nb"},  // an empty member in the middle survives
		{`enum('it''s','o\'k')`, "it's\no'k"},
	} {
		if got := columnValuesForForm(model.Column{DataType: tc.dataType}); got != tc.want {
			t.Errorf("columnValuesForForm(%q) = %q, want %q", tc.dataType, got, tc.want)
		}
	}
}

func TestValueListFromForm(t *testing.T) {
	// Browsers post textarea content with CRLF; a trailing \r would define
	// "a\r" as a member that looks exactly like "a" in every later listing.
	got := valueListFromForm("a\r\nb\r\n\r\n  \r\nc,d\r\n")
	want := []string{"a", "b", "c,d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("valueListFromForm = %q, want %q", got, want)
	}
	// Interior spacing is preserved: " a " and "a" are different ENUM members,
	// and silently trimming would change what the user asked for.
	if got := valueListFromForm(" a \nb"); got[0] != " a " {
		t.Errorf("leading/trailing spaces were trimmed: %q", got[0])
	}
	if got := valueListFromForm(""); got != nil {
		t.Errorf("empty input = %q, want nil", got)
	}
}

// TestValueListTypesAreInTheAllowlist: the two lists must agree, or the editor
// would offer a value-list control for a type the type validation then rejects.
func TestValueListTypesAreInTheAllowlist(t *testing.T) {
	d, editor := mysqlEditor(t)
	typer, ok := d.(driver.ValueListTyper)
	if !ok {
		t.Fatal("mysql no longer implements ValueListTyper")
	}
	for _, base := range typer.ValueListTypes() {
		if _, ok := canonicalColumnType(editor, base); !ok {
			t.Errorf("ValueListTypes() offers %q, which is not in ColumnTypes()", base)
		}
		if !takesValueList(d, strings.ToLower(base)) {
			t.Errorf("takesValueList is case-sensitive about %q; the form submits whatever the option says", base)
		}
	}
}
