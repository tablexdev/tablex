package dump

// The XML writer. What is worth testing is not "does it emit tags" but "is the
// result always a document a parser accepts, whatever the data holds" — the
// failure mode for an export format is a file that looks fine and will not
// parse.

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// wellFormed reports whether s parses as XML, so every case below can assert
// the property that actually matters.
func wellFormed(t *testing.T, s string) error {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func TestXMLCellShapes(t *testing.T) {
	str := func(s string) driver.Value { return driver.Value{Str: s} }

	for _, tc := range []struct {
		name string
		col  string
		val  driver.Value
		want string
	}{
		{"plain", "id", str("7"), `<column name="id">7</column>`},
		// NULL must stay distinguishable from an empty string, as it is in CSV
		// (the \N sentinel) and JSON (a literal null).
		{"null", "note", driver.Value{Null: true}, `<column name="note" null="true"/>`},
		{"empty string", "note", str(""), `<column name="note"></column>`},
		{"binary", "blob", driver.Value{Binary: true, Bytes: []byte{0xde, 0xad}},
			`<column name="blob" format="hex">dead</column>`},
	} {
		if got := xmlCell(tc.col, tc.val); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	// NULL and empty string must not render identically — the whole point of
	// carrying the attribute.
	if xmlCell("c", driver.Value{Null: true}) == xmlCell("c", str("")) {
		t.Error("NULL and the empty string render identically; the distinction is lost")
	}
}

// TestXMLEscapesEverythingThatCouldBreakTheDocument — markup in a value, and
// markup in a COLUMN NAME. The name is an attribute rather than an element name
// precisely because an identifier may hold characters no element name allows.
func TestXMLEscapesMarkup(t *testing.T) {
	cells := []string{
		xmlCell("id", driver.Value{Str: `<script>alert("x")</script> & 'quotes'`}),
		xmlCell(`weird "name" <with> & markup`, driver.Value{Str: "ok"}),
		xmlCell("tab\tand\nnewline", driver.Value{Str: "a\tb\nc\rd"}),
	}
	doc := "<r>" + strings.Join(cells, "") + "</r>"
	if err := wellFormed(t, doc); err != nil {
		t.Fatalf("escaping produced an unparseable document: %v\n%s", err, doc)
	}
	if strings.Contains(doc, "<script>") {
		t.Errorf("raw markup survived escaping:\n%s", doc)
	}

	// Round-trip: the escaped value must decode back to exactly what went in.
	var out struct {
		Columns []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"column"`
	}
	raw := `<script>alert("x")</script> & 'quotes'`
	if err := xml.Unmarshal([]byte("<r>"+xmlCell("id", driver.Value{Str: raw})+"</r>"), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Columns[0].Value != raw {
		t.Errorf("round-trip changed the value:\n got %q\nwant %q", out.Columns[0].Value, raw)
	}
}

// TestXMLHexEncodesWhatXMLCannotCarry is the trap this format has and the
// others do not: xml.EscapeText passes control bytes through UNCHANGED, so a
// value holding a NUL would produce a document no parser accepts.
func TestXMLHexEncodesUnrepresentable(t *testing.T) {
	for _, tc := range []struct{ name, val string }{
		{"NUL", "before\x00after"},
		{"control 0x01", "\x01"},
		{"vertical tab", "\x0b"},
		{"invalid UTF-8", "\xff\xfe bad"},
		{"noncharacter FFFE", "￾"},
	} {
		cell := xmlCell("c", driver.Value{Str: tc.val})
		if !strings.Contains(cell, `format="hex"`) {
			t.Errorf("%s: not hex-encoded: %s", tc.name, cell)
		}
		if err := wellFormed(t, "<r>"+cell+"</r>"); err != nil {
			t.Errorf("%s: produced an unparseable document (%v): %q", tc.name, err, cell)
		}
	}

	// The three whitespace characters XML DOES allow must stay as text — hexing
	// them would be a needless loss of readability across every text column.
	for _, ok := range []string{"a\tb", "a\nb", "a\rb", "héllo ☃", "𝔘nicode"} {
		if cell := xmlCell("c", driver.Value{Str: ok}); strings.Contains(cell, `format="hex"`) {
			t.Errorf("%q was hex-encoded but is representable: %s", ok, cell)
		}
	}

	// An unrepresentable COLUMN NAME has no hex escape hatch (an attribute
	// cannot carry one), so it is scrubbed — the document must still parse.
	cell := xmlCell("bad\x00name", driver.Value{Str: "v"})
	if err := wellFormed(t, "<r>"+cell+"</r>"); err != nil {
		t.Errorf("an unrepresentable column name broke the document (%v): %q", err, cell)
	}
}

func TestWriteXMLDocument(t *testing.T) {
	conn := openTestConn(t)
	for _, s := range []string{
		`CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, note TEXT)`,
		`INSERT INTO t (id, name, note) VALUES (1, 'a<b>', NULL)`,
		`INSERT INTO t (id, name, note) VALUES (2, '', 'x')`,
	} {
		mustExec(t, conn, s)
	}
	groups := []SchemaGroup{{Tables: []driver.TableRef{{Table: "t"}}}}

	var buf bytes.Buffer
	WriteXML(context.Background(), &buf, conn, groups, false, nil, nil)
	got := buf.String()

	if err := wellFormed(t, got); err != nil {
		t.Fatalf("the document does not parse: %v\n%s", err, got)
	}
	if !strings.HasPrefix(got, xml.Header) {
		t.Errorf("missing XML declaration:\n%.200s", got)
	}
	for _, want := range []string{
		`<table name="t">`,
		`<column name="name">a&lt;b&gt;</column>`,
		`<column name="note" null="true"/>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "<row>"); n != 2 {
		t.Errorf("%d rows, want 2:\n%s", n, got)
	}

	// Nested (schema-having) form.
	buf.Reset()
	WriteXML(context.Background(), &buf, conn,
		[]SchemaGroup{{Schema: "main", Tables: []driver.TableRef{{Schema: "main", Table: "t"}}}},
		true, nil, nil)
	nested := buf.String()
	if err := wellFormed(t, nested); err != nil {
		t.Fatalf("the nested document does not parse: %v\n%s", err, nested)
	}
	if !strings.Contains(nested, `<schema name="main">`) {
		t.Errorf("no schema level:\n%s", nested)
	}

	// Empty input is still a valid document, not an empty file.
	buf.Reset()
	WriteXML(context.Background(), &buf, conn, nil, false, nil, nil)
	if err := wellFormed(t, buf.String()); err != nil {
		t.Errorf("an empty export is not a valid document: %v\n%s", err, buf.String())
	}
}
