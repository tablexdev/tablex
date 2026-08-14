package dump

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
)

// WriteXML streams tables as an XML document.
//
// Shape — schema-less engines omit the <schema> level:
//
//	<?xml version="1.0" encoding="utf-8"?>
//	<tablex_export version="1">
//	  <schema name="public">
//	    <table name="orders">
//	      <row>
//	        <column name="id">1</column>
//	        <column name="note" null="true"/>
//	        <column name="blob" format="hex">deadbeef</column>
//	      </row>
//	    </table>
//	  </schema>
//	</tablex_export>
//
// A column's NAME is an attribute, never an element name. That is not a style
// choice: an identifier may legally contain spaces, quotes, dots and leading
// digits, none of which are valid in an XML element name, so <my column> would
// be an unparseable document. The same reasoning applies to schema and table.
//
// Like JSON this is EXPORT-ONLY — the importer takes SQL and CSV — so all
// columns are included (the generated-column filter exists to keep CSV
// re-importable, and that rationale does not apply here).
func WriteXML(ctx context.Context, w io.Writer, conn *driver.Connection, groups []SchemaGroup, nested bool, filter *RowFilter, rng *RowRange) {
	fmt.Fprint(w, xml.Header) // includes the trailing newline
	fmt.Fprint(w, "<tablex_export version=\"1\">\n")
	var streamErrs []string
	indent := "  "
	curSchema, inSchema := "", false
	closeSchema := func() {
		if inSchema {
			fmt.Fprint(w, "  </schema>\n")
			inSchema = false
		}
	}
	for _, g := range groups {
		if nested && (!inSchema || g.Schema != curSchema) {
			closeSchema()
			fmt.Fprintf(w, "  <schema name=%s>\n", xmlAttr(g.Schema))
			inSchema, curSchema = true, g.Schema
			indent = "    "
		}
		for _, t := range g.Tables {
			fmt.Fprintf(w, "%s<table name=%s>\n", indent, xmlAttr(t.Table))
			streamErrs = appendXMLTable(ctx, w, conn, t, indent, filter, rng, streamErrs)
			fmt.Fprintf(w, "%s</table>\n", indent)
		}
	}
	closeSchema()
	// Stream failures become elements inside the root, so a truncated dump is
	// still a well-formed document and no failure is silent — the same contract
	// as the JSON writer's __error__ key.
	for _, e := range streamErrs {
		fmt.Fprintf(w, "  <error>%s</error>\n", xmlText(e))
	}
	fmt.Fprint(w, "</tablex_export>\n")
}

// appendXMLTable streams one table's rows as <row> elements.
func appendXMLTable(ctx context.Context, w io.Writer, conn *driver.Connection, t driver.TableRef, indent string, filter *RowFilter, rng *RowRange, streamErrs []string) []string {
	where, args, allowed := filter.clauseFor(t)
	if !allowed {
		return streamErrs
	}
	rowIndent, colIndent := indent+"  ", indent+"    "
	err := conn.StreamArgs(ctx, "SELECT * FROM "+conn.QualifiedName(t)+where+rng.clauseFor(conn.Dialect()),
		args, func(cols []driver.ResultColumn, row []driver.Value) error {
			var b strings.Builder
			b.WriteString(rowIndent + "<row>\n")
			for i, c := range cols {
				b.WriteString(colIndent)
				b.WriteString(xmlCell(c.Name, row[i]))
				b.WriteByte('\n')
			}
			b.WriteString(rowIndent + "</row>\n")
			_, werr := io.WriteString(w, b.String())
			return werr
		})
	if err != nil {
		label := t.Table
		if t.Schema != "" {
			label = t.Schema + "." + t.Table
		}
		streamErrs = append(streamErrs, fmt.Sprintf("%s: %v", label, err))
	}
	return streamErrs
}

// xmlCell renders one value as a <column> element.
//
// NULL is an empty self-closing element carrying null="true", so it stays
// distinguishable from an empty string — the same distinction CSV draws with
// its \N sentinel and JSON with a literal null.
//
// A value that XML cannot carry — raw bytes, invalid UTF-8, or a control
// character outside the handful XML 1.0 permits — is hex-encoded and marked
// format="hex". Emitting such a byte raw would produce a document no parser
// accepts, and dropping or replacing it would be silent corruption; hex is
// lossless and self-describing.
func xmlCell(name string, v driver.Value) string {
	attr := " name=" + xmlAttr(name)
	switch {
	case v.Null:
		return "<column" + attr + " null=\"true\"/>"
	case v.Binary:
		return "<column" + attr + " format=\"hex\">" + hex.EncodeToString(v.Bytes) + "</column>"
	case !xmlRepresentable(v.Str):
		return "<column" + attr + " format=\"hex\">" + hex.EncodeToString([]byte(v.Str)) + "</column>"
	default:
		return "<column" + attr + ">" + xmlText(v.Str) + "</column>"
	}
}

// xmlRepresentable reports whether s can appear as XML character data at all.
// XML 1.0 admits only #x9, #xA, #xD and #x20 upward, excluding the surrogate
// block and #xFFFE/#xFFFF — so a NUL or a stray #x01 makes the whole document
// unparseable. xml.EscapeText does NOT filter these: it escapes the three legal
// whitespace characters and passes every other control byte through unchanged,
// which is precisely the trap this guards.
func xmlRepresentable(s string) bool {
	if !utf8.ValidString(s) {
		return false // EscapeText would silently substitute U+FFFD
	}
	for _, r := range s {
		switch {
		case r == 0x09 || r == 0x0A || r == 0x0D:
		case r >= 0x20 && r <= 0xD7FF:
		case r >= 0xE000 && r <= 0xFFFD:
		case r >= 0x10000 && r <= 0x10FFFF:
		default:
			return false
		}
	}
	return true
}

// xmlText escapes character data. Callers must have checked xmlRepresentable
// first for values that could hold arbitrary bytes; the fixed strings this is
// also used for (error messages) are scrubbed here instead.
func xmlText(s string) string {
	if !xmlRepresentable(s) {
		s = strings.Map(func(r rune) rune {
			if xmlRepresentable(string(r)) {
				return r
			}
			return ' '
		}, s)
	}
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// xmlAttr renders a quoted attribute value. Identifiers reach this, so it
// scrubs unrepresentable characters the same way xmlText does — an attribute
// cannot carry a format="hex" escape hatch of its own.
func xmlAttr(s string) string { return `"` + xmlText(s) + `"` }
