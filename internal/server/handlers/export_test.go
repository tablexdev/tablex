package handlers

import (
	"bytes"
	"context"
	"testing"

	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// TestExportSchemaGroupsSchemaless covers H1's schema-less branch: MySQL/SQLite
// return exactly one schema-less group with views excluded, so their export
// behavior is unchanged.
func TestExportSchemaGroupsSchemaless(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE a (id INTEGER)")
	mustExec(t, conn, "CREATE VIEW v AS SELECT 1")
	h := &Handlers{}
	groups, err := h.exportSchemaGroups(context.Background(), conn, "main", "")
	if err != nil {
		t.Fatalf("exportSchemaGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].Schema != "" {
		t.Fatalf("schema-less engine should yield one schema-less group, got %+v", groups)
	}
	if len(groups[0].Tables) != 1 || groups[0].Tables[0].Table != "a" {
		t.Errorf("expected table a only (views excluded), got %+v", groups[0].Tables)
	}
}

// TestDecodeHexCell covers the CSV binary-import decode (lowercase hex, optional
// 0x / \x prefix; invalid hex is an error, never a silent text insert).
func TestDecodeHexCell(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
		err  bool
	}{
		{"00ff10", []byte{0x00, 0xff, 0x10}, false},
		{"0x00ff10", []byte{0x00, 0xff, 0x10}, false},
		{`\x4869`, []byte{0x48, 0x69}, false},
		{"", []byte{}, false},
		{"zz", nil, true},  // not hex
		{"abc", nil, true}, // odd length
	}
	for _, c := range cases {
		got, err := decodeHexCell(c.in)
		if c.err {
			if err == nil {
				t.Errorf("decodeHexCell(%q) expected an error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("decodeHexCell(%q): %v", c.in, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("decodeHexCell(%q) = %x, want %x", c.in, got, c.want)
		}
	}
}

// TestSafeFilename pins the Content-Disposition sanitizer (L5): only
// [A-Za-z0-9._-] survive; a quote, CR/LF, path separators and non-ASCII all
// collapse to '_' so the header cannot be broken out of or path-traversed.
func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"dump.sql":         "dump.sql",
		"my table.sql":     "my_table.sql",
		`a"b`:              "a_b",
		"a\r\nb":           "a__b",
		"../../etc/passwd": ".._.._etc_passwd",
		`a\b/c`:            "a_b_c",
		"café":             "caf_",
		"tab\tsep":         "tab_sep",
		"keep-_.chars":     "keep-_.chars",
	}
	for in, want := range cases {
		if got := safeFilename(in); got != want {
			t.Errorf("safeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
