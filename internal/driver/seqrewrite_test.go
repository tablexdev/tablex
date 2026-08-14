package driver

import (
	"strings"
	"testing"
)

func TestRewriteSequenceRefs(t *testing.T) {
	rw := map[string]string{
		SeqRefKey("public", "src_seq"):   SeqRefKey("public", "tablex_seq_abc"),
		SeqRefKey("Other Sch", "We'ird"): SeqRefKey("public", "tablex_seq_def"),
		SeqRefKey("b", "late"):           SeqRefKey("a", "tablex_seq_012"),
	}
	cases := []struct{ name, in, want string }{
		{"early-bound qualified",
			`c integer DEFAULT nextval('public.src_seq'::regclass)`,
			`c integer DEFAULT nextval('public.tablex_seq_abc'::regclass)`},
		{"late-bound text cast",
			`nextval('b.late'::text)`,
			`nextval('a.tablex_seq_012'::text)`},
		{"quoted parts with embedded quote",
			`nextval('"Other Sch"."We''ird"'::regclass)`,
			`nextval('public.tablex_seq_def'::regclass)`},
		{"pg_catalog-qualified cast",
			`nextval('public.src_seq'::pg_catalog.regclass)`,
			`nextval('public.tablex_seq_abc'::pg_catalog.regclass)`},
		{"unqualified literal never rewritten",
			`nextval('src_seq'::regclass)`,
			`nextval('src_seq'::regclass)`},
		{"unmapped sequence untouched",
			`nextval('public.other'::regclass)`,
			`nextval('public.other'::regclass)`},
		{"uncast literal untouched",
			`c text DEFAULT 'public.src_seq'`,
			`c text DEFAULT 'public.src_seq'`},
		{"literal inside quoted identifier untouched",
			`CREATE TABLE "public.src_seq" ("x'y" int DEFAULT nextval('public.src_seq'::regclass))`,
			`CREATE TABLE "public.src_seq" ("x'y" int DEFAULT nextval('public.tablex_seq_abc'::regclass))`},
		{"unquoted folds to lower case",
			`nextval('PUBLIC.SRC_SEQ'::regclass)`,
			`nextval('public.tablex_seq_abc'::regclass)`},
		{"spaces around the cast",
			`nextval('public.src_seq' :: regclass)`,
			`nextval('public.tablex_seq_abc' :: regclass)`},
	}
	for _, tc := range cases {
		if got := RewriteSequenceRefs(tc.in, rw); got != tc.want {
			t.Errorf("%s:\n in  %s\n got %s\n want %s", tc.name, tc.in, got, tc.want)
		}
	}
	if got := RewriteSequenceRefs("nextval('public.src_seq'::regclass)", nil); !strings.Contains(got, "src_seq") {
		t.Errorf("nil map must be a no-op, got %s", got)
	}
	// A replacement into a schema needing quoting renders quoted inside the literal.
	rw2 := map[string]string{SeqRefKey("s", "x"): SeqRefKey("My Schema", "tablex_seq_1")}
	got := RewriteSequenceRefs(`nextval('s.x'::regclass)`, rw2)
	if want := `nextval('"My Schema".tablex_seq_1'::regclass)`; got != want {
		t.Errorf("quoted replacement: got %s want %s", got, want)
	}
}

func TestNextvalTextRefs(t *testing.T) {
	refs, dynamic := NextvalTextRefs(`nextval('public.a'::text)`)
	if len(refs) != 1 || refs[0] != "public.a" || dynamic {
		t.Errorf("simple late-bound: refs=%v dynamic=%v", refs, dynamic)
	}
	refs, dynamic = NextvalTextRefs(`(nextval('a.b'::text) + pg_catalog.nextval('c.d'::text))`)
	if len(refs) != 2 || refs[0] != "a.b" || refs[1] != "c.d" || dynamic {
		t.Errorf("two refs: refs=%v dynamic=%v", refs, dynamic)
	}
	// The REAL deparsed late-bound shape wraps the ::text cast in parens and
	// re-casts to regclass.
	refs, dynamic = NextvalTextRefs(`nextval(('xsrc.custom_sm'::text)::regclass)`)
	if len(refs) != 1 || refs[0] != "xsrc.custom_sm" || dynamic {
		t.Errorf("deparsed late-bound: refs=%v dynamic=%v", refs, dynamic)
	}
	// A deparsed concatenation is dynamic even though it leads with a literal.
	refs, dynamic = NextvalTextRefs(`nextval((('xsrc'::text || '.custom_sm'::text))::regclass)`)
	if len(refs) != 0 || !dynamic {
		t.Errorf("deparsed concat must be dynamic: refs=%v dynamic=%v", refs, dynamic)
	}
	refs, dynamic = NextvalTextRefs(`nextval('public.a'::regclass)`)
	if len(refs) != 0 || dynamic {
		t.Errorf("early-bound must be ignored: refs=%v dynamic=%v", refs, dynamic)
	}
	refs, dynamic = NextvalTextRefs(`nextval((SELECT relname FROM pg_class LIMIT 1)::regclass)`)
	if len(refs) != 0 || !dynamic {
		t.Errorf("dynamic argument: refs=%v dynamic=%v", refs, dynamic)
	}
	refs, dynamic = NextvalTextRefs(`mynextval('public.a'::text)`)
	if len(refs) != 0 || dynamic {
		t.Errorf("longer identifier must not match: refs=%v dynamic=%v", refs, dynamic)
	}
	// A quoted identifier containing "nextval(" must not confuse the scanner.
	refs, dynamic = NextvalTextRefs(`"nextval('x'::text)" + 1`)
	if len(refs) != 0 || dynamic {
		t.Errorf("identifier-embedded text must be opaque: refs=%v dynamic=%v", refs, dynamic)
	}
}

func TestParseQualifiedSeqLiteral(t *testing.T) {
	cases := []struct {
		in           string
		schema, name string
		ok           bool
	}{
		{"public.seq", "public", "seq", true},
		{"PUBLIC.SEQ", "public", "seq", true},
		{`"My Sch"."Se""q"`, "My Sch", `Se"q`, true},
		{` public . seq `, "public", "seq", true},
		{"seq", "", "", false},
		{"a.b.c", "", "", false},
		{`""`, "", "", false},
		{`"unterminated`, "", "", false},
	}
	for _, tc := range cases {
		schema, name, ok := ParseQualifiedSeqLiteral(tc.in)
		if schema != tc.schema || name != tc.name || ok != tc.ok {
			t.Errorf("%q: got (%q,%q,%v) want (%q,%q,%v)", tc.in, schema, name, ok, tc.schema, tc.name, tc.ok)
		}
	}
}
