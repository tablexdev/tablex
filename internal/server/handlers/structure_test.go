package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// These unit tests exercise the shared structure-edit validation helpers
// directly. They cover paths the SQLite HTTP stack cannot reach (SQLite has no
// foreign-key DDL, so the referential-action validation is never invoked there).

func TestValidReferentialAction(t *testing.T) {
	ok := map[string]string{
		"":            "",
		"cascade":     "CASCADE",
		"Set Null":    "SET NULL",
		"NO ACTION":   "NO ACTION",
		"restrict":    "RESTRICT",
		"set default": "SET DEFAULT",
	}
	for in, want := range ok {
		if got, valid := validReferentialAction(in); !valid || got != want {
			t.Errorf("validReferentialAction(%q) = %q,%v; want %q,true", in, got, valid, want)
		}
	}
	for _, bad := range []string{"DROP", "CASCADE; DROP TABLE x", "delete", "set everything"} {
		if _, valid := validReferentialAction(bad); valid {
			t.Errorf("validReferentialAction(%q) should be invalid", bad)
		}
	}
}

func TestAssembleColumnType(t *testing.T) {
	d, _ := driver.Get("sqlite")
	editor := d.(driver.SchemaEditor)

	if got, ok := assembleColumnType(editor, "text", ""); !ok || got != "TEXT" {
		t.Errorf("text → %q,%v (want TEXT,true)", got, ok)
	}
	if got, ok := assembleColumnType(editor, "NUMERIC", "10,2"); !ok || got != "NUMERIC(10,2)" {
		t.Errorf("numeric(10,2) → %q,%v", got, ok)
	}
	if _, ok := assembleColumnType(editor, "bogus", ""); ok {
		t.Error("non-allowlisted base type should be rejected")
	}
	if _, ok := assembleColumnType(editor, "TEXT", "5); DROP TABLE x"); ok {
		t.Error("malformed length should be rejected")
	}
}

func TestBuildDefault(t *testing.T) {
	d, _ := driver.Get("sqlite")

	if def, err := buildDefault(d, "none", "", "TEXT"); err != nil || def != nil {
		t.Errorf("none → %v,%v", def, err)
	}
	if def, err := buildDefault(d, "null", "", "TEXT"); err != nil || def == nil || *def != "NULL" {
		t.Errorf("null → %v,%v", def, err)
	}
	if def, err := buildDefault(d, "current", "", "DATETIME"); err != nil || def == nil || *def != "CURRENT_TIMESTAMP" {
		t.Errorf("current/temporal → %v,%v", def, err)
	}
	if _, err := buildDefault(d, "current", "", "TEXT"); err == nil {
		t.Error("CURRENT_TIMESTAMP on a non-temporal column should error")
	}
	if def, err := buildDefault(d, "custom", "42", "INTEGER"); err != nil || def == nil || *def != "42" {
		t.Errorf("custom numeric → %v,%v", def, err)
	}
	if _, err := buildDefault(d, "custom", "x", "INTEGER"); err == nil {
		t.Error("non-numeric default for a numeric column should error")
	}
	// String defaults are quoted (injection-safe), single quotes doubled.
	if def, err := buildDefault(d, "custom", "O'Brien", "TEXT"); err != nil || def == nil || *def != "'O''Brien'" {
		t.Errorf("custom string → %v,%v", def, err)
	}
}

func ptrStr(s string) *string { return &s }

// TestColumnSpecExprDefault covers: modifying a column whose current default
// is an unedited expression (a PG serial's nextval(...), a MySQL/MariaDB
// expression default) must not be rejected by buildDefault's numeric-literal
// check. On the modify path the spec build skips buildDefault and
// applyExprDefault reinstalls the verbatim expression; on the add path (no
// existing column) an expression in a numeric default is still rejected.
func TestColumnSpecExprDefault(t *testing.T) {
	d, _ := driver.Get("sqlite")
	editor := d.(driver.SchemaEditor)

	existing := model.Column{
		Name:          "id",
		BaseType:      "integer",
		DataType:      "integer",
		Default:       ptrStr("nextval('s'::regclass)"),
		DefaultIsExpr: true,
	}
	// Form prefilled exactly as columnDefaultForForm(existing) would render it.
	vals := url.Values{
		"col_type":      {"integer"},
		"col_nullable":  {"1"},
		"default_mode":  {"custom"},
		"default_value": {"nextval('s'::regclass)"},
		"col_comment":   {"changed comment"},
	}

	// Modify path: unchanged expr default ⇒ buildDefault skipped, no error.
	spec, err := columnSpec(d, editor, vals, &existing)
	if err != nil {
		t.Fatalf("modify with unchanged expr default should not error, got %v", err)
	}
	if spec.Default != nil {
		t.Errorf("columnSpec should leave Default nil for reinstall, got %v", *spec.Default)
	}
	applyExprDefault(&spec, existing, vals)
	if spec.Default == nil || *spec.Default != "nextval('s'::regclass)" || !spec.DefaultExpr {
		t.Errorf("applyExprDefault should reinstall the verbatim expression, got %v expr=%v", spec.Default, spec.DefaultExpr)
	}

	// Add path (no existing column): an expression in a numeric default is still
	// rejected — the skip only applies to an unchanged introspected expr default.
	if _, err := columnSpec(d, editor, vals, nil); err == nil {
		t.Error("add path should reject a non-numeric expression default")
	}
}

// TestColumnDefaultForForm covers the modify-form default round-trip mapping,
// including the engine-quoting differences (MySQL unquoted, MariaDB quoted,
// PostgreSQL "'x'::type" casts). The "null"/"current" radios are driven by the
// kind flags: a literal spelled like a keyword (MariaDB DEFAULT 'NULL', MySQL
// DEFAULT 'CURRENT_TIMESTAMP' — isExpr=false, isNull=false) must stay a
// custom literal, or a modify round-trip silently rewrites it into the real
// keyword/expression.
func TestColumnDefaultForForm(t *testing.T) {
	cases := []struct {
		name              string
		col               model.Column
		wantMode, wantVal string
	}{
		{"no default", model.Column{}, "none", ""},
		// Explicit DEFAULT NULL: MariaDB's keyword flag, or verbatim-SQL engines
		// (SQLite PRAGMA text) where the bare spelling is unambiguous.
		{"mariadb explicit null (flag)", model.Column{Default: ptrStr("NULL"), DefaultIsNull: true}, "null", ""},
		{"sqlite explicit null (verbatim SQL)", model.Column{Default: ptrStr("NULL"), DefaultIsExpr: true}, "null", ""},
		{"current timestamp", model.Column{Default: ptrStr("CURRENT_TIMESTAMP"), DefaultIsExpr: true}, "current", ""},
		{"current timestamp(6)", model.Column{Default: ptrStr("current_timestamp(6)"), DefaultIsExpr: true}, "current", ""},
		{"mariadb now()", model.Column{Default: ptrStr("NOW()"), DefaultIsExpr: true}, "current", ""},
		// Literal strings that merely SPELL a keyword stay custom literals.
		{"mysql literal NULL string", model.Column{Default: ptrStr("NULL")}, "custom", "NULL"},
		{"mariadb literal NULL string (unquoted by introspection)", model.Column{Default: ptrStr("NULL")}, "custom", "NULL"},
		{"literal CURRENT_TIMESTAMP string", model.Column{Default: ptrStr("CURRENT_TIMESTAMP")}, "custom", "CURRENT_TIMESTAMP"},
		{"numeric", model.Column{Default: ptrStr("0")}, "custom", "0"},
		{"mysql unquoted string", model.Column{Default: ptrStr("hello")}, "custom", "hello"},
		{"mariadb quoted string", model.Column{Default: ptrStr("'hello'")}, "custom", "hello"},
		{"postgres cast string", model.Column{Default: ptrStr("'hello'::text"), DefaultIsExpr: true}, "custom", "hello"},
		{"escaped quote", model.Column{Default: ptrStr("'it''s'")}, "custom", "it's"},
	}
	for _, c := range cases {
		mode, val := columnDefaultForForm(c.col)
		if mode != c.wantMode || val != c.wantVal {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, mode, val, c.wantMode, c.wantVal)
		}
	}
}

// TestTableStructureModifyFormServerPrefill covers #11: the Modify-column
// editor renders the selected column's CURRENT definition server-side —
// selected type option, length/comment values, nullable checked, default
// radios — and carries the column as an immutable hidden input, so a submit
// with JavaScript disabled preserves everything the user did not change. The
// old Alpine-only sync() left the controls at blank defaults without JS,
// silently restating the column as the first listed type, NOT NULL, no
// default.
func TestTableStructureModifyFormServerPrefill(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	types := []string{"INT", "VARCHAR", "TEXT"}
	body := structureBody{
		Scope:          reqScope{DB: "d", Table: "t"},
		Caps:           driver.Capabilities{SupportsColumnModify: true},
		CanEdit:        true,
		PostURL:        "/db/d/table/t/structure",
		ModifyColumns:  []modifyColumnVM{{Name: "a"}, {Name: "b"}},
		ModifySelected: "b",
		AddForm:        columnFormVM{ColumnTypes: types},
		ModifyForm: &columnFormVM{
			ColumnTypes: types,
			Sel: modifyColumnVM{
				Name: "b", Type: "VARCHAR", Length: "36", Nullable: true,
				DefaultMode: "custom", DefaultValue: "uuid()", Comment: "note",
			},
		},
	}
	p := view.NewPage("t · Structure")
	p.Body = body
	rec := httptest.NewRecorder()
	if err := renderer.RenderNamed(rec, "table_structure", "content", p); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := rec.Body.String()

	for what, want := range map[string]string{
		"immutable hidden column input": `name="column" value="b"`,
		"selected type option":          `value="VARCHAR" selected`,
		"prefilled length":              `name="col_length" class="form-control form-control-sm" value="36"`,
		"nullable checked":              `name="col_nullable" value="1" checked`,
		"custom default selected":       `value="custom" selected`,
		"prefilled default value":       `name="default_value" class="form-control form-control-sm" value="uuid()"`,
		"prefilled comment":             `name="col_comment" class="form-control form-control-sm" value="note"`,
		"selection picker":              `name="modify"`,
		"picker keeps selection":        `value="b" selected`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("modify editor missing %s (%q):\n%.4000s", what, want, out)
		}
	}
	// The POST editor must have NO changeable column selector: selection is the
	// GET round-trip only.
	if strings.Contains(out, `<select name="column"`) {
		t.Error("the POST form must not carry a changeable column selector")
	}

	// An unrecognized introspected type renders a disabled placeholder instead
	// of silently preselecting the first type (silent narrowing).
	body.ModifyForm = &columnFormVM{
		ColumnTypes:      types,
		Sel:              modifyColumnVM{Name: "b", Type: "geometry"},
		TypeUnrecognized: true,
	}
	p.Body = body
	rec = httptest.NewRecorder()
	if err := renderer.RenderNamed(rec, "table_structure", "content", p); err != nil {
		t.Fatalf("render: %v", err)
	}
	out = rec.Body.String()
	if !strings.Contains(out, "unrecognized") {
		t.Error("unrecognized type should render a placeholder option")
	}
	if strings.Contains(out, `value="INT" selected`) {
		t.Error("unrecognized type must not silently preselect the first type")
	}
}

func TestColumnLengthForForm(t *testing.T) {
	cases := []struct{ dataType, want string }{
		{"varchar(255)", "255"},
		{"numeric(10,2)", "10,2"},
		{"int", ""},
		{"int(11) unsigned", "11"},
		{"enum('a','b')", ""}, // non-numeric parenthesised list is skipped
	}
	for _, c := range cases {
		if got := columnLengthForForm(model.Column{DataType: c.dataType}); got != c.want {
			t.Errorf("columnLengthForForm(%q) = %q, want %q", c.dataType, got, c.want)
		}
	}
}

// TestPreserveColumnAttrs confirms attributes the modify form cannot express are
// carried over from the existing column (and that unsafe values are dropped).
func TestPreserveColumnAttrs(t *testing.T) {
	var spec driver.ColumnSpec
	preserveColumnAttrs(&spec, model.Column{
		IsAutoIncrement: true,
		Collation:       "utf8mb4_bin",
		Charset:         "utf8mb4",
		// Typed, not parsed out of Extra here: the MySQL dialect reads its own
		// EXTRA vocabulary (see mysql.parseOnUpdate) and this side just copies.
		OnUpdate: "CURRENT_TIMESTAMP",
	})
	if !spec.AutoIncrement || spec.Collation != "utf8mb4_bin" || spec.Charset != "utf8mb4" || spec.OnUpdate != "CURRENT_TIMESTAMP" {
		t.Errorf("attrs not preserved: %+v", spec)
	}
	// A collation with non-identifier characters must not be emitted.
	var spec2 driver.ColumnSpec
	preserveColumnAttrs(&spec2, model.Column{Collation: "bad'; DROP"})
	if spec2.Collation != "" {
		t.Errorf("unsafe collation should be dropped, got %q", spec2.Collation)
	}
}

// TestPreserveColumnAttrsSignedness pins the UNSIGNED/ZEROFILL data-integrity
// fix: COLUMN_TYPE carries the numeric attributes, and losing them on a modify
// silently converts INT UNSIGNED to signed (clamping data in non-strict mode).
func TestPreserveColumnAttrsSignedness(t *testing.T) {
	var spec driver.ColumnSpec
	preserveColumnAttrs(&spec, model.Column{DataType: "int(10) unsigned zerofill"})
	if !spec.Unsigned || !spec.Zerofill {
		t.Errorf("unsigned/zerofill not preserved: %+v", spec)
	}
	var plain driver.ColumnSpec
	preserveColumnAttrs(&plain, model.Column{DataType: "int(11)"})
	if plain.Unsigned || plain.Zerofill {
		t.Errorf("signed int must not gain unsigned/zerofill: %+v", plain)
	}
}

// TestPreserveDefaultExpr pins the expression-default fix: when the user does
// not change the default controls, an introspected expression default is kept
// verbatim instead of being re-quoted into a string literal (DEFAULT
// CURRENT_TIMESTAMP must not become DEFAULT 'CURRENT_TIMESTAMP').
func TestPreserveDefaultExpr(t *testing.T) {
	form := func(mode, value string) url.Values {
		return url.Values{"default_mode": {mode}, "default_value": {value}}
	}

	// Unchanged "current" mode keeps the engine's own expression text.
	ct := model.Column{Default: ptrStr("CURRENT_TIMESTAMP"), DefaultIsExpr: true}
	spec := driver.ColumnSpec{Default: ptrStr("CURRENT_TIMESTAMP")}
	applyExprDefault(&spec, ct, form("current", ""))
	if !spec.DefaultExpr || spec.Default == nil || *spec.Default != "CURRENT_TIMESTAMP" {
		t.Errorf("current-timestamp default not preserved: %+v", spec)
	}

	// Unchanged custom value keeps a sequence default verbatim.
	seq := model.Column{Default: ptrStr("nextval('items_id_seq'::regclass)"), DefaultIsExpr: true}
	spec = driver.ColumnSpec{Default: ptrStr("'nextval(''items_id_seq''::regclass)'")} // what the form would re-quote it into
	applyExprDefault(&spec, seq, form("custom", "nextval('items_id_seq'::regclass)"))
	if !spec.DefaultExpr || *spec.Default != "nextval('items_id_seq'::regclass)" {
		t.Errorf("sequence default not preserved verbatim: %+v", spec)
	}

	// A changed value is the user's new literal — must NOT be overridden.
	spec = driver.ColumnSpec{Default: ptrStr("'new literal'")}
	applyExprDefault(&spec, seq, form("custom", "new literal"))
	if spec.DefaultExpr || *spec.Default != "'new literal'" {
		t.Errorf("changed default wrongly overridden: %+v", spec)
	}

	// Literal defaults (no expression flag) are untouched.
	lit := model.Column{Default: ptrStr("hello")}
	spec = driver.ColumnSpec{Default: ptrStr("'hello'")}
	applyExprDefault(&spec, lit, form("custom", "hello"))
	if spec.DefaultExpr || *spec.Default != "'hello'" {
		t.Errorf("literal default should pass through the form path: %+v", spec)
	}
}

// TestPreserveColumnAttrsIdentity confirms the identity mode travels through the
// spec so ModifyColumnSQL can skip DROP/SET DEFAULT. The mode is a typed
// model.Column field (B6); it used to be a magic string inside Extra, which
// meant this engine-neutral code matched on one engine's free-text.
func TestPreserveColumnAttrsIdentity(t *testing.T) {
	var always, byDefault, none driver.ColumnSpec
	preserveColumnAttrs(&always, model.Column{Identity: model.IdentityAlways})
	preserveColumnAttrs(&byDefault, model.Column{Identity: model.IdentityByDefault})
	preserveColumnAttrs(&none, model.Column{Extra: "on update CURRENT_TIMESTAMP"})
	if always.Identity != "always" || byDefault.Identity != "default" || none.Identity != "" {
		t.Errorf("identity modes: always=%q byDefault=%q none=%q", always.Identity, byDefault.Identity, none.Identity)
	}
	// Extra is free text now: nothing may recover a control value from it.
	var fromExtra driver.ColumnSpec
	preserveColumnAttrs(&fromExtra, model.Column{Extra: "identity always"})
	if fromExtra.Identity != "" {
		t.Errorf("Extra must not be parsed as an identity discriminator, got %q", fromExtra.Identity)
	}
}

// TestFKRefHiddenIsEngineCorrect pins the one thing this guard can get wrong in
// two opposite directions.
//
// model.ForeignKey has a single RefSchema field whose MEANING differs by engine:
// on MySQL/MariaDB it is REFERENCED_TABLE_SCHEMA, a DATABASE; on PostgreSQL it
// is n.nspname, an ordinary SCHEMA. restrict.database_allowlist names databases.
// So a generic allowlist test against RefSchema would hide every legitimate
// cross-schema key on PostgreSQL — while on MySQL, not testing it leaves a
// non-allowlisted database's table and column names on an allowlisted page.
//
// Capabilities().HasSchemas is exactly the discriminator, which is why no new
// capability field was added for it.
func TestFKRefHiddenIsEngineCorrect(t *testing.T) {
	h := &Handlers{}
	h.Cfg.Restrict.Databases = []string{"shop"}
	mysqlish := driver.Capabilities{HasSchemas: false}   // MySQL / MariaDB / SQLite
	postgresish := driver.Capabilities{HasSchemas: true} // PostgreSQL

	for _, tc := range []struct {
		name string
		caps driver.Capabilities
		fk   model.ForeignKey
		want bool
	}{
		// No schema level: RefSchema IS a database, so the allowlist applies.
		{"a key into a non-allowlisted database", mysqlish,
			model.ForeignKey{RefSchema: "secrets", RefTable: "orders", RefColumns: []string{"id"}}, true},
		{"a key inside the allowlisted database", mysqlish,
			model.ForeignKey{RefSchema: "shop", RefTable: "orders", RefColumns: []string{"id"}}, false},
		// A schema level: RefSchema is a SCHEMA, never a database. A PG database
		// cannot even be expressed here, so the test must never fire — otherwise
		// every ordinary cross-schema key disappears from an allowlisted page.
		{"a cross-schema key on an engine with schemas", postgresish,
			model.ForeignKey{RefSchema: "reporting", RefTable: "orders", RefColumns: []string{"id"}}, false},
		{"a same-schema key on an engine with schemas", postgresish,
			model.ForeignKey{RefSchema: "public", RefTable: "orders", RefColumns: []string{"id"}}, false},
		// SQLite: no schema level either, but its foreign keys carry no
		// qualifier at all, so the guard is inert rather than wrong.
		{"an unqualified key", mysqlish,
			model.ForeignKey{RefTable: "orders", RefColumns: []string{"id"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.fkRefHidden(tc.caps, tc.fk); got != tc.want {
				t.Errorf("fkRefHidden(HasSchemas=%v, RefSchema=%q) = %v, want %v",
					tc.caps.HasSchemas, tc.fk.RefSchema, got, tc.want)
			}
		})
	}

	// With no allowlist configured the whole thing is inert — DatabaseAllowed
	// permits everything — so a stock deployment sees no change at all.
	var unrestricted Handlers
	if unrestricted.fkRefHidden(mysqlish, model.ForeignKey{RefSchema: "secrets", RefTable: "orders"}) {
		t.Error("a key was hidden with no database_allowlist configured")
	}
}
