// Column-form logic: turning the shared column controls into a validated
// driver.ColumnSpec, and turning an introspected model.Column back into the
// form's prefill values. Everything here operates on url.Values, not on an
// *http.Request — the HTTP adapters live in structure.go, so this file (and its
// tests) never need a request, a ResponseWriter or a route.

package handlers

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// modifyColumnVM carries one column's current definition for the Modify-column
// editor, so submitting it preserves the current definition unless the user
// changes a field — the bug being fixed was the form resetting every attribute
// it did not carry. Generated columns are flagged so the UI can mark them (the
// handler also refuses to modify them).
type modifyColumnVM struct {
	Name         string
	Type         string // base type, matched case-insensitively against the type list
	Length       string
	Nullable     bool
	DefaultMode  string
	DefaultValue string
	Comment      string
	Generated    bool
	// Values prefills the ENUM/SET member list, one per line. Empty for every
	// other type. Submitting it unchanged carries the original type through
	// verbatim — see columnType.
	Values string
}

// columnFormVM feeds the shared column_form_fields partial: the allowlisted
// type choices plus the current values to prefill (zero for the Add form, so
// nothing is preselected). Selection is rendered SERVER-SIDE — the old Alpine
// sync() prefill left the controls at blank defaults with JavaScript off, so a
// no-JS modify submit silently restated the column as the first type in the
// list, NOT NULL, no default, no comment.
type columnFormVM struct {
	ColumnTypes []string
	Sel         modifyColumnVM
	// TypeUnrecognized: the introspected base type has no allowlist entry. The
	// partial renders a disabled placeholder instead of letting the browser
	// silently preselect the first option (a potential silent narrowing);
	// submitting without choosing a real type then fails type validation.
	TypeUnrecognized bool

	// Position controls, rendered only when the engine can reorder columns
	// (MySQL's FIRST / AFTER; PostgreSQL and SQLite cannot, so offering the
	// control there would promise something the dialect ignores).
	CanPosition bool
	// PositionAfter is the list of columns "after X" may name. On the modify
	// path the column being edited is excluded — a column cannot follow itself.
	PositionAfter []string
	// PositionKeepLabel names the do-nothing choice, which differs by form:
	// a new column defaults to the end, an existing one stays put.
	PositionKeepLabel string
	// PlaceFirstToken is the sentinel the "first" option submits, so the
	// template and the parser cannot drift apart.
	PlaceFirstToken string

	// ValueListTypes names the types that take a value list instead of a
	// length (MySQL's ENUM and SET). Empty on an engine with none, which is
	// what hides the control — the field is rendered unconditionally rather
	// than revealed by JavaScript, so the form works with scripting off.
	ValueListTypes []string
}

// newColumnForm builds the shared column controls. exclude is the column being
// modified (empty on the add path), which must not appear in the "after" list.
func newColumnForm(editor driver.SchemaEditor, caps driver.Capabilities, cols []model.Column, exclude string) columnFormVM {
	f := columnFormVM{
		ColumnTypes:     editor.ColumnTypes(),
		CanPosition:     caps.SupportsColumnPosition,
		PlaceFirstToken: placeFirstToken,
		PositionKeepLabel: map[bool]string{
			true:  "Keep current position",
			false: "At end of table",
		}[exclude != ""],
	}
	if f.CanPosition {
		for _, c := range cols {
			if c.Name != exclude {
				f.PositionAfter = append(f.PositionAfter, c.Name)
			}
		}
	}
	if typer, ok := editor.(driver.ValueListTyper); ok {
		f.ValueListTypes = typer.ValueListTypes()
	}
	return f
}

var (
	lengthRE         = regexp.MustCompile(`^[0-9]+(,[0-9]+)?$`)
	numericLiteralRE = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
)

// columnSpec reads the shared column controls. On the modify path the caller
// passes the introspected column as existing; on the add path it is nil.
// When existing has an unedited expression default, buildDefault is skipped
// entirely — a numeric-typed expression (a PG serial's nextval(...), a
// MySQL/MariaDB expression default) is not a numeric literal, so buildDefault
// would reject it with "numeric default must be a number" and no serial/expr
// column could be modified at all. applyExprDefault installs the verbatim
// expression afterward.
func columnSpec(d driver.Dialect, editor driver.SchemaEditor, form url.Values, existing *model.Column) (driver.ColumnSpec, error) {
	base := strings.TrimSpace(form.Get("col_type"))
	typ, err := columnType(d, editor, form, base, existing)
	if err != nil {
		return driver.ColumnSpec{}, err
	}
	spec := driver.ColumnSpec{
		Type:     typ,
		Nullable: form.Get("col_nullable") != "",
		Comment:  strings.TrimSpace(form.Get("col_comment")),
	}
	if existing != nil && unchangedExprDefault(*existing, form) {
		return spec, nil // Default reinstalled verbatim by applyExprDefault
	}
	def, err := buildDefault(d, form.Get("default_mode"), form.Get("default_value"), base)
	if err != nil {
		return driver.ColumnSpec{}, err
	}
	spec.Default = def
	return spec, nil
}

// columnType assembles the column's engine type. Ordinary types take an
// optional numeric length/precision; the engine's list-valued types (MySQL
// ENUM/SET) take the col_values list instead.
//
// On the modify path a value list that is unchanged AND still on the same base
// type is carried through as the introspected type string verbatim rather than
// reassembled, mirroring how an untouched expression default is preserved.
// That is what makes columnValuesForForm's best-effort parse safe: it only has
// to be good enough to display, because a list the user did not edit and did
// not retype does not round-trip through it. Changing ENUM to SET (or back)
// while leaving the members alone is a real request, so it leaves the shortcut
// and reassembles under the new base type — that path does depend on the parse,
// which is the intended trade for honoring the change at all.
func columnType(d driver.Dialect, editor driver.SchemaEditor, form url.Values, base string, existing *model.Column) (string, error) {
	if !takesValueList(d, base) {
		typ, ok := assembleColumnType(editor, base, form.Get("col_length"))
		if !ok {
			return "", errors.New("invalid or unsupported column type")
		}
		return typ, nil
	}
	canon, ok := canonicalColumnType(editor, base)
	if !ok {
		return "", errors.New("invalid or unsupported column type")
	}
	values := valueListFromForm(form.Get("col_values"))
	// The base type has to match too, not just the members: ENUM and SET are
	// both list-valued, so comparing only the list returned the OLD type for an
	// ENUM -> SET change with an untouched textarea — the column kept its type
	// while the UI reported success.
	if existing != nil && takesValueList(d, existing.BaseType) &&
		strings.EqualFold(canon, existing.BaseType) &&
		valueListForForm(values) == columnValuesForForm(*existing) {
		return existing.DataType, nil
	}
	if len(values) == 0 {
		return "", errors.New("a " + canon + " column needs at least one value — enter one per line")
	}
	return d.(driver.ValueListTyper).ValueListType(canon, values)
}

// canonicalColumnType maps an introspected base type onto the editor's
// allowlist spelling (case-insensitive), so the server-rendered type select
// can preselect the current type. ok=false means the type has no allowlist
// entry (the partial then renders a disabled placeholder instead of letting
// the browser default to the first option).
func canonicalColumnType(editor driver.SchemaEditor, base string) (string, bool) {
	for _, t := range editor.ColumnTypes() {
		if strings.EqualFold(t, base) {
			return t, true
		}
	}
	return base, false
}

// takesValueList reports whether base is one of the engine's list-valued types
// (MySQL ENUM/SET). An engine without a ValueListTyper has none, so the whole
// value-list path — control, parsing and validation — simply does not exist
// there.
func takesValueList(d driver.Dialect, base string) bool {
	typer, ok := d.(driver.ValueListTyper)
	if !ok {
		return false
	}
	for _, t := range typer.ValueListTypes() {
		if strings.EqualFold(t, base) {
			return true
		}
	}
	return false
}

// valueListFromForm parses the col_values control: one value PER LINE, in
// order, blank lines dropped. Newline-separated rather than a comma-separated
// 'a','b' list, because a value containing a comma (or a quote)
// is then not a parsing problem at all — nothing here has to strip quoting the
// user typed, and nothing has to guess where a value ends.
//
// A trailing \r is stripped: a browser posts textarea content with CRLF line
// endings, and 'a\r' is a different ENUM member from 'a'.
func valueListFromForm(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if v := strings.TrimRight(line, "\r"); strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// valueListForForm renders a value list back into the textarea's content.
func valueListForForm(values []string) string {
	return strings.Join(values, "\n")
}

// assembleColumnType builds a validated type from an allowlisted base type plus
// an optional length/precision. It returns the canonical (allowlist) casing so
// no raw user type string ever reaches the DDL.
func assembleColumnType(editor driver.SchemaEditor, base, length string) (string, bool) {
	base = strings.TrimSpace(base)
	canonical := ""
	for _, t := range editor.ColumnTypes() {
		if strings.EqualFold(t, base) {
			canonical = t
			break
		}
	}
	if canonical == "" {
		return "", false
	}
	if length = strings.TrimSpace(length); length == "" {
		return canonical, true
	}
	if !lengthRE.MatchString(length) {
		return "", false
	}
	return canonical + "(" + length + ")", true
}

// buildDefault converts the default radio selection into a ColumnSpec.Default:
// none → nil; null → "NULL"; current → "CURRENT_TIMESTAMP" (temporal types
// only); custom → a validated numeric literal for numeric types, otherwise a
// QuoteString-quoted literal. No raw default expression reaches the DDL.
func buildDefault(d driver.Dialect, mode, value, base string) (*string, error) {
	switch mode {
	case "", "none":
		return nil, nil
	case "null":
		s := "NULL"
		return &s, nil
	case "current":
		if !isTemporalBaseType(base) {
			return nil, errors.New("CURRENT_TIMESTAMP is only valid for date/time columns")
		}
		s := "CURRENT_TIMESTAMP"
		return &s, nil
	case "custom":
		value = strings.TrimSpace(value)
		if isNumericBaseType(base) {
			if !numericLiteralRE.MatchString(value) {
				return nil, errors.New("numeric default must be a number")
			}
			return &value, nil
		}
		s := d.QuoteString(value)
		return &s, nil
	}
	return nil, errors.New("invalid default option")
}

var bareIdentRE = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// preserveColumnAttrs copies attributes the modify form cannot express from the
// existing column into spec, so an engine that restates the whole column (MySQL)
// does not drop them. Values come from introspection (DB metadata); the bare
// identifier / CURRENT_TIMESTAMP shapes are validated before they are emitted.
// Per-attribute engines (PostgreSQL) ignore these spec fields, except Identity.
func preserveColumnAttrs(spec *driver.ColumnSpec, c model.Column) {
	spec.AutoIncrement = c.IsAutoIncrement
	// MySQL COLUMN_TYPE carries the numeric attributes ("int unsigned zerofill");
	// columnDef re-emits them only on types where they are valid.
	dt := strings.ToLower(c.DataType)
	spec.Unsigned = strings.Contains(dt, " unsigned")
	spec.Zerofill = strings.Contains(dt, " zerofill")
	if bareIdentRE.MatchString(c.Collation) {
		spec.Collation = c.Collation
	}
	if bareIdentRE.MatchString(c.Charset) {
		spec.Charset = c.Charset
	}
	// Both of these are typed fields on model.Column now, parsed by the dialect
	// that understands them, so this is a copy rather than a pattern match over
	// another engine's free-text Extra. Identity matters here because
	// ModifyColumnSQL must not DROP/SET DEFAULT on an identity column.
	spec.OnUpdate = c.OnUpdate
	spec.Identity = c.Identity
}

// applyExprDefault keeps an expression default verbatim when the user did not
// change the default controls. The form can only express literals, so
// re-quoting the displayed expression would corrupt the column (DEFAULT
// CURRENT_TIMESTAMP becoming DEFAULT 'CURRENT_TIMESTAMP', nextval(...) becoming
// a string). Unchanged is detected by comparing the submitted controls with
// the values the form was prefilled with (columnDefaultForForm).
func applyExprDefault(spec *driver.ColumnSpec, existing model.Column, form url.Values) {
	if !unchangedExprDefault(existing, form) {
		return
	}
	spec.Default = existing.Default
	spec.DefaultExpr = true
}

// unchangedExprDefault reports whether existing carries an expression default
// (DefaultIsExpr) that the submitted form did not change — the mode still equals
// the prefilled value and, for a custom default, the value text is byte-identical
// to what the form was populated with. Such a default cannot flow through
// buildDefault (a numeric-typed expression is not a numeric literal), so both the
// spec-build skip and the verbatim reinstall key on this one predicate.
func unchangedExprDefault(existing model.Column, form url.Values) bool {
	if !existing.DefaultIsExpr || existing.Default == nil {
		return false
	}
	mode, val := columnDefaultForForm(existing)
	if form.Get("default_mode") != mode {
		return false
	}
	if mode == "custom" && strings.TrimSpace(form.Get("default_value")) != val {
		return false
	}
	return true
}

// placeFirstToken is the col_after value meaning "at the very front". It is a
// sentinel rather than an empty string because empty already means "wherever
// the engine would put it", and it cannot collide with a column name:
// ValidNewIdentifier rejects '_' bracketing like this, and even if a column
// were somehow called this, the value is compared BEFORE the name lookup.
const placeFirstToken = "__first__"

// columnPlacement reads the position control and validates it against the
// table's current columns. self is the column being modified ("" on the add
// path); placing a column after itself is a no-op MySQL rejects, so it is
// refused here with a sentence the user can act on.
//
// Placement is only read when the engine supports it. Handing a placement to an
// engine that cannot reorder would be silently ignored by the dialect (see
// drivertest's checkColumnPlacement), but refusing it here means the user is
// told, rather than watching the column not move.
func columnPlacement(form url.Values, caps driver.Capabilities, cols []model.Column, self string) (driver.ColumnPlacement, string, error) {
	v := strings.TrimSpace(form.Get("col_after"))
	if v == "" {
		return driver.PlaceDefault, "", nil
	}
	if !caps.SupportsColumnPosition {
		return 0, "", errors.New("This engine cannot reorder columns.")
	}
	if v == placeFirstToken {
		return driver.PlaceFirst, "", nil
	}
	if !columnExists(cols, v) {
		return 0, "", errors.New("Unknown column to position after.")
	}
	if v == self {
		return 0, "", errors.New("A column cannot be placed after itself.")
	}
	return driver.PlaceAfter, v, nil
}

// formBaseType returns the submitted base column type, normalized.
func formBaseType(form url.Values) string {
	return strings.ToLower(strings.TrimSpace(form.Get("col_type")))
}

// buildModifyColumns derives the pre-filled Modify-column form values for each
// column. The values that round-trip losslessly (type/length/nullable/comment)
// are carried verbatim; the default is mapped best-effort (see
// columnDefaultForForm).
func buildModifyColumns(cols []model.Column) []modifyColumnVM {
	out := make([]modifyColumnVM, 0, len(cols))
	for _, c := range cols {
		mode, val := columnDefaultForForm(c)
		out = append(out, modifyColumnVM{
			Name:         c.Name,
			Type:         c.BaseType,
			Length:       columnLengthForForm(c),
			Nullable:     c.Nullable,
			DefaultMode:  mode,
			DefaultValue: val,
			Comment:      c.Comment,
			Generated:    c.IsGenerated,
			Values:       columnValuesForForm(c),
		})
	}
	return out
}

// columnLengthForForm extracts a numeric length/precision ("255" or "10,2") from
// the full data type. Non-numeric parenthesised parts (e.g. an ENUM value list)
// are skipped — the length input only accepts digits.
func columnLengthForForm(c model.Column) string {
	i := strings.IndexByte(c.DataType, '(')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(c.DataType[i:], ')')
	if j < 0 {
		return ""
	}
	inner := strings.TrimSpace(c.DataType[i+1 : i+j])
	if lengthRE.MatchString(inner) {
		return inner
	}
	return ""
}

// columnValuesForForm extracts an ENUM/SET column's members from its
// introspected type — enum('a','b') becomes "a\nb", and a member's own quote
// arrives doubled and is collapsed — for the editor's
// prefill. It is best-effort by design: a list the user does not touch is
// carried through as the ORIGINAL type string rather than being reassembled
// from this parse (see columnType), so a member this misreads cannot corrupt
// the column. Both MySQL escapes are handled: a doubled quote and a
// backslash-escaped character.
func columnValuesForForm(c model.Column) string {
	i := strings.IndexByte(c.DataType, '(')
	if i < 0 || !strings.HasSuffix(c.DataType, ")") {
		return ""
	}
	body := c.DataType[i+1 : len(c.DataType)-1]
	var values []string
	var cur strings.Builder
	inStr := false
	for j := 0; j < len(body); j++ {
		ch := body[j]
		switch {
		case !inStr && ch == '\'':
			inStr = true
			cur.Reset()
		case !inStr:
			// Separator territory (a comma and any spacing); ignore.
		case ch == '\\' && j+1 < len(body):
			j++
			cur.WriteByte(body[j])
		case ch == '\'' && j+1 < len(body) && body[j+1] == '\'':
			j++
			cur.WriteByte('\'')
		case ch == '\'':
			inStr = false
			values = append(values, cur.String())
		default:
			cur.WriteByte(ch)
		}
	}
	if inStr { // unterminated: the parse is unreliable, so offer nothing
		return ""
	}
	return valueListForForm(values)
}

// columnDefaultForForm maps an introspected default to the form's
// (default_mode, default_value). It is best-effort: literal defaults round-trip,
// but exotic expression defaults vary by engine/version (MySQL stores string
// literals unquoted, MariaDB/PostgreSQL quote them), so the pre-filled value
// should be confirmed before applying.
//
// The "null" and "current" radios are classified from the KIND flags, never
// from the spelling alone: a MariaDB literal string default 'NULL' or
// 'CURRENT_TIMESTAMP' arrives here already unquoted (mysqlDefaultKind strips
// the quotes) and must stay a custom literal — mapping it by spelling would
// silently rewrite DEFAULT 'NULL' into DEFAULT NULL (or a string into a real
// expression) on the next modify. Engines that carry defaults as verbatim SQL
// (DefaultIsExpr: SQLite's PRAGMA text, PostgreSQL's pg_get_expr) may match
// the keywords textually — there a quoted literal still carries its quotes,
// so bare NULL / CURRENT_TIMESTAMP are unambiguous.
func columnDefaultForForm(c model.Column) (mode, value string) {
	if c.Default == nil {
		return "none", ""
	}
	if c.DefaultIsNull {
		return "null", "" // explicit DEFAULT NULL keyword (MariaDB)
	}
	d := strings.TrimSpace(*c.Default)
	up := strings.ToUpper(d)
	if c.DefaultIsExpr {
		switch {
		case up == "NULL":
			return "null", ""
		case strings.HasPrefix(up, "CURRENT_TIMESTAMP"), up == "NOW()":
			return "current", ""
		}
	}
	// Unwrap a PostgreSQL "'x'::type" cast, then surrounding single quotes, so a
	// string default round-trips through buildDefault's QuoteString. Only a cast
	// of a whole quoted literal qualifies — an expression like
	// nextval('seq'::regclass) must stay intact.
	if k := strings.LastIndex(d, "::"); k > 0 && d[0] == '\'' && strings.HasSuffix(d[:k], "'") {
		d = d[:k]
	}
	if len(d) >= 2 && d[0] == '\'' && d[len(d)-1] == '\'' {
		d = strings.ReplaceAll(d[1:len(d)-1], "''", "'")
	}
	return "custom", d
}

func isNumericBaseType(base string) bool {
	return model.Column{BaseType: strings.ToLower(strings.TrimSpace(base))}.IsNumeric()
}

func isTemporalBaseType(base string) bool {
	return isTemporalType(model.Column{BaseType: strings.ToLower(strings.TrimSpace(base))})
}

// validReferentialAction normalizes and validates an ON UPDATE / ON DELETE
// action. The empty string (unspecified) is allowed; any other value must be one
// of the SQL-standard actions. Returns the canonical upper-case keyword and ok.
func validReferentialAction(s string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "":
		return "", true
	case "NO ACTION":
		return "NO ACTION", true
	case "RESTRICT":
		return "RESTRICT", true
	case "CASCADE":
		return "CASCADE", true
	case "SET NULL":
		return "SET NULL", true
	case "SET DEFAULT":
		return "SET DEFAULT", true
	}
	return "", false
}
