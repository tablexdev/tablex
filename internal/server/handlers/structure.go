package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/sqlscript"
	"github.com/tablexdev/tablex/internal/view"
)

type structureBody struct {
	Scope          reqScope
	Columns        []model.Column
	Indexes        []model.Index
	ForeignKeys    []foreignKeyVM
	DDL            string
	IsView         bool
	RowCount       int64
	RowCountApprox bool // RowCount is a statistics estimate, not an exact count
	HasRowCount    bool
	SectionError   string // a section (indexes/FKs/DDL/table list) failed to load
	Caps           driver.Capabilities

	// Structure-editing support (all false / empty when the engine has no
	// SchemaEditor or the target is a view).
	CanEdit        bool             // editor present and not a view: add/drop column, add/drop index
	Tables         []string         // base-table names in scope (foreign-key reference targets)
	PostURL        string           // structure POST target
	ModifyColumns  []modifyColumnVM // selection list for the Modify-column picker (empty unless SupportsColumnModify)
	ModifySelected string           // ?modify=<column> — the column the editor below is prefilled for
	AddForm        columnFormVM     // Add-column controls (type list, zero prefill)
	ModifyForm     *columnFormVM    // Modify-column editor, server-prefilled; nil until a column is selected

	// Index-creation controls: what this engine can express about an index,
	// plus the fixed batch of blank key-part rows the no-JS form submits.
	IndexOptions  driver.IndexOptions
	IndexRowIndex []int
}

// indexFormRows is the number of key-part rows the add-index form offers. A
// composite index beyond this many columns is rare enough to belong in the SQL
// console; the rows exist because a multi-select cannot express key ORDER, a
// prefix length or a direction.
const indexFormRows = 5

// TableStructure serves the Structure tab. GET renders columns, indexes, foreign
// keys and the reconstructed/native CREATE statement; POST runs a structure-edit
// operation (add/modify/drop column, add/drop index, add/drop FK).
func (h *Handlers) TableStructure(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	if !h.requireDataTable(w, r, conn, sc) {
		return
	}
	ctx := r.Context()

	if r.Method == http.MethodPost {
		h.runStructureOp(w, r, uc, conn, sc)
		return
	}

	ref := sc.tableRef()
	body := structureBody{Scope: sc, Caps: uc.Capabilities(), PostURL: urlTable(sc.DB, sc.Schema, sc.Table, "structure")}

	cols, err := conn.Columns(ctx, ref)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	body.Columns = cols

	addWarn := func(msg string) {
		if body.SectionError != "" {
			body.SectionError += "; "
		}
		body.SectionError += msg
	}
	if idx, err := conn.Indexes(ctx, ref); err == nil {
		body.Indexes = idx
	} else {
		addWarn("indexes unavailable: " + err.Error())
	}
	if uc.Capabilities().HasForeignKeys {
		if fks, err := conn.ForeignKeys(ctx, ref); err == nil {
			for _, fk := range fks {
				body.ForeignKeys = append(body.ForeignKeys, foreignKeyVM{
					ForeignKey: fk,
					RefHidden:  h.fkRefHidden(uc.Capabilities(), fk),
				})
			}
		} else {
			addWarn("foreign keys unavailable: " + err.Error())
		}
	}
	if ddl, err := conn.CreateSQL(ctx, ref); err == nil {
		body.DDL = ddl
	} else {
		addWarn("CREATE statement unavailable: " + err.Error())
	}
	// Detect view + collect base-table names from the table listing. This runs
	// BEFORE the row count, which needs IsView to decide whether COUNT(*) may
	// cost an unbounded re-run of the view's query. The listing is memoized, so
	// the reordering costs nothing.
	listOK := false
	if tables, err := h.tableNames(ctx, conn, sc.scope()); err == nil {
		listOK = true
		for _, t := range tables {
			if t.Name == sc.Table && t.IsView() {
				body.IsView = true
			}
			if !t.IsView() && !t.IsSequence() {
				body.Tables = append(body.Tables, t.Name)
			}
		}
	} else {
		addWarn("table list unavailable: " + err.Error())
	}

	if n, approx := h.tableRowCount(ctx, conn, ref, false, body.IsView); n >= 0 {
		body.RowCount = n
		body.RowCountApprox = approx
		body.HasRowCount = true
	}

	// Editing controls require a SchemaEditor, a real (non-view) table, and a
	// successful table listing — so a view whose IsView detection failed above
	// (list error) does not wrongly get add/drop-column controls.
	if editor, ok := conn.Dialect().(driver.SchemaEditor); ok && !body.IsView && listOK {
		// Narrowed by the [restrict] policy as well as by the engine: the template
		// gates every add/drop/edit affordance on this one flag, so the whole
		// structure editor disappears together rather than one button at a time.
		// The column and index LISTINGS stay — they are reads, and this page is
		// where a user goes to see the shape of a table.
		body.CanEdit = h.allowance().DDL
		body.IndexOptions = indexOptions(conn.Dialect())
		body.IndexRowIndex = make([]int, indexFormRows)
		for i := range body.IndexRowIndex {
			body.IndexRowIndex[i] = i
		}
		body.AddForm = newColumnForm(editor, uc.Capabilities(), cols, "")
		if uc.Capabilities().SupportsColumnModify {
			body.ModifyColumns = buildModifyColumns(cols)
			// Column selection is a GET round-trip (?modify=<name>): the POST
			// editor renders that column's current definition server-side and
			// carries the column as an immutable hidden input, so a no-JS
			// submit preserves everything the user did not change. An unknown
			// name simply renders no editor.
			if name := r.URL.Query().Get("modify"); name != "" {
				for _, mc := range body.ModifyColumns {
					if mc.Name != name {
						continue
					}
					vm := newColumnForm(editor, uc.Capabilities(), cols, name)
					vm.Sel = mc
					f := &vm
					if canon, ok := canonicalColumnType(editor, mc.Type); ok {
						f.Sel.Type = canon // allowlist casing, so the option preselects
					} else {
						f.TypeUnrecognized = true
					}
					body.ModifyForm = f
					body.ModifySelected = name
					break
				}
			}
		}
	}

	p := h.newLoggedPage(r, uc, sc.Table+" · Structure")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, "structure", conn)
	p.Body = body
	h.render(w, r, "table_structure", p)
}

// runStructureOp validates and runs one structure-edit operation, mirroring
// operations.go's runTableOp (ParseForm → validate → build → exec → redirect
// with a flash). All identifier/type/default/referential-action validation
// happens here, before any SchemaEditor builder is called.
func (h *Handlers) runStructureOp(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope) {
	if !h.parseFormOr400(w, r) {
		return
	}
	editor, ok := conn.Dialect().(driver.SchemaEditor)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support structure editing.", "")
		return
	}
	exists, err := h.tableExists(r.Context(), conn, sc)
	if err != nil {
		// Not a 404: a structure edit must be able to tell "the table is
		// gone" from "nothing could be read".
		h.Log.Warn("structure edit lookup failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
		h.renderError(w, r, http.StatusInternalServerError, "Could not verify the table before editing its structure.", "")
		return
	}
	if !exists {
		h.renderError(w, r, http.StatusNotFound, "Table not found.", "")
		return
	}
	structureURL := urlTable(sc.DB, sc.Schema, sc.Table, "structure")
	// Views are read-only: the handler is the authority (the UI also hides the
	// controls). Reject every action up front — and fail CLOSED on a lookup
	// error, which must not read as "not a view".
	vw, err := h.isView(r.Context(), conn, sc)
	if err != nil {
		h.Log.Warn("structure edit view lookup failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
		h.renderError(w, r, http.StatusInternalServerError, "Could not verify the table before editing its structure.", "")
		return
	}
	if vw {
		h.redirectTo(w, r, structureURL, view.Flash{Kind: "error", Message: "Views are read-only; their structure cannot be edited."})
		return
	}

	op := &structureOp{
		r:      r,
		form:   r.PostForm,
		conn:   conn,
		sc:     sc,
		ref:    sc.tableRef(),
		caps:   conn.Capabilities(),
		d:      conn.Dialect(),
		editor: editor,
	}
	if op.cols, err = conn.Columns(r.Context(), op.ref); err != nil {
		h.dbError(w, r, err, "")
		return
	}

	build, ok := structureOps[r.PostFormValue("action")]
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
		return
	}
	// THE THIRD ENFORCEMENT POINT for restricted mode (with saveProgram; see
	// programs.go). This route's need is the DDL one — add_column, drop_index and
	// add_fk must keep working under allow_console = false — so the console half
	// is checked here, where the action and its fields are finally known. Only the
	// partial-index PREDICATE is refused, never add_index itself: a blanket check
	// would refuse ordinary index creation and contradict docs/security.md's
	// negative sweep. It sits after the dispatch so an unknown action is still a
	// 400 rather than a 403 naming a setting it never reached.
	if r.PostFormValue("action") == "add_index" &&
		strings.TrimSpace(op.form.Get("index_where")) != "" && !h.allowance().Console {
		h.RefuseByPolicy(w, r, "Running SQL directly is disabled on this TableX (restrict.allow_console), and a partial index's WHERE condition is SQL this TableX cannot describe the reach of. Creating an index without one is still available.")
		return
	}
	stmts, flashMsg, err := build(h, op)
	if err != nil {
		// An opRefusal is a well-formed request the engine cannot satisfy, so it
		// belongs on the structure page as a flash; a failed LOOKUP is a
		// server-side fault (dbError: logged, redacted, 500); anything else is
		// a bad request and gets the 400 page.
		var refusal opRefusal
		if errors.As(err, &refusal) {
			h.redirectTo(w, r, structureURL, view.Flash{Kind: "error", Message: refusal.msg})
			return
		}
		if errors.Is(err, errStructureLookup) {
			h.dbError(w, r, err, "")
			return
		}
		h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}

	// Confirmation goes here, not in the arms: the statements are built and every
	// refusal has already been returned, so a rejection stays a rejection and the
	// operator is only ever asked about something that would actually run.
	if prompt := structureConfirmPrompt(r.PostFormValue("action"), op.form); prompt != "" {
		if !h.requireConfirm(w, r, uc, sc, prompt, structureURL, "Drop") {
			return
		}
	}

	if err := conn.ExecScript(r.Context(), stmts, op.caps.SupportsTransactionalDDL); err != nil {
		// Let the dialect translate an engine-specific DDL error into guidance
		// (e.g. PostgreSQL's dependent-view error) rather than sniffing text here.
		if hinter, ok := conn.Dialect().(driver.DDLErrorHint); ok {
			if hint, ok := hinter.DDLErrorHint(err); ok {
				// An engine failure (translated for the operator), not a
				// refused request — file it as such.
				h.redirectFailed(w, r, structureURL, hint)
				return
			}
		}
		h.dbError(w, r, err, strings.Join(stmts, ";\n"))
		return
	}
	h.redirectTo(w, r, structureURL, view.Flash{Kind: "success", Message: flashMsg})
}

// structureOp is one structure-editing request: the parsed form plus the
// connection state every arm needs, resolved once. The arms take this instead
// of a ResponseWriter — every response is runStructureOp's to write, so an arm
// can only validate, build statements and report why it refused.
type structureOp struct {
	r      *http.Request // for r.Context() and the sub-requests buildAddFK makes
	form   url.Values
	conn   *driver.Connection
	sc     reqScope
	ref    driver.TableRef
	caps   driver.Capabilities
	d      driver.Dialect
	editor driver.SchemaEditor
	cols   []model.Column // the table's current columns, read once
}

// opRefusal is a refusal that belongs on the structure page as an error flash
// rather than as a 400: the request was well-formed and the user did nothing
// wrong, the engine simply cannot do it (SQLite cannot drop a keyed column).
type opRefusal struct{ msg string }

func (e opRefusal) Error() string { return e.msg }

// structureOps maps the form's action to the arm that builds its DDL. Each arm
// returns the statements to run and the success flash, or an error describing
// the refusal. Adding an operation means one entry here and one function —
// the dispatch above never grows.
//
// An arm's error text is rendered to the user verbatim, so these are sentences
// (capitalized, punctuated), not the lower-case fragments Go errors usually
// carry. That is deliberate: the strings are the same ones the switch used to
// pass straight to renderError.
var structureOps = map[string]func(*Handlers, *structureOp) ([]string, string, error){
	"add_column":    (*Handlers).buildAddColumn,
	"modify_column": (*Handlers).buildModifyColumn,
	"rename_column": (*Handlers).buildRenameColumn,
	"drop_column":   (*Handlers).buildDropColumn,
	"add_index":     (*Handlers).buildAddIndex,
	"drop_index":    (*Handlers).buildDropIndex,
	"add_fk":        (*Handlers).buildAddFK,
	"drop_fk":       (*Handlers).buildDropFK,
}

// structureConfirmPrompt names the object for the confirmation page, or returns
// "" for the structure operations that are not destructive (adding a column or
// index takes no confirmation).
func structureConfirmPrompt(action string, form url.Values) string {
	switch action {
	case "drop_column":
		return fmt.Sprintf("Drop column %q and its data?", strings.TrimSpace(form.Get("column")))
	case "drop_index":
		return fmt.Sprintf("Drop index %q?", strings.TrimSpace(form.Get("index_name")))
	case "drop_fk":
		return fmt.Sprintf("Drop foreign key %q?", strings.TrimSpace(form.Get("fk_name")))
	}
	return ""
}

func (h *Handlers) buildAddColumn(op *structureOp) ([]string, string, error) {
	spec, err := columnSpec(op.d, op.editor, op.form, nil)
	if err != nil {
		return nil, "", err
	}
	spec.Name = strings.TrimSpace(op.form.Get("col_name"))
	if !driver.ValidNewIdentifier(op.caps, spec.Name) {
		return nil, "", errors.New("Invalid column name.")
	}
	if spec.Placement, spec.PlacementAfter, err = columnPlacement(op.form, op.caps, op.cols, ""); err != nil {
		return nil, "", err
	}
	stmts, err := op.editor.AddColumnSQL(op.ref, spec)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Column %q added.", spec.Name), nil
}

func (h *Handlers) buildModifyColumn(op *structureOp) ([]string, string, error) {
	if !op.caps.SupportsColumnModify {
		return nil, "", errors.New("Modifying columns is not supported on this engine.")
	}
	old := strings.TrimSpace(op.form.Get("column"))
	existing, found := findColumn(op.cols, old) // existing name: validate by exact match
	if !found {
		return nil, "", errors.New("Unknown column.")
	}
	// The structure page now displays a generated column's expression
	// (model.Column.GeneratedExpr), but the editor form still cannot express
	// one, so a whole-definition restate (MySQL) would drop it — refuse rather
	// than silently corrupt the column.
	if existing.IsGenerated {
		return nil, "", errors.New("Modifying a generated column is not supported.")
	}
	// The value list rides columnSpec now (columnType): a list the user did not
	// touch is carried through as the introspected type verbatim, and an edited
	// one is reassembled by the dialect with every member quoted.
	formBase := formBaseType(op.form)
	spec, err := columnSpec(op.d, op.editor, op.form, &existing)
	if err != nil {
		return nil, "", err
	}
	spec.Name = old // renaming is its own operation; keep the existing name
	// formBase and existing.BaseType share one normalized vocabulary, so this
	// reliably distinguishes a length/precision change from a base-type change
	// for PostgreSQL's USING.
	spec.SameBaseType = formBase == existing.BaseType
	// Preserve attributes the form cannot express (unsigned/zerofill,
	// auto_increment, ON UPDATE, charset/collation, PG identity) so MySQL's
	// whole-definition MODIFY does not silently drop them and PostgreSQL
	// does not DROP DEFAULT on an identity column.
	preserveColumnAttrs(&spec, existing)
	applyExprDefault(&spec, existing, op.form)
	// Reordering rides the modify path because that is the only shape MySQL
	// offers: MODIFY … AFTER x restates the column and moves it in one
	// statement. Nothing is moved unless the user picked a position.
	if spec.Placement, spec.PlacementAfter, err = columnPlacement(op.form, op.caps, op.cols, old); err != nil {
		return nil, "", err
	}
	// SupportsColumnModify was checked above; this assertion is the other
	// half of the same statement — an engine claiming the capability must
	// implement ColumnModifier, which its interfaces.go asserts at compile
	// time. SQLite implements neither, instead of carrying a method that
	// only ever returned an error.
	modifier, ok := op.d.(driver.ColumnModifier)
	if !ok {
		return nil, "", errors.New("Modifying a column is not supported on this engine.")
	}
	stmts, err := modifier.ModifyColumnSQL(op.ref, old, spec)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Column %q modified.", old), nil
}

// buildRenameColumn changes only the name. It is a separate operation from
// modify_column rather than a field on it because the two capabilities do not
// coincide: SQLite can rename but not redefine (no ColumnModifier at all),
// MariaDB before 10.5.2 the other way round. Keeping them apart also means a
// rename cannot become a redefinition by accident — see driver.ColumnRenamer.
func (h *Handlers) buildRenameColumn(op *structureOp) ([]string, string, error) {
	if !op.caps.SupportsColumnRename {
		return nil, "", errors.New("Renaming columns is not supported on this engine or server version.")
	}
	renamer, ok := op.d.(driver.ColumnRenamer)
	if !ok {
		return nil, "", errors.New("Renaming columns is not supported on this engine.")
	}
	old := strings.TrimSpace(op.form.Get("column"))
	if !columnExists(op.cols, old) { // existing name: exact match against introspection
		return nil, "", errors.New("Unknown column.")
	}
	newName := strings.TrimSpace(op.form.Get("new_name"))
	if !driver.ValidNewIdentifier(op.caps, newName) {
		return nil, "", errors.New("Invalid column name.")
	}
	if newName == old {
		return nil, "", errors.New("The new name is the same as the current one.")
	}
	// Collision is checked case-INSENSITIVELY: MySQL and SQLite resolve column
	// names without regard to case, so "id" and "ID" cannot coexist and the
	// engine's own error would be the only warning. Renaming a column to a
	// different case of its OWN name is still allowed — that is a case fix, and
	// old is excluded from the scan.
	for _, c := range op.cols {
		if c.Name != old && strings.EqualFold(c.Name, newName) {
			return nil, "", fmt.Errorf("Column %q already exists.", c.Name)
		}
	}
	stmts, err := renamer.RenameColumnSQL(op.ref, old, newName)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Column %q renamed to %q.", old, newName), nil
}

func (h *Handlers) buildDropColumn(op *structureOp) ([]string, string, error) {
	col := strings.TrimSpace(op.form.Get("column"))
	if !columnExists(op.cols, col) {
		return nil, "", errors.New("Unknown column.")
	}
	if len(op.cols) <= 1 {
		return nil, "", errors.New("Cannot drop the only column of a table.")
	}
	// Some engines (SQLite) cannot drop a PK / indexed / outgoing-FK column;
	// refuse up front with a clear message (rarer cases fall through).
	if op.caps.RestrictedDropColumn {
		if msg, blocked := h.sqliteDropColumnBlocked(op.r.Context(), op.conn, op.ref, op.cols, col); blocked {
			return nil, "", opRefusal{msg}
		}
	}
	stmts, err := op.editor.DropColumnSQL(op.ref, col)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Column %q dropped.", col), nil
}

func (h *Handlers) buildAddIndex(op *structureOp) ([]string, string, error) {
	spec := driver.IndexSpec{
		Name:   strings.TrimSpace(op.form.Get("index_name")),
		Unique: op.form.Get("index_unique") != "",
	}
	if !driver.ValidNewIdentifier(op.caps, spec.Name) {
		return nil, "", errors.New("Invalid index name.")
	}
	opts := indexOptions(op.d)
	var err error
	if spec.Columns, err = indexKeyParts(op.form, opts, op.cols); err != nil {
		return nil, "", err
	}
	if spec.Method, err = indexMethod(op.form, opts); err != nil {
		return nil, "", err
	}
	if spec.Where, err = indexPredicate(op.form, opts, driver.ProfileOf(op.d)); err != nil {
		return nil, "", err
	}
	stmts, err := op.editor.AddIndexSQL(op.ref, spec)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Index %q created.", spec.Name), nil
}

// indexOptions reports what the engine can express about an index. A dialect
// without IndexOptioner gets the zero value: name, columns and UNIQUE only.
func indexOptions(d driver.Dialect) driver.IndexOptions {
	if o, ok := d.(driver.IndexOptioner); ok {
		return o.IndexOptions()
	}
	return driver.IndexOptions{}
}

// indexMaxPrefix bounds a prefix length. MySQL's own ceiling is 3072 bytes
// (InnoDB, DYNAMIC row format); anything larger is the server's error to give,
// but a bare digit string is not a number we should hand on unchecked.
const indexMaxPrefix = 3072

// indexKeyParts reads the per-row key-part controls in FORM ORDER: the repeated
// index_columns select paired with index_prefix_N / index_desc_N by row.
//
// Rows are used instead of one multi-select because a multi-select cannot
// express key ORDER — a browser submits its options in DOM order, not selection
// order, so "(b, a)" was never expressible — nor a per-column prefix or
// direction. Blank rows are skipped, as in the create-table grid.
func indexKeyParts(form url.Values, opts driver.IndexOptions, cols []model.Column) ([]driver.IndexColumn, error) {
	var out []driver.IndexColumn
	seen := map[string]bool{}
	for i, name := range form["index_columns"] {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !columnExists(cols, name) {
			return nil, errors.New("Unknown column in index.")
		}
		if seen[name] {
			return nil, fmt.Errorf("Column %q is listed twice in the index.", name)
		}
		seen[name] = true
		part := driver.IndexColumn{Name: name}
		sfx := "_" + strconv.Itoa(i)
		if p := strings.TrimSpace(form.Get("index_prefix" + sfx)); p != "" {
			if !opts.SupportsPrefix {
				return nil, errors.New("This engine does not support index prefix lengths.")
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > indexMaxPrefix {
				return nil, fmt.Errorf("Invalid prefix length for %q.", name)
			}
			part.Prefix = n
		}
		if form.Get("index_desc"+sfx) != "" {
			// MariaDB parses DESC and ignores it, so claiming support there
			// would produce an index that is not what the user asked for and
			// says nothing about it.
			if !opts.SupportsDesc {
				return nil, errors.New("This engine does not support descending index columns.")
			}
			part.Desc = true
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, errors.New("Select at least one column for the index.")
	}
	return out, nil
}

// indexMethod matches the submitted access method against the engine's own
// list. It is emitted as a bare keyword, so an exact match against that list is
// the only thing that may reach the statement.
func indexMethod(form url.Values, opts driver.IndexOptions) (string, error) {
	m := strings.TrimSpace(form.Get("index_method"))
	if m == "" {
		return "", nil
	}
	for _, known := range opts.Methods {
		if m == known {
			return known, nil
		}
	}
	return "", errors.New("Unknown index method.")
}

// indexPredicateMaxLen bounds the partial-index predicate. It is a WHERE
// clause, not an essay; a cap keeps a pathological body out of the DDL and out
// of the error page that would echo it.
const indexPredicateMaxLen = 1000

// indexPredicate validates a partial index's WHERE clause.
//
// This is one of the places TableX puts user-WRITTEN SQL into a statement it
// builds, because a predicate is an expression and no placeholder can carry one.
// The others are the console, SQL import and a stored program's body;
// allow_console = false closes all four (docs/security.md §4, §9). It grants no
// privilege the user
// does not already have — the same session, the same credentials, and the
// console next door — but it is still checked rather than trusted. The clause is
// split under the dialect's OWN lexer grammar (prof) and must BE the single
// statement that comes back: a ';' that would end it is refused, one inside a
// quoted span is data. The scans below then refuse a comment introducer that
// could hide a tail and unbalanced parentheses outside string literals — neither
// is something the splitter reports, so they are kept as belt-and-braces rather
// than as the guarantee. See docs/security.md.
func indexPredicate(form url.Values, opts driver.IndexOptions, prof driver.LexerProfile) (string, error) {
	w := strings.TrimSpace(form.Get("index_where"))
	if w == "" {
		return "", nil
	}
	if !opts.SupportsPartial {
		return "", errors.New("This engine does not support partial indexes.")
	}
	if len(w) > indexPredicateMaxLen {
		return "", fmt.Errorf("The index condition is too long (limit %d characters).", indexPredicateMaxLen)
	}
	// len != 1 catches a multi-statement payload (and a comment-only input,
	// which the splitter drops to zero); the equality catches a trailing
	// separator, which Split strips before returning.
	stmts := sqlscript.Split(w, prof)
	if len(stmts) != 1 || stmts[0] != w {
		return "", errors.New("The index condition must be a single expression.")
	}
	depth := 0
	inStr := false
	for i := 0; i < len(w); i++ {
		if inStr {
			switch {
			case w[i] == '\'' && i+1 < len(w) && w[i+1] == '\'':
				i++ // an escaped quote, still inside the literal
			case w[i] == '\'':
				inStr = false
			}
			continue
		}
		switch {
		case w[i] == '\'':
			inStr = true
		case w[i] == '-' && i+1 < len(w) && w[i+1] == '-',
			w[i] == '/' && i+1 < len(w) && w[i+1] == '*',
			w[i] == '#':
			return "", errors.New("The index condition may not contain a comment.")
		case w[i] == '(':
			depth++
		case w[i] == ')':
			depth--
			if depth < 0 {
				return "", errors.New("The index condition has unbalanced parentheses.")
			}
		}
	}
	if inStr {
		return "", errors.New("The index condition has an unterminated string literal.")
	}
	if depth != 0 {
		return "", errors.New("The index condition has unbalanced parentheses.")
	}
	return w, nil
}

func (h *Handlers) buildDropIndex(op *structureOp) ([]string, string, error) {
	name := strings.TrimSpace(op.form.Get("index_name"))
	idx, found, err := h.findIndex(op.r.Context(), op.conn, op.ref, name)
	if err != nil {
		return nil, "", fmt.Errorf("%w: verifying index %q: %v", errStructureLookup, name, err)
	}
	if !found {
		return nil, "", errors.New("Unknown index.")
	}
	if idx.Primary {
		return nil, "", errors.New("The primary key index cannot be dropped here.")
	}
	stmts, err := op.editor.DropIndexSQL(op.ref, name)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Index %q dropped.", name), nil
}

func (h *Handlers) buildDropFK(op *structureOp) ([]string, string, error) {
	fkEditor, err := foreignKeyEditor(op.conn)
	if err != nil {
		return nil, "", err
	}
	name := strings.TrimSpace(op.form.Get("fk_name"))
	exists, err := h.fkExists(op.r.Context(), op.conn, op.ref, name)
	if err != nil {
		return nil, "", fmt.Errorf("%w: verifying foreign key %q: %v", errStructureLookup, name, err)
	}
	if !exists {
		return nil, "", errors.New("Unknown foreign key.")
	}
	stmts, err := fkEditor.DropForeignKeySQL(op.ref, name)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Foreign key %q dropped.", name), nil
}

// foreignKeyVM is a foreign key plus whether its referenced object has to be
// withheld from this page. The flag rides the view model rather than the
// template so the decision is made once, in the handler, and both the structure
// page and the designer read the same answer.
type foreignKeyVM struct {
	model.ForeignKey
	RefHidden bool
}

// fkRefHidden reports whether a foreign key points into a DATABASE that
// restrict.database_allowlist does not name. Such a key must be masked WHOLE —
// database, table and columns — not merely stripped of its qualifier: dropping
// only the prefix still leaves "orders(id)" on screen, which is the table and
// column names of a database the operator was refused.
//
// The discriminator is Capabilities().HasSchemas, and no new capability field.
// model.ForeignKey carries ONE RefSchema whose MEANING is engine-dependent: on
// MySQL/MariaDB it is REFERENCED_TABLE_SCHEMA — a database — while on PostgreSQL
// it is n.nspname, an ordinary schema. database_allowlist names databases, and a
// PostgreSQL schema is not one, so a generic test would hide every legitimate
// cross-schema key on PostgreSQL while never being able to express a PG database
// in that field at all.
//
// RefSchema denotes a database EXACTLY when the engine has no schema level, so
// this is correct on all three by construction: MySQL/MariaDB → HasSchemas
// false, the value is a database, the test applies; PostgreSQL → true, the value
// is a schema, the test never fires; SQLite → false, but its foreign keys carry
// no qualifier, so RefSchema is empty and the guard is inert.
//
// Do NOT "clarify" this into a dedicated capability flag. Reusing HasSchemas
// costs internal/driver's line budget nothing, and driver.go sits exactly on its
// size pin.
//
// Inert unless an allowlist is configured: DatabaseAllowed permits everything
// when the list is empty.
func (h *Handlers) fkRefHidden(caps driver.Capabilities, fk model.ForeignKey) bool {
	return !caps.HasSchemas && fk.RefSchema != "" && !h.Cfg.Restrict.DatabaseAllowed(fk.RefSchema)
}

// foreignKeyEditor resolves the dialect's FK builders. The capability flag and
// the interface are two statements of the same fact — SQLite sets
// SupportsForeignKeyDDL false and implements neither builder — so both are
// checked here rather than leaving one of them decorative.
func foreignKeyEditor(conn *driver.Connection) (driver.ForeignKeyEditor, error) {
	editor, ok := conn.Dialect().(driver.ForeignKeyEditor)
	if !ok || !conn.Capabilities().SupportsForeignKeyDDL {
		return nil, errors.New("Foreign-key editing is not supported on this engine.")
	}
	return editor, nil
}

// buildAddFK validates an add-foreign-key request and returns the statements.
// New names (the constraint) pass ValidNewIdentifier; existing objects (local
// and referenced columns, referenced table) are validated by exact match
// against introspection; referential actions go through the shared allowlist.
func (h *Handlers) buildAddFK(op *structureOp) ([]string, string, error) {
	editor, err := foreignKeyEditor(op.conn)
	if err != nil {
		return nil, "", err
	}
	r, conn, sc, ref, cols := op.r, op.conn, op.sc, op.ref, op.cols
	name := strings.TrimSpace(r.PostFormValue("fk_name"))
	if !driver.ValidNewIdentifier(conn.Capabilities(), name) {
		return nil, "", errors.New("invalid constraint name")
	}
	localCols := r.PostForm["fk_columns"]
	if len(localCols) == 0 {
		return nil, "", errors.New("select at least one column for the foreign key")
	}
	for _, c := range localCols {
		if !columnExists(cols, c) {
			return nil, "", errors.New("unknown column in foreign key")
		}
	}
	refTable := strings.TrimSpace(r.PostFormValue("fk_ref_table"))
	refExists, err := h.tableExists(r.Context(), conn, reqScope{DB: sc.DB, Schema: sc.Schema, Table: refTable})
	if err != nil {
		// Distinct from "unknown referenced table": the lookup itself failed,
		// and the FK must not be refused with a message blaming the name.
		return nil, "", fmt.Errorf("could not verify the referenced table: %w", err)
	}
	if !refExists {
		return nil, "", errors.New("unknown referenced table")
	}
	var refCols []string
	for _, c := range strings.Split(r.PostFormValue("fk_ref_columns"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			refCols = append(refCols, c)
		}
	}
	if len(refCols) != len(localCols) {
		return nil, "", errors.New("referenced column count must match the local column count")
	}
	refTableCols, err := conn.Columns(r.Context(), driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: refTable})
	if err != nil {
		return nil, "", err
	}
	for _, c := range refCols {
		if !columnExists(refTableCols, c) {
			return nil, "", errors.New("unknown referenced column")
		}
	}
	onUpd, ok1 := validReferentialAction(r.PostFormValue("fk_on_update"))
	onDel, ok2 := validReferentialAction(r.PostFormValue("fk_on_delete"))
	if !ok1 || !ok2 {
		return nil, "", errors.New("invalid referential action")
	}
	stmts, err := editor.AddForeignKeySQL(ref, name, localCols, refTable, refCols, onUpd, onDel)
	if err != nil {
		return nil, "", err
	}
	return stmts, fmt.Sprintf("Foreign key %q created.", name), nil
}

// --- introspection-backed existence checks --------------------------------------
//
// Every check here separates "the object is absent" from "nothing could be
// read" — the same contract tableExists/databaseExists carry, held by the same
// AST guard (TestTableExistsErrorIsNeverDiscarded). Swallowing the error
// conflated a transient privilege denial or timeout with absence: isView
// routed a view through the table code path, and the drop builders rendered
// "Unknown index." / "Unknown foreign key." with the cause neither logged nor
// shown.

// errStructureLookup marks a builder failure that came from INTROSPECTION —
// verifying the object before building its DDL — not from the request. The
// dispatch renders it as the server-side failure it is (dbError), never as a
// 400 blaming the request, and never as the "Unknown X." refusal that genuine
// absence gets.
var errStructureLookup = errors.New("structure lookup failed")

func (h *Handlers) isView(ctx context.Context, conn *driver.Connection, sc reqScope) (bool, error) {
	tables, err := h.tableNames(ctx, conn, sc.scope())
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == sc.Table {
			return t.IsView(), nil
		}
	}
	return false, nil
}

func (h *Handlers) findIndex(ctx context.Context, conn *driver.Connection, ref driver.TableRef, name string) (model.Index, bool, error) {
	idxs, err := conn.Indexes(ctx, ref)
	if err != nil {
		return model.Index{}, false, err
	}
	for _, i := range idxs {
		if i.Name == name {
			return i, true, nil
		}
	}
	return model.Index{}, false, nil
}

func (h *Handlers) fkExists(ctx context.Context, conn *driver.Connection, ref driver.TableRef, name string) (bool, error) {
	fks, err := conn.ForeignKeys(ctx, ref)
	if err != nil {
		return false, err
	}
	for _, fk := range fks {
		if fk.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// sqliteDropColumnBlocked reports a clear reason (and true) when SQLite cannot
// safely drop a column without an engine error we can detect first: the column
// is part of the primary key, is used by an index on this table, or participates
// in an outgoing foreign key. Incoming-FK and rarer cases fall through to the
// engine, surfaced via ExecScript → flash.
func (h *Handlers) sqliteDropColumnBlocked(ctx context.Context, conn *driver.Connection, ref driver.TableRef, cols []model.Column, col string) (string, bool) {
	for _, c := range cols {
		if c.Name == col && c.IsPrimaryKey {
			return fmt.Sprintf("Cannot drop %q on SQLite: it is part of the primary key.", col), true
		}
	}
	if idxs, err := conn.Indexes(ctx, ref); err == nil {
		for _, idx := range idxs {
			for _, ic := range idx.Columns {
				if ic.Name == col {
					return fmt.Sprintf("Cannot drop %q on SQLite: it is used by index %q.", col, idx.Name), true
				}
			}
		}
	}
	if fks, err := conn.ForeignKeys(ctx, ref); err == nil {
		for _, fk := range fks {
			for _, fc := range fk.Columns {
				if fc == col {
					return fmt.Sprintf("Cannot drop %q on SQLite: it is used by a foreign key.", col), true
				}
			}
		}
	}
	return "", false
}
