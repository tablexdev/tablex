package handlers

import (
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

// Stored-program administration — dropping routines, triggers and events —
// alongside the addressing rule the definition panels share with it.
//
// Both features have to name one object out of a rendered list, and both must
// keep doing so correctly when that list has moved on. The rule lives here once:
// an object is addressed by its POSITION in the list the page rendered plus its
// NAME, and the name is re-checked against that position before anything
// touches the database. Position alone is ambiguous after a concurrent change;
// name alone cannot distinguish PostgreSQL's overloaded functions, which share a
// proname. The identifier that finally reaches the dialect is the one
// introspection returned, never the one the request carried.

// errNoSuchObject is what a stale page hits: the addressed slot is gone, or now
// holds something else.
var errNoSuchObject = errors.New("this object no longer exists — reload the page")

// pickListed returns items[idx], but only if it still carries name.
func pickListed[T any](items []T, idx int, name string, nameOf func(T) string) (T, error) {
	var zero T
	if idx < 0 || idx >= len(items) || nameOf(items[idx]) != name {
		return zero, errNoSuchObject
	}
	return items[idx], nil
}

func (h *Handlers) resolveRoutine(r *http.Request, conn *driver.Connection, sc reqScope, name string, idx int) (model.Routine, error) {
	rs, err := conn.ListRoutines(r.Context(), sc.scope())
	if err != nil {
		return model.Routine{}, err
	}
	return pickListed(rs, idx, name, func(x model.Routine) string { return x.Name })
}

// resolveTrigger reapplies the caller's table filter first. The per-table
// triggers page renders a FILTERED slice, so its row indexes are positions in
// that slice, not in the database-wide list.
func (h *Handlers) resolveTrigger(r *http.Request, conn *driver.Connection, sc reqScope, name, table string, idx int) (model.Trigger, error) {
	ts, err := conn.ListTriggers(r.Context(), sc.scope())
	if err != nil {
		return model.Trigger{}, err
	}
	return pickListed(filterTriggers(ts, table), idx, name, func(x model.Trigger) string { return x.Name })
}

func (h *Handlers) resolveEvent(r *http.Request, conn *driver.Connection, sc reqScope, name string, idx int) (model.Event, error) {
	es, err := conn.ListEvents(r.Context(), sc.scope())
	if err != nil {
		return model.Event{}, err
	}
	return pickListed(es, idx, name, func(x model.Event) string { return x.Name })
}

// filterTriggers narrows a database-wide trigger list to one table. An empty
// table means "no filter" — the database-level page lists them all.
func filterTriggers(ts []model.Trigger, table string) []model.Trigger {
	if table == "" {
		return ts
	}
	out := make([]model.Trigger, 0, len(ts))
	for _, t := range ts {
		if t.Table == table {
			out = append(out, t)
		}
	}
	return out
}

// DBRoutinesManage handles POST /db/{db}/routines.
func (h *Handlers) DBRoutinesManage(w http.ResponseWriter, r *http.Request) {
	h.manageProgram(w, r, "routine")
}

// DBTriggersManage handles POST /db/{db}/triggers.
func (h *Handlers) DBTriggersManage(w http.ResponseWriter, r *http.Request) {
	h.manageProgram(w, r, "trigger")
}

// DBEventsManage handles POST /db/{db}/events.
func (h *Handlers) DBEventsManage(w http.ResponseWriter, r *http.Request) {
	h.manageProgram(w, r, "event")
}

// TableTriggersManage handles POST /db/{db}/table/{table}/triggers. It shares
// manageProgram: the table filter comes from the path, which resolveScope
// already reads, so the database-level and per-table pages need no separate
// logic.
func (h *Handlers) TableTriggersManage(w http.ResponseWriter, r *http.Request) {
	h.manageProgram(w, r, "trigger")
}

// manageProgram runs a stored-program action: drop, or save (create/redefine).
// An unrecognised action is refused rather than silently treated as one of them.
func (h *Handlers) manageProgram(w http.ResponseWriter, r *http.Request, kind string) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	form := r.PostForm
	action := form.Get("action")
	if action != "drop" && action != "save" {
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
		return
	}
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		// connError, like every other terminal dial failure: 503 (a service
		// condition, not a bad request or a bad upstream response) and the
		// redacted warn line — this path used to answer 502 and log nothing.
		h.connError(w, r, uc, err)
		return
	}
	if action == "save" {
		h.saveProgram(w, r, uc, conn, sc, kind, form)
		return
	}

	name := form.Get("name")
	idx, err := strconv.Atoi(form.Get("i"))
	if name == "" || err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Missing object reference.", "")
		return
	}
	noun, err := h.dropProgram(r, conn, sc, kind, name, idx, func(noun string) bool {
		return h.requireConfirm(w, r, uc, sc,
			fmt.Sprintf("Drop %s %q?", strings.ToLower(noun), name), programListURL(sc, kind), "Drop")
	})
	if errors.Is(err, errConfirmPending) {
		return // the confirmation page is already written
	}
	if err != nil {
		h.programError(w, r, err, "drop")
		return
	}
	h.redirectTo(w, r, programListURL(sc, kind), view.Flash{
		Kind: "success", Message: fmt.Sprintf("%s %q dropped.", noun, name),
	})
}

// programListURL is the page an action returns to. The per-table triggers page
// has its own URL, so an action posted from it must not bounce to the
// database-level one.
func programListURL(sc reqScope, kind string) string {
	if sc.Table != "" {
		return urlTable(sc.DB, sc.Schema, sc.Table, "triggers")
	}
	return urlDB(sc.DB, sc.Schema, kind+"s")
}

// programError maps a stored-program failure onto a status. A stale reference is
// a conflict, not a server fault, and an engine without the capability is a bad
// request rather than a 500.
func (h *Handlers) programError(w http.ResponseWriter, r *http.Request, err error, verb string) {
	switch {
	case errors.Is(err, errNoSuchObject):
		h.renderError(w, r, http.StatusConflict, err.Error(), "")
	case errors.Is(err, driver.ErrUnsupported):
		h.renderError(w, r, http.StatusBadRequest, "This engine cannot "+verb+" that object.", "")
	case errors.Is(err, errBadProgramDDL):
		h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
	default:
		h.dbError(w, r, err, "")
	}
}

// errConfirmPending is the sentinel dropProgram returns when it stopped to ask
// for confirmation. It is never rendered — the caller returns on it, because
// the confirmation page IS the response.
var errConfirmPending = errors.New("confirmation pending")

// errBadProgramDDL marks a definition the editor refuses before it reaches the
// server.
var errBadProgramDDL = errors.New("invalid definition")

// saveProgram creates a stored program, or redefines an existing one.
//
// The submitted text is the user's own DDL, run under their own credentials —
// the same bargain as the SQL console — but it is not passed through blind. It
// must lex as exactly ONE statement (so a definition cannot smuggle a second
// one past an engine whose driver happens to allow multi-statements) and that
// statement must create the kind of object the page it came from administers.
//
// ONE OF THE TWO ENFORCEMENT POINTS for restricted mode outside the middleware;
// the other is the partial-index predicate in structure.go, which is the same
// shape for the same reason. The middleware decides per ROUTE, and save and drop
// share one endpoint carrying an `action` field — so the route cannot tell "run
// this arbitrary body" from "drop this object by name". Its need is therefore
// the DDL one, because dropping must keep working under allow_console = false,
// and the console half is checked here where the action is finally known.
//
// What is checked is `allow_console`, not `allow_ddl`: validateProgramDDL below
// constrains only the OUTERMOST statement to be a CREATE of this page's kind.
// The body it wraps — a routine's, a trigger's, an event's — is unconstrained
// SQL and runs on the server, which is the same reach the console has and the
// reason allow_console exists.
func (h *Handlers) saveProgram(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope, kind string, form url.Values) {
	if !h.Cfg.Restrict.AllowConsole {
		h.RefuseByPolicy(w, r, "Running SQL directly is disabled on this TableX (restrict.allow_console), and a stored program's body is SQL this TableX cannot describe the reach of. Dropping one is still available.")
		return
	}
	definition := strings.TrimSpace(form.Get("definition"))
	if definition == "" {
		h.renderError(w, r, http.StatusBadRequest, "The definition is empty.", "")
		return
	}
	if err := validateProgramDDL(conn, kind, definition); err != nil {
		h.programError(w, r, err, "create")
		return
	}

	// A name means "redefine the object at this position"; its absence means a
	// new one. Redefining resolves the old object first, so the drop half names
	// something introspection returned.
	name := form.Get("name")
	if name == "" {
		if err := conn.CreateProgram(r.Context(), definition); err != nil {
			h.dbError(w, r, err, definition)
			return
		}
		h.redirectTo(w, r, programListURL(sc, kind), view.Flash{
			Kind: "success", Message: "Created.",
		})
		return
	}

	idx, err := strconv.Atoi(form.Get("i"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Missing object reference.", "")
		return
	}
	if err := h.replaceProgram(r, conn, sc, kind, name, idx, definition); err != nil {
		h.programError(w, r, err, "redefine")
		return
	}
	h.redirectTo(w, r, programListURL(sc, kind), view.Flash{
		Kind: "success", Message: fmt.Sprintf("%q saved.", name),
	})
}

// validateProgramDDL refuses a definition that is not a single CREATE of the
// expected kind.
func validateProgramDDL(conn *driver.Connection, kind, definition string) error {
	stmts := sqlscript.Split(definition, driver.ProfileOf(conn.Dialect()))
	if len(stmts) != 1 {
		return fmt.Errorf("%w: expected a single CREATE statement, found %d", errBadProgramDDL, len(stmts))
	}
	got, ok := driver.ProgramDDLKind(stmts[0])
	if !ok {
		return fmt.Errorf("%w: this does not look like a CREATE statement", errBadProgramDDL)
	}
	if !programKindMatches(kind, got) {
		return fmt.Errorf("%w: this page administers %ss, but the statement creates a %s",
			errBadProgramDDL, kind, got)
	}
	return nil
}

// programKindMatches maps a page's object kind onto the kinds a CREATE may
// declare. "routine" covers both procedures and functions.
func programKindMatches(page string, got driver.ProgramKind) bool {
	switch page {
	case "routine":
		return got == driver.ProgramProcedure || got == driver.ProgramFunction
	case "trigger":
		return got == driver.ProgramTrigger
	case "event":
		return got == driver.ProgramEvent
	}
	return false
}

// replaceProgram resolves the existing object, then hands its DROP and the new
// CREATE to Connection.ReplaceProgram, along with the object's current
// definition so a failed CREATE on a non-transactional engine can be undone.
func (h *Handlers) replaceProgram(r *http.Request, conn *driver.Connection, sc reqScope, kind, name string, idx int, definition string) error {
	ctx := r.Context()
	var drop []string
	var err error
	var current string

	// The object's current definition is the undo buffer for engines without
	// transactional DDL; it is exactly what the editor was pre-filled with.
	current, err = h.lookupDefinition(r, conn, sc, kind, name, sc.Table, idx)
	if err != nil {
		return err
	}

	switch kind {
	case "routine":
		rt, e := h.resolveRoutine(r, conn, sc, name, idx)
		if e != nil {
			return e
		}
		m, ok := conn.Dialect().(driver.RoutineManager)
		if !ok {
			return driver.ErrUnsupported
		}
		drop, err = m.DropRoutineSQL(sc.scope(), rt)
	case "trigger":
		tr, e := h.resolveTrigger(r, conn, sc, name, sc.Table, idx)
		if e != nil {
			return e
		}
		m, ok := conn.Dialect().(driver.TriggerManager)
		if !ok {
			return driver.ErrUnsupported
		}
		drop, err = m.DropTriggerSQL(sc.scope(), tr)
	case "event":
		ev, e := h.resolveEvent(r, conn, sc, name, idx)
		if e != nil {
			return e
		}
		m, ok := conn.Dialect().(driver.EventManager)
		if !ok {
			return driver.ErrUnsupported
		}
		drop, err = m.DropEventSQL(sc.scope(), ev)
	default:
		return errors.New("unknown object kind")
	}
	if err != nil {
		return err
	}
	return conn.ReplaceProgram(ctx, drop, definition, current)
}

// programEditBody backs the definition editor.
type programEditBody struct {
	Scope      reqScope
	Kind       string // "routine" / "trigger" / "event"
	Title      string
	Name       string // empty when creating
	Index      int
	Definition string
	PostURL    string
	CancelURL  string
	Note       string // engine caveat shown above the editor
}

// RoutineEditor opens the definition editor, as TriggerEditor and EventEditor
// do for their kinds. Separate entry points rather than one kind= route, so each
// list page's link is a plain URL and the kind cannot be spoofed into
// administering another kind.
func (h *Handlers) RoutineEditor(w http.ResponseWriter, r *http.Request) {
	h.programEditor(w, r, "routine")
}

func (h *Handlers) TriggerEditor(w http.ResponseWriter, r *http.Request) {
	h.programEditor(w, r, "trigger")
}

func (h *Handlers) EventEditor(w http.ResponseWriter, r *http.Request) {
	h.programEditor(w, r, "event")
}

// programEditor renders the editor, pre-filled with the object's current
// definition when one is being edited, or the dialect's skeleton when not.
func (h *Handlers) programEditor(w http.ResponseWriter, r *http.Request, kind string) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	q := r.URL.Query()
	name := q.Get("name")

	body := programEditBody{
		Scope:     sc,
		Kind:      kind,
		Name:      name,
		PostURL:   programListURL(sc, kind),
		CancelURL: programListURL(sc, kind),
	}
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		// Same rule as manageProgram above: a failed dial is connError's 503,
		// with its warn line, never a 502.
		h.connError(w, r, uc, err)
		return
	}
	if !programManageable(conn, kind) {
		h.renderError(w, r, http.StatusBadRequest, "This engine has no "+kind+"s to edit.", "")
		return
	}

	if name == "" {
		body.Title = "New " + kind
		body.Definition = programTemplate(conn, kind, q.Get("type"), sc.Table)
	} else {
		idx, err := strconv.Atoi(q.Get("i"))
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, "Missing object reference.", "")
			return
		}
		def, err := h.lookupDefinition(r, conn, sc, kind, name, sc.Table, idx)
		if err != nil {
			h.programError(w, r, err, "edit")
			return
		}
		body.Title = "Edit " + kind + " · " + name
		body.Index, body.Definition = idx, def
		// Saving is drop-then-create; say so where that is not atomic.
		if !conn.Capabilities().SupportsTransactionalDDL {
			body.Note = "Saving replaces this object: it is dropped and recreated. " +
				"This engine cannot do that in one transaction, so if the new definition " +
				"is rejected the current one is restored automatically."
		}
	}

	p := h.newLoggedPage(r, uc, body.Title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.NeedsEditor = true // this page carries a textarea.tx-sql-editor
	if sc.Table != "" {
		p.Tabs = h.tableTabs(r.Context(), uc, sc, "triggers", conn)
	} else {
		p.Tabs = h.dbTabs(uc, sc, kind+"s")
	}
	p.Body = body
	h.render(w, r, "program_edit", p)
}

// programManageable reports whether this engine administers the kind at all.
func programManageable(conn *driver.Connection, kind string) bool {
	switch kind {
	case "routine":
		return conn.CanManageRoutines()
	case "trigger":
		return conn.CanManageTriggers()
	case "event":
		return conn.CanManageEvents()
	}
	return false
}

// programTemplate asks the dialect for the skeleton. routineType selects
// procedure or function on the routines page; anything else means function,
// which every engine with routines has.
func programTemplate(conn *driver.Connection, kind, routineType, table string) string {
	switch kind {
	case "routine":
		if m, ok := conn.Dialect().(driver.RoutineManager); ok {
			want := driver.ProgramFunction
			if strings.EqualFold(routineType, "procedure") {
				want = driver.ProgramProcedure
			}
			return m.NewRoutineTemplate(want)
		}
	case "trigger":
		if m, ok := conn.Dialect().(driver.TriggerManager); ok {
			return m.NewTriggerTemplate(table)
		}
	case "event":
		if m, ok := conn.Dialect().(driver.EventManager); ok {
			return m.NewEventTemplate()
		}
	}
	return ""
}

// dropProgram resolves the object, drops it, and returns the noun for the
// success message.
// dropProgram resolves the addressed object and drops it. confirm is called
// AFTER resolution and before the drop, and returning false from it aborts
// silently — the confirmation page has already been written. That ordering is
// what keeps a stale reference a 409 instead of a confirmation prompt.
func (h *Handlers) dropProgram(r *http.Request, conn *driver.Connection, sc reqScope, kind, name string, idx int, confirm func(noun string) bool) (string, error) {
	ctx := r.Context()
	switch kind {
	case "routine":
		rt, err := h.resolveRoutine(r, conn, sc, name, idx)
		if err != nil {
			return "", err
		}
		// "Procedure"/"Function" rather than a flat "Routine": the two are
		// different objects to the server and the message should say which went.
		noun := "Function"
		if strings.EqualFold(rt.Type, "PROCEDURE") {
			noun = "Procedure"
		}
		if !confirm(noun) {
			return "", errConfirmPending
		}
		return noun, conn.DropRoutine(ctx, sc.scope(), rt)
	case "trigger":
		tr, err := h.resolveTrigger(r, conn, sc, name, sc.Table, idx)
		if err != nil {
			return "", err
		}
		if !confirm("Trigger") {
			return "", errConfirmPending
		}
		return "Trigger", conn.DropTrigger(ctx, sc.scope(), tr)
	case "event":
		ev, err := h.resolveEvent(r, conn, sc, name, idx)
		if err != nil {
			return "", err
		}
		if !confirm("Event") {
			return "", errConfirmPending
		}
		return "Event", conn.DropEvent(ctx, sc.scope(), ev)
	}
	return "", errors.New("unknown object kind")
}
