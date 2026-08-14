package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// The definition viewer. Routines, triggers and events were listed with their
// metadata only, so a stored procedure's body — the thing anyone opening that
// page is there to read — was fetched over the wire and then dropped.
//
// Panels load lazily, one fragment per object on first expand, rather than
// inline with the list: on MySQL a replayable definition costs a SHOW CREATE per
// object, so rendering forty up front would turn one catalog query into forty
// round-trips.

// definitionView is the fragment model; SQL and Error are mutually exclusive.
type definitionView struct {
	Name  string
	SQL   string
	Error string
}

// ObjectDefinition serves one object's CREATE statement as an htmx fragment
// (GET /db/{db}/definition?kind=&name=&i=[&table=]). The object is addressed by
// list position plus name; that rule and its resolvers live in programs.go,
// shared with the drop actions.
func (h *Handlers) ObjectDefinition(w http.ResponseWriter, r *http.Request) {
	uc, _, ok := h.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	idx, err := strconv.Atoi(q.Get("i"))
	if name == "" || err != nil || idx < 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())

	v := definitionView{Name: name}
	conn, connErr := uc.ConnFor(r.Context(), sc.DB)
	if connErr != nil {
		// Section-tier wording: the panel reports its own failure in place;
		// connError's terminal literal stays unique to connError.
		v.Error = "Database unreachable: " + uc.redactErr(connErr)
	} else if def, err := h.lookupDefinition(r, conn, sc, q.Get("kind"), name, q.Get("table"), idx); err != nil {
		v.Error = err.Error()
	} else {
		v.SQL = def
	}
	// "home" is only the carrier page set: object_definition is a layout partial,
	// so every page set holds an identical copy (same idiom as NavChildren).
	if err := h.View.RenderNamed(w, "home", "object_definition", v); err != nil {
		h.renderFailed(w, r, err, "object definition")
	}
}

// lookupDefinition resolves the object at position idx, verifies it still
// carries name, and returns its full CREATE statement.
func (h *Handlers) lookupDefinition(r *http.Request, conn *driver.Connection, sc reqScope, kind, name, table string, idx int) (string, error) {
	ctx := r.Context()
	var listed string
	var objKind driver.ProgramKind

	switch kind {
	case "routine":
		rt, err := h.resolveRoutine(r, conn, sc, name, idx)
		if err != nil {
			return "", err
		}
		listed = rt.Definition
		objKind = driver.ProgramFunction
		if strings.EqualFold(rt.Type, "PROCEDURE") {
			objKind = driver.ProgramProcedure
		}
	case "trigger":
		tr, err := h.resolveTrigger(r, conn, sc, name, table, idx)
		if err != nil {
			return "", err
		}
		listed, objKind = tr.Definition, driver.ProgramTrigger
	case "event":
		ev, err := h.resolveEvent(r, conn, sc, name, idx)
		if err != nil {
			return "", err
		}
		listed, objKind = ev.Definition, driver.ProgramEvent
	default:
		return "", errors.New("unknown object kind")
	}

	// Engines whose listing already carries the whole CREATE statement
	// (PostgreSQL, SQLite) implement no DefinitionViewer and report ok=false:
	// use what the list returned rather than asking the server again.
	full, ok, err := conn.ObjectDefinition(ctx, sc.scope(), objKind, name)
	if err != nil {
		return "", err
	}
	if ok {
		return full, nil
	}
	if strings.TrimSpace(listed) == "" {
		return "", errors.New("this engine exposes no definition for this object")
	}
	return listed, nil
}
