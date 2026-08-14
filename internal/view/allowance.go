package view

import "strings"

// Allowance is what this deployment permits, for the templates' benefit: the
// [restrict] policy in the shape a template can read.
//
// It exists so the UI does not offer what the middleware will refuse. Hiding a
// button is NOT a control and is never treated as one — `internal/server`
// enforces every restriction on the request, keyed on the route, and goes on
// doing so whether or not a template consulted this. The distinction matters
// enough that the config type deliberately does not reach the templates: a
// template that could read the policy might look like it were applying it.
//
// The fields are positive ("what you may do") rather than negative, because
// `{{if $.Allow.DDL}}` reads as an affordance being offered, while
// `{{if not $.Restrict.NoDDL}}` reads as a double negative nobody gets right.
type Allowance struct {
	// Write is set when state-changing requests are permitted at all: row edits,
	// inserts, deletes. Cleared by read_only.
	Write bool
	// Console is set when SQL whose reach TableX cannot describe is permitted:
	// the SQL console, SQL import, WRITING a stored program (the body a CREATE
	// TRIGGER/ROUTINE/EVENT wraps is unconstrained SQL running on the server), and
	// a partial index's WHERE predicate, which is an expression no placeholder can
	// carry. Cleared by allow_console = false, and by read_only, which refuses
	// them along with everything else that changes state.
	Console bool
	// DDL is set when schema and access-control changes are permitted: the
	// structure editor, table and database operations, accounts and grants, and
	// DROPPING a stored program. Cleared by allow_ddl = false, and by read_only.
	//
	// Note the split with Console above: a stored program's list and drop are
	// DDL, its editor is both. The two halves share one endpoint, so the route
	// cannot separate them and saveProgram checks the console half itself.
	DDL bool
}

// AllowAll is the unrestricted default.
var AllowAll = Allowance{Write: true, Console: true, DDL: true}

// Restricted reports whether anything is withheld, so the layout can say so once
// rather than leaving a user to infer it from missing buttons. A UI that quietly
// drops half its features looks broken; one that states the policy looks
// deliberate.
func (a Allowance) Restricted() bool { return !a.Write || !a.Console || !a.DDL }

// Notice summarises what is withheld, for the banner. Empty when nothing is.
//
// read_only subsumes the other two — under it nothing can be changed at all — so
// it is reported alone rather than as three findings that all say the same thing.
func (a Allowance) Notice() string {
	if !a.Write {
		return "This TableX is read-only. Nothing can be changed through it."
	}
	var withheld []string
	if !a.Console {
		withheld = append(withheld, "running SQL directly")
	}
	if !a.DDL {
		withheld = append(withheld, "changing schemas, accounts and privileges")
	}
	if len(withheld) == 0 {
		return ""
	}
	return "This TableX has " + strings.Join(withheld, " and ") + " disabled."
}
