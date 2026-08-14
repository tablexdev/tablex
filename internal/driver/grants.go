package driver

// Grant-builder helpers shared by the engines' DCL files. Exported because
// internal/driver and the engine packages are different packages — the same
// reason QuoteAnsiIdent/QuoteAnsiString are (connection.go).

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tablexdev/tablex/internal/model"
)

// RoutineKeyword picks FUNCTION or PROCEDURE for a routine-scope grant
// statement. Both engines need the kind spelled out, each for its own reason:
// MySQL's grammar has no ON ROUTINE at all, so the wrong keyword targets an
// object that does not exist rather than failing to parse; PostgreSQL has
// ON ROUTINE from PG 11, but naming the kind keeps a mismatched Routine.Type
// an error here rather than a grant on whatever object shares the name.
func RoutineKeyword(r model.Routine) string {
	if strings.EqualFold(r.Type, "PROCEDURE") {
		return "PROCEDURE"
	}
	return "FUNCTION"
}

// CheckColumnScope re-checks a column-scoped spec inside a grant builder. The
// grammar rule — a column list needs a table, since the database-scope object
// takes none — applies to GRANT and REVOKE alike; the per-privilege rule runs
// on grant only, mirroring the allowlist asymmetry the builders already have
// (a revoke is authorized by the introspected grant, not by a curated list).
// columnPrivs is the engine's own column-grantable allowlist — the one
// per-engine fact in an otherwise identical check, and an intentional
// divergence, not a bug in flight.
func CheckColumnScope(g GrantSpec, privs []string, grant bool, columnPrivs []string) error {
	if len(g.Columns) == 0 {
		return nil
	}
	if g.Table == "" {
		return errors.New("column-scope grants require a table")
	}
	if !grant {
		return nil
	}
	for _, p := range privs {
		if !slices.Contains(columnPrivs, p) {
			return fmt.Errorf("privilege %q does not accept a column list", p)
		}
	}
	return nil
}
