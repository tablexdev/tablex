// This file proves RunDialectSuite is not vacuous: a dialect built to violate
// every rule must fail every sub-check. Five of the checks open with a type
// assertion and return silently when it fails (object_kinds, column_placement,
// index_options, column_privileges, routine_privileges) — so a suite run that
// merely COUNTS its subtests cannot see an early return, and a PASS from one of
// those five is indistinguishable from a check that never looked. The broken
// dialect therefore implements all three optional interfaces (held by the
// compile-time assertions below) and plants one violation per check, and the
// harness demands a FAIL from every registered sub-check. A sub-check that
// passes against this dialect IS the failure signal.
package drivertest_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/driver/drivertest"
	"github.com/tablexdev/tablex/internal/model"

	// Register the base dialect the broken fixture embeds.
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// brokenDialect embeds a real registered Dialect and overrides one method per
// suite rule, each override violating exactly the property its check exists to
// hold. Interface embedding promotes only Dialect's own method set, so the
// three optional interfaces are implemented explicitly below — without them,
// five of the thirteen checks would early-return and pass vacuously.
type brokenDialect struct {
	driver.Dialect
}

// The suite's early-returning checks type-assert these; if the fixture ever
// stops satisfying one, the harness must fail to compile rather than let the
// check silently pass again.
var (
	_ driver.Dialect           = brokenDialect{}
	_ driver.SchemaEditor      = brokenDialect{}
	_ driver.ColumnPrivileger  = brokenDialect{}
	_ driver.RoutinePrivileger = brokenDialect{}
)

func newBrokenDialect(t *testing.T) brokenDialect {
	t.Helper()
	base, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered; the blank import above is broken")
	}
	return brokenDialect{Dialect: base}
}

// identity: a Name with upper case and a space, which is unusable as a config
// token or URL segment.
func (brokenDialect) Name() string { return "BROKEN dialect" }

// quote_ident: embedded delimiters are not doubled, so a name that is itself
// two delimiters unquotes to one — the injectable round-trip the check probes.
func (brokenDialect) QuoteIdent(name string) string { return `"` + name + `"` }

// quote_string: no escaping at all — an embedded quote ends the literal early.
func (brokenDialect) QuoteString(s string) string { return "'" + s + "'" }

// placeholders: a partial mix of positional and numbered forms, which binds
// the wrong argument silently.
func (brokenDialect) Placeholder(n int) string {
	if n%2 == 1 {
		return "?"
	}
	return fmt.Sprintf("$%d", n)
}

// limit_clause: the offset goes through int32, truncating the 1<<40 probe.
func (brokenDialect) LimitClause(limit int, offset int64) string {
	return fmt.Sprintf("LIMIT %d OFFSET %d", limit, int32(offset))
}

// qualify_table: bare concatenation — neither the table nor the schema is
// quoted.
func (brokenDialect) QualifyTable(t driver.TableRef) string { return t.Table }

// explain: refuses while Capabilities below promises support.
func (brokenDialect) ExplainSQL(query string, analyze bool) (string, bool) { return "", false }

// capability_coherence: HasSchemas without implementing driver.SchemaManager.
// SupportsExplain is the explain check's other half; everything else stays
// false so no further forward rule is triggered.
func (brokenDialect) Capabilities() driver.Capabilities {
	return driver.Capabilities{HasSchemas: true, SupportsExplain: true}
}

// --- driver.SchemaEditor ---

// object_kinds: an empty type allowlist, and DROP/RENAME statements that never
// name their object.
func (brokenDialect) ColumnTypes() []string { return nil }

func (brokenDialect) CreateTableSQL(t driver.TableRef, cols []driver.ColumnSpec, pk []string) ([]string, error) {
	return []string{"CREATE TABLE broken (x)"}, nil
}

// column_placement: Placement is honoured while Capabilities reports
// SupportsColumnPosition false — the silent approximation the check forbids.
func (d brokenDialect) AddColumnSQL(t driver.TableRef, c driver.ColumnSpec) ([]string, error) {
	s := "ALTER TABLE " + t.Table + " ADD COLUMN " + c.Name + " " + c.Type
	if c.Placement == driver.PlaceAfter {
		s += " AFTER " + c.PlacementAfter
	}
	return []string{s}, nil
}

func (brokenDialect) DropColumnSQL(t driver.TableRef, col string) ([]string, error) {
	return []string{"ALTER TABLE " + t.Table + " DROP COLUMN " + col}, nil
}

func (brokenDialect) DropObjectSQL(t driver.TableRef, kind string) ([]string, error) {
	return []string{"DROP OBJECT"}, nil
}

func (brokenDialect) RenameObjectSQL(t driver.TableRef, newName, kind string) ([]string, error) {
	return []string{"RENAME OBJECT"}, nil
}

// index_options: Desc reaches the statement although no IndexOptioner claims
// it — the silently-honoured option the check forbids in the negative
// direction. Unique is honoured (the suite requires that unconditionally);
// Prefix, Where and Method are ignored, matching the empty claim.
func (d brokenDialect) AddIndexSQL(t driver.TableRef, spec driver.IndexSpec) ([]string, error) {
	cols := make([]string, len(spec.Columns))
	for i, c := range spec.Columns {
		cols[i] = d.QuoteIdent(c.Name)
		if c.Desc {
			cols[i] += " DESC"
		}
	}
	s := "CREATE "
	if spec.Unique {
		s += "UNIQUE "
	}
	s += "INDEX " + d.QuoteIdent(spec.Name) + " ON " + t.Table + " (" + strings.Join(cols, ", ") + ")"
	return []string{s}, nil
}

func (brokenDialect) DropIndexSQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"DROP INDEX " + name}, nil
}

// --- driver.ColumnPrivileger (embeds PrivilegeManager) ---

// column_privileges: the column allowlist is NOT contained in the table
// allowlist, and GrantSQL/RevokeSQL drop the column list (widening the grant)
// while the database-scope form accepts a column list without error.
func (brokenDialect) GrantablePrivileges(table bool) []string { return []string{"UPDATE"} }

func (brokenDialect) ColumnGrantablePrivileges() []string { return []string{"SELECT"} }

func (brokenDialect) GrantSQL(g driver.GrantSpec) ([]string, error) {
	return []string{"GRANT SELECT ON t TO u"}, nil
}

func (brokenDialect) RevokeSQL(g driver.GrantSpec) ([]string, error) {
	return []string{"REVOKE SELECT ON t FROM u"}, nil
}

// --- driver.RoutinePrivileger ---

// routine_privileges: the FUNCTION/PROCEDURE kind never reaches the statement,
// and an empty privilege set builds a statement instead of erroring.
func (brokenDialect) RoutineGrantablePrivileges() []string { return []string{"EXECUTE"} }

func (brokenDialect) RoutinePrivileges(ctx context.Context, db *sql.DB, s driver.Scope, r model.Routine) ([]model.Privilege, error) {
	return nil, nil
}

func (d brokenDialect) GrantRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	return []string{"GRANT EXECUTE ON " + d.QuoteIdent(g.Routine.Name) + " TO u"}, nil
}

func (d brokenDialect) RevokeRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	return []string{"REVOKE EXECUTE ON " + d.QuoteIdent(g.Routine.Name) + " FROM u"}, nil
}

const brokenEnv = "TABLEX_DRIVERTEST_BROKEN"

// TestBrokenDialectHelper is the subprocess half of the harness below. It must
// run RunDialectSuite on the broken dialect and FAIL — which would mark this
// process red — so it only executes under the env guard, in a child process
// whose exit status the harness inspects. t.Run's bool return cannot replace
// this: a failed subtest marks its parent failed regardless of what the caller
// does with the result.
func TestBrokenDialectHelper(t *testing.T) {
	if os.Getenv(brokenEnv) == "" {
		t.Skip("subprocess helper for TestSuiteRejectsBrokenDialect; not a standalone test")
	}
	drivertest.RunDialectSuite(t, newBrokenDialect(t))
}

// TestSuiteRejectsBrokenDialect re-executes this test binary against the
// broken dialect and requires (a) a non-zero exit and (b) a FAIL from every
// sub-check RunDialectSuite registers — the names are parsed from the suite's
// own source, so a fourteenth check added later must fail here until it, too,
// is given a planted violation.
func TestSuiteRejectsBrokenDialect(t *testing.T) {
	names := suiteCheckNames(t)

	cmd := exec.Command(os.Args[0], "-test.run=TestBrokenDialectHelper$", "-test.v")
	cmd.Env = append(os.Environ(), brokenEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("RunDialectSuite passed on a dialect that violates every rule — the suite is vacuous\n%s", out)
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("re-executing %s: %v\n%s", os.Args[0], err, out)
	}

	for _, name := range names {
		want := "--- FAIL: TestBrokenDialectHelper/" + name
		if !strings.Contains(string(out), want) {
			t.Errorf("sub-check %q did not fail against the broken dialect — it is vacuous or early-returned", name)
		}
	}
	if t.Failed() {
		t.Logf("subprocess output:\n%s", out)
	}
}

// suiteCheckNames reads the sub-check registrations out of drivertest.go. The
// floor guards the scan itself: matching nothing must fail loudly, never pass
// by counting an empty list.
func suiteCheckNames(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("drivertest.go")
	if err != nil {
		t.Fatalf("reading the suite source: %v", err)
	}
	matches := regexp.MustCompile(`t\.Run\("([a-z_]+)"`).FindAllStringSubmatch(string(src), -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	const floor = 13 // the registration count when this harness was written
	if len(names) < floor {
		t.Fatalf("found %d t.Run registrations in drivertest.go, expected at least %d — this scan is not looking where it thinks", len(names), floor)
	}
	return names
}
