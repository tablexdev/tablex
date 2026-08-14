package driver_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// optionalInterfaces is every optional capability interface in this package,
// paired with a runtime probe. Adding an interface here is the one manual step
// when a new capability is introduced.
var optionalInterfaces = []struct {
	name string
	has  func(driver.Dialect) bool
}{
	{"BulkIntrospector", func(d driver.Dialect) bool { _, ok := d.(driver.BulkIntrospector); return ok }},
	{"CollationLister", func(d driver.Dialect) bool { _, ok := d.(driver.CollationLister); return ok }},
	{"CollationProber", func(d driver.Dialect) bool { _, ok := d.(driver.CollationProber); return ok }},
	{"ColumnModifier", func(d driver.Dialect) bool { _, ok := d.(driver.ColumnModifier); return ok }},
	{"ColumnPrivileger", func(d driver.Dialect) bool { _, ok := d.(driver.ColumnPrivileger); return ok }},
	{"ColumnRenamer", func(d driver.Dialect) bool { _, ok := d.(driver.ColumnRenamer); return ok }},
	{"DDLErrorHint", func(d driver.Dialect) bool { _, ok := d.(driver.DDLErrorHint); return ok }},
	{"DataScoper", func(d driver.Dialect) bool { _, ok := d.(driver.DataScoper); return ok }},
	{"DatabaseManager", func(d driver.Dialect) bool { _, ok := d.(driver.DatabaseManager); return ok }},
	{"DatabaseRebinder", func(d driver.Dialect) bool { _, ok := d.(driver.DatabaseRebinder); return ok }},
	{"DefinitionViewer", func(d driver.Dialect) bool { _, ok := d.(driver.DefinitionViewer); return ok }},
	{"Dumper", func(d driver.Dialect) bool { _, ok := d.(driver.Dumper); return ok }},
	{"DynamicTyper", func(d driver.Dialect) bool { _, ok := d.(driver.DynamicTyper); return ok }},
	{"EventManager", func(d driver.Dialect) bool { _, ok := d.(driver.EventManager); return ok }},
	{"ExportConnAdjuster", func(d driver.Dialect) bool { _, ok := d.(driver.ExportConnAdjuster); return ok }},
	{"FilePathValidator", func(d driver.Dialect) bool { _, ok := d.(driver.FilePathValidator); return ok }},
	{"ForeignKeyEditor", func(d driver.Dialect) bool { _, ok := d.(driver.ForeignKeyEditor); return ok }},
	{"ForeignTableDumper", func(d driver.Dialect) bool { _, ok := d.(driver.ForeignTableDumper); return ok }},
	{"GlobalDumper", func(d driver.Dialect) bool { _, ok := d.(driver.GlobalDumper); return ok }},
	{"IndexOptioner", func(d driver.Dialect) bool { _, ok := d.(driver.IndexOptioner); return ok }},
	{"Inheritor", func(d driver.Dialect) bool { _, ok := d.(driver.Inheritor); return ok }},
	{"LoginFormHinter", func(d driver.Dialect) bool { _, ok := d.(driver.LoginFormHinter); return ok }},
	{"MaintenanceDatabaseLister", func(d driver.Dialect) bool { _, ok := d.(driver.MaintenanceDatabaseLister); return ok }},
	{"Monitor", func(d driver.Dialect) bool { _, ok := d.(driver.Monitor); return ok }},
	{"NameLister", func(d driver.Dialect) bool { _, ok := d.(driver.NameLister); return ok }},
	{"ParamsNormalizer", func(d driver.Dialect) bool { _, ok := d.(driver.ParamsNormalizer); return ok }},
	{"ParamsValidator", func(d driver.Dialect) bool { _, ok := d.(driver.ParamsValidator); return ok }},
	{"PoolOpener", func(d driver.Dialect) bool { _, ok := d.(driver.PoolOpener); return ok }},
	{"PrivilegeManager", func(d driver.Dialect) bool { _, ok := d.(driver.PrivilegeManager); return ok }},
	{"Privileger", func(d driver.Dialect) bool { _, ok := d.(driver.Privileger); return ok }},
	{"ProcessManager", func(d driver.Dialect) bool { _, ok := d.(driver.ProcessManager); return ok }},
	{"RoleManager", func(d driver.Dialect) bool { _, ok := d.(driver.RoleManager); return ok }},
	{"RoutineManager", func(d driver.Dialect) bool { _, ok := d.(driver.RoutineManager); return ok }},
	{"RoutinePrivileger", func(d driver.Dialect) bool { _, ok := d.(driver.RoutinePrivileger); return ok }},
	{"RowEstimator", func(d driver.Dialect) bool { _, ok := d.(driver.RowEstimator); return ok }},
	{"SchemaEditor", func(d driver.Dialect) bool { _, ok := d.(driver.SchemaEditor); return ok }},
	{"SchemaManager", func(d driver.Dialect) bool { _, ok := d.(driver.SchemaManager); return ok }},
	{"SearchCaster", func(d driver.Dialect) bool { _, ok := d.(driver.SearchCaster); return ok }},
	{"ServerDumpFramer", func(d driver.Dialect) bool { _, ok := d.(driver.ServerDumpFramer); return ok }},
	{"ServerSpecializer", func(d driver.Dialect) bool { _, ok := d.(driver.ServerSpecializer); return ok }},
	{"StagedTableDumper", func(d driver.Dialect) bool { _, ok := d.(driver.StagedTableDumper); return ok }},
	{"StatementLexer", func(d driver.Dialect) bool { _, ok := d.(driver.StatementLexer); return ok }},
	{"StorageHost", func(d driver.Dialect) bool { _, ok := d.(driver.StorageHost); return ok }},
	{"TableMaintainer", func(d driver.Dialect) bool { _, ok := d.(driver.TableMaintainer); return ok }},
	{"TeardownAuditor", func(d driver.Dialect) bool { _, ok := d.(driver.TeardownAuditor); return ok }},
	{"TriggerManager", func(d driver.Dialect) bool { _, ok := d.(driver.TriggerManager); return ok }},
	{"UserManager", func(d driver.Dialect) bool { _, ok := d.(driver.UserManager); return ok }},
	{"ValueListTyper", func(d driver.Dialect) bool { _, ok := d.(driver.ValueListTyper); return ok }},
	{"VersionFloor", func(d driver.Dialect) bool { _, ok := d.(driver.VersionFloor); return ok }},
	{"ViewDumper", func(d driver.Dialect) bool { _, ok := d.(driver.ViewDumper); return ok }},
}

// implemented is the capability set each built-in engine is expected to satisfy
// — the same list each engine package's interfaces.go declares at compile time.
// The `var _` assertions catch a signature that DRIFTS; this catches the other
// direction, a capability gained or lost without the declared list being
// updated, which would leave interfaces.go lying about the engine.
var implemented = map[string][]string{
	"mysql": {
		"BulkIntrospector", "CollationLister", "CollationProber", "ColumnModifier",
		"ColumnPrivileger", "ColumnRenamer", "DatabaseManager", "DefinitionViewer",
		"Dumper", "EventManager",
		"ExportConnAdjuster", "ForeignKeyEditor", "IndexOptioner", "Monitor", "NameLister",
		"PoolOpener", "PrivilegeManager", "Privileger", "ProcessManager",
		"RoleManager", "RoutineManager",
		"RoutinePrivileger", "RowEstimator", "SchemaEditor", "ServerDumpFramer", "ServerSpecializer",
		"StatementLexer", "StorageHost", "TableMaintainer", "TriggerManager", "UserManager",
		"ValueListTyper", "VersionFloor", "ViewDumper",
	},
	"postgres": {
		"BulkIntrospector", "ColumnModifier", "ColumnPrivileger", "ColumnRenamer",
		"DDLErrorHint",
		"DataScoper", "DatabaseManager", "Dumper", "ExportConnAdjuster", "ForeignKeyEditor",
		"ForeignTableDumper", "GlobalDumper", "IndexOptioner", "Inheritor",
		"LoginFormHinter", "MaintenanceDatabaseLister", "Monitor", "NameLister",
		"ParamsNormalizer", "PoolOpener", "PrivilegeManager", "Privileger",
		"ProcessManager", "RoleManager", "RoutineManager", "RoutinePrivileger", "RowEstimator",
		"SchemaEditor", "SchemaManager",
		"SearchCaster", "ServerDumpFramer", "ServerSpecializer",
		"StagedTableDumper", "StatementLexer", "StorageHost", "TableMaintainer",
		"TeardownAuditor", "TriggerManager", "UserManager", "VersionFloor", "ViewDumper",
	},
	"sqlite": {
		"ColumnRenamer", "DatabaseRebinder", "Dumper", "DynamicTyper", "FilePathValidator",
		"IndexOptioner", "Monitor", "ParamsValidator",
		"RowEstimator", "SchemaEditor", "ServerDumpFramer", "StatementLexer",
		"StorageHost", "TableMaintainer", "TriggerManager", "ViewDumper",
	},
}

func TestDialectCapabilitySets(t *testing.T) {
	all := driver.All()
	if len(all) != len(implemented) {
		t.Fatalf("registered dialects = %d, expected sets for %d; a new engine needs an entry here and an interfaces.go", len(all), len(implemented))
	}
	for _, d := range all {
		want, ok := implemented[d.Name()]
		if !ok {
			t.Errorf("dialect %q has no expected capability set", d.Name())
			continue
		}
		var got []string
		for _, iface := range optionalInterfaces {
			if iface.has(d) {
				got = append(got, iface.name)
			}
		}
		gained, lost := diff(got, want)
		for _, n := range gained {
			t.Errorf("%s implements driver.%s but does not assert it: add `_ driver.%s = dialect{}` to internal/driver/%s/interfaces.go",
				d.Name(), n, n, d.Name())
		}
		for _, n := range lost {
			t.Errorf("%s no longer implements driver.%s: the capability was lost, or the assertion in internal/driver/%s/interfaces.go should go",
				d.Name(), n, d.Name())
		}
	}
}

// TestOptionalInterfaceProbesAreSorted keeps the probe table and the expected
// sets in one canonical order, so a diff of this file reads cleanly.
func TestOptionalInterfaceProbesAreSorted(t *testing.T) {
	names := make([]string, len(optionalInterfaces))
	for i, iface := range optionalInterfaces {
		names[i] = iface.name
	}
	if !slices.IsSorted(names) {
		t.Errorf("optionalInterfaces is not sorted by name: %s", strings.Join(names, ", "))
	}
	for engine, want := range implemented {
		if !slices.IsSorted(want) {
			t.Errorf("implemented[%q] is not sorted: %s", engine, strings.Join(want, ", "))
		}
	}
}

// diff returns the names present only in got, then only in want.
func diff(got, want []string) (gained, lost []string) {
	for _, n := range got {
		if !slices.Contains(want, n) {
			gained = append(gained, n)
		}
	}
	for _, n := range want {
		if !slices.Contains(got, n) {
			lost = append(lost, n)
		}
	}
	return gained, lost
}

// TestOptionalInterfaceTableIsComplete: the probe table above cannot go stale.
// Every exported top-level interface in package driver — minus Dialect (the
// required one) and a commented exemption list — must have a probe;
// VersionFloor was the one absentee, which made its drift untestable and left
// postgres/interfaces.go claiming "27 of the 30" while the truth was 41 of 48.
// It also holds any "NN of the MM optional interfaces" numbers written in the
// engines' interfaces.go comments to the live census.
func TestOptionalInterfaceTableIsComplete(t *testing.T) {
	// Not capabilities: required or plumbing, never probed per engine.
	exempt := map[string]string{
		"Dialect": "the required interface, not an optional capability",
	}

	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing package driver: %v (%d files)", err, len(files))
	}
	var declared []string
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		parsed++
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, isIface := ts.Type.(*ast.InterfaceType); !isIface || !ts.Name.IsExported() {
					continue // unexported helpers like sqlExecutor are not capabilities
				}
				declared = append(declared, ts.Name.Name)
			}
		}
	}
	if parsed < 8 {
		t.Fatalf("parsed only %d non-test files — this test is not looking where it thinks", parsed)
	}

	probed := map[string]bool{}
	for _, iface := range optionalInterfaces {
		probed[iface.name] = true
	}
	optional := 0
	for _, name := range declared {
		if _, ok := exempt[name]; ok {
			continue
		}
		optional++
		if !probed[name] {
			t.Errorf("driver.%s has no probe in optionalInterfaces — drift in it is untestable until one is added", name)
		}
	}
	if len(probed) != optional {
		// The reverse direction: a probe for something no longer declared.
		for name := range probed {
			if !slices.Contains(declared, name) {
				t.Errorf("optionalInterfaces probes %q, which is not an exported interface in package driver", name)
			}
		}
	}
	const floor = 40 // optional interfaces when this census was written (48)
	if optional < floor {
		t.Fatalf("censused only %d optional interfaces, expected at least %d — this scan is not looking where it thinks", optional, floor)
	}

	// Any "NN of the MM optional interfaces" claim in an engine's interfaces.go
	// must match the live census.
	claimRE := regexp.MustCompile(`(\d+) of the (\d+) optional\s*\n?//\s*interfaces`)
	for engine, want := range implemented {
		body, err := os.ReadFile(filepath.Join(engine, "interfaces.go"))
		if err != nil {
			t.Fatalf("reading %s/interfaces.go: %v", engine, err)
		}
		for _, m := range claimRE.FindAllStringSubmatch(string(body), -1) {
			if m[1] != strconv.Itoa(len(want)) {
				t.Errorf("%s/interfaces.go claims %s implemented interfaces; the census says %d", engine, m[1], len(want))
			}
			if m[2] != strconv.Itoa(optional) {
				t.Errorf("%s/interfaces.go claims %s optional interfaces exist; the census says %d", engine, m[2], optional)
			}
		}
	}
}

// TestRegisteredNames pins the contract config validation depends on: the
// registry is the engine allowlist, reported sorted, and matching All().
func TestRegisteredNames(t *testing.T) {
	names := driver.RegisteredNames()
	if !slices.IsSorted(names) {
		t.Errorf("RegisteredNames() is not sorted: %v", names)
	}
	all := driver.All()
	if len(names) != len(all) {
		t.Fatalf("RegisteredNames() has %d entries, All() has %d", len(names), len(all))
	}
	for i, d := range all {
		if names[i] != d.Name() {
			t.Errorf("RegisteredNames()[%d] = %q, All()[%d].Name() = %q", i, names[i], i, d.Name())
		}
	}
	// The caller must not be able to reorder or truncate the registry's view.
	if len(names) > 0 {
		names[0] = "clobbered"
		if again := driver.RegisteredNames(); again[0] == "clobbered" {
			t.Error("RegisteredNames() returned shared state")
		}
	}
}
