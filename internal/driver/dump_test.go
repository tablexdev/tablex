package driver_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

func TestTopoOrder(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		deps  map[string][]string
		want  []string
	}{
		{"no deps keeps order", []string{"a", "b", "c"}, nil, []string{"a", "b", "c"}},
		{"simple chain", []string{"v2", "v1"}, map[string][]string{"v2": {"v1"}}, []string{"v1", "v2"}},
		{"diamond", []string{"d", "b", "c", "a"},
			map[string][]string{"d": {"b", "c"}, "b": {"a"}, "c": {"a"}},
			[]string{"a", "b", "c", "d"}},
		{"unknown deps ignored", []string{"x"}, map[string][]string{"x": {"missing"}}, []string{"x"}},
		{"self dep ignored", []string{"x", "y"}, map[string][]string{"x": {"x"}}, []string{"x", "y"}},
	}
	for _, c := range cases {
		if got := driver.TopoOrder(c.names, c.deps); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: TopoOrder = %v, want %v", c.name, got, c.want)
		}
	}

	// A cycle must not drop members, and emits in DFS-completion order (NOT input
	// order): visiting a recurses into b, which completes first → [b, a]. This
	// pins the corrected doc comment.
	got := driver.TopoOrder([]string{"a", "b"}, map[string][]string{"a": {"b"}, "b": {"a"}})
	if !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Errorf("2-cycle A→B→A order = %v, want [b a] (DFS-completion, not input order)", got)
	}
}

// TestSCC pins the Tarjan strongly-connected-components helper the cycle
// resolver and (later) the teardown auditor build on: genuine cycles come back
// as multi-member components, acyclic nodes as singletons in reverse
// topological order of the condensation, boundary edges are ignored, and a
// self-edge — invisible to a singleton component — is reported by HasSelfEdge.
func TestSCC(t *testing.T) {
	find := func(comps [][]string, member string) []string {
		for _, c := range comps {
			for _, m := range c {
				if m == member {
					return c
				}
			}
		}
		return nil
	}
	sorted := func(s []string) []string {
		out := append([]string(nil), s...)
		sort.Strings(out)
		return out
	}

	// Linear chain: three singletons, dependencies first (reverse topo of the
	// condensation = emission order).
	comps := driver.SCC([]string{"c", "b", "a"}, map[string][]string{"c": {"b"}, "b": {"a"}})
	if len(comps) != 3 || comps[0][0] != "a" || comps[1][0] != "b" || comps[2][0] != "c" {
		t.Errorf("chain SCC = %v, want [[a] [b] [c]]", comps)
	}

	// A 2-cycle plus a dependent tail: the cycle is one component and precedes
	// its dependent.
	comps = driver.SCC([]string{"tail", "x", "y"},
		map[string][]string{"tail": {"x"}, "x": {"y"}, "y": {"x"}})
	cyc := find(comps, "x")
	if !reflect.DeepEqual(sorted(cyc), []string{"x", "y"}) {
		t.Errorf("2-cycle component = %v, want [x y]", cyc)
	}
	if len(comps) != 2 || len(comps[0]) != 2 || comps[1][0] != "tail" {
		t.Errorf("2-cycle SCC order = %v, want the cycle before its dependent", comps)
	}

	// Boundary edges (targets outside the node set) are ignored.
	comps = driver.SCC([]string{"solo"}, map[string][]string{"solo": {"missing", "alsoMissing"}})
	if len(comps) != 1 || comps[0][0] != "solo" {
		t.Errorf("boundary SCC = %v, want [[solo]]", comps)
	}

	// A self-edge: singleton component, but HasSelfEdge reports the cycle.
	deps := map[string][]string{"loop": {"loop"}, "plain": nil}
	comps = driver.SCC([]string{"loop", "plain"}, deps)
	if len(comps) != 2 {
		t.Errorf("self-edge SCC = %v, want two singletons", comps)
	}
	if !driver.HasSelfEdge("loop", deps) {
		t.Error("HasSelfEdge(loop) = false, want true")
	}
	if driver.HasSelfEdge("plain", deps) {
		t.Error("HasSelfEdge(plain) = true, want false")
	}

	// A 3-cycle inside a larger graph stays one component.
	comps = driver.SCC([]string{"p", "q", "r", "s"},
		map[string][]string{"p": {"q"}, "q": {"r"}, "r": {"p"}, "s": {"p"}})
	if got := find(comps, "p"); !reflect.DeepEqual(sorted(got), []string{"p", "q", "r"}) {
		t.Errorf("3-cycle component = %v, want [p q r]", got)
	}
}

// TestGroupableDropClass pins the capability table: only a class whose DROP
// grammar accepts a comma-separated object list may be rendered as a grouped
// multi-object DROP. A same-class cycle in a list-less class must be RETAINED,
// never emitted as invalid SQL.
func TestGroupableDropClass(t *testing.T) {
	for _, class := range []string{"FUNCTION", "PROCEDURE", "AGGREGATE", "ROUTINE",
		"TYPE", "DOMAIN", "SEQUENCE", "VIEW", "OPERATOR", "TABLE"} {
		if !driver.GroupableDropClass(class) {
			t.Errorf("GroupableDropClass(%q) = false, want true", class)
		}
	}
	// Single-object syntax only — grouping these would be a syntax error.
	for _, class := range []string{"", "COLLATION", "CAST", "OPERATOR CLASS",
		"OPERATOR FAMILY", "USER MAPPING", "SCHEMA", "function"} {
		if driver.GroupableDropClass(class) {
			t.Errorf("GroupableDropClass(%q) = true, want false", class)
		}
	}
}
