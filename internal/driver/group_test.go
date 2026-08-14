package driver_test

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestGrouper covers the contract the dialect introspection relies on: one
// element per key, stable pointers for in-place mutation, and Slice returning
// groups in first-seen key order.
func TestGrouper(t *testing.T) {
	type index struct {
		Name string
		Cols []string
	}
	g := driver.NewGrouper[string, index]()

	// Interleaved rows, as a grouped ORDER BY stream delivers them.
	for _, row := range []struct{ key, col string }{
		{"pk", "id"},
		{"by_name", "last"},
		{"by_name", "first"},
		{"pk", "tenant"},
	} {
		p := g.GetOrAdd(row.key, func() index { return index{Name: row.key} })
		p.Cols = append(p.Cols, row.col)
	}

	got := g.Slice()
	if len(got) != 2 {
		t.Fatalf("Slice() returned %d groups, want 2", len(got))
	}
	if got[0].Name != "pk" || got[1].Name != "by_name" {
		t.Errorf("group order = %q, %q; want first-seen order pk, by_name", got[0].Name, got[1].Name)
	}
	if len(got[0].Cols) != 2 || got[0].Cols[0] != "id" || got[0].Cols[1] != "tenant" {
		t.Errorf("pk cols = %v, want [id tenant] (stable pointer must accumulate)", got[0].Cols)
	}
	if len(got[1].Cols) != 2 || got[1].Cols[0] != "last" || got[1].Cols[1] != "first" {
		t.Errorf("by_name cols = %v, want [last first]", got[1].Cols)
	}

	// GetOrAdd must return the same pointer for an existing key.
	p1 := g.GetOrAdd("pk", func() index { t.Fatal("create called for existing key"); return index{} })
	p2 := g.GetOrAdd("pk", func() index { return index{} })
	if p1 != p2 {
		t.Error("GetOrAdd returned different pointers for the same key")
	}
}

// TestNestedGrouper covers the two-level form the bulk FK introspections use:
// one element per (outer, inner) pair, stable pointers, and Map preserving
// inner first-seen order per outer key.
func TestNestedGrouper(t *testing.T) {
	type fk struct {
		Name string
		Cols []string
	}
	g := driver.NewNestedGrouper[string, string, fk]()
	for _, row := range []struct{ table, name, col string }{
		{"orders", "fk_customer", "customer_id"},
		{"lines", "fk_order", "order_id"},
		{"orders", "fk_customer", "tenant_id"}, // composite key accumulates
		{"orders", "fk_region", "region_id"},
	} {
		p := g.GetOrAdd(row.table, row.name, func() fk { return fk{Name: row.name} })
		p.Cols = append(p.Cols, row.col)
	}
	m := g.Map()
	if len(m) != 2 {
		t.Fatalf("Map() has %d tables, want 2", len(m))
	}
	orders := m["orders"]
	if len(orders) != 2 || orders[0].Name != "fk_customer" || orders[1].Name != "fk_region" {
		t.Errorf("orders groups = %+v, want fk_customer then fk_region", orders)
	}
	if len(orders[0].Cols) != 2 || orders[0].Cols[1] != "tenant_id" {
		t.Errorf("composite FK columns did not accumulate: %v", orders[0].Cols)
	}
	if len(m["lines"]) != 1 || m["lines"][0].Cols[0] != "order_id" {
		t.Errorf("lines groups = %+v", m["lines"])
	}
}

func TestStringSet(t *testing.T) {
	set := driver.StringSet([]string{"a", "b"})
	if !set["a"] || !set["b"] || set["c"] || len(set) != 2 {
		t.Errorf("StringSet = %v", set)
	}
	if empty := driver.StringSet(nil); empty == nil || len(empty) != 0 {
		t.Errorf("StringSet(nil) = %v, want empty non-nil map", empty)
	}
}
