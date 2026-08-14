package driver

// Grouper accumulates pointers to grouped elements keyed by K, preserving the
// order keys are first seen, then flattens them to a value slice. It removes the
// repeated "order []K + byKey map + lookup-or-create + rebuild tail" idiom the
// dialect Indexes/ForeignKeys introspection used to spell out at every call site
// (a row stream arrives grouped by name/id and must collapse to one element per
// group, preserving query order).
type Grouper[K comparable, T any] struct {
	order []K
	byKey map[K]*T
}

// NewGrouper returns an empty Grouper.
func NewGrouper[K comparable, T any]() *Grouper[K, T] {
	return &Grouper[K, T]{byKey: make(map[K]*T)}
}

// GetOrAdd returns the existing element for key, or inserts create()'s result
// and returns a pointer to it. The returned pointer is stable across calls;
// callers mutate the group through it (e.g. appending columns to an index).
func (g *Grouper[K, T]) GetOrAdd(key K, create func() T) *T {
	if p, ok := g.byKey[key]; ok {
		return p
	}
	v := create()
	g.byKey[key] = &v
	g.order = append(g.order, key)
	return g.byKey[key]
}

// Slice returns the grouped elements as values, in first-seen key order.
func (g *Grouper[K, T]) Slice() []T {
	out := make([]T, 0, len(g.order))
	for _, k := range g.order {
		out = append(out, *g.byKey[k])
	}
	return out
}

// NestedGrouper is Grouper's two-level form: rows arrive keyed by an outer
// group (table) and an inner group (constraint name) and collapse to one
// element per inner group, preserving first-seen order at both levels. It
// absorbs the outer "map[K1]*Grouper + ordered key slice + rebuild loop"
// wrapper the MySQL and PostgreSQL bulk foreign-key introspections both
// spelled out around the shared inner Grouper.
type NestedGrouper[K1, K2 comparable, T any] struct {
	order []K1
	byKey map[K1]*Grouper[K2, T]
}

// NewNestedGrouper returns an empty NestedGrouper.
func NewNestedGrouper[K1, K2 comparable, T any]() *NestedGrouper[K1, K2, T] {
	return &NestedGrouper[K1, K2, T]{byKey: make(map[K1]*Grouper[K2, T])}
}

// GetOrAdd returns the element for (outer, inner), inserting create()'s result
// on first sight. Pointer semantics mirror Grouper.GetOrAdd: callers mutate
// the group through the stable returned pointer.
func (n *NestedGrouper[K1, K2, T]) GetOrAdd(outer K1, inner K2, create func() T) *T {
	g, ok := n.byKey[outer]
	if !ok {
		g = NewGrouper[K2, T]()
		n.byKey[outer] = g
		n.order = append(n.order, outer)
	}
	return g.GetOrAdd(inner, create)
}

// Map flattens to outer key → grouped values (inner first-seen order).
func (n *NestedGrouper[K1, K2, T]) Map() map[K1][]T {
	out := make(map[K1][]T, len(n.order))
	for _, k := range n.order {
		out[k] = n.byKey[k].Slice()
	}
	return out
}

// StringSet builds a membership set from a name slice — the "which tables are
// in scope" lookup every dialect's DumpObjects performs. Exported because the
// dialects live in separate packages.
func StringSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}
