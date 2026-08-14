package dump

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// --- unified database-level dump planning --------------------------------
//
// One planner serves every SQL export path — the single-schema fast path, the
// multi-schema database dump AND each server-scope database section route
// through ResolveDB + WriteDB. The pre-data phase is a GENUINE
// topological sort over all pre-data kinds: the class-major insertion order
// (collations → types → [casts] → routines → [aggregates/operators/opclasses]
// → sequences → [foreign data] → tables → views, mirroring pg_dump's
// dbObjectTypePriority) is the stable input ordering / tie-breaker — this is
// load-bearing for edge-less classes (a cast records no pg_depend edge from
// its consumers) — while DumpScript.Name/DependsOn edges override it. Data
// stays a hard barrier between pre-data and post-data; post-data keeps every
// postDataRank bucket. Plans without graph names (MySQL/SQLite) resolve to
// exactly the historical class-major order.

// predataItem is one pre-data emission unit: a DumpScript, a table create, or
// a generated "-final" stage (a staged routine's CREATE OR REPLACE, a deferred
// domain clause's finalizer bundle).
type predataItem struct {
	id     string
	deps   []string
	script *driver.DumpScript // non-nil for a plan script
	table  *tableDump         // non-nil for a table create
	tnode  driver.DumpTableNode
	sec    int // owning section index

	// fullDeps is the item's COMPLETE edge set as collected — every clause and
	// deferrable table edge included — captured before resolution reduces deps
	// by cutting clauses and staging routines. The teardown needs it: those
	// cuts exist to make the CREATE side restorable, but the RESTORED catalog
	// holds the deferred DDL, so its drop graph is the uncut one.
	fullDeps []string

	// resolution state:
	origDeps         []string
	clauseCut        []bool // parallel to script.Clauses
	stripDefaults    []string
	stripConstraints []string
	staged           bool                // routine stub applied
	sqlText          string              // resolved script SQL (base + kept clauses, or the stub)
	finalOf          string              // non-empty on a generated "-final" stage: the base id
	bundle           []driver.DumpScript // the "-final" stage's scripts
	sccID            int                 // 1-based original SCC id (0 = acyclic)
}

// DBPlan is one database's fully resolved SQL dump: the input sections
// (data + post-data still stream from them), the topo-ordered pre-data stream,
// the deferred post-data scripts cycle resolution produced, and — for a
// drop-first dump — the resolved teardown.
type DBPlan struct {
	sections  []Section
	preOrder  []*predataItem
	extraPost []driver.DumpScript
	teardown  *teardownPlan // nil unless structure && dropFirst
}

// teardownObj is one LOGICAL object in the drop graph. Creation stages a dump
// deliberately emits apart — a shell type and the CREATE completing it, an
// operator family and the ALTER adding its loose members — collapse into one
// node here, because the RESTORED catalog holds a single object whose
// dependencies close the very cycle staging broke.
type teardownObj struct {
	id      string
	label   string          // human name for warnings — never a graph id
	rawDeps []string        // pre-canonicalization edges
	deps    map[string]bool // canonical ids this object requires
	drop    string
	form    driver.DropForm
	dropPos int // preOrder index of the stage carrying the drop (-1: none)
}

// teardownPlan is what the writer consults at each planned DROP. grouped
// carries a multi-object DROP emitted AT one member's position (the only
// non-CASCADE way to drop a dependency cycle); covered marks the other members,
// whose own DROP must not be emitted; omit marks a drop deliberately NOT
// emitted — a cycle no single command covers, an object the dialect refuses to
// drop, or an object a retained one would block.
type teardownPlan struct {
	omit     map[string]bool
	covered  map[string]bool
	grouped  map[string]string
	warnings []string
}

// teardownID returns one pre-data item's drop-graph identity: the logical
// object a staged script belongs to, else the item's own node id.
func teardownID(it *predataItem) string {
	if it.script != nil && it.script.StageOf != "" {
		return it.script.StageOf
	}
	return it.id
}

// teardownLabels renders up to max object labels for a warning.
func teardownLabels(objs map[string]*teardownObj, ids []string, max int) string {
	var out []string
	for _, id := range ids {
		label := objs[id].label
		if label == "" {
			label = "an unnamed object"
		}
		out = append(out, label)
		if len(out) == max && len(ids) > max {
			return strings.Join(out, ", ") + fmt.Sprintf(" (and %d more)", len(ids)-max)
		}
	}
	return strings.Join(out, ", ")
}

// buildTeardownPlan resolves one database's drop-first teardown.
//
// A reverse topological walk alone is not enough: the planner deliberately RESTORES
// dependency cycles that individual reverse-ordered DROPs cannot linearize —
// mutually-recursive routines, a base type and its I/O functions — and under
// RESTRICT (CASCADE is forbidden: it would strip objects outside the export's
// knowledge) the first such DROP fails and the importer aborts the whole
// restore. So the drop graph is rebuilt over LOGICAL objects with UNCUT edges
// and run through Tarjan: a cycle whose members share a list-taking DROP class
// — or whose members are all routines, which one DROP ROUTINE covers — becomes
// a single multi-object statement; any other cycle is RETAINED (drops omitted,
// warned once). Retention then PROPAGATES along prerequisite edges: a retained
// object still holds its own prerequisites, so their drops would fail and must
// be omitted too. Finally the dialect's source-side audit adds advisories for
// dependents this export does not drop at all.
//
// Every outcome is warn-only. Teardown never fails an export: a fresh target
// no-ops every `DROP … IF EXISTS`, so a source-side cycle or blocker must never
// block a valid fresh restore.
func buildTeardownPlan(ctx context.Context, conn *driver.Connection, dbp *DBPlan) *teardownPlan {
	tp := &teardownPlan{omit: map[string]bool{}, covered: map[string]bool{}, grouped: map[string]string{}}
	objs := map[string]*teardownObj{}
	canonOf := map[string]string{} // item id → logical object id
	var order []string             // creation order, for deterministic output

	for pos, it := range dbp.preOrder {
		switch {
		case it.finalOf != "":
			continue // a resolver-generated later stage: its base carries the object
		case it.script != nil && it.script.Name == "":
			continue // an anonymous rider (a comment, an ALTER): it dies with its object
		case it.table != nil && it.table.create == "":
			continue // a data-only leaf: the tree root's drop covers it
		}
		id := teardownID(it)
		canonOf[it.id] = id
		o := objs[id]
		if o == nil {
			o = &teardownObj{id: id, deps: map[string]bool{}, dropPos: -1}
			objs[id] = o
			order = append(order, id)
		}
		o.rawDeps = append(o.rawDeps, it.fullDeps...)
		switch {
		case it.table != nil:
			o.label = it.table.scope.Table
			// Mirrors the writer's own table teardown line, so a grouped or
			// audited statement quotes exactly what the dump emits.
			o.drop = "DROP TABLE IF EXISTS " + it.table.qualified
			o.form = driver.DropForm{Class: "TABLE", Ref: it.table.qualified}
			o.dropPos = pos
		case o.drop == "" && it.script.Drop != "":
			// The stage carrying the drop also NAMES the object: a base type's
			// warning should read "Type bt", not "Shell for type bt".
			o.drop, o.form, o.dropPos = it.script.Drop, it.script.DropForm, pos
			o.label = it.script.Comment
		case o.label == "":
			o.label = it.script.Comment
		}
	}
	for _, o := range objs {
		for _, dep := range o.rawDeps {
			// An id outside the map is a boundary edge (a reference to an
			// out-of-scope object): it constrains nothing this dump drops.
			if c := canonOf[dep]; c != "" && c != o.id {
				o.deps[c] = true
			}
		}
	}

	deps := make(map[string][]string, len(order))
	for _, id := range order {
		for dep := range objs[id].deps {
			deps[id] = append(deps[id], dep)
		}
		sort.Strings(deps[id]) // map iteration order must not reach the dump
	}

	// Cycles: group where one DROP command can cover the whole component,
	// retain (and warn) where none can.
	var retainedRoots []string
	groupSQL := map[string]string{} // member id → the statement that drops it
	for _, comp := range driver.SCC(order, deps) {
		if len(comp) == 1 && !driver.HasSelfEdge(comp[0], deps) {
			continue
		}
		members := append([]string(nil), comp...)
		sort.Slice(members, func(i, j int) bool { return objs[members[i]].dropPos > objs[members[j]].dropPos })
		class, groupable := "", true
		for _, id := range members {
			if objs[id].drop == "" {
				groupable = false // an undroppable member retains the whole component
				break
			}
		}
		if groupable {
			class = objs[members[0]].form.Class
			for _, id := range members {
				if objs[id].form.Class != class || !driver.GroupableDropClass(class) {
					class = ""
					break
				}
			}
			if class == "" {
				// Mixed routine kinds (a function and an aggregate, say) share no
				// class, but DROP ROUTINE covers them all — with the FLAT input
				// signature, the one spelling valid for every routine kind.
				class = "ROUTINE"
				for _, id := range members {
					if objs[id].form.RoutineRef == "" {
						class = ""
						break
					}
				}
			}
			groupable = class != ""
		}
		if !groupable {
			retainedRoots = append(retainedRoots, members...)
			tp.warnings = append(tp.warnings, "drop-first teardown omits the DROP of "+
				teardownLabels(objs, members, 6)+": they form a dependency cycle no single DROP command covers "+
				"(CASCADE is never emitted — it would drop objects outside this export). A fresh target is unaffected; "+
				"a re-restore into a populated target needs them removed manually.")
			continue
		}
		refs := make([]string, 0, len(members))
		for _, id := range members {
			if class == "ROUTINE" {
				refs = append(refs, objs[id].form.RoutineRef)
			} else {
				refs = append(refs, objs[id].form.Ref)
			}
		}
		sql := "DROP " + class + " IF EXISTS " + strings.Join(refs, ", ")
		tp.grouped[members[0]] = sql
		for _, id := range members {
			groupSQL[id] = sql
			if id != members[0] {
				tp.covered[id] = true
			}
		}
	}

	// An emitted object with no drop at all (the dialect refuses to emit one)
	// SURVIVES the teardown, so it seeds retention just like a retained cycle.
	for _, id := range order {
		if objs[id].drop == "" && groupSQL[id] == "" {
			retainedRoots = append(retainedRoots, id)
		}
	}

	// Retention closure: a surviving object still holds its own prerequisites,
	// so dropping them would fail under RESTRICT — omit those drops too.
	retained := map[string]bool{}
	queue := append([]string(nil), retainedRoots...)
	for _, id := range retainedRoots {
		retained[id] = true
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, dep := range deps[id] {
			if !retained[dep] {
				retained[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	rootSet := driver.StringSet(retainedRoots)
	var closure []string
	for _, id := range order {
		if !retained[id] {
			continue
		}
		tp.omit[id] = true
		delete(tp.grouped, id)
		if objs[id].drop != "" && !rootSet[id] {
			closure = append(closure, id)
		}
	}
	if len(closure) > 0 {
		tp.warnings = append(tp.warnings, "drop-first teardown also omits the DROP of "+
			teardownLabels(objs, closure, 8)+": a retained object still depends on them.")
	}

	// The audit runs on what the dump ACTUALLY drops.
	var planned []driver.TeardownDrop
	for _, id := range order {
		o := objs[id]
		if o.drop == "" || retained[id] {
			continue
		}
		sql := o.drop
		if g := groupSQL[id]; g != "" {
			sql = g
		}
		planned = append(planned, driver.TeardownDrop{Node: id, SQL: sql})
	}
	advisories, err := conn.AuditTeardown(ctx, planned)
	if err != nil {
		// Warn-only by contract: a failed audit degrades to a note, never to a
		// failed export or a suppressed drop.
		tp.warnings = append(tp.warnings, "drop-first teardown audit did not complete: "+err.Error())
	}
	tp.warnings = append(tp.warnings, advisories...)
	return tp
}

// buildPredataItems flattens the sections' pre-data scripts and tables in
// class-major insertion order (the priority seeding). Scripts without a Name
// get a synthetic anonymous id: they take no part in edges and keep their
// stable position — which also guarantees a view/type's attached comment
// scripts always emit AFTER their object (an anonymous item is never hoisted,
// and its object is emitted no later than its own input turn).
func buildPredataItems(sections []Section) []*predataItem {
	var items []*predataItem
	anon := 0
	assign := func(name string) string {
		if name != "" {
			return name
		}
		anon++
		return fmt.Sprintf("anon:%d", anon)
	}
	addScripts := func(sec int, list []driver.DumpScript) {
		for i := range list {
			s := &list[i]
			deps := append([]string(nil), s.DependsOn...)
			for _, c := range s.Clauses {
				deps = append(deps, c.Deps...)
			}
			items = append(items, &predataItem{
				id: assign(s.Name), deps: deps, origDeps: append([]string(nil), s.DependsOn...),
				fullDeps: append([]string(nil), deps...),
				script:   s, clauseCut: make([]bool, len(s.Clauses)), sec: sec,
			})
		}
	}
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.Collations)
	}
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.Types)
	}
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.Routines)
	}
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.Sequences)
	}
	// Foreign tables sit between sequences and local tables (pg_dump's
	// foreign-data priority); a foreign table INHERITing a local parent hoists
	// the parent via its edge.
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.ForeignData)
	}
	for si := range sections {
		for i := range sections[si].Plan.tables {
			td := &sections[si].Plan.tables[i]
			node := sections[si].Plan.objects.TableNodes[td.scope.Table]
			deps := append([]string(nil), node.Deps...)
			for _, dd := range node.DeferrableDefaults {
				deps = append(deps, dd...)
			}
			for _, dc := range node.DeferrableConstraints {
				deps = append(deps, dc...)
			}
			items = append(items, &predataItem{
				id: assign(node.Name), deps: deps, origDeps: append([]string(nil), node.Deps...),
				fullDeps: append([]string(nil), deps...),
				table:    td, tnode: node, sec: si,
			})
		}
	}
	for si := range sections {
		addScripts(si, sections[si].Plan.objects.Views)
	}
	return items
}

// effectivePredataDeps returns an item's CURRENT dependency edges: cut clauses
// and stripped table defaults/constraints no longer contribute theirs, and a
// staged routine keeps only its stub's signature edges.
func effectivePredataDeps(it *predataItem) []string {
	switch {
	case it.staged:
		return it.script.StubDeps
	case it.script != nil:
		deps := append([]string(nil), it.script.DependsOn...)
		for i, c := range it.script.Clauses {
			if !it.clauseCut[i] {
				deps = append(deps, c.Deps...)
			}
		}
		return deps
	case it.table != nil:
		deps := append([]string(nil), it.tnode.Deps...)
		strippedD := driver.StringSet(it.stripDefaults)
		strippedC := driver.StringSet(it.stripConstraints)
		for col, dd := range it.tnode.DeferrableDefaults {
			if !strippedD[col] {
				deps = append(deps, dd...)
			}
		}
		for name, dc := range it.tnode.DeferrableConstraints {
			if !strippedC[name] {
				deps = append(deps, dc...)
			}
		}
		return deps
	}
	return it.deps
}

// depsIntersect reports whether any dep is inside the set.
func depsIntersect(deps []string, set map[string]bool) bool {
	for _, d := range deps {
		if set[d] {
			return true
		}
	}
	return false
}

// ResolveDB runs the cycle resolution over one database's sections
// and returns the resolved emission plan. Resolution rounds mirror the plan's
// escalation: (1) CUT deferrable edges (a domain's DEFAULT/CHECK clause, a
// table column DEFAULT or validated CHECK/EXCLUDE expression) whose edges
// close a cycle — the clause re-emerges as deferred DDL in its lane; (2) STAGE
// routines still cyclic (stub now, CREATE OR REPLACE "-final" later — the
// routine analog of type-shell/type-final); (3) any remaining cycle
// preflight-FAILS with a precise error (a warning would leave a silently
// broken dump). External dependers of a staged/deferred object are retargeted
// to its "-final" stage; members of the SAME original cycle keep the base id
// (retargeting them would re-close the cycle).
func ResolveDB(ctx context.Context, conn *driver.Connection, sections []Section, o Options) (*DBPlan, error) {
	dbp := &DBPlan{sections: sections}
	if !o.Structure {
		return dbp, nil // data-only: no pre-data stream at all
	}
	items := buildPredataItems(sections)
	index := make(map[string]*predataItem, len(items))
	for _, it := range items {
		index[it.id] = it
	}
	graph := func() ([]string, map[string][]string) {
		names := make([]string, len(items))
		deps := make(map[string][]string, len(items))
		for i, it := range items {
			names[i] = it.id
			deps[it.id] = effectivePredataDeps(it)
		}
		return names, deps
	}
	cycles := func() [][]string {
		names, deps := graph()
		var bad [][]string
		for _, comp := range driver.SCC(names, deps) {
			if len(comp) > 1 || driver.HasSelfEdge(comp[0], deps) {
				bad = append(bad, comp)
			}
		}
		return bad
	}

	if comps := cycles(); len(comps) > 0 {
		for ci, comp := range comps {
			inComp := driver.StringSet(comp)
			for _, id := range comp {
				it := index[id]
				it.sccID = ci + 1
				if it.script != nil {
					for i, c := range it.script.Clauses {
						if depsIntersect(c.Deps, inComp) {
							it.clauseCut[i] = true
						}
					}
				}
				if it.table != nil {
					for col, dd := range it.tnode.DeferrableDefaults {
						if depsIntersect(dd, inComp) {
							it.stripDefaults = append(it.stripDefaults, col)
						}
					}
					for name, dc := range it.tnode.DeferrableConstraints {
						if depsIntersect(dc, inComp) {
							it.stripConstraints = append(it.stripConstraints, name)
						}
					}
				}
			}
		}
		if comps := cycles(); len(comps) > 0 {
			for _, comp := range comps {
				for _, id := range comp {
					if it := index[id]; it.script != nil && it.script.Stub != "" {
						it.staged = true
					}
				}
			}
			if comps := cycles(); len(comps) > 0 {
				sort.Strings(comps[0])
				return nil, fmt.Errorf("object dependency cycle cannot be restored (no shell/stub/deferral resolves it): %s",
					strings.Join(comps[0], " <-> "))
			}
		}
	}

	// Materialize: resolved SQL per script, "-final" stages, deferred post-data,
	// staged table re-renders.
	stagedFinal := map[string]string{}
	var finals []*predataItem
	for _, it := range items {
		it.deps = effectivePredataDeps(it)
		switch {
		case it.script != nil:
			sql := it.script.SQL
			var preBundle []driver.DumpScript
			var preDeps []string
			for i, c := range it.script.Clauses {
				switch {
				case !it.clauseCut[i]:
					sql += c.Text
				case c.PreData:
					preBundle = append(preBundle, c.Finalize...)
					preDeps = append(preDeps, c.Deps...)
				default:
					dbp.extraPost = append(dbp.extraPost, c.Finalize...)
				}
			}
			if it.staged {
				// Stub now, real object later: the original SQL (already CREATE
				// OR REPLACE) becomes the "-final" stage, ordered after the stub
				// and the original targets' base stages (existence suffices for
				// its CREATE-time validation).
				fs := *it.script
				fs.SQL = sql
				fs.Comment = strings.TrimSpace(fs.Comment + " (restored body/defaults)")
				finalID := it.id + "-final"
				finals = append(finals, &predataItem{
					id: finalID, deps: append([]string{it.id}, it.origDeps...),
					finalOf: it.id, bundle: []driver.DumpScript{fs}, sec: it.sec,
				})
				stagedFinal[it.id] = finalID
				sql = it.script.Stub
			} else if len(preBundle) > 0 {
				finalID := it.id + "-final"
				finals = append(finals, &predataItem{
					id: finalID, deps: append([]string{it.id}, preDeps...),
					finalOf: it.id, bundle: preBundle, sec: it.sec,
				})
				stagedFinal[it.id] = finalID
			}
			it.sqlText = sql
		case it.table != nil && (len(it.stripDefaults) > 0 || len(it.stripConstraints) > 0):
			// A table both conflict-suppressed (StagedDefaultColumns —
			// already rendered and staged by BuildPlan) and cycle-cut
			// here re-renders with the UNION of both strip sets, or the cycle
			// re-render would resurrect the suppressed inline defaults. The
			// carrier scripts the handler already emitted are dropped from the
			// re-render's output by SQL identity so none duplicates.
			conflict := sections[it.sec].Plan.objects.StagedDefaultColumns[it.table.scope.Table]
			have := driver.StringSet(it.stripDefaults)
			for _, col := range conflict {
				if !have[col] {
					it.stripDefaults = append(it.stripDefaults, col)
				}
			}
			sort.Strings(it.stripDefaults) // deterministic re-render + output
			sort.Strings(it.stripConstraints)
			create, fin, err := conn.DumpTableCreateStaged(ctx, it.table.scope, it.table.parents, it.stripDefaults, it.stripConstraints)
			if err != nil {
				return nil, fmt.Errorf("staged structure of %s: %w", it.table.scope.Table, err)
			}
			rewrites := sections[it.sec].Plan.objects.SequenceRewrites
			it.table.create = driver.RewriteSequenceRefs(create, rewrites)
			if len(conflict) > 0 {
				existing := map[string]bool{}
				for _, s := range sections[it.sec].Plan.objects.PostData {
					if s.Kind == "staged-default" {
						existing[s.SQL] = true
					}
				}
				kept := fin[:0]
				for _, s := range fin {
					if s.Kind == "staged-default" && existing[s.SQL] {
						continue
					}
					kept = append(kept, s)
				}
				fin = kept
			}
			for i := range fin {
				fin[i].SQL = driver.RewriteSequenceRefs(fin[i].SQL, rewrites)
			}
			dbp.extraPost = append(dbp.extraPost, fin...)
		}
	}

	// Retarget external dependers of a staged/deferred object to its "-final"
	// stage (a table using a deferred-default domain must wait for the ALTER
	// DOMAIN … SET DEFAULT). Same-cycle members keep the base id.
	for _, it := range items {
		for i, dep := range it.deps {
			if fid, ok := stagedFinal[dep]; ok {
				if target := index[dep]; target != nil && (it.sccID == 0 || it.sccID != target.sccID) {
					it.deps[i] = fid
				}
			}
		}
	}

	all := append(items, finals...)
	names := make([]string, len(all))
	depsMap := make(map[string][]string, len(all))
	byID := make(map[string]*predataItem, len(all))
	for i, it := range all {
		names[i] = it.id
		depsMap[it.id] = it.deps
		byID[it.id] = it
	}
	for _, id := range driver.TopoOrder(names, depsMap) {
		dbp.preOrder = append(dbp.preOrder, byID[id])
	}
	// Resolve the teardown once per database, here, so its source-side audit
	// runs during preflight rather than mid-download.
	if o.DropFirst {
		dbp.teardown = buildTeardownPlan(ctx, conn, dbp)
	}
	return dbp, nil
}
