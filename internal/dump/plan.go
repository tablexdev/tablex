package dump

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// BuildPlan preflights one schema's SQL dump: it resolves what to emit and
// collects every piece of structure DDL BEFORE the download headers go out.
// Only row data streams afterwards, so an introspection failure is a rendered
// error rather than a silently truncated file.
//
// The work is three stages, each its own function: route a special target
// (view / foreign table), read the catalog once, then build one tableDump per
// table.
func BuildPlan(ctx context.Context, conn *driver.Connection, sc driver.TableRef, tables []driver.TableRef, level string, o Options, target *model.Table) (*Plan, error) {
	// The per-table builders below each read some schema-wide catalog facts.
	// The memo lets a dialect read those once for the whole dump instead of once
	// per table; a dialect that does not use it, or a caller that never attaches
	// one, is unaffected — a memo miss just runs the query.
	//
	// Attached only when there is more than one table to amortize ACROSS. With a
	// single table a schema-wide read is not an amortization, it is a scan whose
	// cost grows with the schema to answer for one relation, so its absence is
	// also the signal a dialect uses to narrow that read
	// (driver.HasDumpMemo — postgres/dump_preflight.go).
	if len(tables) > 1 {
		ctx = driver.WithDumpMemo(ctx)
	}
	// V1: a table-scope export whose target is a VIEW/matview emits the view's
	// own DDL (CREATE [MATERIALIZED] VIEW), not a physical CREATE TABLE snapshot
	// with row INSERTs. The table path below would mis-dump it on every engine.
	if target != nil && target.IsView() {
		return buildViewPlan(ctx, conn, sc, *target, o)
	}
	// A FOREIGN target routes to the structure-only foreign plan BEFORE
	// any table machinery — this branch is what provably bypasses
	// DumpDataTables and the row stream (DumpDataTables filters only
	// relispartition, so an untagged foreign relation would flow into the data
	// pass and query the REMOTE server).
	if target != nil && target.Type == model.TableForeign {
		fplan, err := conn.DumpForeignTable(ctx, scopeOf(sc), target.Name)
		if err != nil {
			return nil, err
		}
		return &Plan{objects: fplan}, nil
	}

	pf, err := runPreflight(ctx, conn, sc, tables, level, o)
	if err != nil {
		return nil, err
	}
	if err := pf.buildTables(ctx, conn, o); err != nil {
		return nil, err
	}
	if o.Data {
		if err := pf.buildDataOnlyLeaves(ctx, conn, sc, o.Rows, o.Range); err != nil {
			return nil, err
		}
	}
	return pf.plan, nil
}

// preflight is everything BuildPlan reads from the catalog once, up front,
// before it walks the table list. Keeping it in one value is what lets the
// three stages be separate functions without threading a dozen parameters.
type preflight struct {
	plan   *Plan
	byName map[string]driver.TableRef
	// dataNames is the effective table list: partition children folded into
	// their parents, then topologically ordered so an INHERITS parent precedes
	// its children.
	dataNames []string
	inSet     map[string]bool
	// inheritParents maps a child to its same-schema INHERITS parents; nil for
	// engines without the capability.
	inheritParents map[string][]string
	// bulkCols is the schema-wide column prefetch, or nil when unavailable --
	// callers then fall back to a per-table Columns call.
	bulkCols map[string][]model.Column
	// selectOnly marks the tables whose data SELECT must use FROM ONLY.
	selectOnly map[string]bool
	// dataOnly / structureOnly are the two halves of a mixed local/foreign
	// partition tree: the root carries the DDL but must not scan rows, its
	// local leaves carry the rows but no DDL.
	dataOnly      map[string]bool
	structureOnly map[string]bool
}

func runPreflight(ctx context.Context, conn *driver.Connection, sc driver.TableRef, tables []driver.TableRef, level string, o Options) (*preflight, error) {
	pf := &preflight{plan: &Plan{}, byName: make(map[string]driver.TableRef, len(tables))}
	names := make([]string, len(tables))
	for i, t := range tables {
		names[i] = t.Table
		pf.byName[t.Table] = t
	}
	// PostgreSQL partition children ride with their parent (structure and
	// rows); every other engine returns the list unchanged. The fold runs
	// only for database-scope exports — there the parent is also in the list
	// and a kept child would duplicate its DDL and rows. A TABLE-scope request
	// is explicit: an explicitly requested partition child is KEPT and
	// materialized standalone (the fold used to swallow it into an empty dump).
	pf.dataNames = names
	var err error
	if level != "table" {
		if pf.dataNames, err = conn.DumpDataTables(ctx, scopeOf(sc), names); err != nil {
			return nil, err
		}
	}
	// dbScope, structure and data are passed independently: a data-only DB dump
	// still emits the data-section items (sequence setval, matview refresh)
	// pg_dump would, while not collecting structure-only DDL (routines/views)
	// it would discard — so it cannot fail on introspection it would never use.
	// The mixed local/foreign partition-tree split runs for structure AND data
	// dumps alike: DumpDataTables above kept the tree's local leaves in the
	// effective list, so a structure dump needs the split's DataOnlyTables
	// verdict to suppress each leaf's standalone CREATE (the root's PARTITION
	// OF emission already creates it), and any data-inclusive dump needs the
	// split's per-leaf read plan. Only the split's warnings are data-gated — a
	// structure-only dump must not surface warnings about rows it never reads.
	pf.plan.objects, err = conn.DumpObjects(ctx, scopeOf(sc), pf.dataNames, level != "table", o.Structure, o.Data)
	if err != nil {
		return nil, err
	}
	// G10: same-schema ordinary-inheritance children link to their parent via
	// INHERITS when the parent is also in this export. Parents must be created
	// before children, so topo-order the table list — the writer's
	// reverse-order teardown then drops children first. Nil for engines without
	// the capability (MySQL/SQLite).
	if o.Structure {
		if pf.inheritParents, err = conn.InheritanceParents(ctx, scopeOf(sc), pf.dataNames); err != nil {
			return nil, err
		}
		if len(pf.inheritParents) > 0 {
			pf.dataNames = driver.TopoOrder(pf.dataNames, pf.inheritParents)
		}
	}
	pf.inSet = driver.StringSet(pf.dataNames)
	if o.Data && len(pf.dataNames) > 1 {
		pf.bulkCols = bulkColumnsOrNil(ctx, conn, scopeOf(sc))
	}
	// FROM ONLY set (G10): an ordinary-inheritance parent must scan only its own
	// rows, or its separately-dumped children's rows duplicate into it. Nil for
	// engines without the capability — every table then uses plain FROM.
	if o.Data {
		if pf.selectOnly, err = conn.DataSelectOnly(ctx, scopeOf(sc), pf.dataNames); err != nil {
			return nil, err
		}
	}
	pf.dataOnly = driver.StringSet(pf.plan.objects.DataOnlyTables)
	pf.structureOnly = driver.StringSet(pf.plan.objects.StructureOnlyTables)
	return pf, nil
}

// buildTables walks the effective table list, producing one tableDump each.
func (pf *preflight) buildTables(ctx context.Context, conn *driver.Connection, o Options) error {
	d := conn.Dialect()
	for _, name := range pf.dataNames {
		t := pf.byName[name]
		td := tableDump{scope: t, qualified: conn.QualifiedName(t)}
		if o.Structure && !pf.dataOnly[name] {
			if err := pf.buildTableCreate(ctx, conn, &td, name, t); err != nil {
				return err
			}
		}
		if o.Data && !pf.structureOnly[name] {
			cols, ok := pf.bulkCols[name]
			if !ok {
				var err error
				if cols, err = conn.Columns(ctx, t); err != nil {
					return fmt.Errorf("columns of %s: %w", name, err)
				}
			}
			planTableData(d, &td, cols, pf.selectOnly[name], o.Rows, o.Range)
			if td.excluded {
				pf.plan.objects.Warnings = append(pf.plan.objects.Warnings,
					fmt.Sprintf("table %s carries no data in this export: the selected-row filter targets %s", name, o.Rows.Target.Table))
			}
		}
		pf.plan.tables = append(pf.plan.tables, td)
	}
	return nil
}

// buildTableCreate renders one table's restore-oriented CREATE, choosing among
// the three shapes: staged (deferred conflicting defaults), INHERITS-linked,
// and standalone.
func (pf *preflight) buildTableCreate(ctx context.Context, conn *driver.Connection, td *tableDump, name string, t driver.TableRef) error {
	var err error
	parents := pf.inheritParents[name]
	linked := len(parents) > 0 && allIn(parents, pf.inSet)
	switch strip := pf.plan.objects.StagedDefaultColumns[name]; {
	case len(strip) > 0:
		// A multi-parent default CONFLICT member — the affected columns'
		// inline defaults are suppressed (CREATE … INHERITS would fail on the
		// conflicting parent defaults before any staged DDL could run) and each
		// table's own default re-emerges post-data through the deferred-DDL
		// carrier.
		var linkParents []string
		if linked {
			td.parents = parents
			linkParents = parents
		}
		sorted := append([]string(nil), strip...)
		sort.Strings(sorted)
		var staged []driver.DumpScript
		td.create, staged, err = conn.DumpTableCreateStaged(ctx, t, linkParents, sorted, nil)
		pf.plan.objects.PostData = append(pf.plan.objects.PostData, staged...)
	case linked:
		// Linked: emit CREATE … INHERITS with local-only columns/constraints.
		td.parents = parents
		td.create, err = conn.DumpInheritsChildCreate(ctx, t, parents)
	default:
		td.create, err = conn.DumpTableCreate(ctx, t)
		if errors.Is(err, driver.ErrUnsupported) {
			td.create, err = conn.CreateSQL(ctx, t)
		}
		if len(parents) > 0 {
			// Same-schema parent(s) exist but are not in THIS export (table
			// scope): standalone, with the link lost. Warn.
			pf.plan.objects.Warnings = append(pf.plan.objects.Warnings,
				fmt.Sprintf("table %s inherits from %s, which is not in this export; it is dumped standalone and the inheritance link is not restored",
					name, strings.Join(parents, ", ")))
		}
	}
	if err != nil {
		return fmt.Errorf("structure of %s: %w", name, err)
	}
	// Rebind out-of-scope sequence references (an inherited serial
	// default, a cross-schema/standalone-sequence default) to their replacement
	// sequences. No-op for an empty map.
	td.create = driver.RewriteSequenceRefs(td.create, pf.plan.objects.SequenceRewrites)
	return nil
}

// buildDataOnlyLeaves appends the DataOnlyTables entries absent from the
// request list — the local leaves of a mixed local/foreign partition
// tree in a TABLE-scope export of its root (both data-inclusive forms reach
// here: a structure+data export and a data-only one). At database scope the
// leaves are in dataNames already — the DumpDataTables fold keeps them — so
// this loop finds nothing; at table scope DumpDataTables never runs and the
// leaves must be appended as data-only entries or the tree's local rows
// silently vanish from the dump.
func (pf *preflight) buildDataOnlyLeaves(ctx context.Context, conn *driver.Connection, sc driver.TableRef, filter *RowFilter, rng *RowRange) error {
	inData := driver.StringSet(pf.dataNames)
	for _, name := range pf.plan.objects.DataOnlyTables {
		if inData[name] {
			continue
		}
		t := driver.TableRef{Database: sc.Database, Schema: sc.Schema, Table: name}
		td := tableDump{scope: t, qualified: conn.QualifiedName(t)}
		cols, err := conn.Columns(ctx, t)
		if err != nil {
			return fmt.Errorf("columns of %s: %w", name, err)
		}
		// These are partition-tree leaves, always scanned with ONLY so a row is
		// dumped exactly once.
		planTableData(conn.Dialect(), &td, cols, true, filter, rng)
		if td.excluded {
			// The selected rows were keyed against the tree's ROOT, so the leaf
			// that actually holds them cannot be matched by name. Say so: the
			// alternative is a dump that looks complete and is empty.
			pf.plan.objects.Warnings = append(pf.plan.objects.Warnings,
				fmt.Sprintf("partition %s of %s is not covered by the selected-row filter; its rows are not exported", name, filter.Target.Table))
		}
		pf.plan.tables = append(pf.plan.tables, td)
	}
	return nil
}

// planTableData fills in one table's data-phase state: the quoted insert
// column list, the explicit SELECT that matches it, and the OVERRIDING flag.
//
// It is a single function because the two call sites above must agree
// exactly. The quoted column list, the identity-always walk and the SELECT
// list are all derived from ONE insertableColumns filter — if they ever
// drifted apart, a generated column between two binary ones would shift the
// index mask and the dump would emit values into the wrong columns.
//
// only selects FROM ONLY: an INHERITS parent (or a partition leaf reached
// through DataOnlyTables) must scan its own rows only, or every child row is
// dumped twice.
//
// filter, when set, restricts the rows to a selection made in the browse grid.
// A table it does not target contributes no data and is MARKED as excluded —
// the alternative, dumping that table in full, would hand back rows the user
// never selected.
func planTableData(d driver.Dialect, td *tableDump, cols []model.Column, only bool, filter *RowFilter, rng *RowRange) {
	where, args, allowed := filter.clauseFor(td.scope)
	if !allowed {
		td.excluded = true
		return
	}
	td.args = args
	// The range rides on the row SELECT only. countSQL below feeds the L10
	// all-defaults path, where a LIMIT would be meaningless — it counts rows to
	// decide how many valueless INSERTs to emit — so it is applied per branch
	// rather than to both.
	limit := rng.clauseFor(d)
	quoted := quotedInsertableCols(d, cols)
	// An identity-always column needs OVERRIDING SYSTEM VALUE to accept the
	// dumped value on restore. Walked over the same insertableColumns set the
	// quoted list is built from.
	for _, c := range insertableColumns(cols) {
		if c.Identity == model.IdentityAlways {
			td.overriding = true
		}
	}
	from := " FROM "
	if only {
		from = " FROM ONLY "
	}
	if len(quoted) > 0 {
		td.insertCols = strings.Join(quoted, ", ")
		td.selectSQL = "SELECT " + td.insertCols + from + td.qualified + where + limit
		return
	}
	// L10: no insertable columns (a zero-column table, or one whose every
	// column is generated) — the rows still exist and must be dumped as
	// all-defaults INSERTs. Count them with the same ONLY decision as ordinary
	// extraction: a plain count on an inheritance parent would include the
	// separately-dumped descendant rows.
	td.countSQL = "SELECT count(*)" + from + td.qualified + where
}

// buildViewPlan builds the plan for a table-scope SQL export whose target is
// a view/matview (V1). It emits the view's DDL via the dialect's ViewDumper —
// CREATE [MATERIALIZED] VIEW plus its comments and, for a populated matview with
// data requested, a REFRESH — and NO table CREATE or row INSERTs. The writer's
// existing structure/data gates then apply: structure-only emits the CREATE,
// data-only emits only a matview REFRESH, both emit both. The export is not
// self-contained (the view's referenced objects must exist in the restore
// target), so a warning is prepended.
func buildViewPlan(ctx context.Context, conn *driver.Connection, sc driver.TableRef, target model.Table, o Options) (*Plan, error) {
	vplan, ok, err := conn.DumpView(ctx, scopeOf(sc), target.Name, o.Data)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No engine reaches here — MySQL/PostgreSQL/SQLite all implement ViewDumper
		// — but fail loud rather than silently emit a wrong physical-table snapshot.
		return nil, fmt.Errorf("exporting a view as SQL is not supported for this engine")
	}
	kind := "View"
	if target.Type == model.TableMatView {
		kind = "Materialized view"
	}
	vplan.Warnings = append([]string{
		kind + " " + target.Name + " is exported on its own: its referenced tables, " +
			"views and functions must already exist in the restore target, and an external " +
			"dependent can block a drop-first restore",
	}, vplan.Warnings...)
	return &Plan{objects: vplan}, nil
}
