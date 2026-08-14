// Sequences for the dump path: CREATE SEQUENCE reconstruction, exact value
// synchronization (setval from last_value/is_called, what pg_dump does), the
// deterministic synthetic names that replace out-of-scope sequence references,
// and identity-column options.

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// seqOptions renders the concrete sequence option clause shared by CREATE
// SEQUENCE and an identity column's GENERATED … AS IDENTITY (options). Catalog
// values are always emitted (no NO MINVALUE special-casing) so a restore lands
// the identical catalog state; the caller prepends "AS <type>" for non-bigint
// CREATE SEQUENCE (an identity column's type comes from the column itself).
func seqOptions(start, inc, minv, maxv, cache int64, cycle bool) string {
	s := fmt.Sprintf("START WITH %d INCREMENT BY %d MINVALUE %d MAXVALUE %d CACHE %d", start, inc, minv, maxv, cache)
	if cycle {
		s += " CYCLE"
	}
	return s
}

// seqRow is one sequence's full catalog definition, shared by the schema
// sequence pass and the replacement-sequence collector so a replacement
// reproduces the complete definition (AS type, START/INCREMENT/MIN/MAX/CACHE/
// CYCLE, persistence) — not just a name.
type seqRow struct {
	schema, name, typ             string
	start, inc, minv, maxv, cache int64
	cycle                         bool
	persistence                   string // 'p' permanent, 'u' unlogged (PG15+)
	comment                       string
	deptype                       string // "a", "i", or "" (standalone)
	tblSchema, tblName, colName   string
	tblPersistence                string // owner table's relpersistence ("" when unowned)
}

// seqCreateScript renders one CREATE SEQUENCE DumpScript from a full catalog
// definition. seqIdent must be the quoted qualified name matching r.schema/
// r.name (the graph node id and Drop derive from them).
func (dialect) seqCreateScript(r seqRow, seqIdent string) driver.DumpScript {
	opts := seqOptions(r.start, r.inc, r.minv, r.maxv, r.cache, r.cycle)
	if r.typ != "" && r.typ != "bigint" {
		opts = "AS " + r.typ + " " + opts
	}
	// G13: an UNLOGGED sequence (PG15+) restores UNLOGGED. The keyword sits
	// before SEQUENCE; a permanent sequence keeps the plain CREATE SEQUENCE.
	create := "CREATE SEQUENCE "
	if r.persistence == "u" {
		create = "CREATE UNLOGGED SEQUENCE "
	}
	return driver.DumpScript{
		Kind:     "sequence-def",
		Name:     nodeID("relation", r.schema, r.name),
		Comment:  "Sequence " + r.name,
		Drop:     "DROP SEQUENCE IF EXISTS " + seqIdent,
		DropForm: driver.DropForm{Class: "SEQUENCE", Ref: seqIdent},
		SQL:      create + seqIdent + " " + opts,
	}
}

// seqSetvalScript reads readIdent's current value and emits the post-data
// setval against targetIdent. The two differ for a replacement, which is
// seeded from the SOURCE sequence's value.
func (d dialect) seqSetvalScript(ctx context.Context, db *sql.DB, name, readIdent, targetIdent string) (driver.DumpScript, error) {
	var lastValue int64
	var isCalled bool
	if err := db.QueryRowContext(ctx, "SELECT last_value, is_called FROM "+readIdent).Scan(&lastValue, &isCalled); err != nil {
		return driver.DumpScript{}, err
	}
	return driver.DumpScript{
		Kind:    "sequence",
		Comment: "Sequence " + name,
		SQL:     fmt.Sprintf("SELECT pg_catalog.setval(%s, %d, %t)", d.QuoteString(targetIdent), lastValue, isCalled),
	}, nil
}

// serialSeqSeed / identitySeqSeed build the deterministic hash inputs for a
// replacement sequence's name. NUL separators keep dotted names unambiguous,
// and the placement schema is BOUND INTO the identity so the collision check
// and the name agree per placement. identitySeqSeed additionally binds the
// standalone child (one replacement per (source, child) — each ex-sibling
// partition gets its own), and the child's schema IS the placement (an
// identity sequence lives inline in its table's schema).
func serialSeqSeed(placementSchema, srcSchema, srcName string) string {
	return "seq\x00" + placementSchema + "\x00" + srcSchema + "\x00" + srcName
}

func identitySeqSeed(srcSchema, srcName, childSchema, childName string) string {
	return "idseq\x00" + srcSchema + "\x00" + srcName + "\x00" + childSchema + "\x00" + childName
}

// syntheticSeqCandidates returns the deterministic replacement-name candidates
// for one seed: tablex_seq_<hex> with the SHA-256 prefix lengthened on
// collision (12 → 52 hex; 11+52 = 63 chars keeps NAMEDATALEN-1).
func syntheticSeqCandidates(seed string) []string {
	sum := sha256.Sum256([]byte(seed))
	hexSum := hex.EncodeToString(sum[:])
	out := make([]string, 0, 6)
	for l := 12; l <= 52; l += 8 {
		out = append(out, "tablex_seq_"+hexSum[:l])
	}
	return out
}

// syntheticSeqName picks the first candidate that is free in the placement
// schema's SOURCE-catalog pg_class namespace — checked against EVERY relation
// kind (tables, indexes, views, matviews, sequences, composite types): an
// out-of-scope sibling still occupies the relation namespace and will
// pre-exist in a matching restore target, so the emitted subset is not enough.
// All candidates taken is an explicit error, never a silent rename.
//
// The candidates are tested in ONE query rather than one round-trip each.
// Set membership is the same either way, so the first free candidate is still
// the one chosen.
func (d dialect) syntheticSeqName(ctx context.Context, db *sql.DB, schema, seed string) (string, error) {
	cands := syntheticSeqCandidates(seed)
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = ANY($2)`, schema, cands)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	taken := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", err
		}
		taken[name] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for _, cand := range cands {
		if !taken[cand] {
			return cand, nil
		}
	}
	return "", fmt.Errorf("no free replacement-sequence name in schema %q (every tablex_seq_ candidate length collides)", schema)
}

// collectExternalSequences finds sequences a SCOPED export's
// emitted tables reference but the dump does not emit — early-bound
// nextval('s'::regclass) defaults via their pg_depend edge, late-bound
// nextval('s'::text) defaults by scanning the deparsed expression, and a
// standalone-materialized partition child's root identity sequence. With
// structure on, each source materializes a deterministic tablex_seq_*
// replacement (full definition via seqCreateScript, seeded from the source's
// current value, references rebound through DumpPlan.SequenceRewrites); a
// data-only dump instead targets the ORIGINAL qualified sequence with setval
// (the data-only contract assumes structure pre-exists) and warns where a
// late-bound reference cannot be resolved.
func (d dialect) collectExternalSequences(ctx context.Context, db *sql.DB, schema string, inTables map[string]bool, structure bool, emittedSeq map[string]bool, plan *driver.DumpPlan) error {
	type consumer struct{ table, column string }
	sources := map[string][2]string{} // key → {schema, name}
	consumers := map[string][]consumer{}
	addRef := func(srcSchema, srcName, table, column string) {
		key := driver.SeqRefKey(srcSchema, srcName)
		if emittedSeq[key] {
			return
		}
		if _, ok := sources[key]; !ok {
			sources[key] = [2]string{srcSchema, srcName}
		}
		consumers[key] = append(consumers[key], consumer{table, column})
	}

	// Early-bound references: the pg_attrdef → sequence NORMAL dependency.
	ebRows, err := db.QueryContext(ctx, `
		SELECT t.relname, a.attname, sn.nspname, s.relname
		FROM pg_attrdef ad
		JOIN pg_class t ON t.oid = ad.adrelid
		JOIN pg_namespace tn ON tn.oid = t.relnamespace
		JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
		  AND a.attgenerated = ''
		JOIN pg_depend dep ON dep.classid = 'pg_attrdef'::regclass AND dep.objid = ad.oid
		  AND dep.refclassid = 'pg_class'::regclass AND dep.deptype = 'n'
		JOIN pg_class s ON s.oid = dep.refobjid AND s.relkind = 'S'
		JOIN pg_namespace sn ON sn.oid = s.relnamespace
		WHERE tn.nspname = $1
		ORDER BY t.relname, a.attname, sn.nspname, s.relname`, schema)
	if err != nil {
		return err
	}
	for ebRows.Next() {
		var table, column, srcSchema, srcName string
		if err := ebRows.Scan(&table, &column, &srcSchema, &srcName); err != nil {
			ebRows.Close()
			return err
		}
		if inTables[table] {
			addRef(srcSchema, srcName, table, column)
		}
	}
	ebRows.Close()
	if err := ebRows.Err(); err != nil {
		return err
	}

	// Late-bound references: nextval('lit'::text) records no pg_depend edge —
	// scan the deparsed default text. A qualified literal resolves against the
	// source catalog; unqualified/dynamic/dangling ones can only be warned.
	lbRows, err := db.QueryContext(ctx, `
		SELECT t.relname, a.attname, pg_get_expr(ad.adbin, ad.adrelid)
		FROM pg_attrdef ad
		JOIN pg_class t ON t.oid = ad.adrelid
		JOIN pg_namespace tn ON tn.oid = t.relnamespace
		JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
		  AND a.attgenerated = ''
		WHERE tn.nspname = $1
		ORDER BY t.relname, a.attname`, schema)
	if err != nil {
		return err
	}
	type lateRef struct{ table, column, literal string }
	var lateRefs []lateRef
	for lbRows.Next() {
		var table, column, expr string
		if err := lbRows.Scan(&table, &column, &expr); err != nil {
			lbRows.Close()
			return err
		}
		if !inTables[table] {
			continue
		}
		refs, dynamic := driver.NextvalTextRefs(expr)
		if dynamic {
			plan.Warnings = append(plan.Warnings,
				"default of "+schema+"."+table+"."+column+" calls nextval with a non-literal argument; the referenced sequence cannot be resolved — re-point it manually after restore")
		}
		for _, ref := range refs {
			lateRefs = append(lateRefs, lateRef{table, column, ref})
		}
	}
	lbRows.Close()
	if err := lbRows.Err(); err != nil {
		return err
	}
	for _, lr := range lateRefs {
		srcSchema, srcName, ok := driver.ParseQualifiedSeqLiteral(lr.literal)
		if !ok {
			plan.Warnings = append(plan.Warnings,
				"default of "+schema+"."+lr.table+"."+lr.column+" references sequence '"+lr.literal+"' late-bound and unqualified; its binding depends on the restore-time search_path and is not rewritten")
			continue
		}
		key := driver.SeqRefKey(srcSchema, srcName)
		if emittedSeq[key] {
			continue
		}
		var one int
		err := db.QueryRowContext(ctx, `
			SELECT 1 FROM pg_class s
			JOIN pg_namespace sn ON sn.oid = s.relnamespace
			WHERE sn.nspname = $1 AND s.relname = $2 AND s.relkind = 'S'`,
			srcSchema, srcName).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			plan.Warnings = append(plan.Warnings,
				"default of "+schema+"."+lr.table+"."+lr.column+" references sequence "+srcSchema+"."+srcName+" late-bound, but no such sequence exists in the source; the reference is left as-is")
			continue
		}
		if err != nil {
			return err
		}
		addRef(srcSchema, srcName, lr.table, lr.column)
	}

	// Deterministic emission order.
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		srcSchema, srcName := sources[key][0], sources[key][1]
		srcIdent := d.QuoteIdent(srcSchema) + "." + d.QuoteIdent(srcName)
		if !structure {
			// Data-only: the contract assumes structure pre-exists in the
			// target, so sync the ORIGINAL sequence — no tablex_seq_* reference
			// may appear in a data-only dump.
			s, err := d.seqSetvalScript(ctx, db, srcName, srcIdent, srcIdent)
			if err != nil {
				return err
			}
			plan.PostData = append(plan.PostData, s)
			continue
		}
		// Full definition + the (at most one) OWNED BY owner.
		var r seqRow
		var ownSchema, ownTable, ownColumn string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_catalog.format_type(ps.seqtypid, NULL),
			       ps.seqstart, ps.seqincrement, ps.seqmin, ps.seqmax, ps.seqcache, ps.seqcycle,
			       s.relpersistence::text, COALESCE(obj_description(s.oid, 'pg_class'), ''),
			       COALESCE(otn.nspname, ''), COALESCE(ot.relname, ''), COALESCE(oa.attname, '')
			FROM pg_class s
			JOIN pg_namespace sn ON sn.oid = s.relnamespace
			JOIN pg_sequence ps ON ps.seqrelid = s.oid
			LEFT JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass
			  AND dep.objid = s.oid AND dep.refclassid = 'pg_class'::regclass
			  AND dep.deptype IN ('a','i')
			LEFT JOIN pg_class ot ON ot.oid = dep.refobjid
			LEFT JOIN pg_namespace otn ON otn.oid = ot.relnamespace
			LEFT JOIN pg_attribute oa ON oa.attrelid = dep.refobjid AND oa.attnum = dep.refobjsubid
			WHERE sn.nspname = $1 AND s.relname = $2 AND s.relkind = 'S'`,
			srcSchema, srcName).Scan(
			&r.typ, &r.start, &r.inc, &r.minv, &r.maxv, &r.cache, &r.cycle,
			&r.persistence, &r.comment, &ownSchema, &ownTable, &ownColumn); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue // dropped mid-export: the reference is already captured, nothing to replace
			}
			return err
		}
		// Placement: the owner's schema when the owner column is emitted (it is
		// then schema-compatible by the OWNED BY same-schema invariant);
		// otherwise the first emitted consumer's schema — always THIS schema in
		// a scoped export — with OWNED BY NONE. Consumer count never forces
		// NONE; only an absent/unemitted owner does.
		ownerEmitted := ownTable != "" && ownSchema == schema && inTables[ownTable]
		placement := schema
		if ownerEmitted {
			placement = ownSchema
		}
		synth, err := d.syntheticSeqName(ctx, db, placement, serialSeqSeed(placement, srcSchema, srcName))
		if err != nil {
			return err
		}
		r.schema, r.name = placement, synth
		synthIdent := d.QuoteIdent(placement) + "." + d.QuoteIdent(synth)
		plan.Sequences = append(plan.Sequences, d.seqCreateScript(r, synthIdent))
		if ownerEmitted {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "sequence-own",
				Comment: "Replacement sequence " + synth + " owned by " + ownTable + "." + ownColumn,
				SQL: "ALTER SEQUENCE " + synthIdent + " OWNED BY " +
					d.QuoteIdent(ownSchema) + "." + d.QuoteIdent(ownTable) + "." + d.QuoteIdent(ownColumn),
			})
		}
		if r.comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "sequence-comment",
				Comment: "Comment for replacement sequence " + synth,
				SQL:     "COMMENT ON SEQUENCE " + synthIdent + " IS " + d.QuoteString(r.comment),
			})
		}
		s, err := d.seqSetvalScript(ctx, db, synth, srcIdent, synthIdent)
		if err != nil {
			return err
		}
		plan.PostData = append(plan.PostData, s)
		if plan.SequenceRewrites == nil {
			plan.SequenceRewrites = map[string]string{}
		}
		plan.SequenceRewrites[key] = driver.SeqRefKey(placement, synth)
		names := make([]string, 0, len(consumers[key]))
		seen := map[string]bool{}
		for _, c := range consumers[key] {
			ref := c.table + "." + c.column
			if !seen[ref] {
				seen[ref] = true
				names = append(names, ref)
			}
		}
		ownedBy := "OWNED BY NONE"
		if ownerEmitted {
			ownedBy = "owned by " + ownTable + "." + ownColumn
		}
		plan.Warnings = append(plan.Warnings,
			"sequence "+srcSchema+"."+srcName+" (referenced by "+strings.Join(names, ", ")+") is not part of this export; a replacement sequence "+placement+"."+synth+" ("+ownedBy+") is created, seeded from the source's current value, and the referencing defaults are rebound to it")
	}

	return d.collectStandaloneIdentity(ctx, db, schema, inTables, structure, plan)
}

// collectStandaloneIdentity handles the identity columns of partition
// children materialized STANDALONE (table scope): the backing sequence belongs
// to the partition ROOT — pg_depend records the 'i' edge only there — so the
// child's re-created identity would silently mint a fresh default-option
// sequence. identityOptions inlines the deterministic replacement (SEQUENCE
// NAME tablex_seq_* with the source's options) into the child's CREATE; this
// pass emits the matching post-data state: setval seeded from the source, the
// source's comment, the PG15+ persistence delta, and the shared-stream split
// warning. Data-only dumps target the ORIGINAL root sequence instead.
func (d dialect) collectStandaloneIdentity(ctx context.Context, db *sql.DB, schema string, inTables map[string]bool, structure bool, plan *driver.DumpPlan) error {
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, c.relpersistence::text,
		       sn.nspname, s.relname, s.relpersistence::text,
		       COALESCE(obj_description(s.oid, 'pg_class'), '')
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid AND c.relispartition
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_class r ON r.oid = pg_partition_root(c.oid)
		JOIN pg_attribute ra ON ra.attrelid = r.oid AND ra.attname = a.attname
		  AND NOT ra.attisdropped
		JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass
		  AND dep.refclassid = 'pg_class'::regclass AND dep.refobjid = r.oid
		  AND dep.refobjsubid = ra.attnum AND dep.deptype = 'i'
		JOIN pg_class s ON s.oid = dep.objid AND s.relkind = 'S'
		JOIN pg_namespace sn ON sn.oid = s.relnamespace
		WHERE n.nspname = $1 AND a.attidentity <> '' AND a.attnum > 0
		  AND NOT a.attisdropped
		  AND NOT EXISTS (SELECT 1 FROM pg_depend od
		      WHERE od.classid = 'pg_class'::regclass AND od.refclassid = 'pg_class'::regclass
		        AND od.refobjid = a.attrelid AND od.refobjsubid = a.attnum AND od.deptype = 'i')
		ORDER BY c.relname, a.attname`, schema)
	if err != nil {
		return err
	}
	type idRow struct {
		child, column, childPersistence    string
		srcSchema, srcName, srcPersistence string
		srcComment                         string
	}
	var idRows []idRow
	for rows.Next() {
		var r idRow
		if err := rows.Scan(&r.child, &r.column, &r.childPersistence,
			&r.srcSchema, &r.srcName, &r.srcPersistence, &r.srcComment); err != nil {
			rows.Close()
			return err
		}
		if inTables[r.child] {
			idRows = append(idRows, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range idRows {
		srcIdent := d.QuoteIdent(r.srcSchema) + "." + d.QuoteIdent(r.srcName)
		if !structure {
			s, err := d.seqSetvalScript(ctx, db, r.srcName, srcIdent, srcIdent)
			if err != nil {
				return err
			}
			plan.PostData = append(plan.PostData, s)
			continue
		}
		synth, err := d.syntheticSeqName(ctx, db, schema, identitySeqSeed(r.srcSchema, r.srcName, schema, r.child))
		if err != nil {
			return err
		}
		synthIdent := d.QuoteIdent(schema) + "." + d.QuoteIdent(synth)
		s, err := d.seqSetvalScript(ctx, db, synth, srcIdent, synthIdent)
		if err != nil {
			return err
		}
		plan.PostData = append(plan.PostData, s)
		if r.srcComment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "sequence-comment",
				Comment: "Comment for replacement identity sequence " + synth,
				SQL:     "COMMENT ON SEQUENCE " + synthIdent + " IS " + d.QuoteString(r.srcComment),
			})
		}
		// The recreated identity inherits the CHILD table's persistence; a
		// diverging source state (PG15+) needs the explicit ALTER.
		if d.major >= 15 && r.srcPersistence != r.childPersistence {
			verb := "SET LOGGED"
			if r.srcPersistence == "u" {
				verb = "SET UNLOGGED"
			}
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "sequence-persistence",
				Comment: "Persistence of replacement identity sequence " + synth,
				SQL:     "ALTER SEQUENCE " + synthIdent + " " + verb,
			})
		}
		plan.Warnings = append(plan.Warnings,
			"partition "+schema+"."+r.child+" is materialized standalone with its own identity sequence "+schema+"."+synth+" seeded from "+r.srcSchema+"."+r.srcName+"; the partition tree's shared identity stream is split — values generated across the ex-sibling partitions can overlap")
	}
	return nil
}

// identityOptions maps each identity column of the table to its sequence-option
// clause (START WITH … CACHE [CYCLE]), so a restored GENERATED … AS IDENTITY
// keeps a non-default START/INCREMENT/etc. instead of silently resetting to the
// defaults. The identity's backing sequence is reached through pg_depend
// (deptype 'i'); the column type defines the sequence's element type, so no
// "AS <type>" is emitted inside the IDENTITY options. Valid sequence_options
// syntax inside CREATE TABLE.
// Both catalog reads are SCHEMA-wide and memoized for the dump
// (driver.MemoizedDump), so a 100-table export makes two queries instead of two
// hundred. Only the READS are shared: the synthetic-name resolution below still
// runs for this table's rows alone, because it can fail ("no free
// replacement-sequence name") and resolving names for tables outside this dump
// would surface an error the per-table path never produced.
func (d dialect) identityOptions(ctx context.Context, db *sql.DB, schema, table string) (map[string]string, error) {
	owned, err := d.ownedIdentityOptions(ctx, db, schema)
	if err != nil {
		return nil, err
	}
	// Copy: the memoized map is shared with every later table in this dump, so
	// the caller must not be handed a reference into it.
	out := map[string]string{}
	maps.Copy(out, owned[table])

	root, err := d.rootIdentityRows(ctx, db, schema)
	if err != nil {
		return nil, err
	}
	for _, r := range root[table] {
		synth, err := d.syntheticSeqName(ctx, db, schema, identitySeqSeed(r.srcSchema, r.srcName, schema, table))
		if err != nil {
			return nil, err
		}
		out[r.col] = "SEQUENCE NAME " + d.QuoteIdent(schema) + "." + d.QuoteIdent(synth) + " " +
			seqOptions(r.start, r.inc, r.minv, r.maxv, r.cache, r.cycle)
	}
	return out, nil
}

// ownedIdentityOptions reads every identity column in the schema whose backing
// sequence it OWNS, as table -> column -> option clause.
func (d dialect) ownedIdentityOptions(ctx context.Context, db *sql.DB, schema string) (map[string]map[string]string, error) {
	v, err := driver.MemoizedDump(ctx, "pg:identity-owned:"+schema, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, a.attname, s.relname,
			       ps.seqstart, ps.seqincrement, ps.seqmin, ps.seqmax, ps.seqcache, ps.seqcycle
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_depend dep ON dep.refobjid = a.attrelid AND dep.refobjsubid = a.attnum
			  AND dep.deptype = 'i' AND dep.classid = 'pg_class'::regclass
			JOIN pg_class s ON s.oid = dep.objid AND s.relkind = 'S'
			JOIN pg_sequence ps ON ps.seqrelid = s.oid
			WHERE n.nspname = $1 AND a.attidentity <> ''`, schema)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]map[string]string{}
		for rows.Next() {
			var tbl, col, seqName string
			var start, inc, minv, maxv, cache int64
			var cycle bool
			if err := rows.Scan(&tbl, &col, &seqName, &start, &inc, &minv, &maxv, &cache, &cycle); err != nil {
				return nil, err
			}
			// G12: preserve a renamed identity sequence's name. SEQUENCE NAME is valid
			// as the first identity option (PG 13 floor), and the owned-sequence
			// invariant guarantees the sequence shares the table's schema — so the
			// post-data setval / comment / persistence ALTERs, which target the
			// original name, still resolve after restore. Without it the recreated
			// identity picks the default table_col_seq name and those ALTERs miss.
			seqIdent := d.QuoteIdent(schema) + "." + d.QuoteIdent(seqName)
			if out[tbl] == nil {
				out[tbl] = map[string]string{}
			}
			out[tbl][col] = "SEQUENCE NAME " + seqIdent + " " + seqOptions(start, inc, minv, maxv, cache, cycle)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]map[string]string), nil
}

// rootIdentityRow is one partition child's identity column whose backing
// sequence belongs to the partition ROOT.
type rootIdentityRow struct {
	col, srcSchema, srcName       string
	start, inc, minv, maxv, cache int64
	cycle                         bool
}

// rootIdentityRows reads, per partition child in the schema, the identity
// columns whose backing sequence belongs to the partition ROOT.
//
// A partition child materialized STANDALONE (dumpTableCreate is only
// reached by one at table scope) carries identity columns with no 'i' edge of
// their own, so the owned read finds nothing for them and the re-created
// identity would mint a fresh default-option sequence. The caller inlines the
// deterministic replacement instead: SEQUENCE NAME tablex_seq_* (in the child's
// schema, the placement an identity sequence requires) with the SOURCE
// sequence's full options. collectStandaloneIdentity emits the matching
// setval/comment/persistence post-data against the same deterministic name.
func (d dialect) rootIdentityRows(ctx context.Context, db *sql.DB, schema string) (map[string][]rootIdentityRow, error) {
	v, err := driver.MemoizedDump(ctx, "pg:identity-root:"+schema, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, a.attname, sn.nspname, s.relname,
			       ps.seqstart, ps.seqincrement, ps.seqmin, ps.seqmax, ps.seqcache, ps.seqcycle
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid AND c.relispartition
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_class r ON r.oid = pg_partition_root(c.oid)
			JOIN pg_attribute ra ON ra.attrelid = r.oid AND ra.attname = a.attname
			  AND NOT ra.attisdropped
			JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass
			  AND dep.refclassid = 'pg_class'::regclass AND dep.refobjid = r.oid
			  AND dep.refobjsubid = ra.attnum AND dep.deptype = 'i'
			JOIN pg_class s ON s.oid = dep.objid AND s.relkind = 'S'
			JOIN pg_namespace sn ON sn.oid = s.relnamespace
			JOIN pg_sequence ps ON ps.seqrelid = s.oid
			WHERE n.nspname = $1 AND a.attidentity <> ''
			  AND a.attnum > 0 AND NOT a.attisdropped
			  AND NOT EXISTS (SELECT 1 FROM pg_depend od
			      WHERE od.classid = 'pg_class'::regclass AND od.refclassid = 'pg_class'::regclass
			        AND od.refobjid = a.attrelid AND od.refobjsubid = a.attnum AND od.deptype = 'i')
			ORDER BY c.relname, a.attname`, schema)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][]rootIdentityRow{}
		for rows.Next() {
			var tbl string
			var r rootIdentityRow
			if err := rows.Scan(&tbl, &r.col, &r.srcSchema, &r.srcName,
				&r.start, &r.inc, &r.minv, &r.maxv, &r.cache, &r.cycle); err != nil {
				return nil, err
			}
			out[tbl] = append(out[tbl], r)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string][]rootIdentityRow), nil
}

// dumpSequences emits sequence DDL and exact value sync in one unified pass
// over every sequence in the schema, then materializes replacements for the
// sequences a scoped export references but does not emit.
func (o *objectDump) dumpSequences(ctx context.Context, db *sql.DB) error {
	d, schema, inTables := o.d, o.schema, o.inTables
	dbScope, structure, plan := o.dbScope, o.structure, &o.plan

	// Sequence DDL + exact value sync, one unified pass over every sequence in
	// the schema. A LEFT JOIN to pg_depend (deptype 'a' = serial-style column
	// DEFAULT, 'i' = identity column) classifies each sequence; standalone
	// sequences match no dependency. Extension-owned sequences are excluded —
	// the owning extension recreates them. The CREATE-SEQUENCE strings land in
	// plan.Sequences (emitted only when structure is dumped); setval and the
	// OWNED BY linkage are post-data. last_value / is_called for setval come
	// from the sequence relation itself (pg_sequence holds only the definition).
	// This block stays outside the dbScope/structure gates above so serial and
	// identity sequences sync at table scope too; only the standalone bucket is
	// gated on dbScope. The serial/identity buckets gate on inTables, which
	// expandGateSet widens with the schema's partition children for ANY
	// database-scope dump — that widening is what gets a child-owned sequence
	// its setval in a data-only dump, where nothing else consults the set.
	var seqRows []seqRow
	srows, err := db.QueryContext(ctx, `
		SELECT sn.nspname, s.relname,
		       pg_catalog.format_type(ps.seqtypid, NULL),
		       ps.seqstart, ps.seqincrement, ps.seqmin, ps.seqmax, ps.seqcache, ps.seqcycle,
		       s.relpersistence, COALESCE(obj_description(s.oid, 'pg_class'), ''),
		       COALESCE(dep.deptype, ''),
		       COALESCE(tn.nspname, ''), COALESCE(t.relname, ''), COALESCE(a.attname, ''),
		       COALESCE(t.relpersistence::text, '')
		FROM pg_class s
		JOIN pg_namespace sn ON sn.oid = s.relnamespace
		JOIN pg_sequence ps ON ps.seqrelid = s.oid
		LEFT JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass
		  AND dep.objid = s.oid AND dep.refclassid = 'pg_class'::regclass
		  AND dep.deptype IN ('a','i')
		LEFT JOIN pg_class t ON t.oid = dep.refobjid
		LEFT JOIN pg_namespace tn ON tn.oid = t.relnamespace
		LEFT JOIN pg_attribute a ON a.attrelid = dep.refobjid AND a.attnum = dep.refobjsubid
		WHERE s.relkind = 'S' AND sn.nspname = $1
		  AND NOT EXISTS (SELECT 1 FROM pg_depend ed
		      WHERE ed.classid = 'pg_class'::regclass AND ed.objid = s.oid AND ed.deptype = 'e')
		ORDER BY s.relname`, schema)
	if err != nil {
		return err
	}
	for srows.Next() {
		var r seqRow
		if err := srows.Scan(&r.schema, &r.name, &r.typ,
			&r.start, &r.inc, &r.minv, &r.maxv, &r.cache, &r.cycle,
			&r.persistence, &r.comment,
			&r.deptype, &r.tblSchema, &r.tblName, &r.colName,
			&r.tblPersistence); err != nil {
			srows.Close()
			return err
		}
		seqRows = append(seqRows, r)
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return err
	}

	createSeq := d.seqCreateScript
	// G3: a sequence's comment (structure) rides post-data as its own Kind so a
	// data-only dump drops it — the sequence exists by then (serial/standalone in
	// plan.Sequences, identity via its SEQUENCE NAME). Targets the original name.
	appendSeqComment := func(r seqRow, seqIdent string) {
		if r.comment == "" || !structure {
			return
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "sequence-comment",
			Comment: "Comment for sequence " + r.name,
			SQL:     "COMMENT ON SEQUENCE " + seqIdent + " IS " + d.QuoteString(r.comment),
		})
	}
	appendSetval := func(name, seqIdent string) error {
		s, err := d.seqSetvalScript(ctx, db, name, seqIdent, seqIdent)
		if err != nil {
			return err
		}
		plan.PostData = append(plan.PostData, s)
		return nil
	}

	// Which sequences THIS dump guarantees to exist after restore — the
	// external-reference collector below replaces every reference to a
	// sequence outside this set.
	//
	// KNOWN RESIDUAL: the owner tests below match inTables on the BARE owner
	// name and ignore r.tblSchema, because inTables holds one schema's
	// relations while a sequence's owner may live in another. A same-named
	// table in a different schema therefore reads as "the owner is exported"
	// (over-emitting the sequence), and a cross-schema owner with no
	// same-named local table reads as "not exported" — which does not break a
	// restore, since the external-reference collector then supplies a
	// replacement sequence, but does cost the original's identity. Fixing it
	// properly needs the whole export's table set across schemas, not this
	// per-schema one; deliberately not folded into the gate-set change.
	emittedSeq := map[string]bool{}
	for _, r := range seqRows {
		seqIdent := d.QuoteIdent(r.schema) + "." + d.QuoteIdent(r.name)
		switch r.deptype {
		case "i":
			// Identity: the IDENTITY column (DumpTableCreate) creates the sequence;
			// only sync its value, and only when the owning table is dumped.
			if !inTables[r.tblName] {
				continue
			}
			emittedSeq[driver.SeqRefKey(r.schema, r.name)] = true
			if err := appendSetval(r.name, seqIdent); err != nil {
				return err
			}
			appendSeqComment(r, seqIdent)
			// An identity sequence's persistence can diverge from its
			// table's (PG15+ ALTER SEQUENCE … SET UNLOGGED on a LOGGED table's
			// identity, or SET LOGGED under an UNLOGGED table). The recreated
			// identity always inherits the TABLE's persistence, so a differing
			// source state needs the explicit post-data ALTER or it is lost.
			if structure && d.major >= 15 && r.tblPersistence != "" && r.persistence != r.tblPersistence {
				verb := "SET LOGGED"
				if r.persistence == "u" {
					verb = "SET UNLOGGED"
				}
				plan.PostData = append(plan.PostData, driver.DumpScript{
					Kind:    "sequence-persistence",
					Comment: "Persistence of identity sequence " + r.name,
					SQL:     "ALTER SEQUENCE " + seqIdent + " " + verb,
				})
			}
		case "a":
			// Serial-style: a column DEFAULT nextval(...) references it, but the
			// dump emits no CREATE SEQUENCE for it otherwise — restoring into an
			// empty database fails at CREATE TABLE. Emit it (with the OWNED BY
			// linkage that restores auto-drop), value-synced, whenever the owning
			// table is in scope (table or db scope).
			if !inTables[r.tblName] {
				continue
			}
			emittedSeq[driver.SeqRefKey(r.schema, r.name)] = true
			plan.Sequences = append(plan.Sequences, createSeq(r, seqIdent))
			// The OWNED BY linkage is structure; a data-only dump discards it
			// (the writer keeps only sequence/refresh items in PostData).
			if structure {
				ownerIdent := d.QuoteIdent(r.tblSchema) + "." + d.QuoteIdent(r.tblName)
				plan.PostData = append(plan.PostData, driver.DumpScript{
					Kind:    "sequence-own",
					Comment: "Sequence " + r.name + " owned by " + r.tblName + "." + r.colName,
					SQL:     "ALTER SEQUENCE " + seqIdent + " OWNED BY " + ownerIdent + "." + d.QuoteIdent(r.colName),
				})
			}
			if err := appendSetval(r.name, seqIdent); err != nil {
				return err
			}
			appendSeqComment(r, seqIdent)
		default:
			// Standalone (no column dependency): a database-scope dump recreates it
			// and — matching pg_dump, whose data section carries a sequence's value
			// — syncs its counter even in a data-only dump.
			if !dbScope {
				continue
			}
			emittedSeq[driver.SeqRefKey(r.schema, r.name)] = true
			plan.Sequences = append(plan.Sequences, createSeq(r, seqIdent))
			if err := appendSetval(r.name, seqIdent); err != nil {
				return err
			}
			appendSeqComment(r, seqIdent)
		}
	}

	// A scoped (non-database) export can reference sequences it does
	// not emit — an inherited serial default, a default naming a standalone or
	// cross-schema sequence, a standalone partition child's root identity.
	// Materialize replacements (structure) or target the originals (data-only).
	// A database-scope export emits every sequence, so nothing is external.
	if !dbScope {
		if err := d.collectExternalSequences(ctx, db, schema, inTables, structure, emittedSeq, plan); err != nil {
			return err
		}
	}
	return nil
}
