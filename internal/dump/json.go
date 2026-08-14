package dump

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tablexdev/tablex/internal/driver"
)

// WriteJSON streams tables as a JSON object. Schema-less engines emit a flat
// { "table": [ {col: value}, ... ] }; schema-having engines nest by schema —
// { "schema": { "table": [ ... ] } } — so same-named tables in different schemas
// never collide.
func WriteJSON(ctx context.Context, w io.Writer, conn *driver.Connection, groups []SchemaGroup, nested bool, filter *RowFilter, rng *RowRange) {
	fmt.Fprint(w, "{\n")
	var streamErrs []string
	// Nesting emits ONE object per schema, so each schema must reach the loop
	// below exactly once. Enforce that here rather than assuming it of the
	// caller: two consecutive groups of the same schema would drop the comma
	// between their tables, and two NON-contiguous ones would emit the schema
	// as a duplicate top-level key — well-formed JSON that every decoder
	// silently resolves to the last, so the earlier group's tables would just
	// vanish. This is a streaming writer, so neither is recoverable later:
	// closeSchema puts the closing brace on the wire.
	if nested {
		groups = coalesceBySchema(groups)
	}
	first := true
	curSchema := ""
	inSchema := false
	firstTableInSchema := true
	closeSchema := func() {
		if inSchema {
			fmt.Fprint(w, "\n  }")
			inSchema = false
		}
	}
	tablePrefix := "  "
	if nested {
		tablePrefix = "    "
	}
	for _, g := range groups {
		if nested && (!inSchema || g.Schema != curSchema) {
			closeSchema()
			if !first {
				fmt.Fprint(w, ",\n")
			}
			first = false
			sk, _ := json.Marshal(g.Schema)
			fmt.Fprintf(w, "  %s: {\n", sk)
			inSchema, curSchema = true, g.Schema
			// Reset with the object, not with the group: the separator state
			// belongs to the schema OBJECT being written, and a group is no
			// longer guaranteed to be one of those.
			firstTableInSchema = true
		}
		for _, t := range g.Tables {
			if nested {
				if !firstTableInSchema {
					fmt.Fprint(w, ",\n")
				}
				firstTableInSchema = false
			} else {
				if !first {
					fmt.Fprint(w, ",\n")
				}
				first = false
			}
			key, _ := json.Marshal(t.Table)
			fmt.Fprintf(w, "%s%s: [\n", tablePrefix, key)
			streamErrs = appendJSONTable(ctx, w, conn, t, tablePrefix, filter, rng, streamErrs)
			fmt.Fprintf(w, "\n%s]", tablePrefix)
		}
	}
	closeSchema()
	// Surface any stream failures as a top-level sibling key (never inside a row
	// array) so a truncated dump stays valid JSON and no failure is silent.
	if len(streamErrs) > 0 {
		msg, _ := json.Marshal(streamErrs)
		fmt.Fprintf(w, ",\n  \"__error__\": %s", msg)
	}
	fmt.Fprint(w, "\n}\n")
}

// coalesceBySchema merges every group naming the same schema into one, keeping
// first-appearance order for the schemas and input order for the tables within
// each. Groups with no tables still claim their position, so an empty schema
// object is emitted exactly where the caller asked for it.
func coalesceBySchema(groups []SchemaGroup) []SchemaGroup {
	order := make([]string, 0, len(groups))
	merged := make(map[string][]driver.TableRef, len(groups))
	for _, g := range groups {
		if _, seen := merged[g.Schema]; !seen {
			order = append(order, g.Schema)
		}
		merged[g.Schema] = append(merged[g.Schema], g.Tables...)
	}
	out := make([]SchemaGroup, 0, len(order))
	for _, s := range order {
		out = append(out, SchemaGroup{Schema: s, Tables: merged[s]})
	}
	return out
}

// appendJSONTable streams one table's rows as a JSON array body (without the
// surrounding brackets, which the caller writes), returning streamErrs extended
// with a "schema.table: err" entry on failure.
//
// Under a row filter that targets ANOTHER table the array stays empty rather
// than holding that table's full contents — the same "never widen a selection"
// rule the SQL and CSV writers follow.
func appendJSONTable(ctx context.Context, w io.Writer, conn *driver.Connection, t driver.TableRef, indent string, filter *RowFilter, rng *RowRange, streamErrs []string) []string {
	where, args, allowed := filter.clauseFor(t)
	if !allowed {
		return streamErrs
	}
	first := true
	rowIndent := indent + "  "
	// A DynamicTyper engine (SQLite) types each VALUE, so the runtime kind
	// decides number-vs-string; everywhere else the declared column type does.
	// The same pair of decisions — kind preference plus the shared
	// driver.IsNumericLiteral gate — drives the SQL dump's bare-vs-quoted
	// literals, so the two writers cannot drift apart.
	preferKind := driver.PrefersValueKind(conn.Dialect())
	err := conn.StreamArgs(ctx, "SELECT * FROM "+conn.QualifiedName(t)+where+rng.clauseFor(conn.Dialect()), args, func(cols []driver.ResultColumn, row []driver.Value) error {
		// The object is emitted manually, key by key, so the dump preserves the
		// table's column order — json.Marshal of a map would sort the keys
		// alphabetically, while the CSV and SQL exports keep column order.
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, c := range cols {
			var val any
			v := row[i]
			numeric := c.Numeric
			if preferKind {
				numeric = v.Numeric
			}
			switch {
			case v.Null:
				val = nil
			case v.Binary:
				val = hex.EncodeToString(v.Bytes)
			case numeric && driver.IsNumericLiteral(v.Str):
				// json.Number emits the literal unquoted, avoiding float64
				// precision loss on big integers and high-scale decimals.
				val = json.Number(v.Str)
			case isBooleanResultColumn(c) && (v.Str == "true" || v.Str == "false"):
				val = v.Str == "true"
			default:
				val = v.Str
			}
			key, err := json.Marshal(c.Name)
			if err != nil {
				return err
			}
			b, err := json.Marshal(val)
			if err != nil {
				return err
			}
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(key)
			buf.WriteByte(':')
			buf.Write(b)
		}
		buf.WriteByte('}')
		if !first {
			fmt.Fprint(w, ",\n")
		}
		first = false
		fmt.Fprintf(w, "%s%s", rowIndent, buf.Bytes())
		return nil
	})
	if err != nil {
		// Tag each failure with its (schema-qualified) table and keep going — a
		// later table's error must not be dropped just because an earlier one did.
		label := t.Table
		if t.Schema != "" {
			label = t.Schema + "." + t.Table
		}
		streamErrs = append(streamErrs, fmt.Sprintf("%s: %v", label, err))
	}
	return streamErrs
}
