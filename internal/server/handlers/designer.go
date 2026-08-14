package handlers

import (
	"net/http"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// designerTable is one table in the schema map: its columns plus its outgoing
// foreign keys.
type designerTable struct {
	Name       string
	Columns    []model.Column
	ForeignKey map[string]string // local column -> "refTable(refCol)" for badges
	StructURL  string
	Error      string // introspection failure for this table (columns/FKs)
}

// designerRel is one foreign-key relationship between two tables.
type designerRel struct {
	From     string
	FromCols string
	To       string
	ToCols   string
}

type designerBody struct {
	Scope         reqScope
	Tables        []designerTable
	Relationships []designerRel
	HasFKs        bool
	Skipped       bool // at least one table's columns/FKs could not be read
}

// DBDesigner renders a read-only schema/relations map of the database: a card
// per table (columns with primary-key and foreign-key markers) plus a summary of
// every foreign-key relationship, built from the neutral introspection model.
func (h *Handlers) DBDesigner(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	caps := uc.Capabilities()
	body := designerBody{Scope: sc, HasFKs: caps.HasForeignKeys}

	tables, err := h.tableNames(r.Context(), conn, sc.scope())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	// Bulk fast path (driver.BulkIntrospector): two schema-wide queries instead
	// of two per table. On a bulk failure the loop degrades to the per-table
	// calls, whose existing per-table error surfacing then reports the problem.
	bulkCols, haveCols, errCols := conn.BulkColumns(r.Context(), sc.scope())
	bulkFKs, haveFKs, errFKs := conn.BulkForeignKeys(r.Context(), sc.scope())
	useBulk := haveCols && haveFKs && errCols == nil && errFKs == nil
	for _, t := range tables {
		if t.IsView() || t.IsSequence() {
			continue
		}
		ref := driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: t.Name}
		dt := designerTable{
			Name:       t.Name,
			ForeignKey: map[string]string{},
			StructURL:  urlTable(sc.DB, sc.Schema, t.Name, "structure"),
		}
		var cols []model.Column
		var fks []model.ForeignKey
		var colsErr, fksErr error
		if useBulk {
			cols = bulkCols[t.Name]
			if caps.HasForeignKeys {
				fks = bulkFKs[t.Name]
			}
		} else {
			cols, colsErr = conn.Columns(r.Context(), ref)
			if caps.HasForeignKeys {
				fks, fksErr = conn.ForeignKeys(r.Context(), ref)
			}
		}
		if colsErr == nil {
			dt.Columns = cols
		} else {
			dt.Error = "columns unavailable: " + colsErr.Error()
			body.Skipped = true
		}
		if caps.HasForeignKeys {
			if fksErr == nil {
				for _, fk := range fks {
					// Same finding as the structure page's References column, and
					// the same predicate: a key into a database outside
					// restrict.database_allowlist discloses that database's table
					// and column names. Dropping the qualifier alone would not
					// close it — "orders(id)" is still metadata the operator was
					// refused — so the WHOLE relationship goes, badged rather than
					// deleted, because the column really is a foreign key and
					// hiding that would misdescribe the table.
					if h.fkRefHidden(caps, fk) {
						for _, c := range fk.Columns {
							dt.ForeignKey[c] = "(hidden)"
						}
						continue // no relationship line either: To would name it
					}
					// The reference is QUALIFIED when it leaves this database or
					// schema, which is the information the unqualified display
					// silently dropped. Same-scope keys stay unqualified.
					to := fk.RefTable
					if fk.RefSchema != "" && fk.RefSchema != sc.Schema && fk.RefSchema != sc.DB {
						to = fk.RefSchema + "." + fk.RefTable
					}
					body.Relationships = append(body.Relationships, designerRel{
						From:     t.Name,
						FromCols: strings.Join(fk.Columns, ", "),
						To:       to,
						ToCols:   strings.Join(fk.RefColumns, ", "),
					})
					target := to + "(" + strings.Join(fk.RefColumns, ", ") + ")"
					for _, c := range fk.Columns {
						dt.ForeignKey[c] = target
					}
				}
			} else {
				if dt.Error != "" {
					dt.Error += "; "
				}
				dt.Error += "foreign keys unavailable: " + fksErr.Error()
				body.Skipped = true
			}
		}
		body.Tables = append(body.Tables, dt)
	}

	p := h.newLoggedPage(r, uc, sc.DB+" · Designer")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "designer")
	p.Body = body
	h.render(w, r, "designer", p)
}
