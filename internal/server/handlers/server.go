package handlers

import (
	"net/http"

	"github.com/tablexdev/tablex/internal/model"
)

// dbRow decorates a database with its action links for the server databases list.
type dbRow struct {
	model.Database
	StructureURL string
	// OpsURL is the database Operations page. Renaming a DATABASE is not
	// offered (no engine here supports it without a full dump/restore, which is
	// not what an "operations" button should do); TABLE rename does live on the
	// table-level operations page.
	OpsURL string
}

type serverDatabasesBody struct {
	Databases   []dbRow
	TotalSize   int64
	HasSize     bool
	HasSchemas  bool
	CanManageDB bool             // engine supports CREATE DATABASE (show the create control)
	Collations  []collationGroup // create-DB collation options, grouped by charset
}

// ServerDatabases renders the server-level database list (GET /server).
func (h *Handlers) ServerDatabases(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	dbs, err := uc.ServerConn().ListDatabases(r.Context())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	dbs = h.allowedDatabases(dbs)
	body := serverDatabasesBody{
		HasSchemas:  uc.Capabilities().HasSchemas,
		CanManageDB: uc.Capabilities().CanManageDatabases && h.allowance().DDL,
	}
	if body.CanManageDB && uc.Capabilities().SupportsCharset {
		body.Collations = h.collationOptions(r.Context(), uc)
	}
	for _, d := range dbs {
		body.Databases = append(body.Databases, dbRow{
			Database:     d,
			StructureURL: urlDB(d.Name, "", "structure"),
			OpsURL:       urlDB(d.Name, "", "operations"),
		})
		if d.Size > 0 {
			body.TotalSize += d.Size
			body.HasSize = true
		}
	}
	p := h.newLoggedPage(r, uc, "Databases")
	p.Breadcrumb = h.buildBreadcrumb(uc, reqScope{})
	p.Tabs = h.serverTabsCaps(uc, "databases")
	p.Body = body
	h.render(w, r, "server_databases", p)
}

// ServerDatabasesManage handles the server-scoped Create-database control on the
// databases list (POST /server).
func (h *Handlers) ServerDatabasesManage(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	if r.PostFormValue("action") != "create_db" {
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
		return
	}
	h.createDatabase(w, r, uc)
}
