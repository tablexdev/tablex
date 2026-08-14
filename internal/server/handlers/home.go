package handlers

import (
	"net/http"

	"github.com/tablexdev/tablex/internal/driver"
)

// homeBody backs the server landing page (server info cards
// plus the TableX app/about card).
type homeBody struct {
	Info          driver.ServerInfo
	DatabaseCount int
	AppVersion    string
	SupportEmail  string
	Website       string
}

// Home renders the server overview (GET /). Requires an authenticated session
// (enforced by the auth gate middleware).
func (h *Handlers) Home(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	p := h.newLoggedPage(r, uc, "Server: "+uc.ServerName)
	p.Breadcrumb = h.buildBreadcrumb(uc, reqScope{})
	p.Tabs = h.serverTabsCaps(uc, "databases")

	body := homeBody{
		Info:          uc.ServerConn().Info(),
		DatabaseCount: -1,
		AppVersion:    h.Version,
		SupportEmail:  "info@tablex.dev",
		Website:       "https://tablex.dev",
	}
	if dbs, err := h.databaseNames(r.Context(), uc); err == nil {
		body.DatabaseCount = len(dbs)
	} else {
		h.Log.Warn("home: list databases", "err", err, "reqid", RequestID(r.Context()))
	}
	p.Body = body
	h.render(w, r, "home", p)
}
