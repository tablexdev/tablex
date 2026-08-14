package server

import (
	"net/http"

	"github.com/tablexdev/tablex/internal/server/handlers"
)

// routes registers a route in two places at once: the handler on the mux that
// actually serves, and what the route NEEDS on a parallel mux used only to
// resolve a request back to its pattern.
//
// One call site per route is the whole point. The restricted-mode policy used to
// be inferred from the last path segment, which cannot tell a route verb from a
// {db} or {table} value the user chose — a database named "sql" was refused as
// if it were the console, and a POST that runs an arbitrary stored-program body
// was classified as ordinary DDL. Declaring the need where the route is
// registered removes the guess, and keeping both registrations in one method
// means there is no second list to drift.
type routes struct {
	mux    *http.ServeMux
	policy *http.ServeMux
}

// HandleFunc registers one route and its policy.
//
// The method NAME and the pattern's position as the first argument are both
// load-bearing: routebody_test.go recovers the body-capped route set by scanning
// this file's source for that exact call shape, and cross-checks its count
// against a plain substring count of the method-and-space prefix. A route
// registered in any other shape fails that test rather than silently escaping
// the scan — which is also why nothing else in this file may spell that prefix,
// comments included.
func (rt routes) HandleFunc(pattern string, nd need, h http.HandlerFunc) {
	rt.mux.HandleFunc(pattern, h)
	rt.policy.Handle(pattern, policyEntry{need: nd})
}

// Handle is the http.Handler form, for the one route whose handler is a value
// rather than a function.
func (rt routes) Handle(pattern string, nd need, h http.Handler) {
	rt.mux.Handle(pattern, h)
	rt.policy.Handle(pattern, policyEntry{need: nd})
}

// policyEntry is what the policy mux stores. It is never served — the policy mux
// exists so ServeMux itself can answer "which pattern does this request match",
// which a middleware cannot ask any other way: ServeMux stamps r.Pattern inside
// its own ServeHTTP, after every middleware has already run.
type policyEntry struct{ need need }

func (policyEntry) ServeHTTP(http.ResponseWriter, *http.Request) {}

// router builds the route table. Go 1.22+ ServeMux patterns give method + path
// matching (with {db}/{table} path values) without an external router.
//
// Every route carries its restricted-mode need. Reading the table: a GET is
// almost always need{} because reading a structure page does not change it; the
// exceptions are the routes that RUN the user's own SQL, where the page is
// gated too — a console that refuses to run anything is a worse answer than no
// console. write is anything that changes state; ddl is schema and
// access-control work, which row edits deliberately are not.
func (s *Server) router() http.Handler {
	mux := http.NewServeMux()
	s.policy = http.NewServeMux()
	rt := routes{mux: mux, policy: s.policy}
	h := s.handlers

	// Infrastructure. These short-circuit in isPublicPath before the policy is
	// consulted; they carry need{} so the table stays a complete census of the
	// route set rather than a subset someone has to reason about.
	rt.HandleFunc("GET /healthz", need{}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	// Registered whether or not [metrics] is enabled; the handler answers 404 when
	// it is not, so the flag is honoured in exactly one place.
	rt.HandleFunc("GET "+metricsPath, need{}, s.metricsHandler)
	rt.HandleFunc("GET /favicon.ico", need{}, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/img/favicon.svg", http.StatusMovedPermanently)
	})
	rt.Handle("GET /static/", need{}, s.staticH)

	// Auth.
	rt.HandleFunc("GET /login", need{}, h.LoginForm)
	rt.HandleFunc("POST /login", need{}, h.Login)
	rt.HandleFunc("POST /logout", need{}, h.Logout)

	// The SSO gate. GET on both, because a provider completes the flow by
	// redirecting the browser and a redirect cannot be a POST. They 404 when no
	// provider is configured, so an unconfigured deployment does not advertise a
	// feature it does not have.
	rt.HandleFunc("GET "+handlers.SSOStartPath, need{}, h.SSOStart)
	rt.HandleFunc("GET "+handlers.SSOCallbackPath, need{}, h.SSOCallback)

	// Home / server level.
	rt.HandleFunc("GET /{$}", need{}, h.Home)
	rt.HandleFunc("GET /server", need{}, h.ServerDatabases)
	rt.HandleFunc("POST /server", need{write: true, ddl: true}, h.ServerDatabasesManage)
	rt.HandleFunc("GET /server/sql", need{console: true}, h.ServerSQL)
	rt.HandleFunc("POST /server/sql", need{write: true, console: true}, h.ServerSQL)
	rt.HandleFunc("GET /server/status", need{}, h.ServerStatus)
	rt.HandleFunc("GET /server/variables", need{}, h.ServerVariables)
	rt.HandleFunc("GET /server/processes", need{}, h.ServerProcesses)
	// Killing a session is administrative rather than schema work, but it is the
	// same class of power, so it rides allow_ddl.
	rt.HandleFunc("POST /server/processes", need{write: true, ddl: true}, h.ServerProcessesManage)
	rt.HandleFunc("GET /server/users", need{}, h.ServerUsers)
	rt.HandleFunc("POST /server/users", need{write: true, ddl: true}, h.ServerUsersManage)
	// An export is a read that happens to be a POST (the form carries options),
	// so it needs nothing beyond the allowlist narrowing its object list.
	rt.HandleFunc("GET /server/export", need{}, h.ServerExport)
	rt.HandleFunc("POST /server/export", need{}, h.ServerExport)
	rt.HandleFunc("GET /server/import", need{console: true}, h.ServerImport)
	rt.HandleFunc("POST /server/import", need{write: true, console: true}, h.ServerImport)

	// Navigation fragments (htmx). The database arrives as a QUERY parameter, so
	// the allowlist for these is checked in the handler — see NavChildren.
	rt.HandleFunc("GET /nav", need{}, h.NavTree)
	rt.HandleFunc("GET /nav/children", need{}, h.NavChildren)

	// Database level.
	rt.HandleFunc("GET /db/{db}", need{}, h.DBStructure)
	rt.HandleFunc("GET /db/{db}/sql", need{console: true}, h.DBSQL)
	rt.HandleFunc("POST /db/{db}/sql", need{write: true, console: true}, h.DBSQL)
	rt.HandleFunc("GET /db/{db}/search", need{}, h.DBSearch)
	rt.HandleFunc("POST /db/{db}/search", need{}, h.DBSearch)
	rt.HandleFunc("GET /db/{db}/qbe", need{}, h.DBQBE)
	rt.HandleFunc("POST /db/{db}/qbe", need{}, h.DBQBE)
	rt.HandleFunc("GET /db/{db}/designer", need{}, h.DBDesigner)
	rt.HandleFunc("GET /db/{db}/export", need{}, h.DBExport)
	rt.HandleFunc("POST /db/{db}/export", need{}, h.DBExport)
	rt.HandleFunc("GET /db/{db}/import", need{console: true}, h.DBImport)
	rt.HandleFunc("POST /db/{db}/import", need{write: true, console: true}, h.DBImport)
	rt.HandleFunc("GET /db/{db}/create-table", need{}, h.DBCreateTable)
	rt.HandleFunc("POST /db/{db}/create-table", need{write: true, ddl: true}, h.DBCreateTable)
	rt.HandleFunc("GET /db/{db}/operations", need{}, h.DBOperations)
	rt.HandleFunc("POST /db/{db}/operations", need{write: true, ddl: true}, h.DBOperations)
	rt.HandleFunc("GET /db/{db}/privileges", need{}, h.DBPrivileges)
	rt.HandleFunc("POST /db/{db}/privileges", need{write: true, ddl: true}, h.DBPrivilegesManage)
	// The stored-program routes carry TWO actions on one endpoint: save, whose
	// body is unconstrained SQL, and drop, which is ordinary DDL. A route cannot
	// tell them apart, so the need here is the DDL one and saveProgram takes the
	// console check itself — one of the two such checks living outside this table.
	rt.HandleFunc("GET /db/{db}/routines", need{}, h.DBRoutines)
	rt.HandleFunc("POST /db/{db}/routines", need{write: true, ddl: true}, h.DBRoutinesManage)
	rt.HandleFunc("GET /db/{db}/routines/edit", need{}, h.RoutineEditor)
	rt.HandleFunc("GET /db/{db}/routines/privileges", need{}, h.RoutinePrivileges)
	rt.HandleFunc("POST /db/{db}/routines/privileges", need{write: true, ddl: true}, h.RoutinePrivilegesManage)
	rt.HandleFunc("GET /db/{db}/events", need{}, h.DBEvents)
	rt.HandleFunc("POST /db/{db}/events", need{write: true, ddl: true}, h.DBEventsManage)
	rt.HandleFunc("GET /db/{db}/events/edit", need{}, h.EventEditor)
	rt.HandleFunc("GET /db/{db}/triggers", need{}, h.DBTriggers)
	rt.HandleFunc("POST /db/{db}/triggers", need{write: true, ddl: true}, h.DBTriggersManage)
	rt.HandleFunc("GET /db/{db}/triggers/edit", need{}, h.TriggerEditor)
	// One fragment endpoint for every object kind's lazy definition panel.
	rt.HandleFunc("GET /db/{db}/definition", need{}, h.ObjectDefinition)

	// Table level.
	rt.HandleFunc("GET /db/{db}/table/{table}", need{}, h.TableBrowse)
	rt.HandleFunc("GET /db/{db}/table/{table}/structure", need{}, h.TableStructure)
	rt.HandleFunc("POST /db/{db}/table/{table}/structure", need{write: true, ddl: true}, h.TableStructure)
	rt.HandleFunc("GET /db/{db}/table/{table}/sql", need{console: true}, h.TableSQL)
	rt.HandleFunc("POST /db/{db}/table/{table}/sql", need{write: true, console: true}, h.TableSQL)
	rt.HandleFunc("GET /db/{db}/table/{table}/search", need{}, h.TableSearch)
	rt.HandleFunc("POST /db/{db}/table/{table}/search", need{}, h.TableSearch)
	// Row edits are writes but NOT ddl: "let them fix the data, not reshape it"
	// is the distinction allow_ddl exists for.
	rt.HandleFunc("GET /db/{db}/table/{table}/insert", need{}, h.TableInsertForm)
	rt.HandleFunc("POST /db/{db}/table/{table}/insert", need{write: true}, h.TableInsert)
	rt.HandleFunc("GET /db/{db}/table/{table}/edit", need{}, h.TableEditForm)
	rt.HandleFunc("POST /db/{db}/table/{table}/edit", need{write: true}, h.TableEdit)
	rt.HandleFunc("POST /db/{db}/table/{table}/delete", need{write: true}, h.TableDelete)
	rt.HandleFunc("POST /db/{db}/table/{table}/rows", need{write: true}, h.TableBulkRows)
	rt.HandleFunc("POST /db/{db}/table/{table}/rows/apply", need{write: true}, h.TableBulkApply)
	rt.HandleFunc("GET /db/{db}/table/{table}/export", need{}, h.TableExport)
	rt.HandleFunc("POST /db/{db}/table/{table}/export", need{}, h.TableExport)
	rt.HandleFunc("GET /db/{db}/table/{table}/import", need{console: true}, h.TableImport)
	rt.HandleFunc("POST /db/{db}/table/{table}/import", need{write: true, console: true}, h.TableImport)
	rt.HandleFunc("GET /db/{db}/table/{table}/operations", need{}, h.TableOperations)
	rt.HandleFunc("POST /db/{db}/table/{table}/operations", need{write: true, ddl: true}, h.TableOperations)
	rt.HandleFunc("GET /db/{db}/table/{table}/triggers", need{}, h.TableTriggers)
	rt.HandleFunc("POST /db/{db}/table/{table}/triggers", need{write: true, ddl: true}, h.TableTriggersManage)
	rt.HandleFunc("GET /db/{db}/table/{table}/triggers/edit", need{}, h.TriggerEditor)
	rt.HandleFunc("GET /db/{db}/table/{table}/privileges", need{}, h.TablePrivileges)
	rt.HandleFunc("POST /db/{db}/table/{table}/privileges", need{write: true, ddl: true}, h.TablePrivilegesManage)

	return mux
}
