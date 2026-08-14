// Package view owns TableX's rendering layer: it parses the embedded
// html/template set once at startup, exposes a shared func map (icons,
// humanizers, small helpers), and renders either a full page or — for htmx
// requests — a fragment that swaps #page_content plus out-of-band chrome.
package view

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
)

// WriteTimeout bounds a single response write: the buffered page write below,
// and each export chunk (the handlers' deadlineWriter references it). The
// server deliberately sets no global http.Server WriteTimeout — exports stream
// for longer than any fixed cap — so every write path bounds itself and clears
// the deadline afterwards, keeping the keep-alive connection clean for the
// next request. SetWriteDeadline is best-effort: an unsupported writer (tests'
// ResponseRecorder) degrades to an unbounded write.
const WriteTimeout = 60 * time.Second

// Renderer holds the parsed per-page template sets.
type Renderer struct {
	pages    map[string]*template.Template
	assetVer string
}

// AssetVersion is the fingerprint templates stamp onto /static/ URLs. The server
// reads it to decide which requests may be cached forever.
func (r *Renderer) AssetVersion() string { return r.assetVer }

// assetVersion fingerprints every embedded static asset, once, at startup.
//
// The assets are versioned by the binary but their URLs are not, so a client had
// to revalidate each of them once an hour — a dozen conditional GETs per hour per
// client for bytes that cannot change without a new build. Stamping the
// fingerprint on the URL makes a new build a new URL, which is what lets the
// response be marked immutable.
//
// One fingerprint for the whole tree rather than one per file: a build changes
// the binary, and re-fetching all of it on upgrade is the honest cost of the
// single-binary design. WalkDir is lexical, so the value is deterministic.
func assetVersion(fsys fs.FS) string {
	h := sha256.New()
	_ = fs.WalkDir(fsys, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return nil
		}
		h.Write([]byte(p))
		h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)[:6])
}

// New parses all templates from fsys (the embedded web FS) and loads icons.
func New(fsys fs.FS) (*Renderer, error) {
	icons, err := loadIcons(fsys)
	if err != nil {
		return nil, fmt.Errorf("loading icons: %w", err)
	}
	version := assetVersion(fsys)
	funcs := buildFuncMap(icons, version)

	// Base set: all layout partials (base, fragment, sidebar, breadcrumb, …).
	base := template.New("tablex").Funcs(funcs)
	base, err = base.ParseFS(fsys, "templates/layout/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing layout templates: %w", err)
	}

	pageFiles, err := fs.Glob(fsys, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	if len(pageFiles) == 0 {
		return nil, fmt.Errorf("no page templates found")
	}
	pages := make(map[string]*template.Template, len(pageFiles))
	for _, pf := range pageFiles {
		name := strings.TrimSuffix(path.Base(pf), ".html")
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := clone.ParseFS(fsys, pf); err != nil {
			return nil, fmt.Errorf("parsing page %s: %w", name, err)
		}
		pages[name] = clone
	}
	return &Renderer{pages: pages, assetVer: version}, nil
}

// Render writes a page. For htmx requests it renders the "fragment" entry
// (content + OOB breadcrumb/tabs/title); otherwise the full "base" shell.
// Output is buffered so a render error never emits half a page.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, page string, data *Page) error {
	t, ok := r.pages[page]
	if !ok {
		return fmt.Errorf("view: unknown page %q", page)
	}
	entry := "base"
	if IsHTMX(req) {
		entry = "fragment"
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, entry, data); err != nil {
		return fmt.Errorf("view: rendering %q: %w", page, err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return writeBounded(w, &buf)
}

// RenderNamed renders a specific named template within a page set (used for
// standalone fragments like nav-tree children). Output is buffered.
func (r *Renderer) RenderNamed(w http.ResponseWriter, page, tmpl string, data any) error {
	t, ok := r.pages[page]
	if !ok {
		return fmt.Errorf("view: unknown page %q", page)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, tmpl, data); err != nil {
		return fmt.Errorf("view: rendering %q/%q: %w", page, tmpl, err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return writeBounded(w, &buf)
}

// WriteError marks a failure that happened while WRITING an already-rendered
// page to the client: the template succeeded and the body was fully buffered —
// only the network write failed, typically because the client went away
// mid-download. Callers must not re-stamp such a response as a 500 template
// failure: the header (and part of the body) is already on the wire, so an
// http.Error would falsify the access line, the 5xx metric and the audit
// status, and net/http would log a superfluous WriteHeader. IsWriteError is
// the one classification every render caller shares.
type WriteError struct{ Err error }

func (e *WriteError) Error() string { return "view: writing the rendered page: " + e.Err.Error() }
func (e *WriteError) Unwrap() error { return e.Err }

// IsWriteError reports whether err is (or wraps) a client-side WriteError.
func IsWriteError(err error) bool {
	var we *WriteError
	return errors.As(err, &we)
}

// writeBounded flushes a fully buffered page to the client under WriteTimeout,
// then clears the deadline so it cannot linger on the keep-alive connection
// and cut off an unrelated later response. The middleware's statusRecorder
// implements Unwrap specifically so ResponseController reaches the real
// connection here. A failure here is typed as a WriteError: the page was
// already rendered, so the caller must treat it as a client-side abort, not a
// template failure.
func writeBounded(w http.ResponseWriter, buf *bytes.Buffer) error {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	_, err := buf.WriteTo(w)
	_ = rc.SetWriteDeadline(time.Time{})
	if err != nil {
		return &WriteError{Err: err}
	}
	return nil
}

// IsHTMX reports whether the request is an htmx-driven partial swap.
func IsHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// buildFuncMap assembles the template helper functions.
func buildFuncMap(icons *iconSet, assetVer string) template.FuncMap {
	return template.FuncMap{
		"assetV":     func() string { return assetVer },
		"icon":       icons.Icon,
		"humanBytes": HumanBytes,
		"humanInt":   HumanInt,
		"list":       list,
		"dict":       dict,
		"add":        add,
		"default":    def,
		"lower":      lower,
		"yesno":      yesno,
		"truncate":   truncate,
		"fmtTime":    fmtTime,
		"hasCap":     hasCapability,
		"deref":      deref,
		"join":       strings.Join,
		"contains":   strings.Contains,
		"hasPrefix":  strings.HasPrefix,
		"urlHome":    func() string { return "/" },
		"urlServer":  urlServerTmpl,
	}
}

// urlServerTmpl builds a server-level URL for templates (mirrors the handlers'
// urlServer without importing that package).
func urlServerTmpl(tab string) string {
	if tab == "" || tab == "databases" {
		return "/server"
	}
	return "/server/" + tab
}

// hasCapability lets templates gate UI on a capability flag by name, so tabs
// appear only where the engine supports them (e.g. {{ if hasCap .Caps "Events" }}).
func hasCapability(c driver.Capabilities, name string) bool {
	switch name {
	case "Schemas":
		return c.HasSchemas
	case "Users":
		return c.HasUsers
	case "ForeignKeys":
		return c.HasForeignKeys
	case "Routines":
		return c.HasStoredRoutines
	case "Triggers":
		return c.HasTriggers
	case "Events":
		return c.HasEvents
	case "Explain":
		return c.SupportsExplain
	}
	return false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
