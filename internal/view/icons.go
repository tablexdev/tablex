package view

import (
	"html/template"
	"io/fs"
	"strings"
)

// iconAlias maps TableX's semantic icon names (action/object vocabulary)
// to the vendored Bootstrap Icons file (without extension). Templates use
// {{ icon "edit" }} and never reference the underlying file, so the icon set can
// be swapped wholesale.
var iconAlias = map[string]string{
	"home":          "house-door",
	"server":        "hdd-network",
	"server-alt":    "hdd-stack",
	"database":      "database",
	"database-add":  "database-add",
	"database-ops":  "database-gear",
	"database-drop": "database-x",
	"schema":        "diagram-3",
	"table":         "table",
	"view":          "eye",
	"columns":       "list-columns",
	"structure":     "list-columns",
	"browse":        "card-list",
	"sql":           "terminal",
	"search":        "search",
	"insert":        "plus-square",
	"add":           "plus-lg",
	"new":           "plus-circle",
	"edit":          "pencil-square",
	"drop":          "trash",
	"delete":        "trash",
	"copy":          "copy",
	"export":        "download",
	"import":        "upload",
	"operations":    "gear",
	"settings":      "gear",
	"theme":         "circle-half",
	"privileges":    "people",
	"users":         "people",
	"key":           "key",
	"index":         "list-ol",
	"routines":      "gear-wide-connected",
	"triggers":      "lightning-charge",
	"events":        "clock",
	"logout":        "box-arrow-right",
	"reload":        "arrow-clockwise",
	"refresh":       "arrow-clockwise",
	"docs":          "book",
	"help":          "question-circle",
	"user":          "person-circle",
	"expand":        "caret-right-fill",
	"collapse":      "caret-down-fill",
	"chevron":       "chevron-right",
	"check":         "check-lg",
	"x":             "x-lg",
	"sort-up":       "sort-up",
	"sort-down":     "sort-down",
	"sort":          "sort-alpha-down",
	"fk":            "link-45deg",
	"link":          "link-45deg",
	"folder":        "folder2",
	"info":          "info-circle",
	"warning":       "exclamation-triangle",
	"success":       "check-circle",
	"error":         "x-circle",
	"empty":         "eraser",
	"filter":        "funnel",
	"funnel":        "funnel",
	"json":          "braces",
	"sql-file":      "filetype-sql",
	"csv":           "filetype-csv",
	"json-file":     "filetype-json",
	"sidebar":       "layout-sidebar",
	"collapse-all":  "arrows-collapse",
	"expand-all":    "arrows-expand",
}

// iconSet holds the inner SVG markup for each loaded icon file.
type iconSet struct {
	inner map[string]template.HTML
}

// loadIcons reads every static/img/icons/*.svg from the embedded FS, extracting
// the inner markup (paths) so it can be re-wrapped with consistent attributes.
func loadIcons(fsys fs.FS) (*iconSet, error) {
	set := &iconSet{inner: map[string]template.HTML{}}
	entries, err := fs.ReadDir(fsys, "static/img/icons")
	if err != nil {
		return set, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".svg") {
			continue
		}
		data, err := fs.ReadFile(fsys, "static/img/icons/"+e.Name())
		if err != nil {
			return set, err
		}
		name := strings.TrimSuffix(e.Name(), ".svg")
		set.inner[name] = template.HTML(extractSVGInner(string(data))) //nolint:gosec // vendored trusted assets
	}
	return set, nil
}

// extractSVGInner returns the markup between the outer <svg ...> and </svg>.
func extractSVGInner(s string) string {
	open := strings.IndexByte(s, '>')
	close := strings.LastIndex(s, "</svg>")
	if open < 0 || close < 0 || close <= open {
		return ""
	}
	return strings.TrimSpace(s[open+1 : close])
}

// Icon renders a named icon as an inline SVG. Unknown names render nothing
// (rather than breaking the page). The output is trusted, vendored markup.
func (s *iconSet) Icon(name string) template.HTML {
	file, ok := iconAlias[name]
	if !ok {
		file = name // allow direct file names too
	}
	inner, ok := s.inner[file]
	if !ok {
		return ""
	}
	return template.HTML(`<svg class="tx-icon icon-` + template.HTMLEscapeString(name) +
		`" width="1em" height="1em" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true" focusable="false">` +
		string(inner) + `</svg>`)
}
