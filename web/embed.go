// Package web embeds TableX's templates and static assets into the binary, so
// the compiled program is fully self-contained (no external files at runtime).
package web

import "embed"

// FS holds the HTML templates (templates/) and static assets (static/: css, js,
// img, and vendored Bootstrap/htmx/Alpine/CodeMirror). The all: prefix ensures
// files beginning with "_" or "." are included too.
//
//go:embed all:templates all:static
var FS embed.FS
