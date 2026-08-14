package web

// Contrast tests for the design tokens.
//
// Two contrast defects had the same cause: a rule hardcoded a colour, so
// the dark theme — which is a re-spec of token VALUES and nothing else — could
// not reach it. `.tx-card-header` kept `color: #000` while its background went
// dark, computing 1.83:1. Nothing caught it because there was no CSS test at
// all.
//
// So these tests read the stylesheet that actually ships (through the embedded
// FS, not the file on disk), resolve the token values for both themes, and
// assert the contrast of every foreground/background pair the stylesheet
// renders. TestNoRawColourOutsideTheTokenBlocks then forbids the mistake at its
// root: a colour a theme cannot override.
//
// Two modelling choices, both deliberate:
//
//   - A one-line surface painted with a gradient (a table row, a button, a tab)
//     is checked at the gradient's MIDPOINT, because that is where the text
//     sits. Checking an end stop would be a fiction in either direction.
//   - A gradient taller than its text (the sidebar, the login page) is checked
//     against BOTH stops, because text there really can sit at either end.
//
// Not asserted: the 3:1 non-text ratio for table and card borders. WCAG 1.4.11
// covers boundaries that identify a component or its state; TableX's cell rules
// are structural decoration, and raising them would mean abandoning the
// classic grid this project deliberately keeps. The focus ring — which IS
// state, and IS the affordance — is asserted at 3:1 below.

import (
	"fmt"
	"maps"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const cssPath = "static/css/tablex.css"

// ---------------------------------------------------------------- colour maths

// rgb holds sRGB channels in 0..1.
type rgb struct{ r, g, b float64 }

func parseHex(s string) (rgb, bool) {
	h := strings.TrimPrefix(strings.TrimSpace(s), "#")
	if len(h) == 3 { // #abc -> #aabbcc
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return rgb{}, false
	}
	n, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return rgb{}, false
	}
	return rgb{
		r: float64((n>>16)&0xff) / 255,
		g: float64((n>>8)&0xff) / 255,
		b: float64(n&0xff) / 255,
	}, true
}

// linearize converts one sRGB channel to linear light (WCAG 2.1 / IEC 61966-2-1).
func linearize(c float64) float64 {
	if c <= 0.04045 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func (c rgb) luminance() float64 {
	return 0.2126*linearize(c.r) + 0.7152*linearize(c.g) + 0.0722*linearize(c.b)
}

// contrast is the WCAG 2.1 contrast ratio, 1..21.
func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// mix is the 50/50 point of a two-stop gradient, in sRGB — the space browsers
// interpolate a plain linear-gradient() in.
func mix(a, b rgb) rgb {
	return rgb{r: (a.r + b.r) / 2, g: (a.g + b.g) / 2, b: (a.b + b.b) / 2}
}

// over alpha-composites fg onto bg. Used for Bootstrap's .table-striped and
// .table-hover, which tint the table background with an rgba() overlay rather
// than a colour of their own.
func over(fg, bg rgb, alpha float64) rgb {
	return rgb{
		r: fg.r*alpha + bg.r*(1-alpha),
		g: fg.g*alpha + bg.g*(1-alpha),
		b: fg.b*alpha + bg.b*(1-alpha),
	}
}

func (c rgb) String() string {
	return fmt.Sprintf("#%02x%02x%02x", int(c.r*255+0.5), int(c.g*255+0.5), int(c.b*255+0.5))
}

// ------------------------------------------------------------ token extraction

var (
	commentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	declRe    = regexp.MustCompile(`--([a-z0-9-]+)\s*:\s*([^;]+);`)
	varRefRe  = regexp.MustCompile(`^var\(\s*--([a-z0-9-]+)\s*\)$`)
	hexRe     = regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
)

func loadCSS(t *testing.T) string {
	t.Helper()
	b, err := FS.ReadFile(cssPath)
	if err != nil {
		t.Fatalf("read %s from the embedded FS: %v", cssPath, err)
	}
	return commentRe.ReplaceAllString(string(b), "")
}

// blockAfter returns the body of the brace-delimited block that follows header.
func blockAfter(t *testing.T, css, header string) string {
	t.Helper()
	_, rest, found := strings.Cut(css, header)
	if !found {
		t.Fatalf("%s: no %q block", cssPath, header)
	}
	depth, start := 0, -1
	for j, r := range rest {
		switch r {
		case '{':
			if depth == 0 {
				start = j + 1
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[start:j]
			}
		}
	}
	t.Fatalf("%s: %q block is not closed", cssPath, header)
	return ""
}

// palette is one theme's token values, plus the synthesized surfaces below.
type palette struct {
	name string
	raw  map[string]string
	dark bool
}

func themes(t *testing.T) (light, dark *palette) {
	t.Helper()
	css := loadCSS(t)

	read := func(header string) map[string]string {
		out := map[string]string{}
		for _, m := range declRe.FindAllStringSubmatch(blockAfter(t, css, header), -1) {
			out[m[1]] = strings.TrimSpace(m[2])
		}
		return out
	}
	base := read(":root")
	if len(base) < 40 {
		t.Fatalf("%s: only %d tokens found in :root — the parser is broken", cssPath, len(base))
	}

	darkOverrides := read(`[data-bs-theme="dark"]`)
	if len(darkOverrides) < 20 {
		t.Fatalf("%s: only %d dark overrides found — the parser is broken", cssPath, len(darkOverrides))
	}
	merged := maps.Clone(base)
	maps.Copy(merged, darkOverrides)
	return &palette{name: "light", raw: base}, &palette{name: "dark", raw: merged, dark: true}
}

// colour resolves a token name to an rgb, following var() indirection. Names
// beginning with "@" are the synthesized surfaces described at the top of the
// file; they are not CSS tokens.
func (p *palette) colour(t *testing.T, name string) rgb {
	t.Helper()
	if s, ok := strings.CutPrefix(name, "@"); ok {
		return p.synthetic(t, s)
	}
	seen := map[string]bool{}
	for cur := name; ; {
		if seen[cur] {
			t.Fatalf("%s theme: token --%s resolves in a cycle", p.name, name)
		}
		seen[cur] = true
		v, ok := p.raw[cur]
		if !ok {
			t.Fatalf("%s theme: no token --%s in the stylesheet", p.name, cur)
		}
		if m := varRefRe.FindStringSubmatch(v); m != nil {
			cur = m[1]
			continue
		}
		c, ok := parseHex(v)
		if !ok {
			t.Fatalf("%s theme: token --%s = %q is not a hex colour", p.name, cur, v)
		}
		return c
	}
}

// synthetic builds the surfaces that are not a single token: gradient midpoints
// and Bootstrap's rgba() row tints.
func (p *palette) synthetic(t *testing.T, name string) rgb {
	t.Helper()
	mid := func(a, b string) rgb { return mix(p.colour(t, a), p.colour(t, b)) }
	switch name {
	case "row-hover":
		return mid("tx-row-hover-1", "tx-row-hover-2")
	case "th":
		return mid("tx-th-grad-1", "tx-th-grad-2")
	case "th-sort":
		return mid("tx-th-sort-1", "tx-th-sort-2")
	case "btn":
		return mid("tx-btn-1", "tx-btn-2")
	case "btn-hover":
		return mid("tx-btn-hover-1", "tx-btn-hover-2")
	case "tab":
		return mid("tx-topmenu-tab-1", "tx-topmenu-tab-2")
	case "striped", "striped-hover":
		// Bootstrap 5.3 tints the table background with
		// rgba(var(--bs-emphasis-color-rgb), .05) for .table-striped and .075
		// for .table-hover. --bs-emphasis-color-rgb is black in the light theme
		// and white in the dark one.
		emphasis := rgb{0, 0, 0}
		if p.dark {
			emphasis = rgb{1, 1, 1}
		}
		alpha := 0.05
		if name == "striped-hover" {
			alpha = 0.075
		}
		return over(emphasis, p.colour(t, "tx-bg"), alpha)
	}
	t.Fatalf("%s theme: unknown synthesized surface @%s", p.name, name)
	return rgb{}
}

// ------------------------------------------------------------------ the assertions

// pair is one foreground token checked against a set of backgrounds.
type pair struct {
	what string
	fg   string
	bgs  []string
	min  float64
}

// pageSurfaces are the flat surfaces body copy sits on, plus Bootstrap's tinted
// rows (db_structure, server_databases and friends use .table-striped rather
// than TableX's own .data striping).
var pageSurfaces = []string{
	"tx-bg", "tx-surface-alt", "tx-surface-sunken", "tx-totals-bg",
	"@striped", "@striped-hover",
}

// dataRows are TableX's own alternating rows (.tx-results.data — browse, SQL
// results, the process list), their hover gradient and the "marked" row.
var dataRows = []string{"tx-row-even", "tx-row-odd", "@row-hover", "tx-marker"}

// chromeGradients are taller than their text, so both stops are checked.
var chromeGradients = []string{
	"tx-nav-bg-1", "tx-nav-bg-2", "tx-navbar-bg-1", "tx-navbar-bg-2",
}

var contrastPairs = []pair{
	// --- body copy ---------------------------------------------------------
	{"body text on a page surface", "tx-text", pageSurfaces, 4.5},
	{"body text in a data row", "tx-text", dataRows, 4.5},
	{"button labels", "tx-text", []string{"@btn", "@btn-hover"}, 4.5},
	{"NULL / system-row italics", "tx-text", dataRows, 4.5},

	// --- links -------------------------------------------------------------
	{"links on a page surface", "tx-link", pageSurfaces, 4.5},
	{"row action links", "tx-link", dataRows, 4.5},
	{"links in the chrome", "tx-link", chromeGradients, 4.5},
	{"context tabs", "tx-link", []string{"@tab", "tx-topmenu-bg"}, 4.5},
	{"primary-key header links", "tx-link", []string{"@th", "@th-sort"}, 4.5},
	{"tree links", "tx-nav-text", []string{"tx-nav-bg-1", "tx-nav-bg-2", "tx-pointer"}, 4.5},

	// --- secondary text ----------------------------------------------------
	{"muted text on a page surface", "tx-muted", pageSurfaces, 4.5},
	{"muted text in the chrome", "tx-chrome-muted", chromeGradients, 4.5},

	// --- text over a themed surface ---------------------------------
	{"table header text", "tx-th-text", []string{"@th", "@th-sort", "tx-th-bg"}, 4.5},
	{"card header text", "tx-card-header-text", []string{"tx-card-header"}, 4.5},
	{"the active context tab", "tx-topmenu-active-text", []string{"tx-bg"}, 4.5},

	// --- danger ------------------------------------------------------------
	{"danger text on a page surface", "tx-danger", pageSurfaces, 4.5},
	{"row delete icons", "tx-danger", dataRows, 4.5},
	{"tree error text", "tx-danger", []string{"tx-nav-bg-1", "tx-nav-bg-2"}, 4.5},

	// --- alerts and toasts ------------------------------------
	{"success alert text", "tx-success-fg", []string{"tx-success-bg"}, 4.5},
	{"error alert and toast text", "tx-error-fg", []string{"tx-error-bg"}, 4.5},
	{"info alert text", "tx-info-fg", []string{"tx-info-bg"}, 4.5},
	{"warning alert text", "tx-warning-fg", []string{"tx-warning-bg"}, 4.5},

	// --- login page --------------------------------------------------------
	{"the login footnote", "tx-login-about", []string{"tx-login-grad-1", "tx-login-grad-2"}, 4.5},

	// --- non-text (WCAG 1.4.11) --------------------------------------------
	{"tree table/view icons", "tx-tree-table", []string{"tx-nav-bg-1", "tx-nav-bg-2"}, 3},
	{"tree connector lines", "tx-tree-line", []string{"tx-nav-bg-1", "tx-nav-bg-2"}, 3},
	{"the focus ring", "tx-focus", []string{
		"tx-bg", "tx-surface-alt", "tx-surface-sunken", "tx-row-even", "tx-row-odd",
		"@btn", "tx-nav-bg-1", "tx-nav-bg-2", "@th",
	}, 3},
}

func TestDesignTokenContrast(t *testing.T) {
	light, dark := themes(t)
	for _, p := range []*palette{light, dark} {
		t.Run(p.name, func(t *testing.T) {
			for _, pr := range contrastPairs {
				fg := p.colour(t, pr.fg)
				for _, bgName := range pr.bgs {
					bg := p.colour(t, bgName)
					if got := contrast(fg, bg); got < pr.min {
						t.Errorf("%s: --%s (%s) on %s (%s) is %.2f:1, want >= %.1f:1",
							pr.what, pr.fg, fg, bgName, bg, got, pr.min)
					}
				}
			}
		})
	}
}

// surfaceTokens must genuinely be light in the light theme and dark in the dark
// one. The complaint about the alert palette was not a contrast failure — dark
// text on a pastel fill reads fine in isolation — it was a bright pastel panel
// sitting on a dark page because the fill was never re-tokenized. A token that
// keeps its light value in the dark theme fails here.
var surfaceTokens = []string{
	"tx-bg", "tx-surface-alt", "tx-surface-sunken", "tx-totals-bg",
	"tx-row-even", "tx-row-odd", "tx-row-hover-1", "tx-row-hover-2",
	"tx-marker", "tx-pointer",
	"tx-th-bg", "tx-th-grad-1", "tx-th-grad-2", "tx-th-sort-1", "tx-th-sort-2",
	"tx-card-header", "tx-btn-1", "tx-btn-2", "tx-btn-hover-1", "tx-btn-hover-2",
	"tx-nav-bg-1", "tx-nav-bg-2", "tx-navbar-bg-1", "tx-navbar-bg-2",
	"tx-topmenu-bg", "tx-topmenu-tab-1", "tx-topmenu-tab-2",
	"tx-login-grad-1", "tx-login-grad-2",
	"tx-success-bg", "tx-error-bg", "tx-info-bg", "tx-warning-bg",
}

// accentTokens are painted as a background but are not page surfaces: they are
// deliberately high-contrast against the page in BOTH themes, so the
// light-is-light / dark-is-dark rule below does not apply to them. They still
// have to be listed, so "not a surface" stays a decision someone made rather
// than an omission.
var accentTokens = []string{
	"tx-progress", // the request progress bar, an accent line on the page edge
}

func TestEverySurfaceIsRetokenizedForDarkMode(t *testing.T) {
	light, dark := themes(t)
	const (
		lightFloor = 0.30 // a light surface must be at least this bright
		darkCeil   = 0.18 // a dark surface must be at most this bright
	)
	for _, name := range surfaceTokens {
		if l := light.colour(t, name).luminance(); l < lightFloor {
			t.Errorf("light theme: --%s (%s) has luminance %.3f, want >= %.2f — is it a surface?",
				name, light.colour(t, name), l, lightFloor)
		}
		if d := dark.colour(t, name).luminance(); d > darkCeil {
			t.Errorf("dark theme: --%s (%s) has luminance %.3f, want <= %.2f — it was never re-tokenized for dark mode",
				name, dark.colour(t, name), d, darkCeil)
		}
	}
}

// -------------------------------------------------- the invariant behind it

type cssRule struct {
	sel, body string
}

// cssRules flattens the stylesheet into (selector, body) pairs, descending into
// @media so a nested rule is not missed.
func cssRules(css string) []cssRule {
	var out []cssRule
	var walk func(s string)
	walk = func(s string) {
		for {
			i := strings.IndexByte(s, '{')
			if i < 0 {
				return
			}
			sel := strings.TrimSpace(s[:i])
			depth, end := 0, -1
			for j := i; j < len(s); j++ {
				switch s[j] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						end = j
					}
				}
				if end >= 0 {
					break
				}
			}
			if end < 0 {
				return
			}
			body := s[i+1 : end]
			if strings.HasPrefix(sel, "@") {
				walk(body)
			} else {
				out = append(out, cssRule{sel: sel, body: body})
			}
			s = s[end+1:]
		}
	}
	walk(css)
	return out
}

var (
	colourDeclRe = regexp.MustCompile(`(?:^|[;{}\s])color\s*:\s*([^;]+)`)
	bgDeclRe     = regexp.MustCompile(`(?:^|[;{}\s])background(?:-color|-image)?\s*:\s*([^;]+)`)
	valueVarRe   = regexp.MustCompile(`var\(\s*--([a-z0-9-]+)`)
)

// TestEveryColourTokenIsCovered ties the tables above back to the stylesheet: a
// token used as a `color` must appear as a foreground in contrastPairs, and a
// token used as a `background` must appear in surfaceTokens. Without this, the
// tables would be a private opinion — someone could paint a new element with an
// unaudited token and every other test here would still pass.
//
// What it deliberately does NOT prove: that a given rule pairs its foreground
// with the surface it actually renders on. Deciding that mechanically would mean
// resolving the cascade. So a rule that points a covered token at the wrong
// surface — .tx-null-label back to --tx-muted, say, which is audited against
// page surfaces but would be sitting on a data row — is caught by review, not by
// this file.
func TestEveryColourTokenIsCovered(t *testing.T) {
	foregrounds, backgrounds := map[string]bool{}, map[string]bool{}
	for _, p := range contrastPairs {
		foregrounds[p.fg] = true
	}
	for _, s := range surfaceTokens {
		backgrounds[s] = true
	}
	for _, s := range accentTokens {
		backgrounds[s] = true
	}

	var inspected int
	for _, r := range cssRules(loadCSS(t)) {
		if r.sel == ":root" || r.sel == `[data-bs-theme="dark"]` ||
			strings.Contains(r.sel, "CodeMirror") || strings.Contains(r.sel, ".cm-") {
			continue
		}
		check := func(re *regexp.Regexp, covered map[string]bool, kind, table string) {
			for _, decl := range re.FindAllStringSubmatch(r.body, -1) {
				for _, ref := range valueVarRe.FindAllStringSubmatch(decl[1], -1) {
					tok := ref[1]
					if !strings.HasPrefix(tok, "tx-") {
						// A colour reached in from outside TableX's own tokens is
						// a colour neither theme controls and nothing here can
						// audit. Bootstrap keeps --bs-danger at #dc3545 in both
						// themes, which is 3.29:1 on the sidebar; writing
						// var(--bs-danger, var(--tx-danger)) hides that behind a
						// fallback that never applies.
						t.Errorf("%s: rule %q takes its %s from --%s, which is not a TableX token — "+
							"use a --tx-* token so both themes can set it", cssPath, r.sel, kind, tok)
						continue
					}
					inspected++
					if covered[tok] {
						continue
					}
					t.Errorf("%s: rule %q uses --%s as a %s, but no %s covers it — add it "+
						"there so its contrast is asserted (or to accentTokens, if it is a "+
						"background that is deliberately not a page surface)",
						cssPath, r.sel, tok, kind, table)
				}
			}
		}
		check(colourDeclRe, foregrounds, "foreground", "contrastPairs entry")
		check(bgDeclRe, backgrounds, "background", "surfaceTokens entry")
	}
	// Without this the test would pass by finding nothing at all — the failure
	// mode that let three earlier assertions in this project guard reverted code.
	if inspected < 50 {
		t.Fatalf("only %d token references inspected across the stylesheet; "+
			"the declaration regexps have stopped matching", inspected)
	}
}

func TestNoRawColourOutsideTheTokenBlocks(t *testing.T) {
	for _, r := range cssRules(loadCSS(t)) {
		switch {
		case r.sel == ":root", r.sel == `[data-bs-theme="dark"]`:
			continue // the token blocks are where colours are declared
		case strings.Contains(r.sel, "CodeMirror"), strings.Contains(r.sel, ".cm-"):
			// CodeMirror 5 ships only a light theme and TableX has no build
			// step, so the dark re-skin is a dark-only block with no light
			// counterpart to tokenize against. Documented in the stylesheet.
			continue
		}
		if m := hexRe.FindString(r.body); m != "" {
			t.Errorf("%s: rule %q hardcodes %s — a theme cannot override it.\n"+
				"Add a token to :root, give it a value in the dark block, and use var() here.", cssPath, r.sel, m)
		}
	}
}
