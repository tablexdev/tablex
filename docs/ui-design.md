# TableX — UI Design System

> TableX's UI is the classic server-rendered database-admin layout — a left
> navigation tree, breadcrumb, context tabs and dense data grids — kept
> deliberately familiar, then modernized carefully and only in ways that don't
> break that familiarity. This file defines the design system: tokens, page
> skeleton, components, interactivity policy and accessibility.

## 1. Strategy

- **Base:** Bootstrap 5.3.8.
- **Theme:** our own CSS (`web/static/css/tablex.css`) — an original stylesheet
  defining TableX's classic two-tone admin palette once, as design tokens.
- **Rendering:** Go `html/template`, server-rendered. htmx swaps `#page_content`
  for navigation, so the app feels instant without being a SPA.
- **Two layers:**
  1. *Classic* — the familiar layout, palette, typography, density.
  2. *Modern* — optional dark mode (Bootstrap `data-bs-theme`), better
     spacing/touch targets, modern icons — all opt-in, never degrading the
     classic feel.

---

## 2. Design tokens

Defined once as CSS custom properties in `tablex.css`.

```css
:root {
  /* Color */
  --tx-link:           #235a81;  /* links, active tabs */
  --tx-text:           #444;     /* body text */
  --tx-nav-text:       #000;     /* navigation text */
  --tx-nav-bg-1:       #f3f3f3;  /* nav panel gradient start */
  --tx-nav-bg-2:       #dadcde;  /* nav panel gradient end */
  --tx-navbar-bg-1:    #ffffff;  /* top bar gradient start */
  --tx-navbar-bg-2:    #dcdcdc;  /* top bar gradient end */
  --tx-th-bg:          #d3dce3;  /* table header */
  --tx-row-even:       #e5e5e5;
  --tx-row-odd:        #d5d5d5;
  --tx-row-hover-1:    #ced6df;
  --tx-row-hover-2:    #b6c6d7;
  --tx-pointer:        #cfc;     /* nav-tree row hover (its only use; the data
                                  * grid hovers with --tx-row-hover-1/2 and
                                  * marks a selected row with --tx-marker) */
  --tx-marker:         #fc9;     /* selected row */
  --tx-btn-1:          #f8f8f8;  --tx-btn-2:       #d8d8d8;
  --tx-btn-hover-1:    #fff;     --tx-btn-hover-2: #ddd;
  --tx-border:         #aaa;
  /* Each alert family carries its own text colour so the dark block can move
   * fill, border and text together (see §8). */
  --tx-success-bg:     #ebf8a4;  --tx-success-bd: #a2d246;  --tx-success-fg: #2c3a00;
  --tx-error-bg:       #ffc0cb;  --tx-error-bd:   #333;     --tx-error-fg:   #5a0000;
  --tx-info-bg:        #e8eef1;  --tx-info-bd:    #3a6c7e;  --tx-info-fg:    #14323d;
  --tx-warning-bg:     #fdf2c7;  --tx-warning-bd: #d9b65a;  --tx-warning-fg: #5a4500;
  --tx-card-header:    #bbb;     --tx-card-header-text: #000;
  --tx-tree-line:      #666;
  /* Two muted greys: the page surfaces below are lighter than the nav/top-bar
   * gradients, which need a darker grey to clear 4.5:1 on their far stops. */
  --tx-muted:          #696969;  /* on page surfaces  */
  --tx-chrome-muted:   #5f5f5f;  /* on nav / top bar  */

  /* Surfaces & gradients — light values; the dark block (data-bs-theme="dark")
   * overrides each BY VALUE, so dark mode is ENTIRELY a token re-spec: no rule
   * in the stylesheet carries a raw hex, and web/contrast_test.go fails the
   * build if one appears. (Only the CodeMirror re-skin is exempt — CodeMirror 5
   * ships a light theme alone, so there is no light rule to tokenize against.) */
  --tx-bg:             #fff;     /* page / table background  */
  --tx-surface-alt:    #f6f6f6;  /* DDL / error-sql panels   */
  --tx-surface-sunken: #fafafa;  /* collapsible edit forms   */
  --tx-totals-bg:      #efefef;  /* table totals row         */
  --tx-th-grad-1:      #fff;     --tx-th-grad-2: #ccc;   /* th gradient      */
  --tx-th-sort-1:      #fff;     --tx-th-sort-2: #bcd;   /* sorted th tint   */
  --tx-th-text:        #000;     /* header text + its in-header controls */
  --tx-topmenu-bg:     #e8e8e8;
  --tx-topmenu-tab-1:  #fff;     --tx-topmenu-tab-2: var(--tx-navbar-bg-2);
  --tx-topmenu-active-text: #000;
  --tx-login-grad-1:   #e3e9ee;  --tx-login-grad-2:  #c9d3da;
  --tx-login-about:    #506;     /* login footer (muted in dark) */
  --tx-border-soft:    #ccc;     /* inner / cell gridlines   */
  --tx-danger:         #9c1f2b;  /* deeper than Bootstrap's #dc3545: the row
                                  * delete icons sit on the darkest data rows */
  --tx-tree-table:     #5a7a52;  /* table/view tree icon     */
  --tx-focus:          var(--tx-link);
  --tx-progress:       var(--tx-link);  /* request progress bar: an accent, not a
                                         * surface, so it aliases the link colour
                                         * and needs no dark value of its own */

  /* Type — neutral system stack (Win11 system-ui → Segoe UI); no webfont. */
  --tx-font:           system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --tx-mono:           ui-monospace, "Cascadia Code", "Source Code Pro", Menlo, Consolas, "DejaVu Sans Mono", monospace;
  --tx-font-size:      0.82rem;  /* body base                */
  --tx-fs-xs:          0.72rem;  --tx-fs-sm: 0.78rem;  --tx-fs-md: 0.85rem;
  --tx-fs-lg:          1.05rem;  --tx-fs-xl: 1.1rem;
  --tx-fs-h2:          1.3rem;   --tx-fs-h1: 1.4rem;   /* h1 > h2 */

  /* Radius + shadow scales */
  --tx-radius-sm:      3px;      --tx-radius: 4px;  --tx-radius-lg: 5px;
  --tx-btn-radius:     0.85rem;  /* signature pill button    */
  --tx-shadow:         0 2px 8px rgba(0,0,0,.18);
  --tx-shadow-lg:      0 6px 24px rgba(0,0,0,.18);
  --tx-shadow-drawer:  2px 0 14px rgba(0,0,0,.25);

  /* Metrics */
  --tx-nav-width:      240px;
  --tx-cell-pad-y:     0.1em;    /* 0.35em on coarse-pointer touch */
  --tx-cell-pad-x:     0.3em;    /* 0.5em  on coarse-pointer touch */
}
```

The colour tokens define TableX's classic light palette; the surface/type/
radius/shadow scales were added in the UI-polish pass to fully tokenize dark
mode and responsive touch sizing without changing the classic desktop
appearance.

The `*-text` / `*-fg` / `*-muted` foreground tokens came later, from the contrast
pass: a rule that hardcodes the text colour over a themed background is a colour
the dark theme cannot reach, which is how card headers ended up at 1.83:1. Every
surface value above is unchanged from the original palette — the pass moved only
foregrounds, and `web/contrast_test.go` now holds that line.

---

## 3. Page skeleton

The logged-in layout:

```html
<body id="..." hx-target="#page_content">
  <div id="tx-progress" aria-hidden="true"></div>        <!-- in-flight request bar; lives in the SHELL so a swap cannot replace it -->
  <div id="tx-announce" role="status" aria-live="polite"></div>  <!-- the one aria-live region for the whole app -->
  <a href="#page_content" class="tx-skip">Skip to content</a>    <!-- a11y skip link -->

  <nav id="tx_nav" aria-label="Database navigation">   <!-- resizable left panel -->
    <div id="tx_nav_resizer"></div>          <!-- drag-to-resize (no collapser) -->
    <div id="tx_nav_content">
      <div id="tx_nav_header">...</div>       <!-- logo, Home, Documentation, logout -->
      <div class="tx-nav-filter">...</div>            <!-- live tree filter -->
      <div id="tx_nav_tree">
        <ul class="tx-tree-root">...</ul>             <!-- DB → (schema) → table tree -->
      </div>
    </div>
  </nav>

  <div id="tx-main">                                  <!-- everything right of the nav panel -->
    <div id="page_nav_icons">                         <!-- the top bar -->
      <button data-tx-nav-toggle>…</button>           <!-- small-screen drawer toggle -->
      <nav id="server-breadcrumb">…</nav>             <!-- Server » Database » Table — INSIDE the icon bar, not a sibling -->
      …                                               <!-- engine badge, connected user, theme toggle, logout -->
    </div>
    <div id="topmenucontainer">
      <nav class="navbar"><ul id="topmenu">...</ul></nav>   <!-- context tabs -->
    </div>
    <main id="page_content" tabindex="-1">...</main>  <!-- htmx swap target (<main>, not a div) -->
  </div>
</body>
```

Template files (layout is a flat set of partials — no separate `tree_node.html`;
the recursive tree renders inside `sidebar.html`):

```
web/templates/
├── layout/
│   ├── base.html            # <html> shell, head, asset links, body skeleton
│   ├── navbar_icons.html    # #page_nav_icons
│   ├── sidebar.html         # #tx_nav + the recursive nav tree
│   ├── breadcrumb.html      # #server-breadcrumb
│   ├── tabs.html            # #topmenu context tabs (data/table-driven)
│   ├── flash.html           # success/error/info alerts
│   ├── results.html         # shared result-grid partial
│   ├── empty_state.html     # shared "nothing here" panel
│   ├── collation_select.html# shared charset/collation optgroup select
│   ├── csrf.html            # the hidden CSRF field every no-JS form carries
│   ├── definition.html      # shared routine/trigger/event definition panel
│   ├── destructive.html     # shared POST form behind every irreversible action
│   ├── edit_fields.html     # shared type-aware insert/edit field set
│   └── logout_form.html     # POST-logout control
└── pages/
    ├── login.html
    ├── home.html
    ├── server_databases.html
    ├── db_structure.html
    ├── table_browse.html
    ├── table_structure.html
    ├── sql_console.html
    ├── confirm.html          # the server-side confirmation interstitial
    └── ... (one per feature)
```

The full/fragment split lives **once**, in `base.html`, which defines both
`"base"` and `"fragment"`; `view.Render` picks between them on `HX-Request`.
A page template does not have two versions of itself — every page file opens
with a single `{{define "content" -}}` and is cloned into a set that already
carries both entries. (Two `{{define}}` actions in `pages/` are neither:
`browse_state` and `column_form_fields` are in-file helpers.)

---

## 4. Component inventory

| Component | Structure | Notes |
|---|---|---|
| **Login** | cookie-auth card (`#login_form`, server/user/password/server-choice) | An engine picker, since TableX is multi-DB — but only for **network** engines, and only when ad-hoc login is enabled. The select offers two options, *MySQL / MariaDB* and *PostgreSQL*; **SQLite is never offered here**. A file-backed engine has no credentials, so an ad-hoc login for it would be an unauthenticated arbitrary file open — it is reachable only through an operator-configured predefined server. |
| **Home** | two-column cards | Four cards: General settings, Appearance, Database server, and a **TableX** card showing version, [tablex.dev](https://tablex.dev) and support `info@tablex.dev`. There is no web-server card, since TableX serves itself. |
| **Navigation tree** | `#tx_nav_tree` with DB/table icons, expand/collapse, fast-filter | Includes a **schema level** for PostgreSQL (driven by capabilities). |
| **Breadcrumb** | `#server-breadcrumb`, `#888` bg, `»` divider | Schema crumb for PG. |
| **Context tabs** | `#topmenu` gradient tabs; DB tabs / Table tabs | Tab set filtered by `Capabilities` (hide Users/Routines/Events when unsupported). |
| **Browse grid** | `.tx-results` striped/hover, checkbox + Edit/Copy/Delete, sortable headers w/ arrows, pagination bar, "with selected", rows-per-page, filter | The signature screen — highest polish priority. |
| **Table structure** | columns list, indexes, FKs, row stats, action links | DDL from dialect `CreateSQL`. |
| **SQL console** | CodeMirror editor + run + tabbed results + query history | CodeMirror 5 single-file. |
| **Insert / edit row** | per-column form with type-aware inputs | Type hints from `model.Column`. |
| **Destructive confirms** | server-side interstitial pages | Bootstrap's **JS is not vendored** (only its CSS), so there is no modal component. Destructive actions are confirmed **server-side**: without a confirmation field the handler answers with an interstitial page, so the control survives with JavaScript off. `hx-confirm` adds a browser dialog on top as a convenience. |

---

## 5. Interactivity policy

- **htmx** for navigation and partial updates: clicking a table loads its browse fragment into `#page_content`; the nav tree expands via fragment requests. The CSRF token is sent via an `htmx:configRequest` hook that sets the `X-CSRF-Token` header (`app.js`); no-JS forms carry it in a hidden field. We avoid htmx's `js:`/`hx-on:` eval features so a strict CSP holds.
- **Alpine.js (CSP build, `@alpinejs/csp`)** for purely client-side state. Eight components are registered — `exportForm`, `loginForm`, `navSelect`, `rowFilter`, `bulkRows`, `objectPicker`, `sqlConsole`, `createTableRows` — covering the export form's format-dependent fields, the login form's engine switching, the nav select, the client-side row filter, "check all" and bulk row actions, the object picker, the console, and the create-table row editor. There are **no modals and no Alpine dropdowns**: destructive confirms are server-side interstitials (§4) and collapsible panels are native `<details>`. The CSP build avoids `new Function()`/eval (so the strict CSP holds with no `unsafe-eval`) and still parses a useful subset of expressions — including simple comparisons like `format !== 'sql'`. TableX nonetheless standardizes, **by convention**, on registering components with `Alpine.data()` and referencing properties/getters **by key**, for consistency. See [`security.md`](./security.md) §5.
- **CodeMirror 5** for the SQL editor only — **SQL mode bundled, markdown mode excluded** (CVE-2025-6493; see [`tech-stack.md`](./tech-stack.md)).
- **Vanilla JS** for the few remaining bits (resizable nav panel, sortable column drag later).
- **Every request reports that it is running.** A navigation runs introspection, a
  browse may run `COUNT(*)`, a console submit runs whatever was typed — so a click
  with no acknowledgement looks ignored, and the natural response is to click
  again, which on a POST means running it twice. `app.js` counts in-flight
  requests from `htmx:beforeRequest`/`htmx:afterRequest` and drives three signals:
  a progress bar across the top of the viewport (`#tx-progress`, in the shell and
  *outside* `#page_content` so a swap cannot replace it mid-request), `aria-busy`
  on the region being replaced (which dims it after a 400 ms delay, so only a wait
  worth noticing is visible), and `disabled` on the submitting form's submit
  controls until the response lands. The bar's width is a sign of life, not a
  fraction: nothing here knows how far along a query is, so it creeps toward 90%
  and stops. Under `prefers-reduced-motion` it is simply full while a request is
  out. The submit lock is JS rather than htmx's `hx-disabled-elt` because that
  attribute warns to the console whenever its selector matches nothing, which
  every non-form request would do.
- **Typed-in work is not thrown away silently.** A form whose contents are
  expensive to retype carries `data-tx-guard="<what would be lost>"` — the SQL
  console, the row and bulk editors, create-table, the program editor — and
  `app.js` marks it dirty on the first edit. Leaving then asks, on both paths: the
  browser's own prompt via `beforeunload` for a real navigation, and an
  `htmx:confirm` hook for a swap, which never unloads the page and so never gave
  the browser a chance to ask. Only forms where the work is real carry the
  attribute: a prompt that fires over a rows-per-page dropdown is one people learn
  to dismiss unread. Two details are load-bearing — the dirty flag is a class on
  the form, so the swap that replaces it clears the flag with no bookkeeping; and
  the hook re-issues with `issueRequest()` and no argument, because passing `true`
  would skip an `hx-confirm` dialog while `htmx:configRequest` still adds the
  server-side `tx_confirm` field, turning a confirmed destructive action into an
  unconfirmed one.
- **Assets are fingerprinted, and the fingerprint is what makes them cacheable.**
  `view.New` hashes every embedded file under `static/` once at startup;
  `{{assetV}}` stamps it on each URL and the server answers a matching `?v=` with
  `max-age=31536000, immutable`. A bare path or a stale `v` keeps the old
  one-hour lifetime, because freezing a URL whose bytes can change is how a
  client ends up pinned to an asset it will never request again. The value is
  also published in a `<meta name="asset-version">` so the lazily-loaded
  CodeMirror files are stamped the same way rather than being the only assets
  still revalidating hourly. One fingerprint for the whole tree: a new build is a
  new binary, and re-fetching the assets on upgrade is the honest cost of that.
- **`htmx.config.historyCacheSize = 0`.** htmx keeps up to ten rendered pages in
  `sessionStorage` for back/forward. In an admin tool those pages *are* the data —
  query results, table contents, user lists — so the default left rows from a
  database in the browser profile, outliving the session that fetched them.
  Back/forward re-requests instead: one round trip, fresh rows, nothing at rest.
- **Ctrl/Cmd+Enter runs the query**, via CodeMirror's `extraKeys` and a keydown
  handler for the plain textarea. It goes through `form.requestSubmit()`, not
  `form.submit()`, so htmx still sees the submit event and swaps instead of
  doing a full page load.
- No jQuery. No React.

---

## 6. Icons

Icons are a clean, MIT-licensed SVG set (Bootstrap Icons), mapped to semantic
action/object names via a template helper `{{ icon "edit" }}`, so markup stays
readable and the whole set can be swapped in one place.

---

## 7. Modernization

Each item below records what shipped and in what form:

- **Dark mode** via `data-bs-theme="dark"` with a tuned token set — **shipped**,
  as a value-only override of every surface and foreground token (§2, §8).
- **Larger touch targets / line-height** — shipped, but **not** as an opt-in
  control. The `--tx-cell-pad-y/x` tokens are re-specified under
  `@media (hover: none) and (pointer: coarse)`, so a coarse-pointer device gets
  the looser spacing automatically and a mouse gets the classic density
  unchanged. There is no density toggle, class, config field or handler, and no
  plan for one.
- **Smoother transitions** — shipped: ≤150ms background/colour/border
  transitions on links, tree rows, tabs and buttons, with a
  `prefers-reduced-motion` block that removes them globally.
- **Sticky headers** — **decided against**, not deferred. The result tables live
  inside Bootstrap's `.table-responsive` overflow container with no fixed
  height, which makes `position: sticky` inert for page scrolling and risks the
  header overlapping the toolbar; the classic layout scrolls the page normally.
  The reason is recorded beside the code in `tablex.css`.
- **Keyboard shortcuts** — three ship (Escape closes the mobile drawer, Tab is
  trapped while it is an overlay, Ctrl/Cmd+Enter runs the query). A *global*
  shortcut system is still future work.
- **Never remove the classic layout or rename the familiar tabs** — a standing
  rule, not an item of work.

---

## 8. Accessibility (current baseline)

Modern baseline target: **WCAG 2.2 AA**. Accessibility is additive to the
classic look — we keep the appearance while making the markup correct
underneath:

- **Semantic HTML first**, ARIA only to fill gaps (landmarks on `#tx_nav`/`#page_content`, `aria-current` on the active tab, `aria-sort` on sortable headers, labelled form controls, `scope` on table headers).
- **One `<h1>` per page, and it names the page.** The classic chrome names the
  current page in the breadcrumb and the tab strip rather than in a heading, so
  most pages had none and two — the login page and Browse — had no heading at
  all. The layout emits a visually hidden `<h1>` carrying the same text as
  `<title>`, inside the swapped region so it can never go stale or be forgotten
  on a new page. A visible page title is therefore an `<h2>` (see the home page's
  server name, which keeps the `.tx-h1` sizing).
- **Every column header carries a `scope`** (`colgroup` where one header spans
  several columns, as the action groups do).
- **Row editing is labelled.** The column-name cell of the edit/insert table is a
  `<th scope="row">`, and every value control carries an `aria-label` — this is
  the primary data-editing screen, and it used to announce every field as "edit
  text, blank".
- **One permanent `aria-live` region** (`#tx-announce`) in the shell, outside the
  swap. A `role="alert"` element *created* by a swap is announced unreliably, so
  the region exists up front and text is moved into it — clear-then-set, because
  writing the same string twice is not a change and would be silent.
- **Keyboard operability:** every action reachable without a mouse; visible focus rings (don't suppress `:focus-visible`); logical tab order; Escape closes the mobile navigation drawer (there are no modals to close — see §4).
- **The off-canvas drawer keeps the modal contract.** Below 768px the sidebar is
  `visibility: hidden` when closed — not merely translated off-screen, which left
  the entire database tree in the tab order where focus could land on content
  nobody could see. Opening moves focus into the drawer, Tab is kept inside it,
  and dismissing restores focus to the toggle. All three are conditional on the
  drawer actually being an overlay: on a wide screen the sidebar is permanent
  furniture, and trapping focus there would be the bug.
- **Contrast: both themes meet AA, and a test says so.** `web/contrast_test.go`
  parses the shipped stylesheet, resolves every token for light *and* dark, and
  asserts 4.5:1 for text and 3:1 for non-text indicators on each surface the
  stylesheet actually paints. The classic look and contrast turned out not to
  compete: every fix moved a *foreground*, so no classic surface colour changed.
  Where a grey light enough to read as "muted" could not clear 4.5:1 on a
  surface — the alternating data rows, the sorted table header — that element
  uses the full-strength text colour and carries its secondary weight with
  italics or size instead.
  - **Deliberately not asserted:** the 3:1 non-text ratio for table cell and
    card borders. WCAG 1.4.11 covers boundaries that identify a component or its
    state; these are structural decoration, and raising them would mean
    abandoning the classic grid. The focus ring — which *is* state — is
    asserted at 3:1.
  - **What the test cannot prove:** that a rule pairs its foreground with the
    surface it truly renders on. It checks the palette and that no rule escapes
    the palette; the pairing itself is review.
- **Respect `prefers-reduced-motion`** for the transitions added during modernization.
- **Tests, not intentions.** `internal/server/a11y_test.go` renders 23 routes plus
  the login page through the real server and asserts each of the above: exactly
  one `<h1>` per page and that it matches `<title>`, a `scope` on every header
  cell, a name on every row-editor control, and the live region present once and
  outside the fragment. `web/embed_test.go` covers the parts that only a browser
  executes — the drawer's visibility, focus trap and focus restore, and the
  announcement path — as content assertions, since there is still no JS runner.
  Both carry floors on how much they inspected, so they cannot pass by finding
  nothing.
