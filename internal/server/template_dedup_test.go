package server_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var csrfFieldRE = regexp.MustCompile(`<input type="hidden" name="csrf_token" value="([^"]+)">`)

// TestRenderedCSRFField pins what the {{template "csrf" $.CSRF}} partial has to
// keep producing. Nothing asserted this before: the suite reads its token from
// the <meta name="csrf-token"> tag, so every hidden field could have vanished
// from the forms and only a browser would have noticed.
func TestRenderedCSRFField(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	for _, path := range []string{
		"/db/main/table/widgets/structure",
		"/db/main/table/widgets",
		"/db/main/sql",
		"/db/main/export",
		"/db/main/import",
		"/db/main/operations",
	} {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, code)
			continue
		}
		m := csrfRE.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s: no csrf-token meta tag", path)
		}
		fields := csrfFieldRE.FindAllStringSubmatch(body, -1)
		if len(fields) == 0 {
			t.Errorf("%s: no hidden csrf_token field rendered; every state-changing form needs one", path)
			continue
		}
		for _, f := range fields {
			if f[1] != m[1] {
				t.Errorf("%s: hidden csrf_token %q does not match the meta token %q", path, f[1], m[1])
			}
		}
	}
}

// TestHXTargetInheritance pins the hoist. hx-target now lives on <body> and is
// inherited, which is only correct while the two exceptions stay explicit:
//
//   - the sidebar's lazy-load <details> targets the TREE, and htmx resolves to
//     the nearest ancestor — so the tree links inside it must carry their own
//     target or a database link would replace the tree with the page;
//   - the bulk-delete form may disinherit hx-confirm but NOT hx-target, because
//     disinheriting an attribute stops htmx's ancestor walk, which would leave
//     the row buttons swapping themselves.
func TestHXTargetInheritance(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if code != http.StatusOK {
		t.Fatalf("browse GET = %d, want 200", code)
	}
	if !strings.Contains(body, `<body id=`) || !strings.Contains(body, `hx-target="#page_content"`) {
		t.Fatal("the page has no hx-target at all")
	}
	bodyTag := body[strings.Index(body, "<body"):]
	bodyTag = bodyTag[:strings.Index(bodyTag, ">")+1]
	if !strings.Contains(bodyTag, `hx-target="#page_content"`) {
		t.Errorf("<body> must carry the inherited hx-target, got:\n%s", bodyTag)
	}
	if strings.Contains(body, `hx-disinherit="hx-confirm hx-target"`) {
		t.Error(`hx-disinherit must not list hx-target: it stops the ancestor walk, so the row buttons would lose the inherited target`)
	}
	// Every sidebar tree link must still carry its own target. A collapsed node
	// renders as a <details hx-target="find ul.tx-tree-children"> wrapping its
	// link, so an inheriting link would swap the tree instead of the page.
	links := treeLinkRE.FindAllString(body, -1)
	if len(links) == 0 {
		t.Fatal("no sidebar tree links rendered; this test would assert nothing")
	}
	for _, a := range links {
		if !strings.Contains(a, `hx-target="#page_content"`) {
			t.Errorf("a sidebar tree link inherits its target instead of setting it:\n%s", a)
		}
	}
	// A collapsed node keeps the tree loader's own target (only rendered when
	// the node is not already expanded).
	if strings.Contains(body, "tx-tree-details") && strings.Contains(body, "hx-trigger=\"toggle once\"") &&
		!strings.Contains(body, `hx-target="find ul.tx-tree-children"`) {
		t.Error("the sidebar tree loader lost its explicit target")
	}
}

var treeLinkRE = regexp.MustCompile(`<a class="tx-tree-link"[^>]*>`)

// destructiveFormRE captures each confirm-guarded POST form and its contents.
var destructiveFormRE = regexp.MustCompile(`(?s)<form method="post"[^>]*hx-confirm=[^>]*>(.*?)</form>`)

// TestDestructiveFormPartial pins what the {{template "destructive"}} has to
// render. These forms drop columns, indexes, tables and databases, and nothing
// asserted their contents before — a partial that lost its action field, its
// CSRF field or its confirmation would still render valid-looking HTML.
func TestDestructiveFormPartial(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	for _, tc := range []struct {
		path    string
		action  string
		fields  map[string]string // hidden fields the form must carry
		confirm string            // substring of the confirmation prompt
		label   string            // button text, or "" for an icon-only button
	}{
		{"/db/main/table/widgets/structure", "drop_column",
			map[string]string{"column": "id"}, "Drop column", ""},
		{"/db/main/table/widgets/operations", "drop",
			nil, "This cannot be undone", "Drop table"},
		{"/db/main/table/widgets/operations", "truncate",
			nil, "All rows will be deleted", "Empty (truncate)"},
		// drop_db / drop_schema / drop_user / revoke are not reachable here:
		// the harness runs on SQLite, which reports neither CanManageDatabases
		// nor HasUsers, so those cards are gated out. They share this partial,
		// and the live MySQL/MariaDB/PostgreSQL round-trips exercise them.
	} {
		code, body := getBody(t, client, ts.URL+tc.path)
		if code != http.StatusOK {
			t.Errorf("%s = %d, want 200", tc.path, code)
			continue
		}
		m := csrfRE.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s: no csrf-token meta tag", tc.path)
		}
		var form string
		for _, f := range destructiveFormRE.FindAllStringSubmatch(body, -1) {
			if strings.Contains(f[1], `name="action" value="`+tc.action+`"`) {
				form = f[0]
				break
			}
		}
		if form == "" {
			t.Errorf("%s: no destructive form with action=%q", tc.path, tc.action)
			continue
		}
		if !strings.Contains(form, `hx-post=`) {
			t.Errorf("%s/%s: form lost its hx-post", tc.path, tc.action)
		}
		if !strings.Contains(form, `value="`+m[1]+`"`) {
			t.Errorf("%s/%s: form does not carry the page's CSRF token", tc.path, tc.action)
		}
		if !strings.Contains(form, tc.confirm) {
			t.Errorf("%s/%s: confirmation does not mention %q:\n%s", tc.path, tc.action, tc.confirm, form)
		}
		for name, value := range tc.fields {
			if !strings.Contains(form, `name="`+name+`" value="`+value+`"`) {
				t.Errorf("%s/%s: missing hidden field %s=%s:\n%s", tc.path, tc.action, name, value, form)
			}
		}
		if tc.label != "" && !strings.Contains(form, tc.label) {
			t.Errorf("%s/%s: button text %q missing:\n%s", tc.path, tc.action, tc.label, form)
		}
		if tc.label == "" && !strings.Contains(form, "aria-label=") {
			t.Errorf("%s/%s: an icon-only button needs an accessible name:\n%s", tc.path, tc.action, form)
		}
	}
}
