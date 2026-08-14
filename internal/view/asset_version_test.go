package view

import (
	"testing"
	"testing/fstest"
)

// The fingerprint is what makes an immutable Cache-Control safe: the server
// freezes a response for a year when the URL carries this value, so if the value
// failed to move when an asset changed, clients would be pinned to bytes they
// will never ask for again. These are the two properties that has to rest on —
// it changes when content changes, and it does not change otherwise.
func TestAssetVersionTracksContent(t *testing.T) {
	base := fstest.MapFS{
		"static/css/tablex.css": {Data: []byte("body{color:red}")},
		"static/js/app.js":      {Data: []byte("var a=1;")},
	}
	v1 := assetVersion(base)
	if len(v1) < 8 {
		t.Fatalf("version %q is too short to be a fingerprint", v1)
	}

	// Deterministic: same tree, same value, however often it is computed. A
	// version that moved on its own would invalidate every client on restart.
	if v2 := assetVersion(base); v2 != v1 {
		t.Errorf("recomputing gave %q then %q; the fingerprint is not deterministic", v1, v2)
	}
	same := fstest.MapFS{
		"static/css/tablex.css": {Data: []byte("body{color:red}")},
		"static/js/app.js":      {Data: []byte("var a=1;")},
	}
	if v := assetVersion(same); v != v1 {
		t.Errorf("an identical tree gave %q, want %q", v, v1)
	}

	// A changed byte anywhere must move it.
	edited := fstest.MapFS{
		"static/css/tablex.css": {Data: []byte("body{color:blue}")},
		"static/js/app.js":      {Data: []byte("var a=1;")},
	}
	if v := assetVersion(edited); v == v1 {
		t.Error("editing an asset did not change the fingerprint; clients would be " +
			"frozen on the old bytes for a year")
	}

	// So must a renamed file, even with identical contents: the path is part of
	// what a client asks for.
	renamed := fstest.MapFS{
		"static/css/theme.css": {Data: []byte("body{color:red}")},
		"static/js/app.js":     {Data: []byte("var a=1;")},
	}
	if v := assetVersion(renamed); v == v1 {
		t.Error("renaming an asset did not change the fingerprint")
	}

	// And an added one.
	added := fstest.MapFS{
		"static/css/tablex.css": {Data: []byte("body{color:red}")},
		"static/js/app.js":      {Data: []byte("var a=1;")},
		"static/js/extra.js":    {Data: []byte("var b=2;")},
	}
	if v := assetVersion(added); v == v1 {
		t.Error("adding an asset did not change the fingerprint")
	}

	// Nothing outside static/ counts: templates are compiled into the pages, not
	// fetched by URL, so a template edit must not invalidate every cached asset.
	withTemplates := fstest.MapFS{
		"static/css/tablex.css":      {Data: []byte("body{color:red}")},
		"static/js/app.js":           {Data: []byte("var a=1;")},
		"templates/layout/base.html": {Data: []byte("<html>")},
	}
	if v := assetVersion(withTemplates); v != v1 {
		t.Errorf("a template changed the asset fingerprint (%q vs %q); only /static/ is served by URL", v, v1)
	}
}
