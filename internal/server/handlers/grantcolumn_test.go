package handlers

import (
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/model"
)

func cols(names ...string) []model.Column {
	out := make([]model.Column, len(names))
	for i, n := range names {
		out[i] = model.Column{Name: n}
	}
	return out
}

// TestResolveColumnNamesMatchesIntrospection covers the accept path: names come
// back in INTROSPECTED order (not submission order) and spelled as the catalog
// spells them, because that ordering is what makes two identical grants produce
// identical SQL and that spelling is what earns the name its trip through
// QuoteIdent.
func TestResolveColumnNamesMatchesIntrospection(t *testing.T) {
	existing := cols("id", "email", "note")
	got, err := resolveColumnNames(existing, []string{"note", "id"})
	if err != nil {
		t.Fatalf("resolveColumnNames: %v", err)
	}
	if strings.Join(got, ",") != "id,note" {
		t.Errorf("got %v, want [id note] — introspected order, not form order", got)
	}

	// A duplicate submission is one column, not a repeated one: "SELECT (a, a)"
	// is a server-side error, so collapsing here keeps a double-click working.
	got, err = resolveColumnNames(existing, []string{"email", "email", "  email  "})
	if err != nil {
		t.Fatalf("duplicate columns: %v", err)
	}
	if len(got) != 1 || got[0] != "email" {
		t.Errorf("duplicates = %v, want [email]", got)
	}

	// No selection is the object-wide grant — the form's control is optional.
	if got, err := resolveColumnNames(existing, nil); err != nil || got != nil {
		t.Errorf("empty selection = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := resolveColumnNames(existing, []string{"", "  "}); err != nil || got != nil {
		t.Errorf("blank selection = (%v, %v), want no columns", got, err)
	}
}

// TestResolveColumnNamesRefusesUnknown is the important half. Filtering an
// unmatched name out would be the safe move almost anywhere else in this
// package; here it is the dangerous one, because an EMPTY column list is not
// "grant nothing", it is "grant on every column". Dropping the only recognized
// name from a one-column request would turn a narrow grant into a table-wide
// one and still report success.
func TestResolveColumnNamesRefusesUnknown(t *testing.T) {
	existing := cols("id", "email")

	for _, want := range [][]string{
		{"ghost"},          // nothing matches: the dangerous case
		{"email", "ghost"}, // partial match: still a different grant than asked for
		{"EMAIL"},          // wrong case: PostgreSQL folds nothing here
	} {
		got, err := resolveColumnNames(existing, want)
		if err == nil {
			t.Errorf("resolveColumnNames(%v) = %v, want an error; an unmatched name must never be silently dropped", want, got)
		}
		if got != nil {
			t.Errorf("resolveColumnNames(%v) returned %v alongside its error; the caller must have nothing usable", want, got)
		}
	}

	// The message names the first offender in submission order, so the report
	// is deterministic rather than map-ordered.
	if _, err := resolveColumnNames(existing, []string{"zeta", "alpha"}); err == nil || !strings.Contains(err.Error(), `"zeta"`) {
		t.Errorf("error = %v, want it to name %q", err, "zeta")
	}
}

func TestAnyNonBlank(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{""}, false},
		{[]string{" ", "\t"}, false},
		{[]string{"", "id"}, true},
	} {
		if got := anyNonBlank(c.in); got != c.want {
			t.Errorf("anyNonBlank(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestColumnNote keeps the flash honest about scope: an operator who reads
// "Granted SELECT to alice" on what was a one-column grant would believe the
// account has more access than it does.
func TestColumnNote(t *testing.T) {
	if got := columnNote(nil); got != "" {
		t.Errorf("columnNote(nil) = %q, want empty so the object-wide message is unchanged", got)
	}
	if got := columnNote([]string{"email"}); got != " on column email" {
		t.Errorf("columnNote(one) = %q", got)
	}
	if got := columnNote([]string{"email", "note"}); got != " on columns email, note" {
		t.Errorf("columnNote(many) = %q", got)
	}
}
