package model

import "testing"

// TestExtraDisplay pins the structure page's Extra cell after B6 moved identity
// out of Extra and into a typed field. The wording is deliberately unchanged
// from what the PostgreSQL dialect used to write into Extra directly — this was
// a refactor of where the value lives, not of what the user sees.
func TestExtraDisplay(t *testing.T) {
	cases := []struct {
		name string
		col  Column
		want string
	}{
		{"plain", Column{}, ""},
		{"mysql extra only", Column{Extra: "auto_increment"}, "auto_increment"},
		{"identity always", Column{Identity: IdentityAlways}, "identity always"},
		{"identity by default", Column{Identity: IdentityByDefault}, "identity"},
		{"unknown identity value is not displayed", Column{Identity: "bogus"}, ""},
		{"both", Column{Extra: "auto_increment", Identity: IdentityAlways}, "auto_increment identity always"},
	}
	for _, c := range cases {
		if got := c.col.ExtraDisplay(); got != c.want {
			t.Errorf("%s: ExtraDisplay() = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestIsView / TestIsSequence pin the relation-kind predicates the listings and
// the table-scoped routes gate on.
func TestRelationKindPredicates(t *testing.T) {
	for _, ty := range []TableType{TableView, TableMatView} {
		if !(Table{Type: ty}).IsView() {
			t.Errorf("%s should be a view", ty)
		}
	}
	for _, ty := range []TableType{TableBase, TableSystem, TableSequence, TableForeign} {
		if (Table{Type: ty}).IsView() {
			t.Errorf("%s should not be a view", ty)
		}
	}
	if !(Table{Type: TableSequence}).IsSequence() {
		t.Error("TableSequence should be a sequence")
	}
	if (Table{Type: TableBase}).IsSequence() {
		t.Error("TableBase should not be a sequence")
	}
}
