package sqlite

import (
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestValidateParamsRefusesTimeConversions covers #42 at the dialect seam:
// driver.ParamsValidator refuses an ENABLED _texttotime/_inttotime — which
// would make a text- or integer-stored column scan as time.Time and break the
// text fidelity TableX's browse, export and row-edit paths assume — while
// leaving every disabled, absent, differently-cased or unrelated value alone.
func TestValidateParamsRefusesTimeConversions(t *testing.T) {
	refuse := []map[string]string{
		{"_texttotime": "1"},
		{"_texttotime": "true"},
		{"_texttotime": "T"},
		{"_inttotime": "TRUE"},
		{"_inttotime": "1"},
	}
	for _, p := range refuse {
		err := dialect{}.ValidateParams(p)
		if err == nil {
			t.Errorf("ValidateParams(%v) accepted an enabled conversion, want refusal", p)
			continue
		}
		// The message must name the offending parameter so the operator can find it.
		if !strings.Contains(err.Error(), "_texttotime") && !strings.Contains(err.Error(), "_inttotime") {
			t.Errorf("ValidateParams(%v) error does not name the param: %v", p, err)
		}
	}

	allow := []map[string]string{
		{"_texttotime": "0"},
		{"_texttotime": "false"},
		{"_inttotime": "False"},
		{"_texttotime": ""},              // empty is inert to the driver, so inert here
		{"_texttotime": "maybe"},         // not a bool: the driver rejects it at connect, not us
		{"_TextToTime": "1"},             // wrong case: url.Values.Get never matches it
		{"_pragma": "journal_mode(WAL)"}, // unrelated
		{},
		nil,
	}
	for _, p := range allow {
		if err := (dialect{}).ValidateParams(p); err != nil {
			t.Errorf("ValidateParams(%v) refused an inert value: %v", p, err)
		}
	}
}

// TestBuildDSNRefusesEnabledTimeConversion pins the defense-in-depth check:
// reached directly (a runtime-supplied param bypassing config validation),
// BuildDSN still refuses an enabled conversion rather than producing a DSN that
// would corrupt the fidelity the rest of TableX assumes.
func TestBuildDSNRefusesEnabledTimeConversion(t *testing.T) {
	_, err := dialect{}.BuildDSN(driver.ConnParams{FilePath: ":memory:", Params: map[string]string{"_inttotime": "1"}})
	if err == nil {
		t.Fatal("BuildDSN accepted an enabled _inttotime, want refusal")
	}
	if !strings.Contains(err.Error(), "_inttotime") {
		t.Errorf("BuildDSN error should name the offending param: %v", err)
	}

	// A disabled value still builds a DSN.
	if _, err := (dialect{}).BuildDSN(driver.ConnParams{FilePath: ":memory:", Params: map[string]string{"_inttotime": "false"}}); err != nil {
		t.Errorf("BuildDSN refused a disabled _inttotime: %v", err)
	}
}
