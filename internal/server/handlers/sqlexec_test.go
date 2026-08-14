package handlers

import (
	"testing"

	"github.com/tablexdev/tablex/internal/model"
)

func modelColumn(base string) model.Column { return model.Column{BaseType: base} }

func TestCoerceValue(t *testing.T) {
	intCol := modelColumn("int")
	if v := coerceValue(intCol, "42"); v != int64(42) {
		t.Errorf("coerceValue int = %v (%T), want int64(42)", v, v)
	}
	if v := coerceValue(intCol, "notanumber"); v != "notanumber" {
		t.Errorf("coerceValue bad int should fall back to string, got %v", v)
	}
	textCol := modelColumn("varchar")
	if v := coerceValue(textCol, "hello"); v != "hello" {
		t.Errorf("coerceValue text = %v", v)
	}
}

func TestEncodeDecodeRowKey(t *testing.T) {
	val := "7"
	entries := []rowKeyEntry{{Col: "id", Val: &val}, {Col: "deleted", Val: nil}}
	token := encodeRowKey(entries)
	back, err := decodeRowKey(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(back) != 2 || back[0].Col != "id" || back[0].Val == nil || *back[0].Val != "7" || back[1].Val != nil {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}
