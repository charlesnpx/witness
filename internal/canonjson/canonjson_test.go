package canonjson_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"witness/internal/canonjson"
	"witness/internal/strictjson"
)

func TestMarshalIsDeterministicAndNormalizesStrings(t *testing.T) {
	value := map[string]any{
		"z": "<tag>&value",
		"a": []any{json.Number("1.00e2"), "line\nnext", "\u2028", "\u2029"},
	}
	first, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical output changed: %q != %q", first, second)
	}
	want := `{"a":[1e2,"line\nnext","\u2028","\u2029"],"z":"<tag>&value"}`
	if string(first) != want {
		t.Fatalf("canonical = %s, want %s", first, want)
	}
}

func TestEquivalentNumbersShareCanonicalForm(t *testing.T) {
	for _, raw := range []string{"1", "1.0", "1e0", "10e-1"} {
		value, err := strictjson.DecodeAnyBytes([]byte(raw), strictjson.DefaultMaxBytes)
		if err != nil {
			t.Fatalf("%s strict decode: %v", raw, err)
		}
		encoded, err := canonjson.Marshal(value)
		if err != nil {
			t.Fatalf("%s canonical: %v", raw, err)
		}
		if string(encoded) != "1" {
			t.Fatalf("%s canonical = %s, want 1", raw, encoded)
		}
	}
}

func TestMarshalRoundTripKeepsJSONShape(t *testing.T) {
	type sample struct {
		Name   string         `json:"name"`
		Counts map[string]int `json:"counts"`
	}
	encoded, err := canonjson.Marshal(sample{
		Name:   "stable",
		Counts: map[string]int{"b": 2, "a": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"counts":{"a":1,"b":2},"name":"stable"}` {
		t.Fatalf("canonical = %s", encoded)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("canonical output is not JSON: %v", err)
	}
}
