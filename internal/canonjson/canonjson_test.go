package canonjson_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/strictjson"
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
	want := `{"a":[100,"line\nnext","\u2028","\u2029"],"z":"<tag>&value"}`
	if string(first) != want {
		t.Fatalf("canonical = %s, want %s", first, want)
	}
}

func TestMarshalUsesPlainSafeIntegerNotation(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{raw: "0", want: "0"},
		{raw: "20", want: "20"},
		{raw: "2578", want: "2578"},
		{raw: "-7", want: "-7"},
		{raw: "1.25", want: "1.25"},
		{raw: "9007199254740991", want: "9007199254740991"},
		{raw: "-9007199254740991", want: "-9007199254740991"},
		{raw: "9007199254740992", want: "9.007199254740992e15"},
		{raw: "9007199254740993", want: "9.007199254740993e15"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			value, err := strictjson.DecodeAnyBytes([]byte(test.raw), strictjson.DefaultMaxBytes)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			encoded, err := canonjson.Marshal(value)
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			if got := string(encoded); got != test.want {
				t.Fatalf("canonical = %s, want %s", got, test.want)
			}
		})
	}
}

func TestEquivalentSafeIntegerSpellingsShareCanonicalForm(t *testing.T) {
	for _, raw := range []string{"20", "2e1", "20.0", "0.2e2"} {
		value, err := strictjson.DecodeAnyBytes([]byte(raw), strictjson.DefaultMaxBytes)
		if err != nil {
			t.Fatalf("%s strict decode: %v", raw, err)
		}
		encoded, err := canonjson.Marshal(value)
		if err != nil {
			t.Fatalf("%s canonical: %v", raw, err)
		}
		if got := string(encoded); got != "20" {
			t.Fatalf("%s canonical = %s, want 20", raw, got)
		}
	}
}

func TestMarshalDiagnosticOffsetUsesIntegerNotation(t *testing.T) {
	encoded, err := canonjson.Marshal(diag.Diagnostic{
		Code:    "invalid_json",
		Message: "JSON input is not syntactically valid.",
		Details: map[string]any{"offset": 2609},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"code":"invalid_json","details":{"offset":2609},"message":"JSON input is not syntactically valid."}`
	if got := string(encoded); got != want {
		t.Fatalf("canonical = %s, want %s", got, want)
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
