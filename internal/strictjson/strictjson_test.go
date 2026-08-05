package strictjson

import (
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/diag"
)

type fixtureDocument struct {
	Name  string         `json:"name"`
	Child fixtureChild   `json:"child"`
	List  []fixtureChild `json:"list"`
}

type fixtureChild struct {
	N int `json:"n"`
}

func TestStrictJSONFixtures(t *testing.T) {
	valid := `{"name":"ok","child":{"n":1},"list":[{"n":2}]}`
	tests := []struct {
		name string
		data []byte
		max  int64
		mode string
		code string
	}{
		{name: "valid nesting", data: []byte(valid), mode: "document"},
		{name: "root duplicate key", data: []byte(`{"name":"first","name":"second","child":{"n":1},"list":[]}`), mode: "document", code: diag.CodeDuplicateJSONKey},
		{name: "nested duplicate key", data: []byte(`{"name":"ok","child":{"n":1,"n":2},"list":[]}`), mode: "document", code: diag.CodeDuplicateJSONKey},
		{name: "escaped-equivalent duplicate key", data: []byte(`{"a":1,"\u0061":2}`), mode: "map", code: diag.CodeDuplicateJSONKey},
		{name: "trailing value", data: []byte(valid + ` []`), mode: "document", code: diag.CodeTrailingJSONValue},
		{name: "trailing garbage", data: []byte(valid + ` x`), mode: "document", code: diag.CodeTrailingJSONGarbage},
		{name: "invalid UTF-8", data: []byte{'"', 0xff, '"'}, mode: "map", code: diag.CodeInvalidUTF8},
		{name: "unknown field", data: []byte(`{"name":"ok","child":{"n":1},"list":[],"extra":true}`), mode: "document", code: diag.CodeUnknownJSONField},
		{name: "oversized input", data: []byte(valid), max: 8, mode: "document", code: diag.CodeJSONTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := decodeFixture(test.mode, test.data, test.max)
			if test.code == "" {
				if err != nil {
					t.Fatalf("DecodeBytes returned error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("DecodeBytes succeeded, want %s", test.code)
			}
			if got := diag.FromError(err).Code; got != test.code {
				t.Fatalf("diagnostic code = %s, want %s; err=%v", got, test.code, err)
			}
		})
	}
}

func TestStrictJSONLAppliesReaderPerLine(t *testing.T) {
	records, err := DecodeJSONL[fixtureDocument](strings.NewReader(
		`{"name":"one","child":{"n":1},"list":[]}`+"\n"+
			`{"name":"two","child":{"n":2},"list":[]}`+"\n",
	), DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1].Name != "two" {
		t.Fatalf("records = %#v", records)
	}

	_, err = DecodeJSONL[fixtureDocument](strings.NewReader(
		`{"name":"one","child":{"n":1},"list":[]}`+"\n"+
			`{"name":"two","name":"duplicate","child":{"n":2},"list":[]}`+"\n",
	), DefaultMaxBytes)
	if err == nil {
		t.Fatal("duplicate JSONL key was accepted")
	}
	if diagnostic := diag.FromError(err); diagnostic.Code != diag.CodeDuplicateJSONKey || diagnostic.Path != "/2/name" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestInt64AcceptsIntegralJSONNumbers(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Int64
		wantErr bool
	}{
		{name: "plain integer", raw: `2578`, want: 2578},
		{name: "scientific integer", raw: `2.578e3`, want: 2578},
		{name: "negative fractional scientific integer", raw: `-1.5e1`, want: -15},
		{name: "fractional", raw: `2.5`, wantErr: true},
		{name: "out of range", raw: `1e999`, wantErr: true},
		{name: "non number", raw: `"2578"`, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got Int64
			err := got.UnmarshalJSON([]byte(test.raw))
			if test.wantErr {
				if err == nil {
					t.Fatal("UnmarshalJSON succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("value = %d, want %d", got, test.want)
			}
		})
	}
}

func decodeFixture(mode string, data []byte, max int64) error {
	switch mode {
	case "document":
		_, err := DecodeBytes[fixtureDocument](data, max)
		return err
	case "map":
		_, err := DecodeBytes[map[string]any](data, max)
		return err
	default:
		panic(mode)
	}
}
