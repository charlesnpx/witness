package review

import (
	"reflect"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/strictjson"
)

func TestConformanceFrozenCharterHash(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	source := charter.Charter{
		SchemaVersion:       frozen.Charter.SchemaVersion,
		Goals:               frozen.Charter.Goals,
		NonGoals:            frozen.Charter.NonGoals,
		OwnerEvents:         frozen.Charter.OwnerEvents,
		OperationalEnvelope: frozen.Charter.OperationalEnvelope,
	}
	derived, err := charter.Freeze(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.CharterHash != derived.CharterHash {
		t.Fatalf("conformance charter_hash = %q, want real Freeze/Hash result %q", frozen.CharterHash, derived.CharterHash)
	}
	if !reflect.DeepEqual(frozen, derived) {
		t.Fatalf("conformance frozen charter differs from real Freeze result\nfixture: %#v\nderived: %#v", frozen, derived)
	}
}

func TestReviewReportConformance(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	cases, err := LoadConformanceManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases {
		t.Run(testCase.File, func(t *testing.T) {
			data, err := ConformanceFS.ReadFile("testdata/conformance/" + testCase.File)
			if err != nil {
				t.Fatal(err)
			}
			_, strictErr := strictjson.DecodeBytes[ReviewReportDocument](data, strictjson.DefaultMaxBytes)
			_, validationErr := DecodeAndValidateReviewReport(data, frozen)
			switch testCase.Expect {
			case "valid":
				if strictErr != nil {
					t.Fatalf("strict decode: %v", strictErr)
				}
				if validationErr != nil {
					t.Fatalf("DecodeAndValidateReviewReport: %v", validationErr)
				}
			case "strict-syntax":
				if strictErr == nil {
					t.Fatal("strict decoder accepted invalid syntax")
				}
				if validationErr == nil {
					t.Fatal("DecodeAndValidateReviewReport accepted strict-syntax fixture")
				}
			case "json-schema":
				if strictErr != nil {
					t.Fatalf("schema fixture must remain strictly decodable: %v", strictErr)
				}
				if validationErr == nil {
					t.Fatal("json-schema fixture passed silently; semantic fallback must reject it here")
				}
			case "semantic-binding":
				if strictErr != nil {
					t.Fatalf("semantic fixture must remain strictly decodable: %v", strictErr)
				}
				if validationErr == nil {
					t.Fatal("semantic-binding fixture passed validation")
				}
			default:
				t.Fatalf("unsupported manifest expectation %q", testCase.Expect)
			}
		})
	}
}

func conformanceFrozenCharter(t *testing.T) charter.FrozenCharter {
	t.Helper()
	data, err := ConformanceFS.ReadFile("testdata/conformance/charter.json")
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}
