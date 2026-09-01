package review

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
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
			if testCase.Strict == "fail" {
				if strictErr == nil {
					t.Fatal("strict decoder accepted a fixture expected to fail")
				}
				return
			}
			if strictErr != nil {
				t.Fatalf("strict decode: %v", strictErr)
			}

			schemaData, err := DefaultReviewerSchema(frozen, testCase.ExpectedInputDigest, testCase.ExpectedConsumerIdentity)
			if err != nil {
				t.Fatalf("DefaultReviewerSchema: %v", err)
			}
			schemaErr := validateConformanceSchema(schemaData, data)
			if testCase.Schema == "pass" && schemaErr != nil {
				t.Fatalf("default reviewer schema rejected a fixture expected to pass: %v", schemaErr)
			}
			if testCase.Schema == "fail" && schemaErr == nil {
				t.Fatal("default reviewer schema accepted a fixture expected to fail")
			}

			_, validationErr := DecodeAndValidateReviewReport(data, frozen, testCase.ExpectedInputDigest)
			if testCase.Semantic == "pass" && validationErr != nil {
				t.Fatalf("DecodeAndValidateReviewReport: %v", validationErr)
			}
			if testCase.Semantic == "fail" && validationErr == nil {
				t.Fatal("DecodeAndValidateReviewReport accepted a fixture expected to fail semantic validation")
			}
		})
	}
}

func validateConformanceSchema(schemaData []byte, data []byte) error {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
	if err != nil {
		return err
	}
	if err := compiler.AddResource("https://witness.invalid/review-report-v1.schema.json", schema); err != nil {
		return err
	}
	compiled, err := compiler.Compile("https://witness.invalid/review-report-v1.schema.json")
	if err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return compiled.Validate(instance)
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
