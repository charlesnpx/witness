package review

import (
	"embed"
	"fmt"

	"github.com/charlesnpx/witness/contract/strictjson"
)

// ConformanceFS contains review-report-v1 conformance fixtures and their
// manifest. Consumers may use it without relying on a repository checkout.
//
//go:embed testdata/conformance
var ConformanceFS embed.FS

// ConformanceCase identifies a fixture and its expected outcomes by validation
// layer. Schema outcomes are consumed by the delegate repository.
type ConformanceCase struct {
	File                     string         `json:"file"`
	Strict                   string         `json:"strict"`
	Schema                   string         `json:"schema"`
	Semantic                 string         `json:"semantic"`
	ExpectedInputDigest      string         `json:"expected_input_digest"`
	ExpectedConsumerIdentity map[string]any `json:"expected_consumer_identity"`
}

type conformanceManifest struct {
	Cases []ConformanceCase `json:"cases"`
}

// LoadConformanceManifest reads the embedded corpus manifest.
func LoadConformanceManifest() ([]ConformanceCase, error) {
	data, err := ConformanceFS.ReadFile("testdata/conformance/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read conformance manifest: %w", err)
	}
	manifest, err := strictjson.DecodeBytes[conformanceManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("decode conformance manifest: %w", err)
	}
	if len(manifest.Cases) == 0 {
		return nil, fmt.Errorf("conformance manifest has no cases")
	}
	for index, testCase := range manifest.Cases {
		if testCase.File == "" {
			return nil, fmt.Errorf("conformance case %d has no file", index)
		}
		if !conformancePassFail(testCase.Strict) {
			return nil, fmt.Errorf("conformance case %q has unsupported strict outcome %q", testCase.File, testCase.Strict)
		}
		if !conformancePassFail(testCase.Schema) {
			return nil, fmt.Errorf("conformance case %q has unsupported schema outcome %q", testCase.File, testCase.Schema)
		}
		if testCase.Strict == "fail" {
			if testCase.Semantic != "n/a" {
				return nil, fmt.Errorf("conformance case %q must mark semantic outcome n/a after strict failure", testCase.File)
			}
		} else if !conformancePassFail(testCase.Semantic) {
			return nil, fmt.Errorf("conformance case %q has unsupported semantic outcome %q", testCase.File, testCase.Semantic)
		}
		if !validDigest(testCase.ExpectedInputDigest) {
			return nil, fmt.Errorf("conformance case %q has invalid expected_input_digest", testCase.File)
		}
		if _, _, err := defaultReviewerConsumerIdentity(testCase.ExpectedConsumerIdentity); err != nil {
			return nil, fmt.Errorf("conformance case %q has invalid expected_consumer_identity: %w", testCase.File, err)
		}
	}
	return manifest.Cases, nil
}

func conformancePassFail(outcome string) bool {
	return outcome == "pass" || outcome == "fail"
}
