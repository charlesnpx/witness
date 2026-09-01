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

// ConformanceCase identifies a fixture and its authoritative validation layer.
type ConformanceCase struct {
	File   string `json:"file"`
	Expect string `json:"expect"`
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
		switch testCase.Expect {
		case "valid", "strict-syntax", "json-schema", "semantic-binding":
		default:
			return nil, fmt.Errorf("conformance case %q has unsupported expect value %q", testCase.File, testCase.Expect)
		}
	}
	return manifest.Cases, nil
}
