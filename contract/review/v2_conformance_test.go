package review

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/strictjson"
)

type reviewV2ConformanceManifest struct {
	Cases []reviewV2ConformanceCase `json:"cases"`
}

type reviewV2ConformanceCase struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	File  string `json:"file"`
	Valid bool   `json:"valid"`
}

type reviewV2CompletionFixture struct {
	RequestDigest         string                  `json:"request_digest"`
	Adapter               string                  `json:"adapter"`
	RequiredReportDigests map[string]string       `json:"required_report_digests"`
	ObservedExecution     ObservedReviewExecution `json:"observed_execution"`
	Verdict               string                  `json:"verdict"`
}

func TestReviewV2ConformanceCorpus(t *testing.T) {
	manifestData, err := ConformanceFS.ReadFile("testdata/conformance/v2-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[reviewV2ConformanceManifest](manifestData, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 8 {
		t.Fatalf("v2 conformance cases = %d, want 8 behavioral partitions", len(manifest.Cases))
	}
	frozen := v2ConformanceFrozenCharter(t)
	requestData, err := ConformanceFS.ReadFile("testdata/conformance/v2-valid-request.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeAndValidateReviewRequestV2(requestData)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range manifest.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			data, err := ConformanceFS.ReadFile("testdata/conformance/" + testCase.File)
			if err != nil {
				t.Fatal(err)
			}
			switch testCase.Kind {
			case "request":
				testReviewV2RequestCase(t, data, testCase.Valid)
			case "report":
				_, validationErr := DecodeAndValidateReviewReportV2(data, request, frozen)
				if testCase.Valid && validationErr != nil {
					t.Fatalf("DecodeAndValidateReviewReportV2: %v", validationErr)
				}
				if !testCase.Valid && validationErr == nil {
					t.Fatal("DecodeAndValidateReviewReportV2 accepted an invalid v2 report")
				}
			case "completion":
				testReviewV2CompletionCase(t, data, request, testCase.Valid)
			case "v1-report":
				_, validationErr := DecodeAndValidateReviewReportV2(data, request, frozen)
				if validationErr == nil {
					t.Fatal("DecodeAndValidateReviewReportV2 accepted a v1 report")
				}
				if !bytes.Contains([]byte(validationErr.Error()), []byte(ReviewReportV1)) || !bytes.Contains([]byte(validationErr.Error()), []byte(ReviewReportV2)) {
					t.Fatalf("version mismatch error = %v, want both report versions named", validationErr)
				}
			default:
				t.Fatalf("unsupported v2 conformance kind %q", testCase.Kind)
			}
		})
	}
}

func v2ConformanceFrozenCharter(t *testing.T) charter.FrozenCharter {
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

func testReviewV2RequestCase(t *testing.T, data []byte, valid bool) {
	t.Helper()
	document, err := strictjson.DecodeBytes[ReviewRequestV2Document](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	validationErr := RequireValidReviewRequestV2(document)
	if !valid {
		if validationErr == nil {
			t.Fatal("invalid v2 request passed validation")
		}
		return
	}
	if validationErr != nil {
		t.Fatalf("RequireValidReviewRequestV2: %v", validationErr)
	}
	firstDigest, err := ReviewRequestV2Digest(document)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, err := DecodeAndValidateReviewRequestV2(encoded)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	secondDigest, err := ReviewRequestV2Digest(roundTripped)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("request digest changed after round-trip: %q != %q", firstDigest, secondDigest)
	}
	if firstDigest != "sha256:8c4d9e039f602d9896c77c2687fedb3f681c9243f9ec5063193de423d4cfa39c" {
		t.Fatalf("request digest = %q, want stable conformance digest", firstDigest)
	}
}

func testReviewV2CompletionCase(t *testing.T, data []byte, request ReviewRequestV2Document, valid bool) {
	t.Helper()
	fixture, err := strictjson.DecodeBytes[reviewV2CompletionFixture](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewHostExecutionEvidence(fixture.ObservedExecution)
	if err != nil {
		t.Fatal(err)
	}
	document := ReviewCompletionDocument{
		SchemaVersion:         ReviewCompletionV1,
		RequestDigest:         fixture.RequestDigest,
		Adapter:               fixture.Adapter,
		RequiredReportDigests: fixture.RequiredReportDigests,
		ExecutionEvidence:     evidence,
		Verdict:               fixture.Verdict,
	}
	validationErr := RequireValidReviewCompletion(document, request)
	if valid && validationErr != nil {
		t.Fatalf("RequireValidReviewCompletion: %v", validationErr)
	}
	if !valid && validationErr == nil {
		t.Fatal("invalid completion passed validation")
	}
}
