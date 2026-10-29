package review

import (
	"encoding/json"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
)

func TestReviewReportV2SchemaAndPromptExample(t *testing.T) {
	frozen := v2ConformanceFrozenCharter(t)
	requestBytes, err := ConformanceFS.ReadFile("testdata/conformance/v2-valid-request.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeAndValidateReviewRequestV2(requestBytes)
	if err != nil {
		t.Fatalf("DecodeAndValidateReviewRequestV2: %v", err)
	}

	for _, reviewer := range []string{RoleDefect, RoleEconomy} {
		t.Run(reviewer, func(t *testing.T) {
			schema, err := ReviewReportV2Schema(request, frozen, reviewer)
			if err != nil {
				t.Fatalf("ReviewReportV2Schema: %v", err)
			}
			example, err := ReviewReportV2PromptExample(request, frozen, reviewer)
			if err != nil {
				t.Fatalf("ReviewReportV2PromptExample: %v", err)
			}
			var exampleReport ReviewReportV2Document
			if err := json.Unmarshal(example, &exampleReport); err != nil {
				t.Fatalf("decode prompt example: %v", err)
			}
			if err := RequireValidReviewReportV2(exampleReport, request, frozen); err != nil {
				t.Fatalf("validate prompt example: %v", err)
			}
			if err := validateConformanceSchema(schema, example); err != nil {
				t.Fatalf("generation schema rejected prompt example: %v", err)
			}

			report := validReviewReportV2ForSchema(t, request, frozen, reviewer)
			reportBytes, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateConformanceSchema(schema, reportBytes); err != nil {
				t.Fatalf("generation schema rejected valid report: %v", err)
			}
			if err := RequireValidReviewReportV2(report, request, frozen); err != nil {
				t.Fatalf("valid report failed typed validation: %v", err)
			}
		})
	}

	defectSchema, err := ReviewReportV2Schema(request, frozen, RoleDefect)
	if err != nil {
		t.Fatal(err)
	}
	invalid := validReviewReportV2ForSchema(t, request, frozen, RoleDefect)
	invalidBytes, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	var invalidObject map[string]json.RawMessage
	if err := json.Unmarshal(invalidBytes, &invalidObject); err != nil {
		t.Fatal(err)
	}
	invalidObject["findings"] = json.RawMessage(`[{}]`)
	invalidBytes, err = json.Marshal(invalidObject)
	if err != nil {
		t.Fatal(err)
	}

	// The former workflow schema described findings only as an array, so it
	// admitted [{}]. The shared schema rejects that structurally invalid finding.
	legacyFindingsSchema := []byte(`{"type":"object","properties":{"findings":{"type":"array"}}}`)
	if err := validateConformanceSchema(legacyFindingsSchema, invalidBytes); err != nil {
		t.Fatalf("legacy findings schema rejected previously admitted report: %v", err)
	}
	if err := validateConformanceSchema(defectSchema, invalidBytes); err == nil {
		t.Fatal("shared generation schema accepted findings containing an empty object")
	}
}

func validReviewReportV2ForSchema(t *testing.T, request ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) ReviewReportV2Document {
	t.Helper()
	requestDigest, err := ReviewRequestV2Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	goalIDs := []string{frozen.Charter.Goals[0].ID}
	finding := ReviewReportV2Finding{
		ID:              "schema-example",
		Kind:            FindingKindDefect,
		Title:           "A representative supported finding.",
		ClaimedSeverity: SeverityLow,
		Attribution:     FindingAttributionIntroduced,
		CharterGoalIDs:  append([]string(nil), goalIDs...),
		Witness: ReportWitness{
			Kind:     WitnessKindDefect,
			Strength: WitnessStrengthArgued,
			Content:  "A concrete failure path established by inspection.",
		},
	}
	if reviewer == RoleEconomy {
		finding.Kind = FindingKindEconomy
		finding.Witness.Kind = WitnessKindEquivalence
		finding.Witness.Content = "The removed branch duplicates the documented response path."
		finding.Remedy = &ReportRemedy{
			Direction:          RemedyDirectionRemove,
			Summary:            "Remove the duplicate branch.",
			MinimalityArgument: "Only the redundant branch is removed.",
		}
		finding.EconomyEquivalence = &EconomyEquivalenceEvidence{
			PreservedBehavior: "The documented response path remains available.",
			CharterGoalIDs:    append([]string(nil), goalIDs...),
		}
	}
	return ReviewReportV2Document{
		SchemaVersion:     ReviewReportV2,
		RequestDigest:     requestDigest,
		RecipeDigest:      request.RecipeDigest,
		Reviewer:          reviewer,
		CharterHash:       frozen.CharterHash,
		ReviewInputDigest: request.ReviewInputDigest,
		SourceIdentity:    ReviewReportV2SourceIdentity(request),
		ConsumerIdentity:  request.ConsumerIdentity,
		Findings:          []ReviewReportV2Finding{finding},
		Evaluation: &ReportEvaluation{
			EvaluatedPaths:   []string{"api/response.go"},
			EvaluatedGoalIDs: goalIDs,
		},
	}
}
