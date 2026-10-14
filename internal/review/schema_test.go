package review

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/digest"
	contractreview "github.com/charlesnpx/witness/contract/review"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestReviewerSchemaRejectsObservedMalformedReport(t *testing.T) {
	request, frozen, valid := reviewerSchemaTestReport(t)
	schema := compileReviewerTestSchema(t, request, frozen, valid.Reviewer)
	data, err := os.ReadFile("testdata/u1-fixture-rejected-report.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture := reviewerTestJSONObject(t, data)
	bindings := reviewerTestJSONObject(t, marshalReviewerTestJSON(t, valid))
	for _, field := range []string{"schema_version", "request_digest", "recipe_digest", "reviewer", "charter_hash", "review_input_digest", "source_identity", "consumer_identity"} {
		fixture[field] = bindings[field]
	}
	// Preserve the observed malformed fields; rebind only identities and goals.
	fixture["findings"].([]any)[0].(map[string]any)["goal_ids"] = []string{frozen.Charter.Goals[0].ID}
	fixture["evaluation"].(map[string]any)["evaluated_goal_ids"] = []string{frozen.Charter.Goals[0].ID}
	fixture = reviewerTestJSONObject(t, marshalReviewerTestJSON(t, fixture))
	validationErr := schema.Validate(fixture)
	if validationErr == nil {
		t.Fatal("schema accepted the observed malformed report")
	}
	for _, path := range []string{"/findings", "/evaluation"} {
		if !strings.Contains(validationErr.Error(), path) {
			t.Errorf("schema violations do not mention %s: %v", path, validationErr)
		}
	}
	violations, ok := validationErr.(*jsonschema.ValidationError)
	if !ok {
		t.Fatalf("expected schema violations, got %T: %v", validationErr, validationErr)
	}
	var checkLocations func(*jsonschema.ValidationError)
	checkLocations = func(violation *jsonschema.ValidationError) {
		if len(violation.Causes) == 0 {
			location := violation.InstanceLocation
			if len(location) == 0 || (location[0] != "findings" && location[0] != "evaluation") {
				t.Errorf("fixture failed outside findings and evaluation: %v", violation)
			}
		}
		for _, cause := range violation.Causes {
			checkLocations(cause)
		}
	}
	checkLocations(violations)
	t.Logf("observed fixture violations: %v", validationErr)
	assertReviewerAdapterValidation(t, request, frozen, valid.Reviewer, fixture, false)
}

func TestReviewerSchemaAcceptsValidReports(t *testing.T) {
	request, frozen, report := reviewerSchemaTestReport(t)
	schema := compileReviewerTestSchema(t, request, frozen, report.Reviewer)
	data := marshalReviewerTestJSON(t, report)
	cases := []struct {
		name    string
		changes []reviewerReportChange
	}{
		{name: "all nested fields"},
		{"constructed at high cap", []reviewerReportChange{
			{path: "/findings/0/witness/strength", value: contractreview.WitnessStrengthConstructed},
			{path: "/findings/0/witness/executable", omit: true},
			{path: "/findings/0/claimed_severity", value: contractreview.SeverityHigh},
		}},
		{"argued at medium cap", []reviewerReportChange{
			{path: "/findings/0/witness/strength", value: contractreview.WitnessStrengthArgued},
			{path: "/findings/0/witness/executable", omit: true},
			{path: "/findings/0/claimed_severity", value: contractreview.SeverityMedium},
		}},
		{"argued at low severity", []reviewerReportChange{{path: "/findings/1/claimed_severity", value: contractreview.SeverityLow}}},
		{"unbound defect", []reviewerReportChange{{path: "/findings/0/charter_goal_ids", value: []string{}}}},
		{"empty findings", []reviewerReportChange{
			{path: "/findings", value: []any{}}, {path: "/missing_goal_questions", omit: true},
		}},
		{"optional fields omitted", []reviewerReportChange{
			{path: "/findings/0/annotation", omit: true}, {path: "/findings/0/remedy", omit: true},
			{path: "/findings/0/witness/executable/transformation_ref", omit: true},
			{path: "/findings/1/remedy", omit: true}, {path: "/missing_goal_questions", omit: true},
		}},
		{"optional nulls", []reviewerReportChange{
			{path: "/findings/0/annotation", value: nil}, {path: "/findings/0/remedy", value: nil},
			{path: "/findings/0/economy_equivalence", value: nil},
			{path: "/findings/0/witness/executable/transformation_ref", value: nil},
			{path: "/findings/1/witness/executable", value: nil}, {path: "/missing_goal_questions", value: nil},
		}},
		{"optional scalar nulls", []reviewerReportChange{
			{path: "/findings/0/witness/executable/transformation_ref/digest_profile", value: nil},
			{path: "/findings/0/witness/executable/transformation_ref/media_type", value: nil},
			{path: "/missing_goal_questions/0/anchor_index", value: nil}, {path: "/missing_goal_questions/0/value", value: nil},
		}},
		{"optional scalar defaults", []reviewerReportChange{
			{path: "/findings/0/witness/executable/transformation_ref/digest_profile", value: ""},
			{path: "/findings/0/witness/executable/transformation_ref/media_type", value: ""},
			{path: "/missing_goal_questions/0/anchor_index", omit: true}, {path: "/missing_goal_questions/0/value", value: ""},
			{path: "/findings/0/annotation", value: map[string]any{}},
		}},
		{"defect removal with equivalence evidence", []reviewerReportChange{
			{path: "/findings/0/remedy/direction", value: contractreview.RemedyDirectionRemove},
			{path: "/findings/0/economy_equivalence", value: report.Findings[1].EconomyEquivalence},
		}},
		{"economy executable needs no transformation reference", []reviewerReportChange{
			{path: "/findings/1/witness/strength", value: contractreview.WitnessStrengthExecutable},
			{path: "/findings/1/witness/executable", value: &contractreview.ExecutableSpec{
				Argv: []string{"test", "equivalence"}, CWD: ".", ExpectedObservation: "Both paths preserve the declared behavior.",
			}},
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			instance := reviewerTestJSONObject(t, data)
			changeReviewerTestReport(t, instance, test.changes)
			// Decode again so inserted contract structs become JSON objects.
			instance = reviewerTestJSONObject(t, marshalReviewerTestJSON(t, instance))
			if err := schema.Validate(instance); err != nil {
				t.Fatalf("schema rejected valid report: %v", err)
			}
			assertReviewerAdapterValidation(t, request, frozen, report.Reviewer, instance, true)
		})
	}
}

func TestReviewerSchemaRejectsContractViolations(t *testing.T) {
	request, frozen, report := reviewerSchemaTestReport(t)
	schema := compileReviewerTestSchema(t, request, frozen, report.Reviewer)
	data := marshalReviewerTestJSON(t, report)
	cases := []struct {
		name    string
		changes []reviewerReportChange
	}{
		{"argued above severity cap", []reviewerReportChange{
			{path: "/findings/0/witness/strength", value: contractreview.WitnessStrengthArgued},
			{path: "/findings/0/witness/executable", omit: true},
			{path: "/findings/0/claimed_severity", value: contractreview.SeverityHigh},
		}},
		{"constructed above severity cap", []reviewerReportChange{
			{path: "/findings/0/witness/strength", value: contractreview.WitnessStrengthConstructed},
			{path: "/findings/0/witness/executable", omit: true},
		}},
		{"economy without equivalence evidence", []reviewerReportChange{
			{path: "/findings/1/economy_equivalence", omit: true}, {path: "/findings/1/remedy", omit: true},
		}},
		{"economy null equivalence evidence", []reviewerReportChange{
			{path: "/findings/1/economy_equivalence", value: nil}, {path: "/findings/1/remedy", omit: true},
		}},
		{"remove without equivalence evidence", []reviewerReportChange{{path: "/findings/0/remedy/direction", value: contractreview.RemedyDirectionRemove}}},
		{"economy with defect witness", []reviewerReportChange{{path: "/findings/1/witness/kind", value: contractreview.WitnessKindDefect}}},
		{"defect with equivalence witness", []reviewerReportChange{{path: "/findings/0/witness/kind", value: contractreview.WitnessKindEquivalence}}},
		{"undeclared finding goal", []reviewerReportChange{{path: "/findings/0/charter_goal_ids", value: []string{"undeclared-goal"}}}},
		{"undeclared equivalence goal", []reviewerReportChange{{path: "/findings/1/economy_equivalence/charter_goal_ids", value: []string{"undeclared-goal"}}}},
		{"empty equivalence goals", []reviewerReportChange{{path: "/findings/1/economy_equivalence/charter_goal_ids", value: []string{}}}},
		{"duplicate equivalence goals", []reviewerReportChange{{path: "/findings/1/economy_equivalence/charter_goal_ids", value: []string{frozen.Charter.Goals[0].ID, frozen.Charter.Goals[0].ID}}}},
		{"executable strength without specification", []reviewerReportChange{{path: "/findings/0/witness/executable", omit: true}}},
		{"executable strength with null specification", []reviewerReportChange{{path: "/findings/0/witness/executable", value: nil}}},
		{"specification with argued strength", []reviewerReportChange{
			{path: "/findings/0/witness/strength", value: contractreview.WitnessStrengthArgued},
			{path: "/findings/0/claimed_severity", value: contractreview.SeverityMedium},
		}},
		{"empty argv", []reviewerReportChange{{path: "/findings/0/witness/executable/argv", value: []string{}}}},
		{"blank argv entry", []reviewerReportChange{{path: "/findings/0/witness/executable/argv", value: []string{"test", " "}}}},
		{"invalid artifact digest", []reviewerReportChange{{path: "/findings/0/witness/executable/transformation_ref/digest", value: "invalid"}}},
		{"invalid artifact digest profile", []reviewerReportChange{{path: "/findings/0/witness/executable/transformation_ref/digest_profile", value: "other-profile"}}},
		{"annotation line without path", []reviewerReportChange{{path: "/findings/0/annotation/path", omit: true}}},
		{"annotation line overflow", []reviewerReportChange{{path: "/findings/0/annotation/line", value: uint64(1 << 32)}}},
		{"invalid question dimension", []reviewerReportChange{{path: "/missing_goal_questions/0/dimension", value: "other-dimension"}}},
		{"negative question anchor", []reviewerReportChange{{path: "/missing_goal_questions/0/anchor_index", value: -1}}},
		{"empty evaluated paths", []reviewerReportChange{{path: "/evaluation/evaluated_paths", value: []string{}}}},
		{"invalid evaluated path", []reviewerReportChange{{path: "/evaluation/evaluated_paths", value: []string{" "}}}},
		{"empty evaluated goals", []reviewerReportChange{{path: "/evaluation/evaluated_goal_ids", value: []string{}}}},
		{"undeclared evaluated goal", []reviewerReportChange{{path: "/evaluation/evaluated_goal_ids", value: []string{"undeclared-goal"}}}},
	}
	for _, path := range []string{
		"", "/source_identity", "/consumer_identity", "/findings/0", "/findings/0/witness",
		"/findings/0/witness/executable", "/findings/0/witness/executable/transformation_ref",
		"/findings/0/annotation", "/findings/0/remedy", "/findings/1/economy_equivalence", "/evaluation", "/missing_goal_questions/0",
	} {
		cases = append(cases, struct {
			name    string
			changes []reviewerReportChange
		}{"unknown field at " + path, []reviewerReportChange{{path: path + "/unknown", value: "unexpected"}}})
	}
	for _, field := range []string{"id", "kind", "title", "claimed_severity", "attribution", "charter_goal_ids", "witness"} {
		cases = append(cases, struct {
			name    string
			changes []reviewerReportChange
		}{"missing finding " + field, []reviewerReportChange{{path: "/findings/0/" + field, omit: true}}})
	}
	for _, path := range []string{
		"/findings/0/title", "/findings/0/witness/content", "/findings/0/witness/executable/cwd",
		"/findings/0/witness/executable/expected_observation", "/findings/0/annotation/path",
		"/findings/0/remedy/summary", "/findings/0/remedy/minimality_argument",
		"/findings/1/economy_equivalence/preserved_behavior", "/missing_goal_questions/0/property",
		"/missing_goal_questions/0/affected_decision", "/missing_goal_questions/0/statement",
	} {
		cases = append(cases, struct {
			name    string
			changes []reviewerReportChange
		}{"blank " + path, []reviewerReportChange{{path: path, value: " \t\n\u0085\u00a0\u2003\u2028\u3000"}}})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			instance := reviewerTestJSONObject(t, data)
			changeReviewerTestReport(t, instance, test.changes)
			instance = reviewerTestJSONObject(t, marshalReviewerTestJSON(t, instance))
			if err := schema.Validate(instance); err == nil {
				t.Fatal("schema accepted invalid report")
			}
			assertReviewerAdapterValidation(t, request, frozen, report.Reviewer, instance, false)
		})
	}
}

func TestReviewerSchemaWithoutCharterGoals(t *testing.T) {
	request, frozen, _ := testRunInputs(t)
	_, _, report := reviewerSchemaTestReport(t)
	report.RequestDigest = mustRequestDigest(request)
	report.CharterHash = frozen.CharterHash
	report.Findings = report.Findings[:1]
	report.Findings[0].CharterGoalIDs = []string{}
	report.Evaluation.EvaluatedGoalIDs = []string{}
	schema := compileReviewerTestSchema(t, request, frozen, report.Reviewer)
	instance := reviewerTestJSONObject(t, marshalReviewerTestJSON(t, report))
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema rejected a report for a Charter without goals: %v", err)
	}
	assertReviewerAdapterValidation(t, request, frozen, report.Reviewer, instance, true)
}

type reviewerReportChange struct {
	path  string
	value any
	omit  bool
}

func changeReviewerTestReport(t *testing.T, report map[string]any, changes []reviewerReportChange) {
	t.Helper()
	for _, change := range changes {
		parts := strings.Split(strings.TrimPrefix(change.path, "/"), "/")
		var current any = report
		for _, part := range parts[:len(parts)-1] {
			switch node := current.(type) {
			case map[string]any:
				current = node[part]
			case []any:
				index, err := strconv.Atoi(part)
				if err != nil || index < 0 || index >= len(node) {
					t.Fatalf("invalid test path %q", change.path)
				}
				current = node[index]
			default:
				t.Fatalf("invalid test path %q at %q", change.path, part)
			}
		}
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("test path %q has no parent object", change.path)
		}
		field := parts[len(parts)-1]
		if change.omit {
			delete(object, field)
		} else {
			object[field] = change.value
		}
	}
}

func compileReviewerTestSchema(t *testing.T, request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) *jsonschema.Schema {
	t.Helper()
	data, err := reviewerSchema(request, frozen, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := document.(map[string]any)["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema dialect = %v, want Draft 2020-12", got)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const resource = "https://witness.invalid/reviewer.schema.json"
	if err := compiler.AddResource(resource, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("compile reviewer schema: %v", err)
	}
	return schema
}

func marshalReviewerTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func reviewerTestJSONObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func assertReviewerAdapterValidation(t *testing.T, request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string, instance any, valid bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, marshalReviewerTestJSON(t, instance), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size := artifactMetadata(t, path)
	record := jobRecord{
		Result:   &jobResult{ResultPath: path, SHA256: sum, Bytes: int64(size), MetadataComplete: true},
		Contract: &jobContract{Evaluated: true, EvaluatedPresent: true, Compliant: true, CompliantPresent: true},
	}
	status, report, reportDigest, available, _, err := validateObservedReport(record, request, frozen, reviewer)
	if !available {
		t.Fatalf("adapter could not read test report: %v", err)
	}
	if valid {
		if err != nil || status != contractreview.ExecutionReportValid || report == nil || reportDigest == "" {
			t.Fatalf("adapter rejected valid report: status=%s, report=%v, digest=%q, err=%v", status, report, reportDigest, err)
		}
	} else if err == nil || status != contractreview.ExecutionReportInvalid || report != nil {
		t.Fatalf("adapter accepted invalid report: status=%s, report=%v, err=%v", status, report, err)
	}
}

func reviewerSchemaTestReport(t *testing.T) (contractreview.ReviewRequestV2Document, charter.FrozenCharter, contractreview.ReviewReportV2Document) {
	t.Helper()
	request, _, _ := testRunInputs(t)
	input := charter.InitSkeleton("owner", "initial", "Schema test Charter")
	input.Goals = []charter.Statement{{ID: "preserve-behavior", Statement: "Preserve the declared behavior."}}
	frozen, err := charter.Freeze(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.CharterHash = frozen.CharterHash
	if err := contractreview.RequireValidReviewRequestV2(request); err != nil {
		t.Fatal(err)
	}
	goalIDs := []string{frozen.Charter.Goals[0].ID}
	report := contractreview.ReviewReportV2Document{
		SchemaVersion:     contractreview.ReviewReportV2,
		RequestDigest:     mustRequestDigest(request),
		RecipeDigest:      request.RecipeDigest,
		Reviewer:          contractreview.RoleEconomy,
		CharterHash:       frozen.CharterHash,
		ReviewInputDigest: request.ReviewInputDigest,
		SourceIdentity:    sourceIdentityForRequest(request),
		ConsumerIdentity:  request.ConsumerIdentity,
		Findings: []contractreview.ReviewReportV2Finding{
			{
				ID: "defect-001", Kind: contractreview.FindingKindDefect, Title: "The route accepts an invalid request",
				ClaimedSeverity: contractreview.SeverityCritical, Attribution: contractreview.FindingAttributionIntroduced,
				CharterGoalIDs: goalIDs,
				Witness: contractreview.ReportWitness{
					Kind: contractreview.WitnessKindDefect, Strength: contractreview.WitnessStrengthExecutable,
					Content: "The regression test demonstrates the invalid request reaching the handler.",
					Executable: &contractreview.ExecutableSpec{
						Argv: []string{"go", "test", "./handler"}, CWD: ".", ExpectedObservation: "The invalid request is rejected.",
						TransformationRef: &contractreview.ArtifactRef{
							Kind: "patch", ID: "route-regression", Digest: digest.RawBytes([]byte("test patch")),
							DigestProfile: digest.Profile, MediaType: "text/x-diff",
						},
					},
				},
				Annotation: &contractreview.FindingAnnotation{Path: "handler.go", Line: 12, Category: "correctness"},
				Remedy: &contractreview.ReportRemedy{
					Direction: contractreview.RemedyDirectionChange, Summary: "Validate the request before routing it.",
					MinimalityArgument: "One guard restores the declared boundary.",
				},
			},
			{
				ID: "economy-001", Kind: contractreview.FindingKindEconomy, Title: "A duplicate guard can be removed",
				ClaimedSeverity: contractreview.SeverityMedium, Attribution: contractreview.FindingAttributionPreExisting,
				CharterGoalIDs: goalIDs,
				Witness: contractreview.ReportWitness{
					Kind: contractreview.WitnessKindEquivalence, Strength: contractreview.WitnessStrengthArgued,
					Content: "The earlier guard rejects the same inputs before this branch.",
				},
				Remedy: &contractreview.ReportRemedy{
					Direction: contractreview.RemedyDirectionRemove, Summary: "Remove the duplicate guard.",
					MinimalityArgument: "The earlier guard already performs the required validation.",
				},
				EconomyEquivalence: &contractreview.EconomyEquivalenceEvidence{
					PreservedBehavior: "Invalid requests remain rejected by the earlier guard.", CharterGoalIDs: goalIDs,
				},
			},
		},
		Evaluation: &contractreview.ReportEvaluation{EvaluatedPaths: []string{"handler.go"}, EvaluatedGoalIDs: goalIDs},
		MissingGoalQuestions: []charter.MissingGoalQuestion{{
			ID: "question-001", FindingID: "defect-001", Dimension: charter.DimensionInputSurface, AnchorIndex: 0,
			Property: "maximum request size", Value: "unspecified", AffectedDecision: "request validation",
			Statement: "Which request sizes must the handler accept?",
		}},
	}
	return request, frozen, report
}
