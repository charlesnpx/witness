package review

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/strictjson"
)

func TestReviewRequestDecodeValidateAndDigest(t *testing.T) {
	const request = `{
  "schema_version": "review-request-v1",
  "consumer_identity": {"kind": "delegate", "id": "consumer-a"},
  "subject": {"head": "a1b2c3", "tree": "tree-a", "branch": "main"},
  "charter_hash": "sha256:4ee6839d81e3da60d9e70cbd22b1a4e3f589402e459e7db61c2e4a83b516e976",
  "review_input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}`
	document, err := DecodeAndValidateReviewRequest([]byte(request))
	if err != nil {
		t.Fatalf("DecodeAndValidateReviewRequest: %v", err)
	}
	if document.Subject.Head != "a1b2c3" {
		t.Fatalf("subject = %#v", document.Subject)
	}
	requestDigest, err := ReviewRequestDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	if !validDigest(requestDigest) {
		t.Fatalf("request digest = %q", requestDigest)
	}

	bad := bytes.Replace([]byte(request), []byte(`"head": "a1b2c3"`), []byte(`"head": ""`), 1)
	if _, err := DecodeAndValidateReviewRequest(bad); err == nil {
		t.Fatal("request with an empty subject head passed validation")
	}
}

func TestReviewRequestRejectsPresentEmptyOptionalSubjectLabels(t *testing.T) {
	const request = `{
  "schema_version": "review-request-v1",
  "consumer_identity": {"kind": "delegate", "id": "consumer-a"},
  "subject": {"head": "a1b2c3", "tree": "tree-a", "branch": "main"},
  "charter_hash": "sha256:4ee6839d81e3da60d9e70cbd22b1a4e3f589402e459e7db61c2e4a83b516e976",
  "review_input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}`
	for _, testCase := range []struct {
		name string
		from string
		to   string
	}{
		{name: "empty tree", from: `"tree": "tree-a"`, to: `"tree": ""`},
		{name: "whitespace branch", from: `"branch": "main"`, to: `"branch": " "`},
		{name: "null tree", from: `"tree": "tree-a"`, to: `"tree": null`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			data := bytes.Replace([]byte(request), []byte(testCase.from), []byte(testCase.to), 1)
			if _, err := DecodeAndValidateReviewRequest(data); err == nil {
				t.Fatal("request with a present empty optional subject label passed validation")
			}
		})
	}
}

func TestReviewReportDigest(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	data, err := ConformanceFS.ReadFile("testdata/conformance/valid-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := DecodeAndValidateReviewReport(data, frozen, "sha256:1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	reportDigest, err := ReviewReportDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	if !validDigest(reportDigest) {
		t.Fatalf("report digest = %q", reportDigest)
	}
}

func TestReviewReportBindsExpectedInputDigest(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	data, err := ConformanceFS.ReadFile("testdata/conformance/valid-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndValidateReviewReport(data, frozen, "not-a-digest"); err == nil {
		t.Fatal("report with malformed expected input digest passed validation")
	}
	if _, err := DecodeAndValidateReviewReport(data, frozen, "sha256:2222222222222222222222222222222222222222222222222222222222222222"); err == nil {
		t.Fatal("report with mismatched expected input digest passed validation")
	}
}

func TestReviewReportWitnessRejectsRoleOutputOnlyFields(t *testing.T) {
	const report = `{
  "schema_version": "review-report-v1",
  "role": "defect",
  "charter_hash": "sha256:4ee6839d81e3da60d9e70cbd22b1a4e3f589402e459e7db61c2e4a83b516e976",
  "review_input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "source_identity": {"kind": "git", "id": "source-head"},
  "consumer_identity": {"kind": "delegate", "id": "consumer-a"},
  "findings": [{
    "id": "finding-role-output-field",
    "title": "Report witnesses reject role-output fields.",
    "claimed_severity": "low",
    "charter_goal_ids": [],
    "witness": {
      "kind": "defect",
      "strength": "argued",
      "content": "The report boundary carries only report evidence.",
      "artifact_refs": []
    }
  }]
}`
	if _, err := strictjson.DecodeBytes[ReviewReportDocument]([]byte(report), strictjson.DefaultMaxBytes); err == nil {
		t.Fatal("strict decoder accepted artifact_refs on a report finding witness")
	}
}

func TestReviewReportRejectsPresentEmptyAnnotationPath(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	data, err := ConformanceFS.ReadFile("testdata/conformance/valid-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"path": "api/response.go"`), []byte(`"path": ""`), 1)
	if _, err := DecodeAndValidateReviewReport(data, frozen, "sha256:1111111111111111111111111111111111111111111111111111111111111111"); err == nil {
		t.Fatal("report with a present empty annotation path passed validation")
	}
}

func TestDefaultReviewerSchemaPinsBoundaryValues(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	inputDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	expectedConsumerIdentity := Identity{Kind: "delegate", ID: "consumer-b"}
	schema, err := DefaultReviewerSchema(frozen, inputDigest, expectedConsumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(schema, []byte(`"$comment"`)) {
		t.Fatalf("schema contains $comment: %s", schema)
	}
	decoded, err := strictjson.DecodeAnyBytes(schema, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("schema root = %T", decoded)
	}
	properties, ok := root["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties = %#v", root["properties"])
	}
	assertSchemaConst(t, properties, "schema_version", ReviewReportV1)
	assertSchemaConst(t, properties, "role", RoleDefect)
	assertSchemaConst(t, properties, "charter_hash", frozen.CharterHash)
	assertSchemaConst(t, properties, "review_input_digest", inputDigest)
	consumerIdentity, ok := properties["consumer_identity"].(map[string]any)
	if !ok {
		t.Fatalf("consumer_identity schema = %#v", properties["consumer_identity"])
	}
	if consumerIdentity["additionalProperties"] != false {
		t.Fatalf("consumer_identity additionalProperties = %#v, want false", consumerIdentity["additionalProperties"])
	}
	required, ok := consumerIdentity["required"].([]any)
	if !ok || len(required) != 2 || required[0] != "kind" || required[1] != "id" {
		t.Fatalf("consumer_identity required = %#v, want kind and id", consumerIdentity["required"])
	}
	consumerProperties, ok := consumerIdentity["properties"].(map[string]any)
	if !ok {
		t.Fatalf("consumer_identity properties = %#v", consumerIdentity["properties"])
	}
	assertSchemaConst(t, consumerProperties, "kind", "delegate")
	assertSchemaConst(t, consumerProperties, "id", "consumer-b")

	findings, ok := properties["findings"].(map[string]any)
	if !ok {
		t.Fatalf("findings schema = %#v", properties["findings"])
	}
	if maxItems, ok := findings["maxItems"].(json.Number); !ok || maxItems.String() != "128" {
		t.Fatalf("findings maxItems = %#v, want 128", findings["maxItems"])
	}
	findingSchema, ok := findings["items"].(map[string]any)
	if !ok {
		t.Fatalf("finding item schema = %#v", findings["items"])
	}
	findingProperties, ok := findingSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("finding properties = %#v", findingSchema["properties"])
	}
	goals, ok := findingProperties["charter_goal_ids"].(map[string]any)
	if !ok {
		t.Fatalf("goal IDs schema = %#v", findingProperties["charter_goal_ids"])
	}
	goalItems, ok := goals["items"].(map[string]any)
	if !ok {
		t.Fatalf("goal ID item schema = %#v", goals["items"])
	}
	enum, ok := goalItems["enum"].([]any)
	if !ok || len(enum) != 1 || enum[0] != "goal-api" {
		t.Fatalf("goal enum = %#v", goalItems["enum"])
	}
	witness, ok := findingProperties["witness"].(map[string]any)
	if !ok {
		t.Fatalf("witness schema = %#v", findingProperties["witness"])
	}
	witnessProperties, ok := witness["properties"].(map[string]any)
	if !ok {
		t.Fatalf("witness properties = %#v", witness["properties"])
	}
	if len(witnessProperties) != 4 {
		t.Fatalf("witness properties = %#v, want exactly kind, strength, content, executable", witnessProperties)
	}
	for _, name := range []string{"kind", "strength", "content", "executable"} {
		if _, ok := witnessProperties[name]; !ok {
			t.Fatalf("witness schema omits %q", name)
		}
	}
	assertSchemaConst(t, witnessProperties, "kind", WitnessKindDefect)
	sourceIdentity, ok := properties["source_identity"].(map[string]any)
	if !ok {
		t.Fatalf("source_identity schema = %#v", properties["source_identity"])
	}
	if sourceIdentity["additionalProperties"] != false {
		t.Fatalf("source_identity additionalProperties = %#v, want false", sourceIdentity["additionalProperties"])
	}
	sourceIdentityProperties, ok := sourceIdentity["properties"].(map[string]any)
	if !ok {
		t.Fatalf("source_identity properties = %#v", sourceIdentity["properties"])
	}
	for _, field := range []string{"kind", "id"} {
		assertSchemaPattern(t, sourceIdentityProperties, field, `\S`)
	}
	if !bytes.Contains([]byte(DefaultReviewerBriefText), []byte(`"consumer_identity":{"kind":"<supplied kind>","id":"<supplied id>"}`)) {
		t.Fatalf("DefaultReviewerBriefText does not show the supplied consumer identity object: %s", DefaultReviewerBriefText)
	}
	for _, expectedConsumerIdentity := range []Identity{
		{},
		{ID: "consumer-b"},
		{Kind: "delegate"},
		{Kind: "", ID: "consumer-b"},
		{Kind: "delegate", ID: " "},
	} {
		if _, err := DefaultReviewerSchema(frozen, inputDigest, expectedConsumerIdentity); err == nil {
			t.Fatalf("DefaultReviewerSchema accepted invalid expected consumer identity %#v", expectedConsumerIdentity)
		}
	}
}

func TestDefaultReviewerEvaluationGoalRequirements(t *testing.T) {
	goalBearing := conformanceFrozenCharter(t)
	zeroGoal, err := charter.Freeze(charter.Charter{
		SchemaVersion:       goalBearing.Charter.SchemaVersion,
		Goals:               []charter.Statement{},
		NonGoals:            goalBearing.Charter.NonGoals,
		OwnerEvents:         goalBearing.Charter.OwnerEvents,
		OperationalEnvelope: goalBearing.Charter.OperationalEnvelope,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const inputDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	schema, err := DefaultReviewerSchema(zeroGoal, inputDigest, Identity{Kind: "delegate", ID: "consumer-b"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := strictjson.DecodeAnyBytes(schema, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	root := decoded.(map[string]any)
	properties := root["properties"].(map[string]any)
	evaluation := properties["evaluation"].(map[string]any)
	evaluationProperties := evaluation["properties"].(map[string]any)
	evaluatedGoalIDs := evaluationProperties["evaluated_goal_ids"].(map[string]any)
	if _, hasMinItems := evaluatedGoalIDs["minItems"]; hasMinItems {
		t.Fatalf("evaluated_goal_ids minItems present for zero-goal Charter")
	}
	items := evaluatedGoalIDs["items"].(map[string]any)
	enum := items["enum"].([]any)
	if len(enum) != 0 {
		t.Fatalf("evaluated_goal_ids enum = %#v, want no values", enum)
	}

	document := ReviewReportDocument{
		SchemaVersion:     ReviewReportV1,
		Role:              RoleDefect,
		CharterHash:       zeroGoal.CharterHash,
		ReviewInputDigest: inputDigest,
		SourceIdentity:    Identity{Kind: "git", ID: "source-head"},
		ConsumerIdentity:  Identity{Kind: "delegate", ID: "consumer-b"},
		Findings:          []ReportFinding{},
		Evaluation: &ReportEvaluation{
			EvaluatedPaths:   []string{"api/response.go"},
			EvaluatedGoalIDs: []string{},
		},
	}
	diagnostics := ValidateReviewReport(document, zeroGoal, inputDigest)
	if len(diagnostics) != 0 {
		t.Fatalf("ValidateReviewReport diagnostics = %#v", diagnostics)
	}
}

func assertSchemaConst(t *testing.T, properties map[string]any, name string, want string) {
	t.Helper()
	field, ok := properties[name].(map[string]any)
	if !ok {
		t.Fatalf("schema property %q = %#v", name, properties[name])
	}
	if field["const"] != want {
		t.Fatalf("schema property %q const = %#v, want %q", name, field["const"], want)
	}
}

func assertSchemaPattern(t *testing.T, properties map[string]any, name string, want string) {
	t.Helper()
	field, ok := properties[name].(map[string]any)
	if !ok {
		t.Fatalf("schema property %q = %#v", name, properties[name])
	}
	if field["pattern"] != want {
		t.Fatalf("schema property %q pattern = %#v, want %q", name, field["pattern"], want)
	}
}
