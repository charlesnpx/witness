package review

import (
	"bytes"
	"testing"

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

func TestReviewReportDigest(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	data, err := ConformanceFS.ReadFile("testdata/conformance/valid-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := DecodeAndValidateReviewReport(data, frozen)
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

func TestDefaultReviewerSchemaPinsBoundaryValues(t *testing.T) {
	frozen := conformanceFrozenCharter(t)
	inputDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	schema, err := DefaultReviewerSchema(frozen, inputDigest)
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

	findings, ok := properties["findings"].(map[string]any)
	if !ok {
		t.Fatalf("findings schema = %#v", properties["findings"])
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
