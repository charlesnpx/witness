package review

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
)

// ReviewReportV2SourceIdentity returns the report identity bound to the source
// revision in request. A report cannot choose a different source identity.
func ReviewReportV2SourceIdentity(request ReviewRequestV2Document) Identity {
	return Identity{Kind: "git", ID: request.Subject.Head}
}

// ReviewReportV2Schema returns the supported Draft 2020-12 schema for one
// reviewer report, pinned to the request, its frozen Charter, and reviewer.
// Request, Charter, identity, and digest bindings are exact JSON constants.
// Cross-field rules such as severity caps and economy evidence requirements
// remain enforced by ValidateReviewReportV2.
func ReviewReportV2Schema(request ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) (json.RawMessage, error) {
	if err := validateReviewReportV2ProducerInputs(request, frozen, reviewer); err != nil {
		return nil, err
	}
	baseSchema, err := DefaultReviewerSchema(frozen, request.ReviewInputDigest, request.ConsumerIdentity)
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	decoder := json.NewDecoder(bytes.NewReader(baseSchema))
	decoder.UseNumber()
	if err := decoder.Decode(&schema); err != nil {
		return nil, fmt.Errorf("decode shared v1 report schema: %w", err)
	}

	rootProperties := schema["properties"].(map[string]any)
	rootProperties["schema_version"] = map[string]any{"const": ReviewReportV2}
	delete(rootProperties, "role")
	requestDigest, err := ReviewRequestV2Digest(request)
	if err != nil {
		return nil, fmt.Errorf("compute review request digest: %w", err)
	}
	rootProperties["request_digest"] = map[string]any{"const": requestDigest}
	rootProperties["recipe_digest"] = map[string]any{"const": request.RecipeDigest}
	rootProperties["reviewer"] = map[string]any{"const": reviewer}
	rootProperties["source_identity"] = map[string]any{"const": ReviewReportV2SourceIdentity(request)}
	rootProperties["consumer_identity"] = map[string]any{"const": request.ConsumerIdentity}

	rootRequired := schema["required"].([]any)
	rootRequired = removeSchemaRequired(rootRequired, "role")
	rootRequired = append(rootRequired, "request_digest", "recipe_digest", "reviewer")
	schema["required"] = rootRequired

	findings := rootProperties["findings"].(map[string]any)
	finding := findings["items"].(map[string]any)
	findingRequired := finding["required"].([]any)
	finding["required"] = append(findingRequired, "kind", "attribution")
	findingProperties := finding["properties"].(map[string]any)
	findingProperties["kind"] = map[string]any{"enum": []string{FindingKindDefect, FindingKindEconomy}}
	findingProperties["attribution"] = map[string]any{"enum": []string{
		FindingAttributionIntroduced,
		FindingAttributionWorsened,
		FindingAttributionPreExisting,
		FindingAttributionUnattributed,
	}}
	findingProperties["economy_equivalence"] = economyEquivalenceSchema(frozen)
	witness := findingProperties["witness"].(map[string]any)
	witnessProperties := witness["properties"].(map[string]any)
	witnessProperties["kind"] = map[string]any{"enum": []string{WitnessKindDefect, WitnessKindEquivalence}}
	findingProperties["title"].(map[string]any)["pattern"] = `\S`
	witnessProperties["content"].(map[string]any)["pattern"] = `\S`
	executable := witnessProperties["executable"].(map[string]any)
	executableProperties := executable["properties"].(map[string]any)
	argv := executableProperties["argv"].(map[string]any)
	argv["items"].(map[string]any)["pattern"] = `\S`
	for _, name := range []string{"cwd", "expected_observation"} {
		executableProperties[name].(map[string]any)["pattern"] = `\S`
	}
	annotation := findingProperties["annotation"].(map[string]any)
	annotation["properties"].(map[string]any)["path"].(map[string]any)["pattern"] = `\S`
	remedy := findingProperties["remedy"].(map[string]any)
	remedyProperties := remedy["properties"].(map[string]any)
	for _, name := range []string{"summary", "minimality_argument"} {
		remedyProperties[name].(map[string]any)["pattern"] = `\S`
	}
	evaluation := rootProperties["evaluation"].(map[string]any)
	evaluationProperties := evaluation["properties"].(map[string]any)
	evaluationProperties["evaluated_paths"].(map[string]any)["items"].(map[string]any)["pattern"] = `\S`
	missingGoalQuestions := rootProperties["missing_goal_questions"].(map[string]any)
	question := missingGoalQuestions["items"].(map[string]any)
	questionProperties := question["properties"].(map[string]any)
	for _, name := range []string{"property", "affected_decision", "statement"} {
		questionProperties[name].(map[string]any)["pattern"] = `\S`
	}

	return canonjson.Marshal(schema)
}

// ReviewReportV2PromptExample returns a complete, request-bound JSON example
// for a reviewer prompt. Its evidence and path strings are explicitly marked
// as placeholders and make no claim that an observation or command occurred.
func ReviewReportV2PromptExample(request ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) (json.RawMessage, error) {
	if err := validateReviewReportV2ProducerInputs(request, frozen, reviewer); err != nil {
		return nil, err
	}
	requestDigest, err := ReviewRequestV2Digest(request)
	if err != nil {
		return nil, fmt.Errorf("compute review request digest: %w", err)
	}
	evaluationGoalIDs := make([]string, 0, 1)
	findingGoalIDs := make([]string, 0, 1)
	if len(frozen.Charter.Goals) > 0 {
		goalID := frozen.Charter.Goals[0].ID
		evaluationGoalIDs = append(evaluationGoalIDs, goalID)
		findingGoalIDs = append(findingGoalIDs, goalID)
	}
	finding := ReviewReportV2Finding{
		ID:              "example-finding",
		Kind:            FindingKindDefect,
		Title:           "Illustrative placeholder; replace with a finding supported by your review.",
		ClaimedSeverity: SeverityLow,
		Attribution:     FindingAttributionUnattributed,
		CharterGoalIDs:  findingGoalIDs,
		Witness: ReportWitness{
			Kind:     WitnessKindDefect,
			Strength: WitnessStrengthArgued,
			Content:  "Illustrative placeholder only; replace with evidence established by source inspection. This is not a reproduced observation.",
		},
	}
	if reviewer == RoleEconomy && len(findingGoalIDs) > 0 {
		finding.Kind = FindingKindEconomy
		finding.Witness.Kind = WitnessKindEquivalence
		finding.Witness.Content = "Illustrative placeholder only; replace with a behavior comparison established by your review. No equivalence is claimed here."
		finding.Remedy = &ReportRemedy{
			Direction:          RemedyDirectionRemove,
			Summary:            "Illustrative placeholder; replace with the smallest supported remedy.",
			MinimalityArgument: "Illustrative placeholder; replace with why this is the smallest supported change.",
		}
		finding.EconomyEquivalence = &EconomyEquivalenceEvidence{
			PreservedBehavior: "Illustrative placeholder; replace with behavior you established would remain.",
			CharterGoalIDs:    append([]string(nil), findingGoalIDs...),
		}
	}
	report := ReviewReportV2Document{
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
			EvaluatedPaths:   []string{"replace-with-a-path-you-actually-evaluated"},
			EvaluatedGoalIDs: evaluationGoalIDs,
		},
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode v2 report example: %w", err)
	}
	return append(json.RawMessage(nil), data...), nil
}

func validateReviewReportV2ProducerInputs(request ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) error {
	if err := RequireValidReviewRequestV2(request); err != nil {
		return fmt.Errorf("review report schema requires a valid v2 request: %w", err)
	}
	if !validDigest(frozen.CharterHash) || frozen.CharterHash != request.CharterHash {
		return fmt.Errorf("frozen Charter hash must match the request charter_hash")
	}
	if !validStableID(reviewer) || !containsReviewerID(request.RequiredOutputs, reviewer) {
		return fmt.Errorf("reviewer must be a valid required output of the request")
	}
	return nil
}

func economyEquivalenceSchema(frozen charter.FrozenCharter) map[string]any {
	goalIDs := make([]string, len(frozen.Charter.Goals))
	for index, goal := range frozen.Charter.Goals {
		goalIDs[index] = goal.ID
	}
	return map[string]any{
		"type":     "object",
		"required": []string{"preserved_behavior", "charter_goal_ids"},
		"properties": map[string]any{
			"preserved_behavior": map[string]any{"type": "string", "minLength": 1, "pattern": `\S`},
			"charter_goal_ids": map[string]any{
				"type":     "array",
				"minItems": 1,
				"items":    map[string]any{"enum": goalIDs},
			},
		},
		"additionalProperties": false,
	}
}

func removeSchemaRequired(required []any, removed string) []any {
	result := make([]any, 0, len(required))
	for _, field := range required {
		if field != removed {
			result = append(result, field)
		}
	}
	return result
}
