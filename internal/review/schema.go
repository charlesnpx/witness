package review

import (
	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/digest"
	contractreview "github.com/charlesnpx/witness/contract/review"
)

// reviewerSchema describes the strict review-report-v2 boundary. Validation of
// relationships between array entries (such as unique finding IDs and question
// references) remains with DecodeAndValidateReviewReportV2.
func reviewerSchema(request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) ([]byte, error) {
	goalIDs := make([]string, len(frozen.Charter.Goals))
	for index, goal := range frozen.Charter.Goals {
		goalIDs[index] = goal.ID
	}
	goalID := map[string]any{"type": "string"}
	evaluatedGoals := map[string]any{"type": "array", "items": goalID}
	if len(goalIDs) > 0 {
		goalID["enum"] = goalIDs
		evaluatedGoals["minItems"] = 1
	}
	stableID := map[string]any{"type": "string", "minLength": 1, "pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]*$`}
	nonBlank := reviewerNonBlankStringSchema()
	title := reviewerNonBlankStringSchema()
	// JSON Schema counts characters; the contract also enforces the byte limit.
	title["maxLength"] = 8192

	finding := reviewerObjectSchema(map[string]any{
		"id":               stableID,
		"kind":             reviewerEnumSchema(contractreview.FindingKindDefect, contractreview.FindingKindEconomy),
		"title":            title,
		"claimed_severity": reviewerEnumSchema(contractreview.SeverityCritical, contractreview.SeverityHigh, contractreview.SeverityMedium, contractreview.SeverityLow),
		"attribution": reviewerEnumSchema(
			contractreview.FindingAttributionIntroduced, contractreview.FindingAttributionWorsened,
			contractreview.FindingAttributionPreExisting, contractreview.FindingAttributionUnattributed,
		),
		"charter_goal_ids":    map[string]any{"type": "array", "items": goalID},
		"witness":             map[string]any{"$ref": "#/$defs/witness"},
		"annotation":          map[string]any{"$ref": "#/$defs/annotation"},
		"remedy":              map[string]any{"$ref": "#/$defs/remedy"},
		"economy_equivalence": map[string]any{"$ref": "#/$defs/economy_equivalence"},
	}, "id", "kind", "title", "claimed_severity", "attribution", "charter_goal_ids", "witness")
	finding["allOf"] = []any{
		map[string]any{
			"if": map[string]any{"properties": map[string]any{"kind": map[string]any{"const": contractreview.FindingKindEconomy}}},
			"then": map[string]any{
				"required": []string{"economy_equivalence"},
				"properties": map[string]any{
					"witness":             map[string]any{"properties": map[string]any{"kind": map[string]any{"const": contractreview.WitnessKindEquivalence}}},
					"economy_equivalence": map[string]any{"type": "object"},
				},
			},
		},
		map[string]any{
			"if": map[string]any{"properties": map[string]any{"kind": map[string]any{"const": contractreview.FindingKindDefect}}},
			"then": map[string]any{"properties": map[string]any{
				"witness": map[string]any{"properties": map[string]any{"kind": map[string]any{"const": contractreview.WitnessKindDefect}}},
			}},
		},
		map[string]any{
			"if": map[string]any{
				"required": []string{"remedy"},
				"properties": map[string]any{"remedy": map[string]any{
					"type": "object", "required": []string{"direction"},
					"properties": map[string]any{"direction": map[string]any{"const": contractreview.RemedyDirectionRemove}},
				}},
			},
			"then": map[string]any{
				"required":   []string{"economy_equivalence"},
				"properties": map[string]any{"economy_equivalence": map[string]any{"type": "object"}},
			},
		},
		reviewerSeverityCapSchema(contractreview.WitnessStrengthArgued, contractreview.SeverityMedium, contractreview.SeverityLow),
		reviewerSeverityCapSchema(contractreview.WitnessStrengthConstructed, contractreview.SeverityHigh, contractreview.SeverityMedium, contractreview.SeverityLow),
	}

	witness := reviewerObjectSchema(map[string]any{
		"kind":       reviewerEnumSchema(contractreview.WitnessKindDefect, contractreview.WitnessKindEquivalence),
		"strength":   reviewerEnumSchema(contractreview.WitnessStrengthExecutable, contractreview.WitnessStrengthConstructed, contractreview.WitnessStrengthArgued),
		"content":    nonBlank,
		"executable": map[string]any{"$ref": "#/$defs/executable"},
	}, "kind", "strength", "content")
	witness["if"] = map[string]any{"properties": map[string]any{"strength": map[string]any{"const": contractreview.WitnessStrengthExecutable}}}
	witness["then"] = map[string]any{
		"required":   []string{"executable"},
		"properties": map[string]any{"executable": map[string]any{"type": "object"}},
	}
	// A JSON null decodes to a nil optional pointer, including for non-executable
	// witnesses. Only a non-null specification requires executable strength.
	witness["else"] = map[string]any{"properties": map[string]any{"executable": map[string]any{"type": "null"}}}

	annotation := nullableReviewerObjectSchema(map[string]any{
		"path":     nonBlank,
		"line":     map[string]any{"type": "integer", "minimum": 0, "maximum": uint64(1<<32 - 1)},
		"category": stableID,
	})
	annotation["dependentRequired"] = map[string]any{"line": []string{"path"}}

	schema := reviewerObjectSchema(map[string]any{
		"schema_version":      map[string]any{"const": contractreview.ReviewReportV2},
		"request_digest":      map[string]any{"const": mustRequestDigest(request)},
		"recipe_digest":       map[string]any{"const": request.RecipeDigest},
		"reviewer":            map[string]any{"const": reviewer},
		"charter_hash":        map[string]any{"const": frozen.CharterHash},
		"review_input_digest": map[string]any{"const": request.ReviewInputDigest},
		"source_identity":     reviewerIdentitySchema(sourceIdentityForRequest(request)),
		"consumer_identity":   reviewerIdentitySchema(request.ConsumerIdentity),
		"findings":            map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/finding"}},
		"evaluation": reviewerObjectSchema(map[string]any{
			"evaluated_paths":    map[string]any{"type": "array", "minItems": 1, "items": nonBlank},
			"evaluated_goal_ids": evaluatedGoals,
		}, "evaluated_paths", "evaluated_goal_ids"),
		"missing_goal_questions": map[string]any{"type": []string{"array", "null"}, "items": map[string]any{"$ref": "#/$defs/missing_goal_question"}},
	}, "schema_version", "request_digest", "recipe_digest", "reviewer", "charter_hash", "review_input_digest", "source_identity", "consumer_identity", "findings", "evaluation")
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["$defs"] = map[string]any{
		"finding":    finding,
		"witness":    witness,
		"annotation": annotation,
		"executable": nullableReviewerObjectSchema(map[string]any{
			"argv":                 map[string]any{"type": "array", "minItems": 1, "items": nonBlank},
			"cwd":                  nonBlank,
			"expected_observation": nonBlank,
			"transformation_ref":   map[string]any{"$ref": "#/$defs/artifact_ref"},
		}, "argv", "cwd", "expected_observation"),
		"artifact_ref": nullableReviewerObjectSchema(map[string]any{
			"kind":           nonBlank,
			"id":             stableID,
			"digest":         map[string]any{"type": "string", "minLength": 1, "pattern": "^" + digest.Prefix + "[0-9a-f]{64}$"},
			"digest_profile": map[string]any{"enum": []any{digest.Profile, "", nil}},
			"media_type":     map[string]any{"type": []string{"string", "null"}},
		}, "kind", "id", "digest"),
		"remedy": nullableReviewerObjectSchema(map[string]any{
			"direction":           reviewerEnumSchema(contractreview.RemedyDirectionAdd, contractreview.RemedyDirectionChange, contractreview.RemedyDirectionRemove),
			"summary":             nonBlank,
			"minimality_argument": nonBlank,
		}, "direction", "summary", "minimality_argument"),
		"economy_equivalence": nullableReviewerObjectSchema(map[string]any{
			"preserved_behavior": nonBlank,
			"charter_goal_ids":   map[string]any{"type": "array", "minItems": 1, "uniqueItems": true, "items": goalID},
		}, "preserved_behavior", "charter_goal_ids"),
		"missing_goal_question": reviewerObjectSchema(map[string]any{
			"id":         stableID,
			"finding_id": stableID,
			"dimension": reviewerEnumSchema(
				charter.DimensionEntryPoints, charter.DimensionInputSurface, charter.DimensionValidStates,
				charter.DimensionEnvironments, charter.DimensionScaleBounds, charter.DimensionCompatibilityPromises, charter.DimensionThreatModel,
			),
			// The decoder accepts omitted or null anchor_index as zero.
			"anchor_index":      map[string]any{"type": []string{"integer", "null"}, "minimum": 0},
			"property":          nonBlank,
			"value":             map[string]any{"type": []string{"string", "null"}},
			"affected_decision": nonBlank,
			"statement":         nonBlank,
		}, "id", "finding_id", "dimension", "property", "affected_decision", "statement"),
	}
	return canonjson.Marshal(schema)
}

func reviewerObjectSchema(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func nullableReviewerObjectSchema(properties map[string]any, required ...string) map[string]any {
	schema := reviewerObjectSchema(properties, required...)
	schema["type"] = []string{"object", "null"}
	return schema
}

func reviewerIdentitySchema(identity contractreview.Identity) map[string]any {
	schema := reviewerObjectSchema(map[string]any{
		"kind": reviewerNonBlankStringSchema(),
		"id":   reviewerNonBlankStringSchema(),
	}, "kind", "id")
	schema["const"] = identity
	return schema
}

func reviewerNonBlankStringSchema() map[string]any {
	// Match a character outside strings.TrimSpace's Unicode whitespace set.
	return map[string]any{"type": "string", "minLength": 1, "pattern": "[^\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"}
}

func reviewerEnumSchema(values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}

func reviewerSeverityCapSchema(strength string, severities ...string) map[string]any {
	return map[string]any{
		"if": map[string]any{"properties": map[string]any{
			"witness": map[string]any{"properties": map[string]any{"strength": map[string]any{"const": strength}}},
		}},
		"then": map[string]any{"properties": map[string]any{"claimed_severity": reviewerEnumSchema(severities...)}},
	}
}
