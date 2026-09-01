package review

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charlesnpx/witness/contract/charter"
)

// DefaultReviewerBriefText is the compact prompt-side contract for a defect
// reviewer. The decoder remains authoritative for cross-field requirements.
const DefaultReviewerBriefText = `Emit exactly one review-report-v1 JSON object and nothing else, following this skeleton exactly (replace values, never field names or nesting): {"schema_version":"review-report-v1","role":"defect","charter_hash":"<echo the supplied value>","review_input_digest":"<echo the supplied value>","source_identity":{"kind":"<category>","id":"<identifier>"},"consumer_identity":"<echo the supplied consumer identity object exactly>","findings":[{"id":"<kebab-id>","title":"<one line>","claimed_severity":"critical|high|medium|low","charter_goal_ids":["<goal-id>"],"witness":{"kind":"defect","strength":"argued|constructed|executable","content":"<concrete failure path>"},"annotation":{"path":"<file>","line":1,"category":"<kebab-id>"}}],"evaluation":{"evaluated_paths":["<path>"],"evaluated_goal_ids":["<goal-id>"]}} Rules: claimed severity is capped by witness strength (argued at most medium, constructed at most high, only executable evidence can claim critical, and executable strength requires an executable specification object on the witness). At most 128 findings. Empty findings REQUIRE the evaluation object with BOTH evaluated_paths and evaluated_goal_ids; omit evaluation when findings are present, or include it truthfully. annotation is optional presentation-only file:line metadata with zero epistemic weight. An unbound finding uses an empty charter_goal_ids array. Optional remedy {direction, summary, minimality_argument} and missing_goal_questions surfaces carry review-protocol discipline.`

// The schema contains only the relay-supported Draft 2020-12 keyword subset.
// It cannot express the severity-cap cross-field rule or the empty-findings to
// evaluation dependency. Goal existence is expressed through the injected
// enum; byte-based title length and annotation line-to-path binding remain the
// decoder's job.
const defaultReviewerSchemaTemplate = `{
  "type": "object",
  "required": ["schema_version", "role", "charter_hash", "review_input_digest", "source_identity", "consumer_identity", "findings"],
  "properties": {
    "schema_version": {"const": %s},
    "role": {"const": "defect"},
    "charter_hash": {"const": %s},
    "review_input_digest": {"const": %s},
    "source_identity": {
      "type": "object",
      "required": ["kind", "id"],
      "properties": {
        "kind": {"type": "string", "minLength": 1, "pattern": "\\S"},
        "id": {"type": "string", "minLength": 1, "pattern": "\\S"}
      },
      "additionalProperties": true
    },
    "consumer_identity": {
      "type": "object",
      "required": ["kind", "id"],
      "properties": {
        "kind": {"const": %s},
        "id": {"const": %s}
      },
      "additionalProperties": false
    },
    "findings": {
      "type": "array",
      "maxItems": 128,
      "items": {
        "type": "object",
        "required": ["id", "title", "claimed_severity", "charter_goal_ids", "witness"],
        "properties": {
          "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
          "title": {"type": "string", "minLength": 1, "maxLength": 8192},
          "claimed_severity": {"enum": ["critical", "high", "medium", "low"]},
          "charter_goal_ids": {
            "type": "array",
            "items": {"enum": %s}
          },
          "witness": {
            "type": "object",
            "required": ["kind", "strength", "content"],
            "properties": {
              "kind": {"const": "defect"},
              "strength": {"enum": ["executable", "constructed", "argued"]},
              "content": {"type": "string", "minLength": 1},
              "executable": {
                "type": "object",
                "required": ["argv", "cwd", "expected_observation"],
                "properties": {
                  "argv": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
                  "cwd": {"type": "string", "minLength": 1},
                  "expected_observation": {"type": "string", "minLength": 1},
                  "transformation_ref": {
                    "type": "object",
                    "required": ["kind", "id", "digest"],
                    "properties": {
                      "kind": {"type": "string", "minLength": 1},
                      "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
                      "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                      "digest_profile": {"const": "relay-root-digests-v1"},
                      "media_type": {"type": "string"}
                    },
                    "additionalProperties": false
                  }
                },
                "additionalProperties": false
              }
            },
            "additionalProperties": false
          },
          "annotation": {
            "type": "object",
            "properties": {
              "path": {"type": "string", "minLength": 1},
              "line": {"type": "integer"},
              "category": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"}
            },
            "additionalProperties": false
          },
          "remedy": {
            "type": "object",
            "required": ["direction", "summary", "minimality_argument"],
            "properties": {
              "direction": {"enum": ["add", "change", "remove"]},
              "summary": {"type": "string", "minLength": 1},
              "minimality_argument": {"type": "string", "minLength": 1}
            },
            "additionalProperties": false
          }
        },
        "additionalProperties": false
      }
    },
    "evaluation": {
      "type": "object",
      "required": ["evaluated_paths", "evaluated_goal_ids"],
      "properties": {
        "evaluated_paths": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
        "evaluated_goal_ids": {"type": "array", "items": {"enum": %s}}
      },
      "additionalProperties": false
    },
    "missing_goal_questions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "finding_id", "dimension", "anchor_index", "property", "affected_decision", "statement"],
        "properties": {
          "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
          "finding_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
          "dimension": {"enum": ["entry_points", "input_surface", "valid_states", "environments", "scale_bounds", "compatibility_promises", "threat_model"]},
          "anchor_index": {"type": "integer"},
          "property": {"type": "string", "minLength": 1},
          "value": {"type": "string"},
          "affected_decision": {"type": "string", "minLength": 1},
          "statement": {"type": "string", "minLength": 1}
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}`

// DefaultReviewerSchema returns a $comment-free Draft 2020-12 schema for the
// report document pinned to frozen, the exact reviewer input digest, and the
// requesting consumer identity.
func DefaultReviewerSchema(frozen charter.FrozenCharter, reviewInputDigest string, expectedConsumerIdentity map[string]any) (json.RawMessage, error) {
	if !validDigest(frozen.CharterHash) {
		return nil, fmt.Errorf("frozen charter_hash must be a sha256 digest")
	}
	if !validDigest(reviewInputDigest) {
		return nil, fmt.Errorf("review_input_digest must be a sha256 digest")
	}
	expectedConsumerKind, expectedConsumerID, err := defaultReviewerConsumerIdentity(expectedConsumerIdentity)
	if err != nil {
		return nil, err
	}
	goalIDs := make([]string, len(frozen.Charter.Goals))
	for index, goal := range frozen.Charter.Goals {
		if !validStableID(goal.ID) {
			return nil, fmt.Errorf("frozen charter goal %d has an invalid ID", index)
		}
		goalIDs[index] = goal.ID
	}

	schemaVersionJSON, err := json.Marshal(ReviewReportV1)
	if err != nil {
		return nil, err
	}
	charterHashJSON, err := json.Marshal(frozen.CharterHash)
	if err != nil {
		return nil, err
	}
	reviewInputDigestJSON, err := json.Marshal(reviewInputDigest)
	if err != nil {
		return nil, err
	}
	expectedConsumerKindJSON, err := json.Marshal(expectedConsumerKind)
	if err != nil {
		return nil, err
	}
	expectedConsumerIDJSON, err := json.Marshal(expectedConsumerID)
	if err != nil {
		return nil, err
	}
	goalIDsJSON, err := json.Marshal(goalIDs)
	if err != nil {
		return nil, err
	}
	rendered := fmt.Sprintf(
		defaultReviewerSchemaTemplate,
		schemaVersionJSON,
		charterHashJSON,
		reviewInputDigestJSON,
		expectedConsumerKindJSON,
		expectedConsumerIDJSON,
		goalIDsJSON,
		goalIDsJSON,
	)
	return append(json.RawMessage(nil), rendered...), nil
}

func defaultReviewerConsumerIdentity(expectedConsumerIdentity map[string]any) (string, string, error) {
	for _, field := range []string{"kind", "id"} {
		value, ok := expectedConsumerIdentity[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return "", "", fmt.Errorf("expected consumer_identity requires a non-empty %s", field)
		}
	}
	return expectedConsumerIdentity["kind"].(string), expectedConsumerIdentity["id"].(string), nil
}
