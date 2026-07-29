package contracts

// ReducerBriefText is the prompt-side contract summary used by the relay
// reducer. The broken-only rationale lives here instead of a JSON Schema
// $comment because convo-relay's supported schema subset rejects $comment.
const ReducerBriefText = `Emit exactly one relay-witness-verdicts-v2 JSON object. Cover every supplied finding ID exactly once and preserve each supplied witness digest exactly. A survived verdict means the filed witness survived as filed; it does not validate the remedy, proposed tests, or command execution. For survived, verdict_class and counter_witness must be null. For weakened and broken, verdict_class is required and a concrete counter_witness is required. Classes unreachable and outside_envelope are valid only with broken because they mean the filed witness cannot establish an in-envelope reachable violation, not merely a partial logical or premise weakness. Do not emit execution_attestation, execution-attestation, or execution_contradiction fields.`

// RelayWitnessVerdictsV2SchemaJSON is the relay integration result schema for
// relay-witness-verdicts-v2. It intentionally contains no $comment keyword;
// see ReducerBriefText for the unreachable/outside_envelope broken-only
// rationale that cannot be expressed as a comment in relay's schema subset.
const RelayWitnessVerdictsV2SchemaJSON = `{
  "$defs": {
    "artifact_ref": {
      "type": "object",
      "required": ["kind", "id", "digest"],
      "properties": {
        "kind": {"type": "string", "minLength": 1},
        "id": {"type": "string", "minLength": 1},
        "digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "digest_profile": {"const": "relay-root-digests-v1"},
        "media_type": {"type": "string"}
      },
      "additionalProperties": false
    },
    "scope_anchor": {
      "type": "object",
      "required": ["dimension"],
      "properties": {
        "dimension": {"type": "string", "minLength": 1},
        "entry_id": {"type": "string"},
        "property": {"type": "string"},
        "value": {"type": "string"},
        "affected_decision": {"type": "string"},
        "excluded": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "counter_witness": {
      "type": "object",
      "required": ["summary", "evidence"],
      "properties": {
        "summary": {"type": "string", "minLength": 1},
        "evidence": {"type": "string", "minLength": 1},
        "artifact_refs": {
          "type": "array",
          "items": {"$ref": "#/$defs/artifact_ref"}
        },
        "scope_anchors": {
          "type": "array",
          "items": {"$ref": "#/$defs/scope_anchor"}
        }
      },
      "additionalProperties": false
    },
    "verdict": {
      "type": "object",
      "required": ["finding_id", "witness_digest", "verdict", "verdict_class", "counter_witness"],
      "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "witness_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "verdict": {"enum": ["survived", "weakened", "broken"]},
        "verdict_class": {"type": ["string", "null"], "enum": ["logic", "unreachable", "outside_envelope", "missing_premise", "other", null]},
        "counter_witness": {
          "oneOf": [
            {"type": "null"},
            {"$ref": "#/$defs/counter_witness"}
          ]
        },
        "rationale": {"type": "string"}
      },
      "allOf": [
        {
          "if": {
            "required": ["verdict"],
            "properties": {"verdict": {"const": "survived"}}
          },
          "then": {
            "properties": {
              "verdict_class": {"type": "null"},
              "counter_witness": {"type": "null"}
            }
          }
        },
        {
          "if": {
            "required": ["verdict"],
            "properties": {"verdict": {"enum": ["weakened", "broken"]}}
          },
          "then": {
            "properties": {
              "verdict_class": {"enum": ["logic", "unreachable", "outside_envelope", "missing_premise", "other"]},
              "counter_witness": {"$ref": "#/$defs/counter_witness"}
            }
          }
        },
        {
          "if": {
            "required": ["verdict_class"],
            "properties": {"verdict_class": {"enum": ["unreachable", "outside_envelope"]}}
          },
          "then": {
            "properties": {"verdict": {"const": "broken"}}
          }
        }
      ],
      "additionalProperties": false
    }
  },
  "type": "object",
  "required": ["schema_version", "batch_id", "verdicts"],
  "properties": {
    "schema_version": {"const": "relay-witness-verdicts-v2"},
    "batch_id": {"type": "string", "minLength": 1},
    "verdicts": {
      "type": "array",
      "minItems": 1,
      "maxItems": 8,
      "items": {"$ref": "#/$defs/verdict"}
    }
  },
  "additionalProperties": false
}`

func RelayWitnessVerdictsV2SchemaBytes() []byte {
	return []byte(RelayWitnessVerdictsV2SchemaJSON)
}
