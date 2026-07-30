package planning

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/digest"
)

type planningPortablePayload struct {
	entry map[string]any
	body  []byte
}

func writePlanningPortableExport(t *testing.T, verdicts contracts.RelayWitnessVerdictsDocument, batch contracts.VerificationBatchDocument) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "portable")
	charterBytes := []byte(`{"charter":"input"}`)
	artifactBytes := []byte("artifact")
	batchBytes, err := persistedVerificationBatchBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	charterDigest := digest.RawBytes(charterBytes)
	artifactDigest := digest.RawBytes(artifactBytes)
	batchDigest := digest.RawBytes(batchBytes)
	canonicalResult := mustPlanningCanonicalString(t, verdicts)
	contract := planningContractBody("witnessed-review/witness-falsification-v2")
	contractDigest := mustPlanningSemanticDigest(t, contract)
	integrationContract := map[string]any{
		"kind":            "integration_contract",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	integrationContractSource := map[string]any{
		"id":     "integration_contract:selected",
		"digest": mustPlanningStorageEnvelopeDigest(t, "integration_contract", integrationContract),
	}
	payloads := []planningPortablePayload{
		planningPortablePayloadFor(t, "root_session", "session", map[string]any{
			"execution_kind":  "recipe",
			"kind":            "portable_root_session",
			"provider_retry":  "forbid",
			"status":          "completed",
			"terminal_status": "completed",
		}, nil),
		planningPortablePayloadFor(t, "participant_transcript", "transcript", []any{
			map[string]any{"participant_turn": 1, "actor": "presenter", "content": "turn one", "provider_result_ref": planningPortableRef("artifact-000001", "provider_result:000001")},
			map[string]any{"participant_turn": 2, "actor": "falsifier", "content": "turn two", "provider_result_ref": planningPortableRef("artifact-000007", "provider_result:000003")},
			map[string]any{"participant_turn": 3, "actor": "presenter", "content": "turn three", "provider_result_ref": planningPortableRef("artifact-000013", "provider_result:000005")},
			map[string]any{"participant_turn": 4, "actor": "falsifier", "content": "turn four", "provider_result_ref": planningPortableRef("artifact-000019", "provider_result:000007")},
		}, nil),
		planningPortablePayloadFor(t, "diagnostics", "diagnostics", map[string]any{
			"execution_kind": "recipe",
			"status":         "completed",
		}, nil),
		planningPortablePayloadFor(t, "root_recipe_plan", "root-plan", map[string]any{
			"kind":                        "root_recipe_plan",
			"schema_version":              2,
			"digest_profile":              digest.Profile,
			"recipe_id":                   "witness-falsify-v2-codex",
			"provider_retry":              "forbid",
			"result_source":               "reducer",
			"participant_turns":           4,
			"integration_bundle_digest":   testDigest("bundle"),
			"integration_contract_id":     "witnessed-review/witness-falsification-v2",
			"integration_contract_digest": contractDigest,
			"integration_contract_ref":    planningPortableRefWithDigest("integration-contract", "integration_contract:selected", integrationContractSource["digest"].(string)),
			"prompt_context": map[string]any{
				"participant_transcript": "complete",
				"facilitator_ledger":     "trace_only",
			},
		}, planningSourceRef("root_recipe_plan:selected")),
		planningPortablePayloadFor(t, "integration_contract", "integration-contract", integrationContract, integrationContractSource),
		planningPortablePayloadFor(t, "named_input_content", "named-input-content-1", planningNamedInputContentPayload("charter", 1, charterBytes), planningSourceRef("named_input_content:000001")),
		planningPortablePayloadFor(t, "named_input_content", "named-input-content-2", planningNamedInputContentPayload("findings", 2, batchBytes), planningSourceRef("named_input_content:000002")),
		planningPortablePayloadFor(t, "named_input_content", "named-input-content-3", planningNamedInputContentPayload("artifact", 3, artifactBytes), planningSourceRef("named_input_content:000003")),
		planningPortablePayloadFor(t, "named_input_manifest", "named-input-manifest", map[string]any{
			"kind":           "named_input_manifest",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"contract_id":    "witnessed-review/witness-falsification-v2",
			"input_count":    3,
			"inputs": []any{
				planningNamedInputEntry("charter", 1, "named-input-content-1", "named_input_content:000001", len(charterBytes), charterDigest),
				planningNamedInputEntry("findings", 2, "named-input-content-2", "named_input_content:000002", len(batchBytes), batchDigest),
				planningNamedInputEntry("artifact", 3, "named-input-content-3", "named_input_content:000003", len(artifactBytes), artifactDigest),
			},
		}, planningSourceRef("named_input_manifest:selected")),
		planningPortablePayloadFor(t, "canonical_result", "canonical-result", map[string]any{
			"kind":           "canonical_result",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"transport":      "json",
			"canonical_json": canonicalResult,
			"value":          verdicts,
		}, planningSourceRef("canonical_result:selected")),
		planningPortablePayloadFor(t, "result_validation", "result-validation", map[string]any{
			"kind":                 "result_validation",
			"schema_version":       2,
			"digest_profile":       digest.Profile,
			"status":               "validated",
			"canonical_result_ref": planningPortableRef("canonical-result", "canonical_result:selected"),
		}, planningSourceRef("result_validation:selected")),
	}
	for _, spec := range []struct {
		resultID     string
		invocationID string
		promptID     string
		source       string
		phase        string
		ordinal      int
	}{
		{resultID: "artifact-000001", invocationID: "artifact-000002", promptID: "artifact-000003", source: "000001", phase: "participant", ordinal: 1},
		{resultID: "artifact-000004", invocationID: "artifact-000005", promptID: "artifact-000006", source: "000002", phase: "facilitator", ordinal: 1},
		{resultID: "artifact-000007", invocationID: "artifact-000008", promptID: "artifact-000009", source: "000003", phase: "participant", ordinal: 2},
		{resultID: "artifact-000010", invocationID: "artifact-000011", promptID: "artifact-000012", source: "000004", phase: "facilitator", ordinal: 2},
		{resultID: "artifact-000013", invocationID: "artifact-000014", promptID: "artifact-000015", source: "000005", phase: "participant", ordinal: 3},
		{resultID: "artifact-000016", invocationID: "artifact-000017", promptID: "artifact-000018", source: "000006", phase: "facilitator", ordinal: 3},
		{resultID: "artifact-000019", invocationID: "artifact-000020", promptID: "artifact-000021", source: "000007", phase: "participant", ordinal: 4},
		{resultID: "artifact-000022", invocationID: "artifact-000023", promptID: "artifact-000024", source: "000008", phase: "facilitator", ordinal: 4},
		{resultID: "artifact-000025", invocationID: "artifact-000026", promptID: "artifact-000027", source: "000009", phase: "reducer"},
	} {
		prompt := planningRenderedPromptPayload(spec.phase + " prompt " + spec.source)
		result, invocation := planningProviderPayloads(1, spec.resultID, spec.promptID, spec.source, spec.phase, spec.ordinal, prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string))
		payloads = append(payloads,
			planningPortablePayloadFor(t, "provider_result", spec.resultID, result, planningSourceRef("provider_result:"+spec.source)),
			planningPortablePayloadFor(t, "provider_invocation", spec.invocationID, invocation, planningSourceRef("provider_invocation:"+spec.source)),
			planningPortablePayloadFor(t, "rendered_prompt", spec.promptID, prompt, planningSourceRef("rendered_prompt:"+spec.source)),
		)
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].entry["path"].(string) < payloads[j].entry["path"].(string)
	})
	inventory := make([]any, 0, len(payloads))
	for _, payload := range payloads {
		writePlanningPortableFile(t, dir, payload.entry["path"].(string), payload.body)
		inventory = append(inventory, payload.entry)
	}
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version":      "relay-root-portable-export-v2",
		"convo_relay_version": "v1.4.0",
		"digest_profile":      digest.Profile,
		"terminal_status":     "completed",
		"stop_reason":         nil,
		"session_payload":     "payloads/root_session/session.json",
		"transcript_payload":  "payloads/participant_transcript/transcript.json",
		"diagnostics_payload": "payloads/diagnostics/diagnostics.json",
		"payload_inventory":   inventory,
		"inventory_digest":    inventoryDigest,
	}
	manifestDigest, err := digest.SemanticJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest["manifest_digest"] = manifestDigest
	body, err := canonjson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writePlanningPortableFile(t, dir, "manifest.json", body)
	return dir
}

func planningProviderPayloads(runnerAttempt int, resultPortableID string, promptPortableID string, sourceOrdinal string, phase string, participantOrdinal int, promptDigest string) (map[string]any, map[string]any) {
	invocationDraft := map[string]any{
		"schema_version":            "relay-provider-invocation-v2",
		"invocation_id":             phase + ":" + sourceOrdinal,
		"phase":                     phase,
		"actor":                     "Agent " + sourceOrdinal,
		"participant_ordinal":       nil,
		"reducer_fresh":             phase == "reducer",
		"rendered_prompt_ref":       planningPortableRef(promptPortableID, "rendered_prompt:"+sourceOrdinal),
		"rendered_prompt_digest":    promptDigest,
		"backend":                   "codex",
		"mapped_working_directory":  ".",
		"runner_attempt":            runnerAttempt,
		"provider_launch_attempted": true,
		"provider_retry":            "forbid",
		"started_at":                "2026-01-01T00:00:00Z",
		"completed_at":              "2026-01-01T00:00:01Z",
		"outcome":                   "completed",
		"failure_stage":             nil,
		"classification":            nil,
		"provider_result_ref":       nil,
	}
	if participantOrdinal > 0 {
		invocationDraft["participant_ordinal"] = participantOrdinal
	}
	resultPayload := map[string]any{
		"kind":            "provider_result",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"invocation_id":   invocationDraft["invocation_id"],
		"phase":           invocationDraft["phase"],
		"actor":           invocationDraft["actor"],
		"runner_attempt":  invocationDraft["runner_attempt"],
		"provider_retry":  invocationDraft["provider_retry"],
		"backend":         invocationDraft["backend"],
		"started_at":      invocationDraft["started_at"],
		"completed_at":    invocationDraft["completed_at"],
		"outcome":         invocationDraft["outcome"],
		"failure_stage":   invocationDraft["failure_stage"],
		"classification":  invocationDraft["classification"],
		"provider_result": map[string]any{"backend": "codex", "return_code": 0},
		"invocation":      invocationDraft,
	}
	boundInvocation := map[string]any{}
	for key, value := range invocationDraft {
		boundInvocation[key] = value
	}
	boundInvocation["provider_result_ref"] = planningPortableRef(resultPortableID, "provider_result:"+sourceOrdinal)
	return resultPayload, map[string]any{
		"kind":           "provider_invocation",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"invocation":     boundInvocation,
	}
}

func planningPortablePayloadFor(t *testing.T, kind string, id string, value any, sourceRef map[string]any) planningPortablePayload {
	t.Helper()
	body, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{
		"kind":         kind,
		"portable_id":  id,
		"path":         filepath.ToSlash(filepath.Join("payloads", kind, id+".json")),
		"media_type":   "application/json",
		"size_bytes":   len(body),
		"digest_class": digest.ClassRawBytes,
		"digest":       digest.RawBytes(body),
	}
	if sourceRef != nil {
		entry["source_artifact_id"] = sourceRef["id"]
		entry["source_artifact_digest"] = sourceRef["digest"]
	}
	return planningPortablePayload{entry: entry, body: body}
}

func planningContractBody(contractID string) map[string]any {
	return map[string]any{
		"id": contractID,
		"turns": []any{
			map[string]any{"participant_turn": 1, "slot": "slot_0", "instructions": "Presenter verifies the filed witness."},
			map[string]any{"participant_turn": 2, "slot": "slot_1", "instructions": "Falsifier challenges the filed witness."},
			map[string]any{"participant_turn": 3, "slot": "slot_0", "instructions": "Presenter responds to challenges."},
			map[string]any{"participant_turn": 4, "slot": "slot_1", "instructions": "Falsifier gives final challenge."},
		},
		"reducer": map[string]any{"instructions": "Return relay witness verdict JSON."},
		"inputs": map[string]any{
			"artifact": map[string]any{"required": false, "cardinality": "many", "media_type": "application/json", "max_bytes": 1048576},
			"charter":  map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
			"findings": map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
		},
		"result": map[string]any{
			"transport":  "json",
			"schema":     map[string]any{"type": "object"},
			"assertions": []any{},
		},
		"prompt_context": map[string]any{
			"participant_transcript": "complete",
			"facilitator_ledger":     "trace_only",
		},
	}
}

func planningNamedInputContentPayload(name string, ordinal int, data []byte) map[string]any {
	return map[string]any{
		"kind":           "named_input_content",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"ordinal":        ordinal,
		"name":           name,
		"name_ordinal":   1,
		"encoding":       "base64",
		"bytes_base64":   base64.StdEncoding.EncodeToString(data),
		"size_bytes":     len(data),
		"raw_digest":     digest.RawBytes(data),
		"media_type":     "application/json",
		"schema_status":  "unchecked",
	}
}

func planningRenderedPromptPayload(text string) map[string]any {
	data := []byte(text)
	return map[string]any{
		"kind":           "rendered_prompt",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"rendered_prompt": map[string]any{
			"schema_version": "relay-rendered-prompt-v1",
			"media_type":     "text/plain; charset=utf-8",
			"encoding":       "base64",
			"bytes_base64":   base64.StdEncoding.EncodeToString(data),
			"size_bytes":     len(data),
			"raw_digest":     digest.RawBytes(data),
		},
	}
}

func planningNamedInputEntry(name string, ordinal int, portableID string, sourceID string, sizeBytes int, rawDigest string) map[string]any {
	return map[string]any{
		"ordinal":       ordinal,
		"name":          name,
		"name_ordinal":  1,
		"source_path":   name + ".json",
		"display_name":  name + ".json",
		"size_bytes":    sizeBytes,
		"raw_digest":    rawDigest,
		"media_type":    "application/json",
		"schema_status": "unchecked",
		"content_ref":   planningPortableRef(portableID, sourceID),
	}
}

func planningPortableRef(portableID string, sourceID string) map[string]any {
	return planningPortableRefWithDigest(portableID, sourceID, planningSourceRef(sourceID)["digest"].(string))
}

func planningPortableRefWithDigest(portableID string, sourceID string, sourceDigest string) map[string]any {
	return map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            portableID,
		"source_artifact_id":     sourceID,
		"source_artifact_digest": sourceDigest,
	}
}

func planningSourceRef(id string) map[string]any {
	return map[string]any{
		"kind":           "artifact_ref",
		"schema_version": 1,
		"id":             id,
		"digest":         testDigest(id),
	}
}

func mustPlanningCanonicalString(t *testing.T, value any) string {
	t.Helper()
	data, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustPlanningSemanticDigest(t *testing.T, value any) string {
	t.Helper()
	digestValue, err := digest.SemanticJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return digestValue
}

func mustPlanningStorageEnvelopeDigest(t *testing.T, kind string, value any) string {
	t.Helper()
	digestValue, err := digest.StorageEnvelope(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return digestValue
}

func writePlanningPortableFile(t *testing.T, root string, relative string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}
