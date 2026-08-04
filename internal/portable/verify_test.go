package portable

import (
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestValidatePortablePayloadRefsTraversesMapsDeterministically(t *testing.T) {
	value := map[string]any{
		"z_late": map[string]any{
			"kind":                   "portable_payload_ref",
			"portable_id":            "missing-z",
			"source_artifact_id":     "provider_result:z",
			"source_artifact_digest": testDigest("z"),
		},
		"a_first": map[string]any{
			"kind":                   "portable_payload_ref",
			"portable_id":            "missing-a",
			"source_artifact_id":     "provider_result:a",
			"source_artifact_digest": testDigest("a"),
		},
	}

	for i := 0; i < 50; i++ {
		err := validatePortablePayloadRefs(value, map[string]map[string]any{})
		if err == nil {
			t.Fatal("validatePortablePayloadRefs succeeded, want missing ref")
		}
		if !strings.Contains(err.Error(), "missing-a") {
			t.Fatalf("error = %v, want first sorted missing ref missing-a", err)
		}
	}
}

func TestVerifyDirectoryPortableTamperTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*testing.T, *portableFixture)
		wantErr string
	}{
		{name: "valid"},
		{
			name: "mutated payload",
			mutate: func(t *testing.T, fixture *portableFixture) {
				writePortableFile(t, fixture.dir, "payloads/root_session/session.json", []byte(`{"kind":"portable_root_session","terminal_status":"tampered"}`))
			},
			wantErr: "size or digest mismatch",
		},
		{
			name: "broken provider result lineage",
			mutate: func(t *testing.T, fixture *portableFixture) {
				result := fixture.payloadValue(rootArtifactKindProviderResult, "artifact-000001").(map[string]any)
				result["phase"] = "facilitator"
				fixture.replacePayload(t, rootArtifactKindProviderResult, "artifact-000001", result)
				fixture.refresh(t)
			},
			wantErr: "does not match invocation draft",
		},
		{
			name: "missing provider result ref",
			mutate: func(t *testing.T, fixture *portableFixture) {
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000002").(map[string]any)
				delete(invocation["invocation"].(map[string]any), "provider_result_ref")
				fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000002", invocation)
				fixture.refresh(t)
			},
			wantErr: "requires provider_result_ref",
		},
		{
			name: "edited named input raw digest",
			mutate: func(t *testing.T, fixture *portableFixture) {
				manifest := fixture.payloadValue(rootArtifactKindNamedInputManifest, "named-input-manifest").(map[string]any)
				inputs := manifest["inputs"].([]any)
				inputs[1].(map[string]any)["raw_digest"] = testDigest("edited-raw-digest")
				fixture.replacePayload(t, rootArtifactKindNamedInputManifest, "named-input-manifest", manifest)
				fixture.refresh(t)
			},
			wantErr: "raw_digest does not match content",
		},
		{
			name: "duplicate cardinality one named input",
			mutate: func(t *testing.T, fixture *portableFixture) {
				manifest := fixture.payloadValue(rootArtifactKindNamedInputManifest, "named-input-manifest").(map[string]any)
				inputs := manifest["inputs"].([]any)
				duplicate := cloneObject(inputs[1].(map[string]any))
				manifest["inputs"] = append(inputs, duplicate)
				manifest["input_count"] = len(inputs) + 1
				fixture.replacePayload(t, rootArtifactKindNamedInputManifest, "named-input-manifest", manifest)
				fixture.refresh(t)
			},
			wantErr: "cardinality one",
		},
		{
			name: "provider retry attempt forbidden",
			mutate: func(t *testing.T, fixture *portableFixture) {
				result := fixture.payloadValue(rootArtifactKindProviderResult, "artifact-000001").(map[string]any)
				result["runner_attempt"] = 2
				result["invocation"].(map[string]any)["runner_attempt"] = 2
				fixture.replacePayload(t, rootArtifactKindProviderResult, "artifact-000001", result)
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000002").(map[string]any)
				invocation["invocation"].(map[string]any)["runner_attempt"] = 2
				fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000002", invocation)
				fixture.refresh(t)
			},
			wantErr: "requires runner_attempt 1",
		},
		{
			name: "unlaunched reducer forbidden",
			mutate: func(t *testing.T, fixture *portableFixture) {
				fixture.removePayload(t, rootArtifactKindProviderResult, "artifact-000025")
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000026").(map[string]any)
				record := invocation["invocation"].(map[string]any)
				record["provider_launch_attempted"] = false
				record["provider_result_ref"] = nil
				record["outcome"] = "failed"
				fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000026", invocation)
				fixture.refresh(t)
			},
			wantErr: "must be launched",
		},
		{
			name: "transcript provider result mismatch",
			mutate: func(t *testing.T, fixture *portableFixture) {
				transcript := fixture.payloadValue("participant_transcript", "transcript").([]any)
				transcript[0].(map[string]any)["provider_result_ref"] = portableTestRef("artifact-000007", "provider_result:000003")
				fixture.replacePayload(t, "participant_transcript", "transcript", transcript)
				fixture.refresh(t)
			},
			wantErr: "provider_result_ref does not match participant invocation",
		},
		{
			name: "trace only facilitator ledger leak",
			mutate: func(t *testing.T, fixture *portableFixture) {
				transcript := fixture.payloadValue("participant_transcript", "transcript").([]any)
				transcript[0].(map[string]any)["ledger"] = map[string]any{
					"settled":   []any{},
					"contested": []any{"FACILITATOR_SECRET"},
					"withdrawn": []any{},
				}
				fixture.replacePayload(t, "participant_transcript", "transcript", transcript)
				prompt := fixtureRenderedPromptPayload("participant prompt leaks FACILITATOR_SECRET")
				fixture.replacePayload(t, rootArtifactKindRenderedPrompt, "artifact-000009", prompt)
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000008").(map[string]any)
				invocation["invocation"].(map[string]any)["rendered_prompt_digest"] = prompt["rendered_prompt"].(map[string]any)["raw_digest"]
				fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000008", invocation)
				result := fixture.payloadValue(rootArtifactKindProviderResult, "artifact-000007").(map[string]any)
				result["invocation"].(map[string]any)["rendered_prompt_digest"] = prompt["rendered_prompt"].(map[string]any)["raw_digest"]
				fixture.replacePayload(t, rootArtifactKindProviderResult, "artifact-000007", result)
				fixture.refresh(t)
			},
			wantErr: "embeds facilitator ledger content",
		},
		{
			name: "contract digest mismatch",
			mutate: func(t *testing.T, fixture *portableFixture) {
				rootPlan := fixture.payloadValue(rootArtifactKindRootRecipePlan, "root-plan").(map[string]any)
				rootPlan["integration_contract_digest"] = testDigest("wrong-contract")
				fixture.replacePayload(t, rootArtifactKindRootRecipePlan, "root-plan", rootPlan)
				fixture.refresh(t)
			},
			wantErr: "integration_contract_digest does not match",
		},
		{
			name: "result validation canonical ref mismatch",
			mutate: func(t *testing.T, fixture *portableFixture) {
				validation := fixture.payloadValue(rootArtifactKindResultValidation, "result-validation").(map[string]any)
				validation["canonical_result_ref"] = portableTestRef("named-input-content-1", "named_input_content:000001")
				fixture.replacePayload(t, rootArtifactKindResultValidation, "result-validation", validation)
				fixture.refresh(t)
			},
			wantErr: "canonical_result_ref does not target canonical_result",
		},
		{
			name: "wrong source artifact digest on ref",
			mutate: func(t *testing.T, fixture *portableFixture) {
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000002").(map[string]any)
				ref := invocation["invocation"].(map[string]any)["provider_result_ref"].(map[string]any)
				ref["source_artifact_digest"] = testDigest("wrong-source")
				fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000002", invocation)
				fixture.refresh(t)
			},
			wantErr: "source identity mismatch",
		},
		{
			name: "orphan provider result",
			mutate: func(t *testing.T, fixture *portableFixture) {
				result, _, prompt := fixture.providerAttemptPayloads(t, 2, "artifact-999001", "artifact-999002", "artifact-999004")
				fixture.appendPayload(result)
				fixture.appendPayload(prompt)
				fixture.refresh(t)
			},
			wantErr: "is orphaned",
		},
		{
			name: "duplicate invocation result pairing",
			mutate: func(t *testing.T, fixture *portableFixture) {
				invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000002")
				fixture.appendPayload(mustPortablePayloadWithSource(t, rootArtifactKindProviderInvocation, "artifact-999003", invocation, testSourceRef("provider_invocation:999003")))
				fixture.refresh(t)
			},
			wantErr: "multiple incoming invocation edges",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPortableFixture(t)
			if test.mutate != nil {
				test.mutate(t, fixture)
			}
			report, err := VerifyDirectory(fixture.dir)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyDirectory: %v", err)
				}
				if report.Status != StatusValid || report.PayloadCount != 37 {
					t.Fatalf("report = %#v", report)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("VerifyDirectory error = %v, report=%#v, want %q", err, report, test.wantErr)
			}
		})
	}
}

func TestVerifyDirectorySurvivesRelocationAndSourceDeletion(t *testing.T) {
	fixture := newPortableFixture(t)
	relocated := filepath.Join(t.TempDir(), "relocated-portable")
	copyTree(t, fixture.dir, relocated)
	if err := os.RemoveAll(fixture.dir); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyDirectory(relocated)
	if err != nil {
		t.Fatalf("VerifyDirectory after relocation/source deletion: %v", err)
	}
	if report.Status != StatusValid || report.ManifestDigest == "" {
		t.Fatalf("report = %#v", report)
	}
}

func TestVerifyDirectoryReportsUnverifiedPromptProjection(t *testing.T) {
	fixture := newPortableFixture(t)
	invocation := fixture.payloadValue(rootArtifactKindProviderInvocation, "artifact-000002").(map[string]any)
	delete(invocation["invocation"].(map[string]any), "rendered_prompt_ref")
	delete(invocation["invocation"].(map[string]any), "rendered_prompt_digest")
	fixture.replacePayload(t, rootArtifactKindProviderInvocation, "artifact-000002", invocation)
	result := fixture.payloadValue(rootArtifactKindProviderResult, "artifact-000001").(map[string]any)
	delete(result["invocation"].(map[string]any), "rendered_prompt_ref")
	delete(result["invocation"].(map[string]any), "rendered_prompt_digest")
	fixture.replacePayload(t, rootArtifactKindProviderResult, "artifact-000001", result)
	fixture.refresh(t)

	report, err := VerifyDirectoryDetailed(fixture.dir)
	if err != nil {
		t.Fatalf("VerifyDirectoryDetailed: %v", err)
	}
	found := false
	for _, item := range report.UnverifiedRelationships {
		if item.Relationship == "trace_only_facilitator_ledger_prompt_projection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unverified relationships = %#v, want trace-only prompt projection note", report.UnverifiedRelationships)
	}
}

type portableFixture struct {
	dir      string
	payloads []portablePayload
	manifest map[string]any
}

type portablePayload struct {
	entry map[string]any
	body  []byte
}

func newPortableFixture(t *testing.T) *portableFixture {
	t.Helper()
	fixture := &portableFixture{dir: filepath.Join(t.TempDir(), "portable")}
	verdicts := fixtureVerdicts()
	canonicalResult := mustCanonicalString(t, verdicts)
	charterBytes := []byte(`{"charter":"input"}`)
	batchBytes := []byte(`{"batch":"input"}`)
	charterDigest := digest.RawBytes(charterBytes)
	batchDigest := digest.RawBytes(batchBytes)
	contract := fixtureContractBody(witnessContractFalsificationV2)
	contractDigest := mustSemanticDigest(t, contract)
	integrationContract := map[string]any{
		"kind":            rootArtifactKindIntegrationContract,
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"contract_id":     witnessContractFalsificationV2,
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	integrationContractSource := map[string]any{
		"id":     "integration_contract:selected",
		"digest": mustStorageEnvelopeDigest(t, rootArtifactKindIntegrationContract, integrationContract),
	}
	providerPayloads := []portablePayload{}
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
		prompt := fixtureRenderedPromptPayload(spec.phase + " prompt " + spec.source)
		result, invocation := fixtureProviderPayloads(1, spec.resultID, spec.promptID, spec.source, spec.phase, spec.ordinal, prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string))
		providerPayloads = append(providerPayloads,
			mustPortablePayloadWithSource(t, rootArtifactKindProviderResult, spec.resultID, result, testSourceRef("provider_result:"+spec.source)),
			mustPortablePayloadWithSource(t, rootArtifactKindProviderInvocation, spec.invocationID, invocation, testSourceRef("provider_invocation:"+spec.source)),
			mustPortablePayloadWithSource(t, rootArtifactKindRenderedPrompt, spec.promptID, prompt, testSourceRef("rendered_prompt:"+spec.source)),
		)
	}
	fixture.payloads = []portablePayload{
		mustPortablePayload(t, "root_session", "session", map[string]any{
			"execution_kind":  "recipe",
			"kind":            "portable_root_session",
			"provider_retry":  "forbid",
			"status":          "completed",
			"terminal_status": "completed",
		}),
		mustPortablePayload(t, "participant_transcript", "transcript", []any{
			map[string]any{"participant_turn": 1, "actor": "presenter", "content": "turn one", "provider_result_ref": portableTestRef("artifact-000001", "provider_result:000001")},
			map[string]any{"participant_turn": 2, "actor": "falsifier", "content": "turn two", "provider_result_ref": portableTestRef("artifact-000007", "provider_result:000003")},
			map[string]any{"participant_turn": 3, "actor": "presenter", "content": "turn three", "provider_result_ref": portableTestRef("artifact-000013", "provider_result:000005")},
			map[string]any{"participant_turn": 4, "actor": "falsifier", "content": "turn four", "provider_result_ref": portableTestRef("artifact-000019", "provider_result:000007")},
		}),
		mustPortablePayload(t, "diagnostics", "diagnostics", map[string]any{
			"execution_kind": "recipe",
			"status":         "completed",
		}),
		mustPortablePayloadWithSource(t, rootArtifactKindRootRecipePlan, "root-plan", map[string]any{
			"kind":                        rootArtifactKindRootRecipePlan,
			"schema_version":              2,
			"digest_profile":              digest.Profile,
			"recipe_id":                   "witness-falsify-v2-codex",
			"provider_retry":              "forbid",
			"result_source":               "reducer",
			"participant_turns":           4,
			"integration_bundle_digest":   testDigest("integration-bundle"),
			"integration_contract_id":     witnessContractFalsificationV2,
			"integration_contract_digest": contractDigest,
			"integration_contract_ref":    portableRef("integration-contract", integrationContractSource["id"].(string), integrationContractSource["digest"].(string)),
			"prompt_context": map[string]any{
				"participant_transcript": "complete",
				"facilitator_ledger":     "trace_only",
			},
		}, testSourceRef("root_recipe_plan:selected")),
		mustPortablePayloadWithSource(t, rootArtifactKindIntegrationContract, "integration-contract", integrationContract, integrationContractSource),
		mustPortablePayloadWithSource(t, rootArtifactKindNamedInputContent, "named-input-content-1", namedInputContentPayload("charter", 1, charterBytes), testSourceRef("named_input_content:000001")),
		mustPortablePayloadWithSource(t, rootArtifactKindNamedInputContent, "named-input-content-2", namedInputContentPayload("findings", 2, batchBytes), testSourceRef("named_input_content:000002")),
		mustPortablePayloadWithSource(t, rootArtifactKindNamedInputManifest, "named-input-manifest", map[string]any{
			"kind":           rootArtifactKindNamedInputManifest,
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"contract_id":    witnessContractFalsificationV2,
			"input_count":    2,
			"inputs": []any{
				namedInputEntry("charter", 1, "named-input-content-1", "named_input_content:000001", len(charterBytes), charterDigest),
				namedInputEntry("findings", 2, "named-input-content-2", "named_input_content:000002", len(batchBytes), batchDigest),
			},
		}, testSourceRef("named_input_manifest:selected")),
		mustPortablePayloadWithSource(t, rootArtifactKindCanonicalResult, "canonical-result", map[string]any{
			"kind":           rootArtifactKindCanonicalResult,
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"transport":      "json",
			"canonical_json": canonicalResult,
			"value":          verdicts,
		}, testSourceRef("canonical_result:selected")),
		mustPortablePayloadWithSource(t, rootArtifactKindResultValidation, "result-validation", map[string]any{
			"kind":           rootArtifactKindResultValidation,
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"status":         "validated",
			"canonical_result_ref": map[string]any{
				"kind":                   "portable_payload_ref",
				"portable_id":            "canonical-result",
				"source_artifact_id":     "canonical_result:selected",
				"source_artifact_digest": testSourceRef("canonical_result:selected")["digest"],
			},
		}, testSourceRef("result_validation:selected")),
	}
	fixture.payloads = append(fixture.payloads, providerPayloads...)
	fixture.sort()
	fixture.refresh(t)
	return fixture
}

func fixtureProviderPayloads(runnerAttempt int, resultPortableID string, promptPortableID string, sourceOrdinal string, phase string, participantOrdinal int, promptDigest string) (map[string]any, map[string]any) {
	invocationID := phase + ":" + sourceOrdinal
	invocationDraft := map[string]any{
		"schema_version":            ProviderInvocationV2,
		"invocation_id":             invocationID,
		"phase":                     phase,
		"actor":                     "Agent " + sourceOrdinal,
		"participant_ordinal":       nil,
		"reducer_fresh":             phase == "reducer",
		"rendered_prompt_ref":       portableTestRef(promptPortableID, "rendered_prompt:"+sourceOrdinal),
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
		"kind":            rootArtifactKindProviderResult,
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
	boundInvocation := cloneObject(invocationDraft)
	boundInvocation["provider_result_ref"] = map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            resultPortableID,
		"source_artifact_id":     "provider_result:" + sourceOrdinal,
		"source_artifact_digest": testSourceRef("provider_result:" + sourceOrdinal)["digest"],
	}
	invocationPayload := map[string]any{
		"kind":           rootArtifactKindProviderInvocation,
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"invocation":     boundInvocation,
	}
	return resultPayload, invocationPayload
}

func (fixture *portableFixture) providerAttemptPayloads(t *testing.T, runnerAttempt int, resultID string, invocationID string, promptID string) (portablePayload, portablePayload, portablePayload) {
	t.Helper()
	prompt := fixtureRenderedPromptPayload("orphan prompt")
	resultValue, invocationValue := fixtureProviderPayloads(runnerAttempt, resultID, promptID, "999999", "participant", 1, prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string))
	return mustPortablePayloadWithSource(t, rootArtifactKindProviderResult, resultID, resultValue, testSourceRef("provider_result:999999")),
		mustPortablePayloadWithSource(t, rootArtifactKindProviderInvocation, invocationID, invocationValue, testSourceRef("provider_invocation:999999")),
		mustPortablePayloadWithSource(t, rootArtifactKindRenderedPrompt, promptID, prompt, testSourceRef("rendered_prompt:999999"))
}

func fixtureVerdicts() contracts.RelayWitnessVerdictsDocument {
	return contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       "defect-batch-1",
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:      "finding-1",
			WitnessDigest:  testDigest("witness-1"),
			Verdict:        contracts.VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
		}},
	}
}

func fixtureContractBody(contractID string) map[string]any {
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

func namedInputContentPayload(name string, ordinal int, data []byte) map[string]any {
	return map[string]any{
		"kind":           rootArtifactKindNamedInputContent,
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

func fixtureRenderedPromptPayload(text string) map[string]any {
	data := []byte(text)
	return map[string]any{
		"kind":           rootArtifactKindRenderedPrompt,
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"rendered_prompt": map[string]any{
			"schema_version": RenderedPromptV1,
			"media_type":     "text/plain; charset=utf-8",
			"encoding":       "base64",
			"bytes_base64":   base64.StdEncoding.EncodeToString(data),
			"size_bytes":     len(data),
			"raw_digest":     digest.RawBytes(data),
		},
	}
}

func mustCanonicalString(t *testing.T, value any) string {
	t.Helper()
	data, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustSemanticDigest(t *testing.T, value any) string {
	t.Helper()
	digestValue, err := digest.SemanticJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return digestValue
}

func mustStorageEnvelopeDigest(t *testing.T, kind string, value any) string {
	t.Helper()
	digestValue, err := digest.StorageEnvelope(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return digestValue
}

func namedInputEntry(name string, ordinal int, portableID string, sourceID string, sizeBytes int, rawDigest string) map[string]any {
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
		"content_ref":   portableTestRef(portableID, sourceID),
	}
}

func portableTestRef(portableID string, sourceID string) map[string]any {
	return portableRef(portableID, sourceID, testSourceRef(sourceID)["digest"].(string))
}

func portableRef(portableID string, sourceID string, sourceDigest string) map[string]any {
	return map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            portableID,
		"source_artifact_id":     sourceID,
		"source_artifact_digest": sourceDigest,
	}
}

func mustPortablePayload(t *testing.T, kind string, id string, value any) portablePayload {
	t.Helper()
	return mustPortablePayloadWithSource(t, kind, id, value, nil)
}

func mustPortablePayloadWithSource(t *testing.T, kind string, id string, value any, sourceRef map[string]any) portablePayload {
	t.Helper()
	body, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
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
	return portablePayload{entry: entry, body: body}
}

func (fixture *portableFixture) payloadValue(kind string, id string) any {
	for _, payload := range fixture.payloads {
		if payload.entry["kind"] == kind && payload.entry["portable_id"] == id {
			value, err := strictjson.DecodeAnyBytes(payload.body, strictjson.DefaultMaxBytes)
			if err != nil {
				panic(err)
			}
			return value
		}
	}
	return nil
}

func (fixture *portableFixture) replacePayload(t *testing.T, kind string, id string, value any) {
	t.Helper()
	for index, payload := range fixture.payloads {
		if payload.entry["kind"] != kind || payload.entry["portable_id"] != id {
			continue
		}
		var sourceRef map[string]any
		if payload.entry["source_artifact_id"] != nil {
			sourceRef = map[string]any{
				"id":     payload.entry["source_artifact_id"],
				"digest": payload.entry["source_artifact_digest"],
			}
		}
		fixture.payloads[index] = mustPortablePayloadWithSource(t, kind, id, value, sourceRef)
		return
	}
	t.Fatalf("payload %s/%s not found", kind, id)
}

func (fixture *portableFixture) appendPayload(payload portablePayload) {
	fixture.payloads = append(fixture.payloads, payload)
	fixture.sort()
}

func (fixture *portableFixture) removePayload(t *testing.T, kind string, id string) {
	t.Helper()
	for index, payload := range fixture.payloads {
		if payload.entry["kind"] == kind && payload.entry["portable_id"] == id {
			fixture.payloads = append(fixture.payloads[:index], fixture.payloads[index+1:]...)
			return
		}
	}
	t.Fatalf("payload %s/%s not found", kind, id)
}

func (fixture *portableFixture) sort() {
	sort.Slice(fixture.payloads, func(i, j int) bool {
		return stringValue(fixture.payloads[i].entry["path"]) < stringValue(fixture.payloads[j].entry["path"])
	})
}

func (fixture *portableFixture) refresh(t *testing.T) {
	t.Helper()
	for _, payload := range fixture.payloads {
		writePortableFile(t, fixture.dir, stringValue(payload.entry["path"]), payload.body)
	}
	inventory := make([]any, 0, len(fixture.payloads))
	for _, payload := range fixture.payloads {
		inventory = append(inventory, payload.entry)
	}
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version":      ExportSchemaVersion,
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
	fixture.manifest = manifest
	body, err := canonjson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writePortableFile(t, fixture.dir, "manifest.json", body)
}

func writePortableFile(t *testing.T, root string, relative string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, source string, target string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		return os.WriteFile(destination, body, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func cloneObject(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func testSourceRef(id string) map[string]any {
	return map[string]any{
		"kind":           "artifact_ref",
		"schema_version": 1,
		"id":             id,
		"digest":         testDigest(id),
	}
}

func testDigest(seed string) string {
	return digest.RawBytes([]byte(seed))
}
