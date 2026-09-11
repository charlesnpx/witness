package planning

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/contracts"
)

func TestAssembleInvalidReceiptAndMissingRelayRemainPending(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Batches) != 1 {
		t.Fatalf("planned batches = %#v", planResult.Batches)
	}

	receipt := validContradictoryReceipt(planResult.Plan, "finding-1")
	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  planResult.Batches[0].Plan.BatchID,
			Document: planResult.Batches[0].Document,
		}},
		Receipts:     []contracts.ExecutionReceipt{receipt},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted an unauthenticated contradictory receipt")
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("batch manifest record = %#v, want unavailable", result.Manifest.Batches)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
	if len(result.ReceiptContradictions) != 0 {
		t.Fatalf("receipt contradictions = %#v, want none", result.ReceiptContradictions)
	}
	if len(result.Manifest.ExecutionReceipts) != 1 || result.Manifest.ExecutionReceipts[0].Status != contracts.ExecutionStatusFailed {
		t.Fatalf("execution receipt records = %#v, want failed", result.Manifest.ExecutionReceipts)
	}
}

func TestAssembleRelayAbsentPreflightRecordsLaunchStatus(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	refs := validManifestEvidenceRefs()
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight: PreflightBinding{
			SnapshotDigest:          testDigest("artifact"),
			RelayPresent:            false,
			IntegrationBundleDigest: refs.IntegrationBundle.Digest,
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  planResult.Batches[0].Plan.BatchID,
			Document: planResult.Batches[0].Document,
		}},
		EvidenceRefs: refs,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if result.Manifest.ConsumerIdentity["witness_relay_launch_status"] != contracts.RelayLaunchStatusAbsent {
		t.Fatalf("consumer identity = %#v, want relay_absent launch status", result.Manifest.ConsumerIdentity)
	}
	rawBatches, ok := result.Manifest.ConsumerIdentity["witness_relay_batches"].(map[string]any)
	if !ok {
		t.Fatalf("consumer identity = %#v, missing relay batch metadata", result.Manifest.ConsumerIdentity)
	}
	batch, ok := rawBatches[planResult.Plan.Batches[0].BatchID].(map[string]any)
	if !ok || batch["relay_launch_status"] != contracts.RelayLaunchStatusAbsent {
		t.Fatalf("batch metadata = %#v, want relay_absent launch status", rawBatches)
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable relay-absent batch", result.Manifest.Batches)
	}
}

func TestRelayUnavailableFailureReasonRequiresStartFailure(t *testing.T) {
	tests := []struct {
		name   string
		record map[string]any
		want   string
	}{
		{
			name: "provider false without start failure",
			record: map[string]any{
				"status":           "launch_failed",
				"provider_invoked": "false",
				"relay_launch":     map[string]any{"start_failed": false},
			},
			want: "relay_run_recorded_unavailable",
		},
		{
			name: "provider unknown",
			record: map[string]any{
				"status":           "launch_failed",
				"provider_invoked": "unknown",
				"relay_launch":     map[string]any{"start_failed": true},
			},
			want: "relay_run_recorded_unavailable",
		},
		{
			name: "explicit start failure",
			record: map[string]any{
				"status":           "launch_failed",
				"provider_invoked": "false",
				"relay_launch":     map[string]any{"start_failed": true},
			},
			want: "relay_launch_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := relayUnavailableFailureReason(RelayEvidence{RunRecords: []map[string]any{test.record}})
			if got != test.want {
				t.Fatalf("failure reason = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAssembleRetainsLaunchFailureAndPrefersConsumingRetry(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	stdout := "diagnostic stdout"
	stderr := "diagnostic stderr"
	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:      batch.Plan.BatchID,
			RecipeFamily: batch.Plan.RecipeFamily,
			Backend:      "codex",
			RunRecords: []map[string]any{
				{
					"schema_version":   "witness-relay-verification-run-v2",
					"batch_id":         batch.Plan.BatchID,
					"recipe_id":        batch.Plan.RecipeFamily + "-codex",
					"consumes_batch":   false,
					"status":           "launch_failed",
					"provider_invoked": "false",
					"relay_launch": map[string]any{
						"stdout_b64":       base64.StdEncoding.EncodeToString([]byte(stdout)),
						"stderr_b64":       base64.StdEncoding.EncodeToString([]byte(stderr)),
						"stdout_digest":    digest.RawBytes([]byte(stdout)),
						"stderr_digest":    digest.RawBytes([]byte(stderr)),
						"stdout_bytes":     len([]byte(stdout)),
						"stderr_bytes":     len([]byte(stderr)),
						"start_failed":     true,
						"stdout_truncated": true,
						"stderr_truncated": false,
					},
				},
				{
					"schema_version":   "witness-relay-verification-run-v2",
					"batch_id":         batch.Plan.BatchID,
					"recipe_id":        batch.Plan.RecipeFamily + "-codex",
					"consumes_batch":   true,
					"status":           contracts.RecordStatusUnavailable,
					"provider_invoked": "unknown",
					"plan_digest":      testDigest("plan"),
				},
			},
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].FailureReason != "relay_run_recorded_unavailable" {
		t.Fatalf("manifest batches = %#v, want consuming record to determine unavailable reason", result.Manifest.Batches)
	}
	rawBatches, ok := result.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	if !ok {
		t.Fatalf("consumer identity = %#v, missing relay batch metadata", result.Manifest.ConsumerIdentity)
	}
	metadata, ok := rawBatches[batch.Plan.BatchID].(map[string]any)
	if !ok {
		t.Fatalf("relay batch metadata = %#v", rawBatches)
	}
	runRecords, ok := metadata["run_records"].([]map[string]any)
	if !ok || len(runRecords) != 2 {
		t.Fatalf("run records = %#v", metadata["run_records"])
	}
	launch, ok := runRecords[0]["relay_launch"].(map[string]any)
	if !ok {
		t.Fatalf("run record = %#v, missing launch metadata", runRecords[0])
	}
	if _, exists := launch["stdout"]; exists {
		t.Fatalf("launch metadata retained raw stdout: %#v", launch)
	}
	if _, exists := launch["stderr"]; exists {
		t.Fatalf("launch metadata retained raw stderr: %#v", launch)
	}
	if launch["stdout_digest"] != digest.RawBytes([]byte(stdout)) || launch["stdout_bytes"] != len([]byte(stdout)) || launch["stdout_truncated"] != true {
		t.Fatalf("stdout metadata = %#v", launch)
	}
	if launch["stderr_digest"] != digest.RawBytes([]byte(stderr)) || launch["stderr_bytes"] != len([]byte(stderr)) || launch["stderr_truncated"] != false {
		t.Fatalf("stderr metadata = %#v", launch)
	}
}

func TestAssembleRejectsRunRecordRecipeMismatchToPlannedBatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:      batch.Plan.BatchID,
			RecipeFamily: batch.Plan.RecipeFamily,
			Backend:      "codex",
			RunRecords: []map[string]any{{
				"schema_version":   "witness-relay-verification-run-v2",
				"batch_id":         batch.Plan.BatchID,
				"recipe_id":        "economy-equivalence-v2-codex",
				"status":           contracts.RecordStatusUnavailable,
				"provider_invoked": "unknown",
				"consumes_batch":   true,
				"plan_digest":      testDigest("plan"),
			}},
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a run record whose recipe does not match the planned batch")
	}
	if result == nil || len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].FailureReason != "relay_run_record_provenance_mismatch" {
		t.Fatalf("result = %#v, want failed run-record provenance", result)
	}
	diagnostics := err.(*ValidationError).Diagnostics
	found := false
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeInvalidRelayRunRecord && diagnostic.Details["expected_recipe_family"] == batch.Plan.RecipeFamily {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want planned recipe-family mismatch", diagnostics)
	}
}

func TestAssembleAllowListsRelayRunRecordMetadata(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	const (
		sentinel     = "relay-run-record-secret-sentinel"
		pathSentinel = "relay-run-record-path-sentinel"
	)
	argv := []string{
		"/private/" + pathSentinel + "/bin/fake-relay",
		"run",
		"--integration-bundle",
		"/private/" + pathSentinel + "/integration-bundle.json",
	}
	runRecordDigest := digest.RawBytes([]byte("locally-retained-run-record"))
	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:      batch.Plan.BatchID,
			RecipeFamily: batch.Plan.RecipeFamily,
			Backend:      "codex",
			RunRecords: []map[string]any{{
				"schema_version":   "witness-relay-verification-run-v2",
				"batch_id":         batch.Plan.BatchID,
				"recipe_id":        "witness-falsify-v2-codex",
				"status":           contracts.RecordStatusUnavailable,
				"provider_invoked": "unknown",
				"consumes_batch":   true,
				"plan_digest":      testDigest("plan"),
				"input_bindings":   []string{"token=" + sentinel},
				"relay_run_result": map[string]any{"provider_response": sentinel},
				"session_dir":      sentinel,
				"diagnostics": []map[string]any{{
					"code":    "relayrun_launch_failed",
					"message": sentinel,
					"details": map[string]any{"provider_payload": sentinel},
				}},
				"run_record_digest": runRecordDigest,
				"relay_launch": map[string]any{
					"argv":              argv,
					"working_directory": "/private/" + pathSentinel + "/workspace",
					"exit_code":         1,
					"start_failed":      false,
					"stdout":            sentinel,
					"stderr":            "relay failed",
					"stdout_truncated":  true,
					"stderr_truncated":  false,
				},
			}},
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	manifestBytes, err := contracts.CanonicalBytes(result.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifestBytes, []byte(sentinel)) {
		t.Fatalf("encoded manifest retained local relay content: %s", manifestBytes)
	}
	if bytes.Contains(manifestBytes, []byte(pathSentinel)) {
		t.Fatalf("encoded manifest retained local relay path: %s", manifestBytes)
	}
	rawBatches := result.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	metadata := rawBatches[batch.Plan.BatchID].(map[string]any)
	runRecords, ok := metadata["run_records"].([]map[string]any)
	if !ok || len(runRecords) != 1 {
		t.Fatalf("run records = %#v", metadata["run_records"])
	}
	retained := runRecords[0]
	if _, exists := retained["relay_run_result"]; exists {
		t.Fatalf("manifest metadata retained relay_run_result: %#v", retained)
	}
	if retained["run_record_digest"] != runRecordDigest {
		t.Fatalf("run record metadata = %#v, want retained run-record digest", retained)
	}
	launch, ok := retained["relay_launch"].(map[string]any)
	if !ok {
		t.Fatalf("run record = %#v, missing launch summary", retained)
	}
	if _, exists := launch["argv"]; exists {
		t.Fatalf("launch summary retained argv: %#v", launch)
	}
	if _, exists := launch["working_directory"]; exists {
		t.Fatalf("launch summary retained working directory: %#v", launch)
	}
	if launch["executable"] != "fake-relay" {
		t.Fatalf("launch executable = %#v, want fake-relay", launch["executable"])
	}
	canonicalArgv, err := contracts.CanonicalBytes(argv)
	if err != nil {
		t.Fatal(err)
	}
	argvDigest := digest.RawBytes(canonicalArgv)
	if launch["argv_digest"] != argvDigest {
		t.Fatalf("launch argv digest = %#v, want %q", launch["argv_digest"], argvDigest)
	}
	if launch["stdout_digest"] != digest.RawBytes([]byte(sentinel)) || launch["stdout_bytes"] != len([]byte(sentinel)) || launch["stdout_truncated"] != true {
		t.Fatalf("stdout launch summary = %#v", launch)
	}
	if launch["stderr_digest"] != digest.RawBytes([]byte("relay failed")) || launch["stderr_bytes"] != len([]byte("relay failed")) || launch["stderr_truncated"] != false {
		t.Fatalf("stderr launch summary = %#v", launch)
	}
	diagnostics, ok := retained["diagnostics"].([]map[string]any)
	if !ok || len(diagnostics) != 1 || len(diagnostics[0]) != 1 || diagnostics[0]["code"] != "relayrun_launch_failed" {
		t.Fatalf("manifest diagnostics = %#v, want code-only failure diagnostic", retained["diagnostics"])
	}
}

func TestAssembleSanitizesForgedRelayLaunchStatusOnRelayPresent(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	refs := validManifestEvidenceRefs()
	refs.ConsumerIdentity = map[string]any{
		"kind": "test",
		"id":   "consumer",
		contracts.VerificationManifestRelayLaunchStatusKey: contracts.RelayLaunchStatusAbsent,
		contracts.VerificationManifestRelayBatchesKey: map[string]any{
			batch.Plan.BatchID: map[string]any{
				"recipe_family": "forged-family",
				"backend":       "forged-backend",
				"finding_ids":   []string{"forged-finding"},
				contracts.VerificationManifestBatchRelayLaunchStatusKey: contracts.RelayLaunchStatusAbsent,
			},
		},
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:      batch.Plan.BatchID,
			RecipeFamily: batch.Plan.RecipeFamily,
			Backend:      "codex",
		}},
		EvidenceRefs: refs,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if result.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayLaunchStatusKey] != contracts.RelayLaunchStatusPresent {
		t.Fatalf("consumer identity = %#v, want synthesized relay_present launch status", result.Manifest.ConsumerIdentity)
	}
	rawBatches, ok := result.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	if !ok {
		t.Fatalf("consumer identity = %#v, missing relay batch metadata", result.Manifest.ConsumerIdentity)
	}
	batchMetadata, ok := rawBatches[batch.Plan.BatchID].(map[string]any)
	if !ok {
		t.Fatalf("relay batch metadata = %#v, missing batch %s", rawBatches, batch.Plan.BatchID)
	}
	if batchMetadata[contracts.VerificationManifestBatchRelayLaunchStatusKey] != contracts.RelayLaunchStatusPresent {
		t.Fatalf("batch metadata = %#v, want synthesized relay_present launch status", batchMetadata)
	}
	if batchMetadata["backend"] != "codex" || batchMetadata["recipe_family"] != batch.Plan.RecipeFamily {
		t.Fatalf("batch metadata = %#v, want codex %s", batchMetadata, batch.Plan.RecipeFamily)
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable relay-present batch", result.Manifest.Batches)
	}
	if diagnostics := contracts.ValidateVerificationManifest(result.Manifest); len(diagnostics) > 0 {
		t.Fatalf("manifest diagnostics = %#v", diagnostics)
	}

	if _, err := adjudicate.Run(adjudicate.Options{
		FrozenCharter: frozen,
		RoleOutputs:   []adjudicate.RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Manifest:      result.Manifest,
	}); err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
}

func TestAssembleRejectsBatchEvidenceThatDoesNotMatchPlan(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	tamperedBatch := planResult.Batches[0].Document
	tamperedBatch.BatchID = "detached-batch"

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  planResult.Batches[0].Plan.BatchID,
			Document: tamperedBatch,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted mismatched batch evidence")
	}
	if result == nil || len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusFailed {
		t.Fatalf("manifest batches = %#v, want failed", result)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
}

func TestAssembleRejectsBatchEvidenceBytesThatDoNotMatchPlan(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	canonicalWithoutNewline, err := contracts.VerificationBatchCanonicalBytes(batch.Document)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
			RawBytes: canonicalWithoutNewline,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted byte-different batch evidence")
	}
	if result == nil || len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].FailureReason != "verification_batch_mismatch" {
		t.Fatalf("manifest batches = %#v, want verification batch mismatch", result)
	}
}

func TestAssembleBindsVerdictsToPortableCanonicalResult(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	frozenBytes := canonjson.MustMarshal(frozen)
	verified, portableDir := writePlanningRelayV2Bundle(t, batch, frozenBytes)
	exportedVerdicts, err := contracts.ReadRelayWitnessVerdictsBytes([]byte(verified.Session.Root.Result.Value))
	if err != nil {
		t.Fatalf("decode fake Relay result: %v", err)
	}
	suppliedVerdicts := exportedVerdicts
	suppliedVerdicts.Verdicts[0].Rationale = "not the exported canonical result"
	relayEvidence := RelayEvidence{
		BatchID:           batch.Plan.BatchID,
		PortableExportDir: portableDir,
		VerifiedBundle:    verified,
		Verdicts:          &suppliedVerdicts,
	}
	if _, assemblyErr := assembleRelayV2Evidence(relayEvidence, batch.Plan, planResult.Plan, batch.Document); assemblyErr == nil || !strings.Contains(assemblyErr.Error(), "embedded relay verdicts") {
		t.Fatalf("assembleRelayV2Evidence error = %v, want embedded-result binding diagnostic", assemblyErr)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{relayEvidence},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted relay verdicts that were not the export canonical result")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	record := result.Manifest.Batches[0]
	if record.Status != contracts.RecordStatusFailed || record.FailureReason != "relay_v2_bundle_invalid" {
		t.Fatalf("manifest batch record = %#v, want invalid v2 bundle evidence", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
}

func TestAssembleLeavesEmptyVerifiedResultPendingDespiteSuppliedVerdicts(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	t.Setenv("WITNESS_FAKE_RELAY_EMPTY_ROOT_RESULT", "1")
	verified, portableDir := writePlanningRelayV2Bundle(t, batch, canonjson.MustMarshal(frozen))
	suppliedVerdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.Plan.BatchID,
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:     finding.ID,
			WitnessDigest: batch.Document.Findings[0].WitnessDigest,
			Verdict:       contracts.VerdictSurvived,
			Rationale:     "stale verdict supplied separately from the empty bundle result",
		}},
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:           batch.Plan.BatchID,
			RecipeFamily:      batch.Plan.RecipeFamily,
			Backend:           "codex",
			PortableExportDir: portableDir,
			VerifiedBundle:    verified,
			Verdicts:          &suppliedVerdicts,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted supplied verdicts for an empty verified result")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want one manifest batch", result)
	}
	if record := result.Manifest.Batches[0]; record.Status != contracts.RecordStatusFailed || record.FailureReason != "relay_v2_bundle_invalid" {
		t.Fatalf("manifest batch = %#v, want failed relay bundle", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != finding.ID {
		t.Fatalf("pending verification = %#v, want %s", result.PendingVerification, finding.ID)
	}
}

func TestAssembleRejectsSerializedVerifiedBundleWithoutPortableDirectory(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	verified, portableDir := writePlanningRelayV2Bundle(t, batch, canonjson.MustMarshal(frozen))
	exportedVerdicts, err := contracts.ReadRelayWitnessVerdictsBytes([]byte(verified.Session.Root.Result.Value))
	if err != nil {
		t.Fatalf("decode fake Relay result: %v", err)
	}
	exportedVerdicts.Verdicts[0].Rationale = "edited after export"
	tampered := *verified
	tampered.Session.Root.Result.Value = string(canonjson.MustMarshal(exportedVerdicts))
	serialized, err := json.Marshal(struct {
		VerifiedBundle *bundle.Verification `json:"verified_bundle"`
	}{VerifiedBundle: &tampered})
	if err != nil {
		t.Fatalf("serialize run-record evidence: %v", err)
	}
	var decoded struct {
		VerifiedBundle *bundle.Verification `json:"verified_bundle"`
	}
	if err := json.Unmarshal(serialized, &decoded); err != nil {
		t.Fatalf("decode run-record evidence: %v", err)
	}
	if err := os.RemoveAll(portableDir); err != nil {
		t.Fatalf("delete portable bundle directory: %v", err)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:        batch.Plan.BatchID,
			RecipeFamily:   batch.Plan.RecipeFamily,
			Backend:        "codex",
			VerifiedBundle: decoded.VerifiedBundle,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted serialized bundle evidence without a portable directory")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	if record := result.Manifest.Batches[0]; record.Status == contracts.RecordStatusValid {
		t.Fatalf("manifest batch = %#v, want unavailable or failed", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
}

func TestAssembleRejectsPortableCharterDigestMismatchPending(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	frozenBytes := canonjson.MustMarshal(frozen)
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		CharterDigest: digest.RawBytes(frozenBytes),
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	verified, portableDir := writePlanningRelayV2Bundle(t, batch, []byte(`{"charter":"tampered"}`))
	relayEvidence := RelayEvidence{
		BatchID:           batch.Plan.BatchID,
		PortableExportDir: portableDir,
		VerifiedBundle:    verified,
	}
	if _, assemblyErr := assembleRelayV2Evidence(relayEvidence, batch.Plan, planResult.Plan, batch.Document); assemblyErr == nil || !strings.Contains(assemblyErr.Error(), "plan.inputs.charter digest") {
		t.Fatalf("assembleRelayV2Evidence error = %v, want charter digest binding diagnostic", assemblyErr)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{relayEvidence},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a v2 bundle with the wrong charter input")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	record := result.Manifest.Batches[0]
	if record.Status != contracts.RecordStatusFailed || record.FailureReason != "relay_v2_bundle_invalid" {
		t.Fatalf("manifest batch record = %#v, want invalid v2 bundle evidence", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
}

func TestAssembleMissingRequiredPromptEvidenceFailsPendingAndVisible(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	frozenBytes := canonjson.MustMarshal(frozen)
	verified, portableDir := writePlanningRelayV2Bundle(t, batch, frozenBytes)
	// Relay v2 does not export provider-prompt projections. Its required
	// participant transcript is the durable public conversation evidence.
	transcriptPath := filepath.Join(portableDir, "payloads", "participant_transcript", "transcript.json")
	if err := os.Remove(transcriptPath); err != nil {
		t.Fatalf("remove required v2 transcript evidence: %v", err)
	}
	relayEvidence := RelayEvidence{
		BatchID:           batch.Plan.BatchID,
		PortableExportDir: portableDir,
		VerifiedBundle:    verified,
	}
	if _, assemblyErr := assembleRelayV2Evidence(relayEvidence, batch.Plan, planResult.Plan, batch.Document); assemblyErr == nil || !strings.Contains(assemblyErr.Error(), "participant_transcript") {
		t.Fatalf("assembleRelayV2Evidence error = %v, want missing transcript diagnostic", assemblyErr)
	}

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{relayEvidence},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted missing required v2 transcript evidence")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	record := result.Manifest.Batches[0]
	if record.Status != contracts.RecordStatusFailed || record.FailureReason != "relay_v2_bundle_invalid" {
		t.Fatalf("manifest batch record = %#v, want invalid v2 bundle evidence", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
}

func TestAssembleRejectsPlanDigestMismatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	tamperedPlan := planResult.Plan
	tamperedPlan.ArtifactDigest = testDigest("different-artifact")

	result, err := Assemble(AssembleOptions{
		Plan:         tamperedPlan,
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a plan_digest mismatch")
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil for input-level plan mismatch", result)
	}
	diagnostics := err.(*ValidationError).Diagnostics
	if len(diagnostics) != 1 || diagnostics[0].Code != CodeInvalidPlanDigest {
		t.Fatalf("diagnostics = %#v, want %s", diagnostics, CodeInvalidPlanDigest)
	}
}

func TestAssembleRederivesDeclaredChangeSurface(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	finding := planningTestFinding("in-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	finding.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/changed.go"}}
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	roleOutput.ArtifactDigest = headDigest
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", RefID: "defect-json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	tamperedPlan := planResult.Plan
	tamperedSurface := *tamperedPlan.ChangeSurface
	tamperedSurface.ChangedPaths = []changesurface.PathChange{{Path: "internal/unchanged.go", ChangeKinds: []string{changesurface.ChangeKindModified}}}
	tamperedDigest, err := changesurface.Digest(tamperedSurface)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPlan.ChangeSurface = &tamperedSurface
	tamperedPlan.ChangeSurfaceDigest = tamperedDigest
	if err := stampPlanDigest(&tamperedPlan); err != nil {
		t.Fatal(err)
	}

	result, err := Assemble(AssembleOptions{
		Plan:         tamperedPlan,
		EvidenceRefs: validManifestEvidenceRefs(),
		BaseManifest: &baseManifest,
		HeadManifest: &headManifest,
	})
	if err == nil {
		t.Fatal("Assemble accepted a tampered but self-consistent change surface")
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil for input-level change surface mismatch", result)
	}
	if planningErrorCode(err) != changesurface.CodeInvalidChangeSurface {
		t.Fatalf("err = %v, want %s", err, changesurface.CodeInvalidChangeSurface)
	}
}

func TestAssembleDeclaredChangeSurfaceRequiresDerivationManifests(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	finding := planningTestFinding("in-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	finding.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/changed.go"}}
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	roleOutput.ArtifactDigest = headDigest
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", RefID: "defect-json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	result, err := Assemble(AssembleOptions{
		Plan:         planResult.Plan,
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a declared change surface without derivation manifests")
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil for missing derivation manifests", result)
	}
	if planningErrorCode(err) != changesurface.CodeMissingDerivationManifest {
		t.Fatalf("err = %v, want %s", err, changesurface.CodeMissingDerivationManifest)
	}
}

func TestAssembleRejectsBaselinePassExcludedFindingWithoutChangeSurface(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("included", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", RefID: "defect-json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
		ChangeSurface: ChangeSurfaceInput{BaselinePass: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Plan.Batches) != 1 || len(planResult.Plan.ExcludedFindings) != 0 || planResult.Plan.ChangeSurface != nil || planResult.Plan.BaselinePass == nil {
		t.Fatalf("plan = %#v, want baseline-pass plan with included finding", planResult.Plan)
	}
	batch := planResult.Batches[0]
	tamperedPlan := planResult.Plan
	tamperedPlan.ExcludedFindings = []ExcludedFinding{{
		Role:                   contracts.RoleDefect,
		FindingID:              finding.ID,
		SourceRoleOutputRef:    batch.Plan.SourceRoleOutputRef,
		SourceRoleOutputDigest: batch.Plan.SourceRoleOutputDigest,
		Disposition:            contracts.DispositionAdvisory,
		Reason:                 contracts.ReasonOutOfDelta,
	}}
	if err := stampPlanDigest(&tamperedPlan); err != nil {
		t.Fatal(err)
	}

	result, err := Assemble(AssembleOptions{
		Plan: tamperedPlan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a baseline-pass plan with a fabricated out_of_delta exclusion")
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil for input-level exclusion rejection", result)
	}
	if planningErrorCode(err) != CodeInvalidManifest {
		t.Fatalf("err = %v, want %s", err, CodeInvalidManifest)
	}
}

func TestAssembleRejectsV1PlanBeforeDigestAcceptance(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	legacyPlan := planResult.Plan
	legacyPlan.SchemaVersion = "witness-verification-plan-v1"
	if err := stampPlanDigest(&legacyPlan); err != nil {
		t.Fatal(err)
	}

	result, err := Assemble(AssembleOptions{
		Plan:         legacyPlan,
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted a digest-valid v1 verification plan")
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil for unsupported plan schema", result)
	}
	if planningErrorCode(err) != CodeInvalidPlanDigest {
		t.Fatalf("err = %v, want %s", err, CodeInvalidPlanDigest)
	}
}

func TestExcludedOutOfDeltaFindingsCarryThroughAssemblyAndAdjudication(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	outOfDelta := planningTestFinding("out-of-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	outOfDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/unchanged.go"}}
	inDelta := planningTestFinding("in-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	inDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/changed.go"}}
	outRoleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{outOfDelta})
	outRoleOutput.ArtifactDigest = headDigest
	inRoleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{inDelta})
	inRoleOutput.ArtifactDigest = headDigest
	preflight := planningTestPreflightBinding(t)
	preflight.SnapshotDigest = headDigest
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "role-a.json", RefID: "role-a", Document: outRoleOutput},
			{Path: "role-b.json", RefID: "role-b", Document: inRoleOutput},
		},
		Preflight:     preflight,
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Plan.ExcludedFindings) != 1 || planResult.Plan.ExcludedFindings[0].SourceRoleOutputDigest == "" {
		t.Fatalf("plan exclusions = %#v, want one bound out-of-delta exclusion", planResult.Plan.ExcludedFindings)
	}

	assembled, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  planResult.Batches[0].Plan.BatchID,
			Document: planResult.Batches[0].Document,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
		BaseManifest: &baseManifest,
		HeadManifest: &headManifest,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	manifest := assembled.Manifest
	if len(manifest.ExcludedFindings) != 1 || manifest.ExcludedFindings[0].FindingID != outOfDelta.ID {
		t.Fatalf("manifest exclusions = %#v, want out-of-delta record", manifest.ExcludedFindings)
	}

	_, err = adjudicate.Run(adjudicate.Options{
		FrozenCharter: frozen,
		RoleOutputs:   []adjudicate.RoleOutputInput{{Path: "role-b.json", Document: inRoleOutput}},
		Manifest:      manifest,
		BaseManifest:  &baseManifest,
		HeadManifest:  &headManifest,
	})
	if err == nil {
		t.Fatal("adjudication accepted manifest exclusions without the excluding role output")
	}
	if got := adjudicationErrorCode(err); got != adjudicate.CodeInvalidManifest {
		t.Fatalf("adjudication err = %v, want %s", err, adjudicate.CodeInvalidManifest)
	}

	adjudicated, err := adjudicate.Run(adjudicate.Options{
		FrozenCharter: frozen,
		RoleOutputs: []adjudicate.RoleOutputInput{
			{Path: "role-a.json", Document: outRoleOutput},
			{Path: "role-b.json", Document: inRoleOutput},
		},
		Manifest:     manifest,
		BaseManifest: &baseManifest,
		HeadManifest: &headManifest,
	})
	if err != nil {
		t.Fatalf("adjudicate with exclusion coverage: %v", err)
	}
	byID := map[string]adjudicate.FindingVerdict{}
	for _, finding := range adjudicated.Findings {
		byID[finding.FindingID] = finding
	}
	excluded := byID[outOfDelta.ID]
	if excluded.Disposition != contracts.DispositionAdvisory {
		t.Fatalf("excluded verdict = %#v, want advisory", excluded)
	}
	if !stringSliceContains(excluded.Reasons, contracts.ReasonOutOfDelta) {
		t.Fatalf("excluded reasons = %#v, want out_of_delta", excluded.Reasons)
	}
	if excluded.Relay != nil || excluded.Execution != nil {
		t.Fatalf("excluded verdict used verification evidence: %#v", excluded)
	}
}

func TestAttributionExcludedFindingsCarryThroughAssemblyAndAdjudication(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	finding := planningTestFinding("pre-existing", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	finding.Attribution = contracts.FindingAttributionPreExisting
	finding.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/unchanged.go"}}
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	roleOutput.SchemaVersion = contracts.RoleOutputV4
	roleOutput.ArtifactDigest = headDigest
	preflight := planningTestPreflightBinding(t)
	preflight.SnapshotDigest = headDigest

	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "role.json", RefID: "role", Document: roleOutput}},
		Preflight:     preflight,
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Batches) != 0 || len(planResult.Plan.ExcludedFindings) != 1 || planResult.Plan.ExcludedFindings[0].Reason != contracts.ReasonPreExisting {
		t.Fatalf("plan = %#v, want one pre_existing exclusion and no batches", planResult.Plan)
	}

	assembled, err := Assemble(AssembleOptions{
		Plan:         planResult.Plan,
		EvidenceRefs: validManifestEvidenceRefs(),
		BaseManifest: &baseManifest,
		HeadManifest: &headManifest,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(assembled.Manifest.ExcludedFindings) != 1 || assembled.Manifest.ExcludedFindings[0].Reason != contracts.ReasonPreExisting {
		t.Fatalf("manifest exclusions = %#v, want pre_existing", assembled.Manifest.ExcludedFindings)
	}

	adjudicated, err := adjudicate.Run(adjudicate.Options{
		FrozenCharter: frozen,
		RoleOutputs:   []adjudicate.RoleOutputInput{{Path: "role.json", Document: roleOutput}},
		Manifest:      assembled.Manifest,
		BaseManifest:  &baseManifest,
		HeadManifest:  &headManifest,
	})
	if err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	if len(adjudicated.Findings) != 1 {
		t.Fatalf("findings = %#v, want one", adjudicated.Findings)
	}
	verdict := adjudicated.Findings[0]
	if verdict.Disposition != contracts.DispositionAdvisory || !stringSliceContains(verdict.Reasons, contracts.ReasonPreExisting) || stringSliceContains(verdict.Reasons, contracts.ReasonOutOfDelta) {
		t.Fatalf("verdict = %#v, want pre_existing rather than out_of_delta", verdict)
	}
}

func TestAssembleRejectsSelectedContractManifestEvidenceMismatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	refs := validManifestEvidenceRefs()
	refs.SelectedContracts[0].Digest = testDigest("unclaimed-selected-contract")

	result, err := Assemble(AssembleOptions{
		Plan:         planResult.Plan,
		EvidenceRefs: refs,
	})
	if err == nil {
		t.Fatal("Assemble accepted a manifest selected_contract not backed by authenticated evidence")
	}
	if result == nil || len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusFailed {
		t.Fatalf("result = %#v, want failed manifest batch", result)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
	diagnostics := err.(*ValidationError).Diagnostics
	found := false
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeInvalidSelectedContract {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want %s", diagnostics, CodeInvalidSelectedContract)
	}
}

func TestAssembleZeroBatchPlanRejectsTamperedSelectedContractEvidence(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	refs := validManifestEvidenceRefs()
	defect := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	defect.SchemaVersion = contracts.RoleOutputV5
	defect.Evaluation = planningTestEvaluation("whole-tree")
	economy := planningTestRoleOutput(frozen, contracts.RoleEconomy, []contracts.Finding{})
	economy.SchemaVersion = contracts.RoleOutputV5
	economy.Evaluation = planningTestEvaluation("whole-tree")
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "defect.json", Document: defect},
			{Path: "economy.json", Document: economy},
		},
		Preflight: planningTestPreflightBindingForRefs(t, refs),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Plan.Batches) != 0 {
		t.Fatalf("plan batches = %#v, want none", planResult.Plan.Batches)
	}

	var retained map[string]any
	if err := json.Unmarshal(refs.SelectedContractEvidence[0].RawBytes, &retained); err != nil {
		t.Fatalf("decode selected-contract evidence: %v", err)
	}
	contract, ok := retained["contract"].(map[string]any)
	if !ok {
		t.Fatalf("selected-contract evidence = %#v, want retained contract body", retained)
	}
	contract["tampered"] = true
	refs.SelectedContractEvidence[0].RawBytes = canonjson.MustMarshal(retained)

	_, err = Assemble(AssembleOptions{
		Plan:         planResult.Plan,
		EvidenceRefs: refs,
	})
	if err == nil {
		t.Fatal("Assemble accepted tampered selected-contract evidence for an empty plan")
	}
	found := false
	for _, diagnostic := range err.(*ValidationError).Diagnostics {
		if diagnostic.Code == CodeInvalidSelectedContract {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want %s", err.(*ValidationError).Diagnostics, CodeInvalidSelectedContract)
	}
}

func TestAssembleRejectsUnplannedRelayEvidenceForZeroBatchPlan(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	refs := validManifestEvidenceRefs()
	defect := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	defect.SchemaVersion = contracts.RoleOutputV5
	defect.Evaluation = planningTestEvaluation("whole-tree")
	economy := planningTestRoleOutput(frozen, contracts.RoleEconomy, []contracts.Finding{})
	economy.SchemaVersion = contracts.RoleOutputV5
	economy.Evaluation = planningTestEvaluation("whole-tree")
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "defect.json", Document: defect},
			{Path: "economy.json", Document: economy},
		},
		Preflight: planningTestPreflightBindingForRefs(t, refs),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Plan.Batches) != 0 {
		t.Fatalf("plan batches = %#v, want none", planResult.Plan.Batches)
	}

	_, err = Assemble(AssembleOptions{
		Plan: planResult.Plan,
		RelayResults: []RelayEvidence{{
			BatchID: "unplanned-batch",
		}},
		EvidenceRefs: refs,
	})
	if err == nil {
		t.Fatal("Assemble accepted relay evidence outside an empty plan")
	}
	found := false
	for _, diagnostic := range err.(*ValidationError).Diagnostics {
		if diagnostic.Code == CodeInvalidRelay && diagnostic.Details["batch_id"] == "unplanned-batch" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want %s for unplanned-batch", err.(*ValidationError).Diagnostics, CodeInvalidRelay)
	}
}

func TestAssembleRejectsUnplannedRelayEvidenceAlongsidePlannedEvidence(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	_, err = Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{
			{
				BatchID:      batch.Plan.BatchID,
				RecipeFamily: batch.Plan.RecipeFamily,
				Backend:      "codex",
			},
			{BatchID: "unplanned-batch"},
		},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted relay evidence outside a batched plan")
	}
	found := false
	for _, diagnostic := range err.(*ValidationError).Diagnostics {
		if diagnostic.Code == CodeInvalidRelay && diagnostic.Details["batch_id"] == "unplanned-batch" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want %s for unplanned-batch", err.(*ValidationError).Diagnostics, CodeInvalidRelay)
	}
}

func TestAssembleBatchedPlanRequiresSelectedContractRefs(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(planResult.Plan.Batches) == 0 {
		t.Fatalf("plan batches = %#v, want at least one", planResult.Plan.Batches)
	}
	refs := validManifestEvidenceRefs()
	refs.SelectedContracts = nil

	_, err = Assemble(AssembleOptions{
		Plan:         planResult.Plan,
		EvidenceRefs: refs,
	})
	if err == nil {
		t.Fatal("Assemble accepted a batched plan without selected-contract references")
	}
	found := false
	for _, diagnostic := range err.(*ValidationError).Diagnostics {
		if diagnostic.Code == CodeMissingEvidenceRef && diagnostic.Details["ref"] == "selected_contracts" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want %s for selected_contracts", err.(*ValidationError).Diagnostics, CodeMissingEvidenceRef)
	}
}

func planningTestPreflightBinding(t *testing.T) PreflightBinding {
	t.Helper()
	refs := validManifestEvidenceRefs()
	return planningTestPreflightBindingForRefs(t, refs)
}

func planningTestPreflightBindingForRefs(t *testing.T, refs ManifestEvidenceRefs) PreflightBinding {
	t.Helper()
	return PreflightBinding{
		SnapshotDigest:          testDigest("artifact"),
		IntegrationBundleDigest: refs.IntegrationBundle.Digest,
		RelayPresent:            true,
	}
}

func validManifestEvidenceRefs() ManifestEvidenceRefs {
	selectedContractRefs := make([]contracts.ArtifactRef, 0, 2)
	selectedContractEvidence := make([]SelectedContractEvidence, 0, 2)
	for index, contractID := range []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	} {
		contract := planningContractBody(contractID)
		contractDigest, _ := digest.SemanticJSON(contract)
		selectedContract := map[string]any{
			"contract_id":     contractID,
			"contract_digest": contractDigest,
			"contract":        contract,
		}
		selectedContractRef := contracts.ArtifactRef{
			Kind:          "selected-contract",
			ID:            "contract-" + string(rune('1'+index)),
			Digest:        contractDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		}
		selectedContractRefs = append(selectedContractRefs, selectedContractRef)
		selectedContractEvidence = append(selectedContractEvidence, SelectedContractEvidence{
			Ref:        selectedContractRef,
			ContractID: contractID,
			RawBytes:   canonjson.MustMarshal(selectedContract),
		})
	}
	return ManifestEvidenceRefs{
		IntegrationBundle:        testArtifactRef("integration-bundle", "bundle", "bundle"),
		SelectedContracts:        selectedContractRefs,
		SelectedContractEvidence: selectedContractEvidence,
		ConsumerIdentity:         map[string]any{"kind": "test", "id": "consumer"},
	}
}

func validContradictoryReceipt(plan PlanDocument, findingID string) contracts.ExecutionReceipt {
	return contracts.ExecutionReceipt{
		SchemaVersion:  contracts.ExecutionReceiptV2,
		ReceiptID:      "receipt-1",
		FindingID:      findingID,
		CharterHash:    plan.CharterHash,
		ArtifactDigest: plan.ArtifactDigest,
		FrozenSource:   testArtifactRef("frozen-source", "source", "source"),
		Harness: contracts.HarnessIdentity{
			ID:          "harness",
			Version:     "test",
			BuildDigest: testDigest("harness"),
		},
		Issuer: contracts.ReceiptIssuer{
			ID:     "issuer",
			Actor:  "tester",
			Method: "unit-test",
		},
		Authentication: contracts.ReceiptAuthentication{
			Scheme:       "test",
			KeyID:        "key",
			SignedDigest: testDigest("signed"),
			Signature:    "signature",
		},
		Command: contracts.ExecutableSpec{
			Argv:                []string{"go", "test", "./..."},
			CWD:                 ".",
			ExpectedObservation: "test passes",
		},
		Containment: contracts.ContainmentReport{
			Filesystem: "temporary workspace",
			Network:    "disabled",
			Process:    "child process",
		},
		SourceInventoryBefore:    testArtifactRef("inventory", "source-before", "source-before"),
		SourceInventoryAfter:     testArtifactRef("inventory", "source-after", "source-after"),
		WorkspaceInventoryBefore: testArtifactRef("inventory", "workspace-before", "workspace-before"),
		WorkspaceInventoryAfter:  testArtifactRef("inventory", "workspace-after", "workspace-after"),
		Captures:                 contracts.ExecutionCaptures{},
		ExpectedObservation:      "test passes",
		ObservedObservation:      "test failed",
		ExecutionStatus:          contracts.ExecutionStatusContradicted,
	}
}

func adjudicationErrorCode(err error) string {
	validation, ok := err.(*adjudicate.ValidationError)
	if !ok || len(validation.Diagnostics) == 0 {
		return ""
	}
	return validation.Diagnostics[0].Code
}

func testArtifactRef(kind string, id string, seed string) contracts.ArtifactRef {
	return contracts.ArtifactRef{
		Kind:          kind,
		ID:            id,
		Digest:        testDigest(seed),
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
}

func testDigest(seed string) string {
	return digest.RawBytes([]byte(seed))
}

func TestSanitizeRelayRunRecordMetadataDropsUnsafeIdentifiers(t *testing.T) {
	record := map[string]any{
		"schema_version":   "witness-relay-verification-run-v2",
		"batch_id":         "batch-1",
		"recipe_id":        "witness-falsify-v2-codex",
		"status":           "unavailable",
		"provider_invoked": "unknown",
		"consumes_batch":   true,
		"diagnostics": []any{
			map[string]any{"code": "relay_nonzero_exit"},
			map[string]any{"code": "token=sk-SECRET-VALUE leaked"},
		},
		"relay_launch": map[string]any{
			"argv":              []any{"/home/user/secret dir/relay --token=sk-SECRET", "run"},
			"working_directory": "/home/user/secret",
			"exit_code":         float64(1),
			"start_failed":      false,
		},
	}
	metadata := SanitizeRelayRunRecordMetadata(record)
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatalf("sanitized metadata retains unsafe identifier bytes: %s", encoded)
	}
	codes, _ := metadata["diagnostics"].([]map[string]any)
	if len(codes) != 1 || codes[0]["code"] != "relay_nonzero_exit" {
		t.Fatalf("expected only the conforming diagnostic code, got %v", metadata["diagnostics"])
	}
	launch, _ := metadata["relay_launch"].(map[string]any)
	if launch == nil {
		t.Fatalf("expected relay_launch summary to survive")
	}
	if _, present := launch["executable"]; present {
		t.Fatalf("expected non-conforming executable basename to be dropped, got %v", launch["executable"])
	}
	if _, present := launch["argv_digest"]; !present {
		t.Fatalf("expected argv_digest to remain for correlation")
	}
}
