package planning

import (
	"os"
	"path/filepath"
	"testing"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

func TestAssembleInvalidReceiptAndMissingRelayRemainPending(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
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

func TestAssembleRejectsBatchEvidenceThatDoesNotMatchPlan(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
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
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	exportVerdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.Document.BatchID,
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:      "finding-1",
			WitnessDigest:  batch.Document.Findings[0].WitnessDigest,
			Verdict:        contracts.VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
		}},
	}
	portableDir := writePlanningPortableExport(t, exportVerdicts, batch.Document)
	suppliedVerdicts := exportVerdicts
	suppliedVerdicts.Verdicts[0].Rationale = "not the exported canonical result"

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:           batch.Plan.BatchID,
			PortableExportDir: portableDir,
			Verdicts:          &suppliedVerdicts,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted relay verdicts that were not the export canonical result")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	record := result.Manifest.Batches[0]
	if record.Status != contracts.RecordStatusFailed || record.FailureReason != "relay_verdicts_export_digest_mismatch" {
		t.Fatalf("manifest batch record = %#v, want export digest mismatch", record)
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
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	batch := planResult.Batches[0]
	exportVerdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.Document.BatchID,
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:     "finding-1",
			WitnessDigest: batch.Document.Findings[0].WitnessDigest,
			Verdict:       contracts.VerdictSurvived,
		}},
	}
	portableDir := writePlanningPortableExport(t, exportVerdicts, batch.Document)
	removePlanningRenderedPromptRef(t, portableDir, "provider_invocation", "artifact-000002")
	removePlanningRenderedPromptRef(t, portableDir, "provider_result", "artifact-000001")

	result, err := Assemble(AssembleOptions{
		Plan: planResult.Plan,
		Batches: []BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []RelayEvidence{{
			BatchID:           batch.Plan.BatchID,
			PortableExportDir: portableDir,
		}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err == nil {
		t.Fatal("Assemble accepted missing required prompt evidence")
	}
	if result == nil || len(result.Manifest.Batches) != 1 {
		t.Fatalf("result = %#v, want manifest batch record", result)
	}
	record := result.Manifest.Batches[0]
	if record.Status != contracts.RecordStatusFailed || record.FailureReason != "portable_export_required_relationship_unverified" {
		t.Fatalf("manifest batch record = %#v, want required relationship failure", record)
	}
	if len(result.PendingVerification) != 1 || result.PendingVerification[0] != "finding-1" {
		t.Fatalf("pending verification = %#v, want finding-1", result.PendingVerification)
	}
	found := false
	for _, relationship := range result.UnverifiedRelationships {
		if relationship.BatchID == batch.Plan.BatchID &&
			relationship.Classification == "required" &&
			relationship.Relationship == "trace_only_facilitator_ledger_prompt_projection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unverified relationships = %#v, want required prompt projection relationship", result.UnverifiedRelationships)
	}
}

func TestAssembleRejectsPlanDigestMismatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
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

func TestAssembleRejectsSelectedContractManifestEvidenceMismatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	finding := planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
	planResult, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
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
	if result != nil {
		t.Fatalf("result = %#v, want nil for input-level selected-contract mismatch", result)
	}
	diagnostics := err.(*ValidationError).Diagnostics
	if len(diagnostics) != 1 || diagnostics[0].Code != CodeInvalidSelectedContract {
		t.Fatalf("diagnostics = %#v, want %s", diagnostics, CodeInvalidSelectedContract)
	}
}

func validManifestEvidenceRefs() ManifestEvidenceRefs {
	contractID := "witnessed-review/witness-falsification-v2"
	contract := planningContractBody(contractID)
	contractDigest, _ := digest.SemanticJSON(contract)
	selectedContract := map[string]any{
		"contract_id":     contractID,
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	selectedContractRef := contracts.ArtifactRef{
		Kind:          "selected-contract",
		ID:            "contract",
		Digest:        contractDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
	return ManifestEvidenceRefs{
		CompatibilityManifest: testArtifactRef("compatibility-manifest", "compatibility", "compatibility"),
		RelayCapabilities:     testArtifactRef("relay-capabilities", "capabilities", "capabilities"),
		IntegrationBundle:     testArtifactRef("integration-bundle", "bundle", "bundle"),
		SelectedContracts: []contracts.ArtifactRef{
			selectedContractRef,
		},
		SelectedContractEvidence: []SelectedContractEvidence{
			{
				Ref:        selectedContractRef,
				ContractID: contractID,
				RawBytes:   canonjson.MustMarshal(selectedContract),
			},
		},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
}

func removePlanningRenderedPromptRef(t *testing.T, portableDir string, kind string, id string) {
	t.Helper()
	mutatePlanningPortablePayload(t, portableDir, kind, id, func(value any) any {
		object := value.(map[string]any)
		invocation := object["invocation"].(map[string]any)
		delete(invocation, "rendered_prompt_ref")
		delete(invocation, "rendered_prompt_digest")
		return object
	})
}

func mutatePlanningPortablePayload(t *testing.T, portableDir string, kind string, id string, mutate func(any) any) {
	t.Helper()
	manifestPath := filepath.Join(portableDir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestValue, err := strictjson.DecodeAnyBytes(manifestBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestValue.(map[string]any)
	inventory := manifest["payload_inventory"].([]any)
	var entry map[string]any
	for _, raw := range inventory {
		candidate := raw.(map[string]any)
		if candidate["kind"] == kind && candidate["portable_id"] == id {
			entry = candidate
			break
		}
	}
	if entry == nil {
		t.Fatalf("payload %s/%s not found", kind, id)
	}
	payloadPath := filepath.Join(portableDir, filepath.FromSlash(entry["path"].(string)))
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadValue, err := strictjson.DecodeAnyBytes(payloadBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes, err := canonjson.Marshal(mutate(payloadValue))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, updatedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	entry["size_bytes"] = len(updatedBytes)
	entry["digest"] = digest.RawBytes(updatedBytes)
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		t.Fatal(err)
	}
	manifest["inventory_digest"] = inventoryDigest
	delete(manifest, "manifest_digest")
	manifestDigest, err := digest.SemanticJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest["manifest_digest"] = manifestDigest
	encodedManifest, err := canonjson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encodedManifest, 0o644); err != nil {
		t.Fatal(err)
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
