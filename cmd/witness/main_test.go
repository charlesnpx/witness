package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"witness/internal/adjudicate"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/planning"
	"witness/internal/relayclient"
	"witness/internal/strictjson"
)

func TestCharterCLIInitFreezeAmendShow(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	showPath := filepath.Join(dir, "show.json")
	freezePath := filepath.Join(dir, "freeze.json")
	amendedFreezePath := filepath.Join(dir, "freeze-amended.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := route([]string{"charter", "show", "-charter", charterPath, "-out", showPath}); err != nil {
		t.Fatalf("show: %v", err)
	}
	showData, err := os.ReadFile(showPath)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := strictjson.DecodeBytes[charter.NormalizedCharter](showData, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode show output: %v", err)
	}
	if len(normalized.StandingNoGoals) != 1 || normalized.StandingNoGoals[0].Statement != charter.StandingNoGoalsStatement {
		t.Fatalf("standing invariant = %#v", normalized.StandingNoGoals)
	}

	if err := route([]string{"charter", "freeze", "-charter", charterPath, "-out", freezePath}); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	before := readFrozen(t, freezePath)

	eventJSON := []byte(`{"id":"event-2","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendedFreezePath}); err != nil {
		t.Fatalf("amend: %v", err)
	}
	after := readFrozen(t, amendedFreezePath)
	if before.CharterHash == after.CharterHash {
		t.Fatalf("amended hash did not change: %s", before.CharterHash)
	}
	amendments, err := charter.ReadAmendmentsFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(amendments) != 1 || amendments[0].ID != "event-2" {
		t.Fatalf("amendments = %#v", amendments)
	}
}

func TestCharterAmendRejectsOutputAliasingAmendments(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	originalLedger := []byte(`{"actor":"owner","id":"event-2","summary":"Existing amendment.","type":"charter_amended"}` + "\n")
	if err := os.WriteFile(amendmentsPath, originalLedger, 0o644); err != nil {
		t.Fatal(err)
	}
	eventJSON := []byte(`{"id":"event-3","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendmentsPath})
	if err == nil {
		t.Fatal("amend succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
	afterLedger, err := os.ReadFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterLedger, originalLedger) {
		t.Fatalf("ledger changed:\nafter: %s\nwant:  %s", afterLedger, originalLedger)
	}
}

func TestRejectOutputPathAliasesRejectsHardLinkedAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.WriteFile(amendmentsPath, []byte("existing ledger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(amendmentsPath, outputPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func TestRejectOutputPathAliasesRejectsDanglingSymlinkToAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.Symlink(filepath.Base(amendmentsPath), outputPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("output symlink is not dangling: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func TestVerificationPreflightCLIWiredToRun(t *testing.T) {
	err := route([]string{"verification", "preflight"})
	if err == nil {
		t.Fatal("preflight succeeded without -state-dir")
	}
	diagnostics := diagnosticsFromError(err)
	if len(diagnostics) != 1 || diagnostics[0].Code != "preflight_missing_state_dir" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestVerificationPlanRequiresStateDir(t *testing.T) {
	err := route([]string{
		"verification", "plan",
		"-charter-freeze", "frozen.json",
		"-role-output", "role-output.json",
	})
	if err == nil {
		t.Fatal("verification plan succeeded without -state-dir")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != "verification_plan_missing_state_dir" {
		t.Fatalf("diagnostic code = %s, want verification_plan_missing_state_dir", diagnostic.Code)
	}
}

func TestVerificationPlanAndAssembleCLI(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	planOut := filepath.Join(dir, "plan-out.json")
	manifestOut := filepath.Join(dir, "manifest.json")

	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	roleOutput := validCLIRoleOutput(frozen)
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", planOut,
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}
	batchPath := filepath.Join(stateDir, "verification", "batches", "defect-batch-1.json")
	for _, path := range []string{
		planOut,
		filepath.Join(stateDir, "verification-plan.json"),
		batchPath,
		filepath.Join(stateDir, "verification", "index.skeleton.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	compatibility := writeCLIArtifact(t, dir, "compatibility.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities.json")
	bundle := writeCLIArtifact(t, dir, "bundle.json")
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract.json")
	if err := route([]string{
		"verification", "assemble",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-batch", batchPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble: %v", err)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable missing relay verification", manifest.Batches)
	}
}

func TestAdjudicateCLIWritesRunResult(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"adjudicate",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != adjudicate.ResultSchemaVersion || result.ResultDigest == "" {
		t.Fatalf("adjudication result header = %#v", result)
	}
	if len(result.Findings) != 1 || result.Findings[0].Disposition != contracts.DispositionAdmitted {
		t.Fatalf("adjudication findings = %#v", result.Findings)
	}
}

func TestAdjudicateCLIAcceptsPriorLineage(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	finding := roleOutput.Findings[0]
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	finding.Recurrence = &contracts.RecurrenceRef{
		PriorFindingID: "prior-finding",
		FindingKey:     "cli-recurring-finding",
		WitnessDigest:  witnessDigest,
		ArtifactDigest: roleOutput.ArtifactDigest,
	}
	roleOutput.Findings[0] = finding
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	lineagePath := filepath.Join(dir, "prior-lineage.jsonl")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}
	lineage := adjudicate.PriorLineageRecord{
		FindingID:      "prior-finding",
		FindingKey:     "cli-recurring-finding",
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: roleOutput.ArtifactDigest,
		WitnessDigest:  witnessDigest,
		Disposition:    contracts.DispositionAdmitted,
	}
	if err := os.WriteFile(lineagePath, append(mustCanonicalBytes(t, lineage), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"adjudicate",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-prior-lineage", lineagePath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Disposition != contracts.DispositionAdmitted {
		t.Fatalf("adjudication findings = %#v", result.Findings)
	}
	for _, reason := range result.Findings[0].Reasons {
		if reason == adjudicate.ReasonRecurrenceLineageUnavailable || reason == adjudicate.ReasonInvalidRecurrenceLineage {
			t.Fatalf("adjudication reasons = %#v, recurrence lineage should pass", result.Findings[0].Reasons)
		}
	}
}

func TestVerificationAssembleRunRelayRoutesLaunchFailurePending(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-run.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-run.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleFakeRelayRunner{t: t}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	compatibility := writeCLIArtifact(t, dir, "compatibility-run.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-run.json")
	bundle := writeCLIArtifact(t, dir, "bundle-run.json")
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-run.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("relay run calls = %d, want 1", runner.calls)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable launch failure", manifest.Batches)
	}
}

func TestVerificationAssembleRunRelayRoundTripPasses(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-success.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-success.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleSuccessRelayRunner{t: t}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	compatibility := writeCLIArtifact(t, dir, "compatibility-success.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-success.json")
	bundle := writeCLIArtifact(t, dir, "bundle-success.json")
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-success.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	if runner.runCalls != 1 || runner.exportCalls != 1 || runner.verifyCalls != 1 {
		t.Fatalf("runner calls = run %d export %d verify %d", runner.runCalls, runner.exportCalls, runner.verifyCalls)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusValid {
		t.Fatalf("manifest batches = %#v, want valid relay verification", manifest.Batches)
	}
	if manifest.Batches[0].PortableExportDigest == "" || manifest.Batches[0].CanonicalResultDigest == "" {
		t.Fatalf("manifest batch missing export/result digest: %#v", manifest.Batches[0])
	}
}

func TestVerificationAssembleOutputContainsUnverifiedRelationships(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-unverified.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-unverified.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleSuccessRelayRunner{t: t, supplementaryUnverified: true}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	compatibility := writeCLIArtifact(t, dir, "compatibility-unverified.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-unverified.json")
	bundle := writeCLIArtifact(t, dir, "bundle-unverified.json")
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-unverified.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[planning.AssembleResult](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusValid {
		t.Fatalf("manifest batches = %#v, want valid relay verification", result.Manifest.Batches)
	}
	found := false
	for _, relationship := range result.UnverifiedRelationships {
		if relationship.Classification == "supplementary" &&
			relationship.Code == "facilitator_ledger_content_collision" &&
			relationship.Relationship == "trace_only_facilitator_ledger_prompt_projection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unverified relationships = %#v, want supplementary collision relationship", result.UnverifiedRelationships)
	}
}

func TestVerificationAssembleWritesManifestBeforeBatchError(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-error.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-error.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}
	batchPath := filepath.Join(stateDir, "verification", "batches", "defect-batch-1.json")
	data, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := contracts.ReadVerificationBatchBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	batch.TaskShape = contracts.BatchTaskEconomy
	tamperedBatchPath := filepath.Join(dir, "tampered-batch.json")
	if err := writeCanonical(tamperedBatchPath, batch); err != nil {
		t.Fatal(err)
	}

	compatibility := writeCLIArtifact(t, dir, "compatibility-error.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-error.json")
	bundle := writeCLIArtifact(t, dir, "bundle-error.json")
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-error.json")
	err = route([]string{
		"verification", "assemble",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-batch", tamperedBatchPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	})
	if err == nil {
		t.Fatal("verification assemble accepted tampered batch")
	}
	data, err = os.ReadFile(manifestOut)
	if err != nil {
		t.Fatalf("manifest was not written before error: %v", err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusFailed {
		t.Fatalf("manifest batches = %#v, want failed", manifest.Batches)
	}
}

func TestArtifactRefForSelectedContractPrefersContractDigest(t *testing.T) {
	dir := t.TempDir()
	contract := cliContractBody("witnessed-review/witness-falsification-v2")
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "selected-contract.json")
	if err := writeCanonical(path, map[string]any{
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}); err != nil {
		t.Fatal(err)
	}

	ref, err := artifactRefForFile("selected-contract", path)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Digest != contractDigest {
		t.Fatalf("selected contract digest = %s, want contract_digest %s", ref.Digest, contractDigest)
	}
}

func TestSelectedContractRefsRejectsTamperedSelectedContractEnvelope(t *testing.T) {
	dir := t.TempDir()
	contract := cliContractBody("witnessed-review/witness-falsification-v2")
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	path := filepath.Join(dir, "selected-contract-envelope.json")
	if err := writeCanonical(path, map[string]any{
		"schema_version": "witness-retained-artifact-v1",
		"digest_profile": digest.Profile,
		"payload_digest": digest.RawBytes([]byte("tampered payload digest")),
		"payload":        payload,
	}); err != nil {
		t.Fatal(err)
	}

	refs, err := selectedContractRefsForFile(path)
	if err == nil || !strings.Contains(err.Error(), "payload_digest") {
		t.Fatalf("selectedContractRefsForFile refs=%#v err=%v, want payload_digest error", refs, err)
	}
}

type assembleFakeRelayRunner struct {
	t     *testing.T
	calls int
}

func (runner *assembleFakeRelayRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	if executable != "fake-relay" {
		runner.t.Fatalf("executable = %s, want fake-relay", executable)
	}
	if len(args) == 0 || args[0] != "run" {
		runner.t.Fatalf("unexpected relay command: %v", args)
	}
	runner.calls++
	return relayclient.CommandResult{
		Stdout:   []byte(`{"error":"launch failed"}`),
		Stderr:   []byte("launch failed"),
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	}
}

type assembleSuccessRelayRunner struct {
	t                       *testing.T
	runCalls                int
	exportCalls             int
	verifyCalls             int
	sessionDir              string
	batch                   contracts.VerificationBatchDocument
	batchBytes              []byte
	supplementaryUnverified bool
}

func (runner *assembleSuccessRelayRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	if executable != "fake-relay" {
		runner.t.Fatalf("executable = %s, want fake-relay", executable)
	}
	if len(args) == 0 {
		runner.t.Fatalf("missing relay command")
	}
	switch args[0] {
	case "run":
		runner.runCalls++
		binding := testArgAfter(args, "--input", "findings=")
		if binding == "" {
			runner.t.Fatalf("run args missing findings input: %v", args)
		}
		data, err := os.ReadFile(binding)
		if err != nil {
			runner.t.Fatal(err)
		}
		batch, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			runner.t.Fatal(err)
		}
		runner.batch = batch
		runner.batchBytes = append([]byte(nil), data...)
		runner.sessionDir = filepath.Join(runner.t.TempDir(), "relay-session")
		return relayclient.CommandResult{Stdout: []byte(`{"session_dir":"` + runner.sessionDir + `"}`)}
	case "export":
		runner.exportCalls++
		output := testArgAfter(args, "--output", "")
		if output == "" {
			runner.t.Fatalf("export args missing output: %v", args)
		}
		manifestDigest := writeCLIPortableExport(runner.t, output, runner.batch, runner.batchBytes)
		if runner.supplementaryUnverified {
			manifestDigest = addCLISupplementaryUnverifiedRelationship(runner.t, output)
		}
		return relayclient.CommandResult{Stdout: []byte(`{"manifest_digest":"` + manifestDigest + `"}`)}
	case "verify-export":
		runner.verifyCalls++
		return relayclient.CommandResult{Stdout: []byte(`{"status":"valid"}`)}
	default:
		runner.t.Fatalf("unexpected relay command: %v", args)
		return relayclient.CommandResult{ExitCode: 1, Err: errors.New("unexpected command")}
	}
}

type cliPortablePayload struct {
	entry map[string]any
	body  []byte
}

func writeCLIPortableExport(t *testing.T, dir string, batch contracts.VerificationBatchDocument, batchBytes []byte) string {
	t.Helper()
	if len(batchBytes) == 0 {
		t.Fatal("batch bytes are required")
	}
	verdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.BatchID,
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:      batch.Findings[0].FindingID,
			WitnessDigest:  batch.Findings[0].WitnessDigest,
			Verdict:        contracts.VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
		}},
	}
	contractID := "witnessed-review/witness-falsification-v2"
	contract := cliContractBody(contractID)
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	integrationContract := map[string]any{
		"kind":            "integration_contract",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"contract_id":     contractID,
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	integrationContractDigest, err := digest.StorageEnvelope("integration_contract", integrationContract)
	if err != nil {
		t.Fatal(err)
	}
	charterBytes := []byte(`{"charter":"input"}`)
	payloads := []cliPortablePayload{
		cliPortablePayloadFor(t, "root_session", "session", map[string]any{
			"execution_kind":  "recipe",
			"kind":            "portable_root_session",
			"provider_retry":  "forbid",
			"result_source":   "reducer",
			"status":          "completed",
			"terminal_status": "completed",
		}, nil),
		cliPortablePayloadFor(t, "participant_transcript", "transcript", []any{
			map[string]any{"participant_turn": 1, "actor": "presenter", "content": "turn one", "provider_result_ref": cliPortableRef("artifact-000001", "provider_result:000001")},
			map[string]any{"participant_turn": 2, "actor": "falsifier", "content": "turn two", "provider_result_ref": cliPortableRef("artifact-000007", "provider_result:000003")},
			map[string]any{"participant_turn": 3, "actor": "presenter", "content": "turn three", "provider_result_ref": cliPortableRef("artifact-000013", "provider_result:000005")},
			map[string]any{"participant_turn": 4, "actor": "falsifier", "content": "turn four", "provider_result_ref": cliPortableRef("artifact-000019", "provider_result:000007")},
		}, nil),
		cliPortablePayloadFor(t, "diagnostics", "diagnostics", map[string]any{"execution_kind": "recipe", "status": "completed"}, nil),
		cliPortablePayloadFor(t, "root_recipe_plan", "root-plan", map[string]any{
			"kind":                        "root_recipe_plan",
			"schema_version":              2,
			"digest_profile":              digest.Profile,
			"recipe_id":                   "witness-falsify-v2-codex",
			"provider_retry":              "forbid",
			"result_source":               "reducer",
			"participant_turns":           4,
			"integration_contract_id":     contractID,
			"integration_contract_digest": contractDigest,
			"integration_contract_ref":    cliPortableRefWithDigest("integration-contract", "integration_contract:selected", integrationContractDigest),
			"prompt_context":              map[string]any{"participant_transcript": "complete", "facilitator_ledger": "trace_only"},
		}, cliSourceRef("root_recipe_plan:selected")),
		cliPortablePayloadFor(t, "integration_contract", "integration-contract", integrationContract, map[string]any{"id": "integration_contract:selected", "digest": integrationContractDigest}),
		cliPortablePayloadFor(t, "named_input_content", "named-input-content-1", cliNamedInputContentPayload("charter", 1, charterBytes), cliSourceRef("named_input_content:000001")),
		cliPortablePayloadFor(t, "named_input_content", "named-input-content-2", cliNamedInputContentPayload("findings", 2, batchBytes), cliSourceRef("named_input_content:000002")),
		cliPortablePayloadFor(t, "named_input_manifest", "named-input-manifest", map[string]any{
			"kind":           "named_input_manifest",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"contract_id":    contractID,
			"input_count":    2,
			"inputs": []any{
				cliNamedInputEntry("charter", 1, "named-input-content-1", "named_input_content:000001", len(charterBytes), digest.RawBytes(charterBytes)),
				cliNamedInputEntry("findings", 2, "named-input-content-2", "named_input_content:000002", len(batchBytes), digest.RawBytes(batchBytes)),
			},
		}, cliSourceRef("named_input_manifest:selected")),
		cliPortablePayloadFor(t, "canonical_result", "canonical-result", map[string]any{
			"kind":           "canonical_result",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"transport":      "json",
			"canonical_json": string(mustCanonicalBytes(t, verdicts)),
			"value":          verdicts,
		}, cliSourceRef("canonical_result:selected")),
		cliPortablePayloadFor(t, "result_validation", "result-validation", map[string]any{
			"kind":                 "result_validation",
			"schema_version":       2,
			"digest_profile":       digest.Profile,
			"status":               "validated",
			"canonical_result_ref": cliPortableRef("canonical-result", "canonical_result:selected"),
		}, cliSourceRef("result_validation:selected")),
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
		prompt := cliRenderedPromptPayload(spec.phase + " prompt " + spec.source)
		rawDigest := prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string)
		result, invocation := cliProviderPayloads(spec.resultID, spec.promptID, spec.source, spec.phase, spec.ordinal, rawDigest)
		payloads = append(payloads,
			cliPortablePayloadFor(t, "provider_result", spec.resultID, result, cliSourceRef("provider_result:"+spec.source)),
			cliPortablePayloadFor(t, "provider_invocation", spec.invocationID, invocation, cliSourceRef("provider_invocation:"+spec.source)),
			cliPortablePayloadFor(t, "rendered_prompt", spec.promptID, prompt, cliSourceRef("rendered_prompt:"+spec.source)),
		)
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].entry["path"].(string) < payloads[j].entry["path"].(string)
	})
	inventory := make([]any, 0, len(payloads))
	for _, payload := range payloads {
		writeCLIPortableFile(t, dir, payload.entry["path"].(string), payload.body)
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
	writeCLIPortableFile(t, dir, "manifest.json", mustCanonicalBytes(t, manifest))
	return manifestDigest
}

func addCLISupplementaryUnverifiedRelationship(t *testing.T, dir string) string {
	t.Helper()
	const marker = "SHARED_CONTEXT_MARKER"
	mutateCLIPortablePayload(t, dir, "participant_transcript", "transcript", func(value any) any {
		transcript := value.([]any)
		entry := transcript[0].(map[string]any)
		entry["content"] = entry["content"].(string) + " " + marker
		entry["ledger"] = map[string]any{
			"settled":   []any{},
			"contested": []any{marker},
			"withdrawn": []any{},
		}
		return transcript
	})
	promptDigest := ""
	mutateCLIPortablePayload(t, dir, "rendered_prompt", "artifact-000003", func(any) any {
		prompt := cliRenderedPromptPayload("participant prompt includes " + marker)
		promptDigest = prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string)
		return prompt
	})
	mutateCLIPortablePayload(t, dir, "provider_result", "artifact-000001", func(value any) any {
		result := value.(map[string]any)
		result["invocation"].(map[string]any)["rendered_prompt_digest"] = promptDigest
		return result
	})
	return mutateCLIPortablePayload(t, dir, "provider_invocation", "artifact-000002", func(value any) any {
		invocation := value.(map[string]any)
		invocation["invocation"].(map[string]any)["rendered_prompt_digest"] = promptDigest
		return invocation
	})
}

func mutateCLIPortablePayload(t *testing.T, dir string, kind string, id string, mutate func(any) any) string {
	t.Helper()
	manifestPath := filepath.Join(dir, "manifest.json")
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
	payloadPath := filepath.Join(dir, filepath.FromSlash(entry["path"].(string)))
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadValue, err := strictjson.DecodeAnyBytes(payloadBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes := mustCanonicalBytes(t, mutate(payloadValue))
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
	writeCLIPortableFile(t, dir, "manifest.json", mustCanonicalBytes(t, manifest))
	return manifestDigest
}

func cliProviderPayloads(resultPortableID string, promptPortableID string, sourceOrdinal string, phase string, participantOrdinal int, promptDigest string) (map[string]any, map[string]any) {
	invocationDraft := map[string]any{
		"schema_version":            "relay-provider-invocation-v2",
		"invocation_id":             phase + ":" + sourceOrdinal,
		"phase":                     phase,
		"actor":                     "Agent " + sourceOrdinal,
		"participant_ordinal":       nil,
		"reducer_fresh":             phase == "reducer",
		"rendered_prompt_ref":       cliPortableRef(promptPortableID, "rendered_prompt:"+sourceOrdinal),
		"rendered_prompt_digest":    promptDigest,
		"backend":                   "codex",
		"mapped_working_directory":  ".",
		"runner_attempt":            1,
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
	boundInvocation := cloneMap(invocationDraft)
	boundInvocation["provider_result_ref"] = cliPortableRef(resultPortableID, "provider_result:"+sourceOrdinal)
	return resultPayload, map[string]any{
		"kind":           "provider_invocation",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"invocation":     boundInvocation,
	}
}

func cliPortablePayloadFor(t *testing.T, kind string, id string, value any, sourceRef map[string]any) cliPortablePayload {
	t.Helper()
	body := mustCanonicalBytes(t, value)
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
	return cliPortablePayload{entry: entry, body: body}
}

func cliNamedInputContentPayload(name string, ordinal int, data []byte) map[string]any {
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

func cliRenderedPromptPayload(text string) map[string]any {
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

func cliNamedInputEntry(name string, ordinal int, portableID string, sourceID string, sizeBytes int, rawDigest string) map[string]any {
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
		"content_ref":   cliPortableRef(portableID, sourceID),
	}
}

func cliContractBody(contractID string) map[string]any {
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
		"result": map[string]any{"transport": "json", "schema": map[string]any{"type": "object"}, "assertions": []any{}},
		"prompt_context": map[string]any{
			"participant_transcript": "complete",
			"facilitator_ledger":     "trace_only",
		},
	}
}

func cliPortableRef(portableID string, sourceID string) map[string]any {
	return cliPortableRefWithDigest(portableID, sourceID, cliSourceRef(sourceID)["digest"].(string))
}

func cliPortableRefWithDigest(portableID string, sourceID string, sourceDigest string) map[string]any {
	return map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            portableID,
		"source_artifact_id":     sourceID,
		"source_artifact_digest": sourceDigest,
	}
}

func cliSourceRef(id string) map[string]any {
	return map[string]any{"id": id, "digest": digest.RawBytes([]byte(id))}
}

func writeCLIPortableFile(t *testing.T, root string, relative string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustCanonicalBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testArgAfter(args []string, key string, trimPrefix string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] != key {
			continue
		}
		value := args[index+1]
		if trimPrefix != "" {
			if len(value) <= len(trimPrefix) || value[:len(trimPrefix)] != trimPrefix {
				continue
			}
			return value[len(trimPrefix):]
		}
		return value
	}
	return ""
}

func assertOutputPathConflict(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("alias check succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
}

func readFrozen(t *testing.T, path string) charter.FrozenCharter {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode frozen charter: %v", err)
	}
	return frozen
}

func validCLIFrozenCharter(t *testing.T) charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-cli",
			Statement: "The CLI accepts declared valid inputs deterministically.",
		}},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial charter.",
		}},
		OperationalEnvelope: &charter.OperationalEnvelope{
			EntryPoints: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared entry points.",
				Entries:   []charter.Entry{{ID: "cli", Statement: "Command line interface."}},
			},
			InputSurface: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Caller supplied files.",
				Entries:   []charter.Entry{},
			},
			ValidStates: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared valid states.",
				Entries:   []charter.Entry{{ID: "normal", Statement: "Normal configured operation."}},
			},
			Environments: &charter.Dimension{
				State:     charter.StateNotApplicable,
				Statement: "No environment distinction.",
				Entries:   []charter.Entry{},
			},
			ScaleBounds: &charter.Dimension{
				State:     charter.StateUnspecified,
				Statement: "Scale is unspecified.",
				Entries:   []charter.Entry{},
			},
			CompatibilityPromises: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared compatibility promises.",
				Entries:   []charter.Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
			},
			ThreatModel: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Threat scenarios must be concrete.",
				Entries:   []charter.Entry{},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func validCLIRoleOutput(frozen charter.FrozenCharter) contracts.RoleOutputDocument {
	return contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV3,
		Role:           contracts.RoleDefect,
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: digest.RawBytes([]byte("artifact")),
		SourceIdentity: map[string]any{"kind": "test", "id": "source"},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
		},
		Findings: []contracts.Finding{{
			ID:              "finding-1",
			Kind:            contracts.FindingKindDefect,
			Title:           "CLI rejects a declared input",
			CharterGoalIDs:  []string{"goal-cli"},
			ClaimedSeverity: contracts.SeverityHigh,
			ScopeAnchors:    []contracts.ScopeAnchor{{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}},
			Witness: contracts.Witness{
				Kind:     contracts.WitnessKindDefect,
				Strength: contracts.WitnessStrengthConstructed,
				Content:  "The reachable CLI input hits the rejecting branch.",
				EntryPoint: &contracts.ScopeAnchor{
					Dimension: charter.DimensionEntryPoints,
					EntryID:   "cli",
				},
				ReachabilityChain: []contracts.ScopeAnchor{
					{Dimension: charter.DimensionEntryPoints, EntryID: "cli"},
					{Dimension: charter.DimensionInputSurface, Value: "config"},
					{Dimension: charter.DimensionValidStates, EntryID: "normal"},
				},
			},
			EstimatedDelta: contracts.SplitDeltaEstimate{
				Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
				Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
			},
			SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
				Direction:          contracts.RemedyDirectionChange,
				Summary:            "Change the rejecting branch.",
				MinimalityArgument: "Only the reachable branch changes.",
			},
			ProposedTests: []contracts.ProposedTest{{
				ID:                 "test-finding-1",
				Name:               "accepts declared input",
				ReachablePartition: "cli config",
				CharterRefs:        []contracts.CharterRef{{GoalID: "goal-cli"}},
			}},
		}},
	}
}

func validCLIAdjudicationManifest(t *testing.T, frozen charter.FrozenCharter, roleOutput contracts.RoleOutputDocument) contracts.VerificationManifest {
	t.Helper()
	finding := roleOutput.Findings[0]
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	verdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       "batch-1",
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:     finding.ID,
			WitnessDigest: witnessDigest,
			Verdict:       contracts.VerdictSurvived,
			VerdictClass:  nil,
		}},
	}
	resultDigest, err := contracts.RelayWitnessVerdictsDigest(verdicts)
	if err != nil {
		t.Fatal(err)
	}
	batchRef := artifactRef("verification-batch", "batch-1", digest.RawBytes([]byte("batch")))
	exportRef := artifactRef("relay-root-portable-export", "batch-1", digest.RawBytes([]byte("export")))
	return contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV3,
		PlanDigest:            digest.RawBytes([]byte("plan")),
		CharterHash:           frozen.CharterHash,
		ArtifactDigest:        roleOutput.ArtifactDigest,
		CompatibilityManifest: artifactRef("compatibility-manifest", "compatibility", digest.RawBytes([]byte("compatibility"))),
		RelayCapabilities:     artifactRef("relay-capabilities", "capabilities", digest.RawBytes([]byte("capabilities"))),
		IntegrationBundle:     artifactRef("integration-bundle", "bundle", digest.RawBytes([]byte("bundle"))),
		SelectedContracts:     []contracts.ArtifactRef{artifactRef("selected-contract", "contract", digest.RawBytes([]byte("contract")))},
		Batches: []contracts.VerificationManifestBatch{{
			BatchID:               "batch-1",
			Status:                contracts.RecordStatusValid,
			BatchRef:              batchRef,
			BatchDigest:           batchRef.Digest,
			PortableExportRef:     &exportRef,
			PortableExportDigest:  exportRef.Digest,
			CanonicalResultDigest: resultDigest,
			RelayVerdicts:         &verdicts,
		}},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
}

func writeCLIArtifact(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := writeCanonical(path, map[string]any{"name": name}); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLISelectedContractArtifact(t *testing.T, dir string, name string) string {
	t.Helper()
	contract := cliContractBody("witnessed-review/witness-falsification-v2")
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := writeCanonical(path, map[string]any{
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}); err != nil {
		t.Fatal(err)
	}
	return path
}
