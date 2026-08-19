package planning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestPlanningBatchesDeterministicallyByRoleSeverityAndID(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	findings := []contracts.Finding{
		planningTestFinding("low-2", contracts.SeverityLow, contracts.WitnessStrengthArgued),
		planningTestFinding("high-3", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
		planningTestFinding("medium-2", contracts.SeverityMedium, contracts.WitnessStrengthArgued),
		planningTestFinding("high-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
		planningTestFinding("low-1", contracts.SeverityLow, contracts.WitnessStrengthArgued),
		planningTestFinding("medium-1", contracts.SeverityMedium, contracts.WitnessStrengthArgued),
		planningTestFinding("high-2", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
		planningTestFinding("low-3", contracts.SeverityLow, contracts.WitnessStrengthArgued),
		planningTestFinding("medium-3", contracts.SeverityMedium, contracts.WitnessStrengthArgued),
	}
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, findings)

	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Batches) != 2 {
		t.Fatalf("batches = %d, want 2", len(result.Batches))
	}
	gotFirst := result.Plan.Batches[0].FindingIDs
	wantFirst := []string{"high-1", "high-2", "high-3", "medium-1", "medium-2", "medium-3", "low-1", "low-2"}
	if fmt.Sprint(gotFirst) != fmt.Sprint(wantFirst) {
		t.Fatalf("first batch finding ids = %v, want %v", gotFirst, wantFirst)
	}
	gotSecond := result.Plan.Batches[1].FindingIDs
	wantSecond := []string{"low-3"}
	if fmt.Sprint(gotSecond) != fmt.Sprint(wantSecond) {
		t.Fatalf("second batch finding ids = %v, want %v", gotSecond, wantSecond)
	}
	if result.Plan.Batches[0].BatchID != "defect-batch-1" || result.Plan.Batches[1].BatchID != "defect-batch-2" {
		t.Fatalf("batch ids = %s, %s", result.Plan.Batches[0].BatchID, result.Plan.Batches[1].BatchID)
	}
	for _, batch := range result.Batches {
		if diagnostics := contracts.ValidateVerificationBatch(batch.Document, &roleOutput); len(diagnostics) > 0 {
			t.Fatalf("batch %s diagnostics = %#v", batch.Plan.BatchID, diagnostics)
		}
		if fmt.Sprint(batch.Plan.ArtifactDigestSet) != fmt.Sprint([]string{roleOutput.ArtifactDigest}) {
			t.Fatalf("batch %s artifact digest set = %v, want [%s]", batch.Plan.BatchID, batch.Plan.ArtifactDigestSet, roleOutput.ArtifactDigest)
		}
		if len(batch.Document.Findings) > MaxBatchFindings {
			t.Fatalf("batch %s size = %d", batch.Plan.BatchID, len(batch.Document.Findings))
		}
	}
}

func TestPlanningBatchDigestBindsPersistedBytes(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	stateDir := t.TempDir()
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		StateDir:      stateDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Batches) != 1 {
		t.Fatalf("batches = %#v", result.Plan.Batches)
	}
	batchPath := filepath.Join(stateDir, "verification", "batches", "defect-batch-1.json")
	persisted, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.RawBytes(persisted); got != result.Plan.Batches[0].BatchDigest {
		t.Fatalf("persisted batch digest = %s, want plan digest %s", got, result.Plan.Batches[0].BatchDigest)
	}
	canonical, err := contracts.VerificationBatchCanonicalBytes(result.Batches[0].Document)
	if err != nil {
		t.Fatal(err)
	}
	if digest.RawBytes(canonical) == result.Plan.Batches[0].BatchDigest {
		t.Fatal("plan batch digest did not include the persisted trailing newline")
	}
}

func TestPlanningEmptyFindingsEmitEmptyBatchArrays(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	refs := validManifestEvidenceRefs()
	refs.SelectedContracts = nil
	refs.SelectedContractEvidence = nil
	defect := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	defect.SchemaVersion = contracts.RoleOutputV5
	defect.Evaluation = planningTestEvaluation("whole-tree")
	economy := planningTestRoleOutput(frozen, contracts.RoleEconomy, []contracts.Finding{})
	economy.SchemaVersion = contracts.RoleOutputV5
	economy.Evaluation = planningTestEvaluation("whole-tree")
	stateDir := t.TempDir()
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "defect.json", Document: defect},
			{Path: "economy.json", Document: economy},
		},
		StateDir:  stateDir,
		Preflight: planningTestPreflightBindingForRefs(t, refs),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.Batches == nil {
		t.Fatal("plan batches = nil, want non-nil empty slice")
	}
	if len(result.Plan.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics = %#v, want none", result.Plan.Diagnostics)
	}

	for _, output := range []struct {
		name string
		path string
	}{
		{name: "plan", path: filepath.Join(stateDir, "verification-plan.json")},
		{name: "manifest skeleton", path: filepath.Join(stateDir, "verification", "index.skeleton.json")},
	} {
		data, err := os.ReadFile(output.path)
		if err != nil {
			t.Fatalf("read %s: %v", output.name, err)
		}
		if !strings.Contains(string(data), `"batches":[]`) {
			t.Fatalf("%s bytes = %s, want empty batches array", output.name, data)
		}
	}

	assembled, err := Assemble(AssembleOptions{Plan: result.Plan, EvidenceRefs: refs})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	manifest, err := contracts.VerificationManifestCanonicalBytes(assembled.Manifest)
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	if !strings.Contains(string(manifest), `"batches":[]`) {
		t.Fatalf("manifest bytes = %s, want empty batches array", manifest)
	}
	if len(assembled.Manifest.SelectedContracts) != 0 {
		t.Fatalf("manifest selected contracts = %#v, want none for an empty plan", assembled.Manifest.SelectedContracts)
	}
}

func TestPlanningRejectsUnattestedEmptyRoleOutput(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	if err := contracts.RequireValidRoleOutput(roleOutput, frozen); err != nil {
		t.Fatalf("RequireValidRoleOutput: %v", err)
	}
	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeUnattestedEmptyRoleOutput)
}

func TestPlanningCollectsAdmissionRefusalsAcrossRoleOutputs(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	defect := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	economy := planningTestRoleOutput(frozen, contracts.RoleEconomy, []contracts.Finding{})

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "defect.json", Document: defect},
			{Path: "economy.json", Document: economy},
		},
	})
	validation := requirePlanningValidationError(t, err)
	if len(validation.Diagnostics) != 2 {
		t.Fatalf("validation diagnostics = %#v, want both role-output refusals", validation.Diagnostics)
	}
	for index, roleOutput := range []string{"defect.json", "economy.json"} {
		diagnostic := validation.Diagnostics[index]
		if diagnostic.Code != CodeUnattestedEmptyRoleOutput {
			t.Fatalf("diagnostic %d code = %s, want %s", index, diagnostic.Code, CodeUnattestedEmptyRoleOutput)
		}
		if got, _ := diagnostic.Details["role_output"].(string); got != roleOutput {
			t.Fatalf("diagnostic %d role_output = %q, want %q", index, got, roleOutput)
		}
	}
}

func TestPlanningRefusalDoesNotWriteState(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	stateDir := t.TempDir()
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		StateDir:      stateDir,
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeUnattestedEmptyRoleOutput)
	planPath := filepath.Join(stateDir, "verification-plan.json")
	if _, statErr := os.Stat(planPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused plan state at %s: stat error = %v, want no plan file", planPath, statErr)
	}
	entries, readErr := os.ReadDir(stateDir)
	if readErr != nil {
		t.Fatalf("read state directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("state directory entries = %#v, want no persisted state", entries)
	}
}

func TestPlanningRejectsStructurallyInvalidEmptyRoleOutputWithoutWritingState(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	stateDir := t.TempDir()
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.Evaluation = &contracts.RoleEvaluation{
		EvaluatedPaths:          []string{},
		EvaluatedCharterGoalIDs: []string{},
	}

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		StateDir:      stateDir,
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeUnattestedEmptyRoleOutput)
	planPath := filepath.Join(stateDir, "verification-plan.json")
	if _, statErr := os.Stat(planPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused plan state at %s: stat error = %v, want no plan file", planPath, statErr)
	}
	entries, readErr := os.ReadDir(stateDir)
	if readErr != nil {
		t.Fatalf("read state directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("state directory entries = %#v, want no persisted state", entries)
	}
}

func TestPlanningRejectsEmptyRoleOutputEvaluationWithDuplicatePath(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.Evaluation = &contracts.RoleEvaluation{
		EvaluatedPaths:          []string{"whole-tree", "whole-tree"},
		EvaluatedCharterGoalIDs: []string{"goal-cli"},
	}

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeUnattestedEmptyRoleOutput)
}

func TestPlanningAcceptsTruthfulEmptyRoleOutputEvaluation(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.ArtifactDigest = headDigest
	roleOutput.Evaluation = planningTestEvaluation("internal/changed.go", "internal/deleted.go")

	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics = %#v, want none", result.Plan.Diagnostics)
	}
	if len(result.Plan.Batches) != 0 || len(result.Batches) != 0 {
		t.Fatalf("planned batches = %#v, outputs = %#v; want valid zero-batch plan", result.Plan.Batches, result.Batches)
	}
}

func TestPlanningAcceptsStandingStatementEvaluationUnderZeroGoalCharter(t *testing.T) {
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals:         []charter.Statement{},
		NonGoals:      []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Explicitly allowed empty Charter.",
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frozen.Charter.Goals) != 0 {
		t.Fatalf("frozen Charter goals = %#v, want zero-goal Charter", frozen.Charter.Goals)
	}
	if len(frozen.Charter.StandingNoGoals) != 1 || frozen.Charter.StandingNoGoals[0].ID != charter.StandingNoGoalsID {
		t.Fatalf("frozen Charter standing statements = %#v", frozen.Charter.StandingNoGoals)
	}
	roleOutput := planningTestRoleOutput(&frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.Evaluation = &contracts.RoleEvaluation{
		EvaluatedPaths:          []string{"whole-tree"},
		EvaluatedCharterGoalIDs: []string{charter.StandingNoGoalsID},
	}

	result, err := Run(Options{
		FrozenCharter: &frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics = %#v, want none", result.Plan.Diagnostics)
	}
	if len(result.Plan.Batches) != 0 || len(result.Batches) != 0 {
		t.Fatalf("planned batches = %#v, outputs = %#v; want valid zero-batch plan", result.Plan.Batches, result.Batches)
	}
}

func TestPlanningRejectsEmptyRoleOutputEvaluationPathOutsideChangeSurface(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.ArtifactDigest = headDigest
	roleOutput.Evaluation = planningTestEvaluation("internal/changed.go", "internal/deleted.go", "internal/invented.go")

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeInvalidRoleOutput)
}

func TestPlanningRejectsIncompleteEmptyRoleOutputEvaluation(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.ArtifactDigest = headDigest
	roleOutput.Evaluation = planningTestEvaluation("internal/changed.go")

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeInvalidRoleOutput)
}

func TestPlanningRejectsEmptyRoleOutputEvaluationUnknownCharterGoal(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	roleOutput.SchemaVersion = contracts.RoleOutputV5
	roleOutput.ArtifactDigest = headDigest
	roleOutput.Evaluation = &contracts.RoleEvaluation{
		EvaluatedPaths:          []string{"internal/changed.go", "internal/deleted.go"},
		EvaluatedCharterGoalIDs: []string{"unknown-goal"},
	}

	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	validation := requirePlanningValidationError(t, err)
	assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeInvalidRoleOutput)
}

func TestPlanningValidatesV5EvaluationWhenFindingsArePresent(t *testing.T) {
	t.Run("cross-check failures remain fatal", func(t *testing.T) {
		frozen := planningTestFrozenCharter(t)
		baseManifest, headManifest, headDigest := planningDeltaManifests(t)
		roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
			planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
		})
		roleOutput.SchemaVersion = contracts.RoleOutputV5
		roleOutput.ArtifactDigest = headDigest
		roleOutput.Evaluation = planningTestEvaluation("internal/invented.go")

		_, err := Run(Options{
			FrozenCharter: frozen,
			RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			Preflight:     PreflightBinding{SnapshotDigest: headDigest},
			ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
		})
		validation := requirePlanningValidationError(t, err)
		assertPlanningDiagnosticCode(t, validation.Diagnostics, CodeInvalidRoleOutput)
	})

	t.Run("structural diagnostics remain advisory", func(t *testing.T) {
		frozen := planningTestFrozenCharter(t)
		roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
			planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
		})
		roleOutput.SchemaVersion = contracts.RoleOutputV5
		roleOutput.Evaluation = &contracts.RoleEvaluation{
			EvaluatedPaths:          []string{"whole-tree", "whole-tree"},
			EvaluatedCharterGoalIDs: []string{"goal-cli"},
		}

		result, err := Run(Options{
			FrozenCharter: frozen,
			RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertPlanningDiagnosticCode(t, result.Plan.Diagnostics, contracts.CodeInvalidRoleOutput)
		if len(result.Plan.Batches) != 0 || len(result.Plan.ExcludedFindings) != 1 {
			t.Fatalf("plan = %#v, want one advisory exclusion and no batches", result.Plan)
		}
		excluded := result.Plan.ExcludedFindings[0]
		if excluded.Disposition != DispositionAdvisory || excluded.Reason != CodeInvalidRoleOutput || len(excluded.Diagnostics) == 0 {
			t.Fatalf("excluded finding = %#v, want advisory structural-evaluation exclusion", excluded)
		}
	})
}

func TestPlanningPreSpendViolationsAreAdvisoryBeforeBatching(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	invalidAnchor := planningTestFinding("invalid-anchor", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	invalidAnchor.ScopeAnchors[0].EntryID = "missing"
	invalidAnchor.Witness.EntryPoint.EntryID = "missing"

	overStrength := planningTestFinding("over-strength", contracts.SeverityCritical, contracts.WitnessStrengthArgued)

	recursive := planningTestFinding("recursive", contracts.SeverityMedium, contracts.WitnessStrengthArgued)
	recursive.Recurrence = &contracts.RecurrenceRef{
		PriorFindingID: "recursive",
		FindingKey:     "recursive-key",
		WitnessDigest:  digest.RawBytes([]byte("prior witness")),
		ArtifactDigest: digest.RawBytes([]byte("prior artifact")),
	}

	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{invalidAnchor, overStrength, recursive})
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Batches) != 1 || len(result.Plan.Batches[0].FindingIDs) != 1 || result.Plan.Batches[0].FindingIDs[0] != "over-strength" {
		t.Fatalf("planned batches = %#v, want one batch for over-strength", result.Plan.Batches)
	}
	if len(result.Plan.ExcludedFindings) != 2 {
		t.Fatalf("excluded findings = %#v, want 2", result.Plan.ExcludedFindings)
	}
	reasons := map[string]string{}
	for _, excluded := range result.Plan.ExcludedFindings {
		if excluded.Disposition != DispositionAdvisory {
			t.Fatalf("excluded disposition = %s, want advisory", excluded.Disposition)
		}
		reasons[excluded.FindingID] = excluded.Reason
	}
	if reasons["invalid-anchor"] != CodeInvalidRoleOutput {
		t.Fatalf("invalid anchor reason = %s, want %s", reasons["invalid-anchor"], CodeInvalidRoleOutput)
	}
	if _, excluded := reasons["over-strength"]; excluded {
		t.Fatalf("over-strength was excluded with reason %s, want verification batch", reasons["over-strength"])
	}
	if reasons["recursive"] != CodeRecursiveRecurrence {
		t.Fatalf("recursive reason = %s, want %s", reasons["recursive"], CodeRecursiveRecurrence)
	}
}

func TestPlanningRejectsRoleOutputArtifactDigestDifferentFromPreflightSnapshot(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	snapshotDigest := digest.RawBytes([]byte("preflight snapshot"))
	roleOutput.ArtifactDigest = digest.RawBytes([]byte("role output artifact"))

	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: snapshotDigest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.ArtifactDigest != snapshotDigest {
		t.Fatalf("artifact_digest = %s, want preflight snapshot %s", result.Plan.ArtifactDigest, snapshotDigest)
	}
	if len(result.Plan.Batches) != 0 || len(result.Batches) != 0 {
		t.Fatalf("planned batches = %#v, outputs = %#v; want none", result.Plan.Batches, result.Batches)
	}
	var found bool
	for _, diagnostic := range result.Plan.Diagnostics {
		if diagnostic.Code != CodeSnapshotArtifactMismatch {
			continue
		}
		found = true
		if diagnostic.Details["role_output"] != "defect.json" || diagnostic.Details["artifact_digest"] != roleOutput.ArtifactDigest || diagnostic.Details["expected"] != snapshotDigest {
			t.Fatalf("mismatch diagnostic details = %#v", diagnostic.Details)
		}
	}
	if !found {
		t.Fatalf("missing %s diagnostic: %#v", CodeSnapshotArtifactMismatch, result.Plan.Diagnostics)
	}
}

func TestPlanningDeltaChangeSurfacePartitionsFindings(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	inDelta := planningTestFinding("in-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	inDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/changed.go"}}
	outOfDelta := planningTestFinding("out-of-delta", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	outOfDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/unchanged.go"}}
	deleted := planningTestFinding("deleted", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
	deleted.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/deleted.go"}}
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{inDelta, outOfDelta, deleted})
	roleOutput.ArtifactDigest = headDigest

	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.ScopePolicy != changesurface.ScopePolicyDeltaObligating || result.Plan.ChangeSurface == nil || result.Plan.ChangeSurfaceDigest == "" {
		t.Fatalf("plan change surface fields = %#v", result.Plan)
	}
	if len(result.Plan.Batches) != 1 || fmt.Sprint(result.Plan.Batches[0].FindingIDs) != fmt.Sprint([]string{"deleted", "in-delta"}) {
		t.Fatalf("planned batches = %#v, want deleted and in-delta", result.Plan.Batches)
	}
	if len(result.Plan.ExcludedFindings) != 1 {
		t.Fatalf("excluded findings = %#v, want one out-of-delta", result.Plan.ExcludedFindings)
	}
	excluded := result.Plan.ExcludedFindings[0]
	if excluded.FindingID != "out-of-delta" || excluded.Disposition != DispositionAdvisory || excluded.Reason != contracts.ReasonOutOfDelta {
		t.Fatalf("excluded finding = %#v, want out_of_delta advisory", excluded)
	}
	if result.ManifestSkeleton.ChangeSurfaceDigest != result.Plan.ChangeSurfaceDigest || len(result.ManifestSkeleton.ExcludedFindings) != 1 {
		t.Fatalf("manifest skeleton = %#v, want change surface digest and excluded finding", result.ManifestSkeleton)
	}
}

func TestPlanningBaselinePassProceedsWholeTreeWithVisibleMarker(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		ChangeSurface: ChangeSurfaceInput{BaselinePass: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Batches) != 1 || len(result.Plan.ExcludedFindings) != 0 {
		t.Fatalf("plan = %#v, want whole-tree baseline planning", result.Plan)
	}
	if result.Plan.BaselinePass == nil || !result.Plan.BaselinePass.Declared || result.Plan.BaselinePass.Reason != changesurface.BaselinePassReasonExplicit {
		t.Fatalf("baseline marker = %#v, want explicit marker", result.Plan.BaselinePass)
	}
	if result.ManifestSkeleton.BaselinePass == nil || !result.ManifestSkeleton.BaselinePass.Declared {
		t.Fatalf("skeleton baseline marker = %#v, want visible marker", result.ManifestSkeleton.BaselinePass)
	}
}

func TestPlanningAttributionExclusionsPrecedeDeltaScope(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	for _, test := range []struct {
		name           string
		schemaVersion  string
		attribution    string
		wantReason     string
		wantBatchCount int
	}{
		{name: "v4 pre-existing", schemaVersion: contracts.RoleOutputV4, attribution: contracts.FindingAttributionPreExisting, wantReason: contracts.ReasonPreExisting},
		{name: "v4 unattributed", schemaVersion: contracts.RoleOutputV4, attribution: contracts.FindingAttributionUnattributed, wantReason: contracts.ReasonAttributionUnattributed},
		{name: "readable v3", schemaVersion: contracts.RoleOutputV3, wantReason: contracts.ReasonAttributionUnattributed},
		{name: "introduced", schemaVersion: contracts.RoleOutputV4, attribution: contracts.FindingAttributionIntroduced, wantBatchCount: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []struct {
				name          string
				changeSurface ChangeSurfaceInput
				preflight     PreflightBinding
			}{
				{name: "whole tree"},
				{name: "delta", changeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest}, preflight: PreflightBinding{SnapshotDigest: headDigest}},
			} {
				t.Run(mode.name, func(t *testing.T) {
					finding := planningTestFinding("finding", contracts.SeverityHigh, contracts.WitnessStrengthConstructed)
					finding.Attribution = test.attribution
					scopePath := "internal/unchanged.go"
					if test.wantReason == "" {
						scopePath = "internal/changed.go"
					}
					finding.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: scopePath}}
					roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{finding})
					roleOutput.SchemaVersion = test.schemaVersion
					if test.schemaVersion == contracts.RoleOutputV3 {
						roleOutput.Findings[0].Attribution = ""
					}
					if mode.preflight.SnapshotDigest != "" {
						roleOutput.ArtifactDigest = mode.preflight.SnapshotDigest
					}
					result, err := Run(Options{
						FrozenCharter: frozen,
						RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
						Preflight:     mode.preflight,
						ChangeSurface: mode.changeSurface,
					})
					if err != nil {
						t.Fatalf("Run: %v", err)
					}
					if len(result.Plan.Batches) != test.wantBatchCount {
						t.Fatalf("batches = %#v, want %d", result.Plan.Batches, test.wantBatchCount)
					}
					if test.wantReason == "" {
						if len(result.Plan.ExcludedFindings) != 0 {
							t.Fatalf("excluded findings = %#v, want none", result.Plan.ExcludedFindings)
						}
						return
					}
					if len(result.Plan.ExcludedFindings) != 1 {
						t.Fatalf("excluded findings = %#v, want one attribution exclusion", result.Plan.ExcludedFindings)
					}
					excluded := result.Plan.ExcludedFindings[0]
					if excluded.Disposition != DispositionAdvisory || excluded.Reason != test.wantReason {
						t.Fatalf("excluded finding = %#v, want advisory %s", excluded, test.wantReason)
					}
				})
			}
		})
	}
}

func TestPlanningChangeSurfaceRejectsPartialManifestInput(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	_, headManifest, _ := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		ChangeSurface: ChangeSurfaceInput{HeadManifest: &headManifest},
	})
	if planningErrorCode(err) != CodeMissingChangeSurface {
		t.Fatalf("err = %v, want %s", err, CodeMissingChangeSurface)
	}
}

func TestPlanningChangeSurfaceHeadMustMatchPreflightArtifact(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	baseManifest, headManifest, headDigest := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	roleOutput.ArtifactDigest = headDigest
	wrongDigest := digest.RawBytes([]byte("wrong head"))
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     PreflightBinding{SnapshotDigest: wrongDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if result != nil {
		t.Fatalf("result = %#v, want no plan", result)
	}
	if planningErrorCode(err) != changesurface.CodeHeadArtifactMismatch {
		t.Fatalf("err = %v, want %s", err, changesurface.CodeHeadArtifactMismatch)
	}
}

func TestPlanningWholeTreeWithoutChangeSurfaceRemainsUnchanged(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Plan.Batches) != 1 || result.Plan.ChangeSurface != nil || result.Plan.BaselinePass != nil || result.Plan.ScopePolicy != changesurface.ScopePolicyWholeTree {
		t.Fatalf("plan = %#v, want existing whole-tree behavior", result.Plan)
	}
}

func TestVersionStampsForPlanManifestAndChangeSurface(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight:     planningTestPreflightBinding(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.SchemaVersion != SchemaVersion {
		t.Fatalf("plan schema_version = %s, want %s", result.Plan.SchemaVersion, SchemaVersion)
	}
	if SchemaVersion != "witness-verification-plan-v4" {
		t.Fatalf("planning SchemaVersion = %s, want witness-verification-plan-v4", SchemaVersion)
	}
	if ManifestSkeletonSchemaVersion != "witness-verification-manifest-skeleton-v3" {
		t.Fatalf("planning ManifestSkeletonSchemaVersion = %s, want witness-verification-manifest-skeleton-v3", ManifestSkeletonSchemaVersion)
	}
	if AssembleResultSchemaVersion != "witness-verification-assemble-result-v2" {
		t.Fatalf("planning AssembleResultSchemaVersion = %s, want witness-verification-assemble-result-v2", AssembleResultSchemaVersion)
	}
	if contracts.VerificationManifestV6 != "review-verification-manifest-v6" {
		t.Fatalf("contracts VerificationManifestV6 = %s, want review-verification-manifest-v6", contracts.VerificationManifestV6)
	}
	if contracts.DecisionRulesVersion != "witness-decision-rules-v1" {
		t.Fatalf("decision rules version = %s, want witness-decision-rules-v1", contracts.DecisionRulesVersion)
	}
	if changesurface.SchemaVersion != "witness-change-surface-v1" {
		t.Fatalf("change surface schema = %s, want witness-change-surface-v1", changesurface.SchemaVersion)
	}
	assembled, err := Assemble(AssembleOptions{
		Plan:         result.Plan,
		Batches:      []BatchEvidence{{BatchID: result.Batches[0].Plan.BatchID, Document: result.Batches[0].Document}},
		EvidenceRefs: validManifestEvidenceRefs(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if assembled.Manifest.SchemaVersion != contracts.VerificationManifestV6 {
		t.Fatalf("manifest schema_version = %s, want %s", assembled.Manifest.SchemaVersion, contracts.VerificationManifestV6)
	}
	if assembled.SchemaVersion != AssembleResultSchemaVersion {
		t.Fatalf("assemble result schema_version = %s, want %s", assembled.SchemaVersion, AssembleResultSchemaVersion)
	}
	if result.ManifestSkeleton.SchemaVersion != ManifestSkeletonSchemaVersion {
		t.Fatalf("manifest skeleton schema_version = %s, want %s", result.ManifestSkeleton.SchemaVersion, ManifestSkeletonSchemaVersion)
	}
}

func TestPlanningReadersRefuseActualSchemaVersion(t *testing.T) {
	for _, reader := range []struct {
		name     string
		read     func([]byte) error
		code     string
		expected string
		stale    []string
	}{
		{
			name:     "plan",
			read:     func(data []byte) error { _, err := ReadPlanDocumentBytes(data); return err },
			code:     CodeInvalidPlanDigest,
			expected: SchemaVersion,
			stale:    []string{"witness-verification-plan-v3"},
		},
		{
			name:     "manifest skeleton",
			read:     func(data []byte) error { _, err := ReadManifestSkeletonBytes(data); return err },
			code:     CodeUnsupportedManifestSkeletonSchema,
			expected: ManifestSkeletonSchemaVersion,
			stale:    []string{"witness-verification-manifest-skeleton-v2"},
		},
	} {
		t.Run(reader.name, func(t *testing.T) {
			versions := append(append([]string(nil), reader.stale...), "", "future-version")
			for _, actual := range versions {
				t.Run(schemaVersionTestName(actual), func(t *testing.T) {
					data := []byte(`{"legacy_shape_field":true}`)
					if actual != "" {
						data = []byte(fmt.Sprintf(`{"schema_version":%q,"legacy_shape_field":true}`, actual))
					}
					err := reader.read(data)
					if err == nil {
						t.Fatalf("reader accepted %q", actual)
					}
					diagnostic := diag.FromError(err)
					if diagnostic.Code != reader.code || diagnostic.Path != "/schema_version" {
						t.Fatalf("diagnostic = %#v", diagnostic)
					}
					if strings.Contains(diagnostic.Message, "unknown_json_field") || !strings.Contains(diagnostic.Message, reader.expected) {
						t.Fatalf("diagnostic = %#v, want version refusal before strict decode", diagnostic)
					}
					if actual == "" {
						if !strings.Contains(diagnostic.Message, "missing or unversioned") {
							t.Fatalf("diagnostic = %#v, want missing-version wording", diagnostic)
						}
					} else if !strings.Contains(diagnostic.Message, actual) {
						t.Fatalf("diagnostic = %#v, want message to name %q", diagnostic, actual)
					}
					if diagnostic.Details["actual"] != actual || diagnostic.Details["expected"] != reader.expected {
						t.Fatalf("schema diagnostic details = %#v", diagnostic.Details)
					}
				})
			}
		})
	}
}

func schemaVersionTestName(version string) string {
	if version == "" {
		return "missing"
	}
	return version
}

func TestPlanningConsumerFallbackSkipsPreflightSnapshotMismatch(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	snapshotDigest := digest.RawBytes([]byte("preflight snapshot"))
	mismatched := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-a", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	mismatched.ArtifactDigest = digest.RawBytes([]byte("role output artifact"))
	mismatched.ConsumerIdentity = map[string]any{"kind": "test", "id": "consumer-a"}

	emptyDigest := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{})
	emptyDigest.SchemaVersion = contracts.RoleOutputV5
	emptyDigest.ArtifactDigest = ""
	emptyDigest.Evaluation = planningTestEvaluation("whole-tree")
	emptyDigest.ConsumerIdentity = map[string]any{"kind": "test", "id": "consumer-empty"}

	matching := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-b", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	matching.ArtifactDigest = snapshotDigest
	matching.ConsumerIdentity = map[string]any{"kind": "test", "id": "consumer-b"}

	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs: []RoleOutputInput{
			{Path: "defect-empty.json", Document: emptyDigest},
			{Path: "defect-a.json", Document: mismatched},
			{Path: "defect-b.json", Document: matching},
		},
		Preflight: PreflightBinding{SnapshotDigest: snapshotDigest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.ConsumerIdentity["id"] != "consumer-b" {
		t.Fatalf("consumer identity = %#v, want consumer-b", result.Plan.ConsumerIdentity)
	}
	if len(result.Plan.Batches) != 1 || fmt.Sprint(result.Plan.Batches[0].FindingIDs) != fmt.Sprint([]string{"finding-b"}) {
		t.Fatalf("planned batches = %#v, want finding-b from matching output", result.Plan.Batches)
	}
	var found bool
	for _, diagnostic := range result.Plan.Diagnostics {
		if diagnostic.Code != CodeSnapshotArtifactMismatch {
			continue
		}
		found = true
		if diagnostic.Details["role_output"] != "defect-a.json" || diagnostic.Details["artifact_digest"] != mismatched.ArtifactDigest || diagnostic.Details["expected"] != snapshotDigest {
			t.Fatalf("mismatch diagnostic details = %#v", diagnostic.Details)
		}
	}
	if !found {
		t.Fatalf("missing %s diagnostic: %#v", CodeSnapshotArtifactMismatch, result.Plan.Diagnostics)
	}
}

func planningDeltaManifests(t *testing.T) (freeze.Manifest, freeze.Manifest, string) {
	t.Helper()
	baseManifest := freeze.Manifest{
		SchemaVersion: freeze.SchemaVersion,
		DigestProfile: digest.Profile,
		Files: []freeze.FileEntry{
			planningManifestFile("internal/changed.go", "100644", "old"),
			planningManifestFile("internal/deleted.go", "100644", "deleted"),
			planningManifestFile("internal/unchanged.go", "100644", "same"),
		},
	}
	headManifest := freeze.Manifest{
		SchemaVersion: freeze.SchemaVersion,
		DigestProfile: digest.Profile,
		Files: []freeze.FileEntry{
			planningManifestFile("internal/changed.go", "100644", "new"),
			planningManifestFile("internal/unchanged.go", "100644", "same"),
		},
	}
	headDigest, err := freeze.ManifestDigest(headManifest)
	if err != nil {
		t.Fatal(err)
	}
	return baseManifest, headManifest, headDigest
}

func planningManifestFile(path string, mode string, content string) freeze.FileEntry {
	sum := digest.RawBytes([]byte(content))
	return freeze.FileEntry{
		Path:   path,
		Mode:   mode,
		Size:   strictjson.Int64(len(content)),
		Digest: sum,
		Blob:   "blobs/sha256/" + strings.TrimPrefix(sum, digest.Prefix),
	}
}

func planningErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var diagnostic *diag.Error
	if errors.As(err, &diagnostic) {
		return diagnostic.Diagnostic.Code
	}
	var validation *ValidationError
	if errors.As(err, &validation) && len(validation.Diagnostics) > 0 {
		return validation.Diagnostics[0].Code
	}
	return ""
}

func planningTestRoleOutput(frozen *charter.FrozenCharter, role string, findings []contracts.Finding) contracts.RoleOutputDocument {
	return contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV4,
		Role:           role,
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: digest.RawBytes([]byte("artifact")),
		SourceIdentity: map[string]any{"kind": "test", "id": "source"},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
		},
		Findings: findings,
	}
}

func planningTestEvaluation(paths ...string) *contracts.RoleEvaluation {
	return &contracts.RoleEvaluation{
		EvaluatedPaths:          append([]string(nil), paths...),
		EvaluatedCharterGoalIDs: []string{"goal-cli"},
	}
}

func assertPlanningDiagnosticCode(t *testing.T, diagnostics []diag.Diagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want code %s", diagnostics, code)
}

func requirePlanningValidationError(t *testing.T, err error) *ValidationError {
	t.Helper()
	if err == nil {
		t.Fatal("Run succeeded, want a planning validation refusal")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("Run error = %T (%v), want *ValidationError", err, err)
	}
	return validation
}

func planningTestFinding(id string, severity string, strength string) contracts.Finding {
	witness := contracts.Witness{
		Kind:     contracts.WitnessKindDefect,
		Strength: strength,
		Content:  "The filed witness is specific to the declared CLI behavior.",
	}
	if strength == contracts.WitnessStrengthConstructed || strength == contracts.WitnessStrengthExecutable {
		witness.EntryPoint = &contracts.ScopeAnchor{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}
		witness.ReachabilityChain = []contracts.ScopeAnchor{
			{Dimension: charter.DimensionEntryPoints, EntryID: "cli"},
			{Dimension: charter.DimensionInputSurface, Value: "config"},
			{Dimension: charter.DimensionValidStates, EntryID: "normal"},
		}
	}
	return contracts.Finding{
		ID:              id,
		Kind:            contracts.FindingKindDefect,
		Title:           "Finding " + id,
		CharterGoalIDs:  []string{"goal-cli"},
		ClaimedSeverity: severity,
		Attribution:     contracts.FindingAttributionIntroduced,
		ScopeAnchors:    []contracts.ScopeAnchor{{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}},
		Witness:         witness,
		EstimatedDelta: contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
		},
		SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
			Direction:          contracts.RemedyDirectionChange,
			Summary:            "Change the smallest reachable branch.",
			MinimalityArgument: "The fix is limited to the branch named by the witness.",
		},
		ProposedTests: []contracts.ProposedTest{{
			ID:                 "test-" + id,
			Name:               "covers " + id,
			ReachablePartition: "partition-" + id,
			CharterRefs:        []contracts.CharterRef{{GoalID: "goal-cli"}},
		}},
	}
}

func planningTestFrozenCharter(t *testing.T) *charter.FrozenCharter {
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
	return &frozen
}
