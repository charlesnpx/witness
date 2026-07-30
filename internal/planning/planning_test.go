package planning

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/digest"
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
	if len(result.Plan.Batches) != 0 {
		t.Fatalf("planned batches = %#v, want none", result.Plan.Batches)
	}
	if len(result.Plan.ExcludedFindings) != 3 {
		t.Fatalf("excluded findings = %#v, want 3", result.Plan.ExcludedFindings)
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
	if reasons["over-strength"] != CodeSeverityExceedsCap {
		t.Fatalf("over-strength reason = %s, want %s", reasons["over-strength"], CodeSeverityExceedsCap)
	}
	if reasons["recursive"] != CodeRecursiveRecurrence {
		t.Fatalf("recursive reason = %s, want %s", reasons["recursive"], CodeRecursiveRecurrence)
	}
}

func planningTestRoleOutput(frozen *charter.FrozenCharter, role string, findings []contracts.Finding) contracts.RoleOutputDocument {
	return contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV3,
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
