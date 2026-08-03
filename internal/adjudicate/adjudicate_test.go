package adjudicate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"witness/internal/changesurface"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/harness"
	"witness/internal/planning"
)

func TestAdjudicationBranchTable(t *testing.T) {
	t.Run("valid recurrence match", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-recurrence", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		witnessDigest, err := contracts.WitnessDigest(finding.Witness)
		if err != nil {
			t.Fatal(err)
		}
		finding.Recurrence = &contracts.RecurrenceRef{
			PriorFindingID: "prior-finding",
			FindingKey:     "same-finding",
			WitnessDigest:  witnessDigest,
			ArtifactDigest: artifactDigest,
		}
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
			priorLineage: []PriorLineageRecord{{
				FindingID:      "prior-finding",
				FindingKey:     "same-finding",
				CharterHash:    frozen.CharterHash,
				ArtifactDigest: artifactDigest,
				WitnessDigest:  witnessDigest,
				Disposition:    contracts.DispositionAdmitted,
			}},
			priorLineageProvided: true,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertMissingReason(t, got, ReasonInvalidRecurrenceLineage)
		assertMissingReason(t, got, ReasonRecurrenceLineageUnavailable)
	})

	t.Run("recurrence without prior ledger is advisory", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-lineage", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		witnessDigest, err := contracts.WitnessDigest(finding.Witness)
		if err != nil {
			t.Fatal(err)
		}
		finding.Recurrence = &contracts.RecurrenceRef{
			PriorFindingID: "missing-prior",
			FindingKey:     "same-finding",
			WitnessDigest:  witnessDigest,
			ArtifactDigest: artifactDigest,
		}
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdvisory)
		assertApplicationClass(t, got, contracts.ApplicationClassNone)
		assertHasReason(t, got, ReasonRecurrenceLineageUnavailable)
	})

	t.Run("executable satisfying receipt preserves executable strength", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		command := executableCommand("stdout_contains=ok")
		receipt := signedReceipt(t, frozen.CharterHash, "finding-exec-ok", command)
		finding := defectExecutableFinding("finding-exec-ok", contracts.SeverityCritical, command)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, receipt.artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, receipt.artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, []contracts.ExecutionReceiptManifestRecord{receipt.record}),
			receiptDir:  receipt.outputDir,
			receiptKey:  receipt.key,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		if got.Execution == nil || got.Execution.VerificationClassification != harness.ClassificationValid {
			t.Fatalf("execution metadata = %#v, want valid", got.Execution)
		}
		if len(got.StrengthTrajectory) != 1 || got.StrengthTrajectory[0].Strength != contracts.WitnessStrengthExecutable {
			t.Fatalf("strength trajectory = %#v, want executable retained", got.StrengthTrajectory)
		}
	})

	t.Run("executable receipt with wrong charter starts at constructed", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		command := executableCommand("stdout_contains=ok")
		receipt := signedReceipt(t, testDigest("wrong-charter"), "finding-exec-wrong-charter", command)
		finding := defectExecutableFinding("finding-exec-wrong-charter", contracts.SeverityCritical, command)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, receipt.artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, receipt.artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, []contracts.ExecutionReceiptManifestRecord{receipt.record}),
			receiptDir:  receipt.outputDir,
			receiptKey:  receipt.key,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertHasReason(t, got, ReasonExecutionReceiptInvalid)
		assertStrengthStep(t, got, "execution_receipt", contracts.WitnessStrengthConstructed)
		if got.Execution == nil || got.Execution.VerificationClassification != harness.ClassificationInvalid {
			t.Fatalf("execution metadata = %#v, want invalid", got.Execution)
		}
	})

	t.Run("failed manifest receipt record starts at constructed", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		command := executableCommand("stdout_contains=ok")
		receipt := signedReceipt(t, frozen.CharterHash, "finding-exec-failed-record", command)
		receipt.record.Status = contracts.ExecutionStatusFailed
		receipt.record.FailureReason = "receipt_invalid"
		finding := defectExecutableFinding("finding-exec-failed-record", contracts.SeverityCritical, command)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, receipt.artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, receipt.artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, []contracts.ExecutionReceiptManifestRecord{receipt.record}),
			receiptDir:  receipt.outputDir,
			receiptKey:  receipt.key,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertHasReason(t, got, ReasonExecutionReceiptInvalid)
		assertStrengthStep(t, got, "execution_receipt", contracts.WitnessStrengthConstructed)
		if got.Execution == nil || got.Execution.ManifestStatus != contracts.ExecutionStatusFailed || got.Execution.VerificationClassification != harness.ClassificationInvalid {
			t.Fatalf("execution metadata = %#v, want failed/invalid", got.Execution)
		}
	})

	t.Run("executable missing receipt starts at constructed", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectExecutableFinding("finding-exec-missing", contracts.SeverityHigh, executableCommand("stdout_contains=ok"))
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertHasReason(t, got, ReasonExecutionReceiptMissing)
		assertStrengthStep(t, got, "execution_receipt", contracts.WitnessStrengthConstructed)
	})

	t.Run("valid contradictory receipt breaks executable witness", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		command := executableCommand("stdout_contains=missing")
		receipt := signedReceipt(t, frozen.CharterHash, "finding-exec-contradicted", command)
		if receipt.record.Status != contracts.ExecutionStatusContradicted {
			t.Fatalf("receipt status = %s, want contradicted", receipt.record.Status)
		}
		finding := defectExecutableFinding("finding-exec-contradicted", contracts.SeverityCritical, command)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, receipt.artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, receipt.artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, []contracts.ExecutionReceiptManifestRecord{receipt.record}),
			receiptDir:  receipt.outputDir,
			receiptKey:  receipt.key,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdvisory)
		assertApplicationClass(t, got, contracts.ApplicationClassNone)
		assertHasReason(t, got, ReasonExecutionReceiptContradicted)
	})

	t.Run("contradicted manifest status remains contradicted when receipt is missing", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		command := executableCommand("stdout_contains=missing")
		receipt := signedReceipt(t, frozen.CharterHash, "finding-exec-contradicted-missing", command)
		if receipt.record.Status != contracts.ExecutionStatusContradicted {
			t.Fatalf("receipt status = %s, want contradicted", receipt.record.Status)
		}
		if err := os.Remove(filepath.Join(receipt.outputDir, "receipts", receipt.record.ReceiptRef.ID+".json")); err != nil {
			t.Fatal(err)
		}
		finding := defectExecutableFinding("finding-exec-contradicted-missing", contracts.SeverityCritical, command)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, receipt.artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, receipt.artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, []contracts.ExecutionReceiptManifestRecord{receipt.record}),
			receiptDir:  receipt.outputDir,
			receiptKey:  receipt.key,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdvisory)
		assertApplicationClass(t, got, contracts.ApplicationClassNone)
		assertHasReason(t, got, ReasonExecutionReceiptContradicted)
		if got.Execution == nil || got.Execution.Reason != ReasonExecutionReceiptContradicted || got.Execution.VerificationClassification != harness.ClassificationContradictory {
			t.Fatalf("execution metadata = %#v, want sticky contradicted classification", got.Execution)
		}
		if len(got.Execution.Diagnostics) == 0 {
			t.Fatal("execution diagnostics missing receipt load failure")
		}
	})

	t.Run("strength cap application", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-cap", contracts.WitnessStrengthConstructed, contracts.SeverityCritical)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertSeverity(t, got, contracts.SeverityHigh)
		assertHasReason(t, got, ReasonSeverityCapped)
	})

	t.Run("missing relay verification preserves capped severity as pending", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-pending", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithRelayStatus(frozen, artifactDigest, contracts.RecordStatusUnavailable, "relay_verification_unavailable"),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionPendingVerification)
		assertSeverity(t, got, contracts.SeverityHigh)
		assertHasReason(t, got, ReasonRelayVerificationUnavailable)
	})

	t.Run("survived retains strength", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-survived", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertHasReason(t, got, ReasonRelaySurvived)
		if len(got.StrengthTrajectory) != 1 || got.StrengthTrajectory[0].Strength != contracts.WitnessStrengthConstructed {
			t.Fatalf("strength trajectory = %#v, want constructed retained", got.StrengthTrajectory)
		}
	})

	t.Run("weakened with strength remaining reapplies cap", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-weakened", contracts.WitnessStrengthConstructed, contracts.SeverityCritical)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{counterVerdict(t, finding, contracts.VerdictWeakened)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertStrengthStep(t, got, "relay_result", contracts.WitnessStrengthArgued)
		assertSeverity(t, got, contracts.SeverityMedium)
		assertHasReason(t, got, ReasonRelayWeakened)
	})

	t.Run("weakened below floor is advisory", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-below-floor", contracts.WitnessStrengthArgued, contracts.SeverityMedium)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{counterVerdict(t, finding, contracts.VerdictWeakened)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdvisory)
		assertApplicationClass(t, got, contracts.ApplicationClassNone)
		assertHasReason(t, got, ReasonWitnessWeakenedBelowFloor)
	})

	t.Run("relay broken routes to advisory", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-broken", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{counterVerdict(t, finding, contracts.VerdictBroken)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdvisory)
		assertHasReason(t, got, ReasonRelayBroken)
	})

	t.Run("duplicate relay batches hold finding pending", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectFinding("finding-duplicate-batches", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithDuplicateRelayBatches(t, frozen, artifactDigest, finding),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionPendingVerification)
		assertHasReason(t, got, ReasonRelayVerificationInvalid)
		if got.Relay == nil || got.Relay.Status != contracts.RecordStatusFailed || got.Relay.FailureReason != "relay_verdict_finding_id_collision" {
			t.Fatalf("relay metadata = %#v, want failed collision", got.Relay)
		}
		assertResultHasDiagnostic(t, result, CodeDuplicateRelayBatch, "/manifest/batches")
	})

	t.Run("executable missing receipt weakened chain ends argued medium caller decision", func(t *testing.T) {
		frozen := testFrozenCharter(t)
		artifactDigest := testDigest("artifact")
		finding := defectExecutableFinding("finding-chain", contracts.SeverityCritical, executableCommand("stdout_contains=ok"))
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
		result := runAdjudication(t, runInput{
			frozen:      frozen,
			roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{counterVerdict(t, finding, contracts.VerdictWeakened)}, nil),
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertApplicationClass(t, got, contracts.ApplicationClassCallerDecision)
		assertStrengthStep(t, got, "execution_receipt", contracts.WitnessStrengthConstructed)
		assertStrengthStep(t, got, "relay_result", contracts.WitnessStrengthArgued)
		assertSeverity(t, got, contracts.SeverityMedium)
		assertHasReason(t, got, ReasonExecutionReceiptMissing)
		assertHasReason(t, got, ReasonRelayWeakened)
		assertHasReason(t, got, ReasonSeverityCapped)
	})
}

func TestPlanningAndAdjudicationAgreeOnOverCapSeverity(t *testing.T) {
	frozen := testFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	finding := defectFinding("finding-over-cap", contracts.WitnessStrengthConstructed, contracts.SeverityCritical)
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})

	planResult, err := planning.Run(planning.Options{
		FrozenCharter: &frozen,
		RoleOutputs: []planning.RoleOutputInput{{
			Path:     "defect.json",
			Document: roleOutput,
		}},
	})
	if err != nil {
		t.Fatalf("planning Run: %v", err)
	}
	if len(planResult.Plan.Batches) != 1 || len(planResult.Plan.Batches[0].FindingIDs) != 1 || planResult.Plan.Batches[0].FindingIDs[0] != finding.ID {
		t.Fatalf("planned batches = %#v, want over-cap finding batched", planResult.Plan.Batches)
	}
	if len(planResult.Plan.ExcludedFindings) != 0 {
		t.Fatalf("excluded findings = %#v, want none for over-cap severity", planResult.Plan.ExcludedFindings)
	}

	result := runAdjudication(t, runInput{
		frozen:      frozen,
		roleOutputs: []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		manifest:    manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
	})
	got := onlyFinding(t, result)
	assertDisposition(t, got, contracts.DispositionAdmitted)
	assertSeverity(t, got, contracts.SeverityHigh)
	assertHasReason(t, got, ReasonSeverityCapped)
}

func TestAdjudicationRejectsInvalidEmbeddedNormalizedCharter(t *testing.T) {
	frozen := testFrozenCharter(t)
	frozen.Charter.StandingNoGoals[0].Statement = "Changed invariant."
	hash, err := charter.Hash(frozen.Charter)
	if err != nil {
		t.Fatal(err)
	}
	frozen.CharterHash = hash
	artifactDigest := testDigest("artifact")
	finding := defectFinding("finding-invalid-charter", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})

	result, err := Run(Options{
		FrozenCharter: &frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Manifest:      manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
	})
	if err == nil {
		t.Fatalf("Run result=%#v err=nil, want invalid frozen Charter", result)
	}
	if result != nil {
		t.Fatalf("Run result=%#v, want nil on global frozen Charter failure", result)
	}
	assertErrorHasDiagnostic(t, err, CodeInvalidFrozenCharter, "/charter/charter/standing_no_goals/0")
}

func TestAdjudicationEmptyInvalidRoleOutputReturnsResultAndError(t *testing.T) {
	frozen := testFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{})
	roleOutput.SchemaVersion = "not-review-role-output-v3"

	result, err := Run(Options{
		FrozenCharter: &frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "empty-invalid.json", Document: roleOutput}},
		Manifest:      manifestWithRelayStatus(frozen, artifactDigest, contracts.RecordStatusNotRequired, ""),
	})
	if err == nil {
		t.Fatalf("Run result=%#v err=nil, want role-output validation error", result)
	}
	if result == nil {
		t.Fatal("Run returned nil result, want typed adjudication result")
	}
	if result.ResultDigest == "" {
		t.Fatalf("result missing digest: %#v", result)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %#v, want none", result.Findings)
	}
	assertResultHasDiagnostic(t, result, contracts.CodeInvalidRoleOutput, "/role_outputs/0/schema_version")
	assertErrorHasDiagnostic(t, err, contracts.CodeInvalidRoleOutput, "/role_outputs/0/schema_version")
}

func TestApplicationClassIsIndependentFromDisposition(t *testing.T) {
	frozen := testFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	defect := defectFinding("finding-caller", contracts.WitnessStrengthArgued, contracts.SeverityMedium)
	economy := economyFinding("finding-auto", contracts.SeverityHigh)
	defectOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{defect})
	economyOutput := roleOutputFor(frozen, contracts.RoleEconomy, artifactDigest, []contracts.Finding{economy})
	result := runAdjudication(t, runInput{
		frozen: frozen,
		roleOutputs: []RoleOutputInput{
			{Path: "defect.json", Document: defectOutput},
			{Path: "economy.json", Document: economyOutput},
		},
		manifest: manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{
			survivedVerdict(t, defect),
			survivedVerdict(t, economy),
		}, nil),
	})
	if result.ResultDigest == "" {
		t.Fatal("missing result digest")
	}
	byID := findingsByID(result)
	assertDisposition(t, byID["finding-caller"], contracts.DispositionAdmitted)
	assertDisposition(t, byID["finding-auto"], contracts.DispositionAdmitted)
	assertApplicationClass(t, byID["finding-caller"], contracts.ApplicationClassCallerDecision)
	assertApplicationClass(t, byID["finding-auto"], contracts.ApplicationClassAutomaticCandidate)
}

func TestAdjudicationDeltaScopeRoutesOutOfDeltaFindings(t *testing.T) {
	frozen := testFrozenCharter(t)
	baseManifest, headManifest, artifactDigest := adjudicationDeltaManifests(t)
	inDelta := defectFinding("in-delta", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	inDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/touched.go"}}
	outOfDelta := defectFinding("out-of-delta", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	outOfDelta.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/other.go"}}
	deleted := defectFinding("deleted", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	deleted.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/deleted.go"}}
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{inDelta, outOfDelta, deleted})
	manifest := manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{
		survivedVerdict(t, inDelta),
		survivedVerdict(t, outOfDelta),
		survivedVerdict(t, deleted),
	}, nil)
	surface, surfaceDigest, err := changesurface.Derive(baseManifest, headManifest, artifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ScopePolicy = contracts.ScopePolicyDeltaObligating
	manifest.ChangeSurface = &surface
	manifest.ChangeSurfaceDigest = surfaceDigest
	policyDocument := contracts.DefaultReviewPolicy()
	policyDocument.PolicyID = "delta-policy"
	policyDocument.ScopePolicy = contracts.ScopePolicyDeltaObligating

	result := runAdjudication(t, runInput{
		frozen:       frozen,
		roleOutputs:  []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		manifest:     manifest,
		baseManifest: &baseManifest,
		headManifest: &headManifest,
		policy:       policyDocument,
	})
	byID := findingsByID(result)
	assertDisposition(t, byID["in-delta"], contracts.DispositionAdmitted)
	assertDisposition(t, byID["deleted"], contracts.DispositionAdmitted)
	assertDisposition(t, byID["out-of-delta"], contracts.DispositionAdvisory)
	assertApplicationClass(t, byID["out-of-delta"], contracts.ApplicationClassCallerDecision)
	assertHasReason(t, byID["out-of-delta"], contracts.ReasonOutOfDelta)
	if result.Summary.Advisory != 1 {
		t.Fatalf("summary = %#v, want one advisory finding", result.Summary)
	}
}

func TestAdjudicationRederivesDeclaredChangeSurface(t *testing.T) {
	frozen := testFrozenCharter(t)
	baseManifest, headManifest, artifactDigest := adjudicationDeltaManifests(t)
	finding := defectFinding("in-delta", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	finding.ScopeAnchors = []contracts.ScopeAnchor{{Dimension: charter.DimensionInputSurface, Value: "internal/touched.go"}}
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
	manifest := manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil)
	surface, _, err := changesurface.Derive(baseManifest, headManifest, artifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	surface.ChangedPaths = []changesurface.PathChange{{Path: "internal/other.go", ChangeKinds: []string{changesurface.ChangeKindModified}}}
	surfaceDigest, err := changesurface.Digest(surface)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ScopePolicy = contracts.ScopePolicyDeltaObligating
	manifest.ChangeSurface = &surface
	manifest.ChangeSurfaceDigest = surfaceDigest
	policyDocument := contracts.DefaultReviewPolicy()
	policyDocument.PolicyID = "delta-policy"
	policyDocument.ScopePolicy = contracts.ScopePolicyDeltaObligating

	result, err := Run(Options{
		FrozenCharter: &frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Manifest:      manifest,
		Policy:        policyDocument,
		BaseManifest:  &baseManifest,
		HeadManifest:  &headManifest,
	})
	if err == nil {
		t.Fatalf("Run result=%#v err=nil, want change surface derivation rejection", result)
	}
	assertErrorHasDiagnostic(t, err, changesurface.CodeInvalidChangeSurface, "/manifest/change_surface/change_surface_digest")
}

func TestAdjudicationRejectsBaselinePassExcludedFindingWithoutChangeSurface(t *testing.T) {
	frozen := testFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	finding := defectFinding("included", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
	roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})
	roleOutputDigest, err := contracts.RoleOutputDigest(roleOutput)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil)
	manifest.ScopePolicy = contracts.ScopePolicyDeltaObligating
	manifest.BaselinePass = &changesurface.BaselinePass{
		Declared: true,
		Reason:   changesurface.BaselinePassReasonExplicit,
	}
	manifest.ExcludedFindings = []contracts.ExcludedFindingRecord{{
		Role:      contracts.RoleDefect,
		FindingID: finding.ID,
		SourceRoleOutputRef: contracts.ArtifactRef{
			Kind:          "role-output",
			ID:            "defect-json",
			Digest:        roleOutputDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		SourceRoleOutputDigest: roleOutputDigest,
		Reason:                 contracts.ReasonOutOfDelta,
		Disposition:            contracts.DispositionAdvisory,
		ApplicationClass:       contracts.ApplicationClassCallerDecision,
	}}
	policyDocument := contracts.DefaultReviewPolicy()
	policyDocument.PolicyID = "delta-policy"
	policyDocument.ScopePolicy = contracts.ScopePolicyDeltaObligating

	result, err := Run(Options{
		FrozenCharter: &frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Manifest:      manifest,
		Policy:        policyDocument,
	})
	if err == nil {
		t.Fatalf("Run result=%#v err=nil, want baseline-pass exclusion rejection", result)
	}
	if result != nil {
		t.Fatalf("Run result=%#v, want nil on global manifest failure", result)
	}
	assertErrorHasDiagnostic(t, err, CodeInvalidManifest, "/manifest/excluded_findings/0")
}

func TestAdditiveApplicationClassUsesCapReleaseUnit(t *testing.T) {
	frozen := testFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	productionCap := 5
	testCap := 5
	rules, policyDocument := filesReleasePolicy(t, frozen, productionCap, testCap)

	t.Run("line estimate does not satisfy files release", func(t *testing.T) {
		finding := defectFinding("finding-files-release", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		finding.SmallestSufficientRemedy.Direction = contracts.RemedyDirectionAdd
		finding.EstimatedDelta = contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
		}
		roleOutput := roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding})

		result := runAdjudication(t, runInput{
			frozen:                       frozen,
			roleOutputs:                  []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:                     manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
			rules:                        rules,
			policy:                       policyDocument,
			policyCapReleaseLedgerBacked: true,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertApplicationClass(t, got, contracts.ApplicationClassCallerDecision)
	})

	t.Run("omitted counts do not satisfy files release", func(t *testing.T) {
		finding := defectFinding("finding-files-release-omitted", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		finding.SmallestSufficientRemedy.Direction = contracts.RemedyDirectionAdd
		roleOutput := roleOutputWithEstimatedDelta(t,
			roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding}),
			map[string]any{
				"production": map[string]any{"status": contracts.DeltaStatusKnown},
				"test":       map[string]any{"status": contracts.DeltaStatusKnown},
			},
		)
		finding = roleOutput.Findings[0]

		result := runAdjudication(t, runInput{
			frozen:                       frozen,
			roleOutputs:                  []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:                     manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
			rules:                        rules,
			policy:                       policyDocument,
			policyCapReleaseLedgerBacked: true,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertApplicationClass(t, got, contracts.ApplicationClassCallerDecision)
	})

	t.Run("explicit files zero satisfies files release", func(t *testing.T) {
		finding := defectFinding("finding-files-release-zero", contracts.WitnessStrengthConstructed, contracts.SeverityHigh)
		finding.SmallestSufficientRemedy.Direction = contracts.RemedyDirectionAdd
		roleOutput := roleOutputWithEstimatedDelta(t,
			roleOutputFor(frozen, contracts.RoleDefect, artifactDigest, []contracts.Finding{finding}),
			map[string]any{
				"production": map[string]any{"status": contracts.DeltaStatusKnown, "files": 0},
				"test":       map[string]any{"status": contracts.DeltaStatusKnown, "files": 0},
			},
		)
		finding = roleOutput.Findings[0]

		result := runAdjudication(t, runInput{
			frozen:                       frozen,
			roleOutputs:                  []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
			manifest:                     manifestWithVerdicts(t, frozen, artifactDigest, []contracts.WitnessVerdict{survivedVerdict(t, finding)}, nil),
			rules:                        rules,
			policy:                       policyDocument,
			policyCapReleaseLedgerBacked: true,
		})
		got := onlyFinding(t, result)
		assertDisposition(t, got, contracts.DispositionAdmitted)
		assertApplicationClass(t, got, contracts.ApplicationClassAutomaticCandidate)
	})
}

type runInput struct {
	frozen                       charter.FrozenCharter
	roleOutputs                  []RoleOutputInput
	manifest                     contracts.VerificationManifest
	baseManifest                 *freeze.Manifest
	headManifest                 *freeze.Manifest
	receiptDir                   string
	receiptKey                   []byte
	rules                        contracts.ReviewRules
	policy                       contracts.ReviewPolicy
	policyCapReleaseLedgerBacked bool
	priorLineage                 []PriorLineageRecord
	priorLineageProvided         bool
}

func runAdjudication(t *testing.T, input runInput) *Result {
	t.Helper()
	result, err := Run(Options{
		FrozenCharter:                &input.frozen,
		RoleOutputs:                  input.roleOutputs,
		Manifest:                     input.manifest,
		BaseManifest:                 input.baseManifest,
		HeadManifest:                 input.headManifest,
		ReceiptOutputDir:             input.receiptDir,
		ReceiptHMACKey:               input.receiptKey,
		Rules:                        input.rules,
		Policy:                       input.policy,
		PolicyCapReleaseLedgerBacked: input.policyCapReleaseLedgerBacked,
		PriorLineage:                 input.priorLineage,
		PriorLineageProvided:         input.priorLineageProvided,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.SchemaVersion != ResultSchemaVersion {
		t.Fatalf("schema_version = %s, want %s", result.SchemaVersion, ResultSchemaVersion)
	}
	return result
}

func filesReleasePolicy(t *testing.T, frozen charter.FrozenCharter, productionCap int, testCap int) (contracts.ReviewRules, contracts.ReviewPolicy) {
	t.Helper()
	rules := contracts.DefaultReviewRules()
	policyDocument := contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-files-release",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
	policyDigest, err := contracts.ReviewPolicyDigest(policyDocument)
	if err != nil {
		t.Fatal(err)
	}
	rulesDigest, err := contracts.ReviewRulesDigest(rules)
	if err != nil {
		t.Fatal(err)
	}
	policyDocument.CapRelease = &contracts.CapReleaseRecord{
		Unit:          "files",
		ProductionCap: productionCap,
		TestCap:       testCap,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner accepted file caps.",
		Actor:         "owner",
		PolicyDigest:  policyDigest,
		RulesDigest:   rulesDigest,
		CharterHash:   frozen.CharterHash,
	}
	return rules, policyDocument
}

func roleOutputWithEstimatedDelta(t *testing.T, document contracts.RoleOutputDocument, estimatedDelta map[string]any) contracts.RoleOutputDocument {
	t.Helper()
	data, err := contracts.CanonicalBytes(document)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	findings, ok := value["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %#v, want exactly one finding", value["findings"])
	}
	finding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("finding = %#v, want object", findings[0])
	}
	finding["estimated_delta"] = estimatedDelta
	mutated, err := contracts.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.ReadRoleOutputBytes(mutated)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func onlyFinding(t *testing.T, result *Result) FindingVerdict {
	t.Helper()
	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1: %#v", len(result.Findings), result.Findings)
	}
	return result.Findings[0]
}

func testFrozenCharter(t *testing.T) charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-1",
			Statement: "The CLI behaves deterministically for declared valid inputs.",
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
				Statement: "Declared states.",
				Entries:   []charter.Entry{{ID: "normal", Statement: "Normal state."}},
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
				Statement: "Threats must be concrete.",
				Entries:   []charter.Entry{},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func roleOutputFor(frozen charter.FrozenCharter, role string, artifactDigest string, findings []contracts.Finding) contracts.RoleOutputDocument {
	return contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV3,
		Role:           role,
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: artifactDigest,
		SourceIdentity: map[string]any{"kind": "test", "id": "source"},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
		},
		Findings: findings,
	}
}

func adjudicationDeltaManifests(t *testing.T) (freeze.Manifest, freeze.Manifest, string) {
	t.Helper()
	baseManifest := freeze.Manifest{
		SchemaVersion: freeze.SchemaVersion,
		DigestProfile: digest.Profile,
		Files: []freeze.FileEntry{
			adjudicationManifestFile("internal/deleted.go", "100644", "deleted"),
			adjudicationManifestFile("internal/touched.go", "100644", "old"),
			adjudicationManifestFile("internal/untouched.go", "100644", "same"),
		},
	}
	headManifest := freeze.Manifest{
		SchemaVersion: freeze.SchemaVersion,
		DigestProfile: digest.Profile,
		Files: []freeze.FileEntry{
			adjudicationManifestFile("internal/touched.go", "100644", "new"),
			adjudicationManifestFile("internal/untouched.go", "100644", "same"),
		},
	}
	headDigest, err := freeze.ManifestDigest(headManifest)
	if err != nil {
		t.Fatal(err)
	}
	return baseManifest, headManifest, headDigest
}

func adjudicationManifestFile(path string, mode string, content string) freeze.FileEntry {
	sum := digest.RawBytes([]byte(content))
	return freeze.FileEntry{
		Path:   path,
		Mode:   mode,
		Size:   int64(len(content)),
		Digest: sum,
		Blob:   "blobs/sha256/" + strings.TrimPrefix(sum, digest.Prefix),
	}
}

func defectFinding(id string, strength string, severity string) contracts.Finding {
	return contracts.Finding{
		ID:              id,
		Kind:            contracts.FindingKindDefect,
		Title:           "Defect " + id,
		CharterGoalIDs:  []string{"goal-1"},
		ClaimedSeverity: severity,
		ScopeAnchors:    []contracts.ScopeAnchor{{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}},
		Witness: contracts.Witness{
			Kind:     contracts.WitnessKindDefect,
			Strength: strength,
			Content:  "The declared path reaches the disputed behavior.",
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
			Summary:            "Change the reachable branch.",
			MinimalityArgument: "Only the reachable branch changes.",
		},
		ProposedTests: []contracts.ProposedTest{{
			ID:                 "test-" + id,
			Name:               "covers " + id,
			ReachablePartition: "partition-" + id,
			CharterRefs:        []contracts.CharterRef{{GoalID: "goal-1"}},
		}},
	}
}

func defectExecutableFinding(id string, severity string, command contracts.ExecutableSpec) contracts.Finding {
	finding := defectFinding(id, contracts.WitnessStrengthExecutable, severity)
	finding.Witness.Content = ""
	finding.Witness.Executable = &command
	return finding
}

func economyFinding(id string, severity string) contracts.Finding {
	return contracts.Finding{
		ID:              id,
		Kind:            contracts.FindingKindEconomy,
		Title:           "Economy " + id,
		CharterGoalIDs:  []string{"goal-1"},
		ClaimedSeverity: severity,
		Witness: contracts.Witness{
			Kind:     contracts.WitnessKindEquivalence,
			Strength: contracts.WitnessStrengthConstructed,
			Content:  "The simplified implementation preserves the declared behavior.",
		},
		EstimatedDelta: contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: -4, Files: 0},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 0, Files: 0},
		},
		SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
			Direction:          contracts.RemedyDirectionRemove,
			Summary:            "Remove redundant code.",
			MinimalityArgument: "The removal is the smallest equivalent change.",
		},
	}
}

func executableCommand(expected string) contracts.ExecutableSpec {
	return contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: expected,
	}
}

type receiptFixture struct {
	artifactDigest string
	outputDir      string
	key            []byte
	record         contracts.ExecutionReceiptManifestRecord
}

func signedReceipt(t *testing.T, charterHash string, findingID string, command contracts.ExecutableSpec) receiptFixture {
	t.Helper()
	key := []byte("test-hmac-key")
	outputDir := filepath.Join(t.TempDir(), "receipts")
	artifactDigest := testDigest("source-" + findingID)
	sourceBefore := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "source-snapshot", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	sourceAfter := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "source-snapshot", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	workspaceBefore := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "execution-workspace", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	workspaceAfter := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "execution-workspace", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	sourceBeforeRef := writeJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "source-before", sourceBefore)
	sourceAfterRef := writeJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "source-after", sourceAfter)
	workspaceBeforeRef := writeJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "workspace-before", workspaceBefore)
	workspaceAfterRef := writeJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "workspace-after", workspaceAfter)
	delta := harness.DiffInventories(workspaceBefore, workspaceAfter, workspaceBeforeRef.Digest, workspaceAfterRef.Digest)
	deltaRef := writeJSONReceiptArtifact(t, outputDir, "inventory", "workspace-mutation-report", "workspace-delta", delta)
	stdout := []byte("ok\n")
	stderr := []byte{}
	stdoutRef := writeBytesReceiptArtifact(t, outputDir, "stdout", "execution-stdout", "stdout", "text/plain", stdout)
	stderrRef := writeBytesReceiptArtifact(t, outputDir, "stderr", "execution-stderr", "stderr", "text/plain", stderr)
	executionStatus := contracts.ExecutionStatusSatisfied
	if command.ExpectedObservation == "stdout_contains=missing" {
		executionStatus = contracts.ExecutionStatusContradicted
	}
	receipt := contracts.ExecutionReceipt{
		SchemaVersion:  contracts.ExecutionReceiptV2,
		ReceiptID:      "receipt-" + findingID,
		FindingID:      findingID,
		CharterHash:    charterHash,
		ArtifactDigest: artifactDigest,
		FrozenSource: contracts.ArtifactRef{
			Kind:          "source-snapshot-manifest",
			ID:            "source-snapshot",
			Digest:        artifactDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		Harness: contracts.HarnessIdentity{
			ID:          "witness-harness-v1",
			Version:     harness.Version,
			BuildDigest: testDigest("harness-build"),
		},
		Issuer: contracts.ReceiptIssuer{
			ID:     "issuer-1",
			Actor:  "test",
			Method: "hmac-sha256-key-file",
		},
		Authentication: contracts.ReceiptAuthentication{
			Scheme: harness.AuthenticationScheme,
			KeyID:  "test-key",
		},
		Command:                  command,
		Containment:              contracts.ContainmentReport{Filesystem: "test fixture", Network: "disabled", Process: "test fixture"},
		SourceInventoryBefore:    sourceBeforeRef,
		SourceInventoryAfter:     sourceAfterRef,
		WorkspaceInventoryBefore: workspaceBeforeRef,
		WorkspaceInventoryAfter:  workspaceAfterRef,
		Captures: contracts.ExecutionCaptures{
			Stdout:            &stdoutRef,
			Stderr:            &stderrRef,
			ProducedArtifacts: []contracts.ArtifactRef{deltaRef},
		},
		ExpectedObservation:   command.ExpectedObservation,
		ObservedObservation:   "exit_code=0;timed_out=false;termination_reason=completed;stdout_digest=" + stdoutRef.Digest + ";stderr_digest=" + stderrRef.Digest,
		ExecutionStatus:       executionStatus,
		ResultWorkspaceDigest: workspaceAfterRef.Digest,
		ResourceLimits: map[string]any{
			"source_inventory_before_digest":    sourceBeforeRef.Digest,
			"source_inventory_after_digest":     sourceAfterRef.Digest,
			"workspace_inventory_before_digest": workspaceBeforeRef.Digest,
			"workspace_inventory_after_digest":  workspaceAfterRef.Digest,
			"termination_reason":                "completed",
			"timed_out":                         false,
			"canceled":                          false,
			"exit_code":                         0,
		},
	}
	if err := harness.SignReceipt(&receipt, key); err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := contracts.ExecutionReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptRef := contracts.ArtifactRef{
		Kind:          "execution-receipt",
		ID:            receipt.ReceiptID,
		Digest:        receiptDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
	writeReceiptFile(t, outputDir, receipt)
	return receiptFixture{
		artifactDigest: artifactDigest,
		outputDir:      outputDir,
		key:            key,
		record: contracts.ExecutionReceiptManifestRecord{
			FindingID:     findingID,
			Status:        receipt.ExecutionStatus,
			ReceiptRef:    &receiptRef,
			ReceiptDigest: receiptDigest,
		},
	}
}

func writeJSONReceiptArtifact(t *testing.T, outputDir string, namespace string, kind string, id string, value any) contracts.ArtifactRef {
	t.Helper()
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeBytesReceiptArtifact(t, outputDir, namespace, kind, id, "application/json", data)
}

func writeBytesReceiptArtifact(t *testing.T, outputDir string, namespace string, kind string, id string, mediaType string, data []byte) contracts.ArtifactRef {
	t.Helper()
	sum := digest.RawBytes(data)
	path := filepath.Join(outputDir, "artifacts", namespace, "sha256", strings.TrimPrefix(sum, digest.Prefix))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return contracts.ArtifactRef{
		Kind:          kind,
		ID:            id,
		Digest:        sum,
		DigestProfile: digest.Profile,
		MediaType:     mediaType,
	}
}

func writeReceiptFile(t *testing.T, outputDir string, receipt contracts.ExecutionReceipt) {
	t.Helper()
	data, err := contracts.ExecutionReceiptCanonicalBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(outputDir, "receipts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, receipt.ReceiptID+".json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func survivedVerdict(t *testing.T, finding contracts.Finding) contracts.WitnessVerdict {
	t.Helper()
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.WitnessVerdict{
		FindingID:     finding.ID,
		WitnessDigest: witnessDigest,
		Verdict:       contracts.VerdictSurvived,
		VerdictClass:  nil,
	}
}

func counterVerdict(t *testing.T, finding contracts.Finding, verdict string) contracts.WitnessVerdict {
	t.Helper()
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	class := contracts.VerdictClassLogic
	return contracts.WitnessVerdict{
		FindingID:     finding.ID,
		WitnessDigest: witnessDigest,
		Verdict:       verdict,
		VerdictClass:  &class,
		CounterWitness: &contracts.CounterWitness{
			Summary:  "Counter witness",
			Evidence: "The filed premise only partially holds.",
		},
	}
}

func manifestWithVerdicts(t *testing.T, frozen charter.FrozenCharter, artifactDigest string, verdicts []contracts.WitnessVerdict, receipts []contracts.ExecutionReceiptManifestRecord) contracts.VerificationManifest {
	t.Helper()
	relayVerdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       "batch-1",
		Verdicts:      verdicts,
	}
	resultDigest, err := contracts.RelayWitnessVerdictsDigest(relayVerdicts)
	if err != nil {
		t.Fatal(err)
	}
	batchRef := testArtifactRef("verification-batch", "batch-1", "batch")
	exportRef := testArtifactRef("relay-root-portable-export", "batch-1", "export")
	return contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV4,
		PlanDigest:            testDigest("plan"),
		CharterHash:           frozen.CharterHash,
		ArtifactDigest:        artifactDigest,
		CompatibilityManifest: testArtifactRef("compatibility-manifest", "compatibility", "compatibility"),
		RelayCapabilities:     testArtifactRef("relay-capabilities", "capabilities", "capabilities"),
		IntegrationBundle:     testArtifactRef("integration-bundle", "bundle", "bundle"),
		SelectedContracts:     []contracts.ArtifactRef{testArtifactRef("selected-contract", "contract", "contract")},
		Batches: []contracts.VerificationManifestBatch{{
			BatchID:               "batch-1",
			Status:                contracts.RecordStatusValid,
			BatchRef:              batchRef,
			BatchDigest:           batchRef.Digest,
			PortableExportRef:     &exportRef,
			PortableExportDigest:  exportRef.Digest,
			CanonicalResultDigest: resultDigest,
			RelayVerdicts:         &relayVerdicts,
		}},
		ExecutionReceipts: receipts,
		ConsumerIdentity:  map[string]any{"kind": "test", "id": "consumer"},
	}
}

func manifestWithDuplicateRelayBatches(t *testing.T, frozen charter.FrozenCharter, artifactDigest string, finding contracts.Finding) contracts.VerificationManifest {
	t.Helper()
	return contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV4,
		PlanDigest:            testDigest("plan"),
		CharterHash:           frozen.CharterHash,
		ArtifactDigest:        artifactDigest,
		CompatibilityManifest: testArtifactRef("compatibility-manifest", "compatibility", "compatibility"),
		RelayCapabilities:     testArtifactRef("relay-capabilities", "capabilities", "capabilities"),
		IntegrationBundle:     testArtifactRef("integration-bundle", "bundle", "bundle"),
		SelectedContracts:     []contracts.ArtifactRef{testArtifactRef("selected-contract", "contract", "contract")},
		Batches: []contracts.VerificationManifestBatch{
			manifestBatchWithVerdicts(t, "batch-b", []contracts.WitnessVerdict{survivedVerdict(t, finding)}),
			manifestBatchWithVerdicts(t, "batch-a", []contracts.WitnessVerdict{counterVerdict(t, finding, contracts.VerdictBroken)}),
		},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
			"witness_relay_batches": map[string]any{
				"batch-a": map[string]any{
					"recipe_family": "witness-falsify-v2",
					"backend":       "codex",
					"finding_ids":   []string{finding.ID},
				},
				"batch-b": map[string]any{
					"recipe_family": "witness-falsify-v2",
					"backend":       "claude",
					"finding_ids":   []string{finding.ID},
				},
			},
		},
	}
}

func manifestBatchWithVerdicts(t *testing.T, batchID string, verdicts []contracts.WitnessVerdict) contracts.VerificationManifestBatch {
	t.Helper()
	relayVerdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batchID,
		Verdicts:      verdicts,
	}
	resultDigest, err := contracts.RelayWitnessVerdictsDigest(relayVerdicts)
	if err != nil {
		t.Fatal(err)
	}
	batchRef := testArtifactRef("verification-batch", batchID, "batch-"+batchID)
	exportRef := testArtifactRef("relay-root-portable-export", batchID, "export-"+batchID)
	return contracts.VerificationManifestBatch{
		BatchID:               batchID,
		Status:                contracts.RecordStatusValid,
		BatchRef:              batchRef,
		BatchDigest:           batchRef.Digest,
		PortableExportRef:     &exportRef,
		PortableExportDigest:  exportRef.Digest,
		CanonicalResultDigest: resultDigest,
		RelayVerdicts:         &relayVerdicts,
	}
}

func manifestWithRelayStatus(frozen charter.FrozenCharter, artifactDigest string, status string, failureReason string) contracts.VerificationManifest {
	batchRef := testArtifactRef("verification-batch", "batch-1", "batch")
	return contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV4,
		PlanDigest:            testDigest("plan"),
		CharterHash:           frozen.CharterHash,
		ArtifactDigest:        artifactDigest,
		CompatibilityManifest: testArtifactRef("compatibility-manifest", "compatibility", "compatibility"),
		RelayCapabilities:     testArtifactRef("relay-capabilities", "capabilities", "capabilities"),
		IntegrationBundle:     testArtifactRef("integration-bundle", "bundle", "bundle"),
		SelectedContracts:     []contracts.ArtifactRef{testArtifactRef("selected-contract", "contract", "contract")},
		Batches: []contracts.VerificationManifestBatch{{
			BatchID:       "batch-1",
			Status:        status,
			BatchRef:      batchRef,
			BatchDigest:   batchRef.Digest,
			FailureReason: failureReason,
		}},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
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

func assertDisposition(t *testing.T, finding FindingVerdict, want string) {
	t.Helper()
	if finding.Disposition != want {
		t.Fatalf("%s disposition = %s, want %s; finding=%#v", finding.FindingID, finding.Disposition, want, finding)
	}
}

func assertApplicationClass(t *testing.T, finding FindingVerdict, want string) {
	t.Helper()
	if finding.ApplicationClass != want {
		t.Fatalf("%s application_class = %s, want %s; finding=%#v", finding.FindingID, finding.ApplicationClass, want, finding)
	}
}

func assertSeverity(t *testing.T, finding FindingVerdict, want string) {
	t.Helper()
	if finding.EffectiveSeverity != want {
		t.Fatalf("%s effective_severity = %s, want %s; finding=%#v", finding.FindingID, finding.EffectiveSeverity, want, finding)
	}
}

func assertHasReason(t *testing.T, finding FindingVerdict, reason string) {
	t.Helper()
	for _, got := range finding.Reasons {
		if got == reason {
			return
		}
	}
	t.Fatalf("%s reasons = %#v, missing %s", finding.FindingID, finding.Reasons, reason)
}

func assertMissingReason(t *testing.T, finding FindingVerdict, reason string) {
	t.Helper()
	for _, got := range finding.Reasons {
		if got == reason {
			t.Fatalf("%s reasons = %#v, unexpectedly found %s", finding.FindingID, finding.Reasons, reason)
		}
	}
}

func assertStrengthStep(t *testing.T, finding FindingVerdict, step string, strength string) {
	t.Helper()
	for _, got := range finding.StrengthTrajectory {
		if got.Step == step && got.Strength == strength {
			return
		}
	}
	t.Fatalf("%s strength trajectory = %#v, missing %s/%s", finding.FindingID, finding.StrengthTrajectory, step, strength)
}

func findingsByID(result *Result) map[string]FindingVerdict {
	byID := map[string]FindingVerdict{}
	for _, finding := range result.Findings {
		byID[finding.FindingID] = finding
	}
	return byID
}

func assertResultHasDiagnostic(t *testing.T, result *Result, code string, path string) {
	t.Helper()
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, missing %s at %s", result.Diagnostics, code, path)
}

func assertErrorHasDiagnostic(t *testing.T, err error, code string, path string) {
	t.Helper()
	validationErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error = %T %[1]v, want *ValidationError", err)
	}
	for _, diagnostic := range validationErr.Diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, missing %s at %s", validationErr.Diagnostics, code, path)
}
