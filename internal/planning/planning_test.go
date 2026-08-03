package planning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"witness/internal/changesurface"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
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
		Policy:        planningDeltaPolicy(),
		Preflight:     PreflightBinding{SnapshotDigest: headDigest},
		ChangeSurface: ChangeSurfaceInput{BaseManifest: &baseManifest, HeadManifest: &headManifest},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Plan.ScopePolicy != contracts.ScopePolicyDeltaObligating || result.Plan.ChangeSurface == nil || result.Plan.ChangeSurfaceDigest == "" {
		t.Fatalf("plan change surface fields = %#v", result.Plan)
	}
	if len(result.Plan.Batches) != 1 || fmt.Sprint(result.Plan.Batches[0].FindingIDs) != fmt.Sprint([]string{"deleted", "in-delta"}) {
		t.Fatalf("planned batches = %#v, want deleted and in-delta", result.Plan.Batches)
	}
	if len(result.Plan.ExcludedFindings) != 1 {
		t.Fatalf("excluded findings = %#v, want one out-of-delta", result.Plan.ExcludedFindings)
	}
	excluded := result.Plan.ExcludedFindings[0]
	if excluded.FindingID != "out-of-delta" || excluded.Disposition != DispositionAdvisory || excluded.ApplicationClass != contracts.ApplicationClassCallerDecision || excluded.Reason != contracts.ReasonOutOfDelta {
		t.Fatalf("excluded finding = %#v, want out_of_delta advisory caller decision", excluded)
	}
	if result.ManifestSkeleton.ChangeSurfaceDigest != result.Plan.ChangeSurfaceDigest || len(result.ManifestSkeleton.ExcludedFindings) != 1 {
		t.Fatalf("manifest skeleton = %#v, want change surface digest and excluded finding", result.ManifestSkeleton)
	}
}

func TestPlanningDeltaFailsClosedWithoutDerivedSurfaceOrBaseline(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Policy:        planningDeltaPolicy(),
	})
	if planningErrorCode(err) != CodeMissingChangeSurface {
		t.Fatalf("err = %v, want %s", err, CodeMissingChangeSurface)
	}
}

func TestPlanningDeltaBaselinePassProceedsWholeTreeWithVisibleMarker(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	result, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Policy:        planningDeltaPolicy(),
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

func TestPlanningChangeSurfaceRejectsPartialManifestInput(t *testing.T) {
	frozen := planningTestFrozenCharter(t)
	_, headManifest, _ := planningDeltaManifests(t)
	roleOutput := planningTestRoleOutput(frozen, contracts.RoleDefect, []contracts.Finding{
		planningTestFinding("finding-1", contracts.SeverityHigh, contracts.WitnessStrengthConstructed),
	})
	_, err := Run(Options{
		FrozenCharter: frozen,
		RoleOutputs:   []RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Policy:        planningDeltaPolicy(),
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
		Policy:        planningDeltaPolicy(),
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

func TestPlanningWholeTreeAndAbsentPolicyRemainUnchanged(t *testing.T) {
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
	if len(result.Plan.Batches) != 1 || result.Plan.ChangeSurface != nil || result.Plan.BaselinePass != nil || result.Plan.ScopePolicy != contracts.ScopePolicyWholeTree {
		t.Fatalf("plan = %#v, want existing whole-tree behavior", result.Plan)
	}
}

func TestVersionStampsForPlanManifestRulesPolicyAndChangeSurface(t *testing.T) {
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
	if SchemaVersion != "witness-verification-plan-v2" {
		t.Fatalf("planning SchemaVersion = %s, want witness-verification-plan-v2", SchemaVersion)
	}
	rules := contracts.DefaultReviewRules()
	if rules.SchemaVersion != contracts.ReviewRulesV3 || rules.RulesID != "default-review-rules-v3" {
		t.Fatalf("default rules = %#v, want review-rules-v3/default-review-rules-v3", rules)
	}
	policy := contracts.DefaultReviewPolicy()
	if policy.SchemaVersion != contracts.ReviewPolicyV3 || policy.PolicyID != "bootstrap-review-policy-v3" || policy.ScopePolicy != contracts.ScopePolicyWholeTree {
		t.Fatalf("default policy = %#v, want review-policy-v3 whole_tree", policy)
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
	if assembled.Manifest.SchemaVersion != contracts.VerificationManifestV4 {
		t.Fatalf("manifest schema_version = %s, want %s", assembled.Manifest.SchemaVersion, contracts.VerificationManifestV4)
	}
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
	emptyDigest.ArtifactDigest = ""
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

func planningDeltaPolicy() contracts.ReviewPolicy {
	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "delta-policy"
	policy.ScopePolicy = contracts.ScopePolicyDeltaObligating
	return policy
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
		Size:   int64(len(content)),
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
