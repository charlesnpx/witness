package pass

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/harness"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/metrics"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/preflight"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestDriverWalkAdvancesOneStagePerInvocation(t *testing.T) {
	options := newBeginOptions(t)

	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	assertInvocation(t, invocation, stageFreeze, actionWitnessCommand, false)

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	assertInvocation(t, invocation, stagePreflight, actionCallerRoleOutputs, false)
	writeRoleOutputsForState(t, options.StateDir, false)

	for _, step := range []struct {
		stage    string
		complete bool
	}{
		{stage: stagePlan},
		{stage: stageAssemble},
		{stage: stageAdjudicate},
		{stage: stageMetrics, complete: true},
	} {
		invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
		if err != nil {
			t.Fatalf("resume %s: %v", step.stage, err)
		}
		wantAction := actionWitnessCommand
		if step.complete {
			wantAction = actionComplete
		}
		assertInvocation(t, invocation, step.stage, wantAction, step.complete)
	}

	state := readPassStateForTest(t, options.StateDir)
	if !state.Complete {
		t.Fatal("final pass state is not complete")
	}
	for _, stage := range orderedStages {
		if !stageComplete(state, stage) {
			t.Fatalf("stage %s not complete in final state", stage)
		}
	}
	if state.NextAction.Type != actionComplete {
		t.Fatalf("next action = %s, want complete", state.NextAction.Type)
	}
}

func TestDriverDriftFailsClosed(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := os.WriteFile(options.CharterPath, []byte(`{"schema_version":"review-charter-v2","goals":[],"non_goals":[],"owner_events":[{"id":"changed","type":"charter_initialized","actor":"owner","summary":"changed"}]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume succeeded after mutating a recorded input")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want ValidationError", err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != CodeStateDrift {
		t.Fatalf("diagnostics = %#v, want %s", validation.Diagnostics, CodeStateDrift)
	}
	if _, err := os.Stat(filepath.Join(options.StateDir, "preflight.json")); !os.IsNotExist(err) {
		t.Fatalf("preflight stage was run after drift: %v", err)
	}
}

func TestBeginResumeRejectsStateIdentityMismatch(t *testing.T) {
	t.Run("begin config mismatch", func(t *testing.T) {
		options := newBeginOptions(t)
		if _, err := Begin(context.Background(), options); err != nil {
			t.Fatalf("begin: %v", err)
		}
		changedSource := filepath.Join(filepath.Dir(options.StateDir), "changed-source")
		if err := os.MkdirAll(changedSource, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(changedSource, "app.txt"), []byte("changed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		changed := options
		changed.SourceDir = changedSource

		_, err := Begin(context.Background(), changed)
		if err == nil {
			t.Fatal("begin accepted an existing state with a different source_dir")
		}
		assertValidationCode(t, err, CodePassStateConfigMismatch)
		assertValidationDetailPath(t, err, "mismatched_field_paths", "/config/source_dir")
	})

	t.Run("copied state file", func(t *testing.T) {
		options := newBeginOptions(t)
		if _, err := Begin(context.Background(), options); err != nil {
			t.Fatalf("begin: %v", err)
		}
		copiedDir := filepath.Join(filepath.Dir(options.StateDir), "copied-pass")
		if err := os.MkdirAll(copiedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		stateBytes, err := os.ReadFile(filepath.Join(options.StateDir, StateFileName))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(copiedDir, StateFileName), stateBytes, 0o644); err != nil {
			t.Fatal(err)
		}

		_, err = Resume(context.Background(), ResumeOptions{StateDir: copiedDir})
		if err == nil {
			t.Fatal("resume accepted a pass state copied into a different directory")
		}
		assertValidationCode(t, err, CodeStateInvalid)
	})
}

func TestResumeRejectsV1PassStateSchema(t *testing.T) {
	stateDir := t.TempDir()
	writeCanonicalForTest(t, filepath.Join(stateDir, StateFileName), State{
		SchemaVersion: "witness-pass-state-v1",
		DigestProfile: digest.Profile,
		StateDigest:   digest.Prefix + strings.Repeat("0", 64),
	})

	_, err := Resume(context.Background(), ResumeOptions{StateDir: stateDir})
	if err == nil {
		t.Fatal("resume accepted a v1 pass state")
	}
	assertValidationCode(t, err, CodeStateUnsupported)

	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) == 0 {
		t.Fatalf("error = %T, want ValidationError with diagnostics: %v", err, err)
	}
	details := validation.Diagnostics[0].Details
	if details["actual"] != "witness-pass-state-v1" || details["expected"] != StateSchemaVersion {
		t.Fatalf("schema diagnostic details = %#v, want actual v1 and expected %s", details, StateSchemaVersion)
	}
}

func TestResumeRejectsExplicitHeadManifestSnapshotMismatch(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	basePath := filepath.Join(root, "base-manifest.json")
	headPath := filepath.Join(root, "head-manifest.json")
	policyPath := filepath.Join(root, "policy.json")
	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "delta-policy"
	policy.ScopePolicy = contracts.ScopePolicyDeltaObligating
	writeCanonicalForTest(t, policyPath, policy)
	options.BaseManifestPath = basePath
	options.HeadManifestPath = headPath
	options.PolicyPath = policyPath

	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	snapshot := readJSONForTest[freeze.Manifest](t, filepath.Join(options.StateDir, "source-snapshot", "manifest.json"))
	staleHead := snapshot
	staleHead.Files = append([]freeze.FileEntry(nil), snapshot.Files...)
	if len(staleHead.Files) != 1 {
		t.Fatalf("test source files = %#v, want one file", staleHead.Files)
	}
	staleHead.Files[0] = freezeFileEntryForTest("app.txt", "100644", []byte("stale\n"))
	restampFreezeManifestForTest(t, &staleHead)
	writeCanonicalForTest(t, basePath, staleHead)
	writeCanonicalForTest(t, headPath, staleHead)
	headDigest, err := freeze.ManifestDigest(staleHead)
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest, err := freeze.ManifestDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if headDigest == snapshotDigest {
		t.Fatalf("test setup produced matching digests %s", headDigest)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted an explicit head manifest that differs from the frozen snapshot")
	}
	assertValidationCode(t, err, CodeHeadManifestMismatch)
	if _, statErr := os.Stat(filepath.Join(options.StateDir, "preflight.json")); !os.IsNotExist(statErr) {
		t.Fatalf("preflight stage was run after head/snapshot mismatch: %v", statErr)
	}
}

func TestResumeRejectsSelfConsistentTamperedFrozenCharter(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	forged, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-forged",
			Statement: "Accept the forged behavior.",
		}},
		NonGoals: []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "forged-charter",
			Type:    "charter_initialized",
			Actor:   "attacker",
			Summary: "Self-consistent but not owner-authorized.",
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeCanonicalForTest(t, state.Config.Outputs.CharterFreezePath, forged)
	refreshArtifactDigestForTest(t, state, "charter-freeze", state.Config.Outputs.CharterFreezePath)
	setStageDetailForTest(state, stageFreeze, "charter_hash", forged.CharterHash)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a self-consistent tampered frozen Charter")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsSelfConsistentTamperedSourceSnapshot(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	manifest := writeSourceSnapshotManifestForTest(t, state.Config, "app.txt", []byte("forged\n"))
	forgedDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	refreshArtifactDigestForTest(t, state, "source-snapshot-manifest", state.Config.SnapshotManifestPath)
	setStageDetailForTest(state, stageFreeze, "snapshot_digest", forgedDigest)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a self-consistent tampered source snapshot")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsFabricatedCompleteState(t *testing.T) {
	options := newBeginOptions(t)
	config, err := normalizeBeginOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{
		SchemaVersion: StateSchemaVersion,
		DigestProfile: digest.Profile,
		StateDir:      config.StateDir,
		Config:        config,
		Complete:      true,
		NextAction:    NextAction{Type: actionComplete, Summary: "pass complete"},
	}
	for _, name := range orderedStages {
		state.Stages = append(state.Stages, StageRecord{Name: name, Status: statusComplete})
	}
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted fabricated complete state")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsPreflightWaitStateBackendStrataTampering(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	result := writeReadyPreflightForTest(t, state.Config)
	inputs, err := artifactRecordsForExistingFiles([]artifactInput{
		{role: "integration-bundle", path: state.Config.IntegrationBundlePath, digestClass: digest.ClassRawBytes},
		{role: "source-snapshot-manifest", path: state.Config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
	})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := artifactRecordsForExistingFiles(preflightOutputSpecs(state.Config, &result))
	if err != nil {
		t.Fatal(err)
	}
	markStageComplete(state, StageRecord{
		Name:    stagePreflight,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"relay_absent":   false,
			"backend_strata": cloneStringMap(result.BackendStrata),
		},
	})
	if err := setNextAction(state); err != nil {
		t.Fatal(err)
	}
	if state.NextAction.Type != actionCallerRoleOutputs {
		t.Fatalf("next action = %s, want role-output wait state", state.NextAction.Type)
	}

	result.BackendStrata = map[string]string{
		"claude": contracts.RelayLaunchStatusAbsent,
		"codex":  contracts.RelayLaunchStatusAbsent,
	}
	writeCanonicalForTest(t, state.Config.Outputs.PreflightPath, result)
	refreshArtifactDigestForTest(t, state, "preflight", state.Config.Outputs.PreflightPath)
	setStageDetailForTest(state, stagePreflight, "relay_absent", true)
	setStageDetailForTest(state, stagePreflight, "backend_strata", cloneStringMap(result.BackendStrata))
	state.NextAction.Degraded = true
	state.NextAction.BackendStrata = cloneStringMap(result.BackendStrata)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted tampered preflight backend strata in the role-output wait state")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsSelfConsistentTamperedChangeSurface(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	basePath := filepath.Join(root, "base-manifest.json")
	headPath := filepath.Join(root, "head-manifest.json")
	policyPath := filepath.Join(root, "policy.json")
	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "delta-policy"
	policy.ScopePolicy = contracts.ScopePolicyDeltaObligating
	writeCanonicalForTest(t, policyPath, policy)
	options.BaseManifestPath = basePath
	options.HeadManifestPath = headPath
	options.PolicyPath = policyPath

	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	headManifest := readJSONForTest[freeze.Manifest](t, state.Config.SnapshotManifestPath)
	baseManifest := headManifest
	baseManifest.Files = append([]freeze.FileEntry(nil), headManifest.Files...)
	if len(baseManifest.Files) != 1 {
		t.Fatalf("test source files = %#v, want one file", baseManifest.Files)
	}
	baseManifest.Files[0] = freezeFileEntryForTest("app.txt", "100644", []byte("before\n"))
	restampFreezeManifestForTest(t, &baseManifest)
	writeCanonicalForTest(t, basePath, baseManifest)
	writeCanonicalForTest(t, headPath, headManifest)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForStateWithScopeAnchor(t, options.StateDir, "app.txt")
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state = readPassStateForTest(t, options.StateDir)
	surfacePath := filepath.Join(state.Config.StateDir, "verification", "change-surface.json")
	surface := readJSONForTest[changesurface.Document](t, surfacePath)
	if len(surface.ChangedPaths) == 0 {
		t.Fatal("plan produced no changed paths")
	}
	surface.ChangedPaths[0].Path = "forged.go"
	writeCanonicalForTest(t, surfacePath, surface)
	refreshArtifactDigestForTest(t, state, "change-surface", surfacePath)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a self-consistent tampered change surface")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestCallerRoleOutputsDeltaActionCarriesEarlyChangeSurface(t *testing.T) {
	options, invocation, baseManifest, headManifest := beginDeltaRoleOutputWaitForTest(t)
	action := invocation.NextAction
	if invocation.SchemaVersion != InvocationSchemaVersion {
		t.Fatalf("schema_version = %s, want %s", invocation.SchemaVersion, InvocationSchemaVersion)
	}
	if action.ScopePolicy != contracts.ScopePolicyDeltaObligating {
		t.Fatalf("scope_policy = %s, want %s", action.ScopePolicy, contracts.ScopePolicyDeltaObligating)
	}
	if action.ChangeSurfacePath == "" || !filepath.IsAbs(action.ChangeSurfacePath) {
		t.Fatalf("change_surface_path = %q, want absolute path", action.ChangeSurfacePath)
	}
	if action.ChangeSurfaceDigest == "" {
		t.Fatal("change_surface_digest is empty")
	}
	earlySurface := readJSONForTest[changesurface.Document](t, action.ChangeSurfacePath)
	earlyDigest, err := changesurface.Digest(earlySurface)
	if err != nil {
		t.Fatal(err)
	}
	if action.ChangeSurfaceDigest != earlyDigest {
		t.Fatalf("action change_surface_digest = %s, want persisted digest %s", action.ChangeSurfaceDigest, earlyDigest)
	}

	writeRoleOutputsForStateWithScopeAnchor(t, options.StateDir, "app.txt")
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	plan := readJSONForTest[planning.PlanDocument](t, state.Config.Outputs.PlanPath)
	if plan.ChangeSurface == nil {
		t.Fatal("plan did not derive a change surface")
	}
	derivedSurface, derivedDigest, err := changesurface.Derive(baseManifest, headManifest, plan.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	if action.ChangeSurfaceDigest != derivedDigest || plan.ChangeSurfaceDigest != derivedDigest {
		t.Fatalf("change surface digests action=%s plan=%s derived=%s", action.ChangeSurfaceDigest, plan.ChangeSurfaceDigest, derivedDigest)
	}
	if err := requireSemanticMatch("early change surface", earlySurface, derivedSurface); err != nil {
		t.Fatal(err)
	}
	if err := requireSemanticMatch("plan change surface", *plan.ChangeSurface, derivedSurface); err != nil {
		t.Fatal(err)
	}
}

func TestCallerRoleOutputsWholeTreeActionOmitsChangeSurface(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	action := invocation.NextAction
	if action.ScopePolicy != contracts.ScopePolicyWholeTree {
		t.Fatalf("scope_policy = %s, want %s", action.ScopePolicy, contracts.ScopePolicyWholeTree)
	}
	if action.ChangeSurfacePath != "" || action.ChangeSurfaceDigest != "" {
		t.Fatalf("whole-tree action carried change surface fields: %#v", action)
	}
	state := readPassStateForTest(t, options.StateDir)
	if _, err := os.Stat(roleOutputChangeSurfacePath(state.Config)); !os.IsNotExist(err) {
		t.Fatalf("whole-tree pass wrote early change surface: %v", err)
	}
}

func TestResumeRejectsTamperedEarlyRoleOutputChangeSurface(t *testing.T) {
	options, invocation, _, _ := beginDeltaRoleOutputWaitForTest(t)
	surfacePath := invocation.NextAction.ChangeSurfacePath
	surface := readJSONForTest[changesurface.Document](t, surfacePath)
	if len(surface.ChangedPaths) == 0 {
		t.Fatal("early change surface has no changed paths")
	}
	surface.ChangedPaths[0].Path = "forged.go"
	writeCanonicalForTest(t, surfacePath, surface)
	state := readPassStateForTest(t, options.StateDir)
	refreshArtifactDigestForTest(t, state, roleOutputChangeSurfaceRole, surfacePath)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a self-consistent tampered early change surface")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsSelfConsistentTamperedAdjudicationResult(t *testing.T) {
	options := newBeginOptions(t)
	runPassToCompletion(t, options, true)
	state := readPassStateForTest(t, options.StateDir)
	resultPath := state.Config.Outputs.RunResultPath
	result := readJSONForTest[adjudicate.Result](t, resultPath)
	if len(result.Findings) == 0 {
		t.Fatal("test pass produced no adjudication findings")
	}
	result.Findings[0].Disposition = contracts.DispositionAdvisory
	result.Findings[0].ApplicationClass = contracts.ApplicationClassCallerDecision
	result.Findings[0].Reasons = []string{"tampered"}
	result.Summary = adjudicationSummaryForTest(result.Findings)
	result.ResultDigest = ""
	resultDigest, err := adjudicationResultDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	result.ResultDigest = resultDigest
	writeCanonicalForTest(t, resultPath, result)

	metricsDocument, err := metrics.Run(metrics.Options{
		LedgerPath:     state.Config.LedgerPath,
		PreflightPath:  state.Config.Outputs.PreflightPath,
		RunResultPaths: []string{resultPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(state.Config.Outputs.MetricsPath, metricsDocument); err != nil {
		t.Fatal(err)
	}
	refreshArtifactDigestForTest(t, state, "run-result", state.Config.Outputs.RunResultPath)
	refreshArtifactDigestForTest(t, state, "metrics", state.Config.Outputs.MetricsPath)
	for index := range state.Stages {
		if state.Stages[index].Name == stageAdjudicate {
			state.Stages[index].Details["result_digest"] = result.ResultDigest
		}
	}
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a self-consistent tampered adjudication result")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsForgedRelayBatchActionFields(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	if len(state.RelayBatches) == 0 {
		t.Fatal("plan produced no relay batches")
	}
	state.RelayBatches[0].RecipeID = "attacker-recipe"
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted forged relay batch action fields")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestResumeRejectsSurplusVerificationBatchOutput(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	plan := readJSONForTest[planning.PlanDocument](t, state.Config.Outputs.PlanPath)
	if len(plan.Batches) == 0 {
		t.Fatal("plan produced no verification batches")
	}
	sourcePath := filepath.Join(state.Config.StateDir, "verification", "batches", plan.Batches[0].BatchID+".json")
	forged := readJSONForTest[contracts.VerificationBatchDocument](t, sourcePath)
	forged.BatchID = "forged"
	forgedPath := filepath.Join(state.Config.StateDir, "verification", "batches", "forged.json")
	writeCanonicalForTest(t, forgedPath, forged)
	forgedDigest, err := computeArtifactDigest(forgedPath, digest.ClassRawBytes)
	if err != nil {
		t.Fatal(err)
	}
	added := false
	for index := range state.Stages {
		if state.Stages[index].Name != stagePlan {
			continue
		}
		state.Stages[index].Outputs = append(state.Stages[index].Outputs, ArtifactRecord{
			Role:        "verification-batch:forged",
			Path:        forgedPath,
			Digest:      forgedDigest,
			DigestClass: digest.ClassRawBytes,
		})
		added = true
	}
	if !added {
		t.Fatal("plan stage not found")
	}
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a surplus forged verification batch output")
	}
	assertValidationCode(t, err, CodeStateInvalid)
}

func TestBeginRejectsConfiguredInputInsideStateDirBeforeWrite(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "pass")
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "app.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	charterPath := filepath.Join(stateDir, "charter.json")
	writeCanonicalForTest(t, charterPath, charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals:         []charter.Statement{{ID: "goal-1", Statement: "Preserve behavior."}},
		NonGoals:      []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "initial-charter",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial owner-authorized charter.",
		}},
	})
	before, err := os.ReadFile(charterPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Begin(context.Background(), BeginOptions{
		StateDir:              stateDir,
		CharterPath:           charterPath,
		SourceDir:             sourceDir,
		AllowNonGitSource:     true,
		RelayPath:             filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath: filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json"),
	})
	if err == nil {
		t.Fatal("begin accepted charter inside state-dir")
	}
	if got := diagCode(err); got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
	after, err := os.ReadFile(charterPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("charter changed before alias rejection\nafter: %s\nwant:  %s", after, before)
	}
	for _, path := range []string{
		filepath.Join(stateDir, StateFileName),
		filepath.Join(stateDir, "charter.freeze.json"),
		filepath.Join(stateDir, "preflight.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("driver wrote %s before alias rejection: %v", path, err)
		}
	}
}

func TestBeginRejectsReservedRoleOutputAliases(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "pass")
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(stateDir, "source-snapshot"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "role-outputs"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(stateDir, "source-snapshot", "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(stateDir, "role-outputs", "symlink.json")
	if err := os.Symlink(filepath.Join("..", "source-snapshot", "manifest.json"), symlinkPath); err != nil {
		t.Fatal(err)
	}
	hardlinkPath := filepath.Join(stateDir, "role-outputs", "hardlink.json")
	if err := os.Link(manifestPath, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "direct", path: manifestPath},
		{name: "symlink", path: symlinkPath},
		{name: "hardlink", path: hardlinkPath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeBeginOptions(BeginOptions{
				StateDir:              stateDir,
				CharterPath:           filepath.Join(root, "charter.json"),
				SourceDir:             sourceDir,
				AllowNonGitSource:     true,
				RelayPath:             filepath.Join(root, "missing-convo-relay"),
				IntegrationBundlePath: filepath.Join(root, "bundle.json"),
				RoleOutputs:           []RoleOutputSpec{{Role: contracts.RoleDefect, Path: test.path}},
			})
			if err == nil {
				t.Fatalf("normalizeBeginOptions accepted reserved role-output alias %s", test.path)
			}
			if got := diagCode(err); got != charter.CodeOutputPathConflict {
				t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
			}
		})
	}
}

func TestDriverLedgerAppendsSameLineageKindsAsSharedAdjudicationService(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	options.LedgerPath = filepath.Join(root, "driver-ledger.jsonl")
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume assemble: %v", err)
	}
	stateBeforeAdjudicate := readPassStateForTest(t, options.StateDir)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume adjudicate: %v", err)
	}
	driverRecords, err := ledger.ReadFile(options.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}

	serviceLedgerPath := filepath.Join(root, "service-ledger.jsonl")
	frozen, _, err := readFrozenCharter(stateBeforeAdjudicate.Config.Outputs.CharterFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readVerificationManifest(stateBeforeAdjudicate.Config.Outputs.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	changeSurface, err := readChangeSurfaceInput(stateBeforeAdjudicate.Config.BaseManifestPath, stateBeforeAdjudicate.Config.HeadManifestPath, false)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := loadEffectivePolicy(stateBeforeAdjudicate.Config)
	if err != nil {
		t.Fatal(err)
	}
	roleOutputs := make([]adjudicate.RoleOutputInput, 0, len(stateBeforeAdjudicate.Config.RoleOutputs))
	for _, item := range stateBeforeAdjudicate.Config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			t.Fatal(err)
		}
		roleOutputs = append(roleOutputs, adjudicate.RoleOutputInput{Path: item.Path, Document: document})
	}
	service, err := RunAdjudicationService(AdjudicationOptions{
		FrozenCharter:                frozen,
		RoleOutputs:                  roleOutputs,
		Manifest:                     manifest,
		BaseManifest:                 changeSurface.BaseManifest,
		HeadManifest:                 changeSurface.HeadManifest,
		LedgerPath:                   serviceLedgerPath,
		Rules:                        effective.Rules,
		Policy:                       effective.Policy,
		PolicyCapReleaseLedgerBacked: effective.CapRelease != nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.RunErr != nil {
		t.Fatal(service.RunErr)
	}
	serviceRecords, err := ledger.ReadFile(serviceLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	assertLedgerLineageEqual(t, driverRecords, serviceRecords)
}

func TestDriverResumeAfterDurableLedgerAppendIsIdempotent(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	options.LedgerPath = filepath.Join(root, "ledger.jsonl")
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume assemble: %v", err)
	}
	stateBeforeAdjudicate := readPassStateForTest(t, options.StateDir)
	service, err := runAdjudicationServiceForState(t, stateBeforeAdjudicate, options.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if service.RunErr != nil {
		t.Fatal(service.RunErr)
	}
	recordsBefore, err := ledger.ReadFile(options.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume adjudicate after durable append: %v", err)
	}
	if invocation.StageRun != stageAdjudicate {
		t.Fatalf("stage_run = %s, want %s", invocation.StageRun, stageAdjudicate)
	}
	recordsAfter, err := ledger.ReadFile(options.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	assertLedgerLineageEqual(t, recordsAfter, recordsBefore)
}

func TestDriverAtomicPersistenceRecovery(t *testing.T) {
	t.Run("partial lineage prefix", func(t *testing.T) {
		options := newBeginOptions(t)
		options.LedgerPath = filepath.Join(filepath.Dir(options.StateDir), "ledger.jsonl")
		if _, err := Begin(context.Background(), options); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
			t.Fatalf("resume preflight: %v", err)
		}
		writeRoleOutputsForState(t, options.StateDir, true)
		if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
			t.Fatalf("resume plan: %v", err)
		}
		if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
			t.Fatalf("resume assemble: %v", err)
		}
		stateBeforeAdjudicate := readPassStateForTest(t, options.StateDir)
		service, err := runAdjudicationServiceForState(t, stateBeforeAdjudicate, "")
		if err != nil {
			t.Fatal(err)
		}
		if service.RunErr != nil {
			t.Fatal(service.RunErr)
		}
		frozen, _, err := readFrozenCharter(stateBeforeAdjudicate.Config.Outputs.CharterFreezePath)
		if err != nil {
			t.Fatal(err)
		}
		events := AdjudicationLedgerEvents(service.Result, adjudicationRoleOutputsForState(t, stateBeforeAdjudicate), frozen)
		if len(events) < 2 {
			t.Fatalf("lineage event count = %d, want at least two", len(events))
		}
		if _, err := ledger.AppendEvents(options.LedgerPath, events[:1]); err != nil {
			t.Fatalf("write partial lineage prefix: %v", err)
		}

		invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
		if err != nil {
			t.Fatalf("resume adjudicate after partial lineage prefix: %v", err)
		}
		if invocation.StageRun != stageAdjudicate {
			t.Fatalf("stage_run = %s, want %s", invocation.StageRun, stageAdjudicate)
		}
		records, err := ledger.ReadFile(options.LedgerPath)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := canonicalLineage(events)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != len(expected) {
			t.Fatalf("ledger record count = %d, want %d", len(records), len(expected))
		}
		for index := range expected {
			if !ledgerRecordMatchesExpected(records[index], expected[index]) {
				t.Fatalf("ledger record %d = %s %s, want %s %s", index, records[index].EventKind, records[index].Event, expected[index].kind, expected[index].event)
			}
		}
	})

	t.Run("state rewrite interruption", func(t *testing.T) {
		options := newBeginOptions(t)
		if _, err := Begin(context.Background(), options); err != nil {
			t.Fatalf("begin: %v", err)
		}
		statePath := filepath.Join(options.StateDir, StateFileName)
		before, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected state write interruption")
		original := atomicWriteFile
		atomicWriteFile = func(path string, data []byte, mode os.FileMode) error {
			if filepath.Clean(path) == filepath.Clean(statePath) {
				return injected
			}
			return original(path, data, mode)
		}
		defer func() {
			atomicWriteFile = original
		}()

		_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
		if !errors.Is(err, injected) {
			t.Fatalf("resume error = %v, want injected interruption", err)
		}
		after, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("state file changed after interrupted rewrite\nafter: %s\nwant:  %s", after, before)
		}
		state := readPassStateForTest(t, options.StateDir)
		if len(state.Stages) != 1 || state.Stages[0].Name != stageFreeze {
			t.Fatalf("state stages after interrupted rewrite = %#v, want only freeze", state.Stages)
		}
	})
}

func TestAssembleSupplementaryRelationshipsPersistFullResultOutput(t *testing.T) {
	stateDir := t.TempDir()
	config := Config{StateDir: stateDir}
	applyOutputDefaults(&config)
	result := &planning.AssembleResult{
		Manifest: contracts.VerificationManifest{
			SchemaVersion: contracts.VerificationManifestV4,
			ConsumerIdentity: map[string]any{
				"kind": "test",
				"id":   "pass-test",
			},
		},
		UnverifiedRelationships: []planning.ManifestUnverifiedRelationship{{
			BatchID:        "batch-1",
			Classification: "supplementary",
			Code:           "facilitator_ledger_content_collision",
			Relationship:   "trace_only_facilitator_ledger_prompt_projection",
			Reason:         "supplementary evidence was not required for validity",
		}},
	}
	if err := writeAssembleArtifacts(config, result); err != nil {
		t.Fatal(err)
	}
	outputs, err := artifactRecordsForExistingFiles(assembleOutputSpecs(config, result))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findArtifactRecord(outputs, "assemble-result", assembleResultPath(config)); !ok {
		t.Fatalf("assemble-result output missing from records: %#v", outputs)
	}
	persisted := readJSONForTest[planning.AssembleResult](t, assembleResultPath(config))
	if len(persisted.UnverifiedRelationships) != 1 {
		t.Fatalf("unverified relationships = %#v, want persisted relationship", persisted.UnverifiedRelationships)
	}
}

func TestReceiptKeyMutationAfterAssembleReportsStateDrift(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	options.ReceiptOutputDir = filepath.Join(root, "receipt-output")
	options.ReceiptHMACKeyFile = filepath.Join(root, "receipt.key")
	options.ReceiptPaths = []string{filepath.Join(root, "receipt.json")}
	key := []byte("test-hmac-key")
	if err := os.WriteFile(options.ReceiptHMACKeyFile, key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	plan := readJSONForTest[planning.PlanDocument](t, state.Config.Outputs.PlanPath)
	writePassReceiptFixture(t, options.ReceiptOutputDir, options.ReceiptPaths[0], key, plan, "defect-1")
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume assemble: %v", err)
	}
	state = readPassStateForTest(t, options.StateDir)
	assembleStage := stageRecordForTest(t, state, stageAssemble)
	if !hasArtifactRole(assembleStage.Inputs, "receipt-hmac-key-file") || !hasArtifactRolePrefix(assembleStage.Inputs, "receipt-artifact:") {
		t.Fatalf("assemble inputs did not bind receipt key and artifacts: %#v", assembleStage.Inputs)
	}
	if err := os.WriteFile(options.ReceiptHMACKeyFile, []byte("changed-key"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted mutated receipt key")
	}
	assertValidationCode(t, err, CodeStateDrift)
}

func TestRelayBatchActionCarriesBoundDigestsAndRetainedBundle(t *testing.T) {
	stateDir := t.TempDir()
	config := Config{
		StateDir:              stateDir,
		IntegrationBundlePath: filepath.Join(stateDir, "original-bundle.json"),
		Backend:               "codex",
	}
	applyOutputDefaults(&config)
	integrationDigest := digest.RawBytes([]byte("retained integration bundle"))
	preflightResult := preflight.Result{
		SchemaVersion: preflight.SchemaVersion,
		OK:            true,
		ArtifactDigests: map[string]string{
			"compatibility-manifest.json": digest.RawBytes([]byte("compatibility")),
			"relay-capabilities.json":     digest.RawBytes([]byte("capabilities")),
		},
		ContractDigests: map[string]string{
			"integration_bundle": integrationDigest,
		},
		BackendStrata: map[string]string{"codex": "ready", "claude": "ready"},
	}
	writeCanonicalForTest(t, config.Outputs.PreflightPath, preflightResult)
	charterDigest := digest.RawBytes([]byte("charter"))
	snapshotDigest := digest.RawBytes([]byte("snapshot"))
	batchDigest := digest.RawBytes([]byte("batch"))
	state := &State{
		Config: config,
		Stages: []StageRecord{
			{
				Name:   stageFreeze,
				Status: statusComplete,
				Outputs: []ArtifactRecord{
					{Role: "charter-freeze", Path: config.Outputs.CharterFreezePath, Digest: charterDigest, DigestClass: digest.ClassRawBytes},
					{Role: "source-snapshot-manifest", Path: config.SnapshotManifestPath, Digest: snapshotDigest, DigestClass: digestClassFreezeManifest},
				},
				Details: map[string]any{"snapshot_digest": snapshotDigest},
			},
			{Name: stagePreflight, Status: statusComplete},
			{Name: stagePlan, Status: statusComplete},
		},
	}
	writeCanonicalForTest(t, config.Outputs.PlanPath, planning.PlanDocument{
		Batches: []planning.BatchPlan{{
			BatchID:      "batch-1",
			TaskShape:    contracts.BatchTaskDefect,
			RecipeFamily: "witness-falsify-v2",
			BatchDigest:  batchDigest,
		}},
	})
	action := nextRelayBatchAction(state)
	if action == nil {
		t.Fatal("nextRelayBatchAction returned nil")
	}
	if action.BatchDigest != batchDigest ||
		action.CharterDigest != charterDigest ||
		action.SnapshotDigest != snapshotDigest ||
		action.IntegrationBundleDigest != integrationDigest {
		t.Fatalf("relay batch digests = %#v", action)
	}
	if action.IntegrationBundlePath != retainedIntegrationBundlePath(config) {
		t.Fatalf("integration bundle path = %s, want retained %s", action.IntegrationBundlePath, retainedIntegrationBundlePath(config))
	}
	for _, value := range []string{batchDigest, charterDigest, snapshotDigest, integrationDigest} {
		if !strings.Contains(strings.Join(action.InputBindings, "\n"), value) {
			t.Fatalf("input bindings = %#v, missing digest %s", action.InputBindings, value)
		}
	}
}

func TestRelayAbsentPassSkipsRelayBatchCallerStep(t *testing.T) {
	options := newBeginOptions(t)
	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	assertInvocation(t, invocation, stageFreeze, actionWitnessCommand, false)
	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	if !invocation.Degraded || invocation.BackendStrata["claude"] != contracts.RelayLaunchStatusAbsent || invocation.BackendStrata["codex"] != contracts.RelayLaunchStatusAbsent {
		t.Fatalf("degraded strata = %#v, degraded=%v", invocation.BackendStrata, invocation.Degraded)
	}
	writeRoleOutputsForState(t, options.StateDir, true)

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	if invocation.StageRun != stagePlan {
		t.Fatalf("stage = %s, want plan", invocation.StageRun)
	}
	if invocation.NextAction.Type == actionCallerRelayBatch {
		t.Fatalf("relay-absent plan requested relay batch: %#v", invocation.NextAction)
	}
	if invocation.NextAction.Type != actionWitnessCommand {
		t.Fatalf("next action = %s, want witness command", invocation.NextAction.Type)
	}
	state := readPassStateForTest(t, options.StateDir)
	if len(state.RelayBatches) != 1 || state.RelayBatches[0].Status != statusNotRequired {
		t.Fatalf("relay batches = %#v, want one not-required degraded batch", state.RelayBatches)
	}

	for _, stage := range []string{stageAssemble, stageAdjudicate, stageMetrics} {
		invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
		if err != nil {
			t.Fatalf("resume %s: %v", stage, err)
		}
		if invocation.StageRun != stage {
			t.Fatalf("stage = %s, want %s", invocation.StageRun, stage)
		}
		if invocation.NextAction.Type == actionCallerRelayBatch {
			t.Fatalf("stage %s requested relay in degraded pass", stage)
		}
	}
	result := readJSONForTest[adjudicate.Result](t, filepath.Join(options.StateDir, "verdict.json"))
	if result.Summary.PendingVerification != 1 {
		t.Fatalf("adjudication summary = %#v, want one pending verification", result.Summary)
	}
	metricsDocument := readJSONForTest[map[string]any](t, filepath.Join(options.StateDir, "metrics.json"))
	pending, _ := metricsDocument["pending_verification"].(map[string]any)
	strata, _ := pending["strata"].([]any)
	if len(strata) != 1 {
		t.Fatalf("metrics pending strata = %#v, want one relay_absent stratum", pending["strata"])
	}
	stratum, _ := strata[0].(map[string]any)
	if stratum["backend_auth_status"] != "relay_absent" {
		t.Fatalf("metrics stratum = %#v, want relay_absent", stratum)
	}
}

func TestDriverImportsNoRelayExecutionOrProviderInvocation(t *testing.T) {
	files, err := parser.ParseDir(token.NewFileSet(), ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{
		"github.com/charlesnpx/witness/internal/relayclient": true,
		"github.com/charlesnpx/witness/internal/relayrun":    true,
	}
	for _, pkg := range files {
		for path, file := range pkg.Files {
			for _, imported := range file.Imports {
				value, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if forbidden[value] {
					t.Fatalf("%s imports forbidden relay/provider execution package %s", path, value)
				}
			}
		}
	}
}

func newBeginOptions(t *testing.T) BeginOptions {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "pass")
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "app.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	charterPath := filepath.Join(root, "charter.json")
	writeCanonicalForTest(t, charterPath, charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-1",
			Statement: "Preserve the reviewed behavior.",
		}},
		NonGoals: []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "initial-charter",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial owner-authorized charter.",
		}},
	})
	return BeginOptions{
		StateDir:              stateDir,
		CharterPath:           charterPath,
		SourceDir:             sourceDir,
		AllowNonGitSource:     true,
		RelayPath:             filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath: filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json"),
	}
}

func beginDeltaRoleOutputWaitForTest(t *testing.T) (BeginOptions, *Invocation, freeze.Manifest, freeze.Manifest) {
	t.Helper()
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	basePath := filepath.Join(root, "base-manifest.json")
	policyPath := filepath.Join(root, "policy.json")
	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "delta-policy"
	policy.ScopePolicy = contracts.ScopePolicyDeltaObligating
	writeCanonicalForTest(t, policyPath, policy)
	options.BaseManifestPath = basePath
	options.PolicyPath = policyPath

	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	headManifest := readJSONForTest[freeze.Manifest](t, filepath.Join(options.StateDir, "source-snapshot", "manifest.json"))
	baseManifest := headManifest
	baseManifest.Files = append([]freeze.FileEntry(nil), headManifest.Files...)
	if len(baseManifest.Files) != 1 {
		t.Fatalf("test source files = %#v, want one file", baseManifest.Files)
	}
	baseManifest.Files[0] = freezeFileEntryForTest("app.txt", "100644", []byte("before\n"))
	restampFreezeManifestForTest(t, &baseManifest)
	writeCanonicalForTest(t, basePath, baseManifest)

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	if invocation.NextAction.Type != actionCallerRoleOutputs {
		t.Fatalf("next action = %s, want %s", invocation.NextAction.Type, actionCallerRoleOutputs)
	}
	return options, invocation, baseManifest, headManifest
}

func writeRoleOutputsForState(t *testing.T, stateDir string, withFinding bool) {
	t.Helper()
	state := readPassStateForTest(t, stateDir)
	frozen := readJSONForTest[charter.FrozenCharter](t, state.Config.Outputs.CharterFreezePath)
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	for _, request := range state.Config.RoleOutputs {
		document := contracts.RoleOutputDocument{
			SchemaVersion:    contracts.RoleOutputV3,
			Role:             request.Role,
			CharterHash:      frozen.CharterHash,
			ArtifactDigest:   preflightResult.SnapshotDigest,
			SourceIdentity:   map[string]any{"kind": "test", "id": "source"},
			ConsumerIdentity: map[string]any{"kind": "test", "id": "pass-test"},
			Findings:         []contracts.Finding{},
		}
		if withFinding && request.Role == contracts.RoleDefect {
			document.Findings = []contracts.Finding{{
				ID:              "defect-1",
				Kind:            contracts.FindingKindDefect,
				Title:           "Defect survives only with relay verification",
				CharterGoalIDs:  []string{"goal-1"},
				ClaimedSeverity: contracts.SeverityMedium,
				Witness: contracts.Witness{
					Kind:     contracts.WitnessKindDefect,
					Strength: contracts.WitnessStrengthArgued,
					Content:  "The reviewed behavior can return the wrong value.",
				},
				EstimatedDelta: contracts.SplitDeltaEstimate{
					Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
					Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
				},
				SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
					Direction:          contracts.RemedyDirectionChange,
					Summary:            "Correct the returned value.",
					MinimalityArgument: "One targeted change is sufficient.",
				},
			}}
		}
		writeCanonicalForTest(t, request.Path, document)
	}
}

func writeRoleOutputsForStateWithScopeAnchor(t *testing.T, stateDir string, path string) {
	t.Helper()
	state := readPassStateForTest(t, stateDir)
	frozen := readJSONForTest[charter.FrozenCharter](t, state.Config.Outputs.CharterFreezePath)
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	for _, request := range state.Config.RoleOutputs {
		document := contracts.RoleOutputDocument{
			SchemaVersion:    contracts.RoleOutputV3,
			Role:             request.Role,
			CharterHash:      frozen.CharterHash,
			ArtifactDigest:   preflightResult.SnapshotDigest,
			SourceIdentity:   map[string]any{"kind": "test", "id": "source"},
			ConsumerIdentity: map[string]any{"kind": "test", "id": "pass-test"},
			Findings:         []contracts.Finding{},
		}
		if request.Role == contracts.RoleDefect {
			document.Findings = []contracts.Finding{{
				ID:              "defect-1",
				Kind:            contracts.FindingKindDefect,
				Title:           "Defect in changed file",
				CharterGoalIDs:  []string{"goal-1"},
				ClaimedSeverity: contracts.SeverityMedium,
				ScopeAnchors: []contracts.ScopeAnchor{{
					Dimension: charter.DimensionInputSurface,
					Value:     path,
				}},
				Witness: contracts.Witness{
					Kind:     contracts.WitnessKindDefect,
					Strength: contracts.WitnessStrengthArgued,
					Content:  "The changed file can return the wrong value.",
				},
				EstimatedDelta: contracts.SplitDeltaEstimate{
					Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
					Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1},
				},
				SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
					Direction:          contracts.RemedyDirectionChange,
					Summary:            "Correct the changed file.",
					MinimalityArgument: "One targeted change is sufficient.",
				},
			}}
		}
		writeCanonicalForTest(t, request.Path, document)
	}
}

func writeSourceSnapshotManifestForTest(t *testing.T, config Config, path string, content []byte) freeze.Manifest {
	t.Helper()
	entry := freezeFileEntryForTest(path, "100644", content)
	blobPath := filepath.Join(config.SnapshotDir, filepath.FromSlash(entry.Blob))
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := freeze.Manifest{
		SchemaVersion: freeze.SchemaVersion,
		DigestProfile: digest.Profile,
		Source: freeze.SourceIdentity{
			Path:           config.SourceDir,
			GitTrackedOnly: false,
		},
		Workspace: freeze.WorkspaceIdentity{
			Path:          config.SnapshotDir,
			Format:        freeze.Format,
			BlobDirectory: filepath.Join(config.SnapshotDir, "blobs"),
			ManifestPath:  config.SnapshotManifestPath,
		},
		Files: []freeze.FileEntry{entry},
	}
	restampFreezeManifestForTest(t, &manifest)
	writeCanonicalForTest(t, config.SnapshotManifestPath, manifest)
	return manifest
}

func freezeFileEntryForTest(path string, mode string, content []byte) freeze.FileEntry {
	sum := digest.RawBytes(content)
	return freeze.FileEntry{
		Path:   path,
		Mode:   mode,
		Size:   int64(len(content)),
		Digest: sum,
		Blob:   "blobs/sha256/" + strings.TrimPrefix(sum, digest.Prefix),
	}
}

func restampFreezeManifestForTest(t *testing.T, manifest *freeze.Manifest) {
	t.Helper()
	manifest.Source.ManifestDigest = ""
	manifest.Workspace.ManifestDigest = ""
	manifestDigest, err := freeze.ManifestDigest(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Source.ManifestDigest = manifestDigest
	manifest.Workspace.ManifestDigest = manifestDigest
}

func writeReadyPreflightForTest(t *testing.T, config Config) preflight.Result {
	t.Helper()
	snapshotDigest, err := computeArtifactDigest(config.SnapshotManifestPath, digestClassFreezeManifest)
	if err != nil {
		t.Fatal(err)
	}
	bundlePayload, bundleDigest, err := configuredIntegrationBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	selectedDigests, err := selectedContractDigestsFromBundle(bundlePayload)
	if err != nil {
		t.Fatal(err)
	}
	result := preflight.Result{
		SchemaVersion:        preflight.SchemaVersion,
		OK:                   true,
		StateDir:             config.StateDir,
		RelayVersion:         "v1.4.0",
		ArtifactDigests:      map[string]string{"source-snapshot-manifest": snapshotDigest},
		CompileReportDigests: map[string]string{},
		RecipePlanDigests:    map[string]string{},
		ContractDigests:      map[string]string{"integration_bundle": bundleDigest},
		BackendStrata:        map[string]string{"claude": "ready", "codex": "ready"},
		ConsumerIdentity:     map[string]any{"kind": "witness", "id": "pass-driver"},
	}
	for _, key := range sortedStringMapKeys(selectedDigests) {
		result.ContractDigests[key] = selectedDigests[key]
	}
	result.ArtifactDigests["relay-capabilities.json"] = retainPreflightPayloadForTest(t, config.StateDir, "relay-capabilities.json", readyCapabilitiesPayloadForTest())
	result.ArtifactDigests["backend-status.json"] = retainPreflightPayloadForTest(t, config.StateDir, "backend-status.json", map[string]any{
		"scope":      "backends",
		"probe_auth": false,
		"backends": []any{
			map[string]any{"backend": "claude", "status": "ready"},
			map[string]any{"backend": "codex", "status": "ready"},
		},
	})
	result.ArtifactDigests["recipes-list.json"] = retainPreflightPayloadForTest(t, config.StateDir, "recipes-list.json", readyRecipesPayloadForTest())
	result.ArtifactDigests["integration-bundle.json"] = retainPreflightPayloadForTest(t, config.StateDir, "integration-bundle.json", bundlePayload)
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		plan := map[string]any{
			"schema_version":               "test-root-recipe-plan-v1",
			"recipe_id":                    requirement.RecipeID,
			"integration_contract_id":      requirement.ContractID,
			"integration_contract_digest":  selectedDigests[requirement.ContractID],
			"deterministic_test_fixture":   true,
			"required_input_binding_count": 4,
		}
		report := map[string]any{
			"recipe_id":            requirement.RecipeID,
			"status":               "usable",
			"integration_contract": requirement.ContractID,
			"compiled_plan":        plan,
			"contract_digests": map[string]any{
				requirement.ContractID: selectedDigests[requirement.ContractID],
			},
		}
		reportRelative := filepath.ToSlash(filepath.Join("compile-reports", requirement.RecipeID+".json"))
		planRelative := filepath.ToSlash(filepath.Join("recipe-plans", requirement.RecipeID+".json"))
		result.ArtifactDigests[reportRelative] = retainPreflightPayloadForTest(t, config.StateDir, reportRelative, report)
		result.CompileReportDigests[requirement.RecipeID] = result.ArtifactDigests[reportRelative]
		result.ArtifactDigests[planRelative] = retainPreflightPayloadForTest(t, config.StateDir, planRelative, plan)
		result.RecipePlanDigests[requirement.RecipeID] = result.ArtifactDigests[planRelative]
	}
	contractDigestDoc := map[string]any{
		"schema_version":   "witness-preflight-contract-digests-v1",
		"digest_profile":   digest.Profile,
		"contract_digests": result.ContractDigests,
	}
	result.ArtifactDigests["contract-digests.json"] = retainPreflightPayloadForTest(t, config.StateDir, "contract-digests.json", contractDigestDoc)
	result.ArtifactDigests["compatibility-manifest.json"] = retainPreflightPayloadForTest(t, config.StateDir, "compatibility-manifest.json", expectedPreflightCompatibility(result))
	writeCanonicalForTest(t, config.Outputs.PreflightPath, result)
	return result
}

func readyCapabilitiesPayloadForTest() map[string]any {
	payload := map[string]any{
		"schema_version":      "relay-capabilities-v1",
		"convo_relay_version": "v1.4.0",
		"build_platform":      map[string]any{"goarch": "test", "goos": "test"},
		"contracts":           map[string]any{},
	}
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		if strings.HasPrefix(requirement.Family, "contracts.") {
			contractsPayload := payload["contracts"].(map[string]any)
			key := strings.TrimPrefix(requirement.Family, "contracts.")
			contractsPayload[key] = append(capabilityListForTest(contractsPayload[key]), requirement.Capability)
			continue
		}
		payload[requirement.Family] = append(capabilityListForTest(payload[requirement.Family]), requirement.Capability)
	}
	return payload
}

func capabilityListForTest(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	return nil
}

func readyRecipesPayloadForTest() map[string]any {
	recipes := make([]any, 0, len(preflight.RequiredRecipes))
	for _, requirement := range preflight.RequiredRecipes {
		recipes = append(recipes, map[string]any{
			"id":       requirement.ID,
			"status":   "usable",
			"declared": map[string]any{"integration_contract": requirement.ContractID},
		})
	}
	return map[string]any{
		"scope":   "recipes",
		"status":  "ok",
		"recipes": recipes,
	}
}

func retainPreflightPayloadForTest(t *testing.T, stateDir string, relativePath string, payload any) string {
	t.Helper()
	payloadBytes, err := canonjson.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := digest.RawBytes(payloadBytes)
	envelope := map[string]any{
		"schema_version": "witness-retained-artifact-v1",
		"digest_profile": digest.Profile,
		"payload_digest": payloadDigest,
		"payload":        payload,
	}
	writeCanonicalForTest(t, filepath.Join(stateDir, filepath.FromSlash(relativePath)), envelope)
	return payloadDigest
}

func runPassToCompletion(t *testing.T, options BeginOptions, withFinding bool) *Invocation {
	t.Helper()
	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, withFinding)
	for _, stage := range []string{stagePlan, stageAssemble, stageAdjudicate, stageMetrics} {
		invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
		if err != nil {
			t.Fatalf("resume %s: %v", stage, err)
		}
	}
	if !invocation.Complete {
		t.Fatalf("pass did not complete: %#v", invocation)
	}
	return invocation
}

func adjudicationSummaryForTest(findings []adjudicate.FindingVerdict) adjudicate.Summary {
	var summary adjudicate.Summary
	for _, finding := range findings {
		switch finding.Disposition {
		case contracts.DispositionAdmitted:
			summary.Admitted++
		case contracts.DispositionAdvisory:
			summary.Advisory++
		case contracts.DispositionPendingVerification:
			summary.PendingVerification++
		}
		switch finding.ApplicationClass {
		case contracts.ApplicationClassAutomaticCandidate:
			summary.AutomaticCandidate++
		case contracts.ApplicationClassCallerDecision:
			summary.CallerDecision++
		case contracts.ApplicationClassNone:
			summary.None++
		}
	}
	summary.FixpointEligible = summary.Admitted == 0 &&
		summary.Advisory == 0 &&
		summary.PendingVerification == 0 &&
		summary.AutomaticCandidate == 0 &&
		summary.CallerDecision == 0
	return summary
}

func refreshArtifactDigestForTest(t *testing.T, state *State, role string, path string) {
	t.Helper()
	refreshed := false
	for stageIndex := range state.Stages {
		for inputIndex := range state.Stages[stageIndex].Inputs {
			if state.Stages[stageIndex].Inputs[inputIndex].Role == role && recordedPathsEqual(state.Stages[stageIndex].Inputs[inputIndex].Path, path) {
				value, err := computeArtifactDigest(path, state.Stages[stageIndex].Inputs[inputIndex].DigestClass)
				if err != nil {
					t.Fatal(err)
				}
				state.Stages[stageIndex].Inputs[inputIndex].Digest = value
				refreshed = true
			}
		}
		for outputIndex := range state.Stages[stageIndex].Outputs {
			if state.Stages[stageIndex].Outputs[outputIndex].Role == role && recordedPathsEqual(state.Stages[stageIndex].Outputs[outputIndex].Path, path) {
				value, err := computeArtifactDigest(path, state.Stages[stageIndex].Outputs[outputIndex].DigestClass)
				if err != nil {
					t.Fatal(err)
				}
				state.Stages[stageIndex].Outputs[outputIndex].Digest = value
				refreshed = true
			}
		}
	}
	if !refreshed {
		t.Fatalf("artifact record %s at %s not found", role, path)
	}
}

func setStageDetailForTest(state *State, stageName string, key string, value any) {
	for index := range state.Stages {
		if state.Stages[index].Name != stageName {
			continue
		}
		if state.Stages[index].Details == nil {
			state.Stages[index].Details = map[string]any{}
		}
		state.Stages[index].Details[key] = value
		return
	}
}

func runAdjudicationServiceForState(t *testing.T, state *State, ledgerPath string) (AdjudicationServiceResult, error) {
	t.Helper()
	frozen, _, err := readFrozenCharter(state.Config.Outputs.CharterFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readVerificationManifest(state.Config.Outputs.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	changeSurface, err := readChangeSurfaceInput(state.Config.BaseManifestPath, state.Config.HeadManifestPath, false)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := loadEffectivePolicy(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	roleOutputs := make([]adjudicate.RoleOutputInput, 0, len(state.Config.RoleOutputs))
	for _, item := range state.Config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			t.Fatal(err)
		}
		roleOutputs = append(roleOutputs, adjudicate.RoleOutputInput{Path: item.Path, Document: document})
	}
	return RunAdjudicationService(AdjudicationOptions{
		FrozenCharter:                frozen,
		RoleOutputs:                  roleOutputs,
		Manifest:                     manifest,
		BaseManifest:                 changeSurface.BaseManifest,
		HeadManifest:                 changeSurface.HeadManifest,
		LedgerPath:                   ledgerPath,
		Rules:                        effective.Rules,
		Policy:                       effective.Policy,
		PolicyCapReleaseLedgerBacked: effective.CapRelease != nil,
	})
}

func adjudicationRoleOutputsForState(t *testing.T, state *State) []adjudicate.RoleOutputInput {
	t.Helper()
	roleOutputs := make([]adjudicate.RoleOutputInput, 0, len(state.Config.RoleOutputs))
	for _, item := range state.Config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			t.Fatal(err)
		}
		roleOutputs = append(roleOutputs, adjudicate.RoleOutputInput{Path: item.Path, Document: document})
	}
	return roleOutputs
}

func assertInvocation(t *testing.T, invocation *Invocation, stage string, action string, complete bool) {
	t.Helper()
	if invocation.StageRun != stage {
		t.Fatalf("stage_run = %q, want %q", invocation.StageRun, stage)
	}
	if invocation.NextAction.Type != action {
		t.Fatalf("next action = %q, want %q", invocation.NextAction.Type, action)
	}
	if invocation.Complete != complete {
		t.Fatalf("complete = %v, want %v", invocation.Complete, complete)
	}
	if invocation.PassState.Path == "" || invocation.PassState.Digest == "" {
		t.Fatalf("pass state ref incomplete: %#v", invocation.PassState)
	}
}

func assertValidationCode(t *testing.T, err error, code string) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want ValidationError: %v", err, err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != code {
		t.Fatalf("diagnostics = %#v, want first code %s", validation.Diagnostics, code)
	}
}

func assertValidationDetailPath(t *testing.T, err error, key string, want string) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) == 0 {
		t.Fatalf("error = %T, want ValidationError with diagnostics: %v", err, err)
	}
	paths, ok := validation.Diagnostics[0].Details[key].([]string)
	if !ok {
		t.Fatalf("diagnostic details[%s] = %#v, want []string", key, validation.Diagnostics[0].Details[key])
	}
	for _, path := range paths {
		if path == want {
			return
		}
	}
	t.Fatalf("diagnostic %s = %#v, want %s", key, paths, want)
}

func diagCode(err error) string {
	if err == nil {
		return ""
	}
	return diag.FromError(err).Code
}

func assertLedgerLineageEqual(t *testing.T, left []ledger.Record, right []ledger.Record) {
	t.Helper()
	if len(left) != len(right) {
		t.Fatalf("ledger record length = %d, want %d", len(left), len(right))
	}
	for index := range left {
		if left[index].EventKind != right[index].EventKind || !bytes.Equal(left[index].Event, right[index].Event) {
			t.Fatalf("ledger record %d = kind %s event %s, want kind %s event %s", index, left[index].EventKind, left[index].Event, right[index].EventKind, right[index].Event)
		}
	}
}

func stageRecordForTest(t *testing.T, state *State, name string) StageRecord {
	t.Helper()
	for _, stage := range state.Stages {
		if stage.Name == name {
			return stage
		}
	}
	t.Fatalf("stage %s not found in %#v", name, state.Stages)
	return StageRecord{}
}

func hasArtifactRole(records []ArtifactRecord, role string) bool {
	for _, record := range records {
		if record.Role == role {
			return true
		}
	}
	return false
}

func hasArtifactRolePrefix(records []ArtifactRecord, prefix string) bool {
	for _, record := range records {
		if strings.HasPrefix(record.Role, prefix) {
			return true
		}
	}
	return false
}

func readPassStateForTest(t *testing.T, stateDir string) *State {
	t.Helper()
	state, err := readState(filepath.Join(stateDir, StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func writePassReceiptFixture(t *testing.T, outputDir string, receiptPath string, key []byte, plan planning.PlanDocument, findingID string) contracts.ExecutionReceipt {
	t.Helper()
	sourceBefore := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "source-snapshot", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	sourceAfter := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "source-snapshot", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	workspaceBefore := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "execution-workspace", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	workspaceAfter := harness.Inventory{SchemaVersion: harness.InventorySchema, Kind: "execution-workspace", DigestProfile: digest.Profile, Files: []harness.InventoryFile{}}
	sourceBeforeRef := writePassJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "source-before", sourceBefore)
	sourceAfterRef := writePassJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "source-after", sourceAfter)
	workspaceBeforeRef := writePassJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "workspace-before", workspaceBefore)
	workspaceAfterRef := writePassJSONReceiptArtifact(t, outputDir, "inventory", "execution-inventory", "workspace-after", workspaceAfter)
	delta := harness.DiffInventories(workspaceBefore, workspaceAfter, workspaceBeforeRef.Digest, workspaceAfterRef.Digest)
	deltaRef := writePassJSONReceiptArtifact(t, outputDir, "inventory", "workspace-mutation-report", "workspace-delta", delta)
	stdout := []byte("ok\n")
	stderr := []byte{}
	stdoutRef := writePassBytesReceiptArtifact(t, outputDir, "stdout", "execution-stdout", "stdout", "text/plain", stdout)
	stderrRef := writePassBytesReceiptArtifact(t, outputDir, "stderr", "execution-stderr", "stderr", "text/plain", stderr)
	command := contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "stdout_contains=ok",
	}
	receipt := contracts.ExecutionReceipt{
		SchemaVersion:  contracts.ExecutionReceiptV2,
		ReceiptID:      "receipt-" + findingID,
		FindingID:      findingID,
		CharterHash:    plan.CharterHash,
		ArtifactDigest: plan.ArtifactDigest,
		FrozenSource: contracts.ArtifactRef{
			Kind:          "source-snapshot-manifest",
			ID:            "source-snapshot",
			Digest:        plan.ArtifactDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		Harness: contracts.HarnessIdentity{
			ID:          "witness-harness-v1",
			Version:     harness.Version,
			BuildDigest: digest.RawBytes([]byte("harness-build")),
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
		ExecutionStatus:       contracts.ExecutionStatusSatisfied,
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
	writePassReceiptFile(t, receiptPath, receipt)
	writePassReceiptFile(t, filepath.Join(outputDir, "receipts", receipt.ReceiptID+".json"), receipt)
	return receipt
}

func writePassJSONReceiptArtifact(t *testing.T, outputDir string, namespace string, kind string, id string, value any) contracts.ArtifactRef {
	t.Helper()
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return writePassBytesReceiptArtifact(t, outputDir, namespace, kind, id, "application/json", data)
}

func writePassBytesReceiptArtifact(t *testing.T, outputDir string, namespace string, kind string, id string, mediaType string, data []byte) contracts.ArtifactRef {
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

func writePassReceiptFile(t *testing.T, path string, receipt contracts.ExecutionReceipt) {
	t.Helper()
	data, err := contracts.ExecutionReceiptCanonicalBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeCanonicalForTest(t *testing.T, path string, value any) {
	t.Helper()
	data, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSONForTest[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}
