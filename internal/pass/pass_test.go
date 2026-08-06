package pass

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	"github.com/charlesnpx/witness/internal/relayrun"
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

func TestBeginWithSameOptionsResumesExistingPass(t *testing.T) {
	options := newBeginOptions(t)

	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	assertInvocation(t, invocation, stageFreeze, actionWitnessCommand, false)

	invocation, err = Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin same options: %v", err)
	}
	assertInvocation(t, invocation, stagePreflight, actionCallerRoleOutputs, false)
	if invocation.PassState.Path != filepath.Join(options.StateDir, StateFileName) {
		t.Fatalf("pass state path = %s, want %s", invocation.PassState.Path, filepath.Join(options.StateDir, StateFileName))
	}
}

func TestBeginAllowsDirtyGitSnapshotAndReportsRetainedArtifacts(t *testing.T) {
	options := newBeginOptions(t)
	options.AllowNonGitSource = false
	runPassGit(t, options.SourceDir, "init")
	runPassGit(t, options.SourceDir, "config", "user.email", "witness-test@example.com")
	runPassGit(t, options.SourceDir, "config", "user.name", "Witness Test")
	runPassGit(t, options.SourceDir, "add", "app.txt")
	runPassGit(t, options.SourceDir, "commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(options.SourceDir, "app.txt"), []byte("working-copy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.SourceDir, "untracked.txt"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Begin(context.Background(), options); diag.FromError(err).Code != freeze.CodeSourceDirty {
		t.Fatalf("dirty begin error = %v, want %s", err, freeze.CodeSourceDirty)
	}

	options.AllowDirtySource = true
	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("begin dirty pass with override: %v", err)
	}
	if !invocation.SourceDirty || !strings.Contains(invocation.SourceDirtyStatus, "M app.txt") {
		t.Fatalf("invocation dirty source context = %#v", invocation)
	}
	for _, role := range []string{"pass_state", "charter_freeze", "source_manifest", "workspace_manifest"} {
		relativePath := invocation.RetainedArtifacts[role]
		if relativePath == "" || filepath.IsAbs(relativePath) {
			t.Fatalf("begin retained artifact %s = %q", role, relativePath)
		}
		if _, err := os.Stat(filepath.Join(options.StateDir, filepath.FromSlash(relativePath))); err != nil {
			t.Fatalf("begin retained artifact %s at %s: %v", role, relativePath, err)
		}
	}

	state := readPassStateForTest(t, options.StateDir)
	if !state.Config.AllowDirtySource {
		t.Fatalf("pass config = %#v, want allow_dirty_source", state.Config)
	}
	if !state.SourceDirty || !strings.Contains(state.SourceDirtyStatus, "M app.txt") {
		t.Fatalf("pass source context = dirty:%t status:%q", state.SourceDirty, state.SourceDirtyStatus)
	}
	freezeStage := state.Stages[0]
	if got, _ := freezeStage.Details["source_dirty"].(bool); !got {
		t.Fatalf("freeze stage details = %#v, want source_dirty", freezeStage.Details)
	}
	manifest := readJSONForTest[freeze.Manifest](t, state.Config.SnapshotManifestPath)
	if !manifest.Source.GitDirty || !strings.Contains(manifest.Source.GitDirtyStatus, "?? untracked.txt") {
		t.Fatalf("snapshot source identity = %#v", manifest.Source)
	}

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume dirty pass preflight: %v", err)
	}
	if !invocation.SourceDirty {
		t.Fatalf("preflight invocation lost dirty source context: %#v", invocation)
	}
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	if !preflightResult.SourceDirty || preflightResult.SourceDirtyStatus != manifest.Source.GitDirtyStatus {
		t.Fatalf("preflight dirty source context = %#v, want %#v", preflightResult, manifest.Source)
	}
	for role, relativePath := range invocation.RetainedArtifacts {
		if filepath.IsAbs(relativePath) {
			t.Fatalf("retained artifact %s has absolute path %q", role, relativePath)
		}
		if _, err := os.Stat(filepath.Join(options.StateDir, filepath.FromSlash(relativePath))); err != nil {
			t.Fatalf("retained artifact %s at %s: %v", role, relativePath, err)
		}
	}
}

func TestPassRetainedArtifactsRejectsAdversarialPreflightEntries(t *testing.T) {
	stateDir := t.TempDir()
	retainedPath := filepath.Join(stateDir, "retained.json")
	if err := os.WriteFile(retainedPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(filepath.Dir(stateDir), "outside.json")
	if err := os.WriteFile(outsidePath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		artifacts map[string]string
		code      string
	}{
		{
			name:      "absolute path",
			artifacts: map[string]string{"external": outsidePath},
			code:      CodeInvalidRetainedArtifact,
		},
		{
			name:      "reserved core role",
			artifacts: map[string]string{"pass_state": filepath.Base(retainedPath)},
			code:      CodeReservedRetainedArtifactRole,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := passRetainedArtifacts(Config{StateDir: stateDir}, preflight.Result{RetainedArtifacts: test.artifacts})
			if err == nil {
				t.Fatal("pass retained-artifact inventory accepted adversarial preflight entry")
			}
			assertValidationCode(t, err, test.code)
		})
	}
}

func TestPassRetainedArtifactsRejectsInStateSymlinkToExternalFile(t *testing.T) {
	stateDir := t.TempDir()
	outsidePath := filepath.Join(filepath.Dir(stateDir), "outside.json")
	if err := os.WriteFile(outsidePath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	externalSymlink := filepath.Join(stateDir, "external-link.json")
	if err := os.Symlink(outsidePath, externalSymlink); err != nil {
		t.Fatal(err)
	}

	_, err := passRetainedArtifacts(Config{StateDir: stateDir}, preflight.Result{RetainedArtifacts: map[string]string{
		"external": filepath.Base(externalSymlink),
	}})
	if err == nil {
		t.Fatal("pass retained-artifact inventory accepted an in-state symlink to an external file")
	}
	assertValidationCode(t, err, CodeInvalidRetainedArtifact)
}

func TestPassRetainedArtifactsRequiresMatchingManifestRolePath(t *testing.T) {
	stateDir := t.TempDir()
	localManifestPath := filepath.Join(stateDir, "source-snapshot", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(localManifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localManifestPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	otherManifestPath := filepath.Join(stateDir, "other-manifest.json")
	if err := os.WriteFile(otherManifestPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := Config{StateDir: stateDir, SnapshotManifestPath: localManifestPath}

	_, err := passRetainedArtifacts(config, preflight.Result{RetainedArtifacts: map[string]string{
		"source_manifest": filepath.Base(otherManifestPath),
	}})
	if err == nil {
		t.Fatal("pass retained-artifact inventory accepted a conflicting source manifest path")
	}
	assertValidationCode(t, err, CodeRetainedArtifactRoleConflict)

	artifacts, err := passRetainedArtifacts(config, preflight.Result{RetainedArtifacts: map[string]string{
		"source_manifest": filepath.ToSlash(filepath.Join("source-snapshot", "manifest.json")),
	}})
	if err != nil {
		t.Fatalf("pass retained-artifact inventory rejected matching source manifest path: %v", err)
	}
	if got, want := artifacts["source_manifest"], filepath.ToSlash(filepath.Join("source-snapshot", "manifest.json")); got != want {
		t.Fatalf("source manifest path = %q, want %q", got, want)
	}
}

func TestSaveAndReportRetainedArtifactFailureDoesNotPersistState(t *testing.T) {
	stateDir := t.TempDir()
	config := Config{StateDir: stateDir}
	applyOutputDefaults(&config)
	writeCanonicalForTest(t, config.Outputs.PreflightPath, preflight.Result{
		RetainedArtifacts: map[string]string{"missing": "missing.json"},
	})
	state := &State{
		Config:     config,
		NextAction: NextAction{Type: actionComplete},
	}

	_, err := saveAndReport(state, "")
	if err == nil {
		t.Fatal("saveAndReport accepted a missing retained artifact")
	}
	assertValidationCode(t, err, CodeInvalidRetainedArtifact)
	if _, statErr := os.Stat(config.Outputs.StatePath); !os.IsNotExist(statErr) {
		t.Fatalf("pass state exists after retained-artifact refusal: %v", statErr)
	}
}

func TestBeginRejectsZeroGoalCharterUnlessExplicitlyAllowed(t *testing.T) {
	options := newBeginOptions(t)
	writeCanonicalForTest(t, options.CharterPath, charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals:         []charter.Statement{},
		NonGoals:      []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "initial-charter",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial owner-authorized charter.",
		}},
	})

	if _, err := Begin(context.Background(), options); diag.FromError(err).Code != CodeCharterZeroGoals {
		t.Fatalf("zero-goal begin error = %v, want %s", err, CodeCharterZeroGoals)
	} else if !strings.Contains(err.Error(), "vacuous") || !strings.Contains(err.Error(), "-allow-empty-charter") {
		t.Fatalf("zero-goal diagnostic = %v", err)
	}
	if _, err := os.Stat(filepath.Join(options.StateDir, StateFileName)); !os.IsNotExist(err) {
		t.Fatalf("pass state exists after zero-goal refusal: %v", err)
	}

	options.AllowEmptyCharter = true
	invocation, err := Begin(context.Background(), options)
	if err != nil {
		t.Fatalf("zero-goal begin with override: %v", err)
	}
	if invocation.StageRun != stageFreeze {
		t.Fatalf("override invocation stage = %q, want %q", invocation.StageRun, stageFreeze)
	}
	state := readPassStateForTest(t, options.StateDir)
	if !state.Config.AllowEmptyCharter {
		t.Fatalf("pass config = %#v, want allow_empty_charter", state.Config)
	}
	frozen := readJSONForTest[charter.FrozenCharter](t, state.Config.Outputs.CharterFreezePath)
	if len(frozen.Charter.Goals) != 0 {
		t.Fatalf("frozen Charter goals = %#v, want empty override Charter", frozen.Charter.Goals)
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
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want ValidationError: %v", err, err)
	}
	for _, diagnostic := range validation.Diagnostics {
		if diagnostic.Code == CodeStateInvalid {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want %s", validation.Diagnostics, CodeStateInvalid)
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

func TestValidatePreflightContractDigestDocumentReadsV1AsRelayLineage(t *testing.T) {
	contractID := contracts.RequiredWitnessRecipeContractsV2[0].ContractID
	witnessDigest := digest.RawBytes([]byte("witness-body:" + contractID))
	relayDigest := digest.RawBytes([]byte("relay-lineage:" + contractID))
	integrationBundleDigest := digest.RawBytes([]byte("integration-bundle"))
	retained := map[string]any{
		"schema_version": preflight.ContractDigestDocumentV1,
		"digest_profile": digest.Profile,
		"contract_digests": map[string]any{
			contractID:           relayDigest,
			"integration_bundle": integrationBundleDigest,
		},
	}
	result := preflight.Result{
		ContractDigests: map[string]string{
			contractID:           witnessDigest,
			"integration_bundle": integrationBundleDigest,
		},
		RelayReportedDigests: map[string]string{contractID: relayDigest},
	}

	if err := validatePreflightContractDigestDocument(retained, result); err != nil {
		t.Fatalf("v1 document was compared to witness body digests: %v", err)
	}
}

func TestValidatePreflightContractDigestDocumentAllowsV1LegacyNonRequiredExtra(t *testing.T) {
	contractID := contracts.RequiredWitnessRecipeContractsV2[0].ContractID
	relayDigest := digest.RawBytes([]byte("relay-lineage:" + contractID))
	integrationBundleDigest := digest.RawBytes([]byte("integration-bundle"))
	extraContractID := "example/non-required-contract"
	extraDigest := digest.RawBytes([]byte("relay-lineage:" + extraContractID))
	retained := map[string]any{
		"schema_version": preflight.ContractDigestDocumentV1,
		"digest_profile": digest.Profile,
		"contract_digests": map[string]any{
			contractID:           relayDigest,
			"integration_bundle": integrationBundleDigest,
			extraContractID:      extraDigest,
		},
	}
	result := preflight.Result{
		ContractDigests: map[string]string{
			"integration_bundle": integrationBundleDigest,
		},
		RelayReportedDigests: map[string]string{contractID: relayDigest},
	}

	if err := validatePreflightContractDigestDocument(retained, result); err != nil {
		t.Fatalf("v1 persisted contract-digests rejected a non-required legacy extra: %v", err)
	}
}

func TestValidatePreflightCompileReportRejectsDisagreeingRelayLineage(t *testing.T) {
	requirement := contracts.RequiredWitnessRecipeContractsV2[0]
	reportedDigest := digest.RawBytes([]byte("relay-reported:" + requirement.ContractID))
	planDigest := digest.RawBytes([]byte("recipe-plan:" + requirement.ContractID))
	payload := map[string]any{
		"recipe_id":            requirement.RecipeID,
		"status":               "usable",
		"integration_contract": requirement.ContractID,
		"contract_digests": map[string]any{
			requirement.ContractID: reportedDigest,
		},
		"compiled_plan": map[string]any{
			"recipe_id":                    requirement.RecipeID,
			"integration_contract_id":      requirement.ContractID,
			"integration_contract_digest":  planDigest,
			"deterministic_test_fixture":   true,
			"required_input_binding_count": 4,
		},
	}

	_, _, err := validatePreflightCompileReport(payload, requirement, false)
	if err == nil {
		t.Fatal("validation accepted disagreeing relay lineage")
	}
	_, expectedErr := preflight.ResolveRelayReportedContractDigests(
		map[string]string{requirement.ContractID: reportedDigest},
		requirement.ContractID,
		planDigest,
	)
	if expectedErr == nil {
		t.Fatal("shared relay-lineage resolver accepted mismatched digests")
	}
	if actual, expected := diag.FromError(err), diag.FromError(expectedErr); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("validation diagnostic = %#v, want %#v", actual, expected)
	}
}

func TestValidatePreflightCompileReportRejectsMalformedDigestLikeGeneration(t *testing.T) {
	requirement := contracts.RequiredWitnessRecipeContractsV2[0]
	rawDigests := map[string]any{requirement.ContractID: true}
	payload := map[string]any{
		"recipe_id":            requirement.RecipeID,
		"status":               "usable",
		"integration_contract": requirement.ContractID,
		"contract_digests":     rawDigests,
		"compiled_plan": map[string]any{
			"recipe_id":                    requirement.RecipeID,
			"integration_contract_id":      requirement.ContractID,
			"integration_contract_digest":  digest.RawBytes([]byte("relay-projection:" + requirement.ContractID)),
			"deterministic_test_fixture":   true,
			"required_input_binding_count": 4,
		},
	}

	_, _, err := validatePreflightCompileReport(payload, requirement, false)
	if err == nil {
		t.Fatal("validation accepted a boolean compile-report digest")
	}
	_, expectedErr := preflight.DecodeCompileReportContractDigests(requirement.RecipeID, rawDigests)
	if expectedErr == nil {
		t.Fatal("shared compile-report digest decoder accepted a boolean digest")
	}
	if actual, expected := diag.FromError(err), diag.FromError(expectedErr); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("validation diagnostic = %#v, want generation diagnostic %#v", actual, expected)
	}
}

func TestValidatePreflightOutputProjectsExtraCompileReportDigest(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	generated := writeReadyPreflightForTest(t, state.Config)
	generated.SnapshotDigest = generated.ArtifactDigests["source-snapshot-manifest"]
	requirement := contracts.RequiredWitnessRecipeContractsV2[0]
	selectedDigest := generated.RelayReportedDigests[requirement.ContractID]
	if selectedDigest == "" {
		t.Fatalf("generated relay digest for %s is empty", requirement.ContractID)
	}

	extraContractID := "example/non-required-contract"
	reportRelativePath := filepath.ToSlash(filepath.Join("compile-reports", requirement.RecipeID+".json"))
	report := map[string]any{
		"recipe_id":            requirement.RecipeID,
		"status":               "usable",
		"integration_contract": requirement.ContractID,
		"contract_digests": map[string]any{
			requirement.ContractID: selectedDigest,
			extraContractID:        digest.RawBytes([]byte("relay-projection:" + extraContractID)),
		},
		"compiled_plan": map[string]any{
			"schema_version":               "test-root-recipe-plan-v1",
			"recipe_id":                    requirement.RecipeID,
			"integration_contract_id":      requirement.ContractID,
			"integration_contract_digest":  selectedDigest,
			"deterministic_test_fixture":   true,
			"required_input_binding_count": 4,
		},
	}
	reportDigest := retainPreflightPayloadForTest(t, state.Config.StateDir, reportRelativePath, report)
	generated.ArtifactDigests[reportRelativePath] = reportDigest
	generated.CompileReportDigests[requirement.RecipeID] = reportDigest
	if _, found := generated.RelayReportedDigests[extraContractID]; found {
		t.Fatalf("generated relay lineage retained non-required contract %s", extraContractID)
	}

	generatedDocument := preflight.ContractDigestDocument(generated)
	generated.ArtifactDigests["contract-digests.json"] = retainPreflightPayloadForTest(t, state.Config.StateDir, "contract-digests.json", generatedDocument)
	generated.ArtifactDigests["compatibility-manifest.json"] = retainPreflightPayloadForTest(t, state.Config.StateDir, "compatibility-manifest.json", expectedPreflightCompatibility(generated))
	writeCanonicalForTest(t, state.Config.Outputs.PreflightPath, generated)

	if err := validatePreflightOutput(state.Config, generated); err != nil {
		t.Fatalf("revalidation rejected projected compile-report lineage: %v", err)
	}
	reconstructed, err := expectedPreflightResult(state.Config)
	if err != nil {
		t.Fatalf("reconstruct preflight result: %v", err)
	}
	if actual := preflight.ContractDigestDocument(reconstructed); !reflect.DeepEqual(actual, generatedDocument) {
		t.Fatalf("reconstructed contract-digests document = %#v, want %#v", actual, generatedDocument)
	}
	if _, found := reconstructed.RelayReportedDigests[extraContractID]; found {
		t.Fatalf("reconstructed relay lineage retained non-required contract %s: %#v", extraContractID, reconstructed.RelayReportedDigests)
	}
}

func TestResumeAcceptsLegacyPreflightResultWithoutRetainedArtifacts(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	result := writeReadyPreflightForTest(t, state.Config)
	result.SnapshotDigest = result.ArtifactDigests["source-snapshot-manifest"]

	data, err := canonjson.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	document, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	legacyResult, ok := document.(map[string]any)
	if !ok {
		t.Fatalf("preflight document type = %T, want object", document)
	}
	delete(legacyResult, "retained_artifacts")
	writeCanonicalForTest(t, state.Config.Outputs.PreflightPath, legacyResult)

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
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume legacy preflight state: %v", err)
	}
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

func TestResumeRejectsRoleOutputActionPolicyDriftBeforePlanning(t *testing.T) {
	options, invocation, _, _ := beginDeltaRoleOutputWaitForTest(t)
	if invocation.NextAction.ScopePolicy != contracts.ScopePolicyDeltaObligating {
		t.Fatalf("scope_policy = %s, want %s", invocation.NextAction.ScopePolicy, contracts.ScopePolicyDeltaObligating)
	}
	writeRoleOutputsForState(t, options.StateDir, false)

	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "whole-tree-policy"
	policy.ScopePolicy = contracts.ScopePolicyWholeTree
	writeCanonicalForTest(t, options.PolicyPath, policy)

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted role-output files after action policy drift")
	}
	assertValidationCode(t, err, CodeNextActionDrift)
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) == 0 {
		t.Fatalf("error = %T, want ValidationError with diagnostics: %v", err, err)
	}
	details := validation.Diagnostics[0].Details
	persisted, ok := details["persisted"].(map[string]any)
	if !ok {
		t.Fatalf("persisted details = %#v, want object", details["persisted"])
	}
	rederived, ok := details["rederived"].(map[string]any)
	if !ok {
		t.Fatalf("rederived details = %#v, want object", details["rederived"])
	}
	if persisted["scope_policy"] != contracts.ScopePolicyDeltaObligating || rederived["scope_policy"] != contracts.ScopePolicyWholeTree {
		t.Fatalf("drift details = %#v, want delta persisted and whole-tree rederived", details)
	}
	if strings.TrimSpace(persisted["change_surface_digest"].(string)) == "" || rederived["change_surface_digest"] != "" {
		t.Fatalf("change-surface drift details = %#v, want persisted digest and empty rederived digest", details)
	}
	state := readPassStateForTest(t, options.StateDir)
	if _, statErr := os.Stat(state.Config.Outputs.PlanPath); !os.IsNotExist(statErr) {
		t.Fatalf("plan was written before action drift failure: %v", statErr)
	}
}

func TestCallerRoleOutputsDeltaActionFailsWithoutDerivableChangeSurface(t *testing.T) {
	options := newBeginOptions(t)
	root := filepath.Dir(options.StateDir)
	policyPath := filepath.Join(root, "policy.json")
	policy := contracts.DefaultReviewPolicy()
	policy.PolicyID = "delta-policy"
	policy.ScopePolicy = contracts.ScopePolicyDeltaObligating
	writeCanonicalForTest(t, policyPath, policy)
	options.PolicyPath = policyPath

	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume emitted a delta role-output action without a derivable change surface")
	}
	if got := diagCode(err); got != planning.CodeMissingChangeSurface {
		t.Fatalf("error code = %s, want %s: %v", got, planning.CodeMissingChangeSurface, err)
	}
}

func TestPreflightRecordIncludesEarlyChangeSurfaceInputs(t *testing.T) {
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
	headManifest := readJSONForTest[freeze.Manifest](t, filepath.Join(options.StateDir, "source-snapshot", "manifest.json"))
	baseManifest := headManifest
	baseManifest.Files = append([]freeze.FileEntry(nil), headManifest.Files...)
	if len(baseManifest.Files) != 1 {
		t.Fatalf("test source files = %#v, want one file", baseManifest.Files)
	}
	baseManifest.Files[0] = freezeFileEntryForTest("app.txt", "100644", []byte("before\n"))
	restampFreezeManifestForTest(t, &baseManifest)
	writeCanonicalForTest(t, basePath, baseManifest)
	writeCanonicalForTest(t, headPath, headManifest)

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	if invocation.NextAction.ChangeSurfacePath == "" {
		t.Fatal("delta role-output action did not carry an early change surface")
	}
	state := readPassStateForTest(t, options.StateDir)
	preflightStage := stageRecordForTest(t, state, stagePreflight)
	for _, want := range []struct {
		role string
		path string
	}{
		{role: "base-manifest", path: basePath},
		{role: "head-manifest", path: headPath},
	} {
		record, ok := findArtifactRecord(preflightStage.Inputs, want.role, want.path)
		if !ok {
			t.Fatalf("preflight inputs missing %s at %s: %#v", want.role, want.path, preflightStage.Inputs)
		}
		if record.DigestClass != digestClassFreezeManifest {
			t.Fatalf("%s digest_class = %s, want %s", want.role, record.DigestClass, digestClassFreezeManifest)
		}
		wantDigest, err := computeArtifactDigest(want.path, digestClassFreezeManifest)
		if err != nil {
			t.Fatal(err)
		}
		if record.Digest != wantDigest {
			t.Fatalf("%s digest = %s, want %s", want.role, record.Digest, wantDigest)
		}
	}

	baseManifest.Files[0] = freezeFileEntryForTest("app.txt", "100644", []byte("tampered\n"))
	restampFreezeManifestForTest(t, &baseManifest)
	writeCanonicalForTest(t, basePath, baseManifest)
	_, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted a mutated early change-surface input")
	}
	assertValidationCode(t, err, CodeStateDrift)
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

func TestPlanRoundTripsSafeIntegerEstimatedDeltaInVerificationBatch(t *testing.T) {
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
	writeRoleOutputsForState(t, options.StateDir, true)

	state := readPassStateForTest(t, options.StateDir)
	var defectPath string
	for _, roleOutput := range state.Config.RoleOutputs {
		if roleOutput.Role == contracts.RoleDefect {
			defectPath = roleOutput.Path
			break
		}
	}
	if defectPath == "" {
		t.Fatal("test pass has no defect role output")
	}
	roleOutput := readJSONForTest[contracts.RoleOutputDocument](t, defectPath)
	roleOutput.Findings[0].EstimatedDelta.Test.Lines = 20
	writeCanonicalForTest(t, defectPath, roleOutput)

	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	state = readPassStateForTest(t, options.StateDir)
	batchPath := filepath.Join(state.Config.StateDir, "verification", "batches", "defect-batch-1.json")
	batchBytes, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(batchBytes, []byte(`"lines":20`)) {
		t.Fatalf("verification batch = %s, want integer estimated_delta lines", batchBytes)
	}
	batch, err := contracts.ReadVerificationBatchBytes(batchBytes)
	if err != nil {
		t.Fatalf("re-decode verification batch: %v", err)
	}
	if diagnostics := contracts.ValidateVerificationBatch(batch, nil); len(diagnostics) > 0 {
		t.Fatalf("re-validated verification batch diagnostics = %#v", diagnostics)
	}

	if _, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir}); err != nil {
		t.Fatalf("resume after plan validation: %v", err)
	}
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
	bundleBody := []byte("{}\n")
	if err := os.WriteFile(retainedIntegrationBundleBodyPath(config), bundleBody, 0o644); err != nil {
		t.Fatal(err)
	}
	integrationDigest, err := digest.SemanticJSONBytes(bundleBody)
	if err != nil {
		t.Fatal(err)
	}
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
	action, err := nextRelayBatchAction(state)
	if err != nil {
		t.Fatalf("nextRelayBatchAction: %v", err)
	}
	if action == nil {
		t.Fatal("nextRelayBatchAction returned nil")
	}
	if action.BatchDigest != batchDigest ||
		action.CharterDigest != charterDigest ||
		action.SnapshotDigest != snapshotDigest ||
		action.IntegrationBundleDigest != integrationDigest {
		t.Fatalf("relay batch digests = %#v", action)
	}
	retainedPath, err := retainedIntegrationBundlePath(config)
	if err != nil {
		t.Fatal(err)
	}
	if action.IntegrationBundlePath != retainedPath {
		t.Fatalf("integration bundle path = %s, want retained %s", action.IntegrationBundlePath, retainedPath)
	}
	for _, value := range []string{batchDigest, charterDigest, snapshotDigest, integrationDigest} {
		if !strings.Contains(strings.Join(action.InputBindings, "\n"), value) {
			t.Fatalf("input bindings = %#v, missing digest %s", action.InputBindings, value)
		}
	}
}

func TestRetainedIntegrationBundlePathRejectsLegacyEnvelopeForRelayBinding(t *testing.T) {
	stateDir := t.TempDir()
	config := Config{
		StateDir:              stateDir,
		IntegrationBundlePath: filepath.Join(stateDir, "original-bundle.json"),
	}
	if err := os.WriteFile(retainedIntegrationBundleEnvelopePath(config), []byte("{\"payload\":{}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := retainedIntegrationBundlePath(config)
	if err == nil {
		t.Fatalf("retained integration bundle path = %q, want legacy envelope rejection", path)
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeInvalidState {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeInvalidState)
	}
	if !strings.Contains(diagnostic.Message, "predates") {
		t.Fatalf("diagnostic message = %q, want legacy-state explanation", diagnostic.Message)
	}
	if diagnostic.Details["expected_body_path"] != retainedIntegrationBundleBodyPath(config) ||
		diagnostic.Details["retained_envelope_path"] != retainedIntegrationBundleEnvelopePath(config) ||
		diagnostic.Details["original_bundle_path"] != config.IntegrationBundlePath {
		t.Fatalf("diagnostic details = %#v, want retained-body rebind guidance", diagnostic.Details)
	}
	rebindInstruction, _ := diagnostic.Details["rebind_instruction"].(string)
	if !strings.Contains(rebindInstruction, "-integration-bundle") {
		t.Fatalf("rebind instruction = %#v, want integration bundle guidance", diagnostic.Details["rebind_instruction"])
	}
}

func TestResumeEnvelopeOnlyPreflightReachesLegacyBundleRebind(t *testing.T) {
	options, state, _ := readyPassAtRelayBatchActionForTest(t, true)
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	delete(preflightResult.ArtifactDigests, preflight.RetainedIntegrationBundleBodyFile)
	preflightResult.RetainedArtifacts = preflight.RetainedArtifacts(state.Config.StateDir, state.Config.SnapshotManifestPath, preflightResult.ArtifactDigests)
	writeCanonicalForTest(t, state.Config.Outputs.PreflightPath, preflightResult)
	if err := os.Remove(retainedIntegrationBundleBodyPath(state.Config)); err != nil {
		t.Fatal(err)
	}
	for index := range state.Stages {
		if state.Stages[index].Name != stagePreflight {
			continue
		}
		outputs := state.Stages[index].Outputs[:0]
		for _, output := range state.Stages[index].Outputs {
			if output.Role != "integration-bundle-body" {
				outputs = append(outputs, output)
			}
		}
		state.Stages[index].Outputs = outputs
	}
	refreshArtifactDigestForTest(t, state, "preflight", state.Config.Outputs.PreflightPath)
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}
	for _, specs := range [][]artifactInput{
		preflightOutputSpecs(state.Config, nil),
		preflightOutputSpecs(state.Config, &preflightResult),
	} {
		for _, spec := range specs {
			if spec.role == "integration-bundle-body" {
				t.Fatalf("envelope-only preflight marked %s mandatory: %#v", spec.role, specs)
			}
		}
	}

	_, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err == nil {
		t.Fatal("resume accepted an envelope-only preflight state")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeInvalidState || !strings.Contains(diagnostic.Message, "predates directly consumable retained integration bundle bodies") {
		t.Fatalf("diagnostic = %#v, want legacy rebind guidance", diagnostic)
	}
	if strings.Contains(diagnostic.Message, "missing a mandatory artifact record") {
		t.Fatalf("diagnostic = %#v, want legacy rebind guidance before mandatory-output failure", diagnostic)
	}
}

func TestPassResumeConsumesRecordedUnavailableRelayRun(t *testing.T) {
	options, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         batch.BatchID,
		Status:          contracts.RecordStatusUnavailable,
		RecipeID:        batch.RecipeID,
		InputBindings:   plannedRelayInputBindingsForTest(t, state.Config, batch),
		ProviderInvoked: relayrun.ProviderInvokedUnknown,
		ConsumesBatch:   true,
		Diagnostics: []diag.Diagnostic{{
			Code:    relayrun.CodeRelayRunFailed,
			Message: "relay verification run failed after launch.",
		}},
	})

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume assemble from recorded unavailable run: %v", err)
	}
	assertInvocation(t, invocation, stageAssemble, actionWitnessCommand, false)

	manifest := readJSONForTest[contracts.VerificationManifest](t, state.Config.Outputs.ManifestPath)
	if diagnostics := contracts.ValidateVerificationManifest(manifest); len(diagnostics) > 0 {
		t.Fatalf("manifest diagnostics = %#v", diagnostics)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusUnavailable || manifest.Batches[0].FailureReason != "relay_run_recorded_unavailable" {
		t.Fatalf("manifest batches = %#v, want recorded unavailable evidence", manifest.Batches)
	}

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume adjudicate: %v", err)
	}
	assertInvocation(t, invocation, stageAdjudicate, actionWitnessCommand, false)
	verdict := readJSONForTest[adjudicate.Result](t, state.Config.Outputs.RunResultPath)
	if len(verdict.Findings) != 1 || verdict.Findings[0].Disposition != contracts.DispositionPendingVerification || verdict.Summary.PendingVerification != 1 || verdict.Summary.FixpointEligible {
		t.Fatalf("verdict = %#v, want one pending, fixpoint-ineligible finding", verdict)
	}

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume metrics: %v", err)
	}
	assertInvocation(t, invocation, stageMetrics, actionComplete, true)
}

func TestRunBatchesRecordPassesConsumingBindingValidation(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	plan := readJSONForTest[planning.PlanDocument](t, state.Config.Outputs.PlanPath)
	var plannedBatch planning.BatchPlan
	for _, candidate := range plan.Batches {
		if candidate.BatchID == batch.BatchID {
			plannedBatch = candidate
			break
		}
	}
	if plannedBatch.BatchID == "" {
		t.Fatalf("plan batches = %#v, missing %q", plan.Batches, batch.BatchID)
	}
	batchBytes, err := os.ReadFile(batch.BatchPath)
	if err != nil {
		t.Fatal(err)
	}
	batchDocument, err := contracts.ReadVerificationBatchBytes(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	integrationBundlePath, err := retainedIntegrationBundlePath(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	relayPath := filepath.Join(t.TempDir(), "failing-relay")
	if err := os.WriteFile(relayPath, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := relayrun.RunBatches(context.Background(), []relayrun.BatchInput{{
		Plan:     plannedBatch,
		Document: batchDocument,
		Path:     batch.BatchPath,
		RawBytes: batchBytes,
	}}, relayrun.Options{
		RelayPath:               relayPath,
		IntegrationBundlePath:   integrationBundlePath,
		CharterPath:             state.Config.Outputs.CharterFreezePath,
		ArtifactPaths:           []string{state.Config.SnapshotManifestPath},
		CharterDigest:           plan.CharterDigest,
		ArtifactDigest:          plan.PreflightSnapshotDigest,
		IntegrationBundleDigest: preflightResult.ContractDigests["integration_bundle"],
		OutputDir:               state.Config.StateDir,
		Backend:                 state.Config.Backend,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if len(result.Runs) != 1 {
		t.Fatalf("runs = %#v, want one", result.Runs)
	}
	record := result.Runs[0]
	if record.Status != contracts.RecordStatusUnavailable || !record.ConsumesBatch {
		t.Fatalf("record = %#v, want consuming unavailable record", record)
	}
	if record.RelayLaunch == nil || record.RelayLaunch.StartFailed || record.RelayLaunch.ExitCode != 1 {
		t.Fatalf("relay launch = %#v, want started nonzero exit", record.RelayLaunch)
	}
	if want := plannedRelayInputBindingsForTest(t, state.Config, batch); !reflect.DeepEqual(record.InputBindings, want) {
		t.Fatalf("input bindings = %#v, want %#v", record.InputBindings, want)
	}
	if _, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch}); err != nil {
		t.Fatalf("real relayrun record did not validate for pass resume: %v", err)
	}
}

func TestReadRecordedRelayRunsRequiresCompleteBindingsForConsumingRecord(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	validBindings := plannedRelayInputBindingsForTest(t, state.Config, batch)

	for _, test := range []struct {
		name         string
		bindings     []string
		wantMissing  []string
		wantNoDigest string
	}{
		{
			name:        "no bindings",
			wantMissing: []string{"charter", "findings", "artifact", "integration_bundle"},
		},
		{
			name: "missing findings binding",
			bindings: func() []string {
				bindings := append([]string(nil), validBindings...)
				return append(bindings[:1], bindings[2:]...)
			}(),
			wantMissing: []string{"findings"},
		},
		{
			name: "artifact binding missing digest suffix",
			bindings: func() []string {
				bindings := append([]string(nil), validBindings...)
				bindings[2] = boundInput("artifact", state.Config.SnapshotManifestPath, "")
				return bindings
			}(),
			wantNoDigest: "artifact",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
				SchemaVersion:   relayrun.RunRecordSchema,
				BatchID:         batch.BatchID,
				Status:          contracts.RecordStatusUnavailable,
				RecipeID:        batch.RecipeID,
				InputBindings:   test.bindings,
				ProviderInvoked: relayrun.ProviderInvokedUnknown,
				ConsumesBatch:   true,
			})

			_, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch})
			if err == nil {
				t.Fatal("readRecordedRelayRuns accepted a consuming record without complete bound inputs")
			}
			diagnostic := diag.FromError(err)
			if diagnostic.Code != CodeInvalidState {
				t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeInvalidState)
			}
			if test.wantMissing != nil {
				if !reflect.DeepEqual(diagnostic.Details["missing_bindings"], test.wantMissing) {
					t.Fatalf("missing_bindings = %#v, want %#v", diagnostic.Details["missing_bindings"], test.wantMissing)
				}
			} else if _, found := diagnostic.Details["missing_bindings"]; found {
				t.Fatalf("missing_bindings = %#v, want absent", diagnostic.Details["missing_bindings"])
			}
			if test.wantNoDigest != "" {
				if diagnostic.Details["binding"] != test.wantNoDigest {
					t.Fatalf("binding = %#v, want %#v", diagnostic.Details["binding"], test.wantNoDigest)
				}
			} else if _, found := diagnostic.Details["binding"]; found {
				t.Fatalf("binding = %#v, want absent", diagnostic.Details["binding"])
			}
		})
	}
}

func TestReadRecordedRelayRunsRequiresPlannedArtifactBinding(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	bindings := plannedRelayInputBindingsForTest(t, state.Config, batch)
	bindings[2] = boundInput("artifact", filepath.Join(state.Config.StateDir, "extra-artifact.json"), digest.RawBytes([]byte("extra artifact")))
	writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         batch.BatchID,
		Status:          contracts.RecordStatusUnavailable,
		RecipeID:        batch.RecipeID,
		InputBindings:   bindings,
		ProviderInvoked: relayrun.ProviderInvokedUnknown,
		ConsumesBatch:   true,
	})

	_, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch})
	if err == nil {
		t.Fatal("readRecordedRelayRuns accepted a consuming record without the planned snapshot artifact binding")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeInvalidState || diagnostic.Details["binding"] != "artifact" || diagnostic.Details["expected_path"] != state.Config.SnapshotManifestPath {
		t.Fatalf("diagnostic = %#v, want planned artifact binding rejection", diagnostic)
	}
}

func TestReadRecordedRelayRunsValidatesAdditionalArtifactBindings(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	extraPath := filepath.Join(state.Config.StateDir, "extra-artifact.json")
	for _, test := range []struct {
		name    string
		binding string
		wantErr bool
	}{
		{
			name:    "well-formed",
			binding: boundInput("artifact", extraPath, digest.RawBytes([]byte("extra artifact"))),
		},
		{
			name:    "missing digest",
			binding: "artifact=" + extraPath,
			wantErr: true,
		},
		{
			name:    "malformed digest",
			binding: "artifact=" + extraPath + "@sha256:not-a-digest",
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindings := append(plannedRelayInputBindingsForTest(t, state.Config, batch), test.binding)
			writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
				SchemaVersion:   relayrun.RunRecordSchema,
				BatchID:         batch.BatchID,
				Status:          contracts.RecordStatusUnavailable,
				RecipeID:        batch.RecipeID,
				InputBindings:   bindings,
				ProviderInvoked: relayrun.ProviderInvokedUnknown,
				ConsumesBatch:   true,
			})

			_, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch})
			if test.wantErr {
				if err == nil {
					t.Fatal("readRecordedRelayRuns accepted a malformed additional artifact binding")
				}
				diagnostic := diag.FromError(err)
				if diagnostic.Code != CodeInvalidState || diagnostic.Details["binding"] != "artifact" {
					t.Fatalf("diagnostic = %#v, want additional artifact binding rejection", diagnostic)
				}
				return
			}
			if err != nil {
				t.Fatalf("readRecordedRelayRuns rejected a well-formed additional artifact binding: %v", err)
			}
		})
	}
}

func TestReadRecordedRelayRunsAllowsNoBindingsForNonConsumingLaunchFailure(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         batch.BatchID,
		Status:          relayrun.RunStatusLaunchFailed,
		RecipeID:        batch.RecipeID,
		ProviderInvoked: relayrun.ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch: &relayrun.LaunchRecord{
			ExitCode:    -1,
			StartFailed: true,
		},
	})

	runs, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch})
	if err != nil {
		t.Fatalf("readRecordedRelayRuns rejected a non-consuming launch failure without bindings: %v", err)
	}
	if recorded, found := runs[batch.BatchID]; !found || recorded.Record.ConsumesBatch {
		t.Fatalf("recorded runs = %#v, want one non-consuming record", runs)
	}
}

func TestValidateMandatoryStageArtifactsPropagatesInvalidRecordedRelayRun(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, state *State, batch RelayBatchRecord)
	}{
		{
			name: "malformed JSON",
			mutate: func(t *testing.T, state *State, batch RelayBatchRecord) {
				t.Helper()
				if err := os.WriteFile(relayRunRecordPath(state.Config, batch.BatchID), []byte(`{"schema_version":`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "rebound input",
			mutate: func(t *testing.T, state *State, batch RelayBatchRecord) {
				t.Helper()
				bindings := plannedRelayInputBindingsForTest(t, state.Config, batch)
				bindings[1] = boundInput("findings", filepath.Join(state.Config.StateDir, "other-batch.json"), batch.BatchDigest)
				writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
					SchemaVersion:   relayrun.RunRecordSchema,
					BatchID:         batch.BatchID,
					Status:          contracts.RecordStatusUnavailable,
					RecipeID:        batch.RecipeID,
					InputBindings:   bindings,
					ProviderInvoked: relayrun.ProviderInvokedUnknown,
					ConsumesBatch:   true,
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
			writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
				SchemaVersion:   relayrun.RunRecordSchema,
				BatchID:         batch.BatchID,
				Status:          contracts.RecordStatusUnavailable,
				RecipeID:        batch.RecipeID,
				InputBindings:   plannedRelayInputBindingsForTest(t, state.Config, batch),
				ProviderInvoked: relayrun.ProviderInvokedUnknown,
				ConsumesBatch:   true,
			})

			inputs, outputs, err := mandatoryArtifactsForStage(state, StageRecord{Name: stageAssemble, Status: statusComplete})
			if err != nil {
				t.Fatalf("mandatoryArtifactsForStage with valid run record: %v", err)
			}
			inputsWithoutRunRecord := make([]artifactInput, 0, len(inputs)-1)
			for _, input := range inputs {
				if input.role != "relay-run-record:"+batch.BatchID {
					inputsWithoutRunRecord = append(inputsWithoutRunRecord, input)
				}
			}
			inputRecords, err := artifactRecordsForExistingFiles(inputsWithoutRunRecord)
			if err != nil {
				t.Fatal(err)
			}
			for _, output := range outputs {
				if _, err := os.Stat(output.path); err == nil {
					continue
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(output.path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(output.path, []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			outputRecords, err := artifactRecordsForExistingFiles(outputs)
			if err != nil {
				t.Fatal(err)
			}
			state.Stages = append(state.Stages, StageRecord{
				Name:    stageAssemble,
				Status:  statusComplete,
				Inputs:  inputRecords,
				Outputs: outputRecords,
			})

			test.mutate(t, state, batch)
			_, err = readRecordedRelayRuns(state, []RelayBatchRecord{batch})
			if err == nil {
				t.Fatal("invalid relay run record was accepted before mandatory-artifact validation")
			}
			want := diag.FromError(err)
			diagnostics := validateMandatoryStageArtifacts(state)
			for _, diagnostic := range diagnostics {
				if diagnostic.Code == want.Code && diagnostic.Message == want.Message && reflect.DeepEqual(diagnostic.Details, want.Details) {
					return
				}
			}
			t.Fatalf("state validation diagnostics = %#v, want propagated relay-run diagnostic %#v", diagnostics, want)
		})
	}
}

func TestReadRecordedRelayRunsRejectsReboundIntegrationBundle(t *testing.T) {
	options, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	validBindings := plannedRelayInputBindingsForTest(t, state.Config, batch)
	retainedPath, err := retainedIntegrationBundlePath(state.Config)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		binding string
	}{
		{
			name:    "wrong path",
			binding: boundInput("integration_bundle", filepath.Join(options.StateDir, "other-integration-bundle.body.json"), preflightResult.ContractDigests["integration_bundle"]),
		},
		{
			name:    "wrong digest",
			binding: boundInput("integration_bundle", retainedPath, digest.RawBytes([]byte("wrong integration bundle"))),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindings := append([]string(nil), validBindings...)
			bindings[len(bindings)-1] = test.binding
			writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
				SchemaVersion:   relayrun.RunRecordSchema,
				BatchID:         batch.BatchID,
				Status:          contracts.RecordStatusUnavailable,
				RecipeID:        batch.RecipeID,
				InputBindings:   bindings,
				ProviderInvoked: relayrun.ProviderInvokedUnknown,
				ConsumesBatch:   true,
			})

			_, err := readRecordedRelayRuns(state, []RelayBatchRecord{batch})
			if err == nil {
				t.Fatal("readRecordedRelayRuns accepted a rebound integration bundle")
			}
			diagnostic := diag.FromError(err)
			if diagnostic.Code != CodeInvalidState || diagnostic.Details["binding"] != "integration_bundle" {
				t.Fatalf("diagnostic = %#v, want integration-bundle binding rejection", diagnostic)
			}
		})
	}
}

func TestValidateRecordedRelayRunBindingsAcceptsAtInPath(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	state.Config.Outputs.CharterFreezePath = filepath.Join(t.TempDir(), "user@example", "charter.freeze.json")
	preflightResult := readJSONForTest[preflight.Result](t, state.Config.Outputs.PreflightPath)
	integrationBundlePath, err := retainedIntegrationBundlePath(state.Config)
	if err != nil {
		t.Fatal(err)
	}

	record := relayrun.RunRecord{InputBindings: []string{
		boundInput("charter", state.Config.Outputs.CharterFreezePath, stageOutputDigest(state, "charter-freeze")),
		boundInput("findings", batch.BatchPath, batch.BatchDigest),
		boundInput("artifact", state.Config.SnapshotManifestPath, stageOutputDigest(state, "source-snapshot-manifest")),
		boundInput("integration_bundle", integrationBundlePath, preflightResult.ContractDigests["integration_bundle"]),
	}}
	if err := validateRecordedRelayRunBindings(state, batch, record, preflightResult.ContractDigests["integration_bundle"]); err != nil {
		t.Fatalf("validateRecordedRelayRunBindings rejected a path containing @: %v", err)
	}
}

func TestRelayEvidenceForAssemblyMergesRecordedUnavailableAndReadyPortable(t *testing.T) {
	_, state, unavailableBatch, portableBatch := readyPassAtTwoRelayBatchesForTest(t)
	writeRecordedRelayRunForTest(t, state.Config, unavailableBatch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         unavailableBatch.BatchID,
		Status:          contracts.RecordStatusUnavailable,
		RecipeID:        unavailableBatch.RecipeID,
		InputBindings:   plannedRelayInputBindingsForTest(t, state.Config, unavailableBatch),
		ProviderInvoked: relayrun.ProviderInvokedUnknown,
		ConsumesBatch:   true,
	})
	legacyManifestPath := filepath.Join(portableBatch.PortableExportDir, "manifest.json")
	if err := os.MkdirAll(filepath.Dir(legacyManifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyManifestPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	evidence, recordedRuns, err := relayEvidenceForAssembly(state, state.RelayBatches)
	if err != nil {
		t.Fatalf("relayEvidenceForAssembly: %v", err)
	}
	if len(evidence) != 2 || len(recordedRuns) != 1 {
		t.Fatalf("evidence = %#v, recorded runs = %#v; want one source for each planned batch", evidence, recordedRuns)
	}
	evidenceByBatchID := make(map[string]planning.RelayEvidence, len(evidence))
	for _, item := range evidence {
		evidenceByBatchID[item.BatchID] = item
	}
	if got := evidenceByBatchID[unavailableBatch.BatchID]; len(got.RunRecords) != 1 || got.PortableExportDir != "" {
		t.Fatalf("recorded unavailable evidence = %#v, want retained run-record evidence", got)
	}
	if got := evidenceByBatchID[portableBatch.BatchID]; len(got.RunRecords) != 0 || got.PortableExportDir != portableBatch.PortableExportDir {
		t.Fatalf("legacy ready evidence = %#v, want portable export evidence", got)
	}

	plan := readJSONForTest[planning.PlanDocument](t, state.Config.Outputs.PlanPath)
	batches, err := readBatchEvidence(state.RelayBatches)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := manifestEvidenceRefs(state.Config, plan.ConsumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	result, err := planning.Assemble(planning.AssembleOptions{
		Plan:         plan,
		Batches:      batches,
		RelayResults: evidence,
		EvidenceRefs: refs,
	})
	if err == nil {
		t.Fatal("Assemble accepted the deliberately incomplete legacy portable export")
	}
	if result == nil || !containsStringForTest(result.PendingVerification, "defect-1") {
		t.Fatalf("assemble result = %#v, want unavailable finding pending verification", result)
	}
	for _, manifestBatch := range result.Manifest.Batches {
		if manifestBatch.BatchID == unavailableBatch.BatchID && manifestBatch.FailureReason != "relay_run_recorded_unavailable" {
			t.Fatalf("unavailable manifest batch = %#v, want recorded-unavailable reason", manifestBatch)
		}
	}
}

func TestPassResumeKeepsCallerRelayBatchForRecordedLaunchFailure(t *testing.T) {
	options, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         batch.BatchID,
		Status:          relayrun.RunStatusLaunchFailed,
		RecipeID:        batch.RecipeID,
		InputBindings:   plannedRelayInputBindingsForTest(t, state.Config, batch),
		ProviderInvoked: relayrun.ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch: &relayrun.LaunchRecord{
			ExitCode:    -1,
			StartFailed: true,
		},
	})

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume with recorded launch failure: %v", err)
	}
	if invocation.StageRun != "" || invocation.Complete || invocation.NextAction.Type != actionCallerRelayBatch || invocation.NextAction.RelayBatch == nil || invocation.NextAction.RelayBatch.BatchID != batch.BatchID {
		t.Fatalf("invocation = %#v, want caller relay batch retry", invocation)
	}
}

func TestNextRelayBatchActionUsesReadyPortableExportAfterLaunchFailure(t *testing.T) {
	_, state, batch := readyPassAtRelayBatchActionForTest(t, true)
	writeRecordedRelayRunForTest(t, state.Config, batch, relayrun.RunRecord{
		SchemaVersion:   relayrun.RunRecordSchema,
		BatchID:         batch.BatchID,
		Status:          relayrun.RunStatusLaunchFailed,
		RecipeID:        batch.RecipeID,
		InputBindings:   plannedRelayInputBindingsForTest(t, state.Config, batch),
		ProviderInvoked: relayrun.ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch: &relayrun.LaunchRecord{
			ExitCode:    -1,
			StartFailed: true,
		},
	})
	manifestPath := filepath.Join(batch.PortableExportDir, "manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	action, err := nextRelayBatchAction(state)
	if err != nil {
		t.Fatalf("nextRelayBatchAction: %v", err)
	}
	if action != nil {
		t.Fatalf("nextRelayBatchAction = %#v, want ready portable export to complete the batch", action)
	}
	if len(state.RelayBatches) != 1 || state.RelayBatches[0].Status != statusComplete {
		t.Fatalf("relay batches = %#v, want one completed portable-export batch", state.RelayBatches)
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
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("relayrun.RunBatches(")) {
				t.Fatalf("%s invokes relayrun.RunBatches; the pass driver may read validated records but must not launch relay", path)
			}
		}
	}
}

func readyPassAtRelayBatchActionForTest(t *testing.T, withFinding bool) (BeginOptions, *State, RelayBatchRecord) {
	t.Helper()
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	preflightResult := writeReadyPreflightForTest(t, state.Config)
	if err := validatePreflightOutput(state.Config, preflightResult); err != nil {
		t.Fatalf("ready preflight does not validate: %v", err)
	}
	inputs, err := artifactRecordsForExistingFiles(preflightInputSpecs(state.Config))
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := artifactRecordsForExistingFiles(preflightOutputSpecs(state.Config, &preflightResult))
	if err != nil {
		t.Fatal(err)
	}
	markStageComplete(state, StageRecord{
		Name:    stagePreflight,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"relay_absent":        false,
			"backend_strata":      cloneStringMap(preflightResult.BackendStrata),
			"source_dirty":        preflightResult.SourceDirty,
			"source_dirty_status": preflightResult.SourceDirtyStatus,
		},
	})
	if err := setNextAction(state); err != nil {
		t.Fatal(err)
	}
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume to role outputs: %v", err)
	}
	if invocation.NextAction.Type != actionCallerRoleOutputs {
		t.Fatalf("next action = %#v, want caller role outputs", invocation.NextAction)
	}
	writeRoleOutputsForState(t, options.StateDir, withFinding)

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	if invocation.StageRun != stagePlan || invocation.NextAction.Type != actionCallerRelayBatch {
		t.Fatalf("plan invocation = %#v, want caller relay batch", invocation)
	}
	state = readPassStateForTest(t, options.StateDir)
	if len(state.RelayBatches) != 1 {
		t.Fatalf("relay batches = %#v, want one", state.RelayBatches)
	}
	return options, state, state.RelayBatches[0]
}

func readyPassAtTwoRelayBatchesForTest(t *testing.T) (BeginOptions, *State, RelayBatchRecord, RelayBatchRecord) {
	t.Helper()
	options := newBeginOptions(t)
	if _, err := Begin(context.Background(), options); err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := readPassStateForTest(t, options.StateDir)
	preflightResult := writeReadyPreflightForTest(t, state.Config)
	if err := validatePreflightOutput(state.Config, preflightResult); err != nil {
		t.Fatalf("ready preflight does not validate: %v", err)
	}
	inputs, err := artifactRecordsForExistingFiles(preflightInputSpecs(state.Config))
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := artifactRecordsForExistingFiles(preflightOutputSpecs(state.Config, &preflightResult))
	if err != nil {
		t.Fatal(err)
	}
	markStageComplete(state, StageRecord{
		Name:    stagePreflight,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"relay_absent":        false,
			"backend_strata":      cloneStringMap(preflightResult.BackendStrata),
			"source_dirty":        preflightResult.SourceDirty,
			"source_dirty_status": preflightResult.SourceDirtyStatus,
		},
	})
	if err := setNextAction(state); err != nil {
		t.Fatal(err)
	}
	if err := writeState(state); err != nil {
		t.Fatal(err)
	}

	invocation, err := Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume to role outputs: %v", err)
	}
	if invocation.NextAction.Type != actionCallerRoleOutputs {
		t.Fatalf("next action = %#v, want caller role outputs", invocation.NextAction)
	}
	writeRoleOutputsForState(t, options.StateDir, true)
	state = readPassStateForTest(t, options.StateDir)
	var economyOutputPath string
	for _, output := range state.Config.RoleOutputs {
		if output.Role == contracts.RoleEconomy {
			economyOutputPath = output.Path
			break
		}
	}
	if economyOutputPath == "" {
		t.Fatal("pass config did not include an economy role output")
	}
	economyOutput := readJSONForTest[contracts.RoleOutputDocument](t, economyOutputPath)
	economyOutput.Findings = []contracts.Finding{economyFindingForTest()}
	writeCanonicalForTest(t, economyOutputPath, economyOutput)

	invocation, err = Resume(context.Background(), ResumeOptions{StateDir: options.StateDir})
	if err != nil {
		t.Fatalf("resume plan: %v", err)
	}
	if invocation.StageRun != stagePlan || invocation.NextAction.Type != actionCallerRelayBatch {
		t.Fatalf("plan invocation = %#v, want caller relay batch", invocation)
	}
	state = readPassStateForTest(t, options.StateDir)
	var unavailableBatch, portableBatch *RelayBatchRecord
	for index := range state.RelayBatches {
		batch := &state.RelayBatches[index]
		switch batch.Role {
		case contracts.RoleDefect:
			unavailableBatch = batch
		case contracts.RoleEconomy:
			portableBatch = batch
		}
	}
	if unavailableBatch == nil || portableBatch == nil {
		t.Fatalf("relay batches = %#v, want defect and economy batches", state.RelayBatches)
	}
	return options, state, *unavailableBatch, *portableBatch
}

func writeRecordedRelayRunForTest(t *testing.T, config Config, batch RelayBatchRecord, record relayrun.RunRecord) {
	t.Helper()
	path := relayRunRecordPath(config, batch.BatchID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCanonicalForTest(t, path, record)
}

func plannedRelayInputBindingsForTest(t *testing.T, config Config, batch RelayBatchRecord) []string {
	t.Helper()
	charterDigest, err := computeArtifactDigest(config.Outputs.CharterFreezePath, digest.ClassRawBytes)
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest, err := computeArtifactDigest(config.SnapshotManifestPath, digestClassFreezeManifest)
	if err != nil {
		t.Fatal(err)
	}
	preflightResult := readJSONForTest[preflight.Result](t, config.Outputs.PreflightPath)
	integrationBundlePath, err := retainedIntegrationBundlePath(config)
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		boundInput("charter", config.Outputs.CharterFreezePath, charterDigest),
		boundInput("findings", batch.BatchPath, batch.BatchDigest),
		boundInput("artifact", config.SnapshotManifestPath, snapshotDigest),
		boundInput("integration_bundle", integrationBundlePath, preflightResult.ContractDigests["integration_bundle"]),
	}
}

func economyFindingForTest() contracts.Finding {
	return contracts.Finding{
		ID:              "economy-1",
		Kind:            contracts.FindingKindEconomy,
		Title:           "Remove redundant verification branch",
		CharterGoalIDs:  []string{"goal-1"},
		ClaimedSeverity: contracts.SeverityMedium,
		Witness: contracts.Witness{
			Kind:     contracts.WitnessKindEquivalence,
			Strength: contracts.WitnessStrengthArgued,
			Content:  "The retained branch preserves the reviewed behavior.",
		},
		EstimatedDelta: contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: -1},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 0},
		},
		SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
			Direction:          contracts.RemedyDirectionRemove,
			Summary:            "Remove the redundant branch.",
			MinimalityArgument: "The remaining branch preserves the declared behavior.",
		},
	}
}

func containsStringForTest(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func runPassGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
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
		Size:   strictjson.Int64(len(content)),
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
		RelayReportedDigests: map[string]string{},
		BackendStrata:        map[string]string{"claude": "ready", "codex": "ready"},
		SnapshotDigest:       snapshotDigest,
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
	result.ArtifactDigests[preflight.RetainedIntegrationBundleEnvelopeFile] = retainPreflightPayloadForTest(t, config.StateDir, preflight.RetainedIntegrationBundleEnvelopeFile, bundlePayload)
	bundleBody, err := os.ReadFile(config.IntegrationBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.StateDir, preflight.RetainedIntegrationBundleBodyFile), bundleBody, 0o644); err != nil {
		t.Fatal(err)
	}
	result.ArtifactDigests[preflight.RetainedIntegrationBundleBodyFile] = bundleDigest
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
		result.RelayReportedDigests[requirement.ContractID] = selectedDigests[requirement.ContractID]
		result.ArtifactDigests[planRelative] = retainPreflightPayloadForTest(t, config.StateDir, planRelative, plan)
		result.RecipePlanDigests[requirement.RecipeID] = result.ArtifactDigests[planRelative]
	}
	contractDigestDoc := preflight.ContractDigestDocument(result)
	result.ArtifactDigests["contract-digests.json"] = retainPreflightPayloadForTest(t, config.StateDir, "contract-digests.json", contractDigestDoc)
	result.ArtifactDigests["compatibility-manifest.json"] = retainPreflightPayloadForTest(t, config.StateDir, "compatibility-manifest.json", expectedPreflightCompatibility(result))
	result.RetainedArtifacts = preflight.RetainedArtifacts(config.StateDir, config.SnapshotManifestPath, result.ArtifactDigests)
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
