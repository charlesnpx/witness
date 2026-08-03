package pass

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"witness/internal/adjudicate"
	"witness/internal/canonjson"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/preflight"
	"witness/internal/strictjson"
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
		"witness/internal/relayclient": true,
		"witness/internal/relayrun":    true,
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

func readPassStateForTest(t *testing.T, stateDir string) *State {
	t.Helper()
	state, err := readState(filepath.Join(stateDir, StateFileName))
	if err != nil {
		t.Fatal(err)
	}
	return state
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
