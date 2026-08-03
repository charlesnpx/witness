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

	"witness/internal/adjudicate"
	"witness/internal/canonjson"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/harness"
	"witness/internal/ledger"
	"witness/internal/planning"
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
	assertLedgerKindsEqual(t, driverRecords, serviceRecords)
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
		RelayBatches: []RelayBatchRecord{{
			BatchID:           "batch-1",
			RecipeFamily:      "witness-falsify-v2",
			RecipeID:          "witness-falsify-v2-codex",
			BatchPath:         filepath.Join(stateDir, "verification", "batches", "batch-1.json"),
			BatchDigest:       batchDigest,
			PortableExportDir: filepath.Join(stateDir, "verification", "sessions", "batch-1"),
		}},
	}
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

func diagCode(err error) string {
	if err == nil {
		return ""
	}
	return diag.FromError(err).Code
}

func assertLedgerKindsEqual(t *testing.T, left []ledger.Record, right []ledger.Record) {
	t.Helper()
	leftKinds := ledgerKinds(left)
	rightKinds := ledgerKinds(right)
	if len(leftKinds) != len(rightKinds) {
		t.Fatalf("ledger kinds length = %d, want %d; left=%#v right=%#v", len(leftKinds), len(rightKinds), leftKinds, rightKinds)
	}
	for index := range leftKinds {
		if leftKinds[index] != rightKinds[index] {
			t.Fatalf("ledger kinds = %#v, want %#v", leftKinds, rightKinds)
		}
	}
}

func ledgerKinds(records []ledger.Record) []string {
	kinds := make([]string, 0, len(records))
	for _, record := range records {
		kinds = append(kinds, record.EventKind)
	}
	return kinds
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
