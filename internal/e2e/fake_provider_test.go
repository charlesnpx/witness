package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/harness"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/metrics"
	"github.com/charlesnpx/witness/internal/preflight"
)

type binaries struct {
	witness string
	harness string
	relay   string
}

type passResult struct {
	dir             string
	preflightPath   string
	runResultPath   string
	metricsPath     string
	ledgerShowPath  string
	runsIndexPath   string
	policyCheckPath string
	result          adjudicate.Result
	metrics         metrics.Document
	ledgerShow      ledger.ShowDocument
	runs            relayRunsDocument
	policyCheck     map[string]any
}

type relayRunsDocument struct {
	SchemaVersion string           `json:"schema_version"`
	Runs          []relayRunRecord `json:"runs"`
}

type relayRunRecord struct {
	BatchID  string `json:"batch_id"`
	Status   string `json:"status"`
	RecipeID string `json:"recipe_id"`
}

func TestFakeProviderEndToEndPasses(t *testing.T) {
	bins := buildBinaries(t)
	successes := []struct {
		name             string
		backend          string
		wantRecipeIDs    []string
		wantRelayBackend string
	}{
		{
			name: "mixed",
			wantRecipeIDs: []string{
				"economy-equivalence-v2",
				"witness-falsify-v2",
			},
		},
		{
			name:             "codex only",
			backend:          "codex",
			wantRelayBackend: "codex",
			wantRecipeIDs: []string{
				"economy-equivalence-v2-codex",
				"witness-falsify-v2-codex",
			},
		},
		{
			name:             "claude only",
			backend:          "claude",
			wantRelayBackend: "claude",
			wantRecipeIDs: []string{
				"economy-equivalence-v2-claude",
				"witness-falsify-v2-claude",
			},
		},
	}
	for _, test := range successes {
		t.Run(test.name, func(t *testing.T) {
			pass := runFakeProviderPass(t, bins, test.backend, false)
			assertSuccessfulPass(t, pass, test.wantRelayBackend, test.wantRecipeIDs)
		})
	}

	t.Run("relay launch failure stays pending", func(t *testing.T) {
		pass := runFakeProviderPass(t, bins, "codex", true)
		if pass.result.Summary.PendingVerification != 2 || pass.result.Summary.Admitted != 0 {
			t.Fatalf("summary = %#v, want 2 pending and 0 admitted", pass.result.Summary)
		}
		for _, finding := range pass.result.Findings {
			if finding.Disposition != contracts.DispositionPendingVerification {
				t.Fatalf("%s disposition = %s, want pending_verification", finding.FindingID, finding.Disposition)
			}
			if finding.Relay == nil || finding.Relay.Status != contracts.RecordStatusUnavailable {
				t.Fatalf("%s relay = %#v, want unavailable", finding.FindingID, finding.Relay)
			}
			if finding.Relay.Backend != "codex" {
				t.Fatalf("%s relay backend = %q, want codex", finding.FindingID, finding.Relay.Backend)
			}
			assertStringSliceContains(t, finding.Reasons, adjudicate.ReasonRelayVerificationUnavailable)
		}
		assertRunRecipeIDs(t, pass.runs, []string{
			"economy-equivalence-v2-codex",
			"witness-falsify-v2-codex",
		})
		if pass.metrics.PendingVerification.Total != 2 {
			t.Fatalf("pending metrics total = %d, want 2", pass.metrics.PendingVerification.Total)
		}
		assertPendingStratum(t, pass.metrics, "codex", metrics.BackendAuthStatusInstalledAuthUnknown, 2)
		assertLedgerKinds(t, pass.ledgerShow, map[string]int{
			ledger.EventKindAdjudicationRun:     1,
			ledger.EventKindVerdict:             2,
			ledger.EventKindPendingVerification: 2,
			ledger.EventKindPolicyDecision:      3,
			ledger.EventKindMeasuredDelta:       1,
		})
	})
}

func assertSuccessfulPass(t *testing.T, pass passResult, wantRelayBackend string, wantRecipeIDs []string) {
	t.Helper()
	if pass.result.Summary.Admitted != 2 || pass.result.Summary.PendingVerification != 0 || pass.result.Summary.Advisory != 0 {
		t.Fatalf("summary = %#v, want 2 admitted and no pending/advisory", pass.result.Summary)
	}
	if pass.result.Summary.AutomaticCandidate != 1 || pass.result.Summary.CallerDecision != 1 {
		t.Fatalf("application summary = %#v, want 1 automatic and 1 caller decision", pass.result.Summary)
	}
	findings := findingsByID(pass.result)
	defect := findings["defect-exec"]
	if defect.FindingID == "" {
		t.Fatal("missing defect-exec verdict")
	}
	if defect.Disposition != contracts.DispositionAdmitted || defect.ApplicationClass != contracts.ApplicationClassCallerDecision {
		t.Fatalf("defect verdict = %#v, want admitted/caller_decision", defect)
	}
	if defect.Execution == nil || defect.Execution.VerificationClassification != harness.ClassificationValid {
		t.Fatalf("defect execution = %#v, want valid receipt", defect.Execution)
	}
	assertRelay(t, defect, "witness-falsify-v2", wantRelayBackend)
	assertStringSliceContains(t, defect.Reasons, adjudicate.ReasonRelaySurvived)

	economy := findings["economy-remove"]
	if economy.FindingID == "" {
		t.Fatal("missing economy-remove verdict")
	}
	if economy.Disposition != contracts.DispositionAdmitted || economy.ApplicationClass != contracts.ApplicationClassAutomaticCandidate {
		t.Fatalf("economy verdict = %#v, want admitted/automatic_candidate", economy)
	}
	assertRelay(t, economy, "economy-equivalence-v2", wantRelayBackend)

	if pass.metrics.Verdicts.Survived != 2 || pass.metrics.PendingVerification.Total != 0 {
		t.Fatalf("metrics verdicts=%#v pending=%#v, want 2 survived and 0 pending", pass.metrics.Verdicts, pass.metrics.PendingVerification)
	}
	assertRunRecipeIDs(t, pass.runs, wantRecipeIDs)
	assertLedgerKinds(t, pass.ledgerShow, map[string]int{
		ledger.EventKindAdjudicationRun: 1,
		ledger.EventKindVerdict:         2,
		ledger.EventKindPolicyDecision:  3,
		ledger.EventKindMeasuredDelta:   1,
	})
	if allow, _ := pass.policyCheck["allow"].(bool); allow {
		t.Fatalf("policy check allow = true, want false under caller-decision defect change")
	}
}

func assertRelay(t *testing.T, finding adjudicate.FindingVerdict, recipeFamily string, backend string) {
	t.Helper()
	if finding.Relay == nil {
		t.Fatalf("%s missing relay metadata", finding.FindingID)
	}
	if finding.Relay.Status != contracts.RecordStatusValid || finding.Relay.Verdict != contracts.VerdictSurvived {
		t.Fatalf("%s relay = %#v, want valid survived", finding.FindingID, finding.Relay)
	}
	if finding.Relay.RecipeFamily != recipeFamily {
		t.Fatalf("%s recipe family = %q, want %q", finding.FindingID, finding.Relay.RecipeFamily, recipeFamily)
	}
	if finding.Relay.Backend != backend {
		t.Fatalf("%s backend = %q, want %q", finding.FindingID, finding.Relay.Backend, backend)
	}
}

func runFakeProviderPass(t *testing.T, bins binaries, backend string, failRelay bool) passResult {
	t.Helper()
	root := t.TempDir()
	passDir := filepath.Join(root, "pass")
	mustMkdir(t, passDir)
	resultsDir := filepath.Join(root, "results")
	mustMkdir(t, resultsDir)
	sourceDir := filepath.Join(root, "source")
	mustMkdir(t, sourceDir)
	writeFile(t, filepath.Join(sourceDir, "app.txt"), []byte("ok\n"), 0o644)

	charterPath := filepath.Join(resultsDir, "charter.json")
	runOK(t, nil, bins.witness, "charter", "init", "-out", charterPath, "-actor", "owner", "-event-id", "initial-charter")
	writeCharter(t, charterPath)
	frozenPath := filepath.Join(resultsDir, "charter.freeze.json")
	runOK(t, nil, bins.witness, "charter", "freeze", "-charter", charterPath, "-out", frozenPath)
	frozen := readJSON[charter.FrozenCharter](t, frozenPath)

	preflightPath := filepath.Join(resultsDir, "preflight.json")
	snapshotDir := filepath.Join(root, "snapshot")
	bundlePath := filepath.Join(repoRoot(t), "testdata", "preflight", "integration-bundle-v2.fixture.json")
	runOK(t, nil, bins.witness,
		"verification", "preflight",
		"-relay", bins.relay,
		"-integration-bundle", bundlePath,
		"-state-dir", passDir,
		"-source-dir", sourceDir,
		"-snapshot-dir", snapshotDir,
		"-allow-non-git-source",
		"-out", preflightPath,
	)
	preflightResult := readJSON[preflight.Result](t, preflightPath)
	if !preflightResult.OK {
		t.Fatalf("preflight diagnostics = %#v", preflightResult.Diagnostics)
	}
	if preflightResult.SnapshotDigest == "" {
		t.Fatal("preflight did not produce a snapshot digest")
	}

	executable := contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "stdout_contains=ok",
	}
	defectPath := filepath.Join(resultsDir, "defect-output.json")
	economyPath := filepath.Join(resultsDir, "economy-output.json")
	writeRoleOutputs(t, frozen, preflightResult.SnapshotDigest, executable, defectPath, economyPath)

	keyPath := filepath.Join(resultsDir, "receipt.key")
	writeFile(t, keyPath, []byte("e2e-hmac-key"), 0o600)
	receiptDir := filepath.Join(resultsDir, "verification", "receipts")
	requestPath := filepath.Join(resultsDir, "harness-request.json")
	writeHarnessRequest(t, requestPath, frozen.CharterHash, preflightResult.SnapshotDigest, filepath.Join(snapshotDir, "manifest.json"), executable, keyPath)
	harnessOut := runOK(t, nil, bins.harness, "run", "-request", requestPath, "-out-dir", receiptDir)
	var harnessResult struct {
		ReceiptPath string `json:"receipt_path"`
	}
	decodeBytes(t, harnessOut.stdout, &harnessResult)
	if harnessResult.ReceiptPath == "" {
		t.Fatalf("harness output missing receipt_path: %s", harnessOut.stdout)
	}

	planPath := filepath.Join(resultsDir, "verification-plan.json")
	runOK(t, nil, bins.witness,
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-state-dir", passDir,
		"-role-output", defectPath,
		"-role-output", economyPath,
		"-out", planPath,
	)

	manifestPath := filepath.Join(resultsDir, "verification", "index.json")
	assembleArgs := []string{
		"verification", "assemble",
		"-plan", planPath,
		"-state-dir", passDir,
		"-run-relay",
		"-relay", bins.relay,
		"-relay-home", filepath.Join(resultsDir, "relay-home"),
		"-integration-bundle", bundlePath,
		"-charter-freeze", frozenPath,
		"-artifact", filepath.Join(snapshotDir, "manifest.json"),
		"-compatibility-manifest", filepath.Join(passDir, "compatibility-manifest.json"),
		"-relay-capabilities", filepath.Join(passDir, "relay-capabilities.json"),
		"-selected-contract", bundlePath,
		"-receipt", harnessResult.ReceiptPath,
		"-receipt-output-dir", receiptDir,
		"-receipt-hmac-key-file", keyPath,
		"-out", manifestPath,
	}
	if backend != "" {
		assembleArgs = append(assembleArgs, "-backend", backend)
	}
	env := map[string]string{}
	if failRelay {
		env["WITNESS_FAKE_RELAY_FAIL_RUN"] = "1"
	}
	runOK(t, env, bins.witness, assembleArgs...)

	ledgerPath := filepath.Join(resultsDir, "ledger.jsonl")
	runResultPath := filepath.Join(resultsDir, "run-result.json")
	runOK(t, nil, bins.witness,
		"adjudicate",
		"-charter-freeze", frozenPath,
		"-manifest", manifestPath,
		"-receipt-output-dir", receiptDir,
		"-receipt-hmac-key-file", keyPath,
		"-role-output", defectPath,
		"-role-output", economyPath,
		"-ledger", ledgerPath,
		"-out", runResultPath,
	)

	policyCheckPath := filepath.Join(resultsDir, "policy-check.json")
	runOK(t, nil, bins.witness,
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-charter-freeze", frozenPath,
		"-role", contracts.RoleDefect,
		"-remedy-direction", contracts.RemedyDirectionChange,
		"-remedy-sign", "positive",
		"-estimated-production-status", contracts.DeltaStatusKnown,
		"-estimated-production-lines", "2",
		"-estimated-test-status", contracts.DeltaStatusKnown,
		"-estimated-test-lines", "4",
		"-measured-production", "2",
		"-measured-test", "4",
		"-finding-id", "defect-exec",
		"-out", policyCheckPath,
	)

	metricsPath := filepath.Join(resultsDir, "metrics.json")
	runOK(t, nil, bins.witness,
		"metrics",
		"-ledger", ledgerPath,
		"-preflight", preflightPath,
		"-run-result", runResultPath,
		"-out", metricsPath,
	)
	ledgerShowPath := filepath.Join(resultsDir, "ledger-show.json")
	runOK(t, nil, bins.witness, "ledger", "show", "-ledger", ledgerPath, "-out", ledgerShowPath)

	return passResult{
		dir:             passDir,
		preflightPath:   preflightPath,
		runResultPath:   runResultPath,
		metricsPath:     metricsPath,
		ledgerShowPath:  ledgerShowPath,
		runsIndexPath:   filepath.Join(passDir, "verification", "runs", "index.json"),
		policyCheckPath: policyCheckPath,
		result:          readJSON[adjudicate.Result](t, runResultPath),
		metrics:         readJSON[metrics.Document](t, metricsPath),
		ledgerShow:      readJSON[ledger.ShowDocument](t, ledgerShowPath),
		runs:            readJSON[relayRunsDocument](t, filepath.Join(passDir, "verification", "runs", "index.json")),
		policyCheck:     readJSON[map[string]any](t, policyCheckPath),
	}
}

func writeCharter(t *testing.T, path string) {
	t.Helper()
	base := readJSON[charter.Charter](t, path)
	base.Goals = []charter.Statement{{
		ID:        "goal-cli",
		Statement: "The CLI reports accepted input deterministically.",
	}}
	base.OperationalEnvelope = &charter.OperationalEnvelope{
		EntryPoints: &charter.Dimension{
			State:     charter.StateBounded,
			Statement: "Declared entry points.",
			Entries:   []charter.Entry{{ID: "cli", Statement: "Command line interface."}},
		},
		InputSurface: &charter.Dimension{
			State:     charter.StateUnbounded,
			Statement: "Caller supplied request payloads.",
			Entries:   []charter.Entry{},
		},
		ValidStates: &charter.Dimension{
			State:     charter.StateBounded,
			Statement: "Declared valid runtime states.",
			Entries:   []charter.Entry{{ID: "normal", Statement: "Normal configured operation."}},
		},
		Environments: &charter.Dimension{
			State:     charter.StateNotApplicable,
			Statement: "No environment distinction is declared.",
			Entries:   []charter.Entry{},
		},
		ScaleBounds: &charter.Dimension{
			State:     charter.StateUnspecified,
			Statement: "Scale is intentionally unspecified.",
			Entries:   []charter.Entry{},
		},
		CompatibilityPromises: &charter.Dimension{
			State:     charter.StateBounded,
			Statement: "Declared compatibility promises.",
			Entries:   []charter.Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
		},
		ThreatModel: &charter.Dimension{
			State:     charter.StateUnbounded,
			Statement: "Threat scenarios must name concrete exercised behavior.",
			Entries:   []charter.Entry{},
		},
	}
	writeJSON(t, path, base)
}

func writeRoleOutputs(t *testing.T, frozen charter.FrozenCharter, artifactDigest string, executable contracts.ExecutableSpec, defectPath string, economyPath string) {
	t.Helper()
	identity := map[string]any{"kind": "e2e", "id": "fake-provider"}
	source := map[string]any{"kind": "source-snapshot", "id": "snapshot", "digest": artifactDigest}
	defect := contracts.RoleOutputDocument{
		SchemaVersion:    contracts.RoleOutputV3,
		Role:             contracts.RoleDefect,
		CharterHash:      frozen.CharterHash,
		ArtifactDigest:   artifactDigest,
		SourceIdentity:   source,
		ConsumerIdentity: identity,
		Findings: []contracts.Finding{{
			ID:              "defect-exec",
			Kind:            contracts.FindingKindDefect,
			Title:           "CLI executable witness reports accepted input",
			CharterGoalIDs:  []string{"goal-cli"},
			ClaimedSeverity: contracts.SeverityCritical,
			ScopeAnchors: []contracts.ScopeAnchor{{
				Dimension: "entry_points",
				EntryID:   "cli",
			}},
			Witness: contracts.Witness{
				Kind:       contracts.WitnessKindDefect,
				Strength:   contracts.WitnessStrengthExecutable,
				Content:    "Running the CLI-facing executable witness prints the accepted marker.",
				Executable: &executable,
				EntryPoint: &contracts.ScopeAnchor{
					Dimension: "entry_points",
					EntryID:   "cli",
				},
				ReachabilityChain: []contracts.ScopeAnchor{
					{Dimension: "entry_points", EntryID: "cli"},
					{Dimension: "input_surface", Value: "accepted marker"},
					{Dimension: "valid_states", EntryID: "normal"},
				},
			},
			EstimatedDelta: contracts.SplitDeltaEstimate{
				Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 2, Files: 1},
				Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 4, Files: 1},
			},
			SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
				Direction:          contracts.RemedyDirectionChange,
				Summary:            "Preserve the accepted CLI marker.",
				MinimalityArgument: "The change is limited to the CLI behavior under review.",
			},
			ProposedTests: []contracts.ProposedTest{{
				ID:                 "test-defect-exec",
				Name:               "executable witness remains accepted",
				ReachablePartition: "cli accepted marker",
				CharterRefs: []contracts.CharterRef{{
					GoalID: "goal-cli",
				}},
			}},
		}},
	}
	economy := contracts.RoleOutputDocument{
		SchemaVersion:    contracts.RoleOutputV3,
		Role:             contracts.RoleEconomy,
		CharterHash:      frozen.CharterHash,
		ArtifactDigest:   artifactDigest,
		SourceIdentity:   source,
		ConsumerIdentity: identity,
		Findings: []contracts.Finding{{
			ID:              "economy-remove",
			Kind:            contracts.FindingKindEconomy,
			Title:           "Remove duplicate accepted marker branch",
			CharterGoalIDs:  []string{"goal-cli"},
			ClaimedSeverity: contracts.SeverityHigh,
			Witness: contracts.Witness{
				Kind:     contracts.WitnessKindEquivalence,
				Strength: contracts.WitnessStrengthConstructed,
				Content:  "The retained path emits the same accepted marker for the declared CLI behavior.",
			},
			EstimatedDelta: contracts.SplitDeltaEstimate{
				Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: -3, Files: 0},
				Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 0, Files: 0},
			},
			SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
				Direction:          contracts.RemedyDirectionRemove,
				Summary:            "Delete only the duplicate marker branch.",
				MinimalityArgument: "The retained branch preserves every declared CLI goal.",
			},
			ProposedTests: []contracts.ProposedTest{{
				ID:                 "test-economy-remove",
				Name:               "accepted marker remains stable",
				ReachablePartition: "cli accepted marker",
				CharterRefs: []contracts.CharterRef{{
					GoalID: "goal-cli",
				}},
			}},
		}},
	}
	writeJSON(t, defectPath, defect)
	writeJSON(t, economyPath, economy)
}

func writeHarnessRequest(t *testing.T, path string, charterHash string, artifactDigest string, manifestPath string, executable contracts.ExecutableSpec, keyPath string) {
	t.Helper()
	request := harness.RunRequest{
		SchemaVersion:            harness.RequestSchemaVersion,
		FindingID:                "defect-exec",
		CharterHash:              charterHash,
		FrozenSource:             contracts.ArtifactRef{Kind: "source-snapshot-manifest", ID: "source-snapshot", Digest: artifactDigest, DigestProfile: digest.Profile, MediaType: "application/json"},
		FrozenSourceManifestPath: manifestPath,
		Command:                  executable,
		TimeoutMS:                5000,
		Issuer:                   contracts.ReceiptIssuer{ID: "e2e", Actor: "test", Method: "hmac-sha256-key-file"},
		Authentication:           harness.RunRequestAuthentication{Scheme: harness.AuthenticationScheme, KeyID: "e2e-key", KeyFile: keyPath},
	}
	writeJSON(t, path, request)
}

func buildBinaries(t *testing.T) binaries {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "bin")
	mustMkdir(t, out)
	result := binaries{
		witness: filepath.Join(out, "witness"),
		harness: filepath.Join(out, "witness-harness"),
		relay:   filepath.Join(out, "fake-relay"),
	}
	goBuild(t, root, result.witness, "./cmd/witness")
	goBuild(t, root, result.harness, "./cmd/witness-harness")
	goBuild(t, root, result.relay, "./testdata/e2e/fake-relay")
	return result
}

func goBuild(t *testing.T, dir string, output string, pkg string) {
	t.Helper()
	runCommand(t, nil, dir, "go", "build", "-o", output, pkg)
}

type commandResult struct {
	stdout []byte
	stderr []byte
}

func runOK(t *testing.T, env map[string]string, name string, args ...string) commandResult {
	t.Helper()
	return runCommand(t, env, repoRoot(t), name, args...)
}

func runCommand(t *testing.T, env map[string]string, dir string, name string, args ...string) commandResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = os.Environ()
	command.Env = append(command.Env, "GOCACHE=/tmp/witness-gocache")
	for key, value := range env {
		command.Env = append(command.Env, key+"="+value)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\nstdout:\n%s\nstderr:\n%s", name, strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return commandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", root, err)
	}
	return root
}

func readJSON[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	decodeBytes(t, data, &value)
	return value
}

func decodeBytes(t *testing.T, data []byte, value any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, string(data))
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(data, '\n'), 0o644)
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func findingsByID(result adjudicate.Result) map[string]adjudicate.FindingVerdict {
	findings := map[string]adjudicate.FindingVerdict{}
	for _, finding := range result.Findings {
		findings[finding.FindingID] = finding
	}
	return findings
}

func assertRunRecipeIDs(t *testing.T, runs relayRunsDocument, want []string) {
	t.Helper()
	var got []string
	for _, run := range runs.Runs {
		got = append(got, run.RecipeID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("run recipe IDs = %v, want %v", got, want)
	}
}

func assertLedgerKinds(t *testing.T, show ledger.ShowDocument, want map[string]int) {
	t.Helper()
	got := map[string]int{}
	for _, record := range show.Records {
		got[record.EventKind]++
	}
	for kind, count := range want {
		if got[kind] != count {
			t.Fatalf("ledger kind %s count = %d, want %d; all counts %#v", kind, got[kind], count, got)
		}
	}
}

func assertPendingStratum(t *testing.T, document metrics.Document, backend string, status string, count int) {
	t.Helper()
	for _, stratum := range document.PendingVerification.Strata {
		if stratum.Backend == backend && stratum.BackendAuthStatus == status {
			if stratum.Count != count {
				t.Fatalf("pending stratum %#v count = %d, want %d", stratum, stratum.Count, count)
			}
			return
		}
	}
	t.Fatalf("missing pending stratum backend=%s status=%s in %#v", backend, status, document.PendingVerification.Strata)
}

func assertStringSliceContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("values %v do not contain %s", values, want)
}

func init() {
	json.Valid(nil)
}
