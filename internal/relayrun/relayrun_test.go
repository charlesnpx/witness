package relayrun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/convo-relay/v2/plan"
	"github.com/charlesnpx/convo-relay/v2/result"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayv2"
)

func TestRunBatchesExecutesAndVerifiesRelayV2Plan(t *testing.T) {
	relay := requireRelayV2(t)
	witnessDigest := "sha256:" + strings.Repeat("a", 64)
	verdictPayload := fmt.Sprintf(`{"schema_version":"relay-witness-verdicts-v2","batch_id":"batch-1","verdicts":[{"finding_id":"finding-1","witness_digest":"%s","verdict":"survived","verdict_class":null,"counter_witness":null}]}`, witnessDigest)
	installFakeCodex(t, verdictPayload)
	batch, options := writeRelayRunInputs(t, witnessDigest)
	options.RelayPath = relay
	options.OutputDir = t.TempDir()
	launchTarget := t.TempDir()
	launchLink := filepath.Join(t.TempDir(), "launch-cwd")
	if err := os.Symlink(launchTarget, launchLink); err != nil {
		t.Fatalf("symlink launch CWD: %v", err)
	}
	launchMarker := filepath.Join(t.TempDir(), "relay-cwd")
	launchArgsMarker := filepath.Join(t.TempDir(), "relay-args")
	options.RelayHome = t.TempDir()
	options.SettingsPath = filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(options.SettingsPath, []byte("# relayrun test settings\n"), 0o600); err != nil {
		t.Fatalf("write Relay settings: %v", err)
	}
	launcher := filepath.Join(t.TempDir(), "relay-wrapper")
	launcherScript := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = run ]; then pwd -P > %q; printf '%%s\\n' \"$@\" > %q; fi\nexec %q \"$@\"\n", launchMarker, launchArgsMarker, relay)
	if err := os.WriteFile(launcher, []byte(launcherScript), 0o700); err != nil {
		t.Fatalf("write Relay wrapper: %v", err)
	}
	options.RelayPath = launcher
	options.LaunchCWD = launchLink

	run, err := RunBatches(context.Background(), []BatchInput{batch}, options)
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if len(run.Runs) != 1 {
		t.Fatalf("run records = %#v, want one record", run.Runs)
	}
	record := run.Runs[0]
	wantLaunchCWD := evalRelayPath(t, launchLink)
	launchedCWD, err := os.ReadFile(launchMarker)
	if err != nil {
		t.Fatalf("read Relay working-directory marker: %v", err)
	}
	if got := strings.TrimSpace(string(launchedCWD)); got != wantLaunchCWD {
		t.Fatalf("Relay working directory = %q, want %q", got, wantLaunchCWD)
	}
	launchedArgs, err := os.ReadFile(launchArgsMarker)
	if err != nil {
		t.Fatalf("read Relay argv marker: %v", err)
	}
	if record.RelayLaunch == nil {
		t.Fatal("run record omitted Relay launch evidence")
	}
	wantLaunchedArgs := strings.Join(record.RelayLaunch.Argv[1:], "\n") + "\n"
	if string(launchedArgs) != wantLaunchedArgs {
		t.Fatalf("retained Relay argv = %q, actual invocation args = %q", record.RelayLaunch.Argv, string(launchedArgs))
	}
	for _, expected := range []string{"--home", options.RelayHome, "--settings", options.SettingsPath} {
		if !strings.Contains(wantLaunchedArgs, expected+"\n") && !strings.HasSuffix(wantLaunchedArgs, expected) {
			t.Fatalf("retained Relay argv = %q, missing passed argument %q", record.RelayLaunch.Argv, expected)
		}
	}
	if got := evalRelayPath(t, record.RelayLaunch.WorkingDirectory); got != wantLaunchCWD {
		t.Fatalf("retained Relay working directory = %q, want %q", got, wantLaunchCWD)
	}
	if record.Status != contracts.RecordStatusValid {
		t.Fatalf("record status = %q, diagnostics = %#v", record.Status, record.Diagnostics)
	}
	if record.PlanDigest == "" || record.VerifiedBundle == nil {
		t.Fatalf("record omitted plan or verified bundle: %#v", record)
	}
	verifiedDigest, err := relayPlanDigest(record.VerifiedBundle.Session.Plan)
	if err != nil {
		t.Fatalf("digest verified plan: %v", err)
	}
	if verifiedDigest != record.PlanDigest {
		t.Fatalf("verified plan digest = %q, recorded = %q", verifiedDigest, record.PlanDigest)
	}
	if record.PortableExportDigest != record.VerifiedBundle.Manifest.ManifestDigest {
		t.Fatalf("portable export digest = %q, verified manifest = %q", record.PortableExportDigest, record.VerifiedBundle.Manifest.ManifestDigest)
	}
	if record.RelayVerdicts == nil || len(record.RelayVerdicts.Verdicts) != 1 {
		t.Fatalf("relay verdicts = %#v, want one typed result verdict", record.RelayVerdicts)
	}
	if !record.ProviderInvocationCountPresent || record.ProviderInvocationCount < 1 || record.ProviderInvoked != ProviderInvokedTrue {
		t.Fatalf("invocation evidence = count:%d present:%t provider_invoked:%q", record.ProviderInvocationCount, record.ProviderInvocationCountPresent, record.ProviderInvoked)
	}
	wantExport := filepath.Join(options.OutputDir, "verification", "exports", batch.Plan.BatchID)
	if got, want := evalRelayPath(t, record.PortableExportDir), evalRelayPath(t, wantExport); got != want {
		t.Fatalf("portable export path = %q, want %q", got, want)
	}
	persisted, err := os.ReadFile(filepath.Join(options.OutputDir, "verification", "runs", batch.Plan.BatchID+".json"))
	if err != nil {
		t.Fatalf("read persisted run record: %v", err)
	}
	decoded, err := ReadRunRecordsBytes(persisted)
	if err != nil || len(decoded) != 1 || decoded[0].VerifiedBundle == nil {
		t.Fatalf("decode persisted run record = %#v, err = %v", decoded, err)
	}
}

func TestRunBatchesSurfacesRelayNotInstalled(t *testing.T) {
	batch, options := writeRelayRunInputs(t, "sha256:"+strings.Repeat("b", 64))
	options.RelayPath = filepath.Join(t.TempDir(), "missing", "convo-relay")
	options.OutputDir = t.TempDir()

	run, err := RunBatches(context.Background(), []BatchInput{batch}, options)
	if err != nil {
		t.Fatalf("RunBatches returned an outer error: %v", err)
	}
	if len(run.Runs) != 1 {
		t.Fatalf("run records = %#v, want one record", run.Runs)
	}
	record := run.Runs[0]
	if record.RelayErrorKind != relayv2.ErrorRelayNotInstalled {
		t.Fatalf("relay error kind = %q, want %q", record.RelayErrorKind, relayv2.ErrorRelayNotInstalled)
	}
	if record.Status != RunStatusLaunchFailed || record.ProviderInvoked != ProviderInvokedFalse || record.ConsumesBatch {
		t.Fatalf("missing Relay record = %#v, want non-consuming start failure", record)
	}
	if record.RelayLaunch == nil || !record.RelayLaunch.StartFailed {
		t.Fatalf("missing Relay launch evidence = %#v", record.RelayLaunch)
	}
	if len(record.Diagnostics) == 0 || record.Diagnostics[0].Code != CodeRelayNotInstalled {
		t.Fatalf("missing Relay diagnostics = %#v", record.Diagnostics)
	}
}

func TestRunBatchesPreservesInvocationEvidencePresence(t *testing.T) {
	cases := []struct {
		name         string
		value        result.Result
		wantCount    int
		wantPresent  bool
		wantInvoked  string
		wantConsumes bool
		wantStatus   string
		wantSession  string
	}{
		{
			name:         "absent",
			value:        result.Result{Root: &result.Root{}},
			wantInvoked:  ProviderInvokedUnknown,
			wantConsumes: true,
			wantStatus:   contracts.RecordStatusUnavailable,
			wantSession:  "session-dir",
		},
		{
			name:         "explicit zero",
			value:        result.Result{Root: &result.Root{Invocations: &result.Count{Count: 0}}},
			wantPresent:  true,
			wantInvoked:  ProviderInvokedFalse,
			wantConsumes: true,
			wantStatus:   contracts.RecordStatusFailed,
		},
		{
			name:         "positive",
			value:        result.Result{Root: &result.Root{Invocations: &result.Count{Count: 2}}},
			wantCount:    2,
			wantPresent:  true,
			wantInvoked:  ProviderInvokedTrue,
			wantConsumes: true,
			wantStatus:   contracts.RecordStatusValid,
			wantSession:  "session-dir",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			count, present := relayv2.InvocationEvidence(test.value)
			record := RunRecord{
				SchemaVersion:                  RunRecordSchema,
				BatchID:                        "batch-1",
				RecipeID:                       "witness-falsify-v2-codex",
				Status:                         test.wantStatus,
				ProviderInvoked:                classifyProviderInvocation(&LaunchRecord{}, count, present),
				ConsumesBatch:                  test.wantConsumes,
				ProviderInvocationCount:        count,
				ProviderInvocationCountPresent: present,
				SessionDir:                     test.wantSession,
			}
			if record.ProviderInvoked != test.wantInvoked || count != test.wantCount || present != test.wantPresent {
				t.Fatalf("evidence = count:%d present:%t invoked:%q; want count:%d present:%t invoked:%q", count, present, record.ProviderInvoked, test.wantCount, test.wantPresent, test.wantInvoked)
			}
			data, err := contracts.CanonicalBytes(record)
			if err != nil {
				t.Fatalf("encode record: %v", err)
			}
			decoded, err := ReadRunRecordsBytes(data)
			if err != nil {
				t.Fatalf("decode record: %v", err)
			}
			if len(decoded) != 1 || decoded[0].ProviderInvocationCount != count || decoded[0].ProviderInvocationCountPresent != present || decoded[0].SessionDir != test.wantSession || decoded[0].ConsumesBatch != test.wantConsumes {
				t.Fatalf("decoded evidence = %#v, want count:%d present:%t session:%q consumes:%t", decoded, count, present, test.wantSession, test.wantConsumes)
			}
		})
	}
}

func TestRunLaunchEvidenceBoundsAndRoundTripsRawBytes(t *testing.T) {
	stdout := append(bytes.Repeat([]byte("h"), launchCaptureLimitBytes/2+1), bytes.Repeat([]byte("t"), launchCaptureLimitBytes/2+1)...)
	stderr := []byte{0xff, 0xfe, 'e', 0x80, 'r'}
	launch := testCommandLaunchRecord(stdout, stderr, 1, false)
	if !launch.StdoutTruncated || len(launch.Stdout) != launchCaptureLimitBytes {
		t.Fatalf("bounded stdout = %#v", launch)
	}
	if !bytes.HasPrefix(launch.Stdout, []byte("hhhh")) || !bytes.HasSuffix(launch.Stdout, []byte("tttt")) {
		t.Fatal("bounded stdout did not retain both stream ends")
	}
	if launch.StdoutDigest != digest.RawBytes(launch.Stdout) || launch.StdoutBytes != strictjson.Int(len(launch.Stdout)) {
		t.Fatalf("stdout summary = %#v", launch)
	}

	record := RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "batch-1",
		Status:          RunStatusLaunchFailed,
		RecipeID:        "witness-falsify-v2-codex",
		ProviderInvoked: ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch:     testCommandLaunchRecord([]byte{0xff, 0xfe, 'o', 'k'}, stderr, -1, true),
	}
	data, err := contracts.CanonicalBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := ReadRunRecordsBytes(data)
	if err != nil {
		t.Fatalf("ReadRunRecordsBytes: %v", err)
	}
	if len(runs) != 1 || !bytes.Equal(runs[0].RelayLaunch.Stdout, record.RelayLaunch.Stdout) || !bytes.Equal(runs[0].RelayLaunch.Stderr, stderr) {
		t.Fatalf("round-tripped launch = %#v", runs)
	}
}

func TestReadRunRecordsBytesValidatesInvocationAndLaunchEvidence(t *testing.T) {
	valid := RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "batch-1",
		Status:          contracts.RecordStatusUnavailable,
		RecipeID:        "witness-falsify-v2-codex",
		ProviderInvoked: ProviderInvokedUnknown,
		ConsumesBatch:   true,
		RelayLaunch:     testCommandLaunchRecord([]byte("a"), nil, 0, false),
	}
	data, err := contracts.CanonicalBytes(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err != nil {
		t.Fatalf("valid run record rejected: %v", err)
	}

	invalid := valid
	invalid.ProviderInvoked = ProviderInvokedFalse
	invalid.ProviderInvocationCountPresent = true
	invalid.ProviderInvocationCount = 0
	invalid.Status = contracts.RecordStatusFailed
	invalid.ConsumesBatch = false
	data, err = contracts.CanonicalBytes(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil {
		t.Fatal("non-consuming explicit-zero record was accepted")
	}

	startFailure := valid
	startFailure.Status = RunStatusLaunchFailed
	startFailure.ProviderInvoked = ProviderInvokedFalse
	startFailure.ConsumesBatch = false
	startFailure.RelayLaunch = testCommandLaunchRecord(nil, nil, -1, true)
	startFailure.RelayRunResult = map[string]any{"provider_result": "unexpected"}
	data, err = contracts.CanonicalBytes(startFailure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil {
		t.Fatalf("start failure validation error = %v", err)
	}

	badSummary := valid
	badSummary.RelayLaunch.StdoutDigest = digest.RawBytes([]byte("different"))
	data, err = contracts.CanonicalBytes(badSummary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil || diag.FromError(err).Code != CodeInvalidRunRecordStreamSummary {
		t.Fatalf("stream summary validation error = %v", err)
	}
}

func TestReadRunRecordsBytesAcceptsRunIndex(t *testing.T) {
	data, err := contracts.CanonicalBytes(Result{
		SchemaVersion: SchemaVersion,
		Runs: []RunRecord{{
			SchemaVersion:   RunRecordSchema,
			BatchID:         "batch-1",
			Status:          RunStatusLaunchFailed,
			RecipeID:        "witness-falsify-v2-codex",
			ProviderInvoked: ProviderInvokedFalse,
			ConsumesBatch:   false,
			RelayLaunch:     testCommandLaunchRecord(nil, nil, -1, true),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runs, err := ReadRunRecordsBytes(data)
	if err != nil || len(runs) != 1 || runs[0].BatchID != "batch-1" {
		t.Fatalf("runs = %#v, err = %v", runs, err)
	}
}

func TestRunBatchesRejectsInvalidInputsBeforeRelayV2Launch(t *testing.T) {
	tests := []struct {
		name string
		make func(t *testing.T, dir string) (BatchInput, Options)
	}{
		{
			name: "batch digest mismatch",
			make: func(t *testing.T, dir string) (BatchInput, Options) {
				batch, options := invalidInputFixture(t, dir, false)
				batch.Plan.BatchDigest = digest.RawBytes([]byte("different"))
				return batch, options
			},
		},
		{
			name: "missing planned artifact set",
			make: func(t *testing.T, dir string) (BatchInput, Options) {
				batch, options := invalidInputFixture(t, dir, true)
				batch.Plan.ArtifactDigestSet = nil
				return batch, options
			},
		},
		{
			name: "missing artifact input",
			make: func(t *testing.T, dir string) (BatchInput, Options) {
				batch, options := invalidInputFixture(t, dir, true)
				options.ArtifactPaths = nil
				return batch, options
			},
		},
		{
			name: "unplanned artifact input",
			make: func(t *testing.T, dir string) (BatchInput, Options) {
				batch, options := invalidInputFixture(t, dir, true)
				extra := filepath.Join(dir, "extra.json")
				if err := os.WriteFile(extra, []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
				options.ArtifactPaths = append(options.ArtifactPaths, extra)
				return batch, options
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch, options := test.make(t, t.TempDir())
			options.RelayPath = filepath.Join(t.TempDir(), "relay-not-used")
			result, err := RunBatches(context.Background(), []BatchInput{batch}, options)
			if err != nil {
				t.Fatalf("RunBatches: %v", err)
			}
			if len(result.Runs) != 1 {
				t.Fatalf("runs = %#v", result.Runs)
			}
			record := result.Runs[0]
			if record.Status != RunStatusLaunchFailed || record.ProviderInvoked != ProviderInvokedFalse || record.ConsumesBatch {
				t.Fatalf("record = %#v, want non-consuming pre-launch rejection", record)
			}
			if len(record.Diagnostics) == 0 || record.Diagnostics[0].Code != CodeInvalidBatchInput {
				t.Fatalf("diagnostics = %#v, want %s", record.Diagnostics, CodeInvalidBatchInput)
			}
		})
	}
}

func TestRunBatchesRejectsNamedInputOverBudgetBeforeRelayV2Launch(t *testing.T) {
	batch, options := writeRelayRunInputs(t, "sha256:"+strings.Repeat("b", 64))
	marker := filepath.Join(t.TempDir(), "relay-invoked")
	relay := filepath.Join(t.TempDir(), "relay-stub")
	script := fmt.Sprintf("#!/bin/sh\nprintf invoked > %q\nexit 23\n", marker)
	if err := os.WriteFile(relay, []byte(script), 0o700); err != nil {
		t.Fatalf("write Relay stub: %v", err)
	}
	options.RelayPath = relay
	options.NamedInputBudgetBytes = 1
	options.OutputDir = t.TempDir()

	result, err := RunBatches(context.Background(), []BatchInput{batch}, options)
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if len(result.Runs) != 1 {
		t.Fatalf("runs = %#v, want one", result.Runs)
	}
	record := result.Runs[0]
	if record.Status != RunStatusLaunchFailed || record.ProviderInvoked != ProviderInvokedFalse || record.ConsumesBatch {
		t.Fatalf("record = %#v, want non-consuming pre-launch rejection", record)
	}
	if record.RelayLaunch == nil || !record.RelayLaunch.StartFailed || len(record.RelayLaunch.Argv) != 0 {
		t.Fatalf("launch = %#v, want empty pre-launch launch marker", record.RelayLaunch)
	}
	if len(record.Diagnostics) == 0 || record.Diagnostics[0].Code != CodeNamedInputBudgetExceeded {
		t.Fatalf("diagnostics = %#v, want %s", record.Diagnostics, CodeNamedInputBudgetExceeded)
	}
	diagnostic := record.Diagnostics[0]
	if !strings.Contains(diagnostic.Message, "charter") || !strings.Contains(diagnostic.Message, "1-byte") {
		t.Fatalf("budget diagnostic = %#v, want input name and budget", diagnostic)
	}
	if diagnostic.Details["input"] != "charter" || diagnostic.Details["actual_bytes"] == nil || diagnostic.Details["budget_bytes"] != int64(1) {
		t.Fatalf("budget diagnostic details = %#v, want input and both sizes", diagnostic.Details)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Relay invocation marker exists or could not be checked: %v", err)
	}
}

func testCommandLaunchRecord(stdout, stderr []byte, exitCode int, startFailed bool) *LaunchRecord {
	return launchRecordForRelayV2(relayv2.Invocation{
		Executable:       "fake-relay",
		Args:             []string{"run", "--plan", "/tmp/plan.json", "--blobs", "/tmp/blobs", "--json"},
		WorkingDirectory: "/tmp/workspace",
	}, &relayv2.CommandError{
		Executable:  "fake-relay",
		Args:        []string{"run", "--plan", "/tmp/plan.json", "--blobs", "/tmp/blobs", "--json"},
		ExitCode:    exitCode,
		Stdout:      string(stdout),
		Stderr:      string(stderr),
		Kind:        relayv2.ErrorRelayCommandFailed,
		StartFailed: startFailed,
	})
}

func invalidInputFixture(t *testing.T, dir string, withArtifact bool) (BatchInput, Options) {
	t.Helper()
	batchBytes := []byte(`{"batch":"input"}`)
	batchPath := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(batchPath, batchBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	artifactBytes := []byte("artifact")
	artifactPath := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	batch := BatchInput{
		Plan: planning.BatchPlan{
			BatchID:           "batch-1",
			TaskShape:         contracts.BatchTaskDefect,
			BatchDigest:       digest.RawBytes(batchBytes),
			ArtifactDigestSet: []string{artifactDigest},
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}
	options := Options{}
	if withArtifact {
		options.ArtifactPaths = []string{artifactPath}
	}
	return batch, options
}

func requireRelayV2(t *testing.T) string {
	t.Helper()
	path := filepath.Join("/tmp", "relayr1", "gobin", "convo-relay")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("required convo-relay v2.0.1 binary is unavailable at %s: %v", path, err)
	}
	t.Setenv("PATH", filepath.Dir(path)+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := exec.LookPath("convo-relay"); err != nil {
		t.Skipf("required convo-relay v2.0.1 binary is not on PATH: %v", err)
	}
	return path
}

func installFakeCodex(t *testing.T, payload string) {
	t.Helper()
	directory := t.TempDir()
	literal, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode fake provider payload: %v", err)
	}
	script := strings.Replace(fakeCodexAppServerScript, "PAYLOAD_LITERAL", string(literal), 1)
	path := filepath.Join(directory, "codex")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake codex app server: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+"/tmp/relayr1/gobin"+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CODEX_CLAUDE_HOME", filepath.Join(t.TempDir(), "relay-home"))
}

func writeRelayRunInputs(t *testing.T, witnessDigest string) (BatchInput, Options) {
	t.Helper()
	directory := t.TempDir()
	charterBytes := []byte(`{"goals":[]}`)
	batchBytes := []byte(`{"batch":"batch-1","findings":["finding-1"]}`)
	artifactBytes := []byte(`{"snapshot":"artifact"}`)
	charterPath := filepath.Join(directory, "charter.json")
	batchPath := filepath.Join(directory, "batch.json")
	artifactPath := filepath.Join(directory, "artifact.json")
	for _, file := range []struct {
		path string
		data []byte
	}{
		{path: charterPath, data: charterBytes},
		{path: batchPath, data: batchBytes},
		{path: artifactPath, data: artifactBytes},
	} {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			t.Fatalf("write %s: %v", file.path, err)
		}
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	batchDigest := digest.RawBytes(batchBytes)
	charterDigest := digest.RawBytes(charterBytes)
	return BatchInput{
			Plan: planning.BatchPlan{
				BatchID:           "batch-1",
				Role:              contracts.RoleDefect,
				TaskShape:         contracts.BatchTaskDefect,
				BatchDigest:       batchDigest,
				CharterDigest:     charterDigest,
				ArtifactDigest:    artifactDigest,
				ArtifactDigestSet: []string{artifactDigest},
			},
			Document: contracts.VerificationBatchDocument{
				SchemaVersion:  contracts.VerificationBatchV2,
				TaskShape:      contracts.BatchTaskDefect,
				BatchID:        "batch-1",
				ArtifactDigest: artifactDigest,
				Findings: []contracts.VerificationBatchFinding{{
					FindingID:     "finding-1",
					WitnessDigest: witnessDigest,
				}},
			},
			Path:     batchPath,
			RawBytes: batchBytes,
		}, Options{
			CharterPath:     charterPath,
			ArtifactPaths:   []string{artifactPath},
			CharterDigest:   charterDigest,
			ArtifactDigest:  artifactDigest,
			ArtifactDigests: []string{artifactDigest},
			Backend:         "codex",
		}
}

func relayPlanDigest(value plan.Plan) (string, error) {
	return plan.Digest(value)
}

func evalRelayPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return resolved
}

const fakeCodexAppServerScript = `#!/usr/bin/env python3
import json
import sys

if len(sys.argv) < 2 or sys.argv[1] != "app-server":
    print("expected codex app-server", file=sys.stderr)
    raise SystemExit(2)

result_text = PAYLOAD_LITERAL
thread_id = "relayrun-test-thread"
turn_number = 0

def send(value):
    print(json.dumps(value), flush=True)

def response(request, value):
    send({"id": request.get("id"), "result": value})

for raw in sys.stdin:
    try:
        request = json.loads(raw)
    except json.JSONDecodeError:
        continue
    method = request.get("method", "")
    params = request.get("params", {}) or {}
    if method == "initialize":
        response(request, {"serverInfo": {"name": "relayrun-test"}})
    elif method in ("thread/start", "thread/resume"):
        thread_id = params.get("threadId") or thread_id
        response(request, {"thread": {"id": thread_id}})
    elif method == "model/list":
        response(request, {"data": [{"id": "relayrun-test", "supportedReasoningEfforts": ["low", "high"]}]})
    elif method == "turn/start":
        turn_number += 1
        turn_id = "turn-%d" % turn_number
        response(request, {"turn": {"id": turn_id}})
        send({"method": "item/completed", "params": {"item": {"id": "item-%d" % turn_number, "type": "agentMessage", "text": result_text}}})
        send({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "completed"}}})
    elif method == "turn/interrupt":
        response(request, {})
`
