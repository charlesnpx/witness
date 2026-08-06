package relayrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayclient"
)

type fakeRelayRunner struct {
	t         *testing.T
	runCalls  int
	batchPath string
	result    relayclient.CommandResult
}

func (runner *fakeRelayRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	if len(args) == 0 || args[0] != "run" {
		runner.t.Fatalf("unexpected relay command: %v", args)
	}
	runner.runCalls++
	if runner.runCalls > 1 {
		runner.t.Fatalf("relay run called more than once")
	}
	if got := argAfter(args, "--recipe"); got != "witness-falsify-v2-codex" {
		runner.t.Fatalf("recipe = %s, want witness-falsify-v2-codex; args=%v", got, args)
	}
	if got := argAfter(args, "--workspace-isolation"); got != "read_only" {
		runner.t.Fatalf("workspace isolation = %s, want read_only; args=%v", got, args)
	}
	if !containsArgPair(args, "--input", "charter=charter.json") || !containsArgPair(args, "--input", "findings="+runner.batchPath) {
		runner.t.Fatalf("missing required input bindings: %v", args)
	}
	return runner.result
}

func TestRunBatchesNonzeroWithoutArtifactsConsumesBatch(t *testing.T) {
	dir := t.TempDir()
	record, runner := runLaunchFailure(t, dir, relayclient.CommandResult{
		Stdout:   []byte(`{"message":"auth failed"}`),
		Stderr:   []byte("relay authentication failed"),
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	})
	if runner.runCalls != 1 {
		t.Fatalf("run calls = %d, want 1", runner.runCalls)
	}
	if record.Status != contracts.RecordStatusUnavailable {
		t.Fatalf("status = %s, want %s", record.Status, contracts.RecordStatusUnavailable)
	}
	if record.ProviderInvoked != ProviderInvokedUnknown || !record.ConsumesBatch {
		t.Fatalf("provider classification = %q consumes_batch=%t, want unknown/consumed", record.ProviderInvoked, record.ConsumesBatch)
	}
	if record.RelayLaunch == nil {
		t.Fatal("missing retained relay launch")
	}
	launch := record.RelayLaunch
	if launch.WorkingDirectory != dir || launch.ExitCode != 1 {
		t.Fatalf("launch = %#v, want cwd %q and exit 1", launch, dir)
	}
	if len(launch.Argv) < 2 || launch.Argv[0] != "fake-relay" || launch.Argv[1] != "run" || !containsArgPair(launch.Argv, "--launch-cwd", dir) {
		t.Fatalf("argv = %#v, want fake relay run with launch cwd", launch.Argv)
	}
	if !bytes.Equal(launch.Stdout, []byte(`{"message":"auth failed"}`)) || !bytes.Equal(launch.Stderr, []byte("relay authentication failed")) {
		t.Fatalf("launch captures = %#v", launch)
	}
	if len(record.Diagnostics) != 1 || record.Diagnostics[0].Code != CodeRelayRunFailed {
		t.Fatalf("diagnostics = %#v", record.Diagnostics)
	}
}

func TestRunBatchesStartFailureDoesNotConsumeBatch(t *testing.T) {
	dir := t.TempDir()
	record, runner := runLaunchFailure(t, dir, relayclient.CommandResult{
		Stderr:      []byte("relay executable not found"),
		ExitCode:    -1,
		Err:         errors.New("exec: fake-relay: executable file not found"),
		StartFailed: true,
	})
	if runner.runCalls != 1 {
		t.Fatalf("run calls = %d, want 1", runner.runCalls)
	}
	if record.Status != RunStatusLaunchFailed {
		t.Fatalf("status = %s, want %s", record.Status, RunStatusLaunchFailed)
	}
	if record.ProviderInvoked != ProviderInvokedFalse || record.ConsumesBatch {
		t.Fatalf("provider classification = %q consumes_batch=%t, want false/non-consuming", record.ProviderInvoked, record.ConsumesBatch)
	}
	if record.RelayLaunch == nil || !record.RelayLaunch.StartFailed {
		t.Fatalf("launch = %#v, want retained start failure", record.RelayLaunch)
	}
}

func TestRunBatchesNonzeroWithSessionConsumesBatch(t *testing.T) {
	record, _ := runLaunchFailure(t, t.TempDir(), relayclient.CommandResult{
		Stdout:   []byte(`{"session_dir":"/tmp/relay-session"}`),
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	})
	if record.ProviderInvoked != ProviderInvokedTrue || !record.ConsumesBatch {
		t.Fatalf("provider classification = %q consumes_batch=%t, want true/consumed", record.ProviderInvoked, record.ConsumesBatch)
	}
	if record.Status != contracts.RecordStatusUnavailable {
		t.Fatalf("status = %q, want unavailable", record.Status)
	}
}

func TestRunBatchesBoundsLaunchOutput(t *testing.T) {
	stdout := append(bytes.Repeat([]byte("h"), launchCaptureLimitBytes/2+1), bytes.Repeat([]byte("t"), launchCaptureLimitBytes/2+1)...)
	stderr := append(bytes.Repeat([]byte("x"), launchCaptureLimitBytes/2+1), bytes.Repeat([]byte("z"), launchCaptureLimitBytes/2+1)...)
	record, _ := runLaunchFailure(t, t.TempDir(), relayclient.CommandResult{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	})
	if record.RelayLaunch == nil {
		t.Fatal("missing retained relay launch")
	}
	launch := record.RelayLaunch
	if !launch.StdoutTruncated || !launch.StderrTruncated || len(launch.Stdout) != launchCaptureLimitBytes || len(launch.Stderr) != launchCaptureLimitBytes {
		t.Fatalf("bounded launch captures = %#v", launch)
	}
	if !bytes.HasPrefix(launch.Stdout, []byte("hhhh")) || !bytes.HasSuffix(launch.Stdout, []byte("tttt")) || !bytes.HasPrefix(launch.Stderr, []byte("xxxx")) || !bytes.HasSuffix(launch.Stderr, []byte("zzzz")) {
		t.Fatalf("launch captures did not retain head and tail")
	}
	if launch.StdoutDigest != digest.RawBytes(stdout) || int(launch.StdoutBytes) != len(stdout) || launch.StderrDigest != digest.RawBytes(stderr) || int(launch.StderrBytes) != len(stderr) {
		t.Fatalf("launch raw summaries = %#v", launch)
	}
}

func TestRunRecordRoundTripsInvalidUTF8LaunchCaptureBytes(t *testing.T) {
	stdout := []byte{0xff, 0xfe, 'o', 'k', 0xc3, 0x28}
	stderr := []byte{'e', 0x80, 'r'}
	record := RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "defect-batch-1",
		Status:          RunStatusLaunchFailed,
		RecipeID:        "witness-falsify-v2-codex",
		ProviderInvoked: ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch:     launchRecord(relayclient.CommandResult{Command: "fake-relay", ExitCode: -1, StartFailed: true, Stdout: stdout, Stderr: stderr}, "/tmp/workspace"),
	}
	data, err := contracts.CanonicalBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := ReadRunRecordsBytes(data)
	if err != nil {
		t.Fatalf("ReadRunRecordsBytes: %v", err)
	}
	if len(runs) != 1 || runs[0].RelayLaunch == nil {
		t.Fatalf("runs = %#v, want one launch record", runs)
	}
	launch := runs[0].RelayLaunch
	if !bytes.Equal(launch.Stdout, stdout) || !bytes.Equal(launch.Stderr, stderr) {
		t.Fatalf("round-tripped captures = %#v, want exact raw bytes", launch)
	}
	if launch.StdoutDigest != digest.RawBytes(stdout) || int(launch.StdoutBytes) != len(stdout) || launch.StderrDigest != digest.RawBytes(stderr) || int(launch.StderrBytes) != len(stderr) {
		t.Fatalf("round-tripped raw summaries = %#v", launch)
	}
}

func TestReadRunRecordsBytesAcceptsV2Index(t *testing.T) {
	data, err := contracts.CanonicalBytes(Result{
		SchemaVersion: SchemaVersion,
		Runs: []RunRecord{{
			SchemaVersion:   RunRecordSchema,
			BatchID:         "defect-batch-1",
			Status:          RunStatusLaunchFailed,
			RecipeID:        "witness-falsify-v2-codex",
			ProviderInvoked: ProviderInvokedFalse,
			ConsumesBatch:   false,
			RelayLaunch: &LaunchRecord{
				Argv:             []string{"fake-relay", "run", "--json"},
				WorkingDirectory: "/tmp/workspace",
				ExitCode:         -1,
				StartFailed:      true,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runs, err := ReadRunRecordsBytes(data)
	if err != nil {
		t.Fatalf("ReadRunRecordsBytes: %v", err)
	}
	if len(runs) != 1 || runs[0].BatchID != "defect-batch-1" || runs[0].Status != RunStatusLaunchFailed {
		t.Fatalf("runs = %#v", runs)
	}
}

func TestReadRunRecordsBytesRejectsEmptyRecipeID(t *testing.T) {
	data, err := contracts.CanonicalBytes(RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "defect-batch-1",
		Status:          RunStatusLaunchFailed,
		ProviderInvoked: ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch: &LaunchRecord{
			Argv:             []string{"fake-relay", "run", "--json"},
			WorkingDirectory: "/tmp/workspace",
			ExitCode:         -1,
			StartFailed:      true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil || !strings.Contains(err.Error(), "recipe_id is required") {
		t.Fatalf("ReadRunRecordsBytes error = %v, want missing recipe_id rejection", err)
	}
}

func TestReadRunRecordsBytesRejectsLaunchFailedProviderEvidence(t *testing.T) {
	data, err := contracts.CanonicalBytes(RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "defect-batch-1",
		Status:          RunStatusLaunchFailed,
		RecipeID:        "witness-falsify-v2-codex",
		ProviderInvoked: ProviderInvokedFalse,
		ConsumesBatch:   false,
		RelayLaunch: &LaunchRecord{
			Argv:             []string{"fake-relay", "run", "--json"},
			WorkingDirectory: "/tmp/workspace",
			ExitCode:         -1,
			StartFailed:      false,
		},
		PortableExportDir: "/tmp/relay-export",
		RelayVerdicts:     &contracts.RelayWitnessVerdictsDocument{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil || !strings.Contains(err.Error(), "cannot carry provider evidence") {
		t.Fatalf("ReadRunRecordsBytes error = %v, want provider-evidence rejection", err)
	}
}

func TestReadRunRecordsBytesRejectsStartFailedProviderInvocation(t *testing.T) {
	data, err := contracts.CanonicalBytes(RunRecord{
		SchemaVersion:   RunRecordSchema,
		BatchID:         "defect-batch-1",
		Status:          contracts.RecordStatusUnavailable,
		RecipeID:        "witness-falsify-v2-codex",
		ProviderInvoked: ProviderInvokedTrue,
		ConsumesBatch:   true,
		SessionDir:      "/tmp/relay-session",
		RelayLaunch: &LaunchRecord{
			Argv:             []string{"fake-relay", "run", "--json"},
			WorkingDirectory: "/tmp/workspace",
			ExitCode:         -1,
			StartFailed:      true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunRecordsBytes(data); err == nil || !strings.Contains(err.Error(), "start_failed=true requires provider_invoked=false") {
		t.Fatalf("ReadRunRecordsBytes error = %v, want start-failure converse rejection", err)
	}
}

func TestRunBatchesRejectsBatchFileDigestMismatchBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	batchPath := filepath.Join(dir, "batch.json")
	expectedBytes := []byte(`{"batch":"expected"}`)
	if err := os.WriteFile(batchPath, []byte(`{"batch":"tampered"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRelayRunner{t: t, batchPath: batchPath}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:     "defect-batch-1",
			TaskShape:   contracts.BatchTaskDefect,
			BatchDigest: digest.RawBytes(expectedBytes),
		},
		Path:     batchPath,
		RawBytes: expectedBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("run calls = %d, want 0", runner.runCalls)
	}
	if len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("runs = %#v, want unavailable", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func TestRunBatchesRejectsEmptyPlanBatchDigestBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	batchPath := filepath.Join(dir, "batch.json")
	batchBytes := []byte(`{"batch":"input"}`)
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRelayRunner{t: t, batchPath: batchPath}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:   "defect-batch-1",
			TaskShape: contracts.BatchTaskDefect,
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("run calls = %d, want 0", runner.runCalls)
	}
	if len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("runs = %#v, want unavailable", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func TestRunBatchesRejectsMissingPlanArtifactDigestSetBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	batchPath := filepath.Join(dir, "batch.json")
	batchBytes := []byte(`{"batch":"input"}`)
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(dir, "artifact.json")
	artifactBytes := []byte("artifact")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	runner := &fakeRelayRunner{t: t, batchPath: batchPath}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:        "defect-batch-1",
			TaskShape:      contracts.BatchTaskDefect,
			BatchDigest:    digest.RawBytes(batchBytes),
			ArtifactDigest: artifactDigest,
		},
		Document: contracts.VerificationBatchDocument{
			ArtifactDigest: artifactDigest,
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		ArtifactPaths:         []string{artifactPath},
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("run calls = %d, want 0", runner.runCalls)
	}
	if len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("runs = %#v, want unavailable", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func TestRunBatchesRejectsMissingArtifactInputBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	batchPath := filepath.Join(dir, "batch.json")
	batchBytes := []byte(`{"batch":"input"}`)
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes([]byte("artifact"))
	runner := &fakeRelayRunner{t: t, batchPath: batchPath}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:           "defect-batch-1",
			TaskShape:         contracts.BatchTaskDefect,
			BatchDigest:       digest.RawBytes(batchBytes),
			ArtifactDigest:    artifactDigest,
			ArtifactDigestSet: []string{artifactDigest},
		},
		Document: contracts.VerificationBatchDocument{
			ArtifactDigest: artifactDigest,
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("run calls = %d, want 0", runner.runCalls)
	}
	if len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("runs = %#v, want unavailable", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func TestRunBatchesRejectsExtraUnplannedArtifactInputBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	batchPath := filepath.Join(dir, "batch.json")
	batchBytes := []byte(`{"batch":"input"}`)
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	extraArtifactPath := filepath.Join(dir, "extra-artifact.json")
	if err := os.WriteFile(extraArtifactPath, []byte("extra artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes([]byte("artifact"))
	runner := &fakeRelayRunner{t: t, batchPath: batchPath}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:           "defect-batch-1",
			TaskShape:         contracts.BatchTaskDefect,
			BatchDigest:       digest.RawBytes(batchBytes),
			ArtifactDigest:    artifactDigest,
			ArtifactDigestSet: []string{artifactDigest},
		},
		Document: contracts.VerificationBatchDocument{
			ArtifactDigest: artifactDigest,
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		ArtifactPaths:         []string{artifactPath, extraArtifactPath},
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("run calls = %d, want 0", runner.runCalls)
	}
	if len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("runs = %#v, want unavailable", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func runLaunchFailure(t *testing.T, dir string, commandResult relayclient.CommandResult) (RunRecord, *fakeRelayRunner) {
	t.Helper()
	batchPath := filepath.Join(dir, "batch.json")
	batchBytes := []byte(`{"batch":"input"}`)
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(dir, "artifact.json")
	artifactBytes := []byte("artifact")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	runner := &fakeRelayRunner{t: t, batchPath: batchPath, result: commandResult}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:           "defect-batch-1",
			TaskShape:         contracts.BatchTaskDefect,
			BatchDigest:       digest.RawBytes(batchBytes),
			ArtifactDigest:    artifactDigest,
			ArtifactDigestSet: []string{artifactDigest},
		},
		Document: contracts.VerificationBatchDocument{
			ArtifactDigest: artifactDigest,
		},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: "bundle.json",
		CharterPath:           "charter.json",
		ArtifactPaths:         []string{artifactPath},
		Backend:               "codex",
		LaunchCWD:             dir,
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if len(result.Runs) != 1 {
		t.Fatalf("runs = %#v", result.Runs)
	}
	return result.Runs[0], runner
}

func argAfter(args []string, key string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == key {
			return args[index+1]
		}
	}
	return ""
}

func containsArgPair(args []string, key string, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == key && args[index+1] == value {
			return true
		}
	}
	return false
}
