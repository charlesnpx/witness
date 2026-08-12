package relayrun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayclient"
	"github.com/charlesnpx/witness/internal/strictjson"
)

type fakeRelayRunner struct {
	t           *testing.T
	runCalls    int
	batchPath   string
	charterPath string
	result      relayclient.CommandResult
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
	if !containsArgPair(args, "--input", "charter="+runner.charterPath) || !containsArgPair(args, "--input", "findings="+runner.batchPath) {
		runner.t.Fatalf("missing required input bindings: %v", args)
	}
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--input" && strings.HasPrefix(args[index+1], "integration_bundle=") {
			runner.t.Fatalf("integration bundle must not be a relay named input: %v", args)
		}
	}
	return runner.result
}

type rejectIfInvokedRelayRunner struct {
	t *testing.T
}

func (runner rejectIfInvokedRelayRunner) Run(context.Context, string, ...string) relayclient.CommandResult {
	runner.t.Helper()
	runner.t.Fatal("relay must not be invoked after pre-launch rejection")
	return relayclient.CommandResult{}
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
	if launch.StdoutDigest != digest.RawBytes(launch.Stdout) || int(launch.StdoutBytes) != len(launch.Stdout) || launch.StderrDigest != digest.RawBytes(launch.Stderr) || int(launch.StderrBytes) != len(launch.Stderr) {
		t.Fatalf("launch retained-stream summaries = %#v", launch)
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

func TestReadRunRecordsBytesValidatesRetainedLaunchStreamSummaries(t *testing.T) {
	newRecord := func() RunRecord {
		return RunRecord{
			SchemaVersion:   RunRecordSchema,
			BatchID:         "defect-batch-1",
			Status:          contracts.RecordStatusUnavailable,
			RecipeID:        "witness-falsify-v2-codex",
			ProviderInvoked: ProviderInvokedUnknown,
			ConsumesBatch:   true,
			RelayLaunch: launchRecord(relayclient.CommandResult{
				Command: "fake-relay",
				Stdout:  []byte("a"),
			}, "/tmp/workspace"),
		}
	}

	t.Run("consistent retained content", func(t *testing.T) {
		record := newRecord()
		data, err := contracts.CanonicalBytes(record)
		if err != nil {
			t.Fatal(err)
		}
		runs, err := ReadRunRecordsBytes(data)
		if err != nil {
			t.Fatalf("ReadRunRecordsBytes: %v", err)
		}
		if len(runs) != 1 || runs[0].RelayLaunch == nil || runs[0].RelayLaunch.StdoutDigest != digest.RawBytes([]byte("a")) || runs[0].RelayLaunch.StdoutBytes != 1 {
			t.Fatalf("runs = %#v, want unchanged retained stdout summary", runs)
		}
	})

	t.Run("truncated digest-only capture", func(t *testing.T) {
		record := newRecord()
		record.RelayLaunch.Stdout = nil
		record.RelayLaunch.StdoutDigest = digest.RawBytes([]byte("unretained stream"))
		record.RelayLaunch.StdoutBytes = strictjson.Int(42)
		record.RelayLaunch.StdoutTruncated = true
		data, err := contracts.CanonicalBytes(record)
		if err != nil {
			t.Fatal(err)
		}
		runs, err := ReadRunRecordsBytes(data)
		if err != nil {
			t.Fatalf("ReadRunRecordsBytes: %v", err)
		}
		launch := runs[0].RelayLaunch
		if launch == nil || launch.StdoutDigest != record.RelayLaunch.StdoutDigest || launch.StdoutBytes != record.RelayLaunch.StdoutBytes || !launch.StdoutTruncated {
			t.Fatalf("launch = %#v, want accepted truncated digest-only stdout summary", launch)
		}
	})

	for _, test := range []struct {
		name      string
		mutate    func(*LaunchRecord)
		wantField string
	}{
		{
			name: "contradictory claimed digest",
			mutate: func(launch *LaunchRecord) {
				launch.StdoutDigest = digest.RawBytes([]byte("different"))
			},
			wantField: "stdout_digest",
		},
		{
			name: "contradictory claimed byte count",
			mutate: func(launch *LaunchRecord) {
				launch.StdoutBytes = strictjson.Int(99)
			},
			wantField: "stdout_bytes",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := newRecord()
			test.mutate(record.RelayLaunch)
			data, err := contracts.CanonicalBytes(record)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ReadRunRecordsBytes(data)
			if err == nil {
				t.Fatal("ReadRunRecordsBytes accepted a launch stream summary that contradicts retained stdout")
			}
			diagnostic := diag.FromError(err)
			if diagnostic.Code != CodeInvalidRunRecordStreamSummary || diagnostic.Details["stream"] != "stdout" || diagnostic.Details["field"] != test.wantField {
				t.Fatalf("diagnostic = %#v, want specific stdout stream-summary rejection", diagnostic)
			}
		})
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
	if len(result.Runs) != 1 || result.Runs[0].Status != RunStatusLaunchFailed || result.Runs[0].ProviderInvoked != ProviderInvokedFalse || result.Runs[0].ConsumesBatch {
		t.Fatalf("runs = %#v, want non-consuming launch_failed record", result.Runs)
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
	if len(result.Runs) != 1 || result.Runs[0].Status != RunStatusLaunchFailed || result.Runs[0].ProviderInvoked != ProviderInvokedFalse || result.Runs[0].ConsumesBatch {
		t.Fatalf("runs = %#v, want non-consuming launch_failed record", result.Runs)
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
	if len(result.Runs) != 1 || result.Runs[0].Status != RunStatusLaunchFailed || result.Runs[0].ProviderInvoked != ProviderInvokedFalse || result.Runs[0].ConsumesBatch {
		t.Fatalf("runs = %#v, want non-consuming launch_failed record", result.Runs)
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
	if len(result.Runs) != 1 || result.Runs[0].Status != RunStatusLaunchFailed || result.Runs[0].ProviderInvoked != ProviderInvokedFalse || result.Runs[0].ConsumesBatch {
		t.Fatalf("runs = %#v, want non-consuming launch_failed record", result.Runs)
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
	if len(result.Runs) != 1 || result.Runs[0].Status != RunStatusLaunchFailed || result.Runs[0].ProviderInvoked != ProviderInvokedFalse || result.Runs[0].ConsumesBatch {
		t.Fatalf("runs = %#v, want non-consuming launch_failed record", result.Runs)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeInvalidBatchInput {
		t.Fatalf("diagnostics = %#v, want %s", result.Runs[0].Diagnostics, CodeInvalidBatchInput)
	}
}

func TestRunBatchesRecordsEveryArtifactBinding(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	if err := os.WriteFile(charterPath, []byte("charter"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := writeIntegrationBundleForTest(t, dir)
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
	extraArtifactPath := filepath.Join(dir, "extra-artifact.json")
	extraArtifactBytes := []byte("extra artifact")
	if err := os.WriteFile(extraArtifactPath, extraArtifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	extraArtifactDigest := digest.RawBytes(extraArtifactBytes)
	runner := &fakeRelayRunner{t: t, batchPath: batchPath, charterPath: charterPath, result: relayclient.CommandResult{
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	}}
	result, err := RunBatches(context.Background(), []BatchInput{{
		Plan: planning.BatchPlan{
			BatchID:           "defect-batch-1",
			TaskShape:         contracts.BatchTaskDefect,
			BatchDigest:       digest.RawBytes(batchBytes),
			ArtifactDigest:    artifactDigest,
			ArtifactDigestSet: []string{artifactDigest, extraArtifactDigest},
		},
		Document: contracts.VerificationBatchDocument{ArtifactDigest: artifactDigest},
		Path:     batchPath,
		RawBytes: batchBytes,
	}}, Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: bundlePath,
		CharterPath:           charterPath,
		ArtifactPaths:         []string{artifactPath, extraArtifactPath},
		ArtifactDigests:       []string{artifactDigest, extraArtifactDigest},
		Backend:               "codex",
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 1 || len(result.Runs) != 1 {
		t.Fatalf("run calls = %d, runs = %#v", runner.runCalls, result.Runs)
	}
	want := []string{
		"findings=" + batchPath + "@" + digest.RawBytes(batchBytes),
		"artifact=" + artifactPath + "@" + artifactDigest,
		"artifact=" + extraArtifactPath + "@" + extraArtifactDigest,
	}
	if got := result.Runs[0].InputBindings; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("input bindings = %#v, want %#v", got, want)
	}
}

func TestRunBatchesNamedInputBudgets(t *testing.T) {
	t.Run("within per-role budgets launches unchanged", func(t *testing.T) {
		dir := t.TempDir()
		inputs := newBudgetTestInputs(
			t,
			dir,
			jsonPayloadOfSize(t, 200*1024),
			jsonPayloadOfSize(t, 200*1024),
			bytes.Repeat([]byte("a"), 800*1024),
		)
		runner := &fakeRelayRunner{t: t, batchPath: inputs.batchPath, charterPath: inputs.charterPath, result: relayclient.CommandResult{
			ExitCode: 1,
			Err:      errors.New("exit status 1"),
		}}
		result, err := RunBatches(context.Background(), []BatchInput{inputs.batch}, inputs.options(runner))
		if err != nil {
			t.Fatalf("RunBatches: %v", err)
		}
		if runner.runCalls != 1 || len(result.Runs) != 1 || result.Runs[0].Status != contracts.RecordStatusUnavailable {
			t.Fatalf("run calls = %d, runs = %#v, want one unchanged launch", runner.runCalls, result.Runs)
		}
	})

	for _, test := range []struct {
		name      string
		charter   []byte
		artifact  []byte
		wantRole  string
		wantLimit int64
	}{
		{
			name:      "charter over its 256 KiB contract budget is rejected before launch",
			charter:   jsonPayloadOfSize(t, 256*1024+1),
			artifact:  []byte("artifact"),
			wantRole:  "charter",
			wantLimit: 256 * 1024,
		},
		{
			name:      "artifact over its 1 MiB contract budget is rejected before launch",
			charter:   []byte("charter"),
			artifact:  bytes.Repeat([]byte("a"), 1024*1024+1),
			wantRole:  "artifact",
			wantLimit: 1024 * 1024,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			inputs := newBudgetTestInputs(t, dir, test.charter, []byte("findings"), test.artifact)
			result, err := RunBatches(context.Background(), []BatchInput{inputs.batch}, inputs.options(rejectIfInvokedRelayRunner{t: t}))
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
			if len(record.Diagnostics) != 1 || record.Diagnostics[0].Code != CodeNamedInputBudgetExceeded {
				t.Fatalf("diagnostics = %#v, want one %s", record.Diagnostics, CodeNamedInputBudgetExceeded)
			}
			details := record.Diagnostics[0].Details
			if details["role"] != test.wantRole || details["limit_bytes"] != test.wantLimit || details["contract_id"] != "witnessed-review/witness-falsification-v2" {
				t.Fatalf("diagnostic details = %#v", details)
			}
		})
	}
}

type budgetTestInputs struct {
	batch        BatchInput
	batchPath    string
	charterPath  string
	bundlePath   string
	artifactPath string
}

func newBudgetTestInputs(t *testing.T, dir string, charterBytes []byte, batchBytes []byte, artifactBytes []byte) budgetTestInputs {
	t.Helper()
	charterPath := filepath.Join(dir, "charter.json")
	if err := os.WriteFile(charterPath, charterBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	batchPath := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(batchPath, batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDigest := digest.RawBytes(artifactBytes)
	return budgetTestInputs{
		batchPath:    batchPath,
		charterPath:  charterPath,
		bundlePath:   writeIntegrationBundleForTest(t, dir),
		artifactPath: artifactPath,
		batch: BatchInput{
			Plan: planning.BatchPlan{
				BatchID:           "defect-batch-1",
				TaskShape:         contracts.BatchTaskDefect,
				BatchDigest:       digest.RawBytes(batchBytes),
				ArtifactDigest:    artifactDigest,
				ArtifactDigestSet: []string{artifactDigest},
			},
			Document: contracts.VerificationBatchDocument{ArtifactDigest: artifactDigest},
			Path:     batchPath,
			RawBytes: batchBytes,
		},
	}
}

func jsonPayloadOfSize(t *testing.T, size int) []byte {
	t.Helper()
	prefix := []byte(`{"content":"`)
	suffix := []byte(`"}`)
	if size < len(prefix)+len(suffix) {
		t.Fatalf("JSON payload size %d is too small", size)
	}
	payload := append([]byte(nil), prefix...)
	payload = append(payload, bytes.Repeat([]byte("x"), size-len(prefix)-len(suffix))...)
	payload = append(payload, suffix...)
	if len(payload) != size {
		t.Fatalf("JSON payload size = %d, want %d", len(payload), size)
	}
	return payload
}

func (inputs budgetTestInputs) options(runner relayclient.Runner) Options {
	return Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: inputs.bundlePath,
		CharterPath:           inputs.charterPath,
		ArtifactPaths:         []string{inputs.artifactPath},
		Backend:               "codex",
		Runner:                runner,
	}
}

// TestRunBatchesRejectsBundleWithoutRoleBudget pins the fail-closed half of the
// named-input budget preflight: when the selected contract cannot supply a
// role's max_bytes, the budget is unknowable, so the batch must be rejected
// before launch rather than launched on the hope that relay accepts it. A
// launched-and-rejected run can leave provider_invoked unknown, which consumes
// the batch's single verification attempt.
func TestRunBatchesRejectsBundleWithoutRoleBudget(t *testing.T) {
	dir := t.TempDir()
	inputs := newBudgetTestInputs(t, dir, []byte(`{"charter":"c"}`), []byte(`{"batch":"b"}`), []byte("artifact"))

	options := inputs.options(rejectIfInvokedRelayRunner{t: t})
	options.IntegrationBundlePath = writeBundleWithoutCharterBudget(t, dir, inputs.bundlePath)

	result, err := RunBatches(context.Background(), []BatchInput{inputs.batch}, options)
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
	if len(record.Diagnostics) != 1 || record.Diagnostics[0].Code != CodeNamedInputBudgetInvalid {
		t.Fatalf("diagnostics = %#v, want one %s", record.Diagnostics, CodeNamedInputBudgetInvalid)
	}
}

// writeBundleWithoutCharterBudget copies the shipped bundle fixture and removes
// exactly one role's max_bytes, leaving the rest of the document intact so the
// failure is attributable to the missing budget and not to a malformed bundle.
func writeBundleWithoutCharterBudget(t *testing.T, dir string, sourcePath string) string {
	t.Helper()
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	contractsByID, ok := bundle["contracts"].(map[string]any)
	if !ok {
		t.Fatalf("bundle contracts = %#v, want an object", bundle["contracts"])
	}
	contract, ok := contractsByID["witnessed-review/witness-falsification-v2"].(map[string]any)
	if !ok {
		t.Fatalf("bundle is missing the witness-falsification-v2 contract")
	}
	contractInputs, ok := contract["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("contract inputs = %#v, want an object", contract["inputs"])
	}
	charter, ok := contractInputs["charter"].(map[string]any)
	if !ok {
		t.Fatalf("contract is missing the charter input")
	}
	if _, present := charter["max_bytes"]; !present {
		t.Fatal("charter input already has no max_bytes; fixture no longer exercises this path")
	}
	delete(charter, "max_bytes")

	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle-without-charter-budget.json")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runLaunchFailure(t *testing.T, dir string, commandResult relayclient.CommandResult) (RunRecord, *fakeRelayRunner) {
	t.Helper()
	charterPath := filepath.Join(dir, "charter.json")
	if err := os.WriteFile(charterPath, []byte("charter"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := writeIntegrationBundleForTest(t, dir)
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
	runner := &fakeRelayRunner{t: t, batchPath: batchPath, charterPath: charterPath, result: commandResult}
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
		IntegrationBundlePath: bundlePath,
		CharterPath:           charterPath,
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

func writeIntegrationBundleForTest(t *testing.T, dir string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve relayrun test source path")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
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
