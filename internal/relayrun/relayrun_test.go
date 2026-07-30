package relayrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"witness/internal/contracts"
	"witness/internal/digest"
	"witness/internal/planning"
	"witness/internal/relayclient"
)

type fakeRelayRunner struct {
	t         *testing.T
	runCalls  int
	batchPath string
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
	return relayclient.CommandResult{
		Stdout:   []byte(`{"message":"auth failed"}`),
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	}
}

func TestRunBatchesLaunchesEachBatchOnceAndRoutesFailurePending(t *testing.T) {
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
		Runner:                runner,
	})
	if err != nil {
		t.Fatalf("RunBatches: %v", err)
	}
	if runner.runCalls != 1 {
		t.Fatalf("run calls = %d, want 1", runner.runCalls)
	}
	if len(result.Runs) != 1 {
		t.Fatalf("runs = %#v", result.Runs)
	}
	if result.Runs[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("status = %s, want unavailable", result.Runs[0].Status)
	}
	if len(result.Runs[0].Diagnostics) != 1 || result.Runs[0].Diagnostics[0].Code != CodeRelayRunFailed {
		t.Fatalf("diagnostics = %#v", result.Runs[0].Diagnostics)
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
