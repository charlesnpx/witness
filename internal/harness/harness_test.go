package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/strictjson"
)

func TestRunEchoReceiptValidAndOutputDigestMatches(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "stdout_contains=ok",
	}

	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.ExecutionStatus != contracts.ExecutionStatusSatisfied {
		t.Fatalf("execution_status = %s", result.Receipt.ExecutionStatus)
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationValid {
		t.Fatalf("verification = %#v", verification)
	}
	stdoutPath, err := ArtifactPath(fixture.outputDir, *result.Receipt.Captures.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != "ok\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	if got := digest.RawBytes(stdout); got != result.Receipt.Captures.Stdout.Digest {
		t.Fatalf("stdout digest = %s, want %s", got, result.Receipt.Captures.Stdout.Digest)
	}
	data, err := os.ReadFile(result.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.ReadExecutionReceiptBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := contracts.ExecutionReceiptDigest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if receiptDigest != result.ReceiptDigest {
		t.Fatalf("receipt digest = %s, want %s", receiptDigest, result.ReceiptDigest)
	}
}

func TestValidateEnvironmentDiagnosticsAreDeterministic(t *testing.T) {
	env := map[string]string{
		"z=": "last",
		"a=": "first",
		"m=": "middle",
	}
	var first []diag.Diagnostic
	validateEnvironment(&first, env)
	want := environmentDiagnosticKeys(first)
	if len(want) != 3 || want[0] != "a=" || want[1] != "m=" || want[2] != "z=" {
		t.Fatalf("diagnostic keys = %#v, want sorted invalid keys", want)
	}
	for i := 0; i < 25; i++ {
		var diagnostics []diag.Diagnostic
		validateEnvironment(&diagnostics, env)
		if got := environmentDiagnosticKeys(diagnostics); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("run %d diagnostic keys = %#v, want %#v", i, got, want)
		}
	}
}

func TestVerifyReceiptTamperTable(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name                   string
		mutate                 func(*contracts.ExecutionReceipt)
		expected               string
		resign                 bool
		expectedClassification string
	}{
		{
			name: "mutated payload field",
			mutate: func(receipt *contracts.ExecutionReceipt) {
				receipt.ObservedObservation = "exit_code=99;timed_out=false"
			},
			expected: fixture.sourceDigest,
		},
		{
			name: "wrong source digest",
			mutate: func(receipt *contracts.ExecutionReceipt) {
				receipt.ArtifactDigest = wrongDigest
				receipt.FrozenSource.Digest = wrongDigest
			},
			expected: fixture.sourceDigest,
			resign:   true,
		},
		{
			name: "wrong outputs digest",
			mutate: func(receipt *contracts.ExecutionReceipt) {
				receipt.Captures.Stdout.Digest = wrongDigest
			},
			expected:               fixture.sourceDigest,
			resign:                 true,
			expectedClassification: ClassificationUnavailable,
		},
		{
			name: "signed inconsistent execution status",
			mutate: func(receipt *contracts.ExecutionReceipt) {
				receipt.Command.ExpectedObservation = "exit_code=1"
				receipt.ExpectedObservation = "exit_code=1"
				receipt.ExecutionStatus = contracts.ExecutionStatusSatisfied
			},
			expected: fixture.sourceDigest,
			resign:   true,
		},
		{
			name: "bad authentication",
			mutate: func(receipt *contracts.ExecutionReceipt) {
				receipt.Authentication.Signature = "00"
			},
			expected: fixture.sourceDigest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := cloneReceipt(t, result.Receipt)
			test.mutate(&receipt)
			if test.resign {
				if err := SignReceipt(&receipt, fixture.key); err != nil {
					t.Fatal(err)
				}
			}
			verification := VerifyReceipt(VerifyOptions{
				Receipt:              receipt,
				OutputDir:            fixture.outputDir,
				HMACKey:              fixture.key,
				ExpectedSourceDigest: test.expected,
			})
			expectedClassification := test.expectedClassification
			if expectedClassification == "" {
				expectedClassification = ClassificationInvalid
			}
			if verification.Classification != expectedClassification {
				t.Fatalf("verification = %#v", verification)
			}
		})
	}
}

func environmentDiagnosticKeys(diagnostics []diag.Diagnostic) []string {
	keys := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		key, _ := diagnostic.Details["key"].(string)
		keys = append(keys, key)
	}
	return keys
}

func TestVerifyReceiptWithoutArtifactsUnavailable(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationUnavailable {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyReceiptUnreadableArtifactUnavailable(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	stdoutPath, err := ArtifactPath(fixture.outputDir, *result.Receipt.Captures.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stdoutPath); err != nil {
		t.Fatal(err)
	}

	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationUnavailable {
		t.Fatalf("verification = %#v", verification)
	}
	if !hasDiagnostic(verification.Diagnostics, CodeReceiptUnavailable) {
		t.Fatalf("missing unavailable diagnostic: %#v", verification.Diagnostics)
	}
	if hasDiagnostic(verification.Diagnostics, CodeArtifactDigestMismatch) {
		t.Fatalf("read failure reported as digest mismatch: %#v", verification.Diagnostics)
	}
}

func TestVerifyReceiptUnreadableMutationReportUnavailable(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	deltaRef := findProducedArtifact(t, result.Receipt, "workspace-mutation-report")
	deltaPath, err := ArtifactPath(fixture.outputDir, deltaRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(deltaPath); err != nil {
		t.Fatal(err)
	}

	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationUnavailable {
		t.Fatalf("verification = %#v", verification)
	}
	if !hasDiagnostic(verification.Diagnostics, CodeReceiptUnavailable) {
		t.Fatalf("missing unavailable diagnostic: %#v", verification.Diagnostics)
	}
	if hasDiagnostic(verification.Diagnostics, CodeReceiptRelationshipMismatch) {
		t.Fatalf("unreadable mutation report reported as relationship mismatch: %#v", verification.Diagnostics)
	}
}

func TestRunReportsWorkspaceMutationDelta(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "write",
	}

	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	deltaRef := findProducedArtifact(t, result.Receipt, "workspace-mutation-report")
	deltaPath, err := ArtifactPath(fixture.outputDir, deltaRef)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := strictjson.DecodeBytes[WorkspaceDelta](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Added) != 1 || delta.Added[0].Path != "created.txt" {
		t.Fatalf("delta added = %#v", delta.Added)
	}
	if findProducedArtifact(t, result.Receipt, "execution-artifact").Digest == "" {
		t.Fatal("missing produced workspace artifact")
	}
}

func TestRunReportsDirectoryOnlyMutationDelta(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "mkdir",
	}

	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	deltaRef := findProducedArtifact(t, result.Receipt, "workspace-mutation-report")
	deltaPath, err := ArtifactPath(fixture.outputDir, deltaRef)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := strictjson.DecodeBytes[WorkspaceDelta](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Added) != 1 || delta.Added[0].Path != "created-dir" || !delta.Added[0].AfterDir || delta.Added[0].AfterDigest != "" {
		t.Fatalf("delta added = %#v", delta.Added)
	}
	for _, ref := range result.Receipt.Captures.ProducedArtifacts {
		if ref.Kind == "execution-artifact" {
			t.Fatalf("directory-only mutation produced file artifact: %#v", ref)
		}
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationValid {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestRunAllowsNestedWorkspaceCWD(t *testing.T) {
	sourceDir := t.TempDir()
	nestedDir := filepath.Join(sourceDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "input.txt"), []byte("source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := newRunFixtureFromSource(t, sourceDir)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 "nested",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "write",
	}

	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	deltaRef := findProducedArtifact(t, result.Receipt, "workspace-mutation-report")
	deltaPath, err := ArtifactPath(fixture.outputDir, deltaRef)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := strictjson.DecodeBytes[WorkspaceDelta](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Added) != 1 || delta.Added[0].Path != "nested/created.txt" {
		t.Fatalf("delta added = %#v", delta.Added)
	}
}

func TestRunRejectsWorkspaceCWDSymlinkEscape(t *testing.T) {
	sourceDir := t.TempDir()
	var outsideDir string
	for _, name := range []string{"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9"} {
		candidate := filepath.Join("/tmp", name)
		if err := os.Mkdir(candidate, 0o755); err == nil {
			outsideDir = candidate
			break
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	if outsideDir == "" {
		t.Fatal("no short temporary outside path available")
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })
	if err := os.Symlink(outsideDir, filepath.Join(sourceDir, "outside")); err != nil {
		t.Fatal(err)
	}
	expectedResolved, err := filepath.EvalSymlinks(outsideDir)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newRunFixtureFromSource(t, sourceDir)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 "outside",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "write",
	}

	_, err = Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err == nil {
		t.Fatal("Run succeeded with command.cwd symlink escape")
	}
	var harnessErr *Error
	if !errors.As(err, &harnessErr) || !hasDiagnostic(harnessErr.Diagnostics, CodeWorkspaceCWDEscape) {
		t.Fatalf("err = %#v", err)
	}
	var cwdDiagnostic diag.Diagnostic
	for _, diagnostic := range harnessErr.Diagnostics {
		if diagnostic.Code == CodeWorkspaceCWDEscape {
			cwdDiagnostic = diagnostic
			break
		}
	}
	if cwdDiagnostic.Path != "/command/cwd" {
		t.Fatalf("diagnostic path = %q, want /command/cwd", cwdDiagnostic.Path)
	}
	if cwdDiagnostic.Details["resolved"] != expectedResolved {
		t.Fatalf("resolved detail = %#v, want %s", cwdDiagnostic.Details["resolved"], expectedResolved)
	}
	marker := filepath.Join(outsideDir, "created.txt")
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("command executed outside workspace and wrote %s", marker)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestInventoryWorkspaceRecordsDirectorySpecialModeBits(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sticky")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Skipf("special directory mode bits are not supported: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSticky == 0 {
		t.Skip("sticky bit was not preserved by the filesystem")
	}

	inventory, err := InventoryWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Files) != 1 || inventory.Files[0].Path != "sticky" {
		t.Fatalf("inventory files = %#v", inventory.Files)
	}
	if inventory.Files[0].Mode != "041777" {
		t.Fatalf("directory mode = %s, want 041777", inventory.Files[0].Mode)
	}
}

func TestRunTimeoutRecordsFailedTimedOutStatus(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "sleep",
	}
	fixture.request.TimeoutMS = 100

	started := time.Now()
	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("timeout command did not return promptly")
	}
	if result.Receipt.ExecutionStatus != contracts.ExecutionStatusFailed {
		t.Fatalf("execution_status = %s, want %s", result.Receipt.ExecutionStatus, contracts.ExecutionStatusFailed)
	}
	if timedOut, ok := result.Receipt.ResourceLimits["timed_out"].(bool); !ok || !timedOut {
		t.Fatalf("timed_out resource limit = %#v", result.Receipt.ResourceLimits["timed_out"])
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationValid {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestInterruptedCommandTerminationPrefersEarlierExternalDeadline(t *testing.T) {
	now := time.Now()
	parent, cancel := context.WithDeadline(context.Background(), now.Add(-20*time.Millisecond))
	defer cancel()
	<-parent.Done()

	timedOut, canceled, reason := interruptedCommandTermination(parent, now.Add(-10*time.Millisecond), true, now)
	if timedOut || !canceled || reason != terminationExternalDeadline {
		t.Fatalf("termination = timedOut:%v canceled:%v reason:%s", timedOut, canceled, reason)
	}
}

func TestRunCanceledContextRecordsCanceledNotTimedOut(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                helperCommand(t),
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	fixture.request.Environment = map[string]string{
		"WITNESS_HARNESS_HELPER":      "1",
		"WITNESS_HARNESS_HELPER_MODE": "sleep",
	}
	fixture.request.TimeoutMS = 5000

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Run(ctx, RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.ExecutionStatus != contracts.ExecutionStatusFailed {
		t.Fatalf("execution_status = %s, want %s", result.Receipt.ExecutionStatus, contracts.ExecutionStatusFailed)
	}
	if timedOut, ok := result.Receipt.ResourceLimits["timed_out"].(bool); !ok || timedOut {
		t.Fatalf("timed_out resource limit = %#v", result.Receipt.ResourceLimits["timed_out"])
	}
	if canceled, ok := result.Receipt.ResourceLimits["canceled"].(bool); !ok || !canceled {
		t.Fatalf("canceled resource limit = %#v", result.Receipt.ResourceLimits["canceled"])
	}
	if reason, ok := result.Receipt.ResourceLimits["termination_reason"].(string); !ok || reason != terminationCanceled {
		t.Fatalf("termination_reason resource limit = %#v", result.Receipt.ResourceLimits["termination_reason"])
	}
	if !strings.Contains(result.Receipt.ObservedObservation, "termination_reason=canceled") || strings.Contains(result.Receipt.ObservedObservation, "timed_out=true") {
		t.Fatalf("observed_observation = %q", result.Receipt.ObservedObservation)
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationValid {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestStartErrorObservationRequiresDetailAndCannotSatisfy(t *testing.T) {
	stdoutDigest := digest.RawBytes(nil)
	stderrDigest := digest.RawBytes(nil)
	base := strings.Join([]string{
		"exit_code=-1",
		"timed_out=false",
		"termination_reason=start_error",
		"stdout_digest=" + stdoutDigest,
		"stderr_digest=" + stderrDigest,
	}, ";")
	if _, diagnostics := parseObservedObservation(base); !hasDiagnostic(diagnostics, CodeReceiptRelationshipMismatch) {
		t.Fatalf("missing start_error detail diagnostic: %#v", diagnostics)
	}

	parsed, diagnostics := parseObservedObservation(base + ";start_error=" + escapeObservationValue("fork/exec missing: no such file or directory"))
	if len(diagnostics) > 0 {
		t.Fatalf("parse diagnostics = %#v", diagnostics)
	}
	status := classifyObservedExecution("exit_code=-1", parsed, nil, nil)
	if status != contracts.ExecutionStatusFailed {
		t.Fatalf("execution_status = %s, want %s", status, contracts.ExecutionStatusFailed)
	}
}

func TestRunEscapesStartErrorInObservedObservation(t *testing.T) {
	fixture := newRunFixture(t)
	missing := filepath.Join(t.TempDir(), "missing;name=value")
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{missing},
		CWD:                 ".",
		ExpectedObservation: "exit_code=-1",
	}

	result, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.ExecutionStatus != contracts.ExecutionStatusFailed {
		t.Fatalf("execution_status = %s, want %s", result.Receipt.ExecutionStatus, contracts.ExecutionStatusFailed)
	}
	if strings.Contains(result.Receipt.ObservedObservation, "missing;name=value") {
		t.Fatalf("observed_observation contains unescaped start_error: %q", result.Receipt.ObservedObservation)
	}
	if !strings.Contains(result.Receipt.ObservedObservation, "missing%3Bname%3Dvalue") {
		t.Fatalf("observed_observation did not escape delimiters: %q", result.Receipt.ObservedObservation)
	}
	observed, diagnostics := parseObservedObservation(result.Receipt.ObservedObservation)
	if len(diagnostics) > 0 {
		t.Fatalf("parse diagnostics = %#v", diagnostics)
	}
	if !strings.Contains(observed.StartError, "missing;name=value") {
		t.Fatalf("start_error = %q", observed.StartError)
	}
	verification := VerifyReceipt(VerifyOptions{
		Receipt:              result.Receipt,
		OutputDir:            fixture.outputDir,
		HMACKey:              fixture.key,
		ExpectedSourceDigest: fixture.sourceDigest,
	})
	if verification.Classification != ClassificationValid {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestRunRejectsShellArgv(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/sh", "-c", "true"},
		CWD:                 ".",
		ExpectedObservation: "exit_code=0",
	}
	_, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err == nil {
		t.Fatal("Run succeeded with shell argv")
	}
	var harnessErr *Error
	if !errors.As(err, &harnessErr) || !hasDiagnostic(harnessErr.Diagnostics, CodeShellForbidden) {
		t.Fatalf("err = %#v", err)
	}
}

func TestRunRejectsNonCanonicalExpectedObservationBool(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "timed_out=1",
	}
	_, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err == nil {
		t.Fatal("Run succeeded with non-canonical expected_observation bool")
	}
	var harnessErr *Error
	if !errors.As(err, &harnessErr) || !hasDiagnostic(harnessErr.Diagnostics, CodeInvalidExpectedObservation) {
		t.Fatalf("err = %#v", err)
	}
}

func TestRunRejectsUnsupportedExpectedObservation(t *testing.T) {
	fixture := newRunFixture(t)
	fixture.request.Command = contracts.ExecutableSpec{
		Argv:                []string{"/bin/echo", "ok"},
		CWD:                 ".",
		ExpectedObservation: "exit_zero",
	}
	_, err := Run(context.Background(), RunOptions{Request: fixture.request, OutputDir: fixture.outputDir})
	if err == nil {
		t.Fatal("Run succeeded with unsupported expected_observation")
	}
	var harnessErr *Error
	if !errors.As(err, &harnessErr) || !hasDiagnostic(harnessErr.Diagnostics, CodeInvalidExpectedObservation) {
		t.Fatalf("err = %#v", err)
	}
}

func TestHarnessHelperProcess(t *testing.T) {
	if os.Getenv("WITNESS_HARNESS_HELPER") != "1" {
		return
	}
	switch os.Getenv("WITNESS_HARNESS_HELPER_MODE") {
	case "write":
		if err := os.WriteFile("created.txt", []byte("created\n"), 0o644); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	case "mkdir":
		if err := os.Mkdir("created-dir", 0o755); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

type runFixture struct {
	request      RunRequest
	key          []byte
	outputDir    string
	sourceDigest string
}

func newRunFixture(t *testing.T) runFixture {
	t.Helper()
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "input.txt"), []byte("source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return newRunFixtureFromSource(t, sourceDir)
}

func newRunFixtureFromSource(t *testing.T, sourceDir string) runFixture {
	t.Helper()
	snapshotDir := filepath.Join(t.TempDir(), "snapshot")
	snapshot, err := freeze.Create(context.Background(), freeze.Options{
		SourceDir:   sourceDir,
		OutputDir:   snapshotDir,
		AllowNonGit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("test-hmac-key")
	keyPath := filepath.Join(t.TempDir(), "hmac.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	request := RunRequest{
		SchemaVersion: RequestSchemaVersion,
		FindingID:     "finding-1",
		CharterHash:   "sha256:" + strings.Repeat("a", 64),
		FrozenSource: contracts.ArtifactRef{
			Kind:          "source-snapshot-manifest",
			ID:            "source-snapshot",
			Digest:        snapshot.ManifestDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		FrozenSourceManifestPath: snapshot.ManifestPath,
		TimeoutMS:                2000,
		Issuer: contracts.ReceiptIssuer{
			ID:     "issuer-1",
			Actor:  "test",
			Method: "hmac-sha256-key-file",
		},
		Authentication: RunRequestAuthentication{
			Scheme:  AuthenticationScheme,
			KeyID:   "test-key",
			KeyFile: keyPath,
		},
	}
	return runFixture{
		request:      request,
		key:          key,
		outputDir:    filepath.Join(t.TempDir(), "receipts"),
		sourceDigest: snapshot.ManifestDigest,
	}
}

func helperCommand(t *testing.T) []string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{executable, "-test.run=TestHarnessHelperProcess"}
}

func cloneReceipt(t *testing.T, receipt contracts.ExecutionReceipt) contracts.ExecutionReceipt {
	t.Helper()
	data, err := contracts.ExecutionReceiptCanonicalBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := contracts.ReadExecutionReceiptBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func findProducedArtifact(t *testing.T, receipt contracts.ExecutionReceipt, kind string) contracts.ArtifactRef {
	t.Helper()
	for _, ref := range receipt.Captures.ProducedArtifacts {
		if ref.Kind == kind {
			return ref
		}
	}
	t.Fatalf("missing produced artifact kind %s in %#v", kind, receipt.Captures.ProducedArtifacts)
	return contracts.ArtifactRef{}
}

func hasDiagnostic(diagnostics []diag.Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}
