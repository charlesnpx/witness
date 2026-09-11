package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewRunFailedToRunExitAndRejectsSymlinkedRequest(t *testing.T) {
	if os.Getenv("WITNESS_REVIEW_EXIT_HELPER") == "1" {
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("WITNESS_REVIEW_EXIT_ARGS")), &args); err != nil {
			os.Exit(97)
		}
		err := runReviewRun(args)
		if err == nil {
			os.Exit(0)
		}
		var exitCoder interface{ processExitCode() int }
		if errors.As(err, &exitCoder) {
			os.Exit(exitCoder.processExitCode())
		}
		os.Exit(98)
	}

	directory := t.TempDir()
	sourceDirectory := filepath.Join(directory, "source")
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	charterPath := filepath.Join(directory, "charter.json")
	if err := route([]string{"charter", "init", "-out", charterPath}); err != nil {
		t.Fatalf("charter init: %v", err)
	}
	delegatePath := filepath.Join(directory, "delegate")
	writeExecutableTestFile(t, delegatePath, `#!/bin/sh
case "$*" in
  *defect*) printf '{"jobId":"job-defect"}\n' ;;
  *economy*) printf '{"jobId":"job-economy"}\n' ;;
  *) exit 9 ;;
esac
`)
	agentbusPath := filepath.Join(directory, "agentbus")
	writeExecutableTestFile(t, agentbusPath, `#!/bin/sh
job=""
for arg in "$@"; do
  case "$arg" in
    job-defect|job-economy) job="$arg" ;;
  esac
done
if [ "$1" = "transcript" ]; then
  printf '{"state":"failed","items":[],"gap":false}\n'
  exit 4
fi
if [ "$1" = "status" ]; then
  printf '{"jobs":[{"jobId":"%s","state":"failed"}]}\n' "$job"
else
  printf '{"jobId":"%s","state":"failed"}\n' "$job"
fi
exit 4
`)
	args := []string{
		"-charter", charterPath,
		"-source-dir", sourceDirectory,
		"-out-dir", filepath.Join(directory, "run"),
		"-delegate", delegatePath,
		"-agentbus", agentbusPath,
		"-poll-interval", "1ms",
		"-transcript-page-size", "2",
	}
	argsData, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=TestReviewRunFailedToRunExitAndRejectsSymlinkedRequest")
	command.Env = append(os.Environ(),
		"WITNESS_REVIEW_EXIT_HELPER=1",
		"WITNESS_REVIEW_EXIT_ARGS="+string(argsData),
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("review run error = %v, output = %s; want process exit", err, output)
	}
	if exitErr.ExitCode() != ReviewRunExitFailedToRun {
		t.Fatalf("review run exit code = %d, want %d; output = %s", exitErr.ExitCode(), ReviewRunExitFailedToRun, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("review run output = %s: %v", output, err)
	}
	if result["ok"] != false || result["verdict"] != "failed_to_run" {
		t.Fatalf("review run result = %#v, want ok false and failed_to_run", result)
	}

	symlinkOutputDirectory := t.TempDir()
	resolvedOutputDirectory, err := filepath.EvalSymlinks(symlinkOutputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	operatorPath := filepath.Join(directory, "operator-work.json")
	operatorBefore := []byte("operator work must survive\n")
	if err := os.WriteFile(operatorPath, operatorBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(operatorPath, filepath.Join(symlinkOutputDirectory, "review-request.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	symlinkArgs := append([]string(nil), args...)
	symlinkArgs[5] = symlinkOutputDirectory
	err = runReviewRun(symlinkArgs)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(resolvedOutputDirectory, "review-request.json")) {
		t.Fatalf("review run error = %v, want refusal naming request path %q", err, filepath.Join(resolvedOutputDirectory, "review-request.json"))
	}
	after, err := os.ReadFile(operatorPath)
	if err != nil || string(after) != string(operatorBefore) {
		t.Fatalf("operator file = %q (read error: %v), want unchanged %q", after, err, operatorBefore)
	}
}

func writeExecutableTestFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}
