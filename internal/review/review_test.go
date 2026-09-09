package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/digest"
	contractreview "github.com/charlesnpx/witness/contract/review"
)

func TestAbsentConfigSelectsBundledDefaultsWithoutWriting(t *testing.T) {
	home := t.TempDir()
	path, err := ConfigPathFrom(func(name string) string { return "" }, func() (string, error) { return home, nil })
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfigAt(path)
	if err != nil {
		t.Fatalf("LoadConfigAt: %v", err)
	}
	if config != (Config{Adapter: AdapterDescriptor{ID: DefaultAdapterID}, Recipe: DefaultRecipeID, Policy: Policy{}}) {
		t.Fatalf("config = %#v, want bundled defaults", config)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config stat = %v, want absent path", err)
	}
}

func TestInvalidConfigNamesFieldInsteadOfFallingBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"adapter":{"id":"simple"},"recipe":"operator-typo","policy":{"require_transcript":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfigAt(path)
	if err == nil || !strings.Contains(err.Error(), `"recipe"`) {
		t.Fatalf("LoadConfigAt error = %v, want recipe field error", err)
	}
	if config != (Config{}) {
		t.Fatalf("invalid config returned %#v, want no default selection", config)
	}
}

func TestCompletedNoncompliantExitIsObservedAsCompleted(t *testing.T) {
	request, frozen, packets := testRunInputs(t)
	resultPaths := testReports(t, request, frozen)
	delegate, agentbus := fakeReviewCommands(t, resultPaths, JobExitCompletedNoncompliant)
	result, err := NewSimpleAdapter(SimpleAdapterOptions{
		DelegateExecutable: delegate,
		AgentbusExecutable: agentbus,
		PollInterval:       -1,
		TranscriptPageSize: 2,
	}).Run(context.Background(), SimpleRunOptions{
		Request:          request,
		FrozenCharter:    frozen,
		Packets:          packets,
		WorkingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("adapter Run: %v", err)
	}
	if len(result.Jobs) != 2 || result.Jobs[0].State != "completed" || result.Jobs[0].StateExitCode != JobExitCompletedNoncompliant {
		t.Fatalf("jobs = %#v, want completed job with exit code 3", result.Jobs)
	}
	if !result.ObservedExecution.Complete {
		t.Fatal("completed-noncompliant exit was treated as incomplete execution")
	}
	if result.Completion.Verdict != contractreview.CompletionVerdictFailedToRun {
		t.Fatalf("verdict = %q, want failed_to_run for noncompliant output", result.Completion.Verdict)
	}
}

func TestUnavailableResultArtifactCannotProduceSatisfied(t *testing.T) {
	request, frozen, packets := testRunInputs(t)
	resultPaths := make(map[string]string, len(request.RequiredOutputs))
	for _, reviewer := range request.RequiredOutputs {
		resultPaths[reviewer] = filepath.Join(t.TempDir(), reviewer+"-missing.json")
	}
	delegate, agentbus := fakeReviewCommands(t, resultPaths, JobExitResultUnavailable)
	result, err := NewSimpleAdapter(SimpleAdapterOptions{
		DelegateExecutable: delegate,
		AgentbusExecutable: agentbus,
		PollInterval:       -1,
		TranscriptPageSize: 2,
	}).Run(context.Background(), SimpleRunOptions{
		Request:          request,
		FrozenCharter:    frozen,
		Packets:          packets,
		WorkingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("adapter Run: %v", err)
	}
	if result.Completion.Verdict == contractreview.CompletionVerdictSatisfied {
		t.Fatal("unavailable result artifact produced satisfied completion")
	}
	if !result.ObservedExecution.Complete || result.ObservedExecution.ResultArtifactAvailable {
		t.Fatalf("observed execution = %#v, want complete with unavailable artifact", result.ObservedExecution)
	}
	for _, job := range result.Jobs {
		if job.ReportStatus != contractreview.ExecutionReportUnavailable {
			t.Fatalf("job %q report status = %q, want unavailable", job.Reviewer, job.ReportStatus)
		}
	}
}

func TestValidEmptyReportsProduceSatisfied(t *testing.T) {
	request, frozen, packets := testRunInputs(t)
	resultPaths := testReports(t, request, frozen)
	delegate, agentbus := fakeReviewCommands(t, resultPaths, JobExitCompleted)
	result, err := NewSimpleAdapter(SimpleAdapterOptions{
		DelegateExecutable: delegate,
		AgentbusExecutable: agentbus,
		PollInterval:       -1,
		TranscriptPageSize: 2,
	}).Run(context.Background(), SimpleRunOptions{
		Request:          request,
		FrozenCharter:    frozen,
		Packets:          packets,
		WorkingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("adapter Run: %v", err)
	}
	if result.Completion.Verdict != contractreview.CompletionVerdictSatisfied {
		t.Fatalf("verdict = %q, want satisfied", result.Completion.Verdict)
	}
	if !result.Evidence.HostProduced() || !result.Evidence.Completed() || !result.Evidence.ResultArtifactAvailable() {
		t.Fatalf("evidence = %#v, want host-produced complete available evidence", result.Evidence)
	}
	for _, reviewer := range request.RequiredOutputs {
		if outcome, ok := result.Evidence.ReportOutcome(reviewer); !ok || outcome != contractreview.ExecutionReportValid {
			t.Fatalf("evidence outcome for %q = %q, %t; want valid", reviewer, outcome, ok)
		}
	}
}

func testRunInputs(t *testing.T) (contractreview.ReviewRequestV2Document, charter.FrozenCharter, []ReviewerPacket) {
	t.Helper()
	input, ok := charter.InitTemplate(charter.TemplateMinimal, "owner", "initial", "initial")
	if !ok {
		t.Fatal("minimal Charter template unavailable")
	}
	frozen, err := charter.Freeze(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	recipe, ok := BundledRecipe(DefaultRecipeID)
	if !ok {
		t.Fatal("bundled recipe unavailable")
	}
	recipeBytes, err := contractreview.ReviewRecipeCanonicalBytes(recipe)
	if err != nil {
		t.Fatal(err)
	}
	recipeDigest, err := contractreview.ReviewRecipeDigest(recipeBytes)
	if err != nil {
		t.Fatal(err)
	}
	request := contractreview.ReviewRequestV2Document{
		SchemaVersion:     contractreview.ReviewRequestV2,
		ConsumerIdentity:  contractreview.Identity{Kind: "witness", ID: "test"},
		Subject:           contractreview.RequestSubject{Head: "test-head"},
		CharterHash:       frozen.CharterHash,
		ReviewInputDigest: digest.RawBytes([]byte("review-input")),
		FrozenRecipe:      recipeBytes,
		RecipeDigest:      recipeDigest,
		Adapter:           DefaultAdapterID,
		RequiredOutputs:   append([]string(nil), recipe.RequiredOutputs...),
	}
	if err := contractreview.RequireValidReviewRequestV2(request); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	packets := make([]ReviewerPacket, 0, len(request.RequiredOutputs))
	for _, reviewer := range request.RequiredOutputs {
		promptPath := filepath.Join(directory, reviewer+".prompt")
		if err := os.WriteFile(promptPath, []byte("prompt"), 0o600); err != nil {
			t.Fatal(err)
		}
		packets = append(packets, ReviewerPacket{Reviewer: reviewer, PromptPath: promptPath})
	}
	return request, frozen, packets
}

func testReports(t *testing.T, request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter) map[string]string {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, len(request.RequiredOutputs))
	requestDigest, err := contractreview.ReviewRequestV2Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, reviewer := range request.RequiredOutputs {
		report := contractreview.ReviewReportV2Document{
			SchemaVersion:     contractreview.ReviewReportV2,
			RequestDigest:     requestDigest,
			RecipeDigest:      request.RecipeDigest,
			Reviewer:          reviewer,
			CharterHash:       frozen.CharterHash,
			ReviewInputDigest: request.ReviewInputDigest,
			SourceIdentity:    contractreview.Identity{Kind: "test", ID: "source"},
			ConsumerIdentity:  request.ConsumerIdentity,
			Findings:          []contractreview.ReviewReportV2Finding{},
			Evaluation:        &contractreview.ReportEvaluation{EvaluatedPaths: []string{"."}, EvaluatedGoalIDs: []string{}},
		}
		if err := contractreview.RequireValidReviewReportV2(report, request, frozen); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, reviewer+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[reviewer] = path
	}
	return paths
}

func fakeReviewCommands(t *testing.T, resultPaths map[string]string, exitCode int) (string, string) {
	t.Helper()
	directory := t.TempDir()
	delegate := filepath.Join(directory, "delegate")
	agentbus := filepath.Join(directory, "agentbus")
	defectPath := resultPaths[contractreview.RoleDefect]
	economyPath := resultPaths[contractreview.RoleEconomy]
	defectSHA, defectBytes := artifactMetadata(t, defectPath)
	economySHA, economyBytes := artifactMetadata(t, economyPath)
	contractStatus := "compliant"
	if exitCode == JobExitCompletedNoncompliant {
		contractStatus = "noncompliant"
	}
	setExecutable(t, delegate, strings.Join([]string{
		"#!/bin/sh",
		"case \"$*\" in",
		"  *defect*) printf '{\"jobId\":\"job-defect\"}\\n' ;;",
		"  *economy*) printf '{\"jobId\":\"job-economy\"}\\n' ;;",
		"  *) exit 9 ;;",
		"esac",
		"",
	}, "\n"))
	agentbusScript := fmt.Sprintf(`#!/bin/sh
job=""
for arg in "$@"; do
  case "$arg" in
    job-defect|job-economy) job="$arg" ;;
  esac
done
if [ "$1" = "transcript" ]; then
  printf '{"state":"completed","items":[],"gap":false}\n'
  exit %d
fi
if [ "$job" = "job-defect" ]; then
  path=%q
  sha=%q
  bytes=%d
else
  path=%q
  sha=%q
  bytes=%d
fi
if [ "$1" = "status" ]; then
	printf '{"jobs":[{"jobId":"%%s","state":"completed"}]}\n' "$job"
else
	printf '{"jobId":"%%s","state":"completed","result":{"resultPath":"%%s","sha256":"%%s","bytes":%%d},"contract":{"status":"%s"}}\n' "$job" "$path" "$sha" "$bytes"
fi
exit %d
`, exitCode, defectPath, defectSHA, defectBytes, economyPath, economySHA, economyBytes, contractStatus, exitCode)
	setExecutable(t, agentbus, agentbusScript)
	return delegate, agentbus
}

func artifactMetadata(t *testing.T, path string) (string, int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return strings.Repeat("0", sha256.Size*2), 0
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), len(data)
}

func setExecutable(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}
