package preflight

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/charlesnpx/witness/internal/freeze"
)

func TestRetainedRefObservationChecksFreshAndDrift(t *testing.T) {
	repo := t.TempDir()
	preflightRefGit(t, repo, "init")
	preflightRefGit(t, repo, "config", "user.email", "witness-test@example.com")
	preflightRefGit(t, repo, "config", "user.name", "Witness Test")
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("initial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	preflightRefGit(t, repo, "add", "app.txt")
	preflightRefGit(t, repo, "commit", "-m", "initial")
	observation, err := freeze.CaptureRefObservation(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if _, err := RetainRefObservation(stateDir, observation); err != nil {
		t.Fatal(err)
	}
	if drift := CheckRefDrift(context.Background(), RefObservationPath(stateDir)); drift.Classification != freeze.RefDriftFresh {
		t.Fatalf("fresh checkpoint = %#v", drift)
	}
	if err := os.WriteFile(filepath.Join(repo, "next.txt"), []byte("next\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	preflightRefGit(t, repo, "add", "next.txt")
	preflightRefGit(t, repo, "commit", "-m", "advance")
	if drift := CheckRefDrift(context.Background(), RefObservationPath(stateDir)); drift.Classification != freeze.RefDriftDrifted || !drift.Stale {
		t.Fatalf("drifted checkpoint = %#v", drift)
	}
}

func TestRetainedRefObservationUnreadableIsUnavailable(t *testing.T) {
	drift := CheckRefDrift(context.Background(), filepath.Join(t.TempDir(), "missing.json"))
	if drift.Classification != freeze.RefDriftUnavailable || !drift.Stale || drift.Reason == "" {
		t.Fatalf("unavailable checkpoint = %#v", drift)
	}
}

func preflightRefGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
