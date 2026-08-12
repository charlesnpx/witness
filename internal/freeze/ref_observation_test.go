package freeze

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/charlesnpx/witness/internal/canonjson"
)

func TestRefObservationFreshDriftDetachedNonGitAndDeterminism(t *testing.T) {
	repo := newRefObservationRepo(t)
	frozen, err := CaptureRefObservation(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CaptureRefObservation(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Status != RefObservationAvailable || frozen.HeadState != RefHeadAttached || frozen.CurrentBranch == "" {
		t.Fatalf("attached observation = %#v", frozen)
	}
	if !bytes.Equal(canonjson.MustMarshal(frozen), canonjson.MustMarshal(second)) {
		t.Fatalf("unchanged observations differ:\n%s\n%s", canonjson.MustMarshal(frozen), canonjson.MustMarshal(second))
	}
	if drift := CompareRefObservation(context.Background(), frozen); drift.Classification != RefDriftFresh || drift.Stale {
		t.Fatalf("fresh drift = %#v", drift)
	}
	mustWriteRefFile(t, filepath.Join(repo, "next.txt"), []byte("next\n"))
	refGit(t, repo, "add", "next.txt")
	refGit(t, repo, "commit", "-m", "advance")
	if drift := CompareRefObservation(context.Background(), frozen); drift.Classification != RefDriftDrifted || !drift.Stale || len(drift.Changes) == 0 {
		t.Fatalf("drifted observation = %#v", drift)
	}
	refGit(t, repo, "checkout", "--detach")
	detached, err := CaptureRefObservation(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if detached.Status != RefObservationAvailable || detached.HeadState != RefHeadDetached || detached.CurrentBranch != "" {
		t.Fatalf("detached observation = %#v", detached)
	}
	nonGit := t.TempDir()
	mustWriteRefFile(t, filepath.Join(nonGit, "file.txt"), []byte("content\n"))
	unavailable, err := CaptureRefObservation(context.Background(), nonGit)
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != RefObservationUnavailable || unavailable.Reason == "" {
		t.Fatalf("non-git observation = %#v", unavailable)
	}
	if drift := CompareRefObservation(context.Background(), unavailable); drift.Classification != RefDriftUnavailable || !drift.Stale || drift.Reason == "" {
		t.Fatalf("unavailable drift = %#v", drift)
	}
}

func newRefObservationRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	refGit(t, repo, "init")
	refGit(t, repo, "config", "user.email", "witness-test@example.com")
	refGit(t, repo, "config", "user.name", "Witness Test")
	mustWriteRefFile(t, filepath.Join(repo, "initial.txt"), []byte("initial\n"))
	refGit(t, repo, "add", "initial.txt")
	refGit(t, repo, "commit", "-m", "initial")
	refGit(t, repo, "branch", "also-at-head")
	return repo
}

func refGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func mustWriteRefFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
