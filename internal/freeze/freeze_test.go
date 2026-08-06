package freeze

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestCreateDeterministicManifestDigest(t *testing.T) {
	source := t.TempDir()
	mustWriteFile(t, filepath.Join(source, "b.txt"), []byte("two\n"), 0o644)
	mustWriteFile(t, filepath.Join(source, "a", "exec.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755)

	firstOut := filepath.Join(t.TempDir(), "snapshot-one")
	secondOut := filepath.Join(t.TempDir(), "snapshot-two")
	first, err := Create(context.Background(), Options{SourceDir: source, OutputDir: firstOut, AllowNonGit: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(context.Background(), Options{SourceDir: source, OutputDir: secondOut, AllowNonGit: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestDigest != second.ManifestDigest {
		t.Fatalf("manifest digest changed: %s != %s", first.ManifestDigest, second.ManifestDigest)
	}
	if len(first.Manifest.Files) != 2 {
		t.Fatalf("files = %#v", first.Manifest.Files)
	}
	if first.Manifest.Files[0].Path != "a/exec.sh" || first.Manifest.Files[0].Mode != "100755" {
		t.Fatalf("first file entry = %#v", first.Manifest.Files[0])
	}
	if _, err := os.Stat(filepath.Join(firstOut, "blobs", "sha256", first.Manifest.Files[0].Digest[len("sha256:"):])); err != nil {
		t.Fatalf("blob was not copied: %v", err)
	}
}

func TestCanonicalManifestDecodeAcceptsExponentSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		DigestProfile: digest.Profile,
		Source: SourceIdentity{
			Path:           filepath.Join(dir, "source"),
			GitTrackedOnly: false,
		},
		Workspace: WorkspaceIdentity{
			Path:          dir,
			Format:        Format,
			BlobDirectory: filepath.Join(dir, "blobs"),
			ManifestPath:  path,
		},
		Files: []FileEntry{{
			Path:   "large.txt",
			Mode:   "100644",
			Size:   strictjson.Int64(2578),
			Digest: digest.RawBytes([]byte("large")),
			Blob:   "blobs/sha256/large",
		}},
	}

	if err := writeCanonicalFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"size":2.578e3`)) {
		t.Fatalf("canonical manifest size was not exponent form:\n%s", data)
	}
	decoded, err := strictjson.DecodeBytes[Manifest](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatalf("DecodeBytes returned error: %v", err)
	}
	if len(decoded.Files) != 1 || decoded.Files[0].Size != strictjson.Int64(2578) {
		t.Fatalf("decoded files = %#v, want size 2578", decoded.Files)
	}
}

func TestCreateRejectsOutputInsideSource(t *testing.T) {
	source := t.TempDir()
	mustWriteFile(t, filepath.Join(source, "file.txt"), []byte("content"), 0o644)
	_, err := Create(context.Background(), Options{
		SourceDir:   source,
		OutputDir:   filepath.Join(source, "snapshot"),
		AllowNonGit: true,
	})
	if err == nil {
		t.Fatal("Create succeeded with output inside source")
	}
}

func TestCreateRejectsOutputInsideGitRepositoryRoot(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	source := filepath.Join(repo, "src")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{
		SourceDir:   source,
		OutputDir:   filepath.Join(repo, "snapshot"),
		AllowNonGit: true,
	})
	if errorCode(err) != CodeOutputInsideSource {
		t.Fatalf("err = %v, want %s", err, CodeOutputInsideSource)
	}
}

func TestCreateDirtyGitWorktreeRequiresOverrideAndCapturesWorkingBytes(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "witness-test@example.com")
	runGit(t, repo, "config", "user.name", "Witness Test")
	mustWriteFile(t, filepath.Join(repo, ".gitignore"), []byte("ignored.txt\n"), 0o644)
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("committed\n"), 0o644)
	runGit(t, repo, "add", ".gitignore", "app.txt")
	runGit(t, repo, "commit", "-m", "initial")

	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("working-copy\n"), 0o644)
	mustWriteFile(t, filepath.Join(repo, "untracked.txt"), []byte("untracked\n"), 0o644)
	mustWriteFile(t, filepath.Join(repo, "ignored.txt"), []byte("ignored\n"), 0o644)

	_, err := Create(context.Background(), Options{
		SourceDir: repo,
		OutputDir: filepath.Join(t.TempDir(), "rejected"),
	})
	if got := errorCode(err); got != CodeSourceDirty {
		t.Fatalf("dirty freeze error code = %q, want %q; err=%v", got, CodeSourceDirty, err)
	}

	snapshot, err := Create(context.Background(), Options{
		SourceDir:        repo,
		OutputDir:        filepath.Join(t.TempDir(), "snapshot"),
		AllowDirtySource: true,
	})
	if err != nil {
		t.Fatalf("dirty freeze with override: %v", err)
	}
	if !snapshot.Manifest.Source.GitDirty {
		t.Fatalf("source identity = %#v, want dirty working tree metadata", snapshot.Manifest.Source)
	}
	if snapshot.Manifest.Source.GitTrackedOnly {
		t.Fatalf("source identity = %#v, want untracked files recorded", snapshot.Manifest.Source)
	}
	for _, status := range []string{"M app.txt", "?? untracked.txt"} {
		if !strings.Contains(snapshot.Manifest.Source.GitDirtyStatus, status) {
			t.Fatalf("dirty status %q does not contain %q", snapshot.Manifest.Source.GitDirtyStatus, status)
		}
	}

	entries := map[string]FileEntry{}
	for _, entry := range snapshot.Manifest.Files {
		entries[entry.Path] = entry
	}
	for path, want := range map[string][]byte{
		"app.txt":       []byte("working-copy\n"),
		"untracked.txt": []byte("untracked\n"),
	} {
		entry, found := entries[path]
		if !found {
			t.Fatalf("snapshot files = %#v, missing %s", snapshot.Manifest.Files, path)
		}
		if got := entry.Digest; got != digest.RawBytes(want) {
			t.Fatalf("snapshot digest for %s = %s, want %s", path, got, digest.RawBytes(want))
		}
		blob, err := os.ReadFile(filepath.Join(filepath.Dir(snapshot.ManifestPath), filepath.FromSlash(entry.Blob)))
		if err != nil {
			t.Fatalf("read snapshot blob for %s: %v", path, err)
		}
		if !bytes.Equal(blob, want) {
			t.Fatalf("snapshot blob for %s = %q, want %q", path, blob, want)
		}
	}
	if _, found := entries["ignored.txt"]; found {
		t.Fatalf("snapshot unexpectedly included ignored file: %#v", entries["ignored.txt"])
	}
	if digest, err := ManifestDigest(snapshot.Manifest); err != nil || digest != snapshot.ManifestDigest {
		t.Fatalf("snapshot manifest digest = %q, %v; want %q", digest, err, snapshot.ManifestDigest)
	}
}

func TestCreateRejectsDirtyGitWorktreeContentMutationDuringCapture(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "witness-test@example.com")
	runGit(t, repo, "config", "user.name", "Witness Test")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("committed\n"), 0o644)
	runGit(t, repo, "add", "app.txt")
	runGit(t, repo, "commit", "-m", "initial")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("working-copy\n"), 0o644)

	_, err := Create(context.Background(), Options{
		SourceDir:        repo,
		OutputDir:        filepath.Join(t.TempDir(), "snapshot"),
		AllowDirtySource: true,
		afterDirtySourceCapture: func() {
			mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("rewritten-working-copy\n"), 0o644)
		},
	})
	if got := errorCode(err); got != CodeSourceChangedDuringCapture {
		t.Fatalf("freeze error code = %q, want %q; err=%v", got, CodeSourceChangedDuringCapture, err)
	}
	if !strings.Contains(err.Error(), "quiesce") || !strings.Contains(err.Error(), "retry") {
		t.Fatalf("freeze diagnostic = %v, want quiesce-and-retry guidance", err)
	}
}

func TestCreateRejectsDirtyGitWorktreeHeadMutationDuringCapture(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "witness-test@example.com")
	runGit(t, repo, "config", "user.name", "Witness Test")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("committed\n"), 0o644)
	runGit(t, repo, "add", "app.txt")
	runGit(t, repo, "commit", "-m", "initial")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("working-copy\n"), 0o644)

	_, err := Create(context.Background(), Options{
		SourceDir:        repo,
		OutputDir:        filepath.Join(t.TempDir(), "snapshot"),
		AllowDirtySource: true,
		afterDirtySourceCapture: func() {
			runGit(t, repo, "commit", "--allow-empty", "-m", "advance HEAD")
		},
	})
	if got := errorCode(err); got != CodeSourceChangedDuringCapture {
		t.Fatalf("freeze error code = %q, want %q; err=%v", got, CodeSourceChangedDuringCapture, err)
	}
}

func TestVerifyDirtyGitCaptureRejectsCleanTrackedFileMutationRestoredBeforeInventory(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "witness-test@example.com")
	runGit(t, repo, "config", "user.name", "Witness Test")
	cleanPath := filepath.Join(repo, "clean.txt")
	cleanBytes := []byte("clean\n")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("committed\n"), 0o644)
	mustWriteFile(t, cleanPath, cleanBytes, 0o644)
	runGit(t, repo, "add", "app.txt", "clean.txt")
	runGit(t, repo, "commit", "-m", "initial")
	mustWriteFile(t, filepath.Join(repo, "app.txt"), []byte("working-copy\n"), 0o644)

	before, err := collectDirtyGitDerivation(context.Background(), repo)
	if err != nil {
		t.Fatalf("collect before capture derivation: %v", err)
	}

	// The clean file changes while bytes are captured, then the existing
	// post-capture seam restores its Git-visible state before the re-inventory.
	mustWriteFile(t, cleanPath, []byte("transient-captured-bytes\n"), 0o644)
	entries := make([]FileEntry, 0, len(before.files))
	for _, item := range before.sourceFiles() {
		data, size, err := readSnapshotBytes(repo, item)
		if err != nil {
			t.Fatalf("capture %s: %v", item.path, err)
		}
		sum := digest.RawBytes(data)
		entries = append(entries, FileEntry{
			Path:   item.path,
			Mode:   item.mode,
			Size:   strictjson.Int64(size),
			Digest: sum,
			Blob:   filepath.ToSlash(filepath.Join("blobs", "sha256", strings.TrimPrefix(sum, digest.Prefix))),
		})
	}

	err = verifyDirtyGitCapture(context.Background(), repo, before, entries, func() {
		mustWriteFile(t, cleanPath, cleanBytes, 0o644)
	})
	if got := errorCode(err); got != CodeSourceChangedDuringCapture {
		t.Fatalf("freeze error code = %q, want %q; err=%v", got, CodeSourceChangedDuringCapture, err)
	}
}

func TestCreateRejectsSymlinkedManifestPath(t *testing.T) {
	source := t.TempDir()
	mustWriteFile(t, filepath.Join(source, "file.txt"), []byte("content"), 0o644)
	output := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(output, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{
		SourceDir:   source,
		OutputDir:   output,
		AllowNonGit: true,
	})
	if errorCode(err) != CodeUnsafeOutputPath {
		t.Fatalf("err = %v, want %s", err, CodeUnsafeOutputPath)
	}
}

func TestCreateRejectsSymlinkedBlobPath(t *testing.T) {
	source := t.TempDir()
	data := []byte("content")
	mustWriteFile(t, filepath.Join(source, "file.txt"), data, 0o644)
	output := t.TempDir()
	blobDir := filepath.Join(output, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := digest.RawBytes(data)
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(blobDir, sum[len(digest.Prefix):])); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{
		SourceDir:   source,
		OutputDir:   output,
		AllowNonGit: true,
	})
	if errorCode(err) != CodeUnsafeOutputPath {
		t.Fatalf("err = %v, want %s", err, CodeUnsafeOutputPath)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	var diagnostic *diag.Error
	if errors.As(err, &diagnostic) {
		return diagnostic.Diagnostic.Code
	}
	return ""
}
