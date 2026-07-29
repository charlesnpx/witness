package freeze

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"witness/internal/diag"
	"witness/internal/digest"
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
