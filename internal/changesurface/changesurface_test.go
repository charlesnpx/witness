package changesurface

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/freeze"
)

func TestDeriveChangedPathsAndDeterministicDigest(t *testing.T) {
	baseDir := t.TempDir()
	writeFile(t, filepath.Join(baseDir, "same.txt"), []byte("same\n"), 0o644)
	writeFile(t, filepath.Join(baseDir, "modified.txt"), []byte("old\n"), 0o644)
	writeFile(t, filepath.Join(baseDir, "removed.txt"), []byte("removed\n"), 0o644)
	writeFile(t, filepath.Join(baseDir, "mode.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o644)

	headDir := t.TempDir()
	writeFile(t, filepath.Join(headDir, "same.txt"), []byte("same\n"), 0o644)
	writeFile(t, filepath.Join(headDir, "modified.txt"), []byte("new\n"), 0o644)
	writeFile(t, filepath.Join(headDir, "added.txt"), []byte("added\n"), 0o644)
	writeFile(t, filepath.Join(headDir, "mode.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755)

	baseSnapshot, err := freeze.Create(context.Background(), freeze.Options{SourceDir: baseDir, OutputDir: filepath.Join(t.TempDir(), "base"), AllowNonGit: true})
	if err != nil {
		t.Fatal(err)
	}
	headSnapshot, err := freeze.Create(context.Background(), freeze.Options{SourceDir: headDir, OutputDir: filepath.Join(t.TempDir(), "head"), AllowNonGit: true})
	if err != nil {
		t.Fatal(err)
	}
	surface, surfaceDigest, err := Derive(baseSnapshot.Manifest, headSnapshot.Manifest, headSnapshot.ManifestDigest)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	want := []PathChange{
		{Path: "added.txt", ChangeKinds: []string{ChangeKindAdded}},
		{Path: "mode.sh", ChangeKinds: []string{ChangeKindModeChanged}},
		{Path: "modified.txt", ChangeKinds: []string{ChangeKindModified}},
		{Path: "removed.txt", ChangeKinds: []string{ChangeKindRemoved}},
	}
	if len(surface.ChangedPaths) != len(want) {
		t.Fatalf("changed paths = %#v, want %#v", surface.ChangedPaths, want)
	}
	for index := range want {
		if surface.ChangedPaths[index].Path != want[index].Path || len(surface.ChangedPaths[index].ChangeKinds) != 1 || surface.ChangedPaths[index].ChangeKinds[0] != want[index].ChangeKinds[0] {
			t.Fatalf("changed path %d = %#v, want %#v", index, surface.ChangedPaths[index], want[index])
		}
	}
	if surface.BaseArtifactDigest != baseSnapshot.ManifestDigest || surface.HeadArtifactDigest != headSnapshot.ManifestDigest {
		t.Fatalf("surface digests = %#v, want base/head manifest digests", surface)
	}
	again, err := Digest(surface)
	if err != nil {
		t.Fatal(err)
	}
	if surfaceDigest != again {
		t.Fatalf("surface digest = %s, recomputed = %s", surfaceDigest, again)
	}
	secondSurface, secondDigest, err := Derive(baseSnapshot.Manifest, headSnapshot.Manifest, headSnapshot.ManifestDigest)
	if err != nil {
		t.Fatalf("second Derive: %v", err)
	}
	if secondDigest != surfaceDigest || len(secondSurface.ChangedPaths) != len(surface.ChangedPaths) {
		t.Fatalf("second derivation digest/path count = %s/%d, want %s/%d", secondDigest, len(secondSurface.ChangedPaths), surfaceDigest, len(surface.ChangedPaths))
	}
}

func TestDeriveRejectsHeadDigestMismatch(t *testing.T) {
	manifest := freeze.Manifest{SchemaVersion: freeze.SchemaVersion, DigestProfile: "relay-root-digests-v1"}
	_, _, err := Derive(manifest, manifest, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if diagnosticCode(err) != CodeHeadArtifactMismatch {
		t.Fatalf("err = %v, want %s", err, CodeHeadArtifactMismatch)
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
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

func diagnosticCode(err error) string {
	if err == nil {
		return ""
	}
	var diagnostic *diag.Error
	if errors.As(err, &diagnostic) {
		return diagnostic.Diagnostic.Code
	}
	var validation *ValidationError
	if errors.As(err, &validation) && len(validation.Diagnostics) > 0 {
		return validation.Diagnostics[0].Code
	}
	return ""
}
