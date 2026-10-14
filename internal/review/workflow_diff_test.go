package review

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/contract/digest"
	contractreview "github.com/charlesnpx/witness/contract/review"
)

func TestPrepareWithDiff(t *testing.T) {
	for _, test := range []struct {
		name        string
		inputDigest string
	}{
		{name: "derived digest"},
		{name: "caller-owned digest", inputDigest: digest.RawBytes([]byte("caller-owned input"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceDirectory := t.TempDir()
			if err := os.WriteFile(filepath.Join(sourceDirectory, "source.txt"), []byte("after\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			sourceDigest, err := SourceDigest(sourceDirectory)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			diffBytes := []byte("--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-before\n+after\n")
			inputPath := filepath.Join(directory, "input.diff")
			if err := os.WriteFile(inputPath, diffBytes, 0o644); err != nil {
				t.Fatal(err)
			}
			linkPath := filepath.Join(directory, "diff-link")
			if err := os.Symlink(inputPath, linkPath); err != nil {
				t.Fatal(err)
			}
			workingDirectory, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			relativeDiffPath, err := filepath.Rel(workingDirectory, linkPath)
			if err != nil {
				t.Fatal(err)
			}
			packetDirectory := filepath.Join(directory, "packets")
			prepared, err := Prepare(PrepareOptions{
				Config:            DefaultConfig(),
				FrozenCharter:     testFrozenCharter(t),
				SourceDir:         sourceDirectory,
				DiffPath:          relativeDiffPath,
				PacketDirectory:   packetDirectory,
				Subject:           contractreview.RequestSubject{Head: "test-head"},
				ReviewInputDigest: test.inputDigest,
			})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			resolvedPacketDirectory, err := filepath.EvalSymlinks(packetDirectory)
			if err != nil {
				t.Fatal(err)
			}
			wantPath := filepath.Join(resolvedPacketDirectory, "change.diff")
			if prepared.DiffPath != wantPath {
				t.Fatalf("DiffPath = %q, want %q", prepared.DiffPath, wantPath)
			}
			copiedDiff, err := os.ReadFile(wantPath)
			if err != nil || !bytes.Equal(copiedDiff, diffBytes) {
				t.Fatalf("packet diff = %q (read error: %v), want %q", copiedDiff, err, diffBytes)
			}
			info, err := os.Stat(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("packet diff mode = %v, want a regular file with 0600 permissions", info.Mode())
			}
			wantDiffDigest := digest.RawBytes(diffBytes)
			if prepared.DiffDigest != wantDiffDigest {
				t.Fatalf("DiffDigest = %q, want %q", prepared.DiffDigest, wantDiffDigest)
			}
			wantInputDigest := test.inputDigest
			if wantInputDigest == "" {
				wantInputDigest, err = digest.SemanticJSON(map[string]any{"source_digest": sourceDigest, "diff_digest": wantDiffDigest})
				if err != nil {
					t.Fatal(err)
				}
			}
			if prepared.Request.ReviewInputDigest != wantInputDigest || prepared.Request.ReviewInputDigest == sourceDigest {
				t.Fatalf("ReviewInputDigest = %q, want %q distinct from source digest %q", prepared.Request.ReviewInputDigest, wantInputDigest, sourceDigest)
			}
			afterDigest, err := SourceDigest(sourceDirectory)
			if err != nil || afterDigest != sourceDigest || prepared.SourceDigest != sourceDigest {
				t.Fatalf("source digest = %q, prepared = %q (error: %v), want unchanged %q", afterDigest, prepared.SourceDigest, err, sourceDigest)
			}
			for _, packet := range prepared.Packets {
				prompt, err := os.ReadFile(packet.PromptPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, instruction := range []string{
					"The change under review is the unified diff at " + wantPath,
					"evaluate the changes in that diff and use the rest of the source tree as context",
					`attribution "introduced" or "worsened" applies to problems caused by the diff, "pre-existing" to problems in unchanged code`,
					"evaluated_paths should list the files you inspected, starting with files the diff touches",
					"tests and builds may not be runnable in this environment",
					"if you cannot execute a witness, use constructed or argued strength and say what you did not run",
				} {
					if !strings.Contains(string(prompt), instruction) {
						t.Errorf("%s prompt is missing %q", packet.Reviewer, instruction)
					}
				}
			}
		})
	}
}

func TestPrepareWithoutDiff(t *testing.T) {
	prepared, err := Prepare(PrepareOptions{
		Config:          DefaultConfig(),
		FrozenCharter:   testFrozenCharter(t),
		SourceDir:       t.TempDir(),
		PacketDirectory: filepath.Join(t.TempDir(), "packets"),
		Subject:         contractreview.RequestSubject{Head: "test-head"},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prepared.DiffPath != "" || prepared.DiffDigest != "" {
		t.Fatalf("diff metadata = (%q, %q), want empty", prepared.DiffPath, prepared.DiffDigest)
	}
	if prepared.Request.ReviewInputDigest != prepared.SourceDigest {
		t.Fatalf("ReviewInputDigest = %q, want source digest %q", prepared.Request.ReviewInputDigest, prepared.SourceDigest)
	}
	for _, packet := range prepared.Packets {
		prompt, err := os.ReadFile(packet.PromptPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(prompt), "diff") {
			t.Errorf("%s prompt mentions a diff when none was supplied", packet.Reviewer)
		}
		if !strings.Contains(string(prompt), "tests and builds may not be runnable in this environment") ||
			!strings.Contains(string(prompt), "if you cannot execute a witness, use constructed or argued strength and say what you did not run") {
			t.Errorf("%s prompt is missing witness execution guidance", packet.Reviewer)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(packet.PromptPath), "change.diff")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("change.diff stat error = %v, want no diff packet", err)
		}
	}
}

func TestPrepareRejectsInvalidDiff(t *testing.T) {
	directory := t.TempDir()
	emptyPath := filepath.Join(directory, "empty.diff")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		path    string
		message string
	}{
		{name: "missing", path: filepath.Join(directory, "missing.diff"), message: "review diff file"},
		{name: "empty", path: emptyPath, message: "is empty"},
		{name: "directory", path: directory, message: "is not a regular file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Prepare(PrepareOptions{
				Config:          DefaultConfig(),
				FrozenCharter:   testFrozenCharter(t),
				SourceDir:       t.TempDir(),
				DiffPath:        test.path,
				PacketDirectory: filepath.Join(t.TempDir(), "packets"),
				Subject:         contractreview.RequestSubject{Head: "test-head"},
			})
			if err == nil || !strings.Contains(err.Error(), test.message) || !strings.Contains(err.Error(), filepath.Base(test.path)) {
				t.Fatalf("Prepare error = %v, want %q naming diff path %q", err, test.message, test.path)
			}
			if test.name == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Prepare error = %v, want missing file error", err)
			}
		})
	}
}

func TestPrepareWithDiffRejectsUnsafePacketPaths(t *testing.T) {
	for _, name := range []string{"in source tree", "symlink into source tree"} {
		t.Run(name, func(t *testing.T) {
			sourceDirectory := t.TempDir()
			sourcePath := filepath.Join(sourceDirectory, "source.txt")
			if err := os.WriteFile(sourcePath, []byte("source must survive\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := SourceDigest(sourceDirectory)
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(t.TempDir(), "input.diff")
			if err := os.WriteFile(inputPath, []byte("--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-before\n+after\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			packetDirectory := filepath.Join(sourceDirectory, "packets")
			wantError := "resolves inside source directory"
			if name == "symlink into source tree" {
				packetDirectory = t.TempDir()
				if err := os.Symlink(sourcePath, filepath.Join(packetDirectory, "change.diff")); err != nil {
					t.Fatal(err)
				}
				wantError = "refuse to write symlink target"
			}
			_, err = Prepare(PrepareOptions{
				Config:          DefaultConfig(),
				FrozenCharter:   testFrozenCharter(t),
				SourceDir:       sourceDirectory,
				DiffPath:        inputPath,
				PacketDirectory: packetDirectory,
				Subject:         contractreview.RequestSubject{Head: "test-head"},
			})
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("Prepare error = %v, want %q", err, wantError)
			}
			after, err := SourceDigest(sourceDirectory)
			if err != nil || after != before {
				t.Fatalf("source digest = %q (error: %v), want unchanged %q", after, err, before)
			}
		})
	}
}
