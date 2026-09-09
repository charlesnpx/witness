package modulezip

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/mod/module"
)

func TestTrackedFilesHaveValidModuleZipPaths(t *testing.T) {
	repoRoot := repositoryRoot(t)
	// Include worktree additions so an unstaged rename is validated before it
	// is added to the index. Deleted index entries are not files in the current
	// tree and are skipped below.
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	for _, rawPath := range bytes.Split(output, []byte{0}) {
		if len(rawPath) == 0 {
			continue
		}
		path := string(rawPath)
		if _, err := os.Lstat(filepath.Join(repoRoot, filepath.FromSlash(path))); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat tracked file %q: %v", path, err)
		}
		if err := module.CheckFilePath(path); err != nil {
			t.Errorf("tracked file %q has an invalid module-zip path: %v", path, err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
