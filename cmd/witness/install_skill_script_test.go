package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type installSkillReport struct {
	Schema       int                           `json:"schema"`
	Name         string                        `json:"name"`
	Version      string                        `json:"version"`
	Operation    string                        `json:"operation"`
	Kind         string                        `json:"kind"`
	Capabilities []string                      `json:"capabilities"`
	Setup        []installSkillSetup           `json:"setup"`
	Targets      map[string]installSkillTarget `json:"targets"`
}

type installSkillSetup struct {
	Kind        string   `json:"kind"`
	Executable  string   `json:"executable"`
	RequiredFor []string `json:"required_for"`
}

type installSkillTarget struct {
	Files []installSkillFile `json:"files"`
}

type installSkillFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

const witnessSkillPrefix = `---
name: witness
description: Run deterministic single-pass Witness reviews from a frozen source state and Charter. Use when Codex or Claude should orchestrate Witness review, verification planning, adjudication, policy checks, or metrics without mutating reviewed sources.
---

# Witness Single-Pass Review
`

func TestInstallSkillScriptPlanIsJSONOnlyAndSideEffectFree(t *testing.T) {
	bashPath := requireBash(t)
	repoRoot := repoRootFromCmdWitness(t)
	home := t.TempDir()

	stdout, stderr, err := runInstallSkillScript(t, bashPath, repoRoot, []string{"--plan", "--json"}, "HOME="+home)
	if err != nil {
		t.Fatalf("install-skill.sh --plan failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	report := decodeInstallSkillReport(t, stdout)
	if report.Schema != 1 {
		t.Fatalf("schema = %d, want 1", report.Schema)
	}
	if report.Name != "witness" {
		t.Fatalf("name = %q, want witness", report.Name)
	}
	if report.Operation != "plan" {
		t.Fatalf("operation = %q, want plan", report.Operation)
	}
	if report.Kind != "delegated" {
		t.Fatalf("kind = %q, want delegated", report.Kind)
	}
	if len(report.Capabilities) != 1 || report.Capabilities[0] != "query" {
		t.Fatalf("capabilities = %#v, want [query]", report.Capabilities)
	}
	if len(report.Setup) != 1 {
		t.Fatalf("setup = %#v, want one convo-relay requirement", report.Setup)
	}
	setup := report.Setup[0]
	if setup.Kind != "executable" || setup.Executable != "convo-relay" || len(setup.RequiredFor) != 1 || setup.RequiredFor[0] != "query" {
		t.Fatalf("setup = %#v, want convo-relay executable required for query", setup)
	}
	for _, target := range []string{"tools", "codex", "claude"} {
		if _, ok := report.Targets[target]; !ok {
			t.Fatalf("targets missing %q: %#v", target, report.Targets)
		}
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("plan wrote to HOME: %v", entries)
	}
}

func TestInstallSkillScriptInstallRootAndUninstall(t *testing.T) {
	bashPath := requireBash(t)
	repoRoot := repoRootFromCmdWitness(t)
	installRoot := t.TempDir()
	env := []string{
		"HOME=" + t.TempDir(),
		"WITNESS_VERSION=test",
		"GOCACHE=" + filepath.Join(t.TempDir(), "gocache"),
	}

	stdout, stderr, err := runInstallSkillScript(t, bashPath, repoRoot, []string{"--install", "--json", "--install-root", installRoot}, env...)
	if err != nil {
		t.Fatalf("install-skill.sh --install failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	report := decodeInstallSkillReport(t, stdout)
	if report.Operation != "install" {
		t.Fatalf("operation = %q, want install", report.Operation)
	}
	if report.Version != "test" {
		t.Fatalf("version = %q, want test", report.Version)
	}

	expected := map[string]bool{
		filepath.Join(installRoot, ".local", "bin", "witness"):                                                   false,
		filepath.Join(installRoot, ".local", "bin", "witness-harness"):                                           false,
		filepath.Join(installRoot, ".codex", "skills", "witness", "SKILL.md"):                                    false,
		filepath.Join(installRoot, ".codex", "skills", "witness", "bundle", "relay-integration-bundle-v2.json"):  false,
		filepath.Join(installRoot, ".claude", "skills", "witness", "SKILL.md"):                                   false,
		filepath.Join(installRoot, ".claude", "skills", "witness", "bundle", "relay-integration-bundle-v2.json"): false,
	}
	reported := reportedInstallSkillFiles(report)
	if len(reported) != len(expected) {
		t.Fatalf("reported %d files, want %d: %#v", len(reported), len(expected), reported)
	}

	for _, file := range reported {
		assertPathUnderRoot(t, file.Path, installRoot)
		expected[file.Path] = true

		data, err := os.ReadFile(file.Path)
		if err != nil {
			t.Fatalf("read installed file %s: %v", file.Path, err)
		}
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(file.SHA256) {
			t.Fatalf("sha256 for %s = %q, want 64 lowercase hex chars", file.Path, file.SHA256)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 {
			t.Fatalf("sha256 for %s = %s, want %s", file.Path, file.SHA256, got)
		}
	}
	for path, seen := range expected {
		if !seen {
			t.Fatalf("expected installed file not reported: %s", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected installed file missing %s: %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(installRoot, ".codex", "skills", "witness", "SKILL.md"),
		filepath.Join(installRoot, ".claude", "skills", "witness", "SKILL.md"),
	} {
		assertWitnessSkillMetadata(t, path)
	}

	stdout, stderr, err = runInstallSkillScript(t, bashPath, repoRoot, []string{"--uninstall", "--json", "--install-root", installRoot}, env...)
	if err != nil {
		t.Fatalf("install-skill.sh --uninstall failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	uninstallReport := decodeInstallSkillReport(t, stdout)
	if uninstallReport.Operation != "uninstall" {
		t.Fatalf("operation = %q, want uninstall", uninstallReport.Operation)
	}
	for _, file := range reported {
		assertPathUnderRoot(t, file.Path, installRoot)
		if _, err := os.Stat(file.Path); !os.IsNotExist(err) {
			t.Fatalf("uninstalled file still exists %s: %v", file.Path, err)
		}
	}
}

func requireBash(t *testing.T) string {
	t.Helper()
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	return bashPath
}

func repoRootFromCmdWitness(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return repoRoot
}

func runInstallSkillScript(t *testing.T, bashPath, repoRoot string, args []string, env ...string) ([]byte, []byte, error) {
	t.Helper()
	scriptPath := filepath.Join(repoRoot, "install-skill.sh")
	cmd := exec.Command(bashPath, append([]string{scriptPath}, args...)...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func decodeInstallSkillReport(t *testing.T, stdout []byte) installSkillReport {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	var report installSkillReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("stdout is not JSON: %v\nstdout:\n%s", err, stdout)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout has trailing non-JSON content: %v\nstdout:\n%s", err, stdout)
	}
	return report
}

func reportedInstallSkillFiles(report installSkillReport) []installSkillFile {
	var files []installSkillFile
	for _, target := range []string{"tools", "codex", "claude"} {
		files = append(files, report.Targets[target].Files...)
	}
	return files
}

func assertWitnessSkillMetadata(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installed Witness skill %s: %v", path, err)
	}
	if !strings.HasPrefix(string(body), witnessSkillPrefix) {
		t.Fatalf("installed Witness skill %s is missing discoverable front matter", path)
	}
}

func assertPathUnderRoot(t *testing.T, path, root string) {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel(%s, %s): %v", root, path, err)
	}
	if rel == "." || rel == ".." || rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("path %s is not under install root %s", path, root)
	}
}
