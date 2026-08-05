package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/metrics"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/policy"
	"github.com/charlesnpx/witness/internal/preflight"
	"github.com/charlesnpx/witness/internal/relayclient"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestRouteHelp(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		wantOutput         []string
		wantDiagnosticCode string
	}{
		{
			name: "leaf command",
			args: []string{"verification", "plan", "--help"},
			wantOutput: []string{
				"usage: witness verification plan [flags]",
				"-charter-freeze",
			},
		},
		{
			name: "top level",
			args: []string{"--help"},
			wantOutput: []string{
				"available commands:",
				"charter <subcommand>",
				"verification <subcommand>",
			},
		},
		{
			name:               "bare witness remains invalid",
			args:               []string{},
			wantDiagnosticCode: diag.CodeInvalidCommand,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := captureRouteStdout(t, test.args)
			if test.wantDiagnosticCode != "" {
				if err == nil {
					t.Fatalf("route(%v) succeeded, want %s diagnostic", test.args, test.wantDiagnosticCode)
				}
				if got := diag.FromError(err).Code; got != test.wantDiagnosticCode {
					t.Fatalf("diagnostic code = %s, want %s; err=%v", got, test.wantDiagnosticCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("route(%v): %v", test.args, err)
			}
			for _, want := range test.wantOutput {
				if !strings.Contains(output, want) {
					t.Fatalf("stdout = %q, want substring %q", output, want)
				}
			}
		})
	}
}

func TestRoleOutputValidate(t *testing.T) {
	dir := t.TempDir()
	initializedPath := filepath.Join(dir, "initialized.json")
	if err := route([]string{"role-output", "init", "-role", contracts.RoleDefect, "-out", initializedPath}); err != nil {
		t.Fatalf("role-output init: %v", err)
	}

	initialized, err := readRoleOutputFile(initializedPath)
	if err != nil {
		t.Fatalf("read initialized role output: %v", err)
	}
	if initialized.SchemaVersion != contracts.RoleOutputV3 || initialized.Role != contracts.RoleDefect || initialized.Findings == nil || len(initialized.Findings) != 0 {
		t.Fatalf("initialized role output = %#v, want an empty valid defect document", initialized)
	}
	if err := contracts.RequireValidRoleOutput(initialized, nil); err != nil {
		t.Fatalf("initialized role output validation: %v", err)
	}
	plannerFrozen := validCLIFrozenCharter(t)
	plannerFrozen.CharterHash = initialized.CharterHash
	planned, err := planning.Run(planning.Options{
		FrozenCharter: &plannerFrozen,
		RoleOutputs:   []planning.RoleOutputInput{{Path: initializedPath, Document: initialized}},
		Preflight:     planning.PreflightBinding{SnapshotDigest: initialized.ArtifactDigest},
	})
	if err != nil {
		t.Fatalf("planner accepts initialized role output: %v", err)
	}
	if len(planned.Plan.Diagnostics) != 0 {
		t.Fatalf("planner diagnostics for initialized role output = %#v", planned.Plan.Diagnostics)
	}

	frozen := validCLIFrozenCharter(t)
	valid := initialized
	valid.CharterHash = frozen.CharterHash
	valid.ArtifactDigest = digest.RawBytes([]byte("role-output-artifact"))
	validPath := filepath.Join(dir, "valid.json")
	if err := writeCanonical(validPath, valid); err != nil {
		t.Fatal(err)
	}
	validDigest, err := contracts.RoleOutputDigest(valid)
	if err != nil {
		t.Fatalf("role-output digest: %v", err)
	}
	validBytes, err := contracts.RoleOutputCanonicalBytes(valid)
	if err != nil {
		t.Fatalf("canonical role output: %v", err)
	}
	var invalidPayload map[string]any
	if err := json.Unmarshal(validBytes, &invalidPayload); err != nil {
		t.Fatalf("decode canonical role output: %v", err)
	}
	delete(invalidPayload, "source_identity")
	invalidPath := filepath.Join(dir, "invalid.json")
	if err := writeCanonical(invalidPath, invalidPayload); err != nil {
		t.Fatal(err)
	}
	invalid, err := readRoleOutputFile(invalidPath)
	if err != nil {
		t.Fatalf("read invalid role output: %v", err)
	}
	plannerDiagnostics := contracts.ValidateRoleOutput(invalid, &frozen)
	if len(plannerDiagnostics) == 0 {
		t.Fatal("planner role-output validation accepted document missing source_identity")
	}

	tests := []struct {
		name               string
		input              string
		wantDiagnosticCode string
		wantDiagnosticPath string
		wantDigest         string
	}{
		{
			name:       "valid empty findings document",
			input:      validPath,
			wantDigest: validDigest,
		},
		{
			name:               "missing required source identity",
			input:              invalidPath,
			wantDiagnosticCode: plannerDiagnostics[0].Code,
			wantDiagnosticPath: plannerDiagnostics[0].Path,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := captureRouteStdout(t, []string{"role-output", "validate", "-input", test.input})
			if test.wantDiagnosticCode != "" {
				if err == nil {
					t.Fatal("role-output validate succeeded for an invalid document")
				}
				diagnostics := diagnosticsFromError(err)
				if len(diagnostics) == 0 {
					t.Fatalf("role-output validate diagnostics = none; err=%v", err)
				}
				if got := diagnostics[0].Code; got != test.wantDiagnosticCode {
					t.Fatalf("diagnostic code = %s, want planner code %s; err=%v", got, test.wantDiagnosticCode, err)
				}
				if got := diagnostics[0].Path; got != test.wantDiagnosticPath {
					t.Fatalf("diagnostic path = %s, want planner path %s; err=%v", got, test.wantDiagnosticPath, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("role-output validate: %v", err)
			}
			var result roleOutputValidationResult
			if result, err = strictjson.DecodeBytes[roleOutputValidationResult]([]byte(output), strictjson.DefaultMaxBytes); err != nil {
				t.Fatalf("decode validation output: %v", err)
			}
			if !result.OK || result.SchemaVersion != contracts.RoleOutputV3 || result.RoleOutputDigest != test.wantDigest {
				t.Fatalf("validation result = %#v, want ok result with schema version and digest", result)
			}
		})
	}
}

func captureRouteStdout(t *testing.T, args []string) (string, error) {
	t.Helper()
	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = reader.Close()
		_ = writer.Close()
	})

	routeErr := route(args)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = originalStdout
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output), routeErr
}

func TestCharterCLIInitFreezeAmendShow(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	showPath := filepath.Join(dir, "show.json")
	freezePath := filepath.Join(dir, "freeze.json")
	amendedFreezePath := filepath.Join(dir, "freeze-amended.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := route([]string{"charter", "show", "-charter", charterPath, "-out", showPath}); err != nil {
		t.Fatalf("show: %v", err)
	}
	showData, err := os.ReadFile(showPath)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := strictjson.DecodeBytes[charter.NormalizedCharter](showData, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode show output: %v", err)
	}
	if len(normalized.StandingNoGoals) != 1 || normalized.StandingNoGoals[0].Statement != charter.StandingNoGoalsStatement {
		t.Fatalf("standing invariant = %#v", normalized.StandingNoGoals)
	}

	if err := route([]string{"charter", "freeze", "-charter", charterPath, "-out", freezePath}); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	before := readFrozen(t, freezePath)

	eventJSON := []byte(`{"id":"event-2","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendedFreezePath}); err != nil {
		t.Fatalf("amend: %v", err)
	}
	after := readFrozen(t, amendedFreezePath)
	if before.CharterHash == after.CharterHash {
		t.Fatalf("amended hash did not change: %s", before.CharterHash)
	}
	amendments, err := charter.ReadAmendmentsFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(amendments) != 1 || amendments[0].ID != "event-2" {
		t.Fatalf("amendments = %#v", amendments)
	}
}

func TestCharterInitTemplatesValidateAndFreeze(t *testing.T) {
	dir := t.TempDir()
	for _, name := range charter.TemplateNames() {
		charterPath := filepath.Join(dir, name+".json")
		if err := route([]string{"charter", "init", "-template", name, "-out", charterPath, "-actor", "owner"}); err != nil {
			t.Fatalf("init template %s: %v", name, err)
		}
		document, err := charter.ReadFile(charterPath)
		if err != nil {
			t.Fatalf("read template %s: %v", name, err)
		}
		if diagnostics := charter.Validate(document, nil); len(diagnostics) != 0 {
			t.Fatalf("template %s diagnostics = %#v", name, diagnostics)
		}
		frozen, err := charter.Freeze(document, nil)
		if err != nil {
			t.Fatalf("freeze template %s: %v", name, err)
		}
		if frozen.CharterHash == "" {
			t.Fatalf("template %s froze without charter hash", name)
		}
	}
}

func TestCharterAmendRejectsOutputAliasingAmendments(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	originalLedger := []byte(`{"actor":"owner","id":"event-2","summary":"Existing amendment.","type":"charter_amended"}` + "\n")
	if err := os.WriteFile(amendmentsPath, originalLedger, 0o644); err != nil {
		t.Fatal(err)
	}
	eventJSON := []byte(`{"id":"event-3","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendmentsPath})
	if err == nil {
		t.Fatal("amend succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
	afterLedger, err := os.ReadFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterLedger, originalLedger) {
		t.Fatalf("ledger changed:\nafter: %s\nwant:  %s", afterLedger, originalLedger)
	}
}

func TestRejectOutputPathAliasesRejectsHardLinkedAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.WriteFile(amendmentsPath, []byte("existing ledger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(amendmentsPath, outputPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func TestRejectOutputPathAliasesRejectsDanglingSymlinkToAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.Symlink(filepath.Base(amendmentsPath), outputPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("output symlink is not dangling: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func TestLedgerShowRejectsOutputAliasingLedgerBeforeTruncate(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	original := []byte("not-json-but-must-survive\n")
	if err := os.WriteFile(ledgerPath, original, 0o644); err != nil {
		t.Fatal(err)
	}

	err := route([]string{"ledger", "show", "-ledger", ledgerPath, "-out", ledgerPath})
	assertOutputPathConflict(t, err)
	after, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("ledger changed:\nafter: %s\nwant:  %s", after, original)
	}
}

func TestVerificationPreflightCLIWiredToRun(t *testing.T) {
	err := route([]string{"verification", "preflight"})
	if err == nil {
		t.Fatal("preflight succeeded without -state-dir")
	}
	diagnostics := diagnosticsFromError(err)
	if len(diagnostics) != 1 || diagnostics[0].Code != "preflight_missing_state_dir" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestVerificationPreflightRelayAbsentWritesPassingResult(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	outPath := filepath.Join(dir, "preflight.json")
	missingRelay := filepath.Join(dir, "missing-convo-relay")
	bundlePath := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")

	if err := route([]string{
		"verification", "preflight",
		"-relay", missingRelay,
		"-integration-bundle", bundlePath,
		"-state-dir", stateDir,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("relay-absent preflight: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[preflight.Result](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || len(result.Diagnostics) != 0 {
		t.Fatalf("preflight result = %#v, want ok degraded result without blocking diagnostics", result)
	}
	if !preflight.RelayAbsent(result) {
		t.Fatalf("backend strata = %#v, want relay_absent", result.BackendStrata)
	}
	for _, required := range []string{
		"compatibility-manifest.json",
		"relay-capabilities.json",
		"integration-bundle.json",
		filepath.ToSlash(filepath.Join("compile-reports", "witness-falsify-v2.json")),
	} {
		if result.ArtifactDigests[required] == "" {
			t.Fatalf("artifact digests = %#v, missing %s", result.ArtifactDigests, required)
		}
	}
	compatibilityBytes, err := os.ReadFile(filepath.Join(stateDir, "compatibility-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := retainedPayloadCanonicalBytes(compatibilityBytes)
	if err != nil {
		t.Fatal(err)
	}
	compatibility, err := contracts.ReadRelayCompatibilityBytes(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !contracts.RelayCompatibilityRelayAbsent(compatibility) {
		t.Fatalf("compatibility backend status = %#v, want relay_absent", compatibility.BackendStatus)
	}
	if diagnostics := contracts.ValidateRelayCompatibility(compatibility); len(diagnostics) != 0 {
		t.Fatalf("compatibility diagnostics = %#v", diagnostics)
	}
}

func TestVerificationPreflightRejectsOutputAliasingInputBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	stateDir := filepath.Join(dir, "state")
	original := []byte(`{"name":"bundle"}`)
	if err := os.WriteFile(bundlePath, original, 0o644); err != nil {
		t.Fatal(err)
	}

	err := route([]string{
		"verification", "preflight",
		"-integration-bundle", bundlePath,
		"-state-dir", stateDir,
		"-out", bundlePath,
	})
	assertOutputPathConflict(t, err)
	after, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("bundle changed:\nafter: %s\nwant:  %s", after, original)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("preflight state dir was written before alias refusal: %v", err)
	}
}

func TestVerificationPlanRequiresStateDir(t *testing.T) {
	err := route([]string{
		"verification", "plan",
		"-charter-freeze", "frozen.json",
		"-role-output", "role-output.json",
	})
	if err == nil {
		t.Fatal("verification plan succeeded without -state-dir")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != "verification_plan_missing_state_dir" {
		t.Fatalf("diagnostic code = %s, want verification_plan_missing_state_dir", diagnostic.Code)
	}
}

func TestVerificationPlanRequiresPreflight(t *testing.T) {
	err := route([]string{
		"verification", "plan",
		"-charter-freeze", "frozen.json",
		"-role-output", "role-output.json",
		"-state-dir", t.TempDir(),
	})
	if err == nil {
		t.Fatal("verification plan succeeded without -preflight")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != verificationPlanMissingPreflight {
		t.Fatalf("diagnostic code = %s, want %s", diagnostic.Code, verificationPlanMissingPreflight)
	}
}

func TestVerificationPlanDoesNotAcceptCallerChangedPathList(t *testing.T) {
	err := route([]string{
		"verification", "plan",
		"-changed-path", "internal/changed.go",
	})
	if err == nil {
		t.Fatal("verification plan accepted a caller-supplied changed path")
	}
	diagnostic := diag.FromError(err)
	errorText, _ := diagnostic.Details["error"].(string)
	if diagnostic.Code != diag.CodeInvalidCommand || !strings.Contains(errorText, "flag provided but not defined: -changed-path") {
		t.Fatalf("diagnostic = %#v, want invalid unknown changed-path flag", diagnostic)
	}
}

func TestVerificationPlanRejectsFailedPreflightResult(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	planOut := filepath.Join(dir, "plan-out.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility-failed-preflight.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-failed-preflight.json")
	bundle := writeCLIArtifact(t, dir, "bundle-failed-preflight.json")
	preflightPath := writeCLIPreflightResult(t, dir, "preflight-failed.json", stateDir, compatibility, capabilities, bundle)

	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	failed := preflight.Result{
		SchemaVersion: preflight.SchemaVersion,
		OK:            false,
		StateDir:      stateDir,
		ArtifactDigests: map[string]string{
			"compatibility-manifest.json": digest.RawBytes([]byte("compatibility")),
			"relay-capabilities.json":     digest.RawBytes([]byte("capabilities")),
		},
		CompileReportDigests: map[string]string{},
		RecipePlanDigests:    map[string]string{},
		ContractDigests: map[string]string{
			"integration_bundle": digest.RawBytes([]byte("bundle")),
		},
		BackendStrata:    map[string]string{},
		SnapshotDigest:   digest.RawBytes([]byte("snapshot")),
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
		Diagnostics: []diag.Diagnostic{{
			Code:    preflight.CodeMissingCapability,
			Message: "preflight failed",
		}},
	}
	if err := writeCanonical(preflightPath, failed); err != nil {
		t.Fatal(err)
	}

	err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", planOut,
	})
	if err == nil {
		t.Fatal("verification plan accepted a failed preflight result")
	}
	if got := diag.FromError(err).Code; got != verificationPlanInvalidPreflight {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, verificationPlanInvalidPreflight, err)
	}
	if _, err := os.Stat(planOut); !os.IsNotExist(err) {
		t.Fatalf("plan output was written after failed preflight refusal: %v", err)
	}
}

func TestVerificationPlanRejectsOutputInsideStateDir(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	err := route([]string{
		"verification", "plan",
		"-charter-freeze", filepath.Join(dir, "frozen.json"),
		"-preflight", filepath.Join(dir, "preflight.json"),
		"-role-output", filepath.Join(dir, "role-output.json"),
		"-state-dir", stateDir,
		"-out", filepath.Join(stateDir, "plan-out.json"),
	})
	assertOutputPathConflict(t, err)
}

func TestVerificationPlanRejectsDanglingSymlinkOutputInsideStateDir(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "state-link")
	if err := os.Symlink(stateDir, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	outPath := filepath.Join(linkPath, "missing", "plan-out.json")
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("output path is not dangling: %v", err)
	}

	err := route([]string{
		"verification", "plan",
		"-charter-freeze", filepath.Join(dir, "frozen.json"),
		"-preflight", filepath.Join(dir, "preflight.json"),
		"-role-output", filepath.Join(dir, "role-output.json"),
		"-state-dir", stateDir,
		"-out", outPath,
	})
	assertOutputPathConflict(t, err)
}

func TestVerificationPlanAndAssembleCLI(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	planOut := filepath.Join(dir, "plan-out.json")
	manifestOut := filepath.Join(dir, "manifest.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities.json")
	bundle := writeCLIArtifact(t, dir, "bundle.json")
	preflightPath := writeCLIPreflightResult(t, dir, "preflight.json", stateDir, compatibility, capabilities, bundle)

	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	roleOutput := validCLIRoleOutput(frozen)
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", planOut,
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}
	batchPath := filepath.Join(stateDir, "verification", "batches", "defect-batch-1.json")
	for _, path := range []string{
		planOut,
		filepath.Join(stateDir, "verification-plan.json"),
		batchPath,
		filepath.Join(stateDir, "verification", "index.skeleton.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract.json")
	if err := route([]string{
		"verification", "assemble",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-batch", batchPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble: %v", err)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable missing relay verification", manifest.Batches)
	}
}

func TestAdjudicateCLIWritesRunResult(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"adjudicate",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != adjudicate.ResultSchemaVersion || result.ResultDigest == "" {
		t.Fatalf("adjudication result header = %#v", result)
	}
	if len(result.Findings) != 1 || result.Findings[0].Disposition != contracts.DispositionAdmitted {
		t.Fatalf("adjudication findings = %#v", result.Findings)
	}
}

func TestAdjudicationLedgerEventsEmitFindingPayloads(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	inputs := []adjudicate.RoleOutputInput{{Path: "role-output.json", Document: roleOutput}}
	result, err := adjudicate.Run(adjudicate.Options{
		FrozenCharter: &frozen,
		RoleOutputs:   inputs,
		Manifest:      validCLIAdjudicationManifest(t, frozen, roleOutput),
	})
	if err != nil {
		t.Fatalf("adjudicate Run: %v", err)
	}
	events := adjudicationLedgerEvents(result, inputs, frozen)
	var findingEvents []ledger.FindingEvent
	for _, event := range events {
		if event.Kind != ledger.EventKindFinding {
			continue
		}
		payload, ok := event.Payload.(ledger.FindingEvent)
		if !ok {
			t.Fatalf("finding payload type = %T, want ledger.FindingEvent", event.Payload)
		}
		findingEvents = append(findingEvents, payload)
	}
	if len(findingEvents) != len(result.Findings) {
		t.Fatalf("finding events = %d, want %d", len(findingEvents), len(result.Findings))
	}
	for _, event := range findingEvents {
		if event.FindingID == "" || event.FindingKey == "" || event.WitnessDigest == "" || event.CharterHash == "" || event.ArtifactDigest == "" {
			t.Fatalf("finding event missing required lineage: %#v", event)
		}
		if event.FindingKey != roleOutput.Findings[0].ID {
			t.Fatalf("finding key = %q, want %q", event.FindingKey, roleOutput.Findings[0].ID)
		}
		if _, ok := event.Finding["estimated_delta"]; !ok {
			t.Fatalf("finding payload = %#v, missing estimated_delta", event.Finding)
		}
	}
	events = append(events, ledger.EventToAppend{
		Kind: ledger.EventKindMeasuredDelta,
		Payload: ledger.MeasuredDeltaEvent{
			FindingID:  result.Findings[0].FindingID,
			Production: ledger.IntPtr(1),
			Test:       ledger.IntPtr(1),
			Unit:       ledger.UnitLines,
		},
	})
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	if _, err := ledger.AppendEvents(ledgerPath, events); err != nil {
		t.Fatalf("append ledger events: %v", err)
	}
	document, err := metrics.Run(metrics.Options{LedgerPath: ledgerPath})
	if err != nil {
		t.Fatalf("metrics Run: %v", err)
	}
	if document.DeltaComparison.PairedFindings != 1 || document.DeltaComparison.Production.Equal != 1 || document.DeltaComparison.Test.Equal != 1 {
		t.Fatalf("delta comparison = %#v, want one paired equal finding", document.DeltaComparison)
	}
}

func TestDeltaEstimatePayloadPreservesExplicitZero(t *testing.T) {
	// A known, explicit zero delta must survive into the finding ledger payload as
	// lines:0, distinct from an omitted component. Dropping it (the pre-fix != 0 test)
	// makes metrics treat the finding as estimate-missing instead of comparing zero.
	var estimate contracts.DeltaEstimate
	if err := json.Unmarshal([]byte(`{"status":"known","lines":0}`), &estimate); err != nil {
		t.Fatalf("unmarshal explicit-zero delta: %v", err)
	}
	payload := deltaEstimatePayload(estimate)
	lines, ok := payload["lines"]
	if !ok {
		t.Fatalf("explicit-zero lines dropped from ledger payload: %#v", payload)
	}
	if lines != 0 {
		t.Fatalf("lines = %v, want explicit 0", lines)
	}
	if _, ok := payload["files"]; ok {
		t.Fatalf("omitted files must stay omitted (distinct from explicit zero): %#v", payload)
	}
}

func TestPolicyAndLedgerCLI(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	releaseOut := filepath.Join(dir, "release.json")
	showOut := filepath.Join(dir, "policy-show.json")
	checkOut := filepath.Join(dir, "policy-check.json")
	ledgerShowOut := filepath.Join(dir, "ledger-show.json")
	promoteOut := filepath.Join(dir, "promote.json")
	acceptOut := filepath.Join(dir, "accept.json")

	productionCap := 5
	testCap := 5
	document := contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-cli",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(policyPath, document); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"policy", "release-caps",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-production-cap", "5",
		"-test-cap", "5",
		"-basis", contracts.CapReleaseBasisOwnerJudgment,
		"-rationale", "Owner accepted conservative caps.",
		"-actor", "owner",
		"-out", releaseOut,
	}); err != nil {
		t.Fatalf("policy release-caps: %v", err)
	}
	if err := route([]string{
		"policy", "show",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-out", showOut,
	}); err != nil {
		t.Fatalf("policy show: %v", err)
	}
	showData, err := os.ReadFile(showOut)
	if err != nil {
		t.Fatal(err)
	}
	show, err := strictjson.DecodeBytes[policy.ShowDocument](showData, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !show.PositiveCapAllowanceUsable || show.CapRelease == nil || show.CapReleaseCharterMismatch {
		t.Fatalf("policy show = %#v", show)
	}
	if err := route([]string{
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-estimated-production-lines", "1",
		"-estimated-test-lines", "1",
		"-measured-production", "1",
		"-measured-test", "1",
		"-finding-id", "finding-1",
		"-out", checkOut,
	}); err != nil {
		t.Fatalf("policy check-application: %v", err)
	}
	checkData, err := os.ReadFile(checkOut)
	if err != nil {
		t.Fatal(err)
	}
	check, err := strictjson.DecodeBytes[policyCheckApplicationOutput](checkData, strictjson.DefaultMaxBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	if !check.Allow || len(check.LedgerRecords) != 2 {
		t.Fatalf("policy check output = %#v", check)
	}
	if err := route([]string{
		"ledger", "promote",
		"-ledger", ledgerPath,
		"-question-id", "question-1",
		"-goal-ref", "goal-cli",
		"-actor", "owner",
		"-rationale", "Owner promoted missing goal.",
		"-out", promoteOut,
	}); err != nil {
		t.Fatalf("ledger promote: %v", err)
	}
	if err := route([]string{
		"ledger", "accept-unverified",
		"-ledger", ledgerPath,
		"-finding-id", "finding-1",
		"-pending-verification-id", "verify-1",
		"-actor", "owner",
		"-rationale", "Owner accepted pending risk.",
		"-out", acceptOut,
	}); err != nil {
		t.Fatalf("ledger accept-unverified: %v", err)
	}
	if err := route([]string{
		"ledger", "show",
		"-ledger", ledgerPath,
		"-kind", ledger.EventKindPolicyDecision,
		"-out", ledgerShowOut,
	}); err != nil {
		t.Fatalf("ledger show: %v", err)
	}
	ledgerShowData, err := os.ReadFile(ledgerShowOut)
	if err != nil {
		t.Fatal(err)
	}
	ledgerShow, err := strictjson.DecodeBytes[ledger.ShowDocument](ledgerShowData, strictjson.DefaultMaxBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledgerShow.Records) != 1 || ledgerShow.Records[0].EventKind != ledger.EventKindPolicyDecision {
		t.Fatalf("filtered ledger show = %#v", ledgerShow)
	}
}

func TestMetricsCLIWritesDocument(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "metrics.json")
	if err := route([]string{"metrics", "-out", outPath}); err != nil {
		t.Fatalf("metrics: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	document, err := strictjson.DecodeBytes[metrics.Document](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != metrics.SchemaVersion {
		t.Fatalf("metrics schema_version = %s, want %s", document.SchemaVersion, metrics.SchemaVersion)
	}
	if len(document.PendingVerification.Strata) != 3 || document.PendingVerification.Strata[0].Reason != metrics.ReasonRunResultsMissing {
		t.Fatalf("pending verification strata = %#v", document.PendingVerification.Strata)
	}
}

func TestPolicyCheckApplicationDefaultsOmittedEstimatesUnknown(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "policy-check.json")
	writeCLIAutoPolicy(t, frozen, frozenPath, policyPath, ledgerPath, policy.UnitLines)

	if err := route([]string{
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-measured-production", "1",
		"-measured-test", "1",
		"-finding-id", "finding-1",
		"-out", outPath,
	}); err != nil {
		t.Fatalf("policy check-application: %v", err)
	}
	check := readPolicyCheckOutput(t, outPath)
	if check.Allow || len(check.Reasons) != 1 || check.Reasons[0] != policy.ReasonUnknownEstimatedDelta {
		t.Fatalf("policy check output = %#v, want unknown estimate refusal", check)
	}
	if check.Decision.EstimatedDelta.Production.Status != contracts.DeltaStatusUnknown || check.Decision.EstimatedDelta.Test.Status != contracts.DeltaStatusUnknown {
		t.Fatalf("estimated delta = %#v, want unknown statuses", check.Decision.EstimatedDelta)
	}
}

func TestPolicyCheckApplicationKnownEstimateRequiresExplicitCount(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "policy-check.json")
	writeCLIAutoPolicy(t, frozen, frozenPath, policyPath, ledgerPath, policy.UnitLines)

	err := route([]string{
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-estimated-production-status", contracts.DeltaStatusKnown,
		"-estimated-test-lines", "1",
		"-measured-production", "1",
		"-measured-test", "1",
		"-finding-id", "finding-1",
		"-out", outPath,
	})
	if err == nil {
		t.Fatal("policy check-application accepted known production estimate without an explicit count")
	}
	if got := diag.FromError(err).Code; got != diag.CodeInvalidCommand {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, diag.CodeInvalidCommand, err)
	}
}

func TestPolicyCheckApplicationRefusesReleaseUnitMismatch(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "policy-check.json")
	writeCLIAutoPolicy(t, frozen, frozenPath, policyPath, ledgerPath, policy.UnitFiles)

	err := route([]string{
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-unit", policy.UnitLines,
		"-estimated-production-lines", "1",
		"-estimated-test-lines", "1",
		"-measured-production", "1",
		"-measured-test", "1",
		"-finding-id", "finding-1",
		"-out", outPath,
	})
	if err == nil {
		t.Fatal("policy check-application accepted a release with the wrong unit")
	}
	var validation *policy.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want policy.ValidationError", err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != policy.CodeInvalidPolicyLoad {
		t.Fatalf("diagnostics = %#v, want %s", validation.Diagnostics, policy.CodeInvalidPolicyLoad)
	}
}

func TestPolicyCheckApplicationUsesLatestMatchingUnitRelease(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "policy-check.json")
	writeCLIAutoPolicy(t, frozen, frozenPath, policyPath, ledgerPath, policy.UnitLines)
	if err := route([]string{
		"policy", "release-caps",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-unit", policy.UnitFiles,
		"-production-cap", "5",
		"-test-cap", "5",
		"-basis", contracts.CapReleaseBasisOwnerJudgment,
		"-rationale", "Owner accepted conservative file caps.",
		"-actor", "owner",
		"-out", filepath.Join(dir, "release-files.json"),
	}); err != nil {
		t.Fatalf("policy release-caps files: %v", err)
	}

	if err := route([]string{
		"policy", "check-application",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-unit", policy.UnitLines,
		"-estimated-production-lines", "1",
		"-estimated-test-lines", "1",
		"-measured-production", "1",
		"-measured-test", "1",
		"-finding-id", "finding-1",
		"-out", outPath,
	}); err != nil {
		t.Fatalf("policy check-application: %v", err)
	}
	check := readPolicyCheckOutput(t, outPath)
	if !check.Allow || check.Decision.CapReleaseUnit != policy.UnitLines {
		t.Fatalf("policy check output = %#v, want allow under latest matching lines release", check)
	}
}

func TestAdjudicateCLIIgnoresEmbeddedCapReleaseWithoutLedger(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	policyPath := filepath.Join(dir, "policy.json")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}
	productionCap := 5
	testCap := 5
	policyDocument := contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-cli",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
	release, err := policy.BuildCapRelease(policy.ReleaseInput{
		Policy:        policyDocument,
		Rules:         contracts.DefaultReviewRules(),
		Unit:          policy.UnitLines,
		ProductionCap: productionCap,
		TestCap:       testCap,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner accepted conservative caps.",
		Actor:         "owner",
		CharterHash:   frozen.CharterHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	policyDocument.CapRelease = &release
	if err := writeCanonical(policyPath, policyDocument); err != nil {
		t.Fatal(err)
	}

	err = route([]string{
		"adjudicate",
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	})
	if err == nil {
		t.Fatal("adjudicate accepted an embedded cap_release without ledger provenance")
	}
	var validation *policy.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want policy.ValidationError", err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != policy.CodeInvalidPolicyLoad {
		t.Fatalf("diagnostics = %#v, want %s", validation.Diagnostics, policy.CodeInvalidPolicyLoad)
	}
}

func TestAdjudicateCLILedgerQuestionAllowsEmptyFindingID(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	roleOutput.MissingGoalQuestions = []contracts.MissingGoalQuestion{{
		ID:               "question-anchor",
		Dimension:        charter.DimensionScaleBounds,
		AnchorIndex:      0,
		Property:         "maximum reviewed size",
		Value:            "100 files",
		AffectedDecision: "automatic application",
		Statement:        "Should maximum reviewed size be an explicit goal?",
	}}
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}

	if err := route([]string{
		"adjudicate",
		"-ledger", ledgerPath,
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate with empty question finding_id: %v", err)
	}
	records, err := ledger.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	questionRecords := 0
	var questionEvent ledger.QuestionEvent
	for _, record := range records {
		if record.EventKind == ledger.EventKindQuestion {
			questionRecords++
			event, err := strictjson.DecodeBytes[ledger.QuestionEvent](record.Event, strictjson.DefaultMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			questionEvent = event
		}
	}
	if questionRecords != 1 {
		t.Fatalf("question records = %d, want 1; records=%#v", questionRecords, records)
	}
	if questionEvent.FindingID != "" ||
		questionEvent.Dimension != charter.DimensionScaleBounds ||
		questionEvent.AnchorIndex == nil ||
		*questionEvent.AnchorIndex != 0 ||
		questionEvent.Property != "maximum reviewed size" ||
		questionEvent.Value != "100 files" ||
		questionEvent.AffectedDecision != "automatic application" {
		t.Fatalf("question event = %#v, want persisted envelope linkage without finding_id", questionEvent)
	}
}

func TestAdjudicateCLILedgerBackedPolicyAppendsLineageAndRefusesDuplicate(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	roleOutput.MissingGoalQuestions = []contracts.MissingGoalQuestion{{
		ID:               "question-1",
		FindingID:        "finding-1",
		Dimension:        charter.DimensionScaleBounds,
		AnchorIndex:      0,
		Property:         "maximum reviewed size",
		Value:            "100 files",
		AffectedDecision: "automatic application",
		Statement:        "Should maximum reviewed size be an explicit goal?",
	}}
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	policyPath := filepath.Join(dir, "policy.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	outPath := filepath.Join(dir, "adjudication.json")

	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	manifest := validCLIAdjudicationManifest(t, frozen, roleOutput)
	manifest.Batches[0].Status = contracts.RecordStatusUnavailable
	manifest.Batches[0].RelayVerdicts = nil
	manifest.Batches[0].FailureReason = "relay unavailable"
	if err := writeCanonical(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	productionCap := 5
	testCap := 5
	policyDocument := contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-cli",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
	if err := writeCanonical(policyPath, policyDocument); err != nil {
		t.Fatal(err)
	}
	err := route([]string{
		"adjudicate",
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	})
	if err == nil {
		t.Fatal("adjudicate without ledger-backed cap release succeeded, want fail-closed error")
	}
	release, err := policy.BuildCapRelease(policy.ReleaseInput{
		Policy:        policyDocument,
		Rules:         contracts.DefaultReviewRules(),
		Unit:          policy.UnitLines,
		ProductionCap: productionCap,
		TestCap:       testCap,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner accepted conservative caps.",
		Actor:         "owner",
		CharterHash:   digest.RawBytes([]byte("older-charter")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AppendEvent(ledgerPath, ledger.EventKindCapRelease, ledger.CapReleaseEvent{Release: release}); err != nil {
		t.Fatal(err)
	}

	if err := route([]string{
		"adjudicate",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate with ledger: %v", err)
	}
	resultData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[adjudicate.Result](resultData, strictjson.DefaultMaxBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CapReleaseCharterMismatch {
		t.Fatalf("cap_release_charter_mismatch = false, want true; result=%#v", result)
	}
	records, err := ledger.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, record := range records {
		kinds[record.EventKind]++
	}
	for _, kind := range []string{
		ledger.EventKindCapRelease,
		ledger.EventKindAdjudicationRun,
		ledger.EventKindVerdict,
		ledger.EventKindQuestion,
		ledger.EventKindPendingVerification,
		ledger.EventKindPolicyDecision,
	} {
		if kinds[kind] == 0 {
			t.Fatalf("ledger event kinds = %#v, missing %s", kinds, kind)
		}
	}

	err = route([]string{
		"adjudicate",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-out", outPath,
	})
	if err == nil {
		t.Fatal("second adjudicate succeeded, want duplicate run digest refusal")
	}
	if got := diag.FromError(err).Code; got != ledger.CodeDuplicateRunDigest {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, ledger.CodeDuplicateRunDigest, err)
	}
}

func TestAdjudicateCLIAcceptsPriorLineage(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	roleOutput := validCLIRoleOutput(frozen)
	finding := roleOutput.Findings[0]
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	finding.Recurrence = &contracts.RecurrenceRef{
		PriorFindingID: "prior-finding",
		FindingKey:     "cli-recurring-finding",
		WitnessDigest:  witnessDigest,
		ArtifactDigest: roleOutput.ArtifactDigest,
	}
	roleOutput.Findings[0] = finding
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	lineagePath := filepath.Join(dir, "prior-lineage.jsonl")
	outPath := filepath.Join(dir, "adjudication.json")
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, roleOutput); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(manifestPath, validCLIAdjudicationManifest(t, frozen, roleOutput)); err != nil {
		t.Fatal(err)
	}
	lineage := adjudicate.PriorLineageRecord{
		FindingID:      "prior-finding",
		FindingKey:     "cli-recurring-finding",
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: roleOutput.ArtifactDigest,
		WitnessDigest:  witnessDigest,
		Disposition:    contracts.DispositionAdmitted,
	}
	if err := os.WriteFile(lineagePath, append(mustCanonicalBytes(t, lineage), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"adjudicate",
		"-charter-freeze", frozenPath,
		"-role-output", roleOutputPath,
		"-manifest", manifestPath,
		"-prior-lineage", lineagePath,
		"-out", outPath,
	}); err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Disposition != contracts.DispositionAdmitted {
		t.Fatalf("adjudication findings = %#v", result.Findings)
	}
	for _, reason := range result.Findings[0].Reasons {
		if reason == adjudicate.ReasonRecurrenceLineageUnavailable || reason == adjudicate.ReasonInvalidRecurrenceLineage {
			t.Fatalf("adjudication reasons = %#v, recurrence lineage should pass", result.Findings[0].Reasons)
		}
	}
}

func TestVerificationAssembleRunRelayRoutesLaunchFailurePending(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-run.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility-run.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-run.json")
	bundle := writeCLIArtifact(t, dir, "bundle-run.json")
	artifactPath := writeCLIReviewedArtifact(t, dir)
	preflightPath := writeCLIPreflightResult(t, dir, "preflight-run.json", stateDir, compatibility, capabilities, bundle)
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-run.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleFakeRelayRunner{t: t}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-run.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-artifact", artifactPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("relay run calls = %d, want 1", runner.calls)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusUnavailable {
		t.Fatalf("manifest batches = %#v, want unavailable launch failure", manifest.Batches)
	}
	relayBatches, ok := manifest.ConsumerIdentity["witness_relay_batches"].(map[string]any)
	if !ok {
		t.Fatalf("consumer identity = %#v, missing relay batch metadata", manifest.ConsumerIdentity)
	}
	batchMetadata, ok := relayBatches[manifest.Batches[0].BatchID].(map[string]any)
	if !ok {
		t.Fatalf("relay batch metadata = %#v, missing batch %s", relayBatches, manifest.Batches[0].BatchID)
	}
	if batchMetadata["backend"] != "codex" || batchMetadata["recipe_family"] != "witness-falsify-v2" {
		t.Fatalf("relay batch metadata = %#v, want codex witness-falsify-v2", batchMetadata)
	}
}

func TestVerificationAssembleRunRelayRoundTripPasses(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-success.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility-success.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-success.json")
	bundle := writeCLIArtifact(t, dir, "bundle-success.json")
	artifactPath := writeCLIReviewedArtifact(t, dir)
	preflightPath := writeCLIPreflightResult(t, dir, "preflight-success.json", stateDir, compatibility, capabilities, bundle)
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-success.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleSuccessRelayRunner{t: t}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-success.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-artifact", artifactPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	if runner.runCalls != 1 || runner.exportCalls != 1 || runner.verifyCalls != 1 {
		t.Fatalf("runner calls = run %d export %d verify %d", runner.runCalls, runner.exportCalls, runner.verifyCalls)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusValid {
		t.Fatalf("manifest batches = %#v, want valid relay verification", manifest.Batches)
	}
	if manifest.Batches[0].PortableExportDigest == "" || manifest.Batches[0].CanonicalResultDigest == "" {
		t.Fatalf("manifest batch missing export/result digest: %#v", manifest.Batches[0])
	}
}

func TestVerificationAssembleOutputContainsUnverifiedRelationships(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-unverified.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility-unverified.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-unverified.json")
	bundle := writeCLIArtifact(t, dir, "bundle-unverified.json")
	artifactPath := writeCLIReviewedArtifact(t, dir)
	preflightPath := writeCLIPreflightResult(t, dir, "preflight-unverified.json", stateDir, compatibility, capabilities, bundle)
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-unverified.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}

	runner := &assembleSuccessRelayRunner{t: t, supplementaryUnverified: true}
	previousRunner := verificationAssembleRelayRunner
	verificationAssembleRelayRunner = runner
	defer func() { verificationAssembleRelayRunner = previousRunner }()

	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-unverified.json")
	if err := route([]string{
		"verification", "assemble",
		"-run-relay",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-state-dir", stateDir,
		"-relay", "fake-relay",
		"-backend", "codex",
		"-charter-freeze", frozenPath,
		"-artifact", artifactPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	}); err != nil {
		t.Fatalf("verification assemble -run-relay: %v", err)
	}
	data, err := os.ReadFile(manifestOut)
	if err != nil {
		t.Fatal(err)
	}
	result, err := strictjson.DecodeBytes[planning.AssembleResult](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Manifest.Batches) != 1 || result.Manifest.Batches[0].Status != contracts.RecordStatusValid {
		t.Fatalf("manifest batches = %#v, want valid relay verification", result.Manifest.Batches)
	}
	found := false
	for _, relationship := range result.UnverifiedRelationships {
		if relationship.Classification == "supplementary" &&
			relationship.Code == "facilitator_ledger_content_collision" &&
			relationship.Relationship == "trace_only_facilitator_ledger_prompt_projection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unverified relationships = %#v, want supplementary collision relationship", result.UnverifiedRelationships)
	}
}

func TestVerificationAssembleWritesManifestBeforeBatchError(t *testing.T) {
	dir := t.TempDir()
	frozen := validCLIFrozenCharter(t)
	frozenPath := filepath.Join(dir, "frozen.json")
	roleOutputPath := filepath.Join(dir, "role-output.json")
	stateDir := filepath.Join(dir, "state")
	manifestOut := filepath.Join(dir, "manifest-error.json")
	compatibility := writeCLIArtifact(t, dir, "compatibility-error.json")
	capabilities := writeCLIArtifact(t, dir, "capabilities-error.json")
	bundle := writeCLIArtifact(t, dir, "bundle-error.json")
	preflightPath := writeCLIPreflightResult(t, dir, "preflight-error.json", stateDir, compatibility, capabilities, bundle)
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(roleOutputPath, validCLIRoleOutput(frozen)); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"verification", "plan",
		"-charter-freeze", frozenPath,
		"-preflight", preflightPath,
		"-role-output", roleOutputPath,
		"-state-dir", stateDir,
		"-out", filepath.Join(dir, "plan-error.json"),
	}); err != nil {
		t.Fatalf("verification plan: %v", err)
	}
	batchPath := filepath.Join(stateDir, "verification", "batches", "defect-batch-1.json")
	data, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := contracts.ReadVerificationBatchBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	batch.TaskShape = contracts.BatchTaskEconomy
	tamperedBatchPath := filepath.Join(dir, "tampered-batch.json")
	if err := writeCanonical(tamperedBatchPath, batch); err != nil {
		t.Fatal(err)
	}

	selectedContract := writeCLISelectedContractArtifact(t, dir, "contract-error.json")
	err = route([]string{
		"verification", "assemble",
		"-plan", filepath.Join(stateDir, "verification-plan.json"),
		"-batch", tamperedBatchPath,
		"-compatibility-manifest", compatibility,
		"-relay-capabilities", capabilities,
		"-integration-bundle", bundle,
		"-selected-contract", selectedContract,
		"-out", manifestOut,
	})
	if err == nil {
		t.Fatal("verification assemble accepted tampered batch")
	}
	data, err = os.ReadFile(manifestOut)
	if err != nil {
		t.Fatalf("manifest was not written before error: %v", err)
	}
	manifest, err := strictjson.DecodeBytes[contracts.VerificationManifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Batches) != 1 || manifest.Batches[0].Status != contracts.RecordStatusFailed {
		t.Fatalf("manifest batches = %#v, want failed", manifest.Batches)
	}
}

func TestArtifactRefForSelectedContractPrefersContractDigest(t *testing.T) {
	dir := t.TempDir()
	contract := cliContractBody("witnessed-review/witness-falsification-v2")
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "selected-contract.json")
	if err := writeCanonical(path, map[string]any{
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}); err != nil {
		t.Fatal(err)
	}

	ref, err := artifactRefForFile("selected-contract", path)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Digest != contractDigest {
		t.Fatalf("selected contract digest = %s, want contract_digest %s", ref.Digest, contractDigest)
	}
}

func TestSelectedContractRefsRejectsTamperedSelectedContractEnvelope(t *testing.T) {
	dir := t.TempDir()
	contract := cliContractBody("witnessed-review/witness-falsification-v2")
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"contract_id":     "witnessed-review/witness-falsification-v2",
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	path := filepath.Join(dir, "selected-contract-envelope.json")
	if err := writeCanonical(path, map[string]any{
		"schema_version": "witness-retained-artifact-v1",
		"digest_profile": digest.Profile,
		"payload_digest": digest.RawBytes([]byte("tampered payload digest")),
		"payload":        payload,
	}); err != nil {
		t.Fatal(err)
	}

	refs, err := selectedContractRefsForFile(path)
	if err == nil || !strings.Contains(err.Error(), "payload_digest") {
		t.Fatalf("selectedContractRefsForFile refs=%#v err=%v, want payload_digest error", refs, err)
	}
}

type assembleFakeRelayRunner struct {
	t     *testing.T
	calls int
}

func (runner *assembleFakeRelayRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	if executable != "fake-relay" {
		runner.t.Fatalf("executable = %s, want fake-relay", executable)
	}
	if len(args) == 0 || args[0] != "run" {
		runner.t.Fatalf("unexpected relay command: %v", args)
	}
	runner.calls++
	return relayclient.CommandResult{
		Stdout:   []byte(`{"error":"launch failed"}`),
		Stderr:   []byte("launch failed"),
		ExitCode: 1,
		Err:      errors.New("exit status 1"),
	}
}

type assembleSuccessRelayRunner struct {
	t                       *testing.T
	runCalls                int
	exportCalls             int
	verifyCalls             int
	sessionDir              string
	batch                   contracts.VerificationBatchDocument
	batchBytes              []byte
	charterBytes            []byte
	artifactBytes           []byte
	bundleDigest            string
	supplementaryUnverified bool
}

func (runner *assembleSuccessRelayRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	if executable != "fake-relay" {
		runner.t.Fatalf("executable = %s, want fake-relay", executable)
	}
	if len(args) == 0 {
		runner.t.Fatalf("missing relay command")
	}
	switch args[0] {
	case "run":
		runner.runCalls++
		binding := testArgAfter(args, "--input", "findings=")
		if binding == "" {
			runner.t.Fatalf("run args missing findings input: %v", args)
		}
		charterBinding := testArgAfter(args, "--input", "charter=")
		if charterBinding == "" {
			runner.t.Fatalf("run args missing charter input: %v", args)
		}
		artifactBinding := testArgAfter(args, "--input", "artifact=")
		if artifactBinding == "" {
			runner.t.Fatalf("run args missing artifact input: %v", args)
		}
		bundlePath := testArgAfter(args, "--integration-bundle", "")
		if bundlePath == "" {
			runner.t.Fatalf("run args missing integration bundle: %v", args)
		}
		bundleBytes, err := os.ReadFile(bundlePath)
		if err != nil {
			runner.t.Fatal(err)
		}
		bundlePayload, err := strictjson.DecodeAnyBytes(bundleBytes, strictjson.DefaultMaxBytes)
		if err != nil {
			runner.t.Fatal(err)
		}
		bundleDigest, err := digest.SemanticJSON(bundlePayload)
		if err != nil {
			runner.t.Fatal(err)
		}
		charterBytes, err := os.ReadFile(charterBinding)
		if err != nil {
			runner.t.Fatal(err)
		}
		artifactBytes, err := os.ReadFile(artifactBinding)
		if err != nil {
			runner.t.Fatal(err)
		}
		data, err := os.ReadFile(binding)
		if err != nil {
			runner.t.Fatal(err)
		}
		batch, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			runner.t.Fatal(err)
		}
		runner.batch = batch
		runner.batchBytes = append([]byte(nil), data...)
		runner.charterBytes = append([]byte(nil), charterBytes...)
		runner.artifactBytes = append([]byte(nil), artifactBytes...)
		runner.bundleDigest = bundleDigest
		runner.sessionDir = filepath.Join(runner.t.TempDir(), "relay-session")
		return relayclient.CommandResult{Stdout: []byte(`{"session_dir":"` + runner.sessionDir + `"}`)}
	case "export":
		runner.exportCalls++
		output := testArgAfter(args, "--output", "")
		if output == "" {
			runner.t.Fatalf("export args missing output: %v", args)
		}
		manifestDigest := writeCLIPortableExport(runner.t, output, runner.batch, runner.batchBytes, runner.charterBytes, runner.artifactBytes, runner.bundleDigest)
		if runner.supplementaryUnverified {
			manifestDigest = addCLISupplementaryUnverifiedRelationship(runner.t, output)
		}
		return relayclient.CommandResult{Stdout: []byte(`{"manifest_digest":"` + manifestDigest + `"}`)}
	case "verify-export":
		runner.verifyCalls++
		return relayclient.CommandResult{Stdout: []byte(`{"status":"valid"}`)}
	default:
		runner.t.Fatalf("unexpected relay command: %v", args)
		return relayclient.CommandResult{ExitCode: 1, Err: errors.New("unexpected command")}
	}
}

type cliPortablePayload struct {
	entry map[string]any
	body  []byte
}

func writeCLIPortableExport(t *testing.T, dir string, batch contracts.VerificationBatchDocument, batchBytes []byte, charterBytes []byte, artifactBytes []byte, bundleDigest string) string {
	t.Helper()
	if len(batchBytes) == 0 {
		t.Fatal("batch bytes are required")
	}
	if len(charterBytes) == 0 {
		t.Fatal("charter bytes are required")
	}
	if len(artifactBytes) == 0 {
		t.Fatal("artifact bytes are required")
	}
	if bundleDigest == "" {
		t.Fatal("bundle digest is required")
	}
	verdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.BatchID,
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:      batch.Findings[0].FindingID,
			WitnessDigest:  batch.Findings[0].WitnessDigest,
			Verdict:        contracts.VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
		}},
	}
	contractID := "witnessed-review/witness-falsification-v2"
	contract := cliContractBody(contractID)
	contractDigest, err := digest.SemanticJSON(contract)
	if err != nil {
		t.Fatal(err)
	}
	integrationContract := map[string]any{
		"kind":            "integration_contract",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"contract_id":     contractID,
		"contract_digest": contractDigest,
		"contract":        contract,
	}
	integrationContractDigest, err := digest.StorageEnvelope("integration_contract", integrationContract)
	if err != nil {
		t.Fatal(err)
	}
	payloads := []cliPortablePayload{
		cliPortablePayloadFor(t, "root_session", "session", map[string]any{
			"execution_kind":  "recipe",
			"kind":            "portable_root_session",
			"provider_retry":  "forbid",
			"result_source":   "reducer",
			"status":          "completed",
			"terminal_status": "completed",
		}, nil),
		cliPortablePayloadFor(t, "participant_transcript", "transcript", []any{
			map[string]any{"participant_turn": 1, "actor": "presenter", "content": "turn one", "provider_result_ref": cliPortableRef("artifact-000001", "provider_result:000001")},
			map[string]any{"participant_turn": 2, "actor": "falsifier", "content": "turn two", "provider_result_ref": cliPortableRef("artifact-000007", "provider_result:000003")},
			map[string]any{"participant_turn": 3, "actor": "presenter", "content": "turn three", "provider_result_ref": cliPortableRef("artifact-000013", "provider_result:000005")},
			map[string]any{"participant_turn": 4, "actor": "falsifier", "content": "turn four", "provider_result_ref": cliPortableRef("artifact-000019", "provider_result:000007")},
		}, nil),
		cliPortablePayloadFor(t, "diagnostics", "diagnostics", map[string]any{"execution_kind": "recipe", "status": "completed"}, nil),
		cliPortablePayloadFor(t, "root_recipe_plan", "root-plan", map[string]any{
			"kind":                        "root_recipe_plan",
			"schema_version":              2,
			"digest_profile":              digest.Profile,
			"recipe_id":                   "witness-falsify-v2-codex",
			"provider_retry":              "forbid",
			"result_source":               "reducer",
			"participant_turns":           4,
			"integration_bundle_digest":   bundleDigest,
			"integration_contract_id":     contractID,
			"integration_contract_digest": contractDigest,
			"integration_contract_ref":    cliPortableRefWithDigest("integration-contract", "integration_contract:selected", integrationContractDigest),
			"prompt_context":              map[string]any{"participant_transcript": "complete", "facilitator_ledger": "trace_only"},
		}, cliSourceRef("root_recipe_plan:selected")),
		cliPortablePayloadFor(t, "integration_contract", "integration-contract", integrationContract, map[string]any{"id": "integration_contract:selected", "digest": integrationContractDigest}),
		cliPortablePayloadFor(t, "named_input_content", "named-input-content-1", cliNamedInputContentPayload("charter", 1, charterBytes), cliSourceRef("named_input_content:000001")),
		cliPortablePayloadFor(t, "named_input_content", "named-input-content-2", cliNamedInputContentPayload("findings", 2, batchBytes), cliSourceRef("named_input_content:000002")),
		cliPortablePayloadFor(t, "named_input_content", "named-input-content-3", cliNamedInputContentPayload("artifact", 3, artifactBytes), cliSourceRef("named_input_content:000003")),
		cliPortablePayloadFor(t, "named_input_manifest", "named-input-manifest", map[string]any{
			"kind":           "named_input_manifest",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"contract_id":    contractID,
			"input_count":    3,
			"inputs": []any{
				cliNamedInputEntry("charter", 1, "named-input-content-1", "named_input_content:000001", len(charterBytes), digest.RawBytes(charterBytes)),
				cliNamedInputEntry("findings", 2, "named-input-content-2", "named_input_content:000002", len(batchBytes), digest.RawBytes(batchBytes)),
				cliNamedInputEntry("artifact", 3, "named-input-content-3", "named_input_content:000003", len(artifactBytes), digest.RawBytes(artifactBytes)),
			},
		}, cliSourceRef("named_input_manifest:selected")),
		cliPortablePayloadFor(t, "canonical_result", "canonical-result", map[string]any{
			"kind":           "canonical_result",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"transport":      "json",
			"canonical_json": string(mustCanonicalBytes(t, verdicts)),
			"value":          verdicts,
		}, cliSourceRef("canonical_result:selected")),
		cliPortablePayloadFor(t, "result_validation", "result-validation", map[string]any{
			"kind":                 "result_validation",
			"schema_version":       2,
			"digest_profile":       digest.Profile,
			"status":               "validated",
			"canonical_result_ref": cliPortableRef("canonical-result", "canonical_result:selected"),
		}, cliSourceRef("result_validation:selected")),
	}
	for _, spec := range []struct {
		resultID     string
		invocationID string
		promptID     string
		source       string
		phase        string
		ordinal      int
	}{
		{resultID: "artifact-000001", invocationID: "artifact-000002", promptID: "artifact-000003", source: "000001", phase: "participant", ordinal: 1},
		{resultID: "artifact-000004", invocationID: "artifact-000005", promptID: "artifact-000006", source: "000002", phase: "facilitator", ordinal: 1},
		{resultID: "artifact-000007", invocationID: "artifact-000008", promptID: "artifact-000009", source: "000003", phase: "participant", ordinal: 2},
		{resultID: "artifact-000010", invocationID: "artifact-000011", promptID: "artifact-000012", source: "000004", phase: "facilitator", ordinal: 2},
		{resultID: "artifact-000013", invocationID: "artifact-000014", promptID: "artifact-000015", source: "000005", phase: "participant", ordinal: 3},
		{resultID: "artifact-000016", invocationID: "artifact-000017", promptID: "artifact-000018", source: "000006", phase: "facilitator", ordinal: 3},
		{resultID: "artifact-000019", invocationID: "artifact-000020", promptID: "artifact-000021", source: "000007", phase: "participant", ordinal: 4},
		{resultID: "artifact-000022", invocationID: "artifact-000023", promptID: "artifact-000024", source: "000008", phase: "facilitator", ordinal: 4},
		{resultID: "artifact-000025", invocationID: "artifact-000026", promptID: "artifact-000027", source: "000009", phase: "reducer"},
	} {
		prompt := cliRenderedPromptPayload(spec.phase + " prompt " + spec.source)
		rawDigest := prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string)
		result, invocation := cliProviderPayloads(spec.resultID, spec.promptID, spec.source, spec.phase, spec.ordinal, rawDigest)
		payloads = append(payloads,
			cliPortablePayloadFor(t, "provider_result", spec.resultID, result, cliSourceRef("provider_result:"+spec.source)),
			cliPortablePayloadFor(t, "provider_invocation", spec.invocationID, invocation, cliSourceRef("provider_invocation:"+spec.source)),
			cliPortablePayloadFor(t, "rendered_prompt", spec.promptID, prompt, cliSourceRef("rendered_prompt:"+spec.source)),
		)
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].entry["path"].(string) < payloads[j].entry["path"].(string)
	})
	inventory := make([]any, 0, len(payloads))
	for _, payload := range payloads {
		writeCLIPortableFile(t, dir, payload.entry["path"].(string), payload.body)
		inventory = append(inventory, payload.entry)
	}
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version":      "relay-root-portable-export-v2",
		"convo_relay_version": "v1.4.0",
		"digest_profile":      digest.Profile,
		"terminal_status":     "completed",
		"stop_reason":         nil,
		"session_payload":     "payloads/root_session/session.json",
		"transcript_payload":  "payloads/participant_transcript/transcript.json",
		"diagnostics_payload": "payloads/diagnostics/diagnostics.json",
		"payload_inventory":   inventory,
		"inventory_digest":    inventoryDigest,
	}
	manifestDigest, err := digest.SemanticJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest["manifest_digest"] = manifestDigest
	writeCLIPortableFile(t, dir, "manifest.json", mustCanonicalBytes(t, manifest))
	return manifestDigest
}

func addCLISupplementaryUnverifiedRelationship(t *testing.T, dir string) string {
	t.Helper()
	const marker = "SHARED_CONTEXT_MARKER"
	mutateCLIPortablePayload(t, dir, "participant_transcript", "transcript", func(value any) any {
		transcript := value.([]any)
		entry := transcript[0].(map[string]any)
		entry["content"] = entry["content"].(string) + " " + marker
		entry["ledger"] = map[string]any{
			"settled":   []any{},
			"contested": []any{marker},
			"withdrawn": []any{},
		}
		return transcript
	})
	promptDigest := ""
	mutateCLIPortablePayload(t, dir, "rendered_prompt", "artifact-000003", func(any) any {
		prompt := cliRenderedPromptPayload("participant prompt includes " + marker)
		promptDigest = prompt["rendered_prompt"].(map[string]any)["raw_digest"].(string)
		return prompt
	})
	mutateCLIPortablePayload(t, dir, "provider_result", "artifact-000001", func(value any) any {
		result := value.(map[string]any)
		result["invocation"].(map[string]any)["rendered_prompt_digest"] = promptDigest
		return result
	})
	return mutateCLIPortablePayload(t, dir, "provider_invocation", "artifact-000002", func(value any) any {
		invocation := value.(map[string]any)
		invocation["invocation"].(map[string]any)["rendered_prompt_digest"] = promptDigest
		return invocation
	})
}

func mutateCLIPortablePayload(t *testing.T, dir string, kind string, id string, mutate func(any) any) string {
	t.Helper()
	manifestPath := filepath.Join(dir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestValue, err := strictjson.DecodeAnyBytes(manifestBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestValue.(map[string]any)
	inventory := manifest["payload_inventory"].([]any)
	var entry map[string]any
	for _, raw := range inventory {
		candidate := raw.(map[string]any)
		if candidate["kind"] == kind && candidate["portable_id"] == id {
			entry = candidate
			break
		}
	}
	if entry == nil {
		t.Fatalf("payload %s/%s not found", kind, id)
	}
	payloadPath := filepath.Join(dir, filepath.FromSlash(entry["path"].(string)))
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadValue, err := strictjson.DecodeAnyBytes(payloadBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes := mustCanonicalBytes(t, mutate(payloadValue))
	if err := os.WriteFile(payloadPath, updatedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	entry["size_bytes"] = len(updatedBytes)
	entry["digest"] = digest.RawBytes(updatedBytes)
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		t.Fatal(err)
	}
	manifest["inventory_digest"] = inventoryDigest
	delete(manifest, "manifest_digest")
	manifestDigest, err := digest.SemanticJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest["manifest_digest"] = manifestDigest
	writeCLIPortableFile(t, dir, "manifest.json", mustCanonicalBytes(t, manifest))
	return manifestDigest
}

func cliProviderPayloads(resultPortableID string, promptPortableID string, sourceOrdinal string, phase string, participantOrdinal int, promptDigest string) (map[string]any, map[string]any) {
	invocationDraft := map[string]any{
		"schema_version":            "relay-provider-invocation-v2",
		"invocation_id":             phase + ":" + sourceOrdinal,
		"phase":                     phase,
		"actor":                     "Agent " + sourceOrdinal,
		"participant_ordinal":       nil,
		"reducer_fresh":             phase == "reducer",
		"rendered_prompt_ref":       cliPortableRef(promptPortableID, "rendered_prompt:"+sourceOrdinal),
		"rendered_prompt_digest":    promptDigest,
		"backend":                   "codex",
		"mapped_working_directory":  ".",
		"runner_attempt":            1,
		"provider_launch_attempted": true,
		"provider_retry":            "forbid",
		"started_at":                "2026-01-01T00:00:00Z",
		"completed_at":              "2026-01-01T00:00:01Z",
		"outcome":                   "completed",
		"failure_stage":             nil,
		"classification":            nil,
		"provider_result_ref":       nil,
	}
	if participantOrdinal > 0 {
		invocationDraft["participant_ordinal"] = participantOrdinal
	}
	resultPayload := map[string]any{
		"kind":            "provider_result",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"invocation_id":   invocationDraft["invocation_id"],
		"phase":           invocationDraft["phase"],
		"actor":           invocationDraft["actor"],
		"runner_attempt":  invocationDraft["runner_attempt"],
		"provider_retry":  invocationDraft["provider_retry"],
		"backend":         invocationDraft["backend"],
		"started_at":      invocationDraft["started_at"],
		"completed_at":    invocationDraft["completed_at"],
		"outcome":         invocationDraft["outcome"],
		"failure_stage":   invocationDraft["failure_stage"],
		"classification":  invocationDraft["classification"],
		"provider_result": map[string]any{"backend": "codex", "return_code": 0},
		"invocation":      invocationDraft,
	}
	boundInvocation := cloneMap(invocationDraft)
	boundInvocation["provider_result_ref"] = cliPortableRef(resultPortableID, "provider_result:"+sourceOrdinal)
	return resultPayload, map[string]any{
		"kind":           "provider_invocation",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"invocation":     boundInvocation,
	}
}

func cliPortablePayloadFor(t *testing.T, kind string, id string, value any, sourceRef map[string]any) cliPortablePayload {
	t.Helper()
	body := mustCanonicalBytes(t, value)
	entry := map[string]any{
		"kind":         kind,
		"portable_id":  id,
		"path":         filepath.ToSlash(filepath.Join("payloads", kind, id+".json")),
		"media_type":   "application/json",
		"size_bytes":   len(body),
		"digest_class": digest.ClassRawBytes,
		"digest":       digest.RawBytes(body),
	}
	if sourceRef != nil {
		entry["source_artifact_id"] = sourceRef["id"]
		entry["source_artifact_digest"] = sourceRef["digest"]
	}
	return cliPortablePayload{entry: entry, body: body}
}

func cliNamedInputContentPayload(name string, ordinal int, data []byte) map[string]any {
	return map[string]any{
		"kind":           "named_input_content",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"ordinal":        ordinal,
		"name":           name,
		"name_ordinal":   1,
		"encoding":       "base64",
		"bytes_base64":   base64.StdEncoding.EncodeToString(data),
		"size_bytes":     len(data),
		"raw_digest":     digest.RawBytes(data),
		"media_type":     "application/json",
		"schema_status":  "unchecked",
	}
}

func cliRenderedPromptPayload(text string) map[string]any {
	data := []byte(text)
	return map[string]any{
		"kind":           "rendered_prompt",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"rendered_prompt": map[string]any{
			"schema_version": "relay-rendered-prompt-v1",
			"media_type":     "text/plain; charset=utf-8",
			"encoding":       "base64",
			"bytes_base64":   base64.StdEncoding.EncodeToString(data),
			"size_bytes":     len(data),
			"raw_digest":     digest.RawBytes(data),
		},
	}
}

func cliNamedInputEntry(name string, ordinal int, portableID string, sourceID string, sizeBytes int, rawDigest string) map[string]any {
	return map[string]any{
		"ordinal":       ordinal,
		"name":          name,
		"name_ordinal":  1,
		"source_path":   name + ".json",
		"display_name":  name + ".json",
		"size_bytes":    sizeBytes,
		"raw_digest":    rawDigest,
		"media_type":    "application/json",
		"schema_status": "unchecked",
		"content_ref":   cliPortableRef(portableID, sourceID),
	}
}

func cliContractBody(contractID string) map[string]any {
	return map[string]any{
		"id": contractID,
		"turns": []any{
			map[string]any{"participant_turn": 1, "slot": "slot_0", "instructions": "Presenter verifies the filed witness."},
			map[string]any{"participant_turn": 2, "slot": "slot_1", "instructions": "Falsifier challenges the filed witness."},
			map[string]any{"participant_turn": 3, "slot": "slot_0", "instructions": "Presenter responds to challenges."},
			map[string]any{"participant_turn": 4, "slot": "slot_1", "instructions": "Falsifier gives final challenge."},
		},
		"reducer": map[string]any{"instructions": "Return relay witness verdict JSON."},
		"inputs": map[string]any{
			"artifact": map[string]any{"required": false, "cardinality": "many", "media_type": "application/json", "max_bytes": 1048576},
			"charter":  map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
			"findings": map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
		},
		"result": map[string]any{"transport": "json", "schema": map[string]any{"type": "object"}, "assertions": []any{}},
		"prompt_context": map[string]any{
			"participant_transcript": "complete",
			"facilitator_ledger":     "trace_only",
		},
	}
}

func cliPortableRef(portableID string, sourceID string) map[string]any {
	return cliPortableRefWithDigest(portableID, sourceID, cliSourceRef(sourceID)["digest"].(string))
}

func cliPortableRefWithDigest(portableID string, sourceID string, sourceDigest string) map[string]any {
	return map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            portableID,
		"source_artifact_id":     sourceID,
		"source_artifact_digest": sourceDigest,
	}
}

func cliSourceRef(id string) map[string]any {
	return map[string]any{"id": id, "digest": digest.RawBytes([]byte(id))}
}

func writeCLIPortableFile(t *testing.T, root string, relative string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustCanonicalBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testArgAfter(args []string, key string, trimPrefix string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] != key {
			continue
		}
		value := args[index+1]
		if trimPrefix != "" {
			if len(value) <= len(trimPrefix) || value[:len(trimPrefix)] != trimPrefix {
				continue
			}
			return value[len(trimPrefix):]
		}
		return value
	}
	return ""
}

func assertOutputPathConflict(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("alias check succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
}

func readFrozen(t *testing.T, path string) charter.FrozenCharter {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode frozen charter: %v", err)
	}
	return frozen
}

func validCLIFrozenCharter(t *testing.T) charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-cli",
			Statement: "The CLI accepts declared valid inputs deterministically.",
		}},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial charter.",
		}},
		OperationalEnvelope: &charter.OperationalEnvelope{
			EntryPoints: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared entry points.",
				Entries:   []charter.Entry{{ID: "cli", Statement: "Command line interface."}},
			},
			InputSurface: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Caller supplied files.",
				Entries:   []charter.Entry{},
			},
			ValidStates: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared valid states.",
				Entries:   []charter.Entry{{ID: "normal", Statement: "Normal configured operation."}},
			},
			Environments: &charter.Dimension{
				State:     charter.StateNotApplicable,
				Statement: "No environment distinction.",
				Entries:   []charter.Entry{},
			},
			ScaleBounds: &charter.Dimension{
				State:     charter.StateUnspecified,
				Statement: "Scale is unspecified.",
				Entries:   []charter.Entry{},
			},
			CompatibilityPromises: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared compatibility promises.",
				Entries:   []charter.Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
			},
			ThreatModel: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Threat scenarios must be concrete.",
				Entries:   []charter.Entry{},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func validCLIRoleOutput(frozen charter.FrozenCharter) contracts.RoleOutputDocument {
	return contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV3,
		Role:           contracts.RoleDefect,
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: digest.RawBytes([]byte("artifact")),
		SourceIdentity: map[string]any{"kind": "test", "id": "source"},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
		},
		Findings: []contracts.Finding{{
			ID:              "finding-1",
			Kind:            contracts.FindingKindDefect,
			Title:           "CLI rejects a declared input",
			CharterGoalIDs:  []string{"goal-cli"},
			ClaimedSeverity: contracts.SeverityHigh,
			ScopeAnchors:    []contracts.ScopeAnchor{{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}},
			Witness: contracts.Witness{
				Kind:     contracts.WitnessKindDefect,
				Strength: contracts.WitnessStrengthConstructed,
				Content:  "The reachable CLI input hits the rejecting branch.",
				EntryPoint: &contracts.ScopeAnchor{
					Dimension: charter.DimensionEntryPoints,
					EntryID:   "cli",
				},
				ReachabilityChain: []contracts.ScopeAnchor{
					{Dimension: charter.DimensionEntryPoints, EntryID: "cli"},
					{Dimension: charter.DimensionInputSurface, Value: "config"},
					{Dimension: charter.DimensionValidStates, EntryID: "normal"},
				},
			},
			EstimatedDelta: contracts.SplitDeltaEstimate{
				Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
				Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
			},
			SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
				Direction:          contracts.RemedyDirectionChange,
				Summary:            "Change the rejecting branch.",
				MinimalityArgument: "Only the reachable branch changes.",
			},
			ProposedTests: []contracts.ProposedTest{{
				ID:                 "test-finding-1",
				Name:               "accepts declared input",
				ReachablePartition: "cli config",
				CharterRefs:        []contracts.CharterRef{{GoalID: "goal-cli"}},
			}},
		}},
	}
}

func writeCLIAutoPolicy(t *testing.T, frozen charter.FrozenCharter, frozenPath string, policyPath string, ledgerPath string, unit string) {
	t.Helper()
	productionCap := 5
	testCap := 5
	document := contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-cli",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
	if err := writeCanonical(frozenPath, frozen); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonical(policyPath, document); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{
		"policy", "release-caps",
		"-ledger", ledgerPath,
		"-policy", policyPath,
		"-charter-freeze", frozenPath,
		"-unit", unit,
		"-production-cap", "5",
		"-test-cap", "5",
		"-basis", contracts.CapReleaseBasisOwnerJudgment,
		"-rationale", "Owner accepted conservative caps.",
		"-actor", "owner",
		"-out", filepath.Join(filepath.Dir(policyPath), "release-"+unit+".json"),
	}); err != nil {
		t.Fatalf("policy release-caps: %v", err)
	}
}

func readPolicyCheckOutput(t *testing.T, path string) policyCheckApplicationOutput {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output, err := strictjson.DecodeBytes[policyCheckApplicationOutput](data, strictjson.DefaultMaxBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func validCLIAdjudicationManifest(t *testing.T, frozen charter.FrozenCharter, roleOutput contracts.RoleOutputDocument) contracts.VerificationManifest {
	t.Helper()
	finding := roleOutput.Findings[0]
	witnessDigest, err := contracts.WitnessDigest(finding.Witness)
	if err != nil {
		t.Fatal(err)
	}
	verdicts := contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       "batch-1",
		Verdicts: []contracts.WitnessVerdict{{
			FindingID:     finding.ID,
			WitnessDigest: witnessDigest,
			Verdict:       contracts.VerdictSurvived,
			VerdictClass:  nil,
		}},
	}
	resultDigest, err := contracts.RelayWitnessVerdictsDigest(verdicts)
	if err != nil {
		t.Fatal(err)
	}
	batchRef := artifactRef("verification-batch", "batch-1", digest.RawBytes([]byte("batch")))
	exportRef := artifactRef("relay-root-portable-export", "batch-1", digest.RawBytes([]byte("export")))
	return contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV4,
		PlanDigest:            digest.RawBytes([]byte("plan")),
		CharterHash:           frozen.CharterHash,
		ArtifactDigest:        roleOutput.ArtifactDigest,
		CompatibilityManifest: artifactRef("compatibility-manifest", "compatibility", digest.RawBytes([]byte("compatibility"))),
		RelayCapabilities:     artifactRef("relay-capabilities", "capabilities", digest.RawBytes([]byte("capabilities"))),
		IntegrationBundle:     artifactRef("integration-bundle", "bundle", digest.RawBytes([]byte("bundle"))),
		SelectedContracts:     []contracts.ArtifactRef{artifactRef("selected-contract", "contract", digest.RawBytes([]byte("contract")))},
		Batches: []contracts.VerificationManifestBatch{{
			BatchID:               "batch-1",
			Status:                contracts.RecordStatusValid,
			BatchRef:              batchRef,
			BatchDigest:           batchRef.Digest,
			PortableExportRef:     &exportRef,
			PortableExportDigest:  exportRef.Digest,
			CanonicalResultDigest: resultDigest,
			RelayVerdicts:         &verdicts,
		}},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
}

func writeCLIArtifact(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	value := any(map[string]any{"name": name})
	if strings.HasPrefix(name, "compatibility") {
		compatibility := validCLICompatibility(t, name)
		compatibilityDigest, err := contracts.RelayCompatibilityDigest(compatibility)
		if err != nil {
			t.Fatal(err)
		}
		value = map[string]any{
			"schema_version":  "witness-retained-artifact-v1",
			"digest_profile":  digest.Profile,
			"payload_digest":  compatibilityDigest,
			"payload":         compatibility,
			"retention_kind":  "compatibility-manifest",
			"retention_scope": "test",
		}
	}
	if err := writeCanonical(path, value); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLIReviewedArtifact(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(path, []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLIPreflightResult(t *testing.T, dir string, name string, stateDir string, compatibilityPath string, capabilitiesPath string, bundlePath string) string {
	t.Helper()
	compatibilityRef, err := artifactRefForFile("compatibility-manifest", compatibilityPath)
	if err != nil {
		t.Fatal(err)
	}
	capabilitiesRef, err := artifactRefForFile("relay-capabilities", capabilitiesPath)
	if err != nil {
		t.Fatal(err)
	}
	bundleRef, err := artifactRefForFile("integration-bundle", bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	result := preflight.Result{
		SchemaVersion: preflight.SchemaVersion,
		OK:            true,
		StateDir:      stateDir,
		ArtifactDigests: map[string]string{
			"compatibility-manifest.json": compatibilityRef.Digest,
			"relay-capabilities.json":     capabilitiesRef.Digest,
		},
		CompileReportDigests: map[string]string{},
		RecipePlanDigests:    map[string]string{},
		ContractDigests: map[string]string{
			"integration_bundle": bundleRef.Digest,
		},
		BackendStrata:    map[string]string{},
		SnapshotDigest:   digest.RawBytes([]byte("artifact")),
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
	if err := writeCanonical(path, result); err != nil {
		t.Fatal(err)
	}
	return path
}

func validCLICompatibility(t *testing.T, compatibilityName string) contracts.RelayCompatibility {
	t.Helper()
	suffix := strings.TrimPrefix(compatibilityName, "compatibility")
	capabilitiesName := "capabilities" + suffix
	bundleName := "bundle" + suffix
	capabilities := map[string]bool{}
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		capabilities[requirement.Key] = true
	}
	selectedContracts := make([]contracts.ContractDigest, 0, 2)
	for _, contractID := range []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	} {
		contractDigest, err := digest.SemanticJSON(cliContractBody(contractID))
		if err != nil {
			t.Fatal(err)
		}
		selectedContracts = append(selectedContracts, contracts.ContractDigest{
			ContractID: contractID,
			Digest:     contractDigest,
		})
	}
	recipePlans := make([]contracts.RecipePlanDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	compileReports := make([]contracts.CompileReportRef, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		planDigest := digest.RawBytes([]byte("recipe:" + requirement.RecipeID))
		reportDigest := digest.RawBytes([]byte("compile:" + requirement.RecipeID))
		recipePlans = append(recipePlans, contracts.RecipePlanDigest{
			RecipeID:   requirement.RecipeID,
			ContractID: requirement.ContractID,
			Digest:     planDigest,
		})
		compileReports = append(compileReports, contracts.CompileReportRef{
			RecipeID: requirement.RecipeID,
			Status:   "retained",
			Ref:      artifactRef("compile-report", requirement.RecipeID, reportDigest),
			Digest:   reportDigest,
		})
	}
	return contracts.RelayCompatibility{
		SchemaVersion:           contracts.RelayCompatibilityV3,
		ConvoRelayVersion:       "v1.4.0",
		DigestProfile:           digest.Profile,
		Capabilities:            capabilities,
		CapabilitiesDigest:      cliWrittenCanonicalDigest(t, map[string]any{"name": capabilitiesName}),
		IntegrationBundleDigest: cliSemanticDigest(t, map[string]any{"name": bundleName}),
		SelectedContracts:       selectedContracts,
		RecipePlans:             recipePlans,
		CompileReports:          compileReports,
		BackendStatus: []contracts.BackendStatus{
			{Backend: "codex", Status: "available"},
			{Backend: "claude", Status: "available"},
		},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
}

func cliSemanticDigest(t *testing.T, value any) string {
	t.Helper()
	digestValue, err := digest.SemanticJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return digestValue
}

func cliWrittenCanonicalDigest(t *testing.T, value any) string {
	t.Helper()
	data := append([]byte(nil), mustCanonicalBytes(t, value)...)
	data = append(data, '\n')
	return digest.RawBytes(data)
}

func writeCLISelectedContractArtifact(t *testing.T, dir string, name string) string {
	t.Helper()
	contractEntries := map[string]any{}
	contractDigests := map[string]any{}
	for _, contractID := range []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	} {
		contract := cliContractBody(contractID)
		contractDigest, err := digest.SemanticJSON(contract)
		if err != nil {
			t.Fatal(err)
		}
		contractEntries[contractID] = map[string]any{
			"contract_id":     contractID,
			"contract_digest": contractDigest,
			"contract":        contract,
		}
		contractDigests[contractID] = contractDigest
	}
	path := filepath.Join(dir, name)
	if err := writeCanonical(path, map[string]any{
		"contracts":        contractEntries,
		"contract_digests": contractDigests,
	}); err != nil {
		t.Fatal(err)
	}
	return path
}
