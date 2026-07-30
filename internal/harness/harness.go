package harness

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/strictjson"
)

const (
	RequestSchemaVersion = "witness-harness-run-request-v1"
	ResultSchemaVersion  = "witness-harness-run-result-v1"
	InventorySchema      = "witness-harness-inventory-v1"
	DeltaSchema          = "witness-harness-workspace-delta-v1"
	Version              = "witness-harness-v1"

	AuthenticationScheme = "hmac-sha256"

	ClassificationValid         = "valid"
	ClassificationInvalid       = "invalid"
	ClassificationContradictory = "contradictory"
	ClassificationUnavailable   = "unavailable"

	CodeInvalidRequest              = "harness_invalid_request"
	CodeInvalidExpectedObservation  = "harness_invalid_expected_observation"
	CodeMissingRequest              = "harness_missing_request"
	CodeMissingOutputDir            = "harness_missing_output_dir"
	CodeInvalidFrozenSource         = "harness_invalid_frozen_source"
	CodeSourceDigestMismatch        = "harness_source_digest_mismatch"
	CodeUnsafePath                  = "harness_unsafe_path"
	CodeUnsafeOutputPath            = "harness_unsafe_output_path"
	CodeUnsupportedFileType         = "harness_unsupported_file_type"
	CodeShellForbidden              = "harness_shell_forbidden"
	CodeRestoreDigestMismatch       = "harness_restore_digest_mismatch"
	CodeAuthenticationInvalid       = "harness_authentication_invalid"
	CodeArtifactDigestMismatch      = "harness_artifact_digest_mismatch"
	CodeReceiptDigestMismatch       = "harness_receipt_digest_mismatch"
	CodeReceiptContradictory        = "harness_receipt_contradictory"
	CodeReceiptRelationshipMismatch = "harness_receipt_relationship_mismatch"
	CodeReceiptUnavailable          = "harness_receipt_unavailable"
	CodeArtifactNotLocatable        = "harness_artifact_not_locatable"
	CodeWorkspaceOutputConflict     = "harness_workspace_output_conflict"
)

var (
	stableIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type RunRequest struct {
	SchemaVersion            string                `json:"schema_version"`
	FindingID                string                `json:"finding_id"`
	CharterHash              string                `json:"charter_hash"`
	FrozenSource             contracts.ArtifactRef `json:"frozen_source"`
	FrozenSourceManifestPath string                `json:"frozen_source_manifest_path"`
	// Command.ExpectedObservation supports semicolon-separated predicates:
	// exit_code, stdout_digest, stderr_digest, stdout_contains, stderr_contains, and timed_out.
	// Free-text predicate values use percent escaping for '%', ';', '=', and control bytes.
	Command        contracts.ExecutableSpec `json:"command"`
	Environment    map[string]string        `json:"environment,omitempty"`
	TimeoutMS      int64                    `json:"timeout_ms"`
	Issuer         contracts.ReceiptIssuer  `json:"issuer"`
	Authentication RunRequestAuthentication `json:"authentication"`
	ResourceLimits map[string]any           `json:"resource_limits,omitempty"`
}

type RunRequestAuthentication struct {
	Scheme  string `json:"scheme"`
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}

type RunOptions struct {
	Request      RunRequest
	RequestBytes []byte
	OutputDir    string
	TempDir      string
}

type RunResult struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	ReceiptRef    contracts.ArtifactRef      `json:"receipt_ref"`
	ReceiptDigest string                     `json:"receipt_digest"`
	ReceiptPath   string                     `json:"receipt_path"`
	OutputDir     string                     `json:"output_dir"`
	Receipt       contracts.ExecutionReceipt `json:"-"`
}

type Error struct {
	Diagnostics []diag.Diagnostic
}

func (err *Error) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "harness error"
	}
	if len(err.Diagnostics) == 1 {
		first := err.Diagnostics[0]
		if first.Path != "" {
			return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
		}
		return fmt.Sprintf("%s: %s", first.Code, first.Message)
	}
	return fmt.Sprintf("%s: %s (%d diagnostics)", err.Diagnostics[0].Code, err.Diagnostics[0].Message, len(err.Diagnostics))
}

type Inventory struct {
	SchemaVersion string          `json:"schema_version"`
	Kind          string          `json:"kind"`
	DigestProfile string          `json:"digest_profile"`
	Files         []InventoryFile `json:"files"`
}

type InventoryFile struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Dir    bool   `json:"dir"`
	Size   int64  `json:"size,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type WorkspaceDelta struct {
	SchemaVersion string                `json:"schema_version"`
	DigestProfile string                `json:"digest_profile"`
	BeforeDigest  string                `json:"before_digest"`
	AfterDigest   string                `json:"after_digest"`
	Added         []WorkspaceDeltaEntry `json:"added,omitempty"`
	Removed       []WorkspaceDeltaEntry `json:"removed,omitempty"`
	Modified      []WorkspaceDeltaEntry `json:"modified,omitempty"`
}

type WorkspaceDeltaEntry struct {
	Path         string `json:"path"`
	BeforeDir    bool   `json:"before_dir,omitempty"`
	BeforeMode   string `json:"before_mode,omitempty"`
	BeforeDigest string `json:"before_digest,omitempty"`
	AfterDir     bool   `json:"after_dir,omitempty"`
	AfterMode    string `json:"after_mode,omitempty"`
	AfterDigest  string `json:"after_digest,omitempty"`
}

type ReceiptVerification struct {
	Classification string            `json:"classification"`
	Diagnostics    []diag.Diagnostic `json:"diagnostics,omitempty"`
}

type VerifyOptions struct {
	Receipt              contracts.ExecutionReceipt
	OutputDir            string
	HMACKey              []byte
	HMACKeyFile          string
	ExpectedSourceDigest string
}

func ReadRequest(reader io.Reader) (RunRequest, []byte, error) {
	data, err := readLimited(reader, strictjson.DefaultMaxBytes)
	if err != nil {
		return RunRequest{}, nil, err
	}
	request, err := strictjson.DecodeBytes[RunRequest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return RunRequest{}, nil, err
	}
	return request, data, nil
}

func ReadRequestFile(path string) (RunRequest, []byte, error) {
	if strings.TrimSpace(path) == "" {
		return RunRequest{}, nil, diag.New(CodeMissingRequest, "witness-harness run requires -request.")
	}
	file, err := os.Open(path)
	if err != nil {
		return RunRequest{}, nil, err
	}
	defer file.Close()
	return ReadRequest(file)
}

func RunFile(ctx context.Context, requestPath string, outputDir string) (*RunResult, error) {
	request, data, err := ReadRequestFile(requestPath)
	if err != nil {
		return nil, err
	}
	return Run(ctx, RunOptions{Request: request, RequestBytes: data, OutputDir: outputDir})
}

func Run(ctx context.Context, options RunOptions) (*RunResult, error) {
	request := options.Request
	if len(options.RequestBytes) == 0 {
		encoded, err := canonjson.Marshal(request)
		if err != nil {
			return nil, err
		}
		options.RequestBytes = encoded
	}
	if diagnostics := ValidateRequest(request); len(diagnostics) > 0 {
		return nil, &Error{Diagnostics: diagnostics}
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return nil, &Error{Diagnostics: []diag.Diagnostic{newDiagnostic(CodeMissingOutputDir, "witness-harness run requires -out-dir.", "/out_dir", nil)}}
	}
	outputDir, err := canonicalPath(options.OutputDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	manifest, manifestDir, sourceDigest, err := loadFrozenSourceManifest(request.FrozenSourceManifestPath)
	if err != nil {
		return nil, err
	}
	if request.FrozenSource.Digest != sourceDigest {
		return nil, &Error{Diagnostics: []diag.Diagnostic{newDiagnostic(
			CodeSourceDigestMismatch,
			"frozen_source digest must match the frozen source manifest digest.",
			"/frozen_source/digest",
			map[string]any{"got": request.FrozenSource.Digest, "want": sourceDigest},
		)}}
	}

	key, err := os.ReadFile(request.Authentication.KeyFile)
	if err != nil {
		return nil, err
	}

	tempRoot := options.TempDir
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	workspaceDir, err := os.MkdirTemp(tempRoot, "witness-harness-workspace-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workspaceDir)
	workspaceDir, err = canonicalPath(workspaceDir)
	if err != nil {
		return nil, err
	}
	if outputInsideWorkspace(workspaceDir, outputDir) {
		return nil, &Error{Diagnostics: []diag.Diagnostic{newDiagnostic(
			CodeWorkspaceOutputConflict,
			"receipt output directory must not be inside the ephemeral execution workspace.",
			"/out_dir",
			map[string]any{"workspace_dir": workspaceDir, "output_dir": outputDir},
		)}}
	}

	sourceBefore, err := InventorySourceSnapshot(manifest, manifestDir)
	if err != nil {
		return nil, err
	}
	if err := Restore(ctx, manifest, manifestDir, workspaceDir); err != nil {
		return nil, err
	}
	workspaceBefore, err := InventoryWorkspace(workspaceDir)
	if err != nil {
		return nil, err
	}

	cwdRel, err := cleanWorkspaceRelativePath(request.Command.CWD)
	if err != nil {
		return nil, err
	}
	cwdAbs := filepath.Join(workspaceDir, filepath.FromSlash(cwdRel))
	outcome := runStructuredCommand(ctx, request.Command.Argv, cwdAbs, request.Environment, time.Duration(request.TimeoutMS)*time.Millisecond)

	workspaceAfter, err := InventoryWorkspace(workspaceDir)
	if err != nil {
		return nil, err
	}
	sourceAfter, err := InventorySourceSnapshot(manifest, manifestDir)
	if err != nil {
		return nil, err
	}

	requestDigest, err := digest.SemanticJSON(request)
	if err != nil {
		return nil, err
	}
	stdoutRef, err := writeBytesArtifact(outputDir, "stdout", "execution-stdout", "stdout", "text/plain", outcome.Stdout)
	if err != nil {
		return nil, err
	}
	stderrRef, err := writeBytesArtifact(outputDir, "stderr", "execution-stderr", "stderr", "text/plain", outcome.Stderr)
	if err != nil {
		return nil, err
	}
	sourceBeforeRef, sourceBeforeDigest, err := writeJSONArtifact(outputDir, "inventory", "execution-inventory", "source-before", "application/json", sourceBefore)
	if err != nil {
		return nil, err
	}
	sourceAfterRef, sourceAfterDigest, err := writeJSONArtifact(outputDir, "inventory", "execution-inventory", "source-after", "application/json", sourceAfter)
	if err != nil {
		return nil, err
	}
	workspaceBeforeRef, workspaceBeforeDigest, err := writeJSONArtifact(outputDir, "inventory", "execution-inventory", "workspace-before", "application/json", workspaceBefore)
	if err != nil {
		return nil, err
	}
	workspaceAfterRef, workspaceAfterDigest, err := writeJSONArtifact(outputDir, "inventory", "execution-inventory", "workspace-after", "application/json", workspaceAfter)
	if err != nil {
		return nil, err
	}
	delta := DiffInventories(workspaceBefore, workspaceAfter, workspaceBeforeDigest, workspaceAfterDigest)
	deltaRef, _, err := writeJSONArtifact(outputDir, "inventory", "workspace-mutation-report", "workspace-delta", "application/json", delta)
	if err != nil {
		return nil, err
	}
	producedRefs := []contracts.ArtifactRef{deltaRef}
	workspaceArtifacts, err := writeProducedWorkspaceArtifacts(outputDir, workspaceDir, delta, workspaceAfter)
	if err != nil {
		return nil, err
	}
	producedRefs = append(producedRefs, workspaceArtifacts...)

	observed := observedObservation(outcome, stdoutRef.Digest, stderrRef.Digest)
	executionStatus := classifyExecution(request.Command.ExpectedObservation, outcome, stdoutRef.Digest, stderrRef.Digest)
	receiptID := receiptID(request, requestDigest, observed, workspaceAfterDigest)
	resourceLimits := resourceLimits(request, requestDigest, outcome, sourceBeforeDigest, sourceAfterDigest, workspaceBeforeDigest, workspaceAfterDigest)
	receipt := contracts.ExecutionReceipt{
		SchemaVersion:  contracts.ExecutionReceiptV2,
		ReceiptID:      receiptID,
		FindingID:      request.FindingID,
		CharterHash:    request.CharterHash,
		ArtifactDigest: sourceDigest,
		FrozenSource:   normalizedFrozenSourceRef(request.FrozenSource, sourceDigest),
		Harness:        harnessIdentity(),
		Issuer:         normalizedIssuer(request.Issuer),
		Authentication: contracts.ReceiptAuthentication{
			Scheme: AuthenticationScheme,
			KeyID:  request.Authentication.KeyID,
		},
		Command:                  request.Command,
		Containment:              containmentReport(),
		SourceInventoryBefore:    sourceBeforeRef,
		SourceInventoryAfter:     sourceAfterRef,
		WorkspaceInventoryBefore: workspaceBeforeRef,
		WorkspaceInventoryAfter:  workspaceAfterRef,
		Captures: contracts.ExecutionCaptures{
			Stdout:            &stdoutRef,
			Stderr:            &stderrRef,
			ProducedArtifacts: producedRefs,
		},
		ExpectedObservation:   request.Command.ExpectedObservation,
		ObservedObservation:   observed,
		ExecutionStatus:       executionStatus,
		TransformationRef:     request.Command.TransformationRef,
		ResultWorkspaceDigest: workspaceAfterDigest,
		Environment:           sortedEnvironmentMap(request.Environment),
		ResourceLimits:        resourceLimits,
	}
	if err := SignReceipt(&receipt, key); err != nil {
		return nil, err
	}
	if diagnostics := contracts.ValidateExecutionReceipt(receipt); len(diagnostics) > 0 {
		return nil, &Error{Diagnostics: diagnostics}
	}

	receiptPath, err := writeReceipt(outputDir, receipt)
	if err != nil {
		return nil, err
	}
	receiptDigest, err := contracts.ExecutionReceiptDigest(receipt)
	if err != nil {
		return nil, err
	}
	receiptRef := contracts.ArtifactRef{
		Kind:          "execution-receipt",
		ID:            receipt.ReceiptID,
		Digest:        receiptDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
	return &RunResult{
		SchemaVersion: ResultSchemaVersion,
		OK:            true,
		ReceiptRef:    receiptRef,
		ReceiptDigest: receiptDigest,
		ReceiptPath:   receiptPath,
		OutputDir:     outputDir,
		Receipt:       receipt,
	}, nil
}

func ValidateRequest(request RunRequest) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if request.SchemaVersion != RequestSchemaVersion {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeInvalidRequest,
			"run request schema_version must be witness-harness-run-request-v1.",
			"/schema_version",
			map[string]any{"expected": RequestSchemaVersion, "actual": request.SchemaVersion},
		))
	}
	requireStableID(&diagnostics, "/finding_id", "finding ID", request.FindingID)
	requireDigest(&diagnostics, "/charter_hash", "charter_hash", request.CharterHash)
	validateArtifactRef(&diagnostics, "/frozen_source", request.FrozenSource)
	if strings.TrimSpace(request.FrozenSourceManifestPath) == "" {
		diagnostics = append(diagnostics, newDiagnostic(CodeInvalidRequest, "frozen_source_manifest_path is required.", "/frozen_source_manifest_path", nil))
	}
	validateExecutable(&diagnostics, request.Command)
	validateEnvironment(&diagnostics, request.Environment)
	if request.TimeoutMS <= 0 {
		diagnostics = append(diagnostics, newDiagnostic(CodeInvalidRequest, "timeout_ms must be positive.", "/timeout_ms", map[string]any{"timeout_ms": request.TimeoutMS}))
	}
	if strings.TrimSpace(request.Issuer.ID) != "" {
		requireStableID(&diagnostics, "/issuer/id", "issuer ID", request.Issuer.ID)
	}
	if strings.TrimSpace(request.Authentication.Scheme) != AuthenticationScheme {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeInvalidRequest,
			"authentication scheme must be hmac-sha256.",
			"/authentication/scheme",
			map[string]any{"scheme": request.Authentication.Scheme},
		))
	}
	requireString(&diagnostics, "/authentication/key_id", "authentication key_id", request.Authentication.KeyID)
	requireString(&diagnostics, "/authentication/key_file", "authentication key_file", request.Authentication.KeyFile)
	return diagnostics
}

func Restore(_ context.Context, manifest freeze.Manifest, manifestDir string, workspaceDir string) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	for _, entry := range manifest.Files {
		if err := validateRelativePath(entry.Path); err != nil {
			return err
		}
		data, err := readSnapshotBlob(manifestDir, entry)
		if err != nil {
			return err
		}
		target := filepath.Join(workspaceDir, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		switch entry.Mode {
		case "100644", "100755":
			fileMode := os.FileMode(0o644)
			if entry.Mode == "100755" {
				fileMode = 0o755
			}
			if err := os.WriteFile(target, data, fileMode); err != nil {
				return err
			}
			if err := os.Chmod(target, fileMode); err != nil {
				return err
			}
		case "120000":
			if err := os.Symlink(string(data), target); err != nil {
				return err
			}
		default:
			return diag.New(CodeUnsupportedFileType, "snapshot file mode is not supported by witness-harness.", diag.WithPath("/files"), diag.WithDetail("mode", entry.Mode), diag.WithDetail("path", entry.Path))
		}
	}
	return nil
}

func InventorySourceSnapshot(manifest freeze.Manifest, manifestDir string) (Inventory, error) {
	if err := validateManifest(manifest); err != nil {
		return Inventory{}, err
	}
	files := make([]InventoryFile, 0, len(manifest.Files))
	for _, entry := range manifest.Files {
		if err := validateRelativePath(entry.Path); err != nil {
			return Inventory{}, err
		}
		data, err := readSnapshotBlob(manifestDir, entry)
		if err != nil {
			return Inventory{}, err
		}
		files = append(files, InventoryFile{
			Path:   entry.Path,
			Mode:   entry.Mode,
			Dir:    false,
			Size:   int64(len(data)),
			Digest: digest.RawBytes(data),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return Inventory{SchemaVersion: InventorySchema, Kind: "source-snapshot", DigestProfile: digest.Profile, Files: files}, nil
}

func InventoryWorkspace(root string) (Inventory, error) {
	var files []InventoryFile
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validateRelativePath(rel); err != nil {
			return err
		}
		if info.IsDir() {
			files = append(files, InventoryFile{
				Path: rel,
				Mode: directoryMode(info),
				Dir:  true,
			})
			return nil
		}
		mode, data, err := workspaceEntryBytes(path, info)
		if err != nil {
			return err
		}
		files = append(files, InventoryFile{
			Path:   rel,
			Mode:   mode,
			Dir:    false,
			Size:   int64(len(data)),
			Digest: digest.RawBytes(data),
		})
		return nil
	})
	if err != nil {
		return Inventory{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return Inventory{SchemaVersion: InventorySchema, Kind: "execution-workspace", DigestProfile: digest.Profile, Files: files}, nil
}

func DiffInventories(before Inventory, after Inventory, beforeDigest string, afterDigest string) WorkspaceDelta {
	beforeByPath := map[string]InventoryFile{}
	afterByPath := map[string]InventoryFile{}
	for _, file := range before.Files {
		beforeByPath[file.Path] = file
	}
	for _, file := range after.Files {
		afterByPath[file.Path] = file
	}
	delta := WorkspaceDelta{
		SchemaVersion: DeltaSchema,
		DigestProfile: digest.Profile,
		BeforeDigest:  beforeDigest,
		AfterDigest:   afterDigest,
	}
	for _, file := range after.Files {
		previous, exists := beforeByPath[file.Path]
		if !exists {
			delta.Added = append(delta.Added, WorkspaceDeltaEntry{
				Path:        file.Path,
				AfterDir:    file.Dir,
				AfterMode:   file.Mode,
				AfterDigest: file.Digest,
			})
			continue
		}
		if previous.Mode != file.Mode || previous.Digest != file.Digest || previous.Dir != file.Dir {
			delta.Modified = append(delta.Modified, WorkspaceDeltaEntry{
				Path:         file.Path,
				BeforeDir:    previous.Dir,
				BeforeMode:   previous.Mode,
				BeforeDigest: previous.Digest,
				AfterDir:     file.Dir,
				AfterMode:    file.Mode,
				AfterDigest:  file.Digest,
			})
		}
	}
	for _, file := range before.Files {
		if _, exists := afterByPath[file.Path]; !exists {
			delta.Removed = append(delta.Removed, WorkspaceDeltaEntry{
				Path:         file.Path,
				BeforeDir:    file.Dir,
				BeforeMode:   file.Mode,
				BeforeDigest: file.Digest,
			})
		}
	}
	return delta
}

func SignReceipt(receipt *contracts.ExecutionReceipt, key []byte) error {
	if len(key) == 0 {
		return diag.New(CodeAuthenticationInvalid, "HMAC key file must not be empty.")
	}
	unsigned := *receipt
	unsigned.Authentication.SignedDigest = ""
	unsigned.Authentication.Signature = ""
	signedDigest, err := contracts.ExecutionReceiptDigest(unsigned)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signedDigest))
	receipt.Authentication.SignedDigest = signedDigest
	receipt.Authentication.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func VerifyReceipt(options VerifyOptions) ReceiptVerification {
	var diagnostics []diag.Diagnostic
	var unavailableDiagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, contracts.ValidateExecutionReceipt(options.Receipt)...)
	if options.Receipt.ExpectedObservation != options.Receipt.Command.ExpectedObservation {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"receipt expected_observation must match command.expected_observation.",
			"/expected_observation",
			map[string]any{"receipt": options.Receipt.ExpectedObservation, "command": options.Receipt.Command.ExpectedObservation},
		))
	}
	if !artifactRefPointersEqual(options.Receipt.TransformationRef, options.Receipt.Command.TransformationRef) {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"receipt transformation_ref must match command.transformation_ref.",
			"/transformation_ref",
			nil,
		))
	}
	if strings.TrimSpace(options.Receipt.ExpectedObservation) != "" {
		_, expectationDiagnostics := parseExpectedObservation(options.Receipt.ExpectedObservation, "/expected_observation")
		diagnostics = append(diagnostics, expectationDiagnostics...)
	}
	if options.ExpectedSourceDigest != "" {
		if options.Receipt.ArtifactDigest != options.ExpectedSourceDigest {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeSourceDigestMismatch,
				"receipt artifact_digest does not match expected frozen source digest.",
				"/artifact_digest",
				map[string]any{"got": options.Receipt.ArtifactDigest, "want": options.ExpectedSourceDigest},
			))
		}
		if options.Receipt.FrozenSource.Digest != options.ExpectedSourceDigest {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeSourceDigestMismatch,
				"receipt frozen_source digest does not match expected frozen source digest.",
				"/frozen_source/digest",
				map[string]any{"got": options.Receipt.FrozenSource.Digest, "want": options.ExpectedSourceDigest},
			))
		}
	}
	if options.Receipt.FrozenSource.Digest != "" && options.Receipt.ArtifactDigest != "" && options.Receipt.FrozenSource.Digest != options.Receipt.ArtifactDigest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeSourceDigestMismatch,
			"receipt artifact_digest and frozen_source digest must match.",
			"/frozen_source/digest",
			map[string]any{"artifact_digest": options.Receipt.ArtifactDigest, "frozen_source_digest": options.Receipt.FrozenSource.Digest},
		))
	}
	key := options.HMACKey
	if len(key) == 0 && options.HMACKeyFile != "" {
		var err error
		key, err = os.ReadFile(options.HMACKeyFile)
		if err != nil {
			diagnostics = append(diagnostics, newDiagnostic(CodeAuthenticationInvalid, "HMAC key file could not be read.", "/authentication", map[string]any{"error": err.Error()}))
		}
	}
	if len(key) == 0 {
		diagnostics = append(diagnostics, newDiagnostic(CodeAuthenticationInvalid, "HMAC key is required to verify the receipt.", "/authentication", nil))
	} else {
		diagnostics = append(diagnostics, verifyAuthentication(options.Receipt, key)...)
	}
	if len(diagnostics) == 0 {
		var artifactDiagnostics []diag.Diagnostic
		artifactDiagnostics, unavailableDiagnostics = verifyReceiptArtifacts(options.OutputDir, options.Receipt)
		diagnostics = append(diagnostics, artifactDiagnostics...)
	}
	if len(diagnostics) > 0 {
		return ReceiptVerification{Classification: ClassificationInvalid, Diagnostics: diagnostics}
	}
	if len(unavailableDiagnostics) > 0 {
		return ReceiptVerification{Classification: ClassificationUnavailable, Diagnostics: unavailableDiagnostics}
	}
	if options.Receipt.ExecutionStatus == contracts.ExecutionStatusContradicted {
		return ReceiptVerification{Classification: ClassificationContradictory, Diagnostics: []diag.Diagnostic{newDiagnostic(
			CodeReceiptContradictory,
			"receipt is valid and reports a contradictory observation.",
			"/execution_status",
			map[string]any{"execution_status": options.Receipt.ExecutionStatus},
		)}}
	}
	return ReceiptVerification{Classification: ClassificationValid}
}

func ArtifactPath(outputDir string, ref contracts.ArtifactRef) (string, error) {
	namespace := artifactNamespace(ref.Kind)
	if namespace == "" {
		return "", diag.New(CodeArtifactNotLocatable, "artifact reference kind is not stored in the harness content-addressed area.", diag.WithDetail("kind", ref.Kind))
	}
	if !digestPattern.MatchString(ref.Digest) {
		return "", diag.New(CodeArtifactNotLocatable, "artifact reference digest is not a valid sha256 digest.", diag.WithDetail("digest", ref.Digest))
	}
	return filepath.Join(outputDir, "artifacts", namespace, "sha256", strings.TrimPrefix(ref.Digest, digest.Prefix)), nil
}

func ReceiptPath(outputDir string, ref contracts.ArtifactRef) (string, error) {
	if ref.Kind != "execution-receipt" || !stableIDPattern.MatchString(ref.ID) {
		return "", diag.New(CodeArtifactNotLocatable, "receipt reference is not a witness-harness execution receipt.", diag.WithDetail("kind", ref.Kind), diag.WithDetail("id", ref.ID))
	}
	return filepath.Join(outputDir, "receipts", ref.ID+".json"), nil
}

func loadFrozenSourceManifest(path string) (freeze.Manifest, string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return freeze.Manifest{}, "", "", err
	}
	manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return freeze.Manifest{}, "", "", err
	}
	if err := validateManifest(manifest); err != nil {
		return freeze.Manifest{}, "", "", err
	}
	manifestDigest, err := frozenManifestDigest(manifest)
	if err != nil {
		return freeze.Manifest{}, "", "", err
	}
	if manifest.Source.ManifestDigest != manifestDigest || manifest.Workspace.ManifestDigest != manifestDigest {
		return freeze.Manifest{}, "", "", &Error{Diagnostics: []diag.Diagnostic{newDiagnostic(
			CodeInvalidFrozenSource,
			"frozen source manifest embedded digests do not match the manifest projection.",
			"/manifest_digest",
			map[string]any{"computed": manifestDigest, "source": manifest.Source.ManifestDigest, "workspace": manifest.Workspace.ManifestDigest},
		)}}
	}
	return manifest, filepath.Dir(path), manifestDigest, nil
}

func validateManifest(manifest freeze.Manifest) error {
	var diagnostics []diag.Diagnostic
	if manifest.SchemaVersion != freeze.SchemaVersion {
		diagnostics = append(diagnostics, newDiagnostic(CodeInvalidFrozenSource, "frozen source manifest schema_version is not supported.", "/schema_version", map[string]any{"actual": manifest.SchemaVersion, "expected": freeze.SchemaVersion}))
	}
	if manifest.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, newDiagnostic(CodeInvalidFrozenSource, "frozen source manifest digest_profile is not supported.", "/digest_profile", map[string]any{"actual": manifest.DigestProfile, "expected": digest.Profile}))
	}
	if manifest.Workspace.Format != freeze.Format {
		diagnostics = append(diagnostics, newDiagnostic(CodeInvalidFrozenSource, "frozen source manifest workspace format is not supported.", "/workspace/format", map[string]any{"actual": manifest.Workspace.Format, "expected": freeze.Format}))
	}
	for index, entry := range manifest.Files {
		path := "/files/" + strconv.Itoa(index)
		if err := validateRelativePath(entry.Path); err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
		}
		switch entry.Mode {
		case "100644", "100755", "120000":
		default:
			diagnostics = append(diagnostics, newDiagnostic(CodeUnsupportedFileType, "frozen source manifest contains an unsupported file mode.", path+"/mode", map[string]any{"mode": entry.Mode}))
		}
		if !digestPattern.MatchString(entry.Digest) {
			diagnostics = append(diagnostics, newDiagnostic(CodeInvalidFrozenSource, "frozen source manifest file digest is invalid.", path+"/digest", map[string]any{"digest": entry.Digest}))
		}
		if err := validateRelativePath(entry.Blob); err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
		}
	}
	if len(diagnostics) > 0 {
		return &Error{Diagnostics: diagnostics}
	}
	return nil
}

func frozenManifestDigest(manifest freeze.Manifest) (string, error) {
	projection := map[string]any{
		"schema_version": manifest.SchemaVersion,
		"digest_profile": manifest.DigestProfile,
		"source": map[string]any{
			"path":             manifest.Source.Path,
			"git_root":         manifest.Source.GitRoot,
			"git_head":         manifest.Source.GitHead,
			"git_tracked_only": manifest.Source.GitTrackedOnly,
		},
		"files": manifest.Files,
	}
	encoded, err := canonjson.Marshal(projection)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(encoded), nil
}

func readSnapshotBlob(manifestDir string, entry freeze.FileEntry) ([]byte, error) {
	if err := validateRelativePath(entry.Blob); err != nil {
		return nil, err
	}
	path := filepath.Join(manifestDir, filepath.FromSlash(entry.Blob))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	actual := digest.RawBytes(data)
	if actual != entry.Digest {
		return nil, diag.New(
			CodeRestoreDigestMismatch,
			"frozen source blob digest does not match the manifest entry.",
			diag.WithDetail("path", entry.Path),
			diag.WithDetail("blob", entry.Blob),
			diag.WithDetail("got", actual),
			diag.WithDetail("want", entry.Digest),
		)
	}
	return data, nil
}

func workspaceEntryBytes(path string, info fs.FileInfo) (string, []byte, error) {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return "", nil, err
		}
		return "120000", []byte(target), nil
	}
	if !mode.IsRegular() {
		return "", nil, diag.New(CodeUnsupportedFileType, "execution workspace contains a non-regular file type.", diag.WithDetail("path", path), diag.WithDetail("mode", mode.String()))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	if mode&0o111 != 0 {
		return "100755", data, nil
	}
	return "100644", data, nil
}

func directoryMode(info fs.FileInfo) string {
	mode := info.Mode()
	bits := mode.Perm()
	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("04%04o", bits)
}

func writeProducedWorkspaceArtifacts(outputDir string, workspaceDir string, delta WorkspaceDelta, after Inventory) ([]contracts.ArtifactRef, error) {
	afterByPath := map[string]InventoryFile{}
	for _, file := range after.Files {
		afterByPath[file.Path] = file
	}
	var paths []string
	for _, entry := range delta.Added {
		paths = append(paths, entry.Path)
	}
	for _, entry := range delta.Modified {
		paths = append(paths, entry.Path)
	}
	sort.Strings(paths)
	refs := make([]contracts.ArtifactRef, 0, len(paths))
	for _, rel := range paths {
		file := afterByPath[rel]
		if file.Dir || file.Mode == "120000" {
			continue
		}
		path := filepath.Join(workspaceDir, filepath.FromSlash(rel))
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		ref, err := writeBytesArtifact(outputDir, "workspace", "execution-artifact", stableGeneratedID("workspace-artifact", rel), "application/octet-stream", data)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func writeBytesArtifact(outputDir string, namespace string, kind string, id string, mediaType string, data []byte) (contracts.ArtifactRef, error) {
	sum := digest.RawBytes(data)
	path := filepath.Join(outputDir, "artifacts", namespace, "sha256", strings.TrimPrefix(sum, digest.Prefix))
	if err := writeContentAddressed(path, data, sum); err != nil {
		return contracts.ArtifactRef{}, err
	}
	return contracts.ArtifactRef{
		Kind:          kind,
		ID:            id,
		Digest:        sum,
		DigestProfile: digest.Profile,
		MediaType:     mediaType,
	}, nil
}

func writeJSONArtifact(outputDir string, namespace string, kind string, id string, mediaType string, value any) (contracts.ArtifactRef, string, error) {
	data, err := canonjson.Marshal(value)
	if err != nil {
		return contracts.ArtifactRef{}, "", err
	}
	ref, err := writeBytesArtifact(outputDir, namespace, kind, id, mediaType, data)
	if err != nil {
		return contracts.ArtifactRef{}, "", err
	}
	return ref, ref.Digest, nil
}

func writeContentAddressed(path string, data []byte, expectedDigest string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return diag.New(CodeUnsafeOutputPath, "content-addressed artifact path must not be a symlink.", diag.WithDetail("path", path))
		}
		if !info.Mode().IsRegular() {
			return diag.New(CodeUnsafeOutputPath, "content-addressed artifact path must be a regular file.", diag.WithDetail("path", path))
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if digest.RawBytes(existing) != expectedDigest {
			return diag.New(CodeArtifactDigestMismatch, "existing content-addressed artifact does not match its digest name.", diag.WithDetail("path", path))
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return writeContentAddressed(path, data, expectedDigest)
		}
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeReceipt(outputDir string, receipt contracts.ExecutionReceipt) (string, error) {
	dir := filepath.Join(outputDir, "receipts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, receipt.ReceiptID+".json")
	if err := rejectExistingSymlink(path); err != nil {
		return "", err
	}
	encoded, err := contracts.ExecutionReceiptCanonicalBytes(receipt)
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func runStructuredCommand(parent context.Context, argv []string, cwd string, env map[string]string, timeout time.Duration) commandOutcome {
	started := time.Now()
	if parent == nil {
		parent = context.Background()
	}
	timeoutDeadline := started.Add(timeout)
	if parent.Err() != nil {
		timedOut, canceled, reason := interruptedCommandTermination(parent, timeoutDeadline, false, time.Now())
		return commandOutcome{
			ExitCode:          -1,
			TimedOut:          timedOut,
			Canceled:          canceled,
			TerminationReason: reason,
			Duration:          time.Since(started),
		}
	}
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = cwd
	command.Env = environmentList(env)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return commandOutcome{
			Stdout:            stdout.Bytes(),
			Stderr:            stderr.Bytes(),
			ExitCode:          -1,
			StartError:        err.Error(),
			TerminationReason: terminationStartError,
			Duration:          time.Since(started),
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()
	var waitErr error
	timedOut := false
	canceled := false
	terminationReason := terminationCompleted
	select {
	case waitErr = <-done:
	case <-timeoutTimer.C:
		timedOut, canceled, terminationReason = interruptedCommandTermination(parent, timeoutDeadline, true, time.Now())
		killProcessGroup(command.Process.Pid)
		waitErr = <-done
	case <-parent.Done():
		timerExpired := !timeoutTimer.Stop()
		timedOut, canceled, terminationReason = interruptedCommandTermination(parent, timeoutDeadline, timerExpired, time.Now())
		killProcessGroup(command.Process.Pid)
		waitErr = <-done
	}
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	return commandOutcome{
		Stdout:            stdout.Bytes(),
		Stderr:            stderr.Bytes(),
		ExitCode:          exitCode,
		TimedOut:          timedOut,
		Canceled:          canceled,
		TerminationReason: terminationReason,
		WaitErr:           waitErr,
		Duration:          time.Since(started),
	}
}

type commandOutcome struct {
	Stdout            []byte
	Stderr            []byte
	ExitCode          int
	TimedOut          bool
	Canceled          bool
	TerminationReason string
	StartError        string
	WaitErr           error
	Duration          time.Duration
}

const (
	terminationCompleted        = "completed"
	terminationTimeout          = "timeout"
	terminationCanceled         = "canceled"
	terminationExternalDeadline = "external_deadline"
	terminationStartError       = "start_error"
)

// terminationExternalDeadline means the parent context reached DeadlineExceeded
// before the harness timeout; it is canceled=true and timed_out=false.
func interruptedCommandTermination(parent context.Context, timeoutDeadline time.Time, timerExpired bool, observedAt time.Time) (bool, bool, string) {
	if parent == nil {
		parent = context.Background()
	}
	parentErr := parent.Err()
	if parentErr != nil {
		if parentDeadline, ok := parent.Deadline(); ok && !parentDeadline.After(timeoutDeadline) {
			return false, true, parentTerminationReason(parent)
		}
		if !timerExpired && observedAt.Before(timeoutDeadline) {
			return false, true, parentTerminationReason(parent)
		}
	}
	if timerExpired || !observedAt.Before(timeoutDeadline) {
		return true, false, terminationTimeout
	}
	if parentErr != nil {
		return false, true, parentTerminationReason(parent)
	}
	return true, false, terminationTimeout
}

func parentTerminationReason(parent context.Context) string {
	if parent == nil {
		return terminationCanceled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(context.Cause(parent), context.DeadlineExceeded) {
		return terminationExternalDeadline
	}
	return terminationCanceled
}

func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func observedObservation(outcome commandOutcome, stdoutDigest string, stderrDigest string) string {
	terminationReason := outcome.TerminationReason
	if terminationReason == "" {
		terminationReason = terminationCompleted
	}
	parts := []string{
		"exit_code=" + strconv.Itoa(outcome.ExitCode),
		"timed_out=" + strconv.FormatBool(outcome.TimedOut),
		"termination_reason=" + terminationReason,
		"stdout_digest=" + stdoutDigest,
		"stderr_digest=" + stderrDigest,
	}
	if outcome.StartError != "" {
		parts = append(parts, "start_error="+escapeObservationValue(outcome.StartError))
	}
	return strings.Join(parts, ";")
}

func escapeObservationValue(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var builder strings.Builder
	changed := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != '%' && char != ';' && char != '=' && char >= 0x20 && char != 0x7f {
			if changed {
				builder.WriteByte(char)
			}
			continue
		}
		if !changed {
			builder.Grow(len(value) + 8)
			builder.WriteString(value[:index])
			changed = true
		}
		builder.WriteByte('%')
		builder.WriteByte(hexDigits[char>>4])
		builder.WriteByte(hexDigits[char&0x0f])
	}
	if !changed {
		return value
	}
	return builder.String()
}

func unescapeObservationValue(value string) (string, error) {
	var builder strings.Builder
	changed := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != '%' {
			if changed {
				builder.WriteByte(char)
			}
			continue
		}
		if index+2 >= len(value) {
			return "", fmt.Errorf("incomplete percent escape")
		}
		decoded, ok := decodeObservationHexByte(value[index+1], value[index+2])
		if !ok {
			return "", fmt.Errorf("invalid percent escape")
		}
		if !changed {
			builder.Grow(len(value))
			builder.WriteString(value[:index])
			changed = true
		}
		builder.WriteByte(decoded)
		index += 2
	}
	if !changed {
		return value, nil
	}
	return builder.String(), nil
}

func decodeObservationHexByte(high byte, low byte) (byte, bool) {
	highValue, ok := observationHexValue(high)
	if !ok {
		return 0, false
	}
	lowValue, ok := observationHexValue(low)
	if !ok {
		return 0, false
	}
	return highValue<<4 | lowValue, true
}

func observationHexValue(char byte) (byte, bool) {
	switch {
	case char >= '0' && char <= '9':
		return char - '0', true
	case char >= 'a' && char <= 'f':
		return char - 'a' + 10, true
	case char >= 'A' && char <= 'F':
		return char - 'A' + 10, true
	default:
		return 0, false
	}
}

func parseStrictObservationBool(value string) (bool, bool) {
	switch value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func classifyExecution(expected string, outcome commandOutcome, stdoutDigest string, stderrDigest string) string {
	if outcome.TimedOut || outcome.Canceled || outcome.StartError != "" {
		return contracts.ExecutionStatusFailed
	}
	switch outcome.TerminationReason {
	case terminationTimeout, terminationCanceled, terminationExternalDeadline, terminationStartError:
		return contracts.ExecutionStatusFailed
	}
	predicates, diagnostics := parseExpectedObservation(expected, "")
	if len(diagnostics) > 0 || len(predicates) == 0 {
		return contracts.ExecutionStatusFailed
	}
	if expectedPredicatesMatch(predicates, outcome, stdoutDigest, stderrDigest) {
		return contracts.ExecutionStatusSatisfied
	}
	return contracts.ExecutionStatusContradicted
}

type expectedPredicate struct {
	Key       string
	Value     string
	ExitCode  int
	BoolValue bool
}

func parseExpectedObservation(expected string, path string) ([]expectedPredicate, []diag.Diagnostic) {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil, nil
	}
	parts := strings.Split(expected, ";")
	predicates := make([]expectedPredicate, 0, len(parts))
	var diagnostics []diag.Diagnostic
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			diagnostics = append(diagnostics, expectedObservationDiagnostic(
				"expected observation predicates must use key=value syntax.",
				path,
				map[string]any{"predicate": part, "index": index},
			))
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		predicate := expectedPredicate{Key: key, Value: value}
		switch key {
		case "exit_code":
			want, err := strconv.Atoi(value)
			if err != nil {
				diagnostics = append(diagnostics, expectedObservationDiagnostic(
					"exit_code expectation must be an integer.",
					path,
					map[string]any{"value": value, "index": index},
				))
				continue
			}
			predicate.ExitCode = want
		case "stdout_digest", "stderr_digest":
			if !digestPattern.MatchString(value) {
				diagnostics = append(diagnostics, expectedObservationDiagnostic(
					key+" expectation must be a sha256 digest.",
					path,
					map[string]any{"value": value, "index": index},
				))
				continue
			}
		case "stdout_contains", "stderr_contains":
			unescaped, err := unescapeObservationValue(value)
			if err != nil {
				diagnostics = append(diagnostics, expectedObservationDiagnostic(
					key+" expectation contains an invalid escape sequence.",
					path,
					map[string]any{"value": value, "index": index},
				))
				continue
			}
			predicate.Value = unescaped
		case "timed_out":
			want, ok := parseStrictObservationBool(value)
			if !ok {
				diagnostics = append(diagnostics, expectedObservationDiagnostic(
					"timed_out expectation must be true or false.",
					path,
					map[string]any{"value": value, "index": index},
				))
				continue
			}
			predicate.BoolValue = want
		default:
			diagnostics = append(diagnostics, expectedObservationDiagnostic(
				"expected observation contains an unsupported predicate.",
				path,
				map[string]any{"key": key, "index": index},
			))
			continue
		}
		predicates = append(predicates, predicate)
	}
	if len(predicates) == 0 && len(diagnostics) == 0 {
		diagnostics = append(diagnostics, expectedObservationDiagnostic(
			"expected observation must contain at least one supported predicate.",
			path,
			nil,
		))
	}
	return predicates, diagnostics
}

func expectedPredicatesMatch(predicates []expectedPredicate, outcome commandOutcome, stdoutDigest string, stderrDigest string) bool {
	for _, predicate := range predicates {
		switch predicate.Key {
		case "exit_code":
			if outcome.ExitCode != predicate.ExitCode {
				return false
			}
		case "stdout_digest":
			if stdoutDigest != predicate.Value {
				return false
			}
		case "stderr_digest":
			if stderrDigest != predicate.Value {
				return false
			}
		case "stdout_contains":
			if !strings.Contains(string(outcome.Stdout), predicate.Value) {
				return false
			}
		case "stderr_contains":
			if !strings.Contains(string(outcome.Stderr), predicate.Value) {
				return false
			}
		case "timed_out":
			if outcome.TimedOut != predicate.BoolValue {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func expectedObservationDiagnostic(message string, path string, details map[string]any) diag.Diagnostic {
	if path == "" {
		path = "/command/expected_observation"
	}
	if details == nil {
		details = map[string]any{}
	}
	details["supported"] = []string{"exit_code", "stdout_digest", "stderr_digest", "stdout_contains", "stderr_contains", "timed_out"}
	return newDiagnostic(CodeInvalidExpectedObservation, message, path, details)
}

func evaluateExpectedObservation(expected string, outcome commandOutcome, stdoutDigest string, stderrDigest string) (bool, bool) {
	predicates, diagnostics := parseExpectedObservation(expected, "")
	if len(diagnostics) > 0 || len(predicates) == 0 {
		return false, false
	}
	return true, expectedPredicatesMatch(predicates, outcome, stdoutDigest, stderrDigest)
}

func classifyObservedExecution(expected string, observed parsedObservedObservation, stdout []byte, stderr []byte) string {
	outcome := commandOutcome{
		Stdout:            stdout,
		Stderr:            stderr,
		ExitCode:          observed.ExitCode,
		TimedOut:          observed.TimedOut,
		Canceled:          observed.TerminationReason == terminationCanceled || observed.TerminationReason == terminationExternalDeadline,
		TerminationReason: observed.TerminationReason,
		StartError:        observed.StartError,
	}
	return classifyExecution(expected, outcome, observed.StdoutDigest, observed.StderrDigest)
}

type parsedObservedObservation struct {
	ExitCode          int
	TimedOut          bool
	TerminationReason string
	StdoutDigest      string
	StderrDigest      string
	StartError        string
}

func parseObservedObservation(observed string) (parsedObservedObservation, []diag.Diagnostic) {
	var parsed parsedObservedObservation
	observed = strings.TrimSpace(observed)
	if observed == "" {
		return parsed, []diag.Diagnostic{newDiagnostic(CodeReceiptRelationshipMismatch, "observed observation is required.", "/observed_observation", nil)}
	}
	fields := map[string]string{}
	for index, part := range strings.Split(observed, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return parsed, []diag.Diagnostic{newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"observed observation predicates must use key=value syntax.",
				"/observed_observation",
				map[string]any{"predicate": part, "index": index},
			)}
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if _, exists := fields[key]; exists {
			return parsed, []diag.Diagnostic{newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"observed observation contains a duplicate predicate.",
				"/observed_observation",
				map[string]any{"key": key, "index": index},
			)}
		}
		switch key {
		case "exit_code", "timed_out", "termination_reason", "stdout_digest", "stderr_digest", "start_error":
			if key == "start_error" {
				var err error
				value, err = unescapeObservationValue(value)
				if err != nil {
					return parsed, []diag.Diagnostic{newDiagnostic(
						CodeReceiptRelationshipMismatch,
						"observed start_error contains an invalid escape sequence.",
						"/observed_observation",
						map[string]any{"value": value, "index": index},
					)}
				}
			}
			fields[key] = value
		default:
			return parsed, []diag.Diagnostic{newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"observed observation contains an unsupported predicate.",
				"/observed_observation",
				map[string]any{"key": key, "index": index},
			)}
		}
	}
	var diagnostics []diag.Diagnostic
	exitCode, err := strconv.Atoi(fields["exit_code"])
	if err != nil {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed exit_code must be an integer.", "/observed_observation", map[string]any{"value": fields["exit_code"]}))
	}
	timedOut, ok := parseStrictObservationBool(fields["timed_out"])
	if !ok {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed timed_out must be true or false.", "/observed_observation", map[string]any{"value": fields["timed_out"]}))
	}
	stdoutDigest := fields["stdout_digest"]
	if !digestPattern.MatchString(stdoutDigest) {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed stdout_digest must be a sha256 digest.", "/observed_observation", map[string]any{"value": stdoutDigest}))
	}
	stderrDigest := fields["stderr_digest"]
	if !digestPattern.MatchString(stderrDigest) {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed stderr_digest must be a sha256 digest.", "/observed_observation", map[string]any{"value": stderrDigest}))
	}
	terminationReason := fields["termination_reason"]
	if terminationReason == "" {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed termination_reason is required.", "/observed_observation", nil))
	} else {
		switch terminationReason {
		case terminationCompleted, terminationTimeout, terminationCanceled, terminationExternalDeadline, terminationStartError:
		default:
			diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "observed termination_reason is not supported.", "/observed_observation", map[string]any{"termination_reason": terminationReason}))
		}
	}
	if timedOut && terminationReason != terminationTimeout {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "timed_out=true requires termination_reason=timeout.", "/observed_observation", map[string]any{"termination_reason": terminationReason}))
	}
	if !timedOut && terminationReason == terminationTimeout {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "termination_reason=timeout requires timed_out=true.", "/observed_observation", nil))
	}
	startError, hasStartError := fields["start_error"]
	if terminationReason == terminationStartError && startError == "" {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "termination_reason=start_error requires a non-empty start_error.", "/observed_observation", nil))
	}
	if terminationReason != terminationStartError && hasStartError {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "start_error is only allowed with termination_reason=start_error.", "/observed_observation", map[string]any{"termination_reason": terminationReason}))
	}
	if len(diagnostics) > 0 {
		return parsed, diagnostics
	}
	parsed.ExitCode = exitCode
	parsed.TimedOut = timedOut
	parsed.TerminationReason = terminationReason
	parsed.StdoutDigest = stdoutDigest
	parsed.StderrDigest = stderrDigest
	parsed.StartError = startError
	return parsed, nil
}

func resourceLimits(request RunRequest, requestDigest string, outcome commandOutcome, sourceBeforeDigest string, sourceAfterDigest string, workspaceBeforeDigest string, workspaceAfterDigest string) map[string]any {
	limits := map[string]any{}
	for key, value := range request.ResourceLimits {
		limits[key] = value
	}
	limits["timeout_ms"] = request.TimeoutMS
	limits["duration_ms"] = outcome.Duration.Milliseconds()
	limits["timed_out"] = outcome.TimedOut
	limits["canceled"] = outcome.Canceled
	if outcome.TerminationReason == "" {
		limits["termination_reason"] = terminationCompleted
	} else {
		limits["termination_reason"] = outcome.TerminationReason
	}
	limits["exit_code"] = outcome.ExitCode
	limits["request_digest"] = requestDigest
	limits["source_inventory_before_digest"] = sourceBeforeDigest
	limits["source_inventory_after_digest"] = sourceAfterDigest
	limits["workspace_inventory_before_digest"] = workspaceBeforeDigest
	limits["workspace_inventory_after_digest"] = workspaceAfterDigest
	if outcome.StartError != "" {
		limits["start_error"] = outcome.StartError
	}
	if outcome.WaitErr != nil {
		limits["wait_error"] = outcome.WaitErr.Error()
	}
	return limits
}

func verifyAuthentication(receipt contracts.ExecutionReceipt, key []byte) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if receipt.Authentication.Scheme != AuthenticationScheme {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeAuthenticationInvalid,
			"receipt authentication scheme is not supported.",
			"/authentication/scheme",
			map[string]any{"scheme": receipt.Authentication.Scheme},
		))
		return diagnostics
	}
	unsigned := receipt
	unsigned.Authentication.SignedDigest = ""
	unsigned.Authentication.Signature = ""
	signedDigest, err := contracts.ExecutionReceiptDigest(unsigned)
	if err != nil {
		diagnostics = append(diagnostics, newDiagnostic(CodeAuthenticationInvalid, "receipt signed payload digest could not be recomputed.", "/authentication/signed_digest", map[string]any{"error": err.Error()}))
		return diagnostics
	}
	if receipt.Authentication.SignedDigest != signedDigest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeAuthenticationInvalid,
			"receipt signed_digest does not match the unsigned receipt payload.",
			"/authentication/signed_digest",
			map[string]any{"got": receipt.Authentication.SignedDigest, "want": signedDigest},
		))
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signedDigest))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(receipt.Authentication.Signature), []byte(expectedSignature)) {
		diagnostics = append(diagnostics, newDiagnostic(CodeAuthenticationInvalid, "receipt HMAC signature is invalid.", "/authentication/signature", nil))
	}
	return diagnostics
}

type verifiedReceiptArtifacts struct {
	SourceBefore    Inventory
	SourceAfter     Inventory
	WorkspaceBefore Inventory
	WorkspaceAfter  Inventory
	Delta           WorkspaceDelta
	Stdout          []byte
	Stderr          []byte
}

func verifyReceiptArtifacts(outputDir string, receipt contracts.ExecutionReceipt) ([]diag.Diagnostic, []diag.Diagnostic) {
	if strings.TrimSpace(outputDir) == "" {
		return nil, []diag.Diagnostic{newDiagnostic(
			CodeReceiptUnavailable,
			"receipt verification requires access to the harness output directory and artifacts.",
			"/out_dir",
			nil,
		)}
	}
	artifactsRoot := filepath.Join(outputDir, "artifacts")
	info, err := os.Stat(artifactsRoot)
	if err != nil {
		return nil, []diag.Diagnostic{newDiagnostic(
			CodeReceiptUnavailable,
			"receipt artifact directory is unavailable.",
			"/out_dir",
			map[string]any{"path": artifactsRoot, "error": err.Error()},
		)}
	}
	if !info.IsDir() {
		return nil, []diag.Diagnostic{newDiagnostic(
			CodeReceiptUnavailable,
			"receipt artifact path is not a directory.",
			"/out_dir",
			map[string]any{"path": artifactsRoot},
		)}
	}

	var diagnostics []diag.Diagnostic
	var artifacts verifiedReceiptArtifacts
	var inventoryDiagnostics []diag.Diagnostic
	artifacts.SourceBefore, inventoryDiagnostics = loadInventoryArtifact(
		outputDir,
		receipt.SourceInventoryBefore,
		"source-snapshot",
		"/source_inventory_before",
	)
	diagnostics = append(diagnostics, inventoryDiagnostics...)
	artifacts.SourceAfter, inventoryDiagnostics = loadInventoryArtifact(
		outputDir,
		receipt.SourceInventoryAfter,
		"source-snapshot",
		"/source_inventory_after",
	)
	diagnostics = append(diagnostics, inventoryDiagnostics...)
	artifacts.WorkspaceBefore, inventoryDiagnostics = loadInventoryArtifact(
		outputDir,
		receipt.WorkspaceInventoryBefore,
		"execution-workspace",
		"/workspace_inventory_before",
	)
	diagnostics = append(diagnostics, inventoryDiagnostics...)
	artifacts.WorkspaceAfter, inventoryDiagnostics = loadInventoryArtifact(
		outputDir,
		receipt.WorkspaceInventoryAfter,
		"execution-workspace",
		"/workspace_inventory_after",
	)
	diagnostics = append(diagnostics, inventoryDiagnostics...)

	if receipt.Captures.Stdout == nil {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt must reference captured stdout.", "/captures/stdout", nil))
	} else {
		var stdoutDiagnostics []diag.Diagnostic
		artifacts.Stdout, stdoutDiagnostics = readAndVerifyArtifact(outputDir, *receipt.Captures.Stdout, "/captures/stdout")
		diagnostics = append(diagnostics, stdoutDiagnostics...)
	}
	if receipt.Captures.Stderr == nil {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt must reference captured stderr.", "/captures/stderr", nil))
	} else {
		var stderrDiagnostics []diag.Diagnostic
		artifacts.Stderr, stderrDiagnostics = readAndVerifyArtifact(outputDir, *receipt.Captures.Stderr, "/captures/stderr")
		diagnostics = append(diagnostics, stderrDiagnostics...)
	}

	deltaCount := 0
	for index, ref := range receipt.Captures.ProducedArtifacts {
		path := "/captures/produced_artifacts/" + strconv.Itoa(index)
		isDelta := ref.Kind == "workspace-mutation-report"
		if isDelta {
			deltaCount++
		}
		data, artifactDiagnostics := readAndVerifyArtifact(outputDir, ref, path)
		diagnostics = append(diagnostics, artifactDiagnostics...)
		if len(artifactDiagnostics) > 0 {
			continue
		}
		if !isDelta {
			continue
		}
		delta, deltaDiagnostics := decodeArtifactJSON[WorkspaceDelta](data, path, "workspace mutation report")
		diagnostics = append(diagnostics, deltaDiagnostics...)
		diagnostics = append(diagnostics, validateWorkspaceDelta(delta, path)...)
		artifacts.Delta = delta
	}
	if deltaCount == 0 {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt must include a workspace mutation report artifact.", "/captures/produced_artifacts", nil))
	}
	if deltaCount > 1 {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt must include exactly one workspace mutation report artifact.", "/captures/produced_artifacts", map[string]any{"count": deltaCount}))
	}
	if len(diagnostics) > 0 {
		invalidDiagnostics, unavailableDiagnostics := partitionUnavailableDiagnostics(diagnostics)
		return invalidDiagnostics, unavailableDiagnostics
	}
	diagnostics = append(diagnostics, verifyReceiptArtifactRelationships(receipt, artifacts)...)
	return diagnostics, nil
}

func loadInventoryArtifact(outputDir string, ref contracts.ArtifactRef, wantKind string, path string) (Inventory, []diag.Diagnostic) {
	data, artifactDiagnostics := readAndVerifyArtifact(outputDir, ref, path)
	if len(artifactDiagnostics) > 0 {
		return Inventory{}, artifactDiagnostics
	}
	inventory, decodeDiagnostics := decodeArtifactJSON[Inventory](data, path, "inventory")
	if len(decodeDiagnostics) > 0 {
		return Inventory{}, decodeDiagnostics
	}
	diagnostics := validateInventory(inventory, wantKind, path)
	return inventory, diagnostics
}

func readAndVerifyArtifact(outputDir string, ref contracts.ArtifactRef, path string) ([]byte, []diag.Diagnostic) {
	artifactPath, err := ArtifactPath(outputDir, ref)
	if err != nil {
		diagnostic := diag.FromError(err)
		if diagnostic.Path == "" {
			diagnostic.Path = path
		}
		return nil, []diag.Diagnostic{diagnostic}
	}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, []diag.Diagnostic{newDiagnostic(
			CodeReceiptUnavailable,
			"receipt artifact could not be read.",
			path,
			map[string]any{"id": ref.ID, "kind": ref.Kind, "artifact_path": artifactPath, "error": err.Error()},
		)}
	}
	actual := digest.RawBytes(data)
	if actual != ref.Digest {
		return nil, []diag.Diagnostic{newDiagnostic(
			CodeArtifactDigestMismatch,
			"receipt artifact digest does not match its stored bytes.",
			path,
			map[string]any{"id": ref.ID, "kind": ref.Kind, "got": actual, "want": ref.Digest},
		)}
	}
	return data, nil
}

func partitionUnavailableDiagnostics(diagnostics []diag.Diagnostic) ([]diag.Diagnostic, []diag.Diagnostic) {
	var invalidDiagnostics []diag.Diagnostic
	var unavailableDiagnostics []diag.Diagnostic
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeReceiptUnavailable {
			unavailableDiagnostics = append(unavailableDiagnostics, diagnostic)
			continue
		}
		invalidDiagnostics = append(invalidDiagnostics, diagnostic)
	}
	return invalidDiagnostics, unavailableDiagnostics
}

func decodeArtifactJSON[T any](data []byte, path string, label string) (T, []diag.Diagnostic) {
	value, err := strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes)
	if err != nil {
		var zero T
		return zero, []diag.Diagnostic{newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"receipt "+label+" artifact is not valid strict JSON.",
			path,
			map[string]any{"error": err.Error()},
		)}
	}
	return value, nil
}

func verifyReceiptArtifactRelationships(receipt contracts.ExecutionReceipt, artifacts verifiedReceiptArtifacts) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if !inventoryEntriesEqual(artifacts.SourceBefore.Files, artifacts.SourceAfter.Files, true) {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"source inventories before and after execution must match.",
			"/source_inventory_after",
			nil,
		))
	}
	if !inventoryEntriesEqual(artifacts.SourceBefore.Files, artifacts.WorkspaceBefore.Files, false) {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace inventory before execution must match the frozen source inventory files.",
			"/workspace_inventory_before",
			nil,
		))
	}
	if receipt.ResultWorkspaceDigest == "" {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt result_workspace_digest is required.", "/result_workspace_digest", nil))
	} else if receipt.ResultWorkspaceDigest != receipt.WorkspaceInventoryAfter.Digest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"result_workspace_digest must match workspace_inventory_after digest.",
			"/result_workspace_digest",
			map[string]any{"got": receipt.ResultWorkspaceDigest, "want": receipt.WorkspaceInventoryAfter.Digest},
		))
	}
	if artifacts.Delta.BeforeDigest != receipt.WorkspaceInventoryBefore.Digest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta before_digest must match workspace_inventory_before digest.",
			"/captures/produced_artifacts",
			map[string]any{"got": artifacts.Delta.BeforeDigest, "want": receipt.WorkspaceInventoryBefore.Digest},
		))
	}
	if artifacts.Delta.AfterDigest != receipt.WorkspaceInventoryAfter.Digest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta after_digest must match workspace_inventory_after digest.",
			"/captures/produced_artifacts",
			map[string]any{"got": artifacts.Delta.AfterDigest, "want": receipt.WorkspaceInventoryAfter.Digest},
		))
	}
	expectedDelta := DiffInventories(artifacts.WorkspaceBefore, artifacts.WorkspaceAfter, receipt.WorkspaceInventoryBefore.Digest, receipt.WorkspaceInventoryAfter.Digest)
	expectedDeltaDigest, err := digest.SemanticJSON(expectedDelta)
	if err != nil {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "workspace delta could not be recomputed.", "/captures/produced_artifacts", map[string]any{"error": err.Error()}))
	} else {
		actualDeltaDigest, err := digest.SemanticJSON(artifacts.Delta)
		if err != nil {
			diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "workspace delta artifact could not be canonicalized.", "/captures/produced_artifacts", map[string]any{"error": err.Error()}))
		} else if actualDeltaDigest != expectedDeltaDigest {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"workspace delta artifact does not match recomputed inventory delta.",
				"/captures/produced_artifacts",
				map[string]any{"got": actualDeltaDigest, "want": expectedDeltaDigest},
			))
		}
	}
	diagnostics = append(diagnostics, verifyProducedWorkspaceArtifactRefs(receipt, artifacts.Delta, artifacts.WorkspaceAfter)...)
	diagnostics = append(diagnostics, verifyObservedRelationships(receipt, artifacts.Stdout, artifacts.Stderr)...)
	return diagnostics
}

func validateInventory(inventory Inventory, wantKind string, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if inventory.SchemaVersion != InventorySchema {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"inventory schema_version is not supported.",
			path+"/schema_version",
			map[string]any{"got": inventory.SchemaVersion, "want": InventorySchema},
		))
	}
	if inventory.Kind != wantKind {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"inventory kind does not match the receipt field.",
			path+"/kind",
			map[string]any{"got": inventory.Kind, "want": wantKind},
		))
	}
	if inventory.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"inventory digest_profile is not supported.",
			path+"/digest_profile",
			map[string]any{"got": inventory.DigestProfile, "want": digest.Profile},
		))
	}
	seen := map[string]bool{}
	for index, entry := range inventory.Files {
		entryPath := path + "/files/" + strconv.Itoa(index)
		if err := validateRelativePath(entry.Path); err != nil {
			diagnostic := diag.FromError(err)
			diagnostic.Path = entryPath + "/path"
			diagnostics = append(diagnostics, diagnostic)
		}
		if seen[entry.Path] {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"inventory contains duplicate path entries.",
				entryPath+"/path",
				map[string]any{"path": entry.Path},
			))
		}
		seen[entry.Path] = true
		if strings.TrimSpace(entry.Mode) == "" {
			diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "inventory entry mode is required.", entryPath+"/mode", nil))
		}
		if entry.Dir {
			if !strings.HasPrefix(entry.Mode, "04") {
				diagnostics = append(diagnostics, newDiagnostic(
					CodeReceiptRelationshipMismatch,
					"directory inventory entry mode must use a directory mode.",
					entryPath+"/mode",
					map[string]any{"mode": entry.Mode},
				))
			}
			if entry.Digest != "" {
				diagnostics = append(diagnostics, newDiagnostic(
					CodeReceiptRelationshipMismatch,
					"directory inventory entries must not carry content digests.",
					entryPath+"/digest",
					map[string]any{"digest": entry.Digest},
				))
			}
			continue
		}
		if strings.HasPrefix(entry.Mode, "04") {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"non-directory inventory entry must not use a directory mode.",
				entryPath+"/mode",
				map[string]any{"mode": entry.Mode},
			))
		}
		if !digestPattern.MatchString(entry.Digest) {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"non-directory inventory entry digest must be a sha256 digest.",
				entryPath+"/digest",
				map[string]any{"digest": entry.Digest},
			))
		}
	}
	return diagnostics
}

func validateWorkspaceDelta(delta WorkspaceDelta, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if delta.SchemaVersion != DeltaSchema {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta schema_version is not supported.",
			path+"/schema_version",
			map[string]any{"got": delta.SchemaVersion, "want": DeltaSchema},
		))
	}
	if delta.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta digest_profile is not supported.",
			path+"/digest_profile",
			map[string]any{"got": delta.DigestProfile, "want": digest.Profile},
		))
	}
	if !digestPattern.MatchString(delta.BeforeDigest) {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "workspace delta before_digest must be a sha256 digest.", path+"/before_digest", map[string]any{"digest": delta.BeforeDigest}))
	}
	if !digestPattern.MatchString(delta.AfterDigest) {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "workspace delta after_digest must be a sha256 digest.", path+"/after_digest", map[string]any{"digest": delta.AfterDigest}))
	}
	diagnostics = append(diagnostics, validateWorkspaceDeltaEntries(delta.Added, path+"/added", true, false)...)
	diagnostics = append(diagnostics, validateWorkspaceDeltaEntries(delta.Removed, path+"/removed", false, true)...)
	diagnostics = append(diagnostics, validateWorkspaceDeltaEntries(delta.Modified, path+"/modified", true, true)...)
	return diagnostics
}

func validateWorkspaceDeltaEntries(entries []WorkspaceDeltaEntry, path string, hasAfter bool, hasBefore bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for index, entry := range entries {
		entryPath := path + "/" + strconv.Itoa(index)
		if err := validateRelativePath(entry.Path); err != nil {
			diagnostic := diag.FromError(err)
			diagnostic.Path = entryPath + "/path"
			diagnostics = append(diagnostics, diagnostic)
		}
		if hasBefore {
			diagnostics = append(diagnostics, validateWorkspaceDeltaSide(entry.BeforeDir, entry.BeforeMode, entry.BeforeDigest, entryPath, "before")...)
		}
		if hasAfter {
			diagnostics = append(diagnostics, validateWorkspaceDeltaSide(entry.AfterDir, entry.AfterMode, entry.AfterDigest, entryPath, "after")...)
		}
	}
	return diagnostics
}

func validateWorkspaceDeltaSide(dir bool, mode string, entryDigest string, path string, side string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if strings.TrimSpace(mode) == "" {
		diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "workspace delta "+side+"_mode is required.", path+"/"+side+"_mode", nil))
	}
	if dir {
		if !strings.HasPrefix(mode, "04") {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"workspace delta directory mode must use a directory mode.",
				path+"/"+side+"_mode",
				map[string]any{"mode": mode},
			))
		}
		if entryDigest != "" {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"workspace delta directory entries must not carry content digests.",
				path+"/"+side+"_digest",
				map[string]any{"digest": entryDigest},
			))
		}
		return diagnostics
	}
	if strings.HasPrefix(mode, "04") {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta non-directory mode must not use a directory mode.",
			path+"/"+side+"_mode",
			map[string]any{"mode": mode},
		))
	}
	if !digestPattern.MatchString(entryDigest) {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"workspace delta non-directory digest must be a sha256 digest.",
			path+"/"+side+"_digest",
			map[string]any{"digest": entryDigest},
		))
	}
	return diagnostics
}

func inventoryEntriesEqual(left []InventoryFile, right []InventoryFile, includeDirs bool) bool {
	leftByPath := inventoryEntryMap(left, includeDirs)
	rightByPath := inventoryEntryMap(right, includeDirs)
	if len(leftByPath) != len(rightByPath) {
		return false
	}
	for path, leftEntry := range leftByPath {
		rightEntry, exists := rightByPath[path]
		if !exists {
			return false
		}
		if leftEntry.Mode != rightEntry.Mode || leftEntry.Dir != rightEntry.Dir || leftEntry.Digest != rightEntry.Digest {
			return false
		}
	}
	return true
}

func inventoryEntryMap(entries []InventoryFile, includeDirs bool) map[string]InventoryFile {
	byPath := map[string]InventoryFile{}
	for _, entry := range entries {
		if entry.Dir && !includeDirs {
			continue
		}
		byPath[entry.Path] = entry
	}
	return byPath
}

func verifyProducedWorkspaceArtifactRefs(receipt contracts.ExecutionReceipt, delta WorkspaceDelta, after Inventory) []diag.Diagnostic {
	afterByPath := map[string]InventoryFile{}
	for _, entry := range after.Files {
		afterByPath[entry.Path] = entry
	}
	expected := map[string]string{}
	for _, entry := range delta.Added {
		addExpectedWorkspaceArtifact(expected, afterByPath, entry.Path)
	}
	for _, entry := range delta.Modified {
		addExpectedWorkspaceArtifact(expected, afterByPath, entry.Path)
	}

	actual := map[string]bool{}
	var diagnostics []diag.Diagnostic
	for index, ref := range receipt.Captures.ProducedArtifacts {
		if ref.Kind != "execution-artifact" {
			continue
		}
		key := producedWorkspaceArtifactKey(ref.ID, ref.Digest)
		path := "/captures/produced_artifacts/" + strconv.Itoa(index)
		if actual[key] {
			diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt contains duplicate produced workspace artifact.", path, map[string]any{"id": ref.ID, "digest": ref.Digest}))
		}
		actual[key] = true
		if _, exists := expected[key]; !exists {
			diagnostics = append(diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt contains a produced workspace artifact not present in the workspace delta.", path, map[string]any{"id": ref.ID, "digest": ref.Digest}))
		}
	}
	for key, rel := range expected {
		if !actual[key] {
			diagnostics = append(diagnostics, newDiagnostic(
				CodeReceiptRelationshipMismatch,
				"receipt is missing a produced workspace artifact for a mutated file.",
				"/captures/produced_artifacts",
				map[string]any{"path": rel},
			))
		}
	}
	return diagnostics
}

func addExpectedWorkspaceArtifact(expected map[string]string, afterByPath map[string]InventoryFile, rel string) {
	entry, exists := afterByPath[rel]
	if !exists || entry.Dir || entry.Mode == "120000" {
		return
	}
	id := stableGeneratedID("workspace-artifact", rel)
	expected[producedWorkspaceArtifactKey(id, entry.Digest)] = rel
}

func producedWorkspaceArtifactKey(id string, artifactDigest string) string {
	return id + "\x00" + artifactDigest
}

func verifyObservedRelationships(receipt contracts.ExecutionReceipt, stdout []byte, stderr []byte) []diag.Diagnostic {
	observed, diagnostics := parseObservedObservation(receipt.ObservedObservation)
	if len(diagnostics) > 0 {
		return diagnostics
	}
	stdoutDigest := digest.RawBytes(stdout)
	stderrDigest := digest.RawBytes(stderr)
	if observed.StdoutDigest != stdoutDigest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"observed stdout_digest must match captured stdout bytes.",
			"/observed_observation",
			map[string]any{"got": observed.StdoutDigest, "want": stdoutDigest},
		))
	}
	if observed.StderrDigest != stderrDigest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"observed stderr_digest must match captured stderr bytes.",
			"/observed_observation",
			map[string]any{"got": observed.StderrDigest, "want": stderrDigest},
		))
	}
	if receipt.Captures.Stdout != nil && observed.StdoutDigest != receipt.Captures.Stdout.Digest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"observed stdout_digest must match the stdout artifact ref.",
			"/observed_observation",
			map[string]any{"got": observed.StdoutDigest, "want": receipt.Captures.Stdout.Digest},
		))
	}
	if receipt.Captures.Stderr != nil && observed.StderrDigest != receipt.Captures.Stderr.Digest {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"observed stderr_digest must match the stderr artifact ref.",
			"/observed_observation",
			map[string]any{"got": observed.StderrDigest, "want": receipt.Captures.Stderr.Digest},
		))
	}
	recomputedStatus := classifyObservedExecution(receipt.ExpectedObservation, observed, stdout, stderr)
	if recomputedStatus != receipt.ExecutionStatus {
		diagnostics = append(diagnostics, newDiagnostic(
			CodeReceiptRelationshipMismatch,
			"receipt execution_status does not match the expected observation evaluated against observed outputs.",
			"/execution_status",
			map[string]any{"got": receipt.ExecutionStatus, "want": recomputedStatus},
		))
	}
	diagnostics = append(diagnostics, verifyResourceLimitRelationships(receipt, observed)...)
	return diagnostics
}

func verifyResourceLimitRelationships(receipt contracts.ExecutionReceipt, observed parsedObservedObservation) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "source_inventory_before_digest", receipt.SourceInventoryBefore.Digest)
	verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "source_inventory_after_digest", receipt.SourceInventoryAfter.Digest)
	verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "workspace_inventory_before_digest", receipt.WorkspaceInventoryBefore.Digest)
	verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "workspace_inventory_after_digest", receipt.WorkspaceInventoryAfter.Digest)
	verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "termination_reason", observed.TerminationReason)
	verifyResourceLimitBool(&diagnostics, receipt.ResourceLimits, "timed_out", observed.TimedOut)
	verifyResourceLimitBool(&diagnostics, receipt.ResourceLimits, "canceled", observed.TerminationReason == terminationCanceled || observed.TerminationReason == terminationExternalDeadline)
	verifyResourceLimitInt(&diagnostics, receipt.ResourceLimits, "exit_code", observed.ExitCode)
	if observed.TerminationReason == terminationStartError {
		verifyResourceLimitString(&diagnostics, receipt.ResourceLimits, "start_error", observed.StartError)
	}
	return diagnostics
}

func verifyResourceLimitString(diagnostics *[]diag.Diagnostic, limits map[string]any, key string, want string) {
	value, ok := limits[key]
	if !ok {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit is missing.", "/resource_limits/"+key, nil))
		return
	}
	got, ok := value.(string)
	if !ok || got != want {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit does not match signed receipt fields.", "/resource_limits/"+key, map[string]any{"got": value, "want": want}))
	}
}

func verifyResourceLimitBool(diagnostics *[]diag.Diagnostic, limits map[string]any, key string, want bool) {
	value, ok := limits[key]
	if !ok {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit is missing.", "/resource_limits/"+key, nil))
		return
	}
	got, ok := value.(bool)
	if !ok || got != want {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit does not match signed receipt fields.", "/resource_limits/"+key, map[string]any{"got": value, "want": want}))
	}
}

func verifyResourceLimitInt(diagnostics *[]diag.Diagnostic, limits map[string]any, key string, want int) {
	value, ok := limits[key]
	if !ok {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit is missing.", "/resource_limits/"+key, nil))
		return
	}
	got, ok := intValue(value)
	if !ok || got != want {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeReceiptRelationshipMismatch, "receipt resource limit does not match signed receipt fields.", "/resource_limits/"+key, map[string]any{"got": value, "want": want}))
	}
}

func intValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case float64:
		truncated := int(typed)
		return truncated, float64(truncated) == typed
	case string:
		parsed, err := strconv.Atoi(typed)
		return parsed, err == nil
	default:
		parsed, err := strconv.Atoi(fmt.Sprint(typed))
		return parsed, err == nil
	}
}

func artifactRefPointersEqual(left *contracts.ArtifactRef, right *contracts.ArtifactRef) bool {
	if left == nil || right == nil {
		return left == right
	}
	return artifactRefsEqual(*left, *right)
}

func artifactRefsEqual(left contracts.ArtifactRef, right contracts.ArtifactRef) bool {
	return left.Kind == right.Kind &&
		left.ID == right.ID &&
		left.Digest == right.Digest &&
		left.DigestProfile == right.DigestProfile &&
		left.MediaType == right.MediaType
}

func artifactNamespace(kind string) string {
	switch kind {
	case "execution-stdout":
		return "stdout"
	case "execution-stderr":
		return "stderr"
	case "execution-inventory", "workspace-mutation-report":
		return "inventory"
	case "execution-artifact":
		return "workspace"
	case "harness-request":
		return "request"
	default:
		return ""
	}
}

func harnessIdentity() contracts.HarnessIdentity {
	return contracts.HarnessIdentity{
		ID:          "witness-harness",
		Version:     Version,
		BuildDigest: executableDigest(),
	}
}

func executableDigest() string {
	path, err := os.Executable()
	if err == nil {
		if data, readErr := os.ReadFile(path); readErr == nil {
			return digest.RawBytes(data)
		}
	}
	return digest.RawBytes([]byte(Version))
}

func normalizedIssuer(issuer contracts.ReceiptIssuer) contracts.ReceiptIssuer {
	if strings.TrimSpace(issuer.ID) == "" {
		issuer.ID = "local-harness"
	}
	if strings.TrimSpace(issuer.Actor) == "" {
		issuer.Actor = "witness-harness"
	}
	if strings.TrimSpace(issuer.Method) == "" {
		issuer.Method = "hmac-sha256-key-file"
	}
	return issuer
}

func normalizedFrozenSourceRef(ref contracts.ArtifactRef, sourceDigest string) contracts.ArtifactRef {
	if ref.Kind == "" {
		ref.Kind = "source-snapshot-manifest"
	}
	if ref.ID == "" {
		ref.ID = "source-snapshot"
	}
	ref.Digest = sourceDigest
	if ref.DigestProfile == "" {
		ref.DigestProfile = digest.Profile
	}
	if ref.MediaType == "" {
		ref.MediaType = "application/json"
	}
	return ref
}

func containmentReport() contracts.ContainmentReport {
	return contracts.ContainmentReport{
		Filesystem: "ephemeral workspace restored from the frozen source snapshot; receipt artifacts are written outside that workspace",
		Network:    "no network isolation is provided by this host harness",
		Process:    "command launched directly from structured argv with no shell; environment is restricted to the request allowlist; timeout uses process-group SIGKILL without kernel or container isolation",
		Notes:      "Containment is an execution record, not a stronger sandbox claim.",
	}
}

func receiptID(request RunRequest, requestDigest string, observed string, workspaceDigest string) string {
	raw := strings.Join([]string{request.FindingID, requestDigest, observed, workspaceDigest, strconv.FormatInt(time.Now().UnixNano(), 10)}, "|")
	sum := digest.RawBytes([]byte(raw))
	return "receipt-" + strings.TrimPrefix(sum, digest.Prefix)[:16]
}

func validateExecutable(diagnostics *[]diag.Diagnostic, spec contracts.ExecutableSpec) {
	if len(spec.Argv) == 0 {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "command.argv requires a program and optional arguments.", "/command/argv", nil))
		return
	}
	for index, item := range spec.Argv {
		if strings.TrimSpace(item) == "" || strings.Contains(item, "\x00") {
			*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "command.argv entries must be non-empty strings without NUL bytes.", "/command/argv/"+strconv.Itoa(index), nil))
		}
	}
	program := filepath.Base(spec.Argv[0])
	if isShellProgram(program) {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeShellForbidden, "witness-harness run does not execute shell interpreters.", "/command/argv/0", map[string]any{"program": spec.Argv[0]}))
	}
	if !strings.Contains(spec.Argv[0], string(filepath.Separator)) && !strings.Contains(spec.Argv[0], "/") {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "command.argv[0] must be an absolute path or a workspace-relative path containing a path separator; PATH lookup is not used.", "/command/argv/0", map[string]any{"program": spec.Argv[0]}))
	}
	if _, err := cleanWorkspaceRelativePath(spec.CWD); err != nil {
		*diagnostics = append(*diagnostics, diag.FromError(err))
	}
	requireString(diagnostics, "/command/expected_observation", "expected observation", spec.ExpectedObservation)
	if strings.TrimSpace(spec.ExpectedObservation) != "" {
		_, expectationDiagnostics := parseExpectedObservation(spec.ExpectedObservation, "/command/expected_observation")
		*diagnostics = append(*diagnostics, expectationDiagnostics...)
	}
}

func isShellProgram(program string) bool {
	switch strings.ToLower(program) {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "powershell", "pwsh", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

func validateEnvironment(diagnostics *[]diag.Diagnostic, env map[string]string) {
	for key, value := range env {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "environment keys must be non-empty names without '=' or NUL bytes.", "/environment", map[string]any{"key": key}))
		}
		if strings.Contains(value, "\x00") {
			*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "environment values must not contain NUL bytes.", "/environment/"+key, nil))
		}
	}
}

func validateArtifactRef(diagnostics *[]diag.Diagnostic, path string, ref contracts.ArtifactRef) {
	requireString(diagnostics, path+"/kind", "artifact reference kind", ref.Kind)
	requireStableID(diagnostics, path+"/id", "artifact reference ID", ref.ID)
	requireDigest(diagnostics, path+"/digest", "artifact reference digest", ref.Digest)
	if ref.DigestProfile != "" && ref.DigestProfile != digest.Profile {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, "artifact reference digest_profile must be relay-root-digests-v1 when present.", path+"/digest_profile", map[string]any{"digest_profile": ref.DigestProfile}))
	}
}

func requireString(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if strings.TrimSpace(value) == "" {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, label+" is required.", path, nil))
	}
}

func requireStableID(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if !stableIDPattern.MatchString(value) {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, label+" must be a stable ID.", path, map[string]any{"value": value}))
	}
}

func requireDigest(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if !digestPattern.MatchString(value) {
		*diagnostics = append(*diagnostics, newDiagnostic(CodeInvalidRequest, label+" must be a sha256 digest.", path, map[string]any{"value": value}))
	}
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return diag.New(CodeUnsafePath, "path must be a non-empty relative path.", diag.WithDetail("path", path))
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean != path {
		return diag.New(CodeUnsafePath, "path must be clean and relative.", diag.WithDetail("path", path), diag.WithDetail("clean", clean))
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return diag.New(CodeUnsafePath, "path must not contain empty, current, or parent segments.", diag.WithDetail("path", path))
		}
	}
	return nil
}

func cleanWorkspaceRelativePath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return "", diag.New(CodeUnsafePath, "command.cwd must be a relative workspace path.", diag.WithPath("/command/cwd"), diag.WithDetail("cwd", path))
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", diag.New(CodeUnsafePath, "command.cwd must not escape the ephemeral workspace.", diag.WithPath("/command/cwd"), diag.WithDetail("cwd", path))
	}
	return clean, nil
}

func environmentList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+env[key])
	}
	return values
}

func sortedEnvironmentMap(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	sorted := map[string]string{}
	for _, key := range sortedKeys(env) {
		sorted[key] = env[key]
	}
	return sorted
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stableGeneratedID(prefix string, value string) string {
	sum := digest.RawBytes([]byte(value))
	return prefix + "-" + strings.TrimPrefix(sum, digest.Prefix)[:16]
}

func outputInsideWorkspace(workspaceDir string, outputDir string) bool {
	rel, err := filepath.Rel(workspaceDir, outputDir)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel))
}

func rejectExistingSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return diag.New(CodeUnsafeOutputPath, "output path must not be a symlink.", diag.WithDetail("path", path))
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	}
	var missing []string
	current := absolute
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return absolute, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
	}
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	var buffer bytes.Buffer
	read, err := buffer.ReadFrom(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if read > limit {
		return nil, diag.New(
			diag.CodeJSONTooLarge,
			"JSON input exceeds the configured size limit.",
			diag.WithDetail("limit_bytes", limit),
			diag.WithDetail("size_bytes", read),
		)
	}
	return buffer.Bytes(), nil
}

func newDiagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Message: message, Path: path, Details: details}
}
