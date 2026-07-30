package relayrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/planning"
	"witness/internal/portable"
	"witness/internal/relayclient"
	"witness/internal/strictjson"
)

const (
	SchemaVersion         = "witness-relay-verification-runs-v1"
	RunRecordSchema       = "witness-relay-verification-run-v1"
	CodeMissingBatchPath  = "relayrun_missing_batch_path"
	CodeRelayRunFailed    = "relayrun_launch_failed"
	CodeRelayExportFailed = "relayrun_export_failed"
	CodeRelayVerifyFailed = "relayrun_producer_verify_failed"
	CodePortableInvalid   = "relayrun_portable_invalid"
	CodeOutputFailed      = "relayrun_output_failed"
	CodeInvalidBatchInput = "relayrun_invalid_batch_input"
)

type Options struct {
	RelayPath             string
	IntegrationBundlePath string
	CharterPath           string
	ArtifactPaths         []string
	OutputDir             string
	Backend               string
	WorkspaceIsolation    string
	RelayHome             string
	LaunchCWD             string
	SettingsPath          string
	AllowDirtySource      bool
	Runner                relayclient.Runner
}

type BatchInput struct {
	Plan     planning.BatchPlan
	Document contracts.VerificationBatchDocument
	Path     string
	RawBytes []byte
}

type Result struct {
	SchemaVersion string      `json:"schema_version"`
	Runs          []RunRecord `json:"runs"`
}

type RunRecord struct {
	SchemaVersion        string            `json:"schema_version"`
	BatchID              string            `json:"batch_id"`
	Status               string            `json:"status"`
	RecipeID             string            `json:"recipe_id"`
	InputBindings        []string          `json:"input_bindings"`
	SessionDir           string            `json:"session_dir,omitempty"`
	PortableExportDir    string            `json:"portable_export_dir,omitempty"`
	PortableExportDigest string            `json:"portable_export_digest,omitempty"`
	RelayRunResult       map[string]any    `json:"relay_run_result,omitempty"`
	ProducerCheck        map[string]any    `json:"producer_check,omitempty"`
	WitnessCheck         *portable.Report  `json:"witness_check,omitempty"`
	Diagnostics          []diag.Diagnostic `json:"diagnostics,omitempty"`
}

func RunBatches(ctx context.Context, batches []BatchInput, options Options) (*Result, error) {
	client := relayclient.Client{Executable: options.RelayPath, Runner: options.Runner}
	result := &Result{SchemaVersion: SchemaVersion}
	for _, batch := range batches {
		record := RunRecord{
			SchemaVersion: RunRecordSchema,
			BatchID:       batch.Plan.BatchID,
			RecipeID:      RecipeID(batch.Plan.TaskShape, options.Backend),
			Status:        contracts.RecordStatusUnavailable,
		}
		if strings.TrimSpace(batch.Path) == "" {
			record.Diagnostics = append(record.Diagnostics, diag.FromError(diag.New(CodeMissingBatchPath, "relay verification requires a persisted verification-batch path.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		if diagnostics := validatePreLaunchBatchInput(batch, options); len(diagnostics) > 0 {
			record.Diagnostics = append(record.Diagnostics, diagnostics...)
			result.Runs = append(result.Runs, record)
			continue
		}
		record.InputBindings = inputBindings(options.CharterPath, batch.Path, options.ArtifactPaths)
		runResult, err := client.RunRecipe(ctx, relayclient.RunRecipeOptions{
			Task:                  relayTask(batch),
			RecipeID:              record.RecipeID,
			IntegrationBundlePath: options.IntegrationBundlePath,
			InputBindings:         record.InputBindings,
			WorkspaceIsolation:    defaultWorkspaceIsolation(options.WorkspaceIsolation),
			RelayHome:             options.RelayHome,
			LaunchCWD:             options.LaunchCWD,
			SettingsPath:          options.SettingsPath,
			AllowDirtySource:      options.AllowDirtySource,
		})
		if err != nil {
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(CodeRelayRunFailed, "relay verification run failed.", err))
			result.Runs = append(result.Runs, record)
			continue
		}
		record.RelayRunResult = runResult
		record.SessionDir = firstString(runResult, "session_dir", "session_directory", "directory")
		if record.SessionDir == "" {
			record.Diagnostics = append(record.Diagnostics, diag.FromError(diag.New(CodeRelayRunFailed, "relay run result did not include a session_dir.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		if options.OutputDir == "" {
			record.Diagnostics = append(record.Diagnostics, diag.FromError(diag.New(CodeRelayExportFailed, "relayrun requires an output directory for portable exports.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		exportDir := filepath.Join(options.OutputDir, "verification", "exports", batch.Plan.BatchID)
		record.PortableExportDir = exportDir
		exportResult, err := client.ExportPortable(ctx, relayclient.ExportOptions{SessionDir: record.SessionDir, RelayHome: options.RelayHome, OutputDir: exportDir})
		if err != nil {
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(CodeRelayExportFailed, "relay portable export failed.", err))
			result.Runs = append(result.Runs, record)
			continue
		}
		record.PortableExportDigest = stringValue(exportResult["manifest_digest"])
		producerCheck, err := client.VerifyExport(ctx, exportDir)
		if err != nil {
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(CodeRelayVerifyFailed, "relay producer-side verify-export failed.", err))
		} else {
			record.ProducerCheck = producerCheck
		}
		witnessCheck, err := portable.VerifyDirectory(exportDir)
		record.WitnessCheck = witnessCheck
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.Diagnostics = append(record.Diagnostics, diag.FromError(diag.Wrap(err, CodePortableInvalid, "Witness portable export validation failed.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
		} else {
			record.Status = contracts.RecordStatusValid
			record.PortableExportDigest = witnessCheck.ManifestDigest
		}
		result.Runs = append(result.Runs, record)
	}
	if options.OutputDir != "" {
		if err := writeCanonical(filepath.Join(options.OutputDir, "verification", "runs", "index.json"), result); err != nil {
			return result, err
		}
		for _, record := range result.Runs {
			if err := writeCanonical(filepath.Join(options.OutputDir, "verification", "runs", record.BatchID+".json"), record); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func validatePreLaunchBatchInput(batch BatchInput, options Options) []diag.Diagnostic {
	data, err := os.ReadFile(batch.Path)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification batch input could not be read before launch.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", batch.Path)))}
	}
	var diagnostics []diag.Diagnostic
	actualDigest := digest.RawBytes(data)
	if strings.TrimSpace(batch.Plan.BatchDigest) == "" {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification batch input requires a planned batch digest.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("path", batch.Path),
		))}
	}
	if actualDigest != batch.Plan.BatchDigest {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification batch file digest does not match the planned batch digest.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("path", batch.Path),
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", batch.Plan.BatchDigest),
		))}
	}
	if len(batch.RawBytes) > 0 {
		rawDigest := digest.RawBytes(batch.RawBytes)
		if actualDigest != rawDigest {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidBatchInput,
				"relay verification batch file digest does not match the loaded batch bytes.",
				diag.WithDetail("batch_id", batch.Plan.BatchID),
				diag.WithDetail("path", batch.Path),
				diag.WithDetail("actual_digest", actualDigest),
				diag.WithDetail("expected_digest", rawDigest),
			)))
		}
	}
	diagnostics = append(diagnostics, validatePreLaunchBatchDocument(batch)...)
	diagnostics = append(diagnostics, validatePreLaunchCharter(batch, options.CharterPath)...)
	diagnostics = append(diagnostics, validatePreLaunchArtifacts(batch, options.ArtifactPaths)...)
	diagnostics = append(diagnostics, validatePreLaunchIntegrationBundle(batch, options.IntegrationBundlePath)...)
	return diagnostics
}

func validatePreLaunchBatchDocument(batch BatchInput) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if expected := strings.TrimSpace(batch.Plan.CharterHash); expected != "" && batch.Document.CharterHash != expected {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification batch document charter_hash does not match the planned charter hash.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("actual_digest", batch.Document.CharterHash),
			diag.WithDetail("expected_digest", expected),
		)))
	}
	if expected := strings.TrimSpace(batch.Plan.ArtifactDigest); expected != "" && batch.Document.ArtifactDigest != expected {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification batch document artifact_digest does not match the planned artifact digest.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("actual_digest", batch.Document.ArtifactDigest),
			diag.WithDetail("expected_digest", expected),
		)))
	}
	return diagnostics
}

func validatePreLaunchCharter(batch BatchInput, charterPath string) []diag.Diagnostic {
	expectedHash := strings.TrimSpace(batch.Plan.CharterHash)
	expectedRawDigest := strings.TrimSpace(batch.Plan.CharterDigest)
	if expectedHash == "" && expectedRawDigest == "" {
		return nil
	}
	if strings.TrimSpace(charterPath) == "" {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification requires the planned frozen Charter input before launch.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
		))}
	}
	data, err := os.ReadFile(charterPath)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification frozen Charter input could not be read before launch.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", charterPath)))}
	}
	var diagnostics []diag.Diagnostic
	if expectedRawDigest != "" {
		actualRawDigest := digest.RawBytes(data)
		if actualRawDigest != expectedRawDigest {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidBatchInput,
				"relay verification frozen Charter bytes do not match the planned charter digest.",
				diag.WithDetail("batch_id", batch.Plan.BatchID),
				diag.WithDetail("path", charterPath),
				diag.WithDetail("actual_digest", actualRawDigest),
				diag.WithDetail("expected_digest", expectedRawDigest),
			)))
		}
	}
	if expectedHash != "" {
		frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification frozen Charter input is not a valid frozen Charter.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", charterPath))))
		} else if frozen.CharterHash != expectedHash {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidBatchInput,
				"relay verification frozen Charter hash does not match the planned charter hash.",
				diag.WithDetail("batch_id", batch.Plan.BatchID),
				diag.WithDetail("path", charterPath),
				diag.WithDetail("actual_digest", frozen.CharterHash),
				diag.WithDetail("expected_digest", expectedHash),
			)))
		}
	}
	return diagnostics
}

func validatePreLaunchArtifacts(batch BatchInput, artifactPaths []string) []diag.Diagnostic {
	planned := plannedArtifactDigests(batch.Plan.ArtifactDigestSet...)
	if len(planned) == 0 {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification requires a planned reviewed artifact digest set before launch.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("field", "artifact_digest_set"),
		))}
	}
	plannedSet := stringSet(planned)
	present := map[string]bool{}
	var actualDigestSets [][]string
	var unexpected []string
	seenPath := false
	for _, path := range artifactPaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		seenPath = true
		data, err := os.ReadFile(path)
		if err != nil {
			return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification artifact input could not be read before launch.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", path)))}
		}
		digests := reviewedArtifactDigests(data)
		actualDigestSets = append(actualDigestSets, digests)
		if matched := markPlannedArtifactDigests(present, plannedSet, digests); !matched {
			unexpected = append(unexpected, digests...)
		}
	}
	if !seenPath {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification requires the planned reviewed artifact input before launch.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("expected_digests", planned),
		))}
	}
	missing := missingPlannedArtifactDigests(planned, present)
	if len(unexpected) == 0 && len(missing) == 0 {
		return nil
	}
	sort.Strings(unexpected)
	return []diag.Diagnostic{diag.FromError(diag.New(
		CodeInvalidBatchInput,
		"relay verification artifact inputs do not match the planned artifact digests.",
		diag.WithDetail("batch_id", batch.Plan.BatchID),
		diag.WithDetail("actual_digest_sets", actualDigestSets),
		diag.WithDetail("expected_digests", planned),
		diag.WithDetail("missing_digests", missing),
		diag.WithDetail("unplanned_digests", uniqueStrings(unexpected)),
	))}
}

func reviewedArtifactDigests(data []byte) []string {
	digests := []string{digest.RawBytes(data)}
	if snapshotDigest, ok := frozenSnapshotManifestDigest(data); ok && !stringSliceContains(digests, snapshotDigest) {
		digests = append(digests, snapshotDigest)
	}
	sort.Strings(digests)
	return digests
}

func plannedArtifactDigests(values ...string) []string {
	var planned []string
	for _, value := range values {
		planned = appendUniqueString(planned, strings.TrimSpace(value))
	}
	sort.Strings(planned)
	return planned
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func markPlannedArtifactDigests(present map[string]bool, plannedSet map[string]bool, actual []string) bool {
	matched := false
	for _, value := range actual {
		if plannedSet[value] {
			present[value] = true
			matched = true
		}
	}
	return matched
}

func missingPlannedArtifactDigests(planned []string, present map[string]bool) []string {
	var missing []string
	for _, value := range planned {
		if !present[value] {
			missing = append(missing, value)
		}
	}
	return missing
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func uniqueStrings(values []string) []string {
	var unique []string
	for _, value := range values {
		unique = appendUniqueString(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func frozenSnapshotManifestDigest(data []byte) (string, bool) {
	manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*32)
	if err != nil || manifest.SchemaVersion != freeze.SchemaVersion {
		return "", false
	}
	manifestDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return "", false
	}
	if manifest.Source.ManifestDigest != manifestDigest || manifest.Workspace.ManifestDigest != manifestDigest {
		return "", false
	}
	return manifestDigest, true
}

func validatePreLaunchIntegrationBundle(batch BatchInput, bundlePath string) []diag.Diagnostic {
	expected := strings.TrimSpace(batch.Plan.IntegrationBundleDigest)
	if expected == "" {
		return nil
	}
	if strings.TrimSpace(bundlePath) == "" {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification requires the planned integration bundle before launch.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
		))}
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification integration bundle could not be read before launch.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", bundlePath)))}
	}
	payload, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification integration bundle is not strict JSON.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", bundlePath)))}
	}
	actual, err := digest.SemanticJSON(payload)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification integration bundle digest could not be computed.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", bundlePath)))}
	}
	if actual != expected {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidBatchInput,
			"relay verification integration bundle does not match the planned bundle digest.",
			diag.WithDetail("batch_id", batch.Plan.BatchID),
			diag.WithDetail("path", bundlePath),
			diag.WithDetail("actual_digest", actual),
			diag.WithDetail("expected_digest", expected),
		))}
	}
	return nil
}

func RecipeID(taskShape string, backend string) string {
	base := ""
	switch taskShape {
	case contracts.BatchTaskDefect:
		base = "witness-falsify-v2"
	case contracts.BatchTaskEconomy:
		base = "economy-equivalence-v2"
	default:
		return ""
	}
	switch strings.TrimSpace(backend) {
	case "codex":
		return base + "-codex"
	case "claude":
		return base + "-claude"
	default:
		return base
	}
}

func inputBindings(charterPath string, batchPath string, artifactPaths []string) []string {
	bindings := []string{}
	if charterPath != "" {
		bindings = append(bindings, "charter="+charterPath)
	}
	bindings = append(bindings, "findings="+batchPath)
	for _, path := range artifactPaths {
		if strings.TrimSpace(path) != "" {
			bindings = append(bindings, "artifact="+path)
		}
	}
	return bindings
}

func relayTask(batch BatchInput) string {
	return fmt.Sprintf("Witness verification batch %s (%s). Evaluate only the filed witnesses in the bound verification-batch document.", batch.Plan.BatchID, batch.Plan.TaskShape)
}

func defaultWorkspaceIsolation(value string) string {
	if strings.TrimSpace(value) == "" {
		return "read_only"
	}
	return value
}

func commandDiagnostic(code string, message string, err error) diag.Diagnostic {
	details := map[string]any{"error": err.Error()}
	var commandError *relayclient.CommandError
	if errors.As(err, &commandError) {
		details["relay_error_kind"] = commandError.Kind
		details["exit_code"] = commandError.ExitCode
		if commandError.Diagnostic.Code != "" {
			details["relay_diagnostic_code"] = commandError.Diagnostic.Code
			details["relay_diagnostic_message"] = commandError.Diagnostic.Message
		}
	}
	return diag.FromError(diag.New(code, message, diag.WithDetails(details)))
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if text := stringValue(values[key]); text != "" {
			return text
		}
	}
	return ""
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func writeCanonical(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return diag.Wrap(err, CodeOutputFailed, "relay run output directory could not be created.", diag.WithDetail("path", filepath.Dir(path)))
	}
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return diag.Wrap(err, CodeOutputFailed, "relay run output could not be written.", diag.WithDetail("path", path))
	}
	return nil
}
