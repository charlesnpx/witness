package relayrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/planning"
	"witness/internal/portable"
	"witness/internal/relayclient"
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
		if diagnostics := validatePreLaunchBatchInput(batch); len(diagnostics) > 0 {
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

func validatePreLaunchBatchInput(batch BatchInput) []diag.Diagnostic {
	data, err := os.ReadFile(batch.Path)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidBatchInput, "relay verification batch input could not be read before launch.", diag.WithDetail("batch_id", batch.Plan.BatchID), diag.WithDetail("path", batch.Path)))}
	}
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
			return []diag.Diagnostic{diag.FromError(diag.New(
				CodeInvalidBatchInput,
				"relay verification batch file digest does not match the loaded batch bytes.",
				diag.WithDetail("batch_id", batch.Plan.BatchID),
				diag.WithDetail("path", batch.Path),
				diag.WithDetail("actual_digest", actualDigest),
				diag.WithDetail("expected_digest", rawDigest),
			))}
		}
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
