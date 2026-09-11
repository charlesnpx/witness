package relayrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	"github.com/charlesnpx/convo-relay/v2/plan"
	"github.com/charlesnpx/convo-relay/v2/result"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayv2"
)

const (
	SchemaVersion         = "witness-relay-verification-runs-v2"
	RunRecordSchema       = "witness-relay-verification-run-v2"
	CodeMissingBatchPath  = "relayrun_missing_batch_path"
	CodeRelayRunFailed    = "relayrun_launch_failed"
	CodeRelayExportFailed = "relayrun_export_failed"
	CodeRelayVerifyFailed = "relayrun_producer_verify_failed"
	CodeRelayNotInstalled = "relayrun_relay_not_installed"
	CodeOutputFailed      = "relayrun_output_failed"
	CodeInvalidBatchInput = "relayrun_invalid_batch_input"
	// CodeNamedInputBudgetExceeded identifies relay named inputs whose raw
	// bytes exceed the selected integration contract's effective input budget.
	CodeNamedInputBudgetExceeded = "relayrun_named_input_budget_exceeded"
	// CodeNamedInputBudgetInvalid identifies a failed prerequisite for deriving
	// a relay named-input budget before launch.
	CodeNamedInputBudgetInvalid = "relayrun_named_input_budget_invalid"
	CodeInvalidRunRecord        = "relayrun_invalid_run_record"
	// CodeConsumingRunRecordExists identifies an attempted relaunch of a batch
	// whose retained per-batch record proves it has already been consumed.
	CodeConsumingRunRecordExists = "relayrun_consuming_record_exists"
	// CodeInvalidRunRecordStreamSummary identifies claimed launch stream
	// summaries that do not match retained launch bytes.
	CodeInvalidRunRecordStreamSummary = "relayrun_invalid_run_record_stream_summary"

	// RunStatusLaunchFailed marks a batch rejected before relay launch or a
	// relay command whose process did not start. It is the only status that
	// does not consume the batch's single verification run.
	RunStatusLaunchFailed = "launch_failed"

	ProviderInvokedTrue    = "true"
	ProviderInvokedFalse   = "false"
	ProviderInvokedUnknown = "unknown"

	launchCaptureLimitBytes = 64 * 1024
)

type Options struct {
	RelayPath             string
	IntegrationBundlePath string
	CharterPath           string
	ArtifactPaths         []string
	// NamedInputBudgetBytes overrides every raw named-input limit before relay
	// launch. A zero value derives each input's limit from the selected
	// integration-bundle contract.
	NamedInputBudgetBytes int64
	// ArtifactDigests aligns with ArtifactPaths and retains one digest for
	// every artifact supplied to relay. ArtifactDigest remains the legacy
	// single-artifact planned snapshot digest.
	ArtifactDigests []string
	// The planned digests are retained with the run record, rather than passed
	// to relay. Relay's --input contract takes plain paths.
	CharterDigest           string
	ArtifactDigest          string
	IntegrationBundleDigest string
	OutputDir               string
	Backend                 string
	WorkspaceIsolation      string
	RelayHome               string
	LaunchCWD               string
	SettingsPath            string
	AllowDirtySource        bool
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

// LaunchRecord is the bounded witness-side evidence for one relay run command.
// Stdout and Stderr each retain at most launchCaptureLimitBytes of source
// output, split evenly between the head and tail when truncated. They are raw
// bytes (base64-encoded in JSON) so retained output stays byte-exact. Their
// digest and byte-count summaries cover those retained bytes; the truncated
// flags preserve that the original stream exceeded the retained capture.
type LaunchRecord struct {
	Argv             []string       `json:"argv"`
	WorkingDirectory string         `json:"working_directory"`
	ExitCode         int            `json:"exit_code"`
	StartFailed      bool           `json:"start_failed"`
	Stdout           []byte         `json:"stdout_b64"`
	Stderr           []byte         `json:"stderr_b64"`
	StdoutDigest     string         `json:"stdout_digest"`
	StderrDigest     string         `json:"stderr_digest"`
	StdoutBytes      strictjson.Int `json:"stdout_bytes"`
	StderrBytes      strictjson.Int `json:"stderr_bytes"`
	StdoutTruncated  bool           `json:"stdout_truncated"`
	StderrTruncated  bool           `json:"stderr_truncated"`
}

type RunRecord struct {
	SchemaVersion string        `json:"schema_version"`
	BatchID       string        `json:"batch_id"`
	Status        string        `json:"status"`
	RecipeID      string        `json:"recipe_id"`
	InputBindings []string      `json:"input_bindings"`
	RelayLaunch   *LaunchRecord `json:"relay_launch,omitempty"`
	// ProviderInvoked is one of true, false, or unknown. False is assigned
	// only when no relay process started, including local pre-launch rejection.
	ProviderInvoked string `json:"provider_invoked"`
	// ConsumesBatch is false only for provider_invoked=false launch_failed
	// records, including local pre-launch rejection; true and unknown remain
	// fail-closed and consume the batch.
	ConsumesBatch                  bool                                    `json:"consumes_batch"`
	SessionDir                     string                                  `json:"session_dir,omitempty"`
	PortableExportDir              string                                  `json:"portable_export_dir,omitempty"`
	PortableExportDigest           string                                  `json:"portable_export_digest,omitempty"`
	RelayRunResult                 map[string]any                          `json:"relay_run_result,omitempty"`
	RelayVerdicts                  *contracts.RelayWitnessVerdictsDocument `json:"relay_verdicts,omitempty"`
	PlanDigest                     string                                  `json:"plan_digest,omitempty"`
	RelayErrorKind                 string                                  `json:"relay_error_kind,omitempty"`
	ProviderInvocationCount        int                                     `json:"provider_invocation_count"`
	ProviderInvocationCountPresent bool                                    `json:"provider_invocation_count_present,omitempty"`
	VerifiedBundle                 *bundle.Verification                    `json:"verified_bundle,omitempty"`
	Diagnostics                    []diag.Diagnostic                       `json:"diagnostics,omitempty"`
}

func RunBatches(ctx context.Context, batches []BatchInput, options Options) (*Result, error) {
	result := &Result{SchemaVersion: SchemaVersion}
	launchCWD := effectiveLaunchCWD(options.LaunchCWD)
	// Check every target before launching any batch. Besides refusing a
	// relaunch of a consumed batch, doing this as a complete preflight avoids
	// launching an earlier batch and then discovering a later batch cannot be
	// safely persisted.
	if err := rejectExistingConsumingRunRecords(options.OutputDir, batches); err != nil {
		return result, err
	}
	for _, batch := range batches {
		record := RunRecord{
			SchemaVersion:   RunRecordSchema,
			BatchID:         batch.Plan.BatchID,
			RecipeID:        RecipeID(batch.Plan.TaskShape, options.Backend),
			Status:          contracts.RecordStatusUnavailable,
			ProviderInvoked: ProviderInvokedUnknown,
			ConsumesBatch:   true,
		}
		record.InputBindings = recordedInputBindings(options, batch)
		if strings.TrimSpace(batch.Path) == "" {
			rejectBeforeLaunch(&record, launchCWD, diag.FromError(diag.New(CodeMissingBatchPath, "relay verification requires a persisted verification-batch path.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		if diagnostics := validatePreLaunchBatchInput(batch, options); len(diagnostics) > 0 {
			rejectBeforeLaunch(&record, launchCWD, diagnostics...)
			result.Runs = append(result.Runs, record)
			continue
		}
		compiled, err := compileRelayPlan(batch, options)
		if err != nil {
			rejectBeforeLaunch(&record, launchCWD, diag.FromError(diag.Wrap(err, CodeRelayRunFailed, "relay v2 plan compilation failed.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		if diagnostics := validateNamedInputBudget(compiled, options.NamedInputBudgetBytes, batch.Plan.BatchID); len(diagnostics) > 0 {
			rejectBeforeLaunch(&record, launchCWD, diagnostics...)
			result.Runs = append(result.Runs, record)
			continue
		}
		record.PlanDigest = compiled.Digest
		cleanup, planPath, blobsPath, err := materializeRelayPlan(options.OutputDir, batch.Plan.BatchID, compiled)
		if err != nil {
			rejectBeforeLaunch(&record, launchCWD, diag.FromError(diag.Wrap(err, CodeRelayRunFailed, "relay v2 plan materialization failed.", diag.WithDetail("batch_id", batch.Plan.BatchID))))
			result.Runs = append(result.Runs, record)
			continue
		}
		runValue, invocation, err := relayv2.RunWithOptions(ctx, options.RelayPath, planPath, blobsPath, relayv2.RunOptions{
			WorkingDirectory: launchCWD,
			Home:             options.RelayHome,
			SettingsPath:     options.SettingsPath,
		})
		record.RelayLaunch = launchRecordForRelayV2(invocation, err)
		if err != nil {
			cleanup()
			record.RelayErrorKind = relayErrorKind(err)
			record.ProviderInvoked = classifyProviderInvocation(record.RelayLaunch, 0, false)
			if record.ProviderInvoked == ProviderInvokedFalse && record.RelayLaunch != nil && record.RelayLaunch.StartFailed {
				record.Status = RunStatusLaunchFailed
				record.ConsumesBatch = false
			}
			code := CodeRelayRunFailed
			if relayv2.IsRelayNotInstalled(err) {
				code = CodeRelayNotInstalled
			}
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(code, "relay v2 run failed.", err))
			result.Runs = append(result.Runs, record)
			continue
		}
		cleanup()
		record.RelayRunResult, err = relayResultMap(runValue)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(CodeRelayRunFailed, "relay v2 result could not be decoded into Witness's run record.", err))
		}
		record.SessionDir = runValue.SessionDir
		count, present := relayv2.InvocationEvidence(runValue)
		record.ProviderInvocationCount = count
		record.ProviderInvocationCountPresent = present
		record.ProviderInvoked = classifyProviderInvocation(record.RelayLaunch, count, present)
		if record.ProviderInvoked == ProviderInvokedFalse && !record.RelayLaunch.StartFailed {
			record.Status = contracts.RecordStatusFailed
		}
		verdicts, verdictErr := relayVerdictsFromResult(runValue, batch.Document)
		if verdictErr != nil {
			record.Status = contracts.RecordStatusFailed
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(CodeRelayRunFailed, "relay v2 typed result did not contain valid Witness verdicts.", verdictErr))
		} else {
			record.RelayVerdicts = &verdicts
		}
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
		verified, err := relayv2.ExportAndVerify(ctx, options.RelayPath, record.SessionDir, exportDir, record.PlanDigest)
		if err != nil {
			record.RelayErrorKind = relayErrorKind(err)
			code := CodeRelayVerifyFailed
			message := "relay v2 export and bundle verification failed."
			if relayv2.IsRelayNotInstalled(err) {
				code = CodeRelayNotInstalled
				message = "relay v2 export failed because Relay is not installed."
			}
			record.Diagnostics = append(record.Diagnostics, commandDiagnostic(code, message, err))
			result.Runs = append(result.Runs, record)
			continue
		}
		record.VerifiedBundle = &verified
		record.PortableExportDigest = verified.Manifest.ManifestDigest
		if record.Status != contracts.RecordStatusFailed {
			record.Status = contracts.RecordStatusValid
		}
		result.Runs = append(result.Runs, record)
	}
	if options.OutputDir != "" {
		// Recheck before persistence so a consuming per-batch record that
		// appeared after the launch preflight is not replaced.
		if err := rejectExistingConsumingRunRecords(options.OutputDir, batches); err != nil {
			return result, err
		}
		for _, record := range result.Runs {
			// Keep the final check adjacent to the replacement itself. The
			// earlier batch-wide check prevents an avoidable partial run; this
			// one preserves consuming evidence if the file changed meanwhile.
			if err := rejectExistingConsumingRunRecord(options.OutputDir, record.BatchID); err != nil {
				return result, err
			}
			if err := writeCanonical(filepath.Join(options.OutputDir, "verification", "runs", record.BatchID+".json"), record); err != nil {
				return result, err
			}
		}
		if err := writeCanonical(filepath.Join(options.OutputDir, "verification", "runs", "index.json"), result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func rejectExistingConsumingRunRecords(outputDir string, batches []BatchInput) error {
	if strings.TrimSpace(outputDir) == "" {
		return nil
	}
	seen := make(map[string]bool, len(batches))
	for _, batch := range batches {
		batchID := strings.TrimSpace(batch.Plan.BatchID)
		if batchID == "" || seen[batchID] {
			continue
		}
		seen[batchID] = true
		if err := rejectExistingConsumingRunRecord(outputDir, batchID); err != nil {
			return err
		}
	}
	return nil
}

func rejectExistingConsumingRunRecord(outputDir string, batchID string) error {
	path := filepath.Join(outputDir, "verification", "runs", batchID+".json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return diag.Wrap(err, CodeOutputFailed, "existing relay run record could not be read.", diag.WithDetail("batch_id", batchID), diag.WithDetail("path", path))
	}
	records, err := ReadRunRecordsBytes(data)
	if err != nil {
		return diag.Wrap(err, CodeInvalidRunRecord, "existing relay run record could not be validated before launch.", diag.WithDetail("batch_id", batchID), diag.WithDetail("path", path))
	}
	if len(records) != 1 {
		return diag.New(CodeInvalidRunRecord, "existing per-batch relay run record must contain exactly one run.", diag.WithDetail("batch_id", batchID), diag.WithDetail("path", path), diag.WithDetail("run_count", len(records)))
	}
	record := records[0]
	if record.BatchID != batchID {
		return diag.New(CodeInvalidRunRecord, "existing per-batch relay run record batch_id does not match its file name.", diag.WithDetail("expected_batch_id", batchID), diag.WithDetail("actual_batch_id", record.BatchID), diag.WithDetail("path", path))
	}
	if !record.ConsumesBatch {
		return nil
	}
	return diag.New(
		CodeConsumingRunRecordExists,
		fmt.Sprintf("relay verification batch %q cannot proceed because a consuming record already exists.", batchID),
		diag.WithDetail("batch_id", batchID),
		diag.WithDetail("path", path),
	)
}

// rejectBeforeLaunch records a local rejection without invoking relay. The
// empty launch marker means no process started; downstream consumers use the
// existing launch_failed tuple to keep the batch available for a corrected
// later launch.
func rejectBeforeLaunch(record *RunRecord, workingDirectory string, diagnostics ...diag.Diagnostic) {
	record.Status = RunStatusLaunchFailed
	record.ProviderInvoked = ProviderInvokedFalse
	record.ConsumesBatch = false
	record.RelayLaunch = &LaunchRecord{
		Argv:             []string{},
		WorkingDirectory: workingDirectory,
		ExitCode:         -1,
		StartFailed:      true,
	}
	record.Diagnostics = append(record.Diagnostics, diagnostics...)
}

// ReadRunRecordsBytes accepts one v2 run record or a v2 runs index. The
// version bump is required because strict JSON decoding rejects unknown fields.
func ReadRunRecordsBytes(data []byte) ([]RunRecord, error) {
	raw, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, err
	}
	document, ok := raw.(map[string]any)
	if !ok {
		return nil, diag.New(CodeInvalidRunRecord, "relay run record input must be a JSON object.")
	}
	schemaVersion, _ := document["schema_version"].(string)
	switch schemaVersion {
	case RunRecordSchema:
		record, err := strictjson.DecodeBytes[RunRecord](data, strictjson.DefaultMaxBytes*32)
		if err != nil {
			return nil, err
		}
		if err := requireValidRunRecord(record, document); err != nil {
			return nil, err
		}
		return []RunRecord{record}, nil
	case SchemaVersion:
		index, err := strictjson.DecodeBytes[Result](data, strictjson.DefaultMaxBytes*32)
		if err != nil {
			return nil, err
		}
		rawRuns, _ := document["runs"].([]any)
		for index, record := range index.Runs {
			var rawRecord map[string]any
			if index < len(rawRuns) {
				rawRecord, _ = rawRuns[index].(map[string]any)
			}
			if err := requireValidRunRecord(record, rawRecord); err != nil {
				return nil, err
			}
		}
		return index.Runs, nil
	default:
		return nil, diag.New(
			CodeInvalidRunRecord,
			"relay run record input has an unsupported schema_version.",
			diag.WithDetail("actual", schemaVersion),
			diag.WithDetail("record_schema", RunRecordSchema),
			diag.WithDetail("index_schema", SchemaVersion),
		)
	}
}

// ManifestRunRecordMetadata produces the local-safe evidence projection used
// by assembly consumers. ReadRunRecordsBytes must validate the record first;
// this helper retains only provenance metadata and a digest of the full local
// record, never raw launch output or provider payloads.
func ManifestRunRecordMetadata(record RunRecord) (map[string]any, error) {
	data, err := contracts.CanonicalBytes(record)
	if err != nil {
		return nil, err
	}
	metadata, err := strictjson.DecodeBytes[map[string]any](data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, err
	}
	metadata["run_record_digest"] = digest.RawBytes(data)
	return planning.SanitizeRelayRunRecordMetadata(metadata), nil
}

func requireValidRunRecord(record RunRecord, source ...map[string]any) error {
	var rawRecord map[string]any
	if len(source) > 0 {
		rawRecord = source[0]
	}
	if record.SchemaVersion != RunRecordSchema {
		return diag.New(CodeInvalidRunRecord, "relay run record schema_version is unsupported.", diag.WithDetail("actual", record.SchemaVersion), diag.WithDetail("expected", RunRecordSchema))
	}
	if strings.TrimSpace(record.BatchID) == "" {
		return diag.New(CodeInvalidRunRecord, "relay run record batch_id is required.")
	}
	if strings.TrimSpace(record.RecipeID) == "" {
		return diag.New(CodeInvalidRunRecord, "relay run record recipe_id is required.")
	}
	if record.ProviderInvoked != ProviderInvokedTrue && record.ProviderInvoked != ProviderInvokedFalse && record.ProviderInvoked != ProviderInvokedUnknown {
		return diag.New(CodeInvalidRunRecord, "relay run record provider_invoked is unsupported.", diag.WithDetail("value", record.ProviderInvoked))
	}
	if record.ProviderInvocationCount < 0 {
		return diag.New(CodeInvalidRunRecord, "relay run record provider invocation count must not be negative.", diag.WithDetail("count", record.ProviderInvocationCount))
	}
	if !record.ProviderInvocationCountPresent && record.ProviderInvocationCount != 0 {
		return diag.New(CodeInvalidRunRecord, "relay run record provider invocation count is present only when its presence bit is true.", diag.WithDetail("count", record.ProviderInvocationCount))
	}
	if record.ProviderInvocationCountPresent {
		wantInvoked := ProviderInvokedFalse
		if record.ProviderInvocationCount > 0 {
			wantInvoked = ProviderInvokedTrue
		}
		if record.ProviderInvoked != wantInvoked {
			return diag.New(CodeInvalidRunRecord, "relay run record provider_invoked does not agree with typed invocation evidence.", diag.WithDetail("provider_invoked", record.ProviderInvoked), diag.WithDetail("count", record.ProviderInvocationCount), diag.WithDetail("present", record.ProviderInvocationCountPresent))
		}
	}
	if record.Status != contracts.RecordStatusValid && record.Status != contracts.RecordStatusFailed && record.Status != contracts.RecordStatusUnavailable && record.Status != RunStatusLaunchFailed {
		return diag.New(CodeInvalidRunRecord, "relay run record status is unsupported.", diag.WithDetail("value", record.Status))
	}
	if err := requireValidRelayLaunchStreamSummaries(record.RelayLaunch, rawRelayLaunch(rawRecord)); err != nil {
		return err
	}
	providerEvidence := runRecordProviderEvidence(record)
	if record.RelayLaunch != nil && record.RelayLaunch.StartFailed {
		if record.ProviderInvoked != ProviderInvokedFalse || record.Status != RunStatusLaunchFailed || record.ConsumesBatch || len(providerEvidence) > 0 || record.ProviderInvocationCountPresent {
			return diag.New(
				CodeInvalidRunRecord,
				"relay_launch.start_failed=true requires provider_invoked=false, launch_failed status, a non-consuming batch, and no provider evidence.",
				diag.WithDetail("provider_invoked", record.ProviderInvoked),
				diag.WithDetail("status", record.Status),
				diag.WithDetail("consumes_batch", record.ConsumesBatch),
				diag.WithDetail("provider_evidence", providerEvidence),
			)
		}
	}
	if record.ProviderInvoked == ProviderInvokedFalse {
		if record.RelayLaunch != nil && record.RelayLaunch.StartFailed {
			if record.Status != RunStatusLaunchFailed {
				return diag.New(CodeInvalidRunRecord, "provider_invoked=false start failure requires launch_failed status.", diag.WithDetail("status", record.Status))
			}
			if record.ConsumesBatch {
				return diag.New(CodeInvalidRunRecord, "provider_invoked=false start-failure run records must not consume the batch.")
			}
			if len(providerEvidence) > 0 {
				return diag.New(
					CodeInvalidRunRecord,
					"provider_invoked=false start-failure records cannot carry provider evidence.",
					diag.WithDetail("provider_evidence", providerEvidence),
				)
			}
			return nil
		}
		if !record.ProviderInvocationCountPresent || record.ProviderInvocationCount != 0 {
			return diag.New(CodeInvalidRunRecord, "provider_invoked=false without a start failure requires explicit zero invocation evidence.")
		}
		if record.Status == RunStatusLaunchFailed || !record.ConsumesBatch {
			return diag.New(CodeInvalidRunRecord, "explicit zero invocation evidence must retain a consuming, non-launch-failed record.", diag.WithDetail("status", record.Status), diag.WithDetail("consumes_batch", record.ConsumesBatch))
		}
		return nil
	}
	if record.Status == RunStatusLaunchFailed {
		return diag.New(CodeInvalidRunRecord, "launch_failed status requires provider_invoked=false.")
	}
	if !record.ConsumesBatch {
		return diag.New(CodeInvalidRunRecord, "provider_invoked=true or unknown run records must consume the batch.")
	}
	if len(providerEvidence) == 0 && record.ProviderInvoked == ProviderInvokedTrue {
		return diag.New(CodeInvalidRunRecord, "provider_invoked=true requires a session or provider artifact.")
	}
	return nil
}

func rawRelayLaunch(record map[string]any) map[string]any {
	launch, _ := record["relay_launch"].(map[string]any)
	return launch
}

func requireValidRelayLaunchStreamSummaries(launch *LaunchRecord, rawLaunch map[string]any) error {
	if launch == nil {
		return nil
	}
	for _, stream := range []struct {
		name      string
		retained  []byte
		digest    string
		bytes     strictjson.Int
		truncated bool
	}{
		{name: "stdout", retained: launch.Stdout, digest: launch.StdoutDigest, bytes: launch.StdoutBytes, truncated: launch.StdoutTruncated},
		{name: "stderr", retained: launch.Stderr, digest: launch.StderrDigest, bytes: launch.StderrBytes, truncated: launch.StderrTruncated},
	} {
		if err := requireValidRelayLaunchStreamSummary(stream.name, stream.retained, stream.digest, stream.bytes, stream.truncated, rawLaunch); err != nil {
			return err
		}
	}
	return nil
}

func requireValidRelayLaunchStreamSummary(stream string, retained []byte, claimedDigest string, claimedBytes strictjson.Int, truncated bool, rawLaunch map[string]any) error {
	digestKey := stream + "_digest"
	bytesKey := stream + "_bytes"
	_, digestClaimed := rawLaunch[digestKey]
	_, bytesClaimed := rawLaunch[bytesKey]
	if rawLaunch == nil {
		digestClaimed = strings.TrimSpace(claimedDigest) != ""
		bytesClaimed = claimedBytes != 0
	}
	if digestClaimed && strings.TrimSpace(claimedDigest) != "" && !digest.WellFormed(strings.TrimSpace(claimedDigest)) {
		return invalidRelayLaunchStreamSummary(stream, digestKey, "relay launch stream digest must be a well-formed sha256 digest.", diag.WithDetail("claimed_digest", claimedDigest))
	}
	if bytesClaimed && claimedBytes < 0 {
		return invalidRelayLaunchStreamSummary(stream, bytesKey, "relay launch stream byte count must not be negative.", diag.WithDetail("claimed_bytes", claimedBytes))
	}
	if retained == nil {
		hasDigestClaim := digestClaimed && strings.TrimSpace(claimedDigest) != ""
		hasBytesClaim := bytesClaimed && claimedBytes != 0
		if (hasDigestClaim || hasBytesClaim) && !truncated {
			return invalidRelayLaunchStreamSummary(stream, "retained_content", "relay launch stream summaries without retained content require a truncated capture.", diag.WithDetail("claimed_digest", claimedDigest), diag.WithDetail("claimed_bytes", claimedBytes))
		}
		return nil
	}
	actualDigest := digest.RawBytes(retained)
	actualBytes := strictjson.Int(len(retained))
	if digestClaimed && strings.TrimSpace(claimedDigest) != actualDigest {
		return invalidRelayLaunchStreamSummary(stream, digestKey, "relay launch stream digest does not match retained content.", diag.WithDetail("claimed_digest", claimedDigest), diag.WithDetail("retained_digest", actualDigest))
	}
	if bytesClaimed && claimedBytes != actualBytes {
		return invalidRelayLaunchStreamSummary(stream, bytesKey, "relay launch stream byte count does not match retained content.", diag.WithDetail("claimed_bytes", claimedBytes), diag.WithDetail("retained_bytes", actualBytes))
	}
	return nil
}

func invalidRelayLaunchStreamSummary(stream, field, message string, options ...diag.Option) error {
	options = append(options, diag.WithDetail("stream", stream), diag.WithDetail("field", field))
	return diag.New(CodeInvalidRunRecordStreamSummary, message, options...)
}

func effectiveLaunchCWD(value string) string {
	if strings.TrimSpace(value) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return ""
		}
		return cwd
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return value
	}
	return abs
}

func launchRecordForRelayV2(invocation relayv2.Invocation, err error) *LaunchRecord {
	invocationArgv := invocation.Argv()
	command := ""
	args := []string(nil)
	if len(invocationArgv) > 0 {
		command = invocationArgv[0]
		args = append([]string(nil), invocationArgv[1:]...)
	}
	workingDirectory := invocation.WorkingDirectory
	stdout := []byte(nil)
	stderr := []byte(nil)
	exitCode := 0
	startFailed := false
	if commandError := relayCommandError(err); commandError != nil {
		command = commandError.Executable
		args = append([]string(nil), commandError.Args...)
		stdout = []byte(commandError.Stdout)
		stderr = []byte(commandError.Stderr)
		exitCode = commandError.ExitCode
		startFailed = commandError.StartFailed
	}
	stdout, stdoutTruncated := boundedLaunchOutput(stdout)
	stderr, stderrTruncated := boundedLaunchOutput(stderr)
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, command)
	argv = append(argv, args...)
	return &LaunchRecord{
		Argv:             argv,
		WorkingDirectory: workingDirectory,
		ExitCode:         exitCode,
		StartFailed:      startFailed,
		Stdout:           stdout,
		Stderr:           stderr,
		StdoutDigest:     digest.RawBytes(stdout),
		StderrDigest:     digest.RawBytes(stderr),
		StdoutBytes:      strictjson.Int(len(stdout)),
		StderrBytes:      strictjson.Int(len(stderr)),
		StdoutTruncated:  stdoutTruncated,
		StderrTruncated:  stderrTruncated,
	}
}

func boundedLaunchOutput(value []byte) ([]byte, bool) {
	if len(value) <= launchCaptureLimitBytes {
		retained := make([]byte, len(value))
		copy(retained, value)
		return retained, false
	}
	head := launchCaptureLimitBytes / 2
	tail := launchCaptureLimitBytes - head
	return append(append([]byte(nil), value[:head]...), value[len(value)-tail:]...), true
}

func classifyProviderInvocation(launch *LaunchRecord, count int, present bool) string {
	if present {
		if count > 0 {
			return ProviderInvokedTrue
		}
		return ProviderInvokedFalse
	}
	if launch != nil && launch.StartFailed {
		return ProviderInvokedFalse
	}
	return ProviderInvokedUnknown
}

func compileRelayPlan(batch BatchInput, options Options) (relayv2.CompiledPlan, error) {
	role := strings.TrimSpace(batch.Plan.Role)
	if role == "" {
		switch batch.Plan.TaskShape {
		case contracts.BatchTaskDefect:
			role = contracts.RoleDefect
		case contracts.BatchTaskEconomy:
			role = contracts.RoleEconomy
		}
	}
	recipe, err := relayv2.RecipeForRole(role)
	if err != nil {
		return relayv2.CompiledPlan{}, err
	}
	charterBytes, err := readRelayInput(options.CharterPath, "frozen Charter")
	if err != nil {
		return relayv2.CompiledPlan{}, err
	}
	findingsBytes, err := readRelayInput(batch.Path, "verification batch")
	if err != nil {
		return relayv2.CompiledPlan{}, err
	}
	artifacts := make([]relayv2.Input, 0, len(options.ArtifactPaths))
	for _, path := range options.ArtifactPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, readErr := readRelayInput(path, "reviewed artifact")
		if readErr != nil {
			return relayv2.CompiledPlan{}, readErr
		}
		artifacts = append(artifacts, relayv2.Input{
			Name:      fmt.Sprintf("artifact-%d", len(artifacts)+1),
			Bytes:     data,
			MediaType: "application/json",
		})
	}
	profile := strings.TrimSpace(options.Backend)
	if profile == "" {
		profile = relayv2.DefaultProfileID
	}
	return relayv2.Compile(relayv2.CompileOptions{
		SessionID: batch.Plan.BatchID,
		Task:      relayTask(batch),
		RecipeID:  recipe.ID,
		ProfileID: profile,
		Workspace: relayWorkspace(options.WorkspaceIsolation),
		BatchID:   batch.Plan.BatchID,
		Charter:   charterBytes,
		Findings:  findingsBytes,
		Artifacts: artifacts,
	})
}

func validateNamedInputBudget(compiled relayv2.CompiledPlan, budgetBytes int64, batchID string) []diag.Diagnostic {
	if budgetBytes <= 0 {
		return nil
	}
	var diagnostics []diag.Diagnostic
	for _, input := range compiled.Inputs {
		actualBytes := int64(len(input.Bytes))
		if actualBytes <= budgetBytes {
			continue
		}
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeNamedInputBudgetExceeded,
			fmt.Sprintf("relay named input %q is %d bytes, exceeding the configured %d-byte budget.", input.Name, actualBytes, budgetBytes),
			diag.WithDetail("batch_id", batchID),
			diag.WithDetail("input", input.Name),
			diag.WithDetail("actual_bytes", actualBytes),
			diag.WithDetail("budget_bytes", budgetBytes),
		)))
	}
	return diagnostics
}

func readRelayInput(path string, label string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("read %s: path is required", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", label, path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("read %s %q: input is empty", label, path)
	}
	return data, nil
}

func relayWorkspace(value string) string {
	switch strings.TrimSpace(value) {
	case "", "read_only", "current":
		return plan.WorkspaceModeCurrent
	case "head_copy", "head-copy":
		return plan.WorkspaceModeHeadCopy
	default:
		return strings.TrimSpace(value)
	}
}

func materializeRelayPlan(outputDir string, batchID string, compiled relayv2.CompiledPlan) (func(), string, string, error) {
	var root string
	cleanup := func() {}
	if strings.TrimSpace(outputDir) == "" {
		directory, err := os.MkdirTemp("", "witness-relay-v2-")
		if err != nil {
			return cleanup, "", "", fmt.Errorf("create temporary relay v2 execution directory: %w", err)
		}
		root = directory
		cleanup = func() { _ = os.RemoveAll(directory) }
	} else {
		root = filepath.Join(outputDir, "verification", "relay-v2", strings.TrimSpace(batchID))
		if err := os.MkdirAll(root, 0o700); err != nil {
			return cleanup, "", "", fmt.Errorf("create relay v2 execution directory %q: %w", root, err)
		}
	}
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, compiled.Canonical, 0o600); err != nil {
		cleanup()
		return func() {}, "", "", fmt.Errorf("write compiled relay v2 plan %q: %w", planPath, err)
	}
	blobsPath := filepath.Join(root, "blobs")
	if err := relayv2.Materialize(blobsPath, compiled); err != nil {
		cleanup()
		return func() {}, "", "", fmt.Errorf("materialize relay v2 plan inputs in %q: %w", blobsPath, err)
	}
	return cleanup, planPath, blobsPath, nil
}

func relayCommandError(err error) *relayv2.CommandError {
	var commandError *relayv2.CommandError
	if errors.As(err, &commandError) {
		return commandError
	}
	return nil
}

func relayErrorKind(err error) string {
	if commandError := relayCommandError(err); commandError != nil {
		return commandError.Kind
	}
	if relayv2.IsRelayNotInstalled(err) {
		return relayv2.ErrorRelayNotInstalled
	}
	return ""
}

func relayResultMap(value result.Result) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode relay v2 result: %w", err)
	}
	decoded, err := strictjson.DecodeBytes[map[string]any](data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, fmt.Errorf("decode relay v2 result for local retention: %w", err)
	}
	return decoded, nil
}

func relayVerdictsFromResult(value result.Result, batch contracts.VerificationBatchDocument) (contracts.RelayWitnessVerdictsDocument, error) {
	payload := strings.TrimSpace(value.Result)
	if payload == "" && value.Root != nil {
		payload = strings.TrimSpace(value.Root.Result.Value)
	}
	if payload == "" {
		return contracts.RelayWitnessVerdictsDocument{}, errors.New("relay v2 result payload is empty")
	}
	verdicts, err := contracts.ReadRelayWitnessVerdictsBytes([]byte(payload))
	if err != nil {
		return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("decode relay witness verdicts: %w", err)
	}
	if err := contracts.RequireValidRelayWitnessVerdicts(verdicts, &batch); err != nil {
		return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("validate relay witness verdicts: %w", err)
	}
	return verdicts, nil
}

func runRecordProviderEvidence(record RunRecord) []string {
	evidence := make([]string, 0, 5)
	if strings.TrimSpace(record.SessionDir) != "" {
		evidence = append(evidence, "session_dir")
	}
	if strings.TrimSpace(record.PortableExportDir) != "" {
		evidence = append(evidence, "portable_export_dir")
	}
	if strings.TrimSpace(record.PortableExportDigest) != "" {
		evidence = append(evidence, "portable_export_digest")
	}
	if record.RelayVerdicts != nil {
		evidence = append(evidence, "relay_verdicts")
	}
	if containsSessionOrProviderArtifact(record.RelayRunResult) {
		evidence = append(evidence, "relay_run_result")
	}
	return evidence
}

func containsSessionOrProviderArtifact(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		for key, item := range current {
			if nonEmptyRelayArtifact(item) && isSessionOrProviderArtifactKey(key) {
				return true
			}
			if containsSessionOrProviderArtifact(item) {
				return true
			}
		}
	case []any:
		for _, item := range current {
			if containsSessionOrProviderArtifact(item) {
				return true
			}
		}
	}
	return false
}

func isSessionOrProviderArtifactKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "session_dir", "session_directory", "provider_result", "provider_results", "provider_artifact", "provider_artifacts", "provider_output", "provider_outputs", "provider_response", "provider_responses", "provider_invocation", "provider_invocations", "provider_result_ref":
		return true
	default:
		return false
	}
}

func nonEmptyRelayArtifact(value any) bool {
	switch current := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(current) != ""
	case []any:
		return len(current) > 0
	case map[string]any:
		return len(current) > 0
	default:
		return true
	}
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
	if len(diagnostics) > 0 {
		return diagnostics
	}
	return nil
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

// recordedInputBindings retains the frozen input provenance that pass resume
// validates. These bindings are retained as provenance; Relay v2 receives
// content-addressed blobs materialized from the same bytes instead.
func recordedInputBindings(options Options, batch BatchInput) []string {
	bindings := make([]string, 0, 3+len(options.ArtifactPaths))
	bindings = appendRecordedInputBinding(bindings, "charter", options.CharterPath, firstPlannedDigest(options.CharterDigest, batch.Plan.CharterDigest))
	bindings = appendRecordedInputBinding(bindings, "findings", batch.Path, batch.Plan.BatchDigest)
	firstArtifact := true
	for index, path := range options.ArtifactPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		bindings = appendRecordedInputBinding(bindings, "artifact", path, recordedArtifactDigest(options, batch, index, path, firstArtifact))
		firstArtifact = false
	}
	bindings = appendRecordedInputBinding(bindings, "integration_bundle", options.IntegrationBundlePath, firstPlannedDigest(options.IntegrationBundleDigest, batch.Plan.IntegrationBundleDigest))
	return bindings
}

func recordedArtifactDigest(options Options, batch BatchInput, index int, path string, firstArtifact bool) string {
	if index < len(options.ArtifactDigests) {
		if valueDigest := strings.TrimSpace(options.ArtifactDigests[index]); valueDigest != "" {
			return valueDigest
		}
	}
	if firstArtifact {
		return firstPlannedDigest(options.ArtifactDigest, batch.Plan.PreflightSnapshotDigest, batch.Plan.ArtifactDigest)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return digest.RawBytes(data)
}

func appendRecordedInputBinding(bindings []string, name string, path string, valueDigest string) []string {
	path = strings.TrimSpace(path)
	valueDigest = strings.TrimSpace(valueDigest)
	if path == "" || valueDigest == "" {
		return bindings
	}
	return append(bindings, name+"="+path+"@"+valueDigest)
}

func firstPlannedDigest(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func relayTask(batch BatchInput) string {
	return fmt.Sprintf("Witness verification batch %s (%s). Evaluate only the filed witnesses in the bound verification-batch document.", batch.Plan.BatchID, batch.Plan.TaskShape)
}

func commandDiagnostic(code string, message string, err error) diag.Diagnostic {
	details := map[string]any{"error": err.Error()}
	if commandError := relayCommandError(err); commandError != nil {
		details["relay_error_kind"] = commandError.Kind
		details["exit_code"] = commandError.ExitCode
		details["relay_operation"] = commandError.Operation
		details["relay_executable"] = commandError.Executable
	}
	return diag.FromError(diag.New(code, message, diag.WithDetails(details)))
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
