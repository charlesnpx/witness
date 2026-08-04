package pass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/metrics"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/policy"
	"github.com/charlesnpx/witness/internal/preflight"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	StateSchemaVersion      = "witness-pass-state-v2"
	InvocationSchemaVersion = "witness-pass-next-action-v2"

	StateFileName = "pass-state.json"

	CodeMissingStateDir         = "pass_missing_state_dir"
	CodeMissingCharter          = "pass_missing_charter"
	CodeMissingSource           = "pass_missing_source"
	CodeMissingBundle           = "pass_missing_integration_bundle"
	CodeStateExistsInvalid      = "pass_state_exists_invalid"
	CodeStateUnsupported        = "pass_state_unsupported"
	CodeStateDigestMismatch     = "pass_state_digest_mismatch"
	CodeStateInvalid            = "pass_state_invalid"
	CodeStateDrift              = "pass_state_drift"
	CodeStateDirInsideSource    = "pass_state_dir_inside_source"
	CodeInvalidRoleOutputSpec   = "pass_invalid_role_output_spec"
	CodeInvalidPreflight        = "pass_invalid_preflight"
	CodeInvalidState            = "pass_invalid_state"
	CodePassStateConfigMismatch = "pass_state_config_mismatch"
	CodeHeadManifestMismatch    = "pass_head_manifest_snapshot_mismatch"

	stageFreeze     = "freeze"
	stagePreflight  = "preflight"
	stagePlan       = "plan"
	stageAssemble   = "assemble"
	stageAdjudicate = "adjudicate"
	stageMetrics    = "metrics"

	statusComplete    = "complete"
	statusPending     = "pending"
	statusNotRequired = "not_required"

	actionWitnessCommand      = "witness_command"
	actionCallerRoleOutputs   = "caller_role_outputs"
	actionCallerRelayBatch    = "caller_relay_batch"
	actionComplete            = "complete"
	digestClassFreezeManifest = "freeze-manifest"
	digestClassPassState      = "pass-state"

	roleOutputChangeSurfaceRole = "role-output-change-surface"
)

var atomicWriteFile = ledger.WriteFileAtomic

var orderedStages = []string{
	stageFreeze,
	stagePreflight,
	stagePlan,
	stageAssemble,
	stageAdjudicate,
	stageMetrics,
}

type BeginOptions struct {
	StateDir              string
	CharterPath           string
	AmendmentsPath        string
	SourceDir             string
	SnapshotDir           string
	AllowNonGitSource     bool
	RelayPath             string
	IntegrationBundlePath string
	Backend               string
	PolicyPath            string
	RulesPath             string
	LedgerPath            string
	BaseManifestPath      string
	HeadManifestPath      string
	BaselinePass          bool
	PriorLineagePath      string
	ReceiptOutputDir      string
	ReceiptHMACKeyFile    string
	RoleOutputs           []RoleOutputSpec
	ReceiptPaths          []string
}

type ResumeOptions struct {
	StateDir string
}

type RoleOutputSpec struct {
	Role string `json:"role"`
	Path string `json:"path"`
}

type Config struct {
	StateDir              string           `json:"state_dir"`
	CharterPath           string           `json:"charter_path"`
	AmendmentsPath        string           `json:"amendments_path,omitempty"`
	SourceDir             string           `json:"source_dir"`
	SnapshotDir           string           `json:"snapshot_dir"`
	SnapshotManifestPath  string           `json:"snapshot_manifest_path"`
	AllowNonGitSource     bool             `json:"allow_non_git_source,omitempty"`
	RelayPath             string           `json:"relay_path,omitempty"`
	IntegrationBundlePath string           `json:"integration_bundle_path"`
	Backend               string           `json:"backend,omitempty"`
	PolicyPath            string           `json:"policy_path,omitempty"`
	RulesPath             string           `json:"rules_path,omitempty"`
	LedgerPath            string           `json:"ledger_path,omitempty"`
	BaseManifestPath      string           `json:"base_manifest_path,omitempty"`
	HeadManifestPath      string           `json:"head_manifest_path,omitempty"`
	BaselinePass          bool             `json:"baseline_pass,omitempty"`
	PriorLineagePath      string           `json:"prior_lineage_path,omitempty"`
	ReceiptOutputDir      string           `json:"receipt_output_dir,omitempty"`
	ReceiptHMACKeyFile    string           `json:"receipt_hmac_key_file,omitempty"`
	RoleOutputs           []RoleOutputSpec `json:"role_outputs"`
	ReceiptPaths          []string         `json:"receipt_paths,omitempty"`
	Outputs               Outputs          `json:"outputs"`
}

type Outputs struct {
	StatePath                   string `json:"state_path"`
	CharterFreezePath           string `json:"charter_freeze_path"`
	PreflightPath               string `json:"preflight_path"`
	PlanPath                    string `json:"plan_path"`
	ManifestPath                string `json:"manifest_path"`
	AssembleResultPath          string `json:"assemble_result_path,omitempty"`
	RoleOutputChangeSurfacePath string `json:"role_output_change_surface_path,omitempty"`
	RunResultPath               string `json:"run_result_path"`
	MetricsPath                 string `json:"metrics_path"`
}

type State struct {
	SchemaVersion string             `json:"schema_version"`
	DigestProfile string             `json:"digest_profile"`
	StateDigest   string             `json:"state_digest"`
	StateDir      string             `json:"state_dir"`
	Config        Config             `json:"config"`
	Stages        []StageRecord      `json:"stages"`
	RelayBatches  []RelayBatchRecord `json:"relay_batches,omitempty"`
	NextAction    NextAction         `json:"next_action"`
	Complete      bool               `json:"complete"`
}

type StageRecord struct {
	Name    string           `json:"name"`
	Status  string           `json:"status"`
	Inputs  []ArtifactRecord `json:"inputs,omitempty"`
	Outputs []ArtifactRecord `json:"outputs,omitempty"`
	Details map[string]any   `json:"details,omitempty"`
}

type ArtifactRecord struct {
	Role        string `json:"role"`
	Path        string `json:"path,omitempty"`
	Digest      string `json:"digest"`
	DigestClass string `json:"digest_class"`
}

type RelayBatchRecord struct {
	BatchID           string `json:"batch_id"`
	Role              string `json:"role"`
	TaskShape         string `json:"task_shape"`
	RecipeFamily      string `json:"recipe_family"`
	RecipeID          string `json:"recipe_id"`
	BatchPath         string `json:"batch_path"`
	BatchDigest       string `json:"batch_digest"`
	PortableExportDir string `json:"portable_export_dir"`
	Status            string `json:"status"`
}

type NextAction struct {
	Type                 string              `json:"type"`
	Command              []string            `json:"command,omitempty"`
	Roles                []RoleOutputRequest `json:"roles,omitempty"`
	ScopePolicy          string              `json:"scope_policy,omitempty"`
	ChangeSurfacePath    string              `json:"change_surface_path,omitempty"`
	ChangeSurfaceDigest  string              `json:"change_surface_digest,omitempty"`
	SnapshotDigest       string              `json:"snapshot_digest,omitempty"`
	SnapshotManifestPath string              `json:"snapshot_manifest_path,omitempty"`
	CharterHash          string              `json:"charter_hash,omitempty"`
	CharterFreezePath    string              `json:"charter_freeze_path,omitempty"`
	RelayBatch           *RelayBatchAction   `json:"relay_batch,omitempty"`
	Degraded             bool                `json:"degraded,omitempty"`
	BackendStrata        map[string]string   `json:"backend_strata,omitempty"`
	Summary              string              `json:"summary"`
}

type RoleOutputRequest struct {
	Role string `json:"role"`
	Path string `json:"path"`
}

type RelayBatchAction struct {
	BatchID                 string   `json:"batch_id"`
	RecipeID                string   `json:"recipe_id"`
	RecipeFamily            string   `json:"recipe_family"`
	Backend                 string   `json:"backend,omitempty"`
	BatchPath               string   `json:"batch_path"`
	BatchDigest             string   `json:"batch_digest"`
	PortableExportDir       string   `json:"portable_export_dir"`
	IntegrationBundlePath   string   `json:"integration_bundle_path"`
	IntegrationBundleDigest string   `json:"integration_bundle_digest"`
	CharterDigest           string   `json:"charter_digest"`
	SnapshotDigest          string   `json:"snapshot_digest"`
	InputBindings           []string `json:"input_bindings"`
}

type Invocation struct {
	SchemaVersion string            `json:"schema_version"`
	DigestProfile string            `json:"digest_profile"`
	PassState     ArtifactRecord    `json:"pass_state"`
	StageRun      string            `json:"stage_run,omitempty"`
	Complete      bool              `json:"complete"`
	Degraded      bool              `json:"degraded,omitempty"`
	BackendStrata map[string]string `json:"backend_strata,omitempty"`
	NextAction    NextAction        `json:"next_action"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "pass validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func Begin(ctx context.Context, options BeginOptions) (*Invocation, error) {
	config, err := normalizeBeginOptions(options)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(config.Outputs.StatePath); err == nil {
		state, err := readState(config.Outputs.StatePath)
		if err != nil {
			return nil, err
		}
		applyOutputDefaults(&state.Config)
		if mismatches := configMismatchPaths(state.Config, config); len(mismatches) > 0 {
			return nil, validationError(
				CodePassStateConfigMismatch,
				"existing pass state config does not match the requested begin options.",
				"/config",
				map[string]any{"mismatched_field_paths": mismatches},
			)
		}
		return resumeLoadedState(ctx, state, config.StateDir, config.Outputs.StatePath)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fileError(err, config.Outputs.StatePath, "open pass state")
	}
	state := &State{
		SchemaVersion: StateSchemaVersion,
		DigestProfile: digest.Profile,
		StateDir:      config.StateDir,
		Config:        config,
	}
	return advance(ctx, state)
}

func Resume(ctx context.Context, options ResumeOptions) (*Invocation, error) {
	if strings.TrimSpace(options.StateDir) == "" {
		return nil, diag.New(CodeMissingStateDir, "witness pass resume requires -state-dir.")
	}
	stateDir, err := absPath(options.StateDir)
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(stateDir, StateFileName)
	state, err := readState(statePath)
	if err != nil {
		return nil, err
	}
	return resumeLoadedState(ctx, state, stateDir, statePath)
}

func resumeLoadedState(ctx context.Context, state *State, stateDir string, statePath string) (*Invocation, error) {
	applyOutputDefaults(&state.Config)
	if err := validateResumeStateBinding(state, stateDir, statePath); err != nil {
		return nil, err
	}
	if err := rejectDriverOutputAliases(state.Config); err != nil {
		return nil, err
	}
	if err := validateLoadedState(state); err != nil {
		return nil, err
	}
	return advance(ctx, state)
}

func validateResumeStateBinding(state *State, stateDir string, statePath string) error {
	if state == nil {
		return validationError(CodeStateInvalid, "pass state is empty.", "", nil)
	}
	if filepath.Clean(stateDir) != filepath.Clean(state.Config.StateDir) {
		return validationError(
			CodeStateInvalid,
			"resolved resume state directory does not match the persisted pass config.",
			"/config/state_dir",
			map[string]any{"actual_state_dir": filepath.Clean(stateDir), "persisted_state_dir": filepath.Clean(state.Config.StateDir)},
		)
	}
	if filepath.Clean(statePath) != filepath.Clean(state.Config.Outputs.StatePath) {
		return validationError(
			CodeStateInvalid,
			"resolved pass state file path does not match the persisted pass config.",
			"/config/outputs/state_path",
			map[string]any{"actual_state_path": filepath.Clean(statePath), "persisted_state_path": filepath.Clean(state.Config.Outputs.StatePath)},
		)
	}
	return nil
}

func (invocation *Invocation) HumanSummary() string {
	if invocation == nil {
		return ""
	}
	return invocation.NextAction.Summary
}

func advance(ctx context.Context, state *State) (*Invocation, error) {
	if !stageComplete(state, stageFreeze) {
		if err := runFreeze(ctx, state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stageFreeze)
	}
	if !stageComplete(state, stagePreflight) {
		if err := runPreflight(ctx, state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stagePreflight)
	}
	if missing := missingRoleOutputs(state); len(missing) > 0 {
		if err := setRoleOutputAction(state, missing); err != nil {
			return nil, err
		}
		return saveAndReport(state, "")
	}
	if !stageComplete(state, stagePlan) {
		if err := runPlan(state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stagePlan)
	}
	if batch := nextRelayBatchAction(state); batch != nil {
		setRelayBatchAction(state, batch)
		return saveAndReport(state, "")
	}
	if !stageComplete(state, stageAssemble) {
		if err := runAssemble(state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stageAssemble)
	}
	if !stageComplete(state, stageAdjudicate) {
		if err := runAdjudicate(state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stageAdjudicate)
	}
	if !stageComplete(state, stageMetrics) {
		if err := runMetrics(state); err != nil {
			return nil, err
		}
		return saveAndReport(state, stageMetrics)
	}
	state.Complete = true
	setCompleteAction(state)
	return saveAndReport(state, "")
}

func saveAndReport(state *State, stageRun string) (*Invocation, error) {
	if state.NextAction.Type == "" || stageRun != "" {
		if err := setNextAction(state); err != nil {
			return nil, err
		}
	}
	if err := writeState(state); err != nil {
		return nil, err
	}
	preflightResult, _ := readPreflightResult(state.Config.Outputs.PreflightPath)
	backendStrata := cloneStringMap(preflightResult.BackendStrata)
	degraded := preflight.RelayAbsent(preflightResult)
	return &Invocation{
		SchemaVersion: InvocationSchemaVersion,
		DigestProfile: digest.Profile,
		PassState: ArtifactRecord{
			Role:        "pass-state",
			Path:        state.Config.Outputs.StatePath,
			Digest:      state.StateDigest,
			DigestClass: digestClassPassState,
		},
		StageRun:      stageRun,
		Complete:      state.Complete,
		Degraded:      degraded,
		BackendStrata: backendStrata,
		NextAction:    state.NextAction,
	}, nil
}

func runFreeze(ctx context.Context, state *State) error {
	config := state.Config
	input, err := charter.ReadFile(config.CharterPath)
	if err != nil {
		return err
	}
	var amendments []charter.OwnerEvent
	if config.AmendmentsPath != "" {
		amendments, err = charter.ReadAmendmentsFile(config.AmendmentsPath)
		if err != nil {
			return err
		}
	}
	frozen, err := charter.Freeze(input, amendments)
	if err != nil {
		return err
	}
	if err := writeCanonicalFile(config.Outputs.CharterFreezePath, frozen); err != nil {
		return err
	}
	snapshot, err := freeze.Create(ctx, freeze.Options{
		SourceDir:   config.SourceDir,
		OutputDir:   config.SnapshotDir,
		AllowNonGit: config.AllowNonGitSource,
	})
	if err != nil {
		return err
	}
	inputs, err := artifactRecordsForExistingFiles([]artifactInput{
		{role: "charter", path: config.CharterPath, digestClass: digest.ClassRawBytes},
		{role: "amendments", path: config.AmendmentsPath, digestClass: digest.ClassRawBytes},
	})
	if err != nil {
		return err
	}
	outputs, err := artifactRecordsForExistingFiles([]artifactInput{
		{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digest.ClassRawBytes},
		{role: "source-snapshot-manifest", path: snapshot.ManifestPath, digestClass: digestClassFreezeManifest},
	})
	if err != nil {
		return err
	}
	markStageComplete(state, StageRecord{
		Name:    stageFreeze,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"charter_hash":           frozen.CharterHash,
			"snapshot_digest":        snapshot.ManifestDigest,
			"snapshot_manifest_path": snapshot.ManifestPath,
		},
	})
	return nil
}

func runPreflight(ctx context.Context, state *State) error {
	config := state.Config
	if err := validateEffectiveHeadManifest(config); err != nil {
		return err
	}
	result, err := preflight.Run(ctx, preflight.Options{
		RelayPath:              config.RelayPath,
		IntegrationBundlePath:  config.IntegrationBundlePath,
		StateDir:               config.StateDir,
		SnapshotManifestPath:   config.SnapshotManifestPath,
		ExpectedSnapshotDigest: stageOutputDigest(state, "source-snapshot-manifest"),
		ConsumerIdentity:       map[string]any{"kind": "witness", "id": "pass-driver"},
	})
	if err != nil {
		return err
	}
	if err := writeCanonicalFile(config.Outputs.PreflightPath, result); err != nil {
		return err
	}
	if err := writeRoleOutputChangeSurface(config, result.SnapshotDigest); err != nil {
		return err
	}
	inputs, err := artifactRecordsForExistingFiles([]artifactInput{
		{role: "integration-bundle", path: config.IntegrationBundlePath, digestClass: digest.ClassRawBytes},
		{role: "source-snapshot-manifest", path: config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
	})
	if err != nil {
		return err
	}
	outputs, err := artifactRecordsForExistingFiles(preflightOutputSpecs(config, result))
	if err != nil {
		return err
	}
	markStageComplete(state, StageRecord{
		Name:    stagePreflight,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"relay_absent":   preflight.RelayAbsent(*result),
			"backend_strata": cloneStringMap(result.BackendStrata),
		},
	})
	return nil
}

func runPlan(state *State) error {
	config := state.Config
	frozen, frozenBytes, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return err
	}
	preflightResult, err := readPreflightResult(config.Outputs.PreflightPath)
	if err != nil {
		return err
	}
	if err := validatePlanningPreflight(preflightResult); err != nil {
		return err
	}
	policyDocument, err := readReviewPolicy(config.PolicyPath)
	if err != nil {
		return err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, config.BaselinePass)
	if err != nil {
		return err
	}
	headManifestPath, err := effectiveHeadManifestPath(config)
	if err != nil {
		return err
	}
	roleOutputs := make([]planning.RoleOutputInput, 0, len(config.RoleOutputs))
	for _, item := range config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			return err
		}
		roleOutputs = append(roleOutputs, planning.RoleOutputInput{
			Path:     item.Path,
			RefID:    artifactIDFromPath(item.Path),
			Document: document,
		})
	}
	result, err := planning.Run(planning.Options{
		FrozenCharter: &frozen,
		CharterDigest: digest.RawBytes(frozenBytes),
		RoleOutputs:   roleOutputs,
		StateDir:      config.StateDir,
		Policy:        policyDocument,
		Preflight:     preflightBinding(preflightResult),
		ChangeSurface: changeSurface,
	})
	if err != nil {
		return err
	}
	if err := writeCanonicalFile(config.Outputs.PlanPath, result.Plan); err != nil {
		return err
	}
	inputSpecs := []artifactInput{
		{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digest.ClassRawBytes},
		{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digest.ClassRawBytes},
		{role: "policy", path: config.PolicyPath, digestClass: digest.ClassRawBytes},
		{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
		{role: "head-manifest", path: headManifestPath, digestClass: digestClassFreezeManifest},
	}
	for _, item := range config.RoleOutputs {
		inputSpecs = append(inputSpecs, artifactInput{role: "role-output:" + item.Role, path: item.Path, digestClass: digest.ClassRawBytes})
	}
	inputs, err := artifactRecordsForExistingFiles(inputSpecs)
	if err != nil {
		return err
	}
	outputSpecs := []artifactInput{{role: "verification-plan", path: config.Outputs.PlanPath, digestClass: digest.ClassRawBytes}}
	for _, batch := range result.Batches {
		outputSpecs = append(outputSpecs, artifactInput{role: "verification-batch:" + batch.Plan.BatchID, path: batch.Path, digestClass: digest.ClassRawBytes})
	}
	if result.Plan.ChangeSurface != nil {
		outputSpecs = append(outputSpecs, artifactInput{role: "change-surface", path: filepath.Join(config.StateDir, "verification", "change-surface.json"), digestClass: digest.ClassRawBytes})
	}
	outputs, err := artifactRecordsForExistingFiles(outputSpecs)
	if err != nil {
		return err
	}
	state.RelayBatches = relayBatchRecords(result.Plan, config, preflight.RelayAbsent(preflightResult))
	markStageComplete(state, StageRecord{
		Name:    stagePlan,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"plan_digest":    result.Plan.PlanDigest,
			"batch_count":    len(result.Plan.Batches),
			"relay_absent":   preflight.RelayAbsent(preflightResult),
			"backend_strata": cloneStringMap(preflightResult.BackendStrata),
		},
	})
	return nil
}

func runAssemble(state *State) error {
	config := state.Config
	plan, err := readPlan(config.Outputs.PlanPath)
	if err != nil {
		return err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, false)
	if err != nil {
		return err
	}
	headManifestPath, err := effectiveHeadManifestPath(config)
	if err != nil {
		return err
	}
	relayRecords, err := relayBatchRecordsFromValidatedPlan(state)
	if err != nil {
		return err
	}
	state.RelayBatches = relayRecords
	batches, err := readBatchEvidence(relayRecords)
	if err != nil {
		return err
	}
	relayEvidence := relayEvidenceFromReadyBatches(state, relayRecords)
	receipts, err := readReceipts(config.ReceiptPaths)
	if err != nil {
		return err
	}
	refs, err := manifestEvidenceRefs(config, plan.ConsumerIdentity)
	if err != nil {
		return err
	}
	result, err := planning.Assemble(planning.AssembleOptions{
		Plan:               plan,
		Batches:            batches,
		RelayResults:       relayEvidence,
		Receipts:           receipts,
		EvidenceRefs:       refs,
		BaseManifest:       changeSurface.BaseManifest,
		HeadManifest:       changeSurface.HeadManifest,
		ReceiptOutputDir:   config.ReceiptOutputDir,
		ReceiptHMACKeyFile: config.ReceiptHMACKeyFile,
	})
	if result != nil {
		if writeErr := writeAssembleArtifacts(config, result); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		return err
	}
	inputSpecs := []artifactInput{
		{role: "verification-plan", path: config.Outputs.PlanPath, digestClass: digest.ClassRawBytes},
		{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digest.ClassRawBytes},
		{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digest.ClassRawBytes},
		{role: "integration-bundle-retained", path: filepath.Join(config.StateDir, "integration-bundle.json"), digestClass: digest.ClassRawBytes},
		{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
		{role: "head-manifest", path: headManifestPath, digestClass: digestClassFreezeManifest},
	}
	for _, batch := range relayRecords {
		inputSpecs = append(inputSpecs, artifactInput{role: "verification-batch:" + batch.BatchID, path: batch.BatchPath, digestClass: digest.ClassRawBytes})
		if portableExportReady(batch.PortableExportDir) {
			inputSpecs = append(inputSpecs, artifactInput{role: "portable-export:" + batch.BatchID, path: filepath.Join(batch.PortableExportDir, "manifest.json"), digestClass: digest.ClassRawBytes})
		}
	}
	for _, path := range config.ReceiptPaths {
		inputSpecs = append(inputSpecs, artifactInput{role: "receipt", path: path, digestClass: digest.ClassRawBytes})
	}
	receiptInputs, err := receiptArtifactInputs(config, receipts)
	if err != nil {
		return err
	}
	inputSpecs = append(inputSpecs, receiptInputs...)
	inputs, err := artifactRecordsForExistingFiles(inputSpecs)
	if err != nil {
		return err
	}
	outputs, err := artifactRecordsForExistingFiles(assembleOutputSpecs(config, result))
	if err != nil {
		return err
	}
	manifestDigest, err := contracts.VerificationManifestDigest(result.Manifest)
	if err != nil {
		return err
	}
	markStageComplete(state, StageRecord{
		Name:    stageAssemble,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"manifest_digest":               manifestDigest,
			"pending_count":                 len(result.PendingVerification),
			"unverified_relationship_count": len(result.UnverifiedRelationships),
		},
	})
	return nil
}

func runAdjudicate(state *State) error {
	config := state.Config
	frozen, _, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return err
	}
	manifest, err := readVerificationManifest(config.Outputs.ManifestPath)
	if err != nil {
		return err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, false)
	if err != nil {
		return err
	}
	headManifestPath, err := effectiveHeadManifestPath(config)
	if err != nil {
		return err
	}
	roleOutputs := make([]adjudicate.RoleOutputInput, 0, len(config.RoleOutputs))
	for _, item := range config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			return err
		}
		roleOutputs = append(roleOutputs, adjudicate.RoleOutputInput{Path: item.Path, Document: document})
	}
	var priorLineage []adjudicate.PriorLineageRecord
	priorProvided := config.PriorLineagePath != ""
	if priorProvided {
		priorLineage, err = adjudicate.ReadPriorLineageFile(config.PriorLineagePath)
		if err != nil {
			return err
		}
	}
	effective, err := loadEffectivePolicy(config)
	if err != nil {
		return err
	}
	service, err := RunAdjudicationService(AdjudicationOptions{
		FrozenCharter:                frozen,
		RoleOutputs:                  roleOutputs,
		Manifest:                     manifest,
		BaseManifest:                 changeSurface.BaseManifest,
		HeadManifest:                 changeSurface.HeadManifest,
		LedgerPath:                   config.LedgerPath,
		ReceiptOutputDir:             config.ReceiptOutputDir,
		ReceiptHMACKeyFile:           config.ReceiptHMACKeyFile,
		Rules:                        effective.Rules,
		Policy:                       effective.Policy,
		PolicyCapReleaseLedgerBacked: effective.CapRelease != nil,
		PriorLineage:                 priorLineage,
		PriorLineageProvided:         priorProvided,
		DriverResumeMode:             true,
	})
	if err != nil {
		return err
	}
	result := service.Result
	if result != nil {
		if writeErr := writeCanonicalFile(config.Outputs.RunResultPath, result); writeErr != nil {
			return writeErr
		}
	}
	if service.RunErr != nil {
		return service.RunErr
	}
	if result == nil {
		return diag.New(CodeInvalidState, "adjudication did not produce a run result.")
	}
	inputSpecs := []artifactInput{
		{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digest.ClassRawBytes},
		{role: "verification-manifest", path: config.Outputs.ManifestPath, digestClass: digest.ClassRawBytes},
		{role: "policy", path: config.PolicyPath, digestClass: digest.ClassRawBytes},
		{role: "rules", path: config.RulesPath, digestClass: digest.ClassRawBytes},
		{role: "ledger", path: config.LedgerPath, digestClass: digest.ClassRawBytes},
		{role: "prior-lineage", path: config.PriorLineagePath, digestClass: digest.ClassRawBytes},
		{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
		{role: "head-manifest", path: headManifestPath, digestClass: digestClassFreezeManifest},
	}
	for _, item := range config.RoleOutputs {
		inputSpecs = append(inputSpecs, artifactInput{role: "role-output:" + item.Role, path: item.Path, digestClass: digest.ClassRawBytes})
	}
	inputs, err := artifactRecordsForExistingFiles(inputSpecs)
	if err != nil {
		return err
	}
	outputs, err := artifactRecordsForExistingFiles([]artifactInput{{role: "run-result", path: config.Outputs.RunResultPath, digestClass: digest.ClassRawBytes}})
	if err != nil {
		return err
	}
	markStageComplete(state, StageRecord{
		Name:    stageAdjudicate,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
		Details: map[string]any{
			"result_digest": result.ResultDigest,
		},
	})
	return nil
}

func runMetrics(state *State) error {
	config := state.Config
	document, err := metrics.Run(metrics.Options{
		LedgerPath:     config.LedgerPath,
		PreflightPath:  config.Outputs.PreflightPath,
		RunResultPaths: []string{config.Outputs.RunResultPath},
	})
	if err != nil {
		return err
	}
	if err := writeJSONFile(config.Outputs.MetricsPath, document); err != nil {
		return err
	}
	inputSpecs := []artifactInput{
		{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digest.ClassRawBytes},
		{role: "run-result", path: config.Outputs.RunResultPath, digestClass: digest.ClassRawBytes},
		{role: "ledger", path: config.LedgerPath, digestClass: digest.ClassRawBytes},
	}
	inputs, err := artifactRecordsForExistingFiles(inputSpecs)
	if err != nil {
		return err
	}
	outputs, err := artifactRecordsForExistingFiles([]artifactInput{{role: "metrics", path: config.Outputs.MetricsPath, digestClass: digest.ClassRawBytes}})
	if err != nil {
		return err
	}
	markStageComplete(state, StageRecord{
		Name:    stageMetrics,
		Status:  statusComplete,
		Inputs:  inputs,
		Outputs: outputs,
	})
	state.Complete = true
	return nil
}

func normalizeBeginOptions(options BeginOptions) (Config, error) {
	if strings.TrimSpace(options.StateDir) == "" {
		return Config{}, diag.New(CodeMissingStateDir, "witness pass begin requires -state-dir.")
	}
	if strings.TrimSpace(options.CharterPath) == "" {
		return Config{}, diag.New(CodeMissingCharter, "witness pass begin requires -charter.")
	}
	if strings.TrimSpace(options.SourceDir) == "" {
		return Config{}, diag.New(CodeMissingSource, "witness pass begin requires -source-dir.")
	}
	if strings.TrimSpace(options.IntegrationBundlePath) == "" {
		return Config{}, diag.New(CodeMissingBundle, "witness pass begin requires -integration-bundle.")
	}
	stateDir, err := absPath(options.StateDir)
	if err != nil {
		return Config{}, err
	}
	sourceDir, err := absPath(options.SourceDir)
	if err != nil {
		return Config{}, err
	}
	if stateDirInsideSource(sourceDir, stateDir) {
		return Config{}, diag.New(
			CodeStateDirInsideSource,
			"pass state directory must resolve outside the reviewed source tree.",
			diag.WithDetail("source_dir", sourceDir),
			diag.WithDetail("state_dir", stateDir),
		)
	}
	snapshotDir := options.SnapshotDir
	if strings.TrimSpace(snapshotDir) == "" {
		snapshotDir = filepath.Join(stateDir, "source-snapshot")
	}
	snapshotDir, err = absPath(snapshotDir)
	if err != nil {
		return Config{}, err
	}
	config := Config{
		StateDir:             stateDir,
		SourceDir:            sourceDir,
		SnapshotDir:          snapshotDir,
		SnapshotManifestPath: filepath.Join(snapshotDir, "manifest.json"),
		AllowNonGitSource:    options.AllowNonGitSource,
		Backend:              strings.TrimSpace(options.Backend),
		BaselinePass:         options.BaselinePass,
		Outputs: Outputs{
			StatePath:          filepath.Join(stateDir, StateFileName),
			CharterFreezePath:  filepath.Join(stateDir, "charter.freeze.json"),
			PreflightPath:      filepath.Join(stateDir, "preflight.json"),
			PlanPath:           filepath.Join(stateDir, "verification-plan.json"),
			ManifestPath:       filepath.Join(stateDir, "verification", "index.json"),
			AssembleResultPath: filepath.Join(stateDir, "verification", "assemble-result.json"),
			RunResultPath:      filepath.Join(stateDir, "verdict.json"),
			MetricsPath:        filepath.Join(stateDir, "metrics.json"),
		},
	}
	for _, assign := range []struct {
		value *string
		input string
	}{
		{&config.CharterPath, options.CharterPath},
		{&config.AmendmentsPath, options.AmendmentsPath},
		{&config.RelayPath, options.RelayPath},
		{&config.IntegrationBundlePath, options.IntegrationBundlePath},
		{&config.PolicyPath, options.PolicyPath},
		{&config.RulesPath, options.RulesPath},
		{&config.LedgerPath, options.LedgerPath},
		{&config.BaseManifestPath, options.BaseManifestPath},
		{&config.HeadManifestPath, options.HeadManifestPath},
		{&config.PriorLineagePath, options.PriorLineagePath},
		{&config.ReceiptOutputDir, options.ReceiptOutputDir},
		{&config.ReceiptHMACKeyFile, options.ReceiptHMACKeyFile},
	} {
		path, err := optionalAbsPath(assign.input)
		if err != nil {
			return Config{}, err
		}
		*assign.value = path
	}
	config.RoleOutputs, err = normalizeRoleOutputs(options.RoleOutputs, stateDir)
	if err != nil {
		return Config{}, err
	}
	for _, path := range options.ReceiptPaths {
		absolute, err := optionalAbsPath(path)
		if err != nil {
			return Config{}, err
		}
		if absolute != "" {
			config.ReceiptPaths = append(config.ReceiptPaths, absolute)
		}
	}
	if err := rejectDriverOutputAliases(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func normalizeRoleOutputs(inputs []RoleOutputSpec, stateDir string) ([]RoleOutputSpec, error) {
	if len(inputs) == 0 {
		inputs = []RoleOutputSpec{
			{Role: contracts.RoleDefect},
			{Role: contracts.RoleEconomy},
		}
	}
	seen := map[string]bool{}
	outputs := make([]RoleOutputSpec, 0, len(inputs))
	for _, input := range inputs {
		role := strings.TrimSpace(input.Role)
		switch role {
		case contracts.RoleDefect, contracts.RoleEconomy, contracts.RoleGoalFit:
		default:
			return nil, diag.New(CodeInvalidRoleOutputSpec, "pass role-output specs require a supported role.", diag.WithDetail("role", input.Role))
		}
		if seen[role] {
			return nil, diag.New(CodeInvalidRoleOutputSpec, "pass role-output specs must not repeat a role.", diag.WithDetail("role", role))
		}
		path := strings.TrimSpace(input.Path)
		if path == "" {
			path = filepath.Join(roleOutputDir(Config{StateDir: stateDir}), role+"-output.json")
		}
		absolute, err := absPath(path)
		if err != nil {
			return nil, err
		}
		seen[role] = true
		outputs = append(outputs, RoleOutputSpec{Role: role, Path: absolute})
	}
	sort.SliceStable(outputs, func(i, j int) bool {
		if roleRank(outputs[i].Role) != roleRank(outputs[j].Role) {
			return roleRank(outputs[i].Role) < roleRank(outputs[j].Role)
		}
		return outputs[i].Path < outputs[j].Path
	})
	return outputs, nil
}

func roleRank(role string) int {
	switch role {
	case contracts.RoleDefect:
		return 0
	case contracts.RoleEconomy:
		return 1
	case contracts.RoleGoalFit:
		return 2
	default:
		return 3
	}
}

func stateDirInsideSource(sourceDir string, stateDir string) bool {
	rel, err := filepath.Rel(filepath.Clean(sourceDir), filepath.Clean(stateDir))
	if err != nil || rel == "." || rel == "" {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func setNextAction(state *State) error {
	if !stageComplete(state, stageFreeze) ||
		!stageComplete(state, stagePreflight) ||
		!stageComplete(state, stagePlan) ||
		!stageComplete(state, stageAssemble) ||
		!stageComplete(state, stageAdjudicate) ||
		!stageComplete(state, stageMetrics) {
		if missing := missingRoleOutputs(state); len(missing) > 0 && stageComplete(state, stagePreflight) {
			return setRoleOutputAction(state, missing)
		}
		if batch := nextRelayBatchAction(state); batch != nil && stageComplete(state, stagePlan) {
			setRelayBatchAction(state, batch)
			return nil
		}
		setWitnessCommandAction(state)
		return nil
	}
	state.Complete = true
	setCompleteAction(state)
	return nil
}

func setWitnessCommandAction(state *State) {
	command := []string{"witness", "pass", "resume", "-state-dir", state.Config.StateDir}
	state.NextAction = NextAction{
		Type:    actionWitnessCommand,
		Command: command,
		Summary: strings.Join(command, " "),
	}
	addDegradedActionContext(state)
}

func setRoleOutputAction(state *State, missing []RoleOutputSpec) error {
	requests := make([]RoleOutputRequest, 0, len(missing))
	for _, item := range missing {
		requests = append(requests, RoleOutputRequest{Role: item.Role, Path: item.Path})
	}
	scopePolicy, err := nextActionScopePolicy(state.Config)
	if err != nil {
		return err
	}
	changeSurfacePath, changeSurfaceDigest, err := roleOutputChangeSurfaceActionRef(state, scopePolicy)
	if err != nil {
		return err
	}
	snapshotDigest := stageOutputDigest(state, "source-snapshot-manifest")
	charterHash := currentCharterHash(state.Config)
	state.NextAction = NextAction{
		Type:                 actionCallerRoleOutputs,
		Roles:                requests,
		ScopePolicy:          scopePolicy,
		ChangeSurfacePath:    changeSurfacePath,
		ChangeSurfaceDigest:  changeSurfaceDigest,
		SnapshotDigest:       snapshotDigest,
		SnapshotManifestPath: state.Config.SnapshotManifestPath,
		CharterHash:          charterHash,
		CharterFreezePath:    state.Config.Outputs.CharterFreezePath,
		Summary:              roleOutputSummary(requests, snapshotDigest),
	}
	addDegradedActionContext(state)
	return nil
}

func setRelayBatchAction(state *State, batch *RelayBatchAction) {
	state.NextAction = NextAction{
		Type:       actionCallerRelayBatch,
		RelayBatch: batch,
		Summary:    fmt.Sprintf("run relay batch %s with recipe %s into %s", batch.BatchID, batch.RecipeID, batch.PortableExportDir),
	}
	addDegradedActionContext(state)
}

func setCompleteAction(state *State) {
	state.NextAction = NextAction{
		Type:    actionComplete,
		Summary: "pass complete",
	}
	addDegradedActionContext(state)
}

func roleOutputSummary(requests []RoleOutputRequest, snapshotDigest string) string {
	parts := make([]string, 0, len(requests))
	for _, request := range requests {
		parts = append(parts, request.Role+"="+request.Path)
	}
	return fmt.Sprintf("produce role outputs for roles %s at snapshot digest %s", strings.Join(parts, ","), snapshotDigest)
}

func addDegradedActionContext(state *State) {
	preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath)
	if err != nil {
		return
	}
	state.NextAction.BackendStrata = cloneStringMap(preflightResult.BackendStrata)
	if preflight.RelayAbsent(preflightResult) {
		state.NextAction.Degraded = true
	}
}

func missingRoleOutputs(state *State) []RoleOutputSpec {
	if !stageComplete(state, stagePreflight) || stageComplete(state, stagePlan) {
		return nil
	}
	var missing []RoleOutputSpec
	for _, item := range state.Config.RoleOutputs {
		if _, err := os.Stat(item.Path); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, item)
			}
		}
	}
	return missing
}

func nextRelayBatchAction(state *State) *RelayBatchAction {
	if !stageComplete(state, stagePlan) || stageComplete(state, stageAssemble) {
		return nil
	}
	preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath)
	if err == nil && preflight.RelayAbsent(preflightResult) {
		if records, deriveErr := relayBatchRecordsFromValidatedPlan(state); deriveErr == nil {
			state.RelayBatches = records
		} else {
			markRelayBatchesNotRequired(state)
		}
		return nil
	}
	records, err := relayBatchRecordsFromValidatedPlan(state)
	if err != nil {
		return nil
	}
	state.RelayBatches = records
	for index := range state.RelayBatches {
		batch := &state.RelayBatches[index]
		if batch.Status == statusNotRequired {
			continue
		}
		if portableExportReady(batch.PortableExportDir) {
			batch.Status = statusComplete
			continue
		}
		batch.Status = statusPending
		charterDigest := stageOutputDigest(state, "charter-freeze")
		snapshotDigest := stageOutputDigest(state, "source-snapshot-manifest")
		integrationBundlePath := retainedIntegrationBundlePath(state.Config)
		integrationBundleDigest := preflightResult.ContractDigests["integration_bundle"]
		return &RelayBatchAction{
			BatchID:                 batch.BatchID,
			RecipeID:                batch.RecipeID,
			RecipeFamily:            batch.RecipeFamily,
			Backend:                 state.Config.Backend,
			BatchPath:               batch.BatchPath,
			BatchDigest:             batch.BatchDigest,
			PortableExportDir:       batch.PortableExportDir,
			IntegrationBundlePath:   integrationBundlePath,
			IntegrationBundleDigest: integrationBundleDigest,
			CharterDigest:           charterDigest,
			SnapshotDigest:          snapshotDigest,
			InputBindings: []string{
				boundInput("charter", state.Config.Outputs.CharterFreezePath, charterDigest),
				boundInput("findings", batch.BatchPath, batch.BatchDigest),
				boundInput("artifact", state.Config.SnapshotManifestPath, snapshotDigest),
				boundInput("integration_bundle", integrationBundlePath, integrationBundleDigest),
			},
		}
	}
	return nil
}

func markRelayBatchesNotRequired(state *State) {
	for index := range state.RelayBatches {
		state.RelayBatches[index].Status = statusNotRequired
	}
}

func relayBatchRecords(plan planning.PlanDocument, config Config, relayAbsent bool) []RelayBatchRecord {
	records := make([]RelayBatchRecord, 0, len(plan.Batches))
	for _, batch := range plan.Batches {
		status := statusPending
		if relayAbsent {
			status = statusNotRequired
		}
		records = append(records, RelayBatchRecord{
			BatchID:           batch.BatchID,
			Role:              batch.Role,
			TaskShape:         batch.TaskShape,
			RecipeFamily:      batch.RecipeFamily,
			RecipeID:          recipeID(batch.TaskShape, config.Backend),
			BatchPath:         filepath.Join(config.StateDir, "verification", "batches", batch.BatchID+".json"),
			BatchDigest:       batch.BatchDigest,
			PortableExportDir: filepath.Join(config.StateDir, "verification", "sessions", batch.BatchID),
			Status:            status,
		})
	}
	return records
}

func relayBatchRecordsFromValidatedPlan(state *State) ([]RelayBatchRecord, error) {
	plan, err := readPlan(state.Config.Outputs.PlanPath)
	if err != nil {
		return nil, err
	}
	relayAbsent := false
	if preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath); err == nil {
		relayAbsent = preflight.RelayAbsent(preflightResult)
	}
	records := relayBatchRecords(plan, state.Config, relayAbsent)
	for index := range records {
		if records[index].Status == statusNotRequired {
			continue
		}
		if portableExportReady(records[index].PortableExportDir) {
			records[index].Status = statusComplete
		}
	}
	return records, nil
}

func recipeID(taskShape string, backend string) string {
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

func portableExportReady(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(path, "manifest.json"))
	return err == nil && !info.IsDir()
}

func relayEvidenceFromReadyBatches(state *State, records []RelayBatchRecord) []planning.RelayEvidence {
	preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath)
	if err == nil && preflight.RelayAbsent(preflightResult) {
		return nil
	}
	var evidence []planning.RelayEvidence
	for _, batch := range records {
		if !portableExportReady(batch.PortableExportDir) {
			continue
		}
		evidence = append(evidence, planning.RelayEvidence{
			BatchID:           batch.BatchID,
			RecipeFamily:      batch.RecipeFamily,
			Backend:           state.Config.Backend,
			PortableExportDir: batch.PortableExportDir,
		})
	}
	return evidence
}

func readBatchEvidence(records []RelayBatchRecord) ([]planning.BatchEvidence, error) {
	batches := make([]planning.BatchEvidence, 0, len(records))
	for _, record := range records {
		data, err := os.ReadFile(record.BatchPath)
		if err != nil {
			return nil, fileError(err, record.BatchPath, "open verification batch")
		}
		document, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			return nil, err
		}
		batches = append(batches, planning.BatchEvidence{
			BatchID:  document.BatchID,
			Document: document,
			Path:     record.BatchPath,
			RawBytes: append([]byte(nil), data...),
		})
	}
	return batches, nil
}

func markStageComplete(state *State, stage StageRecord) {
	replaced := false
	for index := range state.Stages {
		if state.Stages[index].Name == stage.Name {
			state.Stages[index] = stage
			replaced = true
			break
		}
	}
	if !replaced {
		state.Stages = append(state.Stages, stage)
	}
	sort.SliceStable(state.Stages, func(i, j int) bool {
		return stageOrder(state.Stages[i].Name) < stageOrder(state.Stages[j].Name)
	})
	state.NextAction = NextAction{}
}

func stageOrder(stage string) int {
	for index, item := range orderedStages {
		if item == stage {
			return index
		}
	}
	return len(orderedStages)
}

func stageComplete(state *State, name string) bool {
	for _, stage := range state.Stages {
		if stage.Name == name {
			return stage.Status == statusComplete
		}
	}
	return false
}

func stageDetailString(state *State, stageName string, key string) string {
	for _, stage := range state.Stages {
		if stage.Name != stageName {
			continue
		}
		value, _ := stage.Details[key].(string)
		return strings.TrimSpace(value)
	}
	return ""
}

func currentCharterHash(config Config) string {
	frozen, _, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(frozen.CharterHash)
}

func readState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fileError(err, path, "open pass state")
	}
	state, err := strictjson.DecodeBytes[State](data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return nil, err
	}
	if state.SchemaVersion != StateSchemaVersion {
		return nil, validationError(CodeStateUnsupported, "pass state schema_version is unsupported.", "/schema_version", map[string]any{"expected": StateSchemaVersion, "actual": state.SchemaVersion})
	}
	if state.DigestProfile != digest.Profile {
		return nil, validationError(CodeStateUnsupported, "pass state digest_profile is unsupported.", "/digest_profile", map[string]any{"expected": digest.Profile, "actual": state.DigestProfile})
	}
	expected := strings.TrimSpace(state.StateDigest)
	if expected == "" {
		return nil, validationError(CodeStateDigestMismatch, "pass state is missing its state_digest.", "/state_digest", nil)
	}
	actual, err := stateDigest(state)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, validationError(CodeStateDigestMismatch, "pass state self digest does not match the canonical state document.", "/state_digest", map[string]any{"actual_digest": actual, "expected_digest": expected})
	}
	return &state, nil
}

func writeState(state *State) error {
	state.SchemaVersion = StateSchemaVersion
	state.DigestProfile = digest.Profile
	applyOutputDefaults(&state.Config)
	state.StateDir = state.Config.StateDir
	value, err := stateDigest(*state)
	if err != nil {
		return err
	}
	state.StateDigest = value
	return writeCanonicalFile(state.Config.Outputs.StatePath, state)
}

func stateDigest(state State) (string, error) {
	state.StateDigest = ""
	return digest.SemanticJSON(state)
}

func configMismatchPaths(existing Config, current Config) []string {
	var paths []string
	collectConfigMismatches(reflect.ValueOf(existing), reflect.ValueOf(current), reflect.TypeOf(existing), "/config", &paths)
	sort.Strings(paths)
	return paths
}

func collectConfigMismatches(left reflect.Value, right reflect.Value, valueType reflect.Type, path string, paths *[]string) {
	switch valueType.Kind() {
	case reflect.Struct:
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			if field.PkgPath != "" {
				continue
			}
			name := jsonFieldName(field)
			if name == "-" {
				continue
			}
			collectConfigMismatches(left.Field(index), right.Field(index), field.Type, path+"/"+jsonPointerEscape(name), paths)
		}
	case reflect.Slice:
		if left.Len() != right.Len() {
			*paths = append(*paths, path)
			return
		}
		for index := 0; index < left.Len(); index++ {
			collectConfigMismatches(left.Index(index), right.Index(index), valueType.Elem(), fmt.Sprintf("%s/%d", path, index), paths)
		}
		if left.IsNil() != right.IsNil() && left.Len() == 0 {
			*paths = append(*paths, path)
		}
	default:
		if !reflect.DeepEqual(left.Interface(), right.Interface()) {
			*paths = append(*paths, path)
		}
	}
}

func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return field.Name
	}
	return name
}

func jsonPointerEscape(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

type artifactInput struct {
	role        string
	path        string
	digestClass string
}

func artifactRecordsForExistingFiles(inputs []artifactInput) ([]ArtifactRecord, error) {
	records := make([]ArtifactRecord, 0, len(inputs))
	for _, input := range inputs {
		if strings.TrimSpace(input.path) == "" {
			continue
		}
		if _, err := os.Stat(input.path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fileError(err, input.path, "stat artifact")
		}
		value, err := computeArtifactDigest(input.path, input.digestClass)
		if err != nil {
			return nil, err
		}
		records = append(records, ArtifactRecord{
			Role:        input.role,
			Path:        input.path,
			Digest:      value,
			DigestClass: input.digestClass,
		})
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Role != records[j].Role {
			return records[i].Role < records[j].Role
		}
		return records[i].Path < records[j].Path
	})
	return records, nil
}

func computeArtifactDigest(path string, digestClass string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	switch digestClass {
	case "", digest.ClassRawBytes:
		return digest.RawBytes(data), nil
	case digest.ClassSemanticJSON:
		value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return digest.SemanticJSON(value)
	case digestClassFreezeManifest:
		manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
		if err != nil {
			return "", err
		}
		return freeze.ManifestDigest(manifest)
	default:
		return "", diag.New(diag.CodeUnsupportedDigest, "unsupported pass artifact digest class.", diag.WithDetail("digest_class", digestClass))
	}
}

func validatePlanningPreflight(result preflight.Result) error {
	if result.SchemaVersion != preflight.SchemaVersion {
		return diag.New(CodeInvalidPreflight, "verification preflight result schema_version is not supported.", diag.WithDetail("expected", preflight.SchemaVersion), diag.WithDetail("actual", result.SchemaVersion))
	}
	if !result.OK {
		return diag.New(CodeInvalidPreflight, "verification preflight result did not pass.", diag.WithDetail("diagnostic_count", len(result.Diagnostics)))
	}
	if len(result.Diagnostics) > 0 {
		return diag.New(CodeInvalidPreflight, "verification preflight result contains blocking diagnostics.", diag.WithDetail("diagnostics", result.Diagnostics))
	}
	binding := preflightBinding(result)
	var missing []string
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "snapshot_digest", value: binding.SnapshotDigest},
		{label: "compatibility_manifest", value: binding.CompatibilityDigest},
		{label: "relay_capabilities", value: binding.RelayCapabilitiesDigest},
		{label: "integration_bundle", value: binding.IntegrationBundleDigest},
	} {
		if strings.TrimSpace(item.value) == "" {
			missing = append(missing, item.label)
		}
	}
	if len(missing) > 0 {
		return diag.New(CodeInvalidPreflight, "verification preflight result is missing required pass-binding digests.", diag.WithDetail("missing", missing))
	}
	return nil
}

func preflightBinding(result preflight.Result) planning.PreflightBinding {
	return planning.PreflightBinding{
		SnapshotDigest:          result.SnapshotDigest,
		CompatibilityDigest:     result.ArtifactDigests["compatibility-manifest.json"],
		RelayCapabilitiesDigest: result.ArtifactDigests["relay-capabilities.json"],
		IntegrationBundleDigest: result.ContractDigests["integration_bundle"],
	}
}

func manifestEvidenceRefs(config Config, consumerIdentity map[string]any) (planning.ManifestEvidenceRefs, error) {
	refs := planning.ManifestEvidenceRefs{ConsumerIdentity: cloneMap(consumerIdentity)}
	compatibilityPath := filepath.Join(config.StateDir, "compatibility-manifest.json")
	capabilitiesPath := filepath.Join(config.StateDir, "relay-capabilities.json")
	integrationBundlePath := filepath.Join(config.StateDir, "integration-bundle.json")
	var err error
	refs.CompatibilityManifest, err = artifactRefForFile("compatibility-manifest", compatibilityPath)
	if err != nil {
		return refs, err
	}
	compatibility, err := relayCompatibilityFromArtifactFile(compatibilityPath)
	if err != nil {
		return refs, err
	}
	refs.RelayCompatibility = &compatibility
	refs.RelayCapabilities, err = artifactRefForFile("relay-capabilities", capabilitiesPath)
	if err != nil {
		return refs, err
	}
	refs.IntegrationBundle, err = artifactRefForFile("integration-bundle", integrationBundlePath)
	if err != nil {
		return refs, err
	}
	selected, evidence, err := selectedContractRefsAndEvidenceForFile(integrationBundlePath)
	if err != nil {
		return refs, err
	}
	refs.SelectedContracts = selected
	refs.SelectedContractEvidence = evidence
	return refs, nil
}

func artifactRefForFile(kind string, path string) (contracts.ArtifactRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.ArtifactRef{}, fileError(err, path, "open artifact reference source")
	}
	refDigest := digest.RawBytes(data)
	if value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32); err == nil {
		if object, ok := value.(map[string]any); ok {
			if payloadDigest, ok := object["payload_digest"].(string); ok && strings.TrimSpace(payloadDigest) != "" {
				payload, hasPayload := object["payload"]
				if !hasPayload {
					return contracts.ArtifactRef{}, diag.New(diag.CodeInvalidCommand, "retained artifact payload_digest requires a retained payload.", diag.WithDetail("path", path))
				}
				payloadBytes, err := canonjson.Marshal(payload)
				if err != nil {
					return contracts.ArtifactRef{}, err
				}
				actualDigest := digest.RawBytes(payloadBytes)
				if actualDigest != strings.TrimSpace(payloadDigest) {
					return contracts.ArtifactRef{}, diag.New(diag.CodeInvalidCommand, "retained artifact payload_digest does not match the retained payload.", diag.WithDetail("path", path), diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", strings.TrimSpace(payloadDigest)))
				}
				refDigest = actualDigest
			} else if kind == "integration-bundle" {
				semanticDigest, err := digest.SemanticJSON(value)
				if err != nil {
					return contracts.ArtifactRef{}, err
				}
				refDigest = semanticDigest
			}
		}
	}
	return contracts.ArtifactRef{
		Kind:          kind,
		ID:            artifactIDFromPath(path),
		Digest:        refDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}, nil
}

func relayCompatibilityFromArtifactFile(path string) (contracts.RelayCompatibility, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.RelayCompatibility{}, fileError(err, path, "open compatibility manifest")
	}
	payloadBytes, err := retainedPayloadCanonicalBytes(data)
	if err != nil {
		return contracts.RelayCompatibility{}, err
	}
	if len(payloadBytes) == 0 {
		payloadBytes = data
	}
	return contracts.ReadRelayCompatibilityBytes(payloadBytes)
}

func retainedPayloadCanonicalBytes(data []byte) ([]byte, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil
	}
	payloadDigest, ok := object["payload_digest"].(string)
	if !ok || strings.TrimSpace(payloadDigest) == "" {
		return nil, nil
	}
	payload, hasPayload := object["payload"]
	if !hasPayload {
		return nil, diag.New(diag.CodeInvalidCommand, "retained artifact payload_digest requires a retained payload.")
	}
	payloadBytes, err := canonjson.Marshal(payload)
	if err != nil {
		return nil, err
	}
	actualDigest := digest.RawBytes(payloadBytes)
	if actualDigest != strings.TrimSpace(payloadDigest) {
		return nil, diag.New(diag.CodeInvalidCommand, "retained artifact payload_digest does not match the retained payload.", diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", strings.TrimSpace(payloadDigest)))
	}
	return payloadBytes, nil
}

func selectedContractRefsAndEvidenceForFile(path string) ([]contracts.ArtifactRef, []planning.SelectedContractEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fileError(err, path, "open selected contract evidence")
	}
	authenticated, err := planning.AuthenticatedSelectedContractsFromBytes(data)
	if err != nil {
		return nil, nil, err
	}
	refs := make([]contracts.ArtifactRef, 0, len(authenticated))
	evidence := make([]planning.SelectedContractEvidence, 0, len(authenticated))
	baseID := artifactIDFromPath(path)
	for _, contract := range authenticated {
		id := baseID
		if len(authenticated) > 1 {
			id += ":" + artifactIDFromText(contract.ContractID)
		}
		ref := contracts.ArtifactRef{
			Kind:          "selected-contract",
			ID:            id,
			Digest:        contract.ContractDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		}
		refs = append(refs, ref)
		evidence = append(evidence, planning.SelectedContractEvidence{
			Ref:        ref,
			ContractID: contract.ContractID,
			Path:       path,
			RawBytes:   append([]byte(nil), data...),
		})
	}
	return refs, evidence, nil
}

func loadEffectivePolicy(config Config) (policy.Effective, error) {
	policyDocument, err := readReviewPolicy(config.PolicyPath)
	if err != nil {
		return policy.Effective{}, err
	}
	rules, err := readReviewRules(config.RulesPath)
	if err != nil {
		return policy.Effective{}, err
	}
	records, err := ledger.ReadFile(config.LedgerPath)
	if config.LedgerPath == "" {
		records = nil
		err = nil
	}
	if err != nil {
		return policy.Effective{}, err
	}
	releases, err := ledger.CapReleases(records)
	if err != nil {
		return policy.Effective{}, err
	}
	frozen, _, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return policy.Effective{}, err
	}
	return policy.Load(policy.LoadOptions{
		Policy:      policyDocument,
		Rules:       rules,
		CharterHash: frozen.CharterHash,
		CapReleases: releases,
	})
}

func readFrozenCharter(path string) (charter.FrozenCharter, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return charter.FrozenCharter{}, nil, fileError(err, path, "open frozen Charter")
	}
	frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return charter.FrozenCharter{}, nil, err
	}
	return frozen, append([]byte(nil), data...), nil
}

func readRoleOutput(path string) (contracts.RoleOutputDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.RoleOutputDocument{}, fileError(err, path, "open role-output")
	}
	return contracts.ReadRoleOutputBytes(data)
}

func readPlan(path string) (planning.PlanDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return planning.PlanDocument{}, fileError(err, path, "open verification plan")
	}
	return strictjson.DecodeBytes[planning.PlanDocument](data, strictjson.DefaultMaxBytes*4)
}

func readVerificationManifest(path string) (contracts.VerificationManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.VerificationManifest{}, fileError(err, path, "open verification manifest")
	}
	return contracts.ReadVerificationManifestBytes(data)
}

func readPreflightResult(path string) (preflight.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return preflight.Result{}, fileError(err, path, "open verification preflight")
	}
	return strictjson.DecodeBytes[preflight.Result](data, strictjson.DefaultMaxBytes*4)
}

func readReviewPolicy(path string) (contracts.ReviewPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return contracts.DefaultReviewPolicy(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.ReviewPolicy{}, fileError(err, path, "open review policy")
	}
	return contracts.ReadReviewPolicyBytes(data)
}

func readReviewRules(path string) (contracts.ReviewRules, error) {
	if strings.TrimSpace(path) == "" {
		return contracts.DefaultReviewRules(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.ReviewRules{}, fileError(err, path, "open review rules")
	}
	return contracts.ReadReviewRulesBytes(data)
}

func nextActionScopePolicy(config Config) (string, error) {
	policyDocument, err := readReviewPolicy(config.PolicyPath)
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(policyDocument.ScopePolicy) {
	case "", contracts.ScopePolicyWholeTree:
		return contracts.ScopePolicyWholeTree, nil
	case contracts.ScopePolicyDeltaObligating:
		return contracts.ScopePolicyDeltaObligating, nil
	default:
		return "", diag.New(
			contracts.CodeInvalidPolicy,
			"scope_policy must be delta_obligating or whole_tree when set.",
			diag.WithPath("/scope_policy"),
			diag.WithDetail("value", policyDocument.ScopePolicy),
		)
	}
}

func roleOutputChangeSurfaceActionRef(state *State, scopePolicy string) (string, string, error) {
	if state == nil || scopePolicy != contracts.ScopePolicyDeltaObligating || !roleOutputChangeSurfaceExpected(state.Config) {
		return "", "", nil
	}
	path := roleOutputChangeSurfacePath(state.Config)
	document, err := readChangeSurfaceDocument(path)
	if err != nil {
		return "", "", err
	}
	surfaceDigest, err := changesurface.Digest(document)
	if err != nil {
		return "", "", err
	}
	return path, surfaceDigest, nil
}

func writeRoleOutputChangeSurface(config Config, passArtifactDigest string) error {
	document, _, err := deriveRoleOutputChangeSurface(config, passArtifactDigest)
	if err != nil || document == nil {
		return err
	}
	return writeCanonicalFile(roleOutputChangeSurfacePath(config), *document)
}

func deriveRoleOutputChangeSurface(config Config, passArtifactDigest string) (*changesurface.Document, string, error) {
	if !roleOutputChangeSurfaceExpected(config) {
		return nil, "", nil
	}
	input, err := readDriverChangeSurfaceInput(config, false)
	if err != nil {
		return nil, "", err
	}
	if input.BaseManifest == nil || input.HeadManifest == nil {
		return nil, "", diag.New(
			planning.CodeMissingChangeSurface,
			"change surface derivation requires both a base manifest and the derived head manifest.",
			diag.WithDetail("base_manifest", input.BaseManifest != nil),
			diag.WithDetail("head_manifest", input.HeadManifest != nil),
		)
	}
	surface, surfaceDigest, err := changesurface.Derive(*input.BaseManifest, *input.HeadManifest, passArtifactDigest)
	if err != nil {
		return nil, "", err
	}
	return &surface, surfaceDigest, nil
}

func roleOutputChangeSurfaceExpected(config Config) bool {
	return strings.TrimSpace(config.BaseManifestPath) != "" && !config.BaselinePass
}

func readDriverChangeSurfaceInput(config Config, baselinePass bool) (planning.ChangeSurfaceInput, error) {
	headPath, err := effectiveHeadManifestPath(config)
	if err != nil {
		return planning.ChangeSurfaceInput{}, err
	}
	return readChangeSurfaceInput(config.BaseManifestPath, headPath, baselinePass)
}

func validateEffectiveHeadManifest(config Config) error {
	_, err := effectiveHeadManifestPath(config)
	return err
}

func effectiveHeadManifestPath(config Config) (string, error) {
	if strings.TrimSpace(config.HeadManifestPath) != "" {
		if err := requireHeadManifestSnapshotMatch(config, config.HeadManifestPath); err != nil {
			return "", err
		}
		return config.HeadManifestPath, nil
	}
	if strings.TrimSpace(config.BaseManifestPath) != "" {
		return config.SnapshotManifestPath, nil
	}
	return "", nil
}

func effectiveHeadManifestPathUnchecked(config Config) string {
	if strings.TrimSpace(config.HeadManifestPath) != "" {
		return config.HeadManifestPath
	}
	if strings.TrimSpace(config.BaseManifestPath) != "" {
		return config.SnapshotManifestPath
	}
	return ""
}

func requireHeadManifestSnapshotMatch(config Config, headPath string) error {
	snapshotPath := strings.TrimSpace(config.SnapshotManifestPath)
	if strings.TrimSpace(headPath) == "" || snapshotPath == "" {
		return nil
	}
	headManifest, err := readFreezeManifest(headPath)
	if err != nil {
		return err
	}
	snapshotManifest, err := readFreezeManifest(snapshotPath)
	if err != nil {
		return err
	}
	headDigest, err := freeze.ManifestDigest(headManifest)
	if err != nil {
		return diag.Wrap(err, CodeHeadManifestMismatch, "explicit head manifest digest could not be recomputed.", diag.WithPath("/config/head_manifest_path"), diag.WithDetail("head_manifest_path", headPath))
	}
	snapshotDigest, err := freeze.ManifestDigest(snapshotManifest)
	if err != nil {
		return diag.Wrap(err, CodeHeadManifestMismatch, "snapshot manifest digest could not be recomputed.", diag.WithPath("/config/snapshot_manifest_path"), diag.WithDetail("snapshot_manifest_path", snapshotPath))
	}
	if headDigest != snapshotDigest {
		return diag.New(
			CodeHeadManifestMismatch,
			"explicit head manifest does not match the frozen snapshot manifest.",
			diag.WithPath("/config/head_manifest_path"),
			diag.WithDetail("head_manifest_path", headPath),
			diag.WithDetail("snapshot_manifest_path", snapshotPath),
			diag.WithDetail("head_manifest_digest", headDigest),
			diag.WithDetail("snapshot_manifest_digest", snapshotDigest),
		)
	}
	return nil
}

func readChangeSurfaceDocument(path string) (changesurface.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return changesurface.Document{}, fileError(err, path, "open role-output change surface")
	}
	return strictjson.DecodeBytes[changesurface.Document](data, strictjson.DefaultMaxBytes*4)
}

func readChangeSurfaceInput(basePath string, headPath string, baselinePass bool) (planning.ChangeSurfaceInput, error) {
	input := planning.ChangeSurfaceInput{BaselinePass: baselinePass}
	if strings.TrimSpace(basePath) != "" {
		manifest, err := readFreezeManifest(basePath)
		if err != nil {
			return planning.ChangeSurfaceInput{}, err
		}
		input.BaseManifest = &manifest
	}
	if strings.TrimSpace(headPath) != "" {
		manifest, err := readFreezeManifest(headPath)
		if err != nil {
			return planning.ChangeSurfaceInput{}, err
		}
		input.HeadManifest = &manifest
	}
	return input, nil
}

func readFreezeManifest(path string) (freeze.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return freeze.Manifest{}, fileError(err, path, "open freeze manifest")
	}
	return strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
}

func readReceipts(paths []string) ([]contracts.ExecutionReceipt, error) {
	receipts := make([]contracts.ExecutionReceipt, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fileError(err, path, "open execution receipt")
		}
		receipt, err := contracts.ReadExecutionReceiptBytes(data)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func writeCanonicalFile(path string, value any) error {
	encoded, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fileError(err, filepath.Dir(path), "create output directory")
	}
	if err := atomicWriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return fileError(err, path, "write output")
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fileError(err, filepath.Dir(path), "create output directory")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := atomicWriteFile(path, buffer.Bytes(), 0o644); err != nil {
		return fileError(err, path, "write output")
	}
	return nil
}

func validationError(code string, message string, path string, details map[string]any) error {
	return &ValidationError{Diagnostics: []diag.Diagnostic{{
		Code:    code,
		Message: message,
		Path:    path,
		Details: details,
	}}}
}

func fileError(err error, path string, action string) error {
	return diag.Wrap(
		err,
		charter.CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", action),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}

func absPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", diag.Wrap(err, charter.CodeFileIO, "file operation failed.", diag.WithDetail("action", "resolve path"), diag.WithDetail("path", path), diag.WithDetail("error", err.Error()))
	}
	return filepath.Clean(absolute), nil
}

func optionalAbsPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	return absPath(path)
}

func artifactIDFromPath(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if base == "" {
		base = "artifact"
	}
	return artifactIDFromText(base)
}

func artifactIDFromText(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == ':':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	id := strings.Trim(builder.String(), ".-_")
	if id == "" {
		return "artifact"
	}
	return id
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
