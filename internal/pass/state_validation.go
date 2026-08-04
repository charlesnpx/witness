package pass

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/metrics"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/preflight"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func validateLoadedState(state *State) error {
	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, validateStageOrdering(state)...)
	if state == nil {
		return &ValidationError{Diagnostics: diagnostics}
	}
	diagnostics = append(diagnostics, validateMandatoryStageArtifacts(state)...)
	diagnostics = append(diagnostics, validateRecordedArtifactDigestsAndOutputs(state)...)
	diagnostics = append(diagnostics, validateDerivedRelayBatches(state)...)
	diagnostics = append(diagnostics, validateStageCrossBindings(state)...)
	if len(diagnostics) > 0 {
		diag.Sort(diagnostics)
		return &ValidationError{Diagnostics: diagnostics}
	}
	return nil
}

func validateStageOrdering(state *State) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if state == nil {
		return []diag.Diagnostic{stateInvalidDiagnostic("pass state is empty.", "", nil)}
	}
	if state.StateDir != "" && state.Config.StateDir != "" && filepath.Clean(state.StateDir) != filepath.Clean(state.Config.StateDir) {
		diagnostics = append(diagnostics, stateInvalidDiagnostic(
			"pass state_dir does not match config.state_dir.",
			"/state_dir",
			map[string]any{"state_dir": state.StateDir, "config_state_dir": state.Config.StateDir},
		))
	}
	if len(state.Stages) > len(orderedStages) {
		diagnostics = append(diagnostics, stateInvalidDiagnostic(
			"pass state records more stages than the driver supports.",
			"/stages",
			map[string]any{"actual_count": len(state.Stages), "expected_count": len(orderedStages)},
		))
	}
	for index, stage := range state.Stages {
		path := fmt.Sprintf("/stages/%d", index)
		if index >= len(orderedStages) {
			continue
		}
		if stage.Name != orderedStages[index] {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"pass stages must be recorded in exact driver order without gaps.",
				path+"/name",
				map[string]any{"actual": stage.Name, "expected": orderedStages[index]},
			))
		}
		if stage.Status != statusComplete {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"pass state may only persist completed stage records.",
				path+"/status",
				map[string]any{"actual": stage.Status, "expected": statusComplete},
			))
		}
	}
	if state.Complete && len(state.Stages) != len(orderedStages) {
		diagnostics = append(diagnostics, stateInvalidDiagnostic(
			"complete pass state must record every driver stage.",
			"/complete",
			map[string]any{"actual_stage_count": len(state.Stages), "expected_stage_count": len(orderedStages)},
		))
	}
	return diagnostics
}

func validateMandatoryStageArtifacts(state *State) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, stage := range state.Stages {
		if stage.Status != statusComplete {
			continue
		}
		inputs, outputs := mandatoryArtifactsForStage(state, stage)
		diagnostics = append(diagnostics, requireArtifactRecords(stage, "inputs", stage.Inputs, inputs)...)
		diagnostics = append(diagnostics, requireArtifactRecords(stage, "outputs", stage.Outputs, outputs)...)
	}
	return diagnostics
}

func mandatoryArtifactsForStage(state *State, stage StageRecord) ([]artifactInput, []artifactInput) {
	config := state.Config
	switch stage.Name {
	case stageFreeze:
		inputs := []artifactInput{{role: "charter", path: config.CharterPath, digestClass: digestClassRaw()}}
		if config.AmendmentsPath != "" {
			inputs = append(inputs, artifactInput{role: "amendments", path: config.AmendmentsPath, digestClass: digestClassRaw()})
		}
		return inputs, []artifactInput{
			{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digestClassRaw()},
			{role: "source-snapshot-manifest", path: config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
		}
	case stagePreflight:
		var result *preflight.Result
		if decoded, err := readPreflightResult(config.Outputs.PreflightPath); err == nil {
			result = &decoded
		}
		return []artifactInput{
			{role: "integration-bundle", path: config.IntegrationBundlePath, digestClass: digestClassRaw()},
			{role: "source-snapshot-manifest", path: config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
		}, preflightOutputSpecs(config, result)
	case stagePlan:
		inputs := []artifactInput{
			{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digestClassRaw()},
			{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digestClassRaw()},
			{role: "policy", path: config.PolicyPath, digestClass: digestClassRaw()},
			{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
			{role: "head-manifest", path: effectiveHeadManifestPath(config), digestClass: digestClassFreezeManifest},
		}
		for _, item := range config.RoleOutputs {
			inputs = append(inputs, artifactInput{role: "role-output:" + item.Role, path: item.Path, digestClass: digestClassRaw()})
		}
		outputs := []artifactInput{{role: "verification-plan", path: config.Outputs.PlanPath, digestClass: digestClassRaw()}}
		if plan, err := readPlan(config.Outputs.PlanPath); err == nil {
			for _, batch := range plan.Batches {
				outputs = append(outputs, artifactInput{role: "verification-batch:" + batch.BatchID, path: filepath.Join(config.StateDir, "verification", "batches", batch.BatchID+".json"), digestClass: digestClassRaw()})
			}
			if plan.ChangeSurface != nil {
				outputs = append(outputs, artifactInput{role: "change-surface", path: filepath.Join(config.StateDir, "verification", "change-surface.json"), digestClass: digestClassRaw()})
			}
		}
		return inputs, outputs
	case stageAssemble:
		relayBatches := state.RelayBatches
		if derived, err := relayBatchRecordsFromValidatedPlan(state); err == nil {
			relayBatches = derived
		}
		inputs := []artifactInput{
			{role: "verification-plan", path: config.Outputs.PlanPath, digestClass: digestClassRaw()},
			{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digestClassRaw()},
			{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digestClassRaw()},
			{role: "integration-bundle-retained", path: retainedIntegrationBundlePath(config), digestClass: digestClassRaw()},
			{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
			{role: "head-manifest", path: effectiveHeadManifestPath(config), digestClass: digestClassFreezeManifest},
		}
		for _, batch := range relayBatches {
			inputs = append(inputs, artifactInput{role: "verification-batch:" + batch.BatchID, path: batch.BatchPath, digestClass: digestClassRaw()})
			if portableExportReady(batch.PortableExportDir) {
				inputs = append(inputs, artifactInput{role: "portable-export:" + batch.BatchID, path: filepath.Join(batch.PortableExportDir, "manifest.json"), digestClass: digestClassRaw()})
			}
		}
		for _, path := range config.ReceiptPaths {
			inputs = append(inputs, artifactInput{role: "receipt", path: path, digestClass: digestClassRaw()})
		}
		if receipts, err := readReceipts(config.ReceiptPaths); err == nil {
			if receiptInputs, err := receiptArtifactInputs(config, receipts); err == nil {
				inputs = append(inputs, receiptInputs...)
			}
		}
		outputs := []artifactInput{{role: "verification-manifest", path: config.Outputs.ManifestPath, digestClass: digestClassRaw()}}
		if expected, err := expectedAssembleResult(state); err == nil && hasSupplementaryAssembleContent(expected) {
			outputs = append(outputs, artifactInput{role: "assemble-result", path: assembleResultPath(config), digestClass: digestClassRaw()})
		}
		return inputs, outputs
	case stageAdjudicate:
		inputs := []artifactInput{
			{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digestClassRaw()},
			{role: "verification-manifest", path: config.Outputs.ManifestPath, digestClass: digestClassRaw()},
			{role: "policy", path: config.PolicyPath, digestClass: digestClassRaw()},
			{role: "rules", path: config.RulesPath, digestClass: digestClassRaw()},
			{role: "ledger", path: config.LedgerPath, digestClass: digestClassRaw()},
			{role: "prior-lineage", path: config.PriorLineagePath, digestClass: digestClassRaw()},
			{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
			{role: "head-manifest", path: effectiveHeadManifestPath(config), digestClass: digestClassFreezeManifest},
		}
		for _, item := range config.RoleOutputs {
			inputs = append(inputs, artifactInput{role: "role-output:" + item.Role, path: item.Path, digestClass: digestClassRaw()})
		}
		return inputs, []artifactInput{{role: "run-result", path: config.Outputs.RunResultPath, digestClass: digestClassRaw()}}
	case stageMetrics:
		return []artifactInput{
			{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digestClassRaw()},
			{role: "run-result", path: config.Outputs.RunResultPath, digestClass: digestClassRaw()},
			{role: "ledger", path: config.LedgerPath, digestClass: digestClassRaw()},
		}, []artifactInput{{role: "metrics", path: config.Outputs.MetricsPath, digestClass: digestClassRaw()}}
	default:
		return nil, nil
	}
}

func requireArtifactRecords(stage StageRecord, field string, records []ArtifactRecord, required []artifactInput) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, want := range required {
		if strings.TrimSpace(want.path) == "" {
			continue
		}
		record, ok := findArtifactRecord(records, want.role, want.path)
		if !ok {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"completed pass stage is missing a mandatory artifact record.",
				"",
				map[string]any{"stage": stage.Name, "field": field, "role": want.role, "path": want.path},
			))
			continue
		}
		if strings.TrimSpace(record.Digest) == "" || strings.TrimSpace(record.Path) == "" {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"completed pass stage artifact record is incomplete.",
				"",
				map[string]any{"stage": stage.Name, "field": field, "role": record.Role, "path": record.Path},
			))
		}
		if record.DigestClass != want.digestClass {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"completed pass stage artifact record has an unexpected digest class.",
				"",
				map[string]any{"stage": stage.Name, "field": field, "role": record.Role, "path": record.Path, "actual": record.DigestClass, "expected": want.digestClass},
			))
		}
	}
	return diagnostics
}

func findArtifactRecord(records []ArtifactRecord, role string, path string) (ArtifactRecord, bool) {
	for _, record := range records {
		if record.Role == role && recordedPathsEqual(record.Path, path) {
			return record, true
		}
	}
	return ArtifactRecord{}, false
}

func validateRecordedArtifactDigestsAndOutputs(state *State) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, stage := range state.Stages {
		if stage.Status != statusComplete {
			continue
		}
		for _, artifact := range append(append([]ArtifactRecord(nil), stage.Inputs...), stage.Outputs...) {
			actual, err := computeArtifactDigest(artifact.Path, artifact.DigestClass)
			if err != nil {
				diagnostics = append(diagnostics, diag.FromError(diag.Wrap(
					err,
					CodeStateDrift,
					"recorded pass artifact could not be revalidated.",
					diag.WithDetail("stage", stage.Name),
					diag.WithDetail("role", artifact.Role),
					diag.WithDetail("path", artifact.Path),
				)))
				continue
			}
			if actual != artifact.Digest {
				diagnostics = append(diagnostics, stateDriftDiagnostic(
					"recorded pass artifact digest changed.",
					stage.Name,
					artifact,
					map[string]any{"actual_digest": actual, "expected_digest": artifact.Digest},
				))
			}
		}
		for _, artifact := range stage.Outputs {
			if err := validateStageOutput(state, stage, artifact); err != nil {
				diagnostics = append(diagnostics, diag.FromError(diag.Wrap(
					err,
					CodeStateInvalid,
					"recorded pass stage output failed semantic validation.",
					diag.WithDetail("stage", stage.Name),
					diag.WithDetail("role", artifact.Role),
					diag.WithDetail("path", artifact.Path),
				)))
			}
		}
	}
	return diagnostics
}

func validateStageOutput(state *State, stage StageRecord, artifact ArtifactRecord) error {
	data, err := os.ReadFile(artifact.Path)
	if err != nil {
		return err
	}
	switch {
	case artifact.Role == "charter-freeze":
		var frozen charter.FrozenCharter
		frozen, err = strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
		if err == nil {
			err = validateFrozenCharterOutput(state.Config, frozen)
		}
	case artifact.Role == "source-snapshot-manifest":
		var manifest freeze.Manifest
		manifest, err = strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
		if err == nil {
			_, err = validateFreezeManifestOutput(state.Config, manifest)
		}
	case artifact.Role == "preflight":
		var result preflight.Result
		result, err = strictjson.DecodeBytes[preflight.Result](data, strictjson.DefaultMaxBytes*4)
		if err == nil {
			err = validatePreflightOutput(state.Config, result)
		}
	case isPreflightRetainedOutputRole(artifact.Role):
		err = validatePreflightRetainedOutput(state.Config, artifact)
	case artifact.Role == roleOutputChangeSurfaceRole:
		err = validateRoleOutputChangeSurfaceOutput(state, artifact)
	case artifact.Role == "verification-plan":
		err = validatePlanStageOutputs(state)
	case artifact.Role == "change-surface":
		err = validatePlanStageOutputs(state)
	case strings.HasPrefix(artifact.Role, "verification-batch:"):
		err = validatePlanVerificationBatchOutput(state, artifact, data)
	case artifact.Role == "verification-manifest":
		err = validateAssembleStageOutputs(state, artifact.Role)
	case artifact.Role == "assemble-result":
		err = validateAssembleStageOutputs(state, artifact.Role)
	case artifact.Role == "run-result":
		err = validateAdjudicateOutput(state)
	case artifact.Role == "metrics":
		err = validateMetricsOutput(state)
	default:
		err = diag.New(CodeStateInvalid, "recorded pass stage output has no authoritative validator.", diag.WithDetail("role", artifact.Role))
	}
	return err
}

func validateStageCrossBindings(state *State) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	outputsByRole := map[string]ArtifactRecord{}
	for _, stage := range state.Stages {
		if stage.Status != statusComplete {
			continue
		}
		for _, input := range stage.Inputs {
			upstream, ok := outputsByRole[input.Role]
			if !ok {
				continue
			}
			if !artifactRecordsEqual(input, upstream) {
				diagnostics = append(diagnostics, stateInvalidDiagnostic(
					"completed pass stage input does not match the upstream output it depends on.",
					"",
					map[string]any{
						"stage":                 stage.Name,
						"role":                  input.Role,
						"input_path":            input.Path,
						"upstream_path":         upstream.Path,
						"input_digest":          input.Digest,
						"upstream_digest":       upstream.Digest,
						"input_digest_class":    input.DigestClass,
						"upstream_digest_class": upstream.DigestClass,
					},
				))
			}
		}
		for _, output := range stage.Outputs {
			outputsByRole[output.Role] = output
		}
	}
	return diagnostics
}

func artifactRecordsEqual(left ArtifactRecord, right ArtifactRecord) bool {
	return left.Role == right.Role &&
		recordedPathsEqual(left.Path, right.Path) &&
		left.Digest == right.Digest &&
		left.DigestClass == right.DigestClass
}

func validateDerivedRelayBatches(state *State) []diag.Diagnostic {
	if state == nil || !stageComplete(state, stagePlan) {
		return nil
	}
	derived, err := relayBatchRecordsFromValidatedPlan(state)
	if err != nil {
		return []diag.Diagnostic{stateInvalidDiagnostic(
			"pass relay batch records could not be derived from the verification plan.",
			"/relay_batches",
			map[string]any{"error": err.Error()},
		)}
	}
	recorded := state.RelayBatches
	if len(recorded) != len(derived) {
		return []diag.Diagnostic{stateInvalidDiagnostic(
			"pass relay batch records do not match the verification plan.",
			"/relay_batches",
			map[string]any{"actual_count": len(recorded), "expected_count": len(derived)},
		)}
	}
	var diagnostics []diag.Diagnostic
	for index := range derived {
		if !relayBatchStableFieldsEqual(recorded[index], derived[index]) {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"pass relay batch record contains fields not derived from the verification plan.",
				"/relay_batches/"+strconv.Itoa(index),
				map[string]any{"actual": recorded[index], "expected": derived[index]},
			))
			continue
		}
		if !relayBatchStatusCompatible(recorded[index].Status, derived[index].Status) {
			diagnostics = append(diagnostics, stateInvalidDiagnostic(
				"pass relay batch record status is inconsistent with derived relay state.",
				"/relay_batches/"+strconv.Itoa(index)+"/status",
				map[string]any{"actual": recorded[index].Status, "expected": derived[index].Status},
			))
		}
	}
	return diagnostics
}

func relayBatchStableFieldsEqual(left RelayBatchRecord, right RelayBatchRecord) bool {
	return left.BatchID == right.BatchID &&
		left.Role == right.Role &&
		left.TaskShape == right.TaskShape &&
		left.RecipeFamily == right.RecipeFamily &&
		left.RecipeID == right.RecipeID &&
		recordedPathsEqual(left.BatchPath, right.BatchPath) &&
		left.BatchDigest == right.BatchDigest &&
		recordedPathsEqual(left.PortableExportDir, right.PortableExportDir)
}

func relayBatchStatusCompatible(recorded string, derived string) bool {
	if recorded == derived {
		return true
	}
	return recorded == statusPending && derived == statusComplete
}

func validateFrozenCharterOutput(config Config, frozen charter.FrozenCharter) error {
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
	expected, err := charter.Freeze(input, amendments)
	if err != nil {
		return err
	}
	return requireSemanticMatch("frozen Charter", frozen, expected)
}

func validateFreezeManifestOutput(config Config, manifest freeze.Manifest) (string, error) {
	expected, err := freeze.DeriveManifest(context.Background(), freeze.Options{
		SourceDir:   config.SourceDir,
		OutputDir:   config.SnapshotDir,
		AllowNonGit: config.AllowNonGitSource,
	})
	if err != nil {
		return "", err
	}
	if err := requireSemanticMatch("source snapshot manifest", manifest, expected.Manifest); err != nil {
		return "", err
	}
	actualDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return "", diag.Wrap(err, CodeStateInvalid, "snapshot manifest digest could not be recomputed.")
	}
	if actualDigest != expected.ManifestDigest {
		return "", diag.New(CodeStateInvalid, "snapshot manifest digest does not match the source inventory.", diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", expected.ManifestDigest))
	}
	for label, embedded := range map[string]string{
		"source":    manifest.Source.ManifestDigest,
		"workspace": manifest.Workspace.ManifestDigest,
	} {
		if strings.TrimSpace(embedded) == "" {
			return "", diag.New(CodeStateInvalid, "snapshot manifest is missing an embedded digest.", diag.WithDetail("location", label), diag.WithDetail("expected_digest", actualDigest))
		}
		if embedded != actualDigest {
			return "", diag.New(CodeStateInvalid, "snapshot manifest embedded digest does not match its content.", diag.WithDetail("location", label), diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", embedded))
		}
	}
	for index, entry := range manifest.Files {
		if !safeSlashRelativePath(entry.Path) {
			return "", diag.New(CodeStateInvalid, "snapshot manifest contains an unsafe file path.", diag.WithDetail("index", index), diag.WithDetail("path", entry.Path))
		}
		if !validDigestString(entry.Digest) {
			return "", diag.New(CodeStateInvalid, "snapshot manifest file digest is invalid.", diag.WithDetail("index", index), diag.WithDetail("digest", entry.Digest))
		}
		if manifest.Workspace.Path == "" || entry.Blob == "" {
			continue
		}
		if !safeSlashRelativePath(entry.Blob) {
			return "", diag.New(CodeStateInvalid, "snapshot manifest contains an unsafe blob path.", diag.WithDetail("index", index), diag.WithDetail("path", entry.Blob))
		}
		blobPath := filepath.Join(manifest.Workspace.Path, filepath.FromSlash(entry.Blob))
		blobBytes, err := os.ReadFile(blobPath)
		if err != nil {
			return "", diag.Wrap(err, CodeStateInvalid, "snapshot manifest blob could not be read.", diag.WithDetail("path", blobPath))
		}
		if int64(len(blobBytes)) != entry.Size {
			return "", diag.New(CodeStateInvalid, "snapshot manifest blob size does not match file entry.", diag.WithDetail("path", entry.Path), diag.WithDetail("actual_size", len(blobBytes)), diag.WithDetail("expected_size", entry.Size))
		}
		if blobDigest := digest.RawBytes(blobBytes); blobDigest != entry.Digest {
			return "", diag.New(CodeStateInvalid, "snapshot manifest blob digest does not match file entry.", diag.WithDetail("path", entry.Path), diag.WithDetail("actual_digest", blobDigest), diag.WithDetail("expected_digest", entry.Digest))
		}
	}
	return actualDigest, nil
}

func validDigestString(value string) bool {
	if !strings.HasPrefix(value, digest.Prefix) {
		return false
	}
	hex := strings.TrimPrefix(value, digest.Prefix)
	if len(hex) != 64 {
		return false
	}
	for _, r := range hex {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func safeSlashRelativePath(value string) bool {
	if strings.TrimSpace(value) == "" || filepath.IsAbs(value) || strings.Contains(value, "\x00") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validatePreflightOutput(config Config, result preflight.Result) error {
	expected, err := expectedPreflightResult(config)
	if err != nil {
		return err
	}
	return requireSemanticMatch("preflight", result, expected)
}

func expectedPreflightResult(config Config) (preflight.Result, error) {
	result := preflight.Result{
		SchemaVersion:        preflight.SchemaVersion,
		OK:                   true,
		StateDir:             config.StateDir,
		ArtifactDigests:      map[string]string{},
		CompileReportDigests: map[string]string{},
		RecipePlanDigests:    map[string]string{},
		ContractDigests:      map[string]string{},
		BackendStrata:        map[string]string{},
		ConsumerIdentity:     map[string]any{"kind": "witness", "id": "pass-driver"},
	}
	manifest, err := readFreezeManifest(config.SnapshotManifestPath)
	if err != nil {
		return result, err
	}
	snapshotDigest, err := validateFreezeManifestOutput(config, manifest)
	if err != nil {
		return result, err
	}
	result.SnapshotDigest = snapshotDigest
	result.ArtifactDigests["source-snapshot-manifest"] = snapshotDigest

	capabilities, capabilitiesDigest, err := readRetainedPreflightArtifact(config, "relay-capabilities.json")
	if err != nil {
		return result, err
	}
	result.ArtifactDigests["relay-capabilities.json"] = capabilitiesDigest
	backendStatus, backendStatusDigest, err := readRetainedPreflightArtifact(config, "backend-status.json")
	if err != nil {
		return result, err
	}
	result.ArtifactDigests["backend-status.json"] = backendStatusDigest
	strata, err := derivePreflightBackendStrata(backendStatus)
	if err != nil {
		return result, err
	}
	result.BackendStrata = strata
	relayAbsent := preflight.RelayAbsent(result)
	if err := validatePreflightCapabilities(capabilities, relayAbsent); err != nil {
		return result, err
	}
	result.RelayVersion = preflightRelayVersion(capabilities, relayAbsent)

	recipes, recipesDigest, err := readRetainedPreflightArtifact(config, "recipes-list.json")
	if err != nil {
		return result, err
	}
	result.ArtifactDigests["recipes-list.json"] = recipesDigest
	if err := validatePreflightRecipes(recipes, relayAbsent); err != nil {
		return result, err
	}

	configuredBundle, bundleDigest, err := configuredIntegrationBundle(config)
	if err != nil {
		return result, err
	}
	retainedBundle, retainedBundleDigest, err := readRetainedPreflightArtifact(config, "integration-bundle.json")
	if err != nil {
		return result, err
	}
	if err := requireSemanticMatch("preflight retained integration bundle", retainedBundle, configuredBundle); err != nil {
		return result, err
	}
	if retainedBundleDigest != bundleDigest {
		return result, diag.New(CodeStateInvalid, "preflight retained integration bundle digest does not match the configured bundle.", diag.WithDetail("actual_digest", retainedBundleDigest), diag.WithDetail("expected_digest", bundleDigest))
	}
	result.ArtifactDigests["integration-bundle.json"] = retainedBundleDigest
	result.ContractDigests["integration_bundle"] = bundleDigest
	selectedDigests, err := selectedContractDigestsFromBundle(configuredBundle)
	if err != nil {
		return result, err
	}
	for _, key := range sortedStringMapKeys(selectedDigests) {
		result.ContractDigests[key] = selectedDigests[key]
	}

	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		relativePath := filepath.ToSlash(filepath.Join("compile-reports", requirement.RecipeID+".json"))
		compileReport, compileReportDigest, err := readRetainedPreflightArtifact(config, relativePath)
		if err != nil {
			return result, err
		}
		result.ArtifactDigests[relativePath] = compileReportDigest
		result.CompileReportDigests[requirement.RecipeID] = compileReportDigest
		recipePlan, err := validatePreflightCompileReport(compileReport, requirement, relayAbsent, selectedDigests)
		if err != nil {
			return result, err
		}
		if relayAbsent {
			continue
		}
		planRelativePath := filepath.ToSlash(filepath.Join("recipe-plans", requirement.RecipeID+".json"))
		retainedPlan, retainedPlanDigest, err := readRetainedPreflightArtifact(config, planRelativePath)
		if err != nil {
			return result, err
		}
		if err := requireSemanticMatch("preflight recipe plan "+requirement.RecipeID, retainedPlan, recipePlan); err != nil {
			return result, err
		}
		result.ArtifactDigests[planRelativePath] = retainedPlanDigest
		result.RecipePlanDigests[requirement.RecipeID] = retainedPlanDigest
	}

	contractDigestDoc := map[string]any{
		"schema_version":   "witness-preflight-contract-digests-v1",
		"digest_profile":   digest.Profile,
		"contract_digests": result.ContractDigests,
	}
	retainedContractDigests, contractDigestArtifactDigest, err := readRetainedPreflightArtifact(config, "contract-digests.json")
	if err != nil {
		return result, err
	}
	if err := requireSemanticMatch("preflight contract digests", retainedContractDigests, contractDigestDoc); err != nil {
		return result, err
	}
	result.ArtifactDigests["contract-digests.json"] = contractDigestArtifactDigest

	compatibility := expectedPreflightCompatibility(result)
	if err := contracts.RequireValidRelayCompatibility(compatibility); err != nil {
		return result, err
	}
	retainedCompatibility, compatibilityDigest, err := readRetainedPreflightArtifact(config, "compatibility-manifest.json")
	if err != nil {
		return result, err
	}
	if err := requireSemanticMatch("preflight compatibility manifest", retainedCompatibility, compatibility); err != nil {
		return result, err
	}
	result.ArtifactDigests["compatibility-manifest.json"] = compatibilityDigest
	return result, nil
}

func isPreflightRetainedOutputRole(role string) bool {
	switch role {
	case "compatibility-manifest", "relay-capabilities", "integration-bundle-retained", "backend-status", "recipes-list", "contract-digests":
		return true
	default:
		return strings.HasPrefix(role, "compile-report:") ||
			strings.HasPrefix(role, "recipe-plan:") ||
			strings.HasPrefix(role, "preflight-retained:")
	}
}

func validatePreflightRetainedOutput(config Config, artifact ArtifactRecord) error {
	expected, err := expectedPreflightResult(config)
	if err != nil {
		return err
	}
	for _, spec := range preflightOutputSpecs(config, &expected) {
		if spec.role == artifact.Role && recordedPathsEqual(spec.path, artifact.Path) {
			return nil
		}
	}
	return diag.New(CodeStateInvalid, "preflight retained output is not part of the derived artifact set.", diag.WithDetail("role", artifact.Role), diag.WithDetail("path", artifact.Path))
}

func validateRoleOutputChangeSurfaceOutput(state *State, artifact ArtifactRecord) error {
	if state == nil {
		return diag.New(CodeStateInvalid, "pass state is empty.")
	}
	expectedPath := roleOutputChangeSurfacePath(state.Config)
	if !recordedPathsEqual(artifact.Path, expectedPath) {
		return diag.New(
			CodeStateInvalid,
			"role-output change surface output path does not match the driver output path.",
			diag.WithDetail("actual_path", artifact.Path),
			diag.WithDetail("expected_path", expectedPath),
		)
	}
	preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath)
	if err != nil {
		return err
	}
	expected, expectedDigest, err := deriveRoleOutputChangeSurface(state.Config, preflightResult.SnapshotDigest)
	if err != nil {
		return err
	}
	if expected == nil {
		return diag.New(
			CodeStateInvalid,
			"role-output change surface output is present but no early change surface is expected.",
			diag.WithDetail("path", artifact.Path),
		)
	}
	actual, err := readChangeSurfaceDocument(artifact.Path)
	if err != nil {
		return err
	}
	actualDigest, err := changesurface.Digest(actual)
	if err != nil {
		return err
	}
	if actualDigest != expectedDigest {
		return diag.New(
			CodeStateInvalid,
			"role-output change surface digest does not match the surface derived from authoritative manifests.",
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", expectedDigest),
		)
	}
	return requireSemanticMatch("role-output change surface", actual, *expected)
}

func preflightRetainedArtifactPath(stateDir string, relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) || strings.Contains(relativePath, "\x00") {
		return "", diag.New(CodeStateInvalid, "preflight retained artifact path is unsafe.", diag.WithDetail("path", relativePath))
	}
	for _, part := range strings.Split(filepath.ToSlash(relativePath), "/") {
		if part == "" || part == "." || part == ".." {
			return "", diag.New(CodeStateInvalid, "preflight retained artifact path contains an unsafe segment.", diag.WithDetail("path", relativePath))
		}
	}
	return filepath.Join(stateDir, filepath.FromSlash(relativePath)), nil
}

func retainedArtifactPayloadDigest(path string) (string, error) {
	_, digest, err := readRetainedPayloadFile(path)
	return digest, err
}

func readRetainedPreflightArtifact(config Config, relativePath string) (any, string, error) {
	path, err := preflightRetainedArtifactPath(config.StateDir, relativePath)
	if err != nil {
		return nil, "", err
	}
	payload, payloadDigest, err := readRetainedPayloadFile(path)
	if err != nil {
		return nil, "", err
	}
	return payload, payloadDigest, nil
}

func readRetainedPayloadFile(path string) (any, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	payloadBytes, err := retainedPayloadCanonicalBytes(data)
	if err != nil {
		return nil, "", err
	}
	if len(payloadBytes) == 0 {
		return nil, "", diag.New(CodeStateInvalid, "preflight retained artifact is missing its payload envelope.", diag.WithDetail("path", path))
	}
	payload, err := strictjson.DecodeAnyBytes(payloadBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, "", err
	}
	return payload, digest.RawBytes(payloadBytes), nil
}

func configuredIntegrationBundle(config Config) (any, string, error) {
	data, err := os.ReadFile(config.IntegrationBundlePath)
	if err != nil {
		return nil, "", err
	}
	payload, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return nil, "", err
	}
	payloadDigest, err := digest.SemanticJSON(payload)
	if err != nil {
		return nil, "", err
	}
	return payload, payloadDigest, nil
}

func derivePreflightBackendStrata(payload any) (map[string]string, error) {
	object, ok := payload.(map[string]any)
	if !ok {
		return nil, diag.New(CodeStateInvalid, "preflight backend-status retained payload must be an object.")
	}
	rawBackends, ok := object["backends"].([]any)
	if !ok {
		return nil, diag.New(CodeStateInvalid, "preflight backend-status retained payload is missing backends.")
	}
	records := map[string]string{}
	for index, raw := range rawBackends {
		backend, ok := raw.(map[string]any)
		if !ok {
			return nil, diag.New(CodeStateInvalid, "preflight backend-status entry must be an object.", diag.WithDetail("index", index))
		}
		name, _ := backend["backend"].(string)
		status, _ := backend["status"].(string)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(status) == "" {
			return nil, diag.New(CodeStateInvalid, "preflight backend-status entry is incomplete.", diag.WithDetail("index", index))
		}
		records[name] = status
	}
	strata := map[string]string{}
	for _, backend := range preflightRequiredBackends() {
		status := strings.TrimSpace(records[backend])
		if status == "" {
			return nil, diag.New(CodeStateInvalid, "preflight backend-status is missing a required backend.", diag.WithDetail("backend", backend))
		}
		if status != contracts.RelayLaunchStatusAbsent && !preflightBackendAttemptable(status) {
			return nil, diag.New(CodeStateInvalid, "preflight backend-status is not attemptable.", diag.WithDetail("backend", backend), diag.WithDetail("status", status))
		}
		strata[backend] = status
	}
	return strata, nil
}

func preflightRequiredBackends() []string {
	return []string{"claude", "codex"}
}

func preflightBackendAttemptable(status string) bool {
	switch status {
	case "ready", "installed", "installed_auth_unknown", "auth_unknown":
		return true
	default:
		return false
	}
}

func validatePreflightCapabilities(payload any, relayAbsent bool) error {
	object, ok := payload.(map[string]any)
	if !ok {
		return diag.New(CodeStateInvalid, "preflight relay-capabilities retained payload must be an object.")
	}
	if relayAbsent {
		capabilities, _ := object["capabilities"].(map[string]any)
		for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
			value, exists := capabilities[requirement.Key]
			if !exists {
				return diag.New(CodeStateInvalid, "relay-absent capabilities are missing a required capability entry.", diag.WithDetail("capability", requirement.Key))
			}
			available, ok := value.(bool)
			if !ok || available {
				return diag.New(CodeStateInvalid, "relay-absent capabilities must record required capabilities as unavailable.", diag.WithDetail("capability", requirement.Key))
			}
		}
		return nil
	}
	if version := preflightRelayVersion(payload, false); version != "v1.4.0" {
		return diag.New(CodeStateInvalid, "preflight relay capabilities version does not match the supported baseline.", diag.WithDetail("actual", version), diag.WithDetail("expected", "v1.4.0"))
	}
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		if !preflightCapabilityPresent(object, requirement) {
			return diag.New(CodeStateInvalid, "preflight relay capabilities are missing a required capability.", diag.WithDetail("family", requirement.Family), diag.WithDetail("capability", requirement.Capability))
		}
	}
	return nil
}

func preflightRelayVersion(payload any, relayAbsent bool) string {
	if relayAbsent {
		return ""
	}
	object, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	version, _ := object["convo_relay_version"].(string)
	return strings.TrimSpace(version)
}

func preflightCapabilityPresent(capabilities map[string]any, requirement contracts.RelayCapabilityRequirementV3) bool {
	if strings.HasPrefix(requirement.Family, "contracts.") {
		contractsObject, _ := capabilities["contracts"].(map[string]any)
		values, _ := contractsObject[strings.TrimPrefix(requirement.Family, "contracts.")].([]any)
		return preflightAnySliceContains(values, requirement.Capability)
	}
	values, _ := capabilities[requirement.Family].([]any)
	return preflightAnySliceContains(values, requirement.Capability)
}

func preflightAnySliceContains(values []any, want string) bool {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if typed == want {
				return true
			}
		case json.Number:
			if typed.String() == want {
				return true
			}
		default:
			if fmt.Sprint(typed) == want {
				return true
			}
		}
	}
	return false
}

func validatePreflightRecipes(payload any, relayAbsent bool) error {
	object, ok := payload.(map[string]any)
	if !ok {
		return diag.New(CodeStateInvalid, "preflight recipes-list retained payload must be an object.")
	}
	rawRecipes, ok := object["recipes"].([]any)
	if !ok {
		return diag.New(CodeStateInvalid, "preflight recipes-list retained payload is missing recipes.")
	}
	if relayAbsent {
		if len(rawRecipes) != 0 {
			return diag.New(CodeStateInvalid, "relay-absent recipes-list must not claim available recipes.")
		}
		return nil
	}
	recipes := map[string]map[string]any{}
	for index, raw := range rawRecipes {
		recipe, ok := raw.(map[string]any)
		if !ok {
			return diag.New(CodeStateInvalid, "preflight recipe entry must be an object.", diag.WithDetail("index", index))
		}
		id, _ := recipe["id"].(string)
		if strings.TrimSpace(id) == "" {
			return diag.New(CodeStateInvalid, "preflight recipe entry is missing id.", diag.WithDetail("index", index))
		}
		recipes[id] = recipe
	}
	for _, requirement := range preflight.RequiredRecipes {
		recipe, ok := recipes[requirement.ID]
		if !ok {
			return diag.New(CodeStateInvalid, "preflight recipes-list is missing a required recipe.", diag.WithDetail("recipe_id", requirement.ID))
		}
		status, _ := recipe["status"].(string)
		if status != "usable" && status != "requires_integration" {
			return diag.New(CodeStateInvalid, "preflight recipe is not usable.", diag.WithDetail("recipe_id", requirement.ID), diag.WithDetail("status", status))
		}
		declared, _ := recipe["declared"].(map[string]any)
		contractID, _ := declared["integration_contract"].(string)
		if contractID != requirement.ContractID {
			return diag.New(CodeStateInvalid, "preflight recipe is bound to the wrong integration contract.", diag.WithDetail("recipe_id", requirement.ID), diag.WithDetail("actual", contractID), diag.WithDetail("expected", requirement.ContractID))
		}
	}
	return nil
}

func validatePreflightCompileReport(payload any, requirement contracts.RecipePlanDigest, relayAbsent bool, selectedDigests map[string]string) (any, error) {
	object, ok := payload.(map[string]any)
	if !ok {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report retained payload must be an object.", diag.WithDetail("recipe_id", requirement.RecipeID))
	}
	if relayAbsent {
		recipeID, _ := object["recipe_id"].(string)
		contractID, _ := object["contract_id"].(string)
		status, _ := object["status"].(string)
		if recipeID != requirement.RecipeID || contractID != requirement.ContractID || status != contracts.RelayLaunchStatusAbsent {
			return nil, diag.New(CodeStateInvalid, "relay-absent compile-report retained payload does not match the required recipe.", diag.WithDetail("recipe_id", requirement.RecipeID))
		}
		return nil, nil
	}
	if recipeID, _ := object["recipe_id"].(string); recipeID != "" && recipeID != requirement.RecipeID {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report recipe_id does not match the retained artifact path.", diag.WithDetail("actual", recipeID), diag.WithDetail("expected", requirement.RecipeID))
	}
	status, _ := object["status"].(string)
	switch status {
	case "", "usable", "ok":
	default:
		return nil, diag.New(CodeStateInvalid, "preflight compile-report status is not successful.", diag.WithDetail("recipe_id", requirement.RecipeID), diag.WithDetail("status", status))
	}
	if contractID, _ := object["integration_contract"].(string); contractID != "" && contractID != requirement.ContractID {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report integration contract does not match the required recipe.", diag.WithDetail("recipe_id", requirement.RecipeID), diag.WithDetail("actual", contractID), diag.WithDetail("expected", requirement.ContractID))
	}
	if diagnostics, _ := object["diagnostics"].([]any); len(diagnostics) > 0 {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report contains diagnostics.", diag.WithDetail("recipe_id", requirement.RecipeID), diag.WithDetail("diagnostic_count", len(diagnostics)))
	}
	plan, err := preflightCompileReportPlan(payload)
	if err != nil {
		return nil, err
	}
	planObject, ok := plan.(map[string]any)
	if !ok {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report recipe plan must be an object.", diag.WithDetail("recipe_id", requirement.RecipeID))
	}
	contractDigest, _ := planObject["integration_contract_digest"].(string)
	if strings.TrimSpace(contractDigest) == "" {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report recipe plan is missing integration_contract_digest.", diag.WithDetail("recipe_id", requirement.RecipeID))
	}
	if expected := selectedDigests[requirement.ContractID]; contractDigest != expected {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report integration contract digest does not match the configured bundle.", diag.WithDetail("recipe_id", requirement.RecipeID), diag.WithDetail("actual_digest", contractDigest), diag.WithDetail("expected_digest", expected))
	}
	return plan, nil
}

func preflightCompileReportPlan(payload any) (any, error) {
	object, ok := payload.(map[string]any)
	if !ok {
		return nil, diag.New(CodeStateInvalid, "preflight compile-report retained payload must be an object.")
	}
	for _, key := range []string{"compiled_plan", "root_recipe_plan", "recipe_plan", "plan"} {
		value, ok := object[key]
		if !ok || value == nil {
			continue
		}
		if _, ok := value.(map[string]any); !ok {
			return nil, diag.New(CodeStateInvalid, "preflight compile-report recipe plan must be an object.", diag.WithDetail("field", key))
		}
		return value, nil
	}
	return nil, diag.New(CodeStateInvalid, "preflight compile-report is missing its retained recipe plan.")
}

func selectedContractDigestsFromBundle(bundle any) (map[string]string, error) {
	wanted := map[string]bool{}
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		wanted[requirement.ContractID] = true
	}
	digests := map[string]string{}
	var scan func(any) error
	scan = func(value any) error {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				if err := scan(item); err != nil {
					return err
				}
			}
		case map[string]any:
			if contractsMap, ok := typed["contracts"].(map[string]any); ok {
				keys := make([]string, 0, len(contractsMap))
				for key := range contractsMap {
					keys = append(keys, key)
				}
				sortStrings(keys)
				for _, contractID := range keys {
					contractPayload := contractsMap[contractID]
					if wanted[contractID] {
						if err := recordSelectedContractDigest(digests, contractID, contractPayload); err != nil {
							return err
						}
					}
					if err := scan(contractPayload); err != nil {
						return err
					}
				}
			}
			if id := contractIDValue(typed); wanted[id] {
				if err := recordSelectedContractDigest(digests, id, typed); err != nil {
					return err
				}
			}
			keys := make([]string, 0, len(typed))
			for key := range typed {
				if key == "contracts" {
					continue
				}
				keys = append(keys, key)
			}
			sortStrings(keys)
			for _, key := range keys {
				if err := scan(typed[key]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := scan(bundle); err != nil {
		return nil, err
	}
	for contractID := range wanted {
		if digests[contractID] == "" {
			return nil, diag.New(CodeStateInvalid, "configured integration bundle is missing a required Witness contract.", diag.WithDetail("contract_id", contractID))
		}
	}
	return digests, nil
}

func recordSelectedContractDigest(digests map[string]string, contractID string, payload any) error {
	if digests[contractID] != "" {
		return nil
	}
	object, ok := payload.(map[string]any)
	if !ok {
		return diag.New(CodeStateInvalid, "configured integration bundle contract must be an object.", diag.WithDetail("contract_id", contractID))
	}
	if bodyID := contractIDValue(object); bodyID != "" && bodyID != contractID {
		return diag.New(CodeStateInvalid, "configured integration bundle contract body id does not match the contract map key.", diag.WithDetail("contract_id", contractID), diag.WithDetail("body_id", bodyID))
	}
	contractDigest, err := digest.SemanticJSON(object)
	if err != nil {
		return diag.Wrap(err, CodeStateInvalid, "configured integration bundle contract digest could not be computed.", diag.WithDetail("contract_id", contractID))
	}
	digests[contractID] = contractDigest
	return nil
}

func contractIDValue(object map[string]any) string {
	for _, key := range []string{"id", "contract_id"} {
		if value, ok := object[key].(string); ok {
			return value
		}
	}
	return ""
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func expectedPreflightCompatibility(result preflight.Result) contracts.RelayCompatibility {
	relayAbsent := preflight.RelayAbsent(result)
	capabilities := make(map[string]bool, len(contracts.RequiredRelayCapabilityClosureV3))
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		capabilities[requirement.Key] = !relayAbsent
	}
	return contracts.RelayCompatibility{
		SchemaVersion:           contracts.RelayCompatibilityV3,
		ConvoRelayVersion:       result.RelayVersion,
		DigestProfile:           digest.Profile,
		Capabilities:            capabilities,
		CapabilitiesDigest:      result.ArtifactDigests["relay-capabilities.json"],
		IntegrationBundleDigest: result.ContractDigests["integration_bundle"],
		SelectedContracts:       expectedPreflightSelectedContracts(result.ContractDigests),
		RecipePlans:             expectedPreflightRecipePlans(result.RecipePlanDigests, relayAbsent),
		CompileReports:          expectedPreflightCompileReports(result.CompileReportDigests, relayAbsent),
		BackendStatus:           expectedPreflightBackendStatus(result.BackendStrata),
		ConsumerIdentity:        cloneMap(result.ConsumerIdentity),
	}
}

func expectedPreflightSelectedContracts(contractDigests map[string]string) []contracts.ContractDigest {
	seen := map[string]bool{}
	selected := make([]contracts.ContractDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		if seen[requirement.ContractID] {
			continue
		}
		seen[requirement.ContractID] = true
		selected = append(selected, contracts.ContractDigest{
			ContractID: requirement.ContractID,
			Digest:     contractDigests[requirement.ContractID],
		})
	}
	return selected
}

func expectedPreflightRecipePlans(recipePlanDigests map[string]string, relayAbsent bool) []contracts.RecipePlanDigest {
	if relayAbsent {
		return nil
	}
	plans := make([]contracts.RecipePlanDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		plans = append(plans, contracts.RecipePlanDigest{
			RecipeID:   requirement.RecipeID,
			ContractID: requirement.ContractID,
			Digest:     recipePlanDigests[requirement.RecipeID],
		})
	}
	return plans
}

func expectedPreflightCompileReports(compileReportDigests map[string]string, relayAbsent bool) []contracts.CompileReportRef {
	reports := make([]contracts.CompileReportRef, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		reportDigest := compileReportDigests[requirement.RecipeID]
		status := "retained"
		if relayAbsent {
			status = contracts.RelayLaunchStatusAbsent
		}
		reports = append(reports, contracts.CompileReportRef{
			RecipeID: requirement.RecipeID,
			Status:   status,
			Ref: contracts.ArtifactRef{
				Kind:          "compile-report",
				ID:            requirement.RecipeID,
				Digest:        reportDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			},
			Digest: reportDigest,
		})
	}
	return reports
}

func expectedPreflightBackendStatus(strata map[string]string) []contracts.BackendStatus {
	status := make([]contracts.BackendStatus, 0, len(preflightRequiredBackends()))
	for _, backend := range preflightRequiredBackends() {
		status = append(status, contracts.BackendStatus{
			Backend: backend,
			Status:  strata[backend],
		})
	}
	return status
}

func validatePlanStageOutputs(state *State) error {
	actual, err := readPlan(state.Config.Outputs.PlanPath)
	if err != nil {
		return err
	}
	if err := validatePlanDigest(actual); err != nil {
		return err
	}
	expected, err := expectedPlanningResult(state)
	if err != nil {
		return err
	}
	if err := requireSemanticMatch("verification plan", actual, expected.Plan); err != nil {
		return err
	}
	for _, expectedBatch := range expected.Batches {
		path := filepath.Join(state.Config.StateDir, "verification", "batches", expectedBatch.Plan.BatchID+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		actualBatch, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			return err
		}
		if err := contracts.ErrorFromDiagnostics(contracts.ValidateVerificationBatch(actualBatch, nil)); err != nil {
			return err
		}
		if digest.RawBytes(data) != expectedBatch.Plan.BatchDigest {
			return diag.New(CodeStateInvalid, "verification batch raw digest does not match the verification plan.", diag.WithDetail("batch_id", expectedBatch.Plan.BatchID), diag.WithDetail("actual_digest", digest.RawBytes(data)), diag.WithDetail("expected_digest", expectedBatch.Plan.BatchDigest))
		}
		if err := requireSemanticMatch("verification batch "+expectedBatch.Plan.BatchID, actualBatch, expectedBatch.Document); err != nil {
			return err
		}
	}
	if expected.Plan.ChangeSurface != nil {
		path := filepath.Join(state.Config.StateDir, "verification", "change-surface.json")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		actualSurface, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*4)
		if err != nil {
			return err
		}
		if err := requireSemanticMatch("change surface", actualSurface, expected.Plan.ChangeSurface); err != nil {
			return err
		}
	}
	return nil
}

func validatePlanVerificationBatchOutput(state *State, artifact ArtifactRecord, data []byte) error {
	expected, err := expectedPlanningResult(state)
	if err != nil {
		return err
	}
	for _, expectedBatch := range expected.Batches {
		expectedRole := "verification-batch:" + expectedBatch.Plan.BatchID
		expectedPath := filepath.Join(state.Config.StateDir, "verification", "batches", expectedBatch.Plan.BatchID+".json")
		if artifact.Role != expectedRole {
			continue
		}
		if !recordedPathsEqual(artifact.Path, expectedPath) {
			return diag.New(
				CodeStateInvalid,
				"verification batch output path does not match the derived batch.",
				diag.WithDetail("role", artifact.Role),
				diag.WithDetail("actual_path", artifact.Path),
				diag.WithDetail("expected_path", expectedPath),
			)
		}
		actualBatch, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			return err
		}
		if err := contracts.ErrorFromDiagnostics(contracts.ValidateVerificationBatch(actualBatch, nil)); err != nil {
			return err
		}
		if actualDigest := digest.RawBytes(data); actualDigest != expectedBatch.Plan.BatchDigest {
			return diag.New(CodeStateInvalid, "verification batch raw digest does not match the verification plan.", diag.WithDetail("batch_id", expectedBatch.Plan.BatchID), diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", expectedBatch.Plan.BatchDigest))
		}
		return requireSemanticMatch("verification batch "+expectedBatch.Plan.BatchID, actualBatch, expectedBatch.Document)
	}
	return diag.New(
		CodeStateInvalid,
		"verification batch output is not part of the derived batch set.",
		diag.WithDetail("role", artifact.Role),
		diag.WithDetail("path", artifact.Path),
	)
}

func validatePlanDigest(plan planning.PlanDocument) error {
	if plan.SchemaVersion != planning.SchemaVersion {
		return diag.New(CodeStateInvalid, "verification plan schema_version is unsupported.", diag.WithDetail("actual", plan.SchemaVersion), diag.WithDetail("expected", planning.SchemaVersion))
	}
	if plan.DigestProfile != digest.Profile {
		return diag.New(CodeStateInvalid, "verification plan digest_profile is unsupported.", diag.WithDetail("actual", plan.DigestProfile), diag.WithDetail("expected", digest.Profile))
	}
	if strings.TrimSpace(plan.PlanDigest) == "" {
		return diag.New(CodeStateInvalid, "verification plan is missing plan_digest.")
	}
	unstamped := plan
	unstamped.PlanDigest = ""
	actualDigest, err := contracts.SemanticDigest(unstamped)
	if err != nil {
		return diag.Wrap(err, CodeStateInvalid, "verification plan digest could not be recomputed.")
	}
	if actualDigest != plan.PlanDigest {
		return diag.New(CodeStateInvalid, "verification plan digest does not match its content.", diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", plan.PlanDigest))
	}
	return nil
}

func expectedPlanningResult(state *State) (*planning.Result, error) {
	config := state.Config
	frozen, frozenBytes, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return nil, err
	}
	if err := validateFrozenCharterOutput(config, frozen); err != nil {
		return nil, err
	}
	preflightResult, err := readPreflightResult(config.Outputs.PreflightPath)
	if err != nil {
		return nil, err
	}
	if err := validatePlanningPreflight(preflightResult); err != nil {
		return nil, err
	}
	policyDocument, err := readReviewPolicy(config.PolicyPath)
	if err != nil {
		return nil, err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, config.BaselinePass)
	if err != nil {
		return nil, err
	}
	roleOutputs := make([]planning.RoleOutputInput, 0, len(config.RoleOutputs))
	for _, item := range config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			return nil, err
		}
		roleOutputs = append(roleOutputs, planning.RoleOutputInput{
			Path:     item.Path,
			RefID:    artifactIDFromPath(item.Path),
			Document: document,
		})
	}
	return planning.Run(planning.Options{
		FrozenCharter: &frozen,
		CharterDigest: digest.RawBytes(frozenBytes),
		RoleOutputs:   roleOutputs,
		Policy:        policyDocument,
		Preflight:     preflightBinding(preflightResult),
		ChangeSurface: changeSurface,
	})
}

func validateAssembleStageOutputs(state *State, role string) error {
	expected, err := expectedAssembleResult(state)
	if err != nil {
		return err
	}
	if hasSupplementaryAssembleContent(expected) {
		if _, err := os.Stat(assembleResultPath(state.Config)); err != nil {
			return err
		}
	}
	switch role {
	case "verification-manifest":
		actual, err := readVerificationManifest(state.Config.Outputs.ManifestPath)
		if err != nil {
			return err
		}
		if err := contracts.ErrorFromDiagnostics(contracts.ValidateVerificationManifest(actual)); err != nil {
			return err
		}
		return requireSemanticMatch("verification manifest", actual, expected.Manifest)
	case "assemble-result":
		if !hasSupplementaryAssembleContent(expected) {
			return diag.New(CodeStateInvalid, "assemble-result output is present but not semantically required.")
		}
		data, err := os.ReadFile(assembleResultPath(state.Config))
		if err != nil {
			return err
		}
		actual, err := strictjson.DecodeBytes[planning.AssembleResult](data, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return err
		}
		return requireSemanticMatch("assemble result", actual, *expected)
	default:
		return nil
	}
}

func expectedAssembleResult(state *State) (*planning.AssembleResult, error) {
	config := state.Config
	plan, err := readPlan(config.Outputs.PlanPath)
	if err != nil {
		return nil, err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, false)
	if err != nil {
		return nil, err
	}
	relayRecords, err := relayBatchRecordsFromValidatedPlan(state)
	if err != nil {
		return nil, err
	}
	batches, err := readBatchEvidence(relayRecords)
	if err != nil {
		return nil, err
	}
	receipts, err := readReceipts(config.ReceiptPaths)
	if err != nil {
		return nil, err
	}
	refs, err := manifestEvidenceRefs(config, plan.ConsumerIdentity)
	if err != nil {
		return nil, err
	}
	result, err := planning.Assemble(planning.AssembleOptions{
		Plan:               plan,
		Batches:            batches,
		RelayResults:       relayEvidenceFromReadyBatches(state, relayRecords),
		Receipts:           receipts,
		EvidenceRefs:       refs,
		BaseManifest:       changeSurface.BaseManifest,
		HeadManifest:       changeSurface.HeadManifest,
		ReceiptOutputDir:   config.ReceiptOutputDir,
		ReceiptHMACKeyFile: config.ReceiptHMACKeyFile,
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, diag.New(CodeStateInvalid, "assemble did not produce a verification manifest.")
	}
	return result, nil
}

func validateAdjudicateOutput(state *State) error {
	data, err := os.ReadFile(state.Config.Outputs.RunResultPath)
	if err != nil {
		return err
	}
	actual, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return err
	}
	if actual.SchemaVersion != adjudicate.ResultSchemaVersion {
		return diag.New(CodeStateInvalid, "adjudication result schema_version is unsupported.", diag.WithDetail("actual", actual.SchemaVersion), diag.WithDetail("expected", adjudicate.ResultSchemaVersion))
	}
	actualDigest, err := adjudicationResultDigest(actual)
	if err != nil {
		return err
	}
	if actual.ResultDigest != actualDigest {
		return diag.New(CodeStateInvalid, "adjudication result_digest does not match its content.", diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", actual.ResultDigest))
	}
	expected, err := expectedAdjudicationResult(state)
	if err != nil {
		return err
	}
	return requireSemanticMatch("adjudication result", actual, *expected)
}

func expectedAdjudicationResult(state *State) (*adjudicate.Result, error) {
	config := state.Config
	frozen, _, err := readFrozenCharter(config.Outputs.CharterFreezePath)
	if err != nil {
		return nil, err
	}
	manifest, err := readVerificationManifest(config.Outputs.ManifestPath)
	if err != nil {
		return nil, err
	}
	changeSurface, err := readDriverChangeSurfaceInput(config, false)
	if err != nil {
		return nil, err
	}
	roleOutputs := make([]adjudicate.RoleOutputInput, 0, len(config.RoleOutputs))
	for _, item := range config.RoleOutputs {
		document, err := readRoleOutput(item.Path)
		if err != nil {
			return nil, err
		}
		roleOutputs = append(roleOutputs, adjudicate.RoleOutputInput{Path: item.Path, Document: document})
	}
	var priorLineage []adjudicate.PriorLineageRecord
	priorProvided := config.PriorLineagePath != ""
	if priorProvided {
		priorLineage, err = adjudicate.ReadPriorLineageFile(config.PriorLineagePath)
		if err != nil {
			return nil, err
		}
	}
	effective, err := loadEffectivePolicy(config)
	if err != nil {
		return nil, err
	}
	result, runErr := adjudicate.Run(adjudicate.Options{
		FrozenCharter:                &frozen,
		RoleOutputs:                  roleOutputs,
		Manifest:                     manifest,
		BaseManifest:                 changeSurface.BaseManifest,
		HeadManifest:                 changeSurface.HeadManifest,
		ReceiptOutputDir:             config.ReceiptOutputDir,
		ReceiptHMACKeyFile:           config.ReceiptHMACKeyFile,
		Rules:                        effective.Rules,
		Policy:                       effective.Policy,
		PolicyCapReleaseLedgerBacked: effective.CapRelease != nil,
		PriorLineage:                 priorLineage,
		PriorLineageProvided:         priorProvided,
	})
	if runErr != nil {
		return nil, runErr
	}
	if result == nil {
		return nil, diag.New(CodeStateInvalid, "adjudication did not produce a run result.")
	}
	return result, nil
}

func validateMetricsOutput(state *State) error {
	data, err := os.ReadFile(state.Config.Outputs.MetricsPath)
	if err != nil {
		return err
	}
	actual, err := strictjson.DecodeBytes[metrics.Document](data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return err
	}
	if actual.SchemaVersion != metrics.SchemaVersion {
		return diag.New(CodeStateInvalid, "metrics result schema_version is unsupported.", diag.WithDetail("actual", actual.SchemaVersion), diag.WithDetail("expected", metrics.SchemaVersion))
	}
	expected, err := metrics.Run(metrics.Options{
		LedgerPath:     state.Config.LedgerPath,
		PreflightPath:  state.Config.Outputs.PreflightPath,
		RunResultPaths: []string{state.Config.Outputs.RunResultPath},
	})
	if err != nil {
		return err
	}
	return requireSemanticMatch("metrics", actual, expected)
}

func adjudicationResultDigest(result adjudicate.Result) (string, error) {
	result.ResultDigest = ""
	return digest.SemanticJSON(result)
}

func requireSemanticMatch(label string, actual any, expected any) error {
	actualDigest, err := digest.SemanticJSON(actual)
	if err != nil {
		return diag.Wrap(err, CodeStateInvalid, "semantic digest could not be computed.", diag.WithDetail("artifact", label), diag.WithDetail("side", "actual"))
	}
	expectedDigest, err := digest.SemanticJSON(expected)
	if err != nil {
		return diag.Wrap(err, CodeStateInvalid, "semantic digest could not be computed.", diag.WithDetail("artifact", label), diag.WithDetail("side", "expected"))
	}
	if actualDigest != expectedDigest {
		return diag.New(CodeStateInvalid, "recorded output does not match semantically derived content.", diag.WithDetail("artifact", label), diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", expectedDigest))
	}
	return nil
}

func recordedPathsEqual(left string, right string) bool {
	if filepath.Clean(left) == filepath.Clean(right) {
		return true
	}
	leftComparable, leftErr := comparablePathString(left)
	rightComparable, rightErr := comparablePathString(right)
	return leftErr == nil && rightErr == nil && leftComparable == rightComparable
}

func stateInvalidDiagnostic(message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: CodeStateInvalid, Message: message, Path: path, Details: details}
}

func stateDriftDiagnostic(message string, stage string, artifact ArtifactRecord, details map[string]any) diag.Diagnostic {
	if details == nil {
		details = map[string]any{}
	}
	details["stage"] = stage
	details["role"] = artifact.Role
	details["path"] = artifact.Path
	return diag.Diagnostic{Code: CodeStateDrift, Message: message, Details: details}
}

func stageDetailInt(stage StageRecord, key string) int {
	value, ok := stage.Details[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	default:
		return 0
	}
}

func digestClassRaw() string {
	return digest.ClassRawBytes
}
