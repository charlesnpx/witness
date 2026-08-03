package pass

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"witness/internal/adjudicate"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/metrics"
	"witness/internal/planning"
	"witness/internal/preflight"
	"witness/internal/strictjson"
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
		return []artifactInput{
				{role: "integration-bundle", path: config.IntegrationBundlePath, digestClass: digestClassRaw()},
				{role: "source-snapshot-manifest", path: config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
			}, []artifactInput{
				{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digestClassRaw()},
				{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digestClassRaw()},
				{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digestClassRaw()},
				{role: "integration-bundle-retained", path: retainedIntegrationBundlePath(config), digestClass: digestClassRaw()},
			}
	case stagePlan:
		inputs := []artifactInput{
			{role: "charter-freeze", path: config.Outputs.CharterFreezePath, digestClass: digestClassRaw()},
			{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digestClassRaw()},
			{role: "policy", path: config.PolicyPath, digestClass: digestClassRaw()},
			{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
			{role: "head-manifest", path: config.HeadManifestPath, digestClass: digestClassFreezeManifest},
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
			{role: "head-manifest", path: config.HeadManifestPath, digestClass: digestClassFreezeManifest},
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
		if stageDetailInt(stage, "unverified_relationship_count") > 0 {
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
			{role: "head-manifest", path: config.HeadManifestPath, digestClass: digestClassFreezeManifest},
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
			err = validateFrozenCharterOutput(frozen)
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
	case artifact.Role == "verification-plan":
		err = validatePlanStageOutputs(state)
	case strings.HasPrefix(artifact.Role, "verification-batch:"):
		var batch contracts.VerificationBatchDocument
		batch, err = contracts.ReadVerificationBatchBytes(data)
		if err == nil {
			err = contracts.ErrorFromDiagnostics(contracts.ValidateVerificationBatch(batch, nil))
		}
	case artifact.Role == "verification-manifest":
		err = validateAssembleStageOutputs(state, artifact.Role)
	case artifact.Role == "assemble-result":
		err = validateAssembleStageOutputs(state, artifact.Role)
	case artifact.Role == "run-result":
		err = validateAdjudicateOutput(state)
	case artifact.Role == "metrics":
		err = validateMetricsOutput(state)
	default:
		_, err = strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*8)
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

func validateFrozenCharterOutput(frozen charter.FrozenCharter) error {
	if frozen.SchemaVersion != charter.FrozenSchemaVersion {
		return diag.New(CodeStateInvalid, "frozen Charter schema_version is unsupported.", diag.WithDetail("actual", frozen.SchemaVersion), diag.WithDetail("expected", charter.FrozenSchemaVersion))
	}
	if frozen.DigestProfile != digest.Profile {
		return diag.New(CodeStateInvalid, "frozen Charter digest_profile is unsupported.", diag.WithDetail("actual", frozen.DigestProfile), diag.WithDetail("expected", digest.Profile))
	}
	input := charter.Charter{
		SchemaVersion:       frozen.Charter.SchemaVersion,
		Goals:               frozen.Charter.Goals,
		NonGoals:            frozen.Charter.NonGoals,
		OwnerEvents:         frozen.Charter.OwnerEvents,
		OperationalEnvelope: frozen.Charter.OperationalEnvelope,
	}
	if diagnostics := charter.Validate(input, nil); len(diagnostics) > 0 {
		return diag.New(CodeStateInvalid, "embedded frozen Charter failed validation.", diag.WithDetail("diagnostic", diagnostics[0]))
	}
	hash, err := charter.Hash(frozen.Charter)
	if err != nil {
		return diag.Wrap(err, CodeStateInvalid, "frozen Charter hash could not be recomputed.")
	}
	if hash != frozen.CharterHash {
		return diag.New(CodeStateInvalid, "frozen Charter hash does not match embedded Charter.", diag.WithDetail("actual_digest", hash), diag.WithDetail("expected_digest", frozen.CharterHash))
	}
	return nil
}

func validateFreezeManifestOutput(config Config, manifest freeze.Manifest) (string, error) {
	if manifest.SchemaVersion != freeze.SchemaVersion {
		return "", diag.New(CodeStateInvalid, "snapshot manifest schema_version is unsupported.", diag.WithDetail("actual", manifest.SchemaVersion), diag.WithDetail("expected", freeze.SchemaVersion))
	}
	if manifest.DigestProfile != digest.Profile {
		return "", diag.New(CodeStateInvalid, "snapshot manifest digest_profile is unsupported.", diag.WithDetail("actual", manifest.DigestProfile), diag.WithDetail("expected", digest.Profile))
	}
	if config.SourceDir != "" && !recordedPathsEqual(manifest.Source.Path, config.SourceDir) {
		return "", diag.New(CodeStateInvalid, "snapshot manifest source path does not match pass config.", diag.WithDetail("actual", manifest.Source.Path), diag.WithDetail("expected", config.SourceDir))
	}
	if config.SnapshotDir != "" && !recordedPathsEqual(manifest.Workspace.Path, config.SnapshotDir) {
		return "", diag.New(CodeStateInvalid, "snapshot manifest workspace path does not match pass config.", diag.WithDetail("actual", manifest.Workspace.Path), diag.WithDetail("expected", config.SnapshotDir))
	}
	if config.SnapshotManifestPath != "" && !recordedPathsEqual(manifest.Workspace.ManifestPath, config.SnapshotManifestPath) {
		return "", diag.New(CodeStateInvalid, "snapshot manifest path does not match pass config.", diag.WithDetail("actual", manifest.Workspace.ManifestPath), diag.WithDetail("expected", config.SnapshotManifestPath))
	}
	actualDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return "", diag.Wrap(err, CodeStateInvalid, "snapshot manifest digest could not be recomputed.")
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
	if result.SchemaVersion != preflight.SchemaVersion {
		return diag.New(CodeStateInvalid, "preflight result schema_version is unsupported.", diag.WithDetail("actual", result.SchemaVersion), diag.WithDetail("expected", preflight.SchemaVersion))
	}
	if !result.OK || len(result.Diagnostics) > 0 {
		return diag.New(CodeStateInvalid, "completed preflight output contains blocking diagnostics.", diag.WithDetail("ok", result.OK), diag.WithDetail("diagnostic_count", len(result.Diagnostics)))
	}
	manifest, err := readFreezeManifest(config.SnapshotManifestPath)
	if err != nil {
		return err
	}
	snapshotDigest, err := validateFreezeManifestOutput(config, manifest)
	if err != nil {
		return err
	}
	if result.SnapshotDigest != snapshotDigest {
		return diag.New(CodeStateInvalid, "preflight snapshot digest does not match the validated snapshot manifest.", diag.WithDetail("actual_digest", result.SnapshotDigest), diag.WithDetail("expected_digest", snapshotDigest))
	}
	if recorded := result.ArtifactDigests["source-snapshot-manifest"]; recorded != snapshotDigest {
		return diag.New(CodeStateInvalid, "preflight artifact digest for source snapshot manifest is invalid.", diag.WithDetail("actual_digest", recorded), diag.WithDetail("expected_digest", snapshotDigest))
	}
	for relativePath, expectedDigest := range result.ArtifactDigests {
		if relativePath == "source-snapshot-manifest" {
			continue
		}
		path, err := preflightRetainedArtifactPath(config.StateDir, relativePath)
		if err != nil {
			return err
		}
		actualDigest, err := retainedArtifactPayloadDigest(path)
		if err != nil {
			return err
		}
		if actualDigest != expectedDigest {
			return diag.New(CodeStateInvalid, "preflight retained artifact digest does not match retained payload.", diag.WithDetail("path", path), diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", expectedDigest))
		}
	}
	if expectedDigest := result.ContractDigests["integration_bundle"]; expectedDigest != "" {
		actualDigest, err := retainedArtifactPayloadDigest(retainedIntegrationBundlePath(config))
		if err != nil {
			return err
		}
		if actualDigest != expectedDigest {
			return diag.New(CodeStateInvalid, "preflight integration bundle digest does not match retained payload.", diag.WithDetail("actual_digest", actualDigest), diag.WithDetail("expected_digest", expectedDigest))
		}
	}
	if compatibilityPath := filepath.Join(config.StateDir, "compatibility-manifest.json"); result.ArtifactDigests["compatibility-manifest.json"] != "" {
		if _, err := relayCompatibilityFromArtifactFile(compatibilityPath); err != nil {
			return err
		}
	}
	return nil
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
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	payloadBytes, err := retainedPayloadCanonicalBytes(data)
	if err != nil {
		return "", err
	}
	if len(payloadBytes) == 0 {
		return "", diag.New(CodeStateInvalid, "preflight retained artifact is missing its payload envelope.", diag.WithDetail("path", path))
	}
	return digest.RawBytes(payloadBytes), nil
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
	if err := validateFrozenCharterOutput(frozen); err != nil {
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
	changeSurface, err := readChangeSurfaceInput(config.BaseManifestPath, config.HeadManifestPath, config.BaselinePass)
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
	changeSurface, err := readChangeSurfaceInput(config.BaseManifestPath, config.HeadManifestPath, false)
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
	changeSurface, err := readChangeSurfaceInput(config.BaseManifestPath, config.HeadManifestPath, false)
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
