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
		inputs := []artifactInput{
			{role: "verification-plan", path: config.Outputs.PlanPath, digestClass: digestClassRaw()},
			{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digestClassRaw()},
			{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digestClassRaw()},
			{role: "integration-bundle-retained", path: retainedIntegrationBundlePath(config), digestClass: digestClassRaw()},
			{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest},
			{role: "head-manifest", path: config.HeadManifestPath, digestClass: digestClassFreezeManifest},
		}
		for _, batch := range state.RelayBatches {
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
			if err := decodeStageOutput(artifact); err != nil {
				diagnostics = append(diagnostics, diag.FromError(diag.Wrap(
					err,
					CodeStateInvalid,
					"recorded pass stage output could not be decoded.",
					diag.WithDetail("stage", stage.Name),
					diag.WithDetail("role", artifact.Role),
					diag.WithDetail("path", artifact.Path),
				)))
			}
		}
	}
	return diagnostics
}

func decodeStageOutput(artifact ArtifactRecord) error {
	data, err := os.ReadFile(artifact.Path)
	if err != nil {
		return err
	}
	switch {
	case artifact.Role == "charter-freeze":
		_, err = strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	case artifact.Role == "source-snapshot-manifest":
		_, err = strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
	case artifact.Role == "preflight":
		_, err = strictjson.DecodeBytes[preflight.Result](data, strictjson.DefaultMaxBytes*4)
	case artifact.Role == "verification-plan":
		_, err = strictjson.DecodeBytes[planning.PlanDocument](data, strictjson.DefaultMaxBytes*4)
	case strings.HasPrefix(artifact.Role, "verification-batch:"):
		_, err = contracts.ReadVerificationBatchBytes(data)
	case artifact.Role == "verification-manifest":
		_, err = contracts.ReadVerificationManifestBytes(data)
	case artifact.Role == "assemble-result":
		_, err = strictjson.DecodeBytes[planning.AssembleResult](data, strictjson.DefaultMaxBytes*8)
	case artifact.Role == "run-result":
		_, err = strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes*4)
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
