package contracts

import (
	"fmt"
	"io"
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/review"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/changesurface"
)

const (
	VerificationManifestRelayLaunchStatusKey      = "witness_relay_launch_status"
	VerificationManifestRelayBatchesKey           = "witness_relay_batches"
	VerificationManifestBatchRelayLaunchStatusKey = "relay_launch_status"
)

type VerificationManifest struct {
	SchemaVersion         string                           `json:"schema_version"`
	PlanDigest            string                           `json:"plan_digest"`
	CharterHash           string                           `json:"charter_hash"`
	ArtifactDigest        string                           `json:"artifact_digest"`
	ScopePolicy           string                           `json:"scope_policy,omitempty"`
	ChangeSurface         *changesurface.Document          `json:"change_surface,omitempty"`
	ChangeSurfaceDigest   string                           `json:"change_surface_digest,omitempty"`
	BaselinePass          *changesurface.BaselinePass      `json:"baseline_pass,omitempty"`
	CompatibilityManifest ArtifactRef                      `json:"compatibility_manifest"`
	RelayCapabilities     ArtifactRef                      `json:"relay_capabilities"`
	IntegrationBundle     ArtifactRef                      `json:"integration_bundle"`
	SelectedContracts     []ArtifactRef                    `json:"selected_contracts"`
	Batches               []VerificationManifestBatch      `json:"batches"`
	ExcludedFindings      []ExcludedFindingRecord          `json:"excluded_findings,omitempty"`
	ExecutionReceipts     []ExecutionReceiptManifestRecord `json:"execution_receipts,omitempty"`
	ConsumerIdentity      map[string]any                   `json:"consumer_identity"`
}

type VerificationManifestBatch struct {
	BatchID               string                        `json:"batch_id"`
	Status                string                        `json:"status"`
	BatchRef              ArtifactRef                   `json:"batch_ref"`
	BatchDigest           string                        `json:"batch_digest"`
	PortableExportRef     *ArtifactRef                  `json:"portable_export_ref,omitempty"`
	PortableExportDigest  string                        `json:"portable_export_digest,omitempty"`
	CanonicalResultDigest string                        `json:"canonical_result_digest,omitempty"`
	RelayVerdicts         *RelayWitnessVerdictsDocument `json:"relay_verdicts,omitempty"`
	FailureReason         string                        `json:"failure_reason,omitempty"`
}

type ExecutionReceiptManifestRecord struct {
	FindingID     string       `json:"finding_id"`
	Status        string       `json:"status"`
	ReceiptRef    *ArtifactRef `json:"receipt_ref,omitempty"`
	ReceiptDigest string       `json:"receipt_digest,omitempty"`
	FailureReason string       `json:"failure_reason,omitempty"`
}

type ExcludedFindingRecord struct {
	Role                   string      `json:"role"`
	FindingID              string      `json:"finding_id"`
	SourceRoleOutputRef    ArtifactRef `json:"source_role_output_ref"`
	SourceRoleOutputDigest string      `json:"source_role_output_digest"`
	Reason                 string      `json:"reason"`
	Disposition            string      `json:"disposition"`
}

type ExecutionReceipt struct {
	SchemaVersion            string                `json:"schema_version"`
	ReceiptID                string                `json:"receipt_id"`
	FindingID                string                `json:"finding_id"`
	CharterHash              string                `json:"charter_hash"`
	ArtifactDigest           string                `json:"artifact_digest"`
	FrozenSource             ArtifactRef           `json:"frozen_source"`
	Harness                  HarnessIdentity       `json:"harness"`
	Issuer                   ReceiptIssuer         `json:"issuer"`
	Authentication           ReceiptAuthentication `json:"authentication"`
	Command                  ExecutableSpec        `json:"command"`
	Containment              ContainmentReport     `json:"containment"`
	SourceInventoryBefore    ArtifactRef           `json:"source_inventory_before"`
	SourceInventoryAfter     ArtifactRef           `json:"source_inventory_after"`
	WorkspaceInventoryBefore ArtifactRef           `json:"workspace_inventory_before"`
	WorkspaceInventoryAfter  ArtifactRef           `json:"workspace_inventory_after"`
	Captures                 ExecutionCaptures     `json:"captures"`
	ExpectedObservation      string                `json:"expected_observation"`
	ObservedObservation      string                `json:"observed_observation"`
	ExecutionStatus          string                `json:"execution_status"`
	TransformationRef        *ArtifactRef          `json:"transformation_ref,omitempty"`
	ResultWorkspaceDigest    string                `json:"result_workspace_digest,omitempty"`
	Environment              map[string]string     `json:"environment,omitempty"`
	ResourceLimits           map[string]any        `json:"resource_limits,omitempty"`
}

type HarnessIdentity struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	BuildDigest string `json:"build_digest"`
}

type ReceiptIssuer struct {
	ID     string `json:"id"`
	Actor  string `json:"actor"`
	Method string `json:"method"`
}

type ReceiptAuthentication struct {
	Scheme       string `json:"scheme"`
	KeyID        string `json:"key_id"`
	SignedDigest string `json:"signed_digest"`
	Signature    string `json:"signature"`
}

type ContainmentReport struct {
	Filesystem string `json:"filesystem"`
	Network    string `json:"network"`
	Process    string `json:"process"`
	Notes      string `json:"notes,omitempty"`
}

type ExecutionCaptures struct {
	Stdout            *ArtifactRef  `json:"stdout,omitempty"`
	Stderr            *ArtifactRef  `json:"stderr,omitempty"`
	ProducedArtifacts []ArtifactRef `json:"produced_artifacts,omitempty"`
}

func ReadVerificationManifest(reader io.Reader) (VerificationManifest, error) {
	data, err := io.ReadAll(io.LimitReader(reader, strictjson.DefaultMaxBytes+1))
	if err != nil {
		return VerificationManifest{}, err
	}
	return ReadVerificationManifestBytes(data)
}

func ReadVerificationManifestBytes(data []byte) (VerificationManifest, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return VerificationManifest{}, err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return VerificationManifest{}, diag.New(CodeInvalidManifest, "verification manifest must be a JSON object.", diag.WithPath("/schema_version"))
	}
	actual, _ := document["schema_version"].(string)
	if actual != VerificationManifestV6 {
		return VerificationManifest{}, diag.New(
			CodeInvalidManifest,
			unsupportedSchemaVersionMessage("verification manifest", actual, VerificationManifestV6, VerificationManifestV5, "after exclusion reasons expanded."),
			diag.WithPath("/schema_version"),
			diag.WithDetail("expected", VerificationManifestV6),
			diag.WithDetail("actual", actual),
		)
	}
	return strictjson.DecodeBytes[VerificationManifest](data, strictjson.DefaultMaxBytes)
}

func ReadExecutionReceipt(reader io.Reader) (ExecutionReceipt, error) {
	return strictjson.Decode[ExecutionReceipt](reader, strictjson.DefaultMaxBytes)
}

func ReadExecutionReceiptBytes(data []byte) (ExecutionReceipt, error) {
	return strictjson.DecodeBytes[ExecutionReceipt](data, strictjson.DefaultMaxBytes)
}

func RequireValidVerificationManifest(document VerificationManifest) error {
	return ErrorFromDiagnostics(ValidateVerificationManifest(document))
}

func ValidateVerificationManifest(document VerificationManifest) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != VerificationManifestV6 {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "verification manifest schema_version must be review-verification-manifest-v6.", "/schema_version", map[string]any{"expected": VerificationManifestV6, "actual": document.SchemaVersion}))
	}
	review.RequireDigest(&diagnostics, "/plan_digest", "plan_digest", document.PlanDigest)
	review.RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	review.RequireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	diagnostics = append(diagnostics, validateManifestChangeSurface(document)...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/compatibility_manifest", validateArtifactRef(document.CompatibilityManifest, ""))...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/relay_capabilities", validateArtifactRef(document.RelayCapabilities, ""))...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/integration_bundle", validateArtifactRef(document.IntegrationBundle, ""))...)
	for index, ref := range document.SelectedContracts {
		diagnostics = append(diagnostics, review.PrefixDiagnostics("/selected_contracts/"+itoa(index), validateArtifactRef(ref, ""))...)
	}
	if !review.IdentityPresent(document.ConsumerIdentity) {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "consumer_identity is required.", "/consumer_identity", nil))
	}
	diagnostics = append(diagnostics, validateManifestRelayLaunchStatus(document)...)
	for index, batch := range document.Batches {
		diagnostics = append(diagnostics, validateManifestBatch(batch, "/batches/"+itoa(index))...)
	}
	for index, excluded := range document.ExcludedFindings {
		diagnostics = append(diagnostics, validateExcludedFindingRecord(excluded, "/excluded_findings/"+itoa(index))...)
	}
	for index, receipt := range document.ExecutionReceipts {
		diagnostics = append(diagnostics, validateExecutionReceiptRecord(receipt, "/execution_receipts/"+itoa(index))...)
	}
	return diagnostics
}

func validateManifestRelayLaunchStatus(document VerificationManifest) []diag.Diagnostic {
	identity := document.ConsumerIdentity
	if len(identity) == 0 {
		return nil
	}
	globalValue, globalMarkerPresent := identity[VerificationManifestRelayLaunchStatusKey]
	rawBatches, batchMetadataPresent := identity[VerificationManifestRelayBatchesKey]
	if !globalMarkerPresent && !batchMetadataPresent {
		return nil
	}
	var diagnostics []diag.Diagnostic
	globalStatus, globalStatusOK := manifestRelayLaunchStatus(globalValue)
	globalStatusValid := globalMarkerPresent && globalStatusOK && validRelayLaunchStatus(globalStatus)
	if !globalMarkerPresent {
		diagnostics = append(diagnostics, review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity witness_relay_launch_status is required when relay batch metadata is present.",
			"/consumer_identity/"+VerificationManifestRelayLaunchStatusKey,
			nil,
		))
	} else if !globalStatusOK || !validRelayLaunchStatus(globalStatus) {
		diagnostics = append(diagnostics, review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity witness_relay_launch_status has an unsupported value.",
			"/consumer_identity/"+VerificationManifestRelayLaunchStatusKey,
			map[string]any{"value": globalValue},
		))
	}
	if !batchMetadataPresent {
		return diagnostics
	}
	batches, ok := rawBatches.(map[string]any)
	if !ok {
		diagnostics = append(diagnostics, review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity witness_relay_batches must be an object when present.",
			"/consumer_identity/"+VerificationManifestRelayBatchesKey,
			nil,
		))
		return diagnostics
	}
	knownBatchIDs := make(map[string]bool, len(document.Batches))
	for _, batch := range document.Batches {
		knownBatchIDs[batch.BatchID] = true
		path := review.AppendPointer("/consumer_identity/"+VerificationManifestRelayBatchesKey, batch.BatchID)
		raw, exists := batches[batch.BatchID]
		if !exists {
			if globalMarkerPresent {
				diagnostics = append(diagnostics, review.Diagnostic(
					CodeInvalidManifest,
					"consumer_identity relay batch metadata is required when relay launch status is recorded.",
					path,
					map[string]any{"batch_id": batch.BatchID},
				))
			}
			continue
		}
		diagnostics = append(diagnostics, validateManifestRelayBatchLaunchStatus(raw, path, globalStatus, globalStatusValid)...)
	}
	for batchID, raw := range batches {
		if knownBatchIDs[batchID] {
			continue
		}
		path := review.AppendPointer("/consumer_identity/"+VerificationManifestRelayBatchesKey, batchID)
		diagnostics = append(diagnostics, validateManifestExtraRelayBatchLaunchStatus(raw, path, globalStatus, globalStatusValid)...)
	}
	return diagnostics
}

func validateManifestRelayBatchLaunchStatus(raw any, path string, globalStatus string, globalStatusValid bool) []diag.Diagnostic {
	object, ok := raw.(map[string]any)
	if !ok {
		return []diag.Diagnostic{review.Diagnostic(CodeInvalidManifest, "consumer_identity relay batch metadata must be an object.", path, nil)}
	}
	value, exists := object[VerificationManifestBatchRelayLaunchStatusKey]
	status, statusOK := manifestRelayLaunchStatus(value)
	statusPath := path + "/" + VerificationManifestBatchRelayLaunchStatusKey
	if !exists {
		return []diag.Diagnostic{review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity relay batch metadata requires relay_launch_status.",
			statusPath,
			nil,
		)}
	}
	return validateManifestRelayBatchStatusValue(value, status, statusOK, statusPath, globalStatus, globalStatusValid)
}

func validateManifestExtraRelayBatchLaunchStatus(raw any, path string, globalStatus string, globalStatusValid bool) []diag.Diagnostic {
	object, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	value, exists := object[VerificationManifestBatchRelayLaunchStatusKey]
	if !exists {
		return nil
	}
	status, statusOK := manifestRelayLaunchStatus(value)
	return validateManifestRelayBatchStatusValue(value, status, statusOK, path+"/"+VerificationManifestBatchRelayLaunchStatusKey, globalStatus, globalStatusValid)
}

func validateManifestRelayBatchStatusValue(value any, status string, statusOK bool, path string, globalStatus string, globalStatusValid bool) []diag.Diagnostic {
	if !statusOK || !validRelayLaunchStatus(status) {
		return []diag.Diagnostic{review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity relay batch metadata relay_launch_status has an unsupported value.",
			path,
			map[string]any{"value": value},
		)}
	}
	if globalStatusValid && status != globalStatus {
		return []diag.Diagnostic{review.Diagnostic(
			CodeInvalidManifest,
			"consumer_identity relay batch metadata relay_launch_status does not match witness_relay_launch_status.",
			path,
			map[string]any{"actual": status, "expected": globalStatus},
		)}
	}
	return nil
}

func manifestRelayLaunchStatus(value any) (string, bool) {
	status, ok := value.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(status), true
}

func validRelayLaunchStatus(status string) bool {
	return status == RelayLaunchStatusAbsent || status == RelayLaunchStatusPresent
}

func validateManifestChangeSurface(document VerificationManifest) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	scopePolicy := changesurface.ScopePolicy(document.ScopePolicy)
	if !changesurface.ValidateScopePolicy(document.ScopePolicy) {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "scope_policy must be delta_obligating or whole_tree when set.", "/scope_policy", map[string]any{"value": document.ScopePolicy}))
	}
	if document.ChangeSurface != nil {
		surfaceDiagnostics := changesurface.Validate(*document.ChangeSurface)
		for _, item := range surfaceDiagnostics {
			item.Code = CodeInvalidManifest
			diagnostics = append(diagnostics, review.PrefixDiagnostics("/change_surface", []diag.Diagnostic{item})...)
		}
		if len(surfaceDiagnostics) == 0 {
			surfaceDigest, err := changesurface.Digest(*document.ChangeSurface)
			if err != nil {
				diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "change surface digest could not be computed.", "/change_surface_digest", map[string]any{"error": err.Error()}))
			} else {
				review.CompareDigest(&diagnostics, "/change_surface_digest", "change surface", document.ChangeSurfaceDigest, surfaceDigest)
				review.CompareDigest(&diagnostics, "/change_surface/head_artifact_digest", "change surface head artifact", document.ChangeSurface.HeadArtifactDigest, document.ArtifactDigest)
			}
		}
	} else if document.ChangeSurfaceDigest != "" {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "change_surface_digest requires an embedded change_surface document.", "/change_surface_digest", nil))
	}
	if document.BaselinePass != nil {
		if !document.BaselinePass.Declared {
			diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "baseline_pass marker must be declared when present.", "/baseline_pass/declared", nil))
		}
		if document.BaselinePass.Reason == "" {
			diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "baseline_pass reason is required.", "/baseline_pass/reason", nil))
		}
		if document.ChangeSurface != nil {
			diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "baseline_pass and change_surface are mutually exclusive.", "/baseline_pass", nil))
		}
	}
	if scopePolicy == changesurface.ScopePolicyDeltaObligating && document.ChangeSurface == nil && document.BaselinePass == nil {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "delta_obligating manifests require a change_surface or explicit baseline_pass.", "/change_surface", map[string]any{"scope_policy": scopePolicy}))
	}
	return diagnostics
}

func validateManifestBatch(batch VerificationManifestBatch, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireStableID(&diagnostics, path+"/batch_id", "batch ID", batch.BatchID)
	review.RequireEnum(&diagnostics, path+"/status", "manifest record status", batch.Status, review.StringSet(RecordStatusValid, RecordStatusFailed, RecordStatusUnavailable, RecordStatusNotRequired), CodeInvalidManifest)
	diagnostics = append(diagnostics, review.PrefixDiagnostics(path+"/batch_ref", validateArtifactRef(batch.BatchRef, ""))...)
	review.RequireDigest(&diagnostics, path+"/batch_digest", "batch digest", batch.BatchDigest)
	if batch.BatchRef.Digest != "" {
		review.CompareDigest(&diagnostics, path+"/batch_ref/digest", "batch ref", batch.BatchRef.Digest, batch.BatchDigest)
	}
	if batch.Status == RecordStatusValid {
		diagnostics = append(diagnostics, validateArtifactRefPointer(batch.PortableExportRef, path+"/portable_export_ref", true)...)
		review.RequireDigest(&diagnostics, path+"/portable_export_digest", "portable_export_digest", batch.PortableExportDigest)
		review.RequireDigest(&diagnostics, path+"/canonical_result_digest", "canonical_result_digest", batch.CanonicalResultDigest)
		if batch.PortableExportRef != nil && batch.PortableExportDigest != "" {
			review.CompareDigest(&diagnostics, path+"/portable_export_ref/digest", "portable export ref", batch.PortableExportRef.Digest, batch.PortableExportDigest)
		}
		if batch.RelayVerdicts == nil {
			diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "valid relay manifest records require relay_verdicts.", path+"/relay_verdicts", nil))
		} else {
			diagnostics = append(diagnostics, review.PrefixDiagnostics(path+"/relay_verdicts", ValidateRelayWitnessVerdicts(*batch.RelayVerdicts, nil))...)
			relayVerdictsDigest, err := RelayWitnessVerdictsDigest(*batch.RelayVerdicts)
			if err != nil {
				diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "embedded relay_verdicts digest could not be recomputed.", path+"/canonical_result_digest", map[string]any{"error": err.Error()}))
			} else {
				review.CompareDigest(&diagnostics, path+"/canonical_result_digest", "embedded relay_verdicts", batch.CanonicalResultDigest, relayVerdictsDigest)
			}
		}
		return diagnostics
	}
	if batch.RelayVerdicts != nil {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "relay_verdicts may be present only when relay verification status is valid.", path+"/relay_verdicts", map[string]any{"status": batch.Status}))
	}
	return diagnostics
}

func validateExecutionReceiptRecord(record ExecutionReceiptManifestRecord, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireStableID(&diagnostics, path+"/finding_id", "finding ID", record.FindingID)
	review.RequireEnum(&diagnostics, path+"/status", "execution status", record.Status, review.StringSet(ExecutionStatusSatisfied, ExecutionStatusContradicted, ExecutionStatusFailed, ExecutionStatusUnavailable, ExecutionStatusNotRequired), CodeInvalidManifest)
	requiredReceipt := record.Status == ExecutionStatusSatisfied || record.Status == ExecutionStatusContradicted
	diagnostics = append(diagnostics, validateArtifactRefPointer(record.ReceiptRef, path+"/receipt_ref", requiredReceipt)...)
	if requiredReceipt {
		review.RequireDigest(&diagnostics, path+"/receipt_digest", "receipt digest", record.ReceiptDigest)
	}
	if record.ReceiptRef != nil && record.ReceiptDigest != "" {
		review.CompareDigest(&diagnostics, path+"/receipt_ref/digest", "receipt ref", record.ReceiptRef.Digest, record.ReceiptDigest)
	}
	return diagnostics
}

func validateExcludedFindingRecord(record ExcludedFindingRecord, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireEnum(&diagnostics, path+"/role", "role", record.Role, review.StringSet(RoleDefect, RoleEconomy), CodeInvalidManifest)
	review.RequireStableID(&diagnostics, path+"/finding_id", "finding ID", record.FindingID)
	diagnostics = append(diagnostics, review.PrefixDiagnostics(path+"/source_role_output_ref", validateArtifactRef(record.SourceRoleOutputRef, ""))...)
	if record.SourceRoleOutputRef.Kind != "" && record.SourceRoleOutputRef.Kind != "role-output" {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "excluded finding source_role_output_ref must reference a role-output artifact.", path+"/source_role_output_ref/kind", map[string]any{"actual": record.SourceRoleOutputRef.Kind, "expected": "role-output"}))
	}
	review.RequireDigest(&diagnostics, path+"/source_role_output_digest", "source role-output digest", record.SourceRoleOutputDigest)
	if record.SourceRoleOutputRef.Digest != "" && record.SourceRoleOutputDigest != "" {
		review.CompareDigest(&diagnostics, path+"/source_role_output_ref/digest", "source role-output reference", record.SourceRoleOutputRef.Digest, record.SourceRoleOutputDigest)
	}
	if !excludedFindingReason(record.Reason) {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "excluded finding reason must be out_of_delta, pre_existing, or attribution_unattributed.", path+"/reason", map[string]any{"actual": record.Reason, "expected": []string{ReasonOutOfDelta, ReasonPreExisting, ReasonAttributionUnattributed}}))
	}
	if record.Disposition != DispositionAdvisory {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidManifest, "excluded finding disposition must be advisory.", path+"/disposition", map[string]any{"actual": record.Disposition, "expected": DispositionAdvisory}))
	}
	return diagnostics
}

func excludedFindingReason(reason string) bool {
	switch reason {
	case ReasonOutOfDelta, ReasonPreExisting, ReasonAttributionUnattributed:
		return true
	default:
		return false
	}
}

func unsupportedSchemaVersionMessage(artifact string, actual string, expected string, predecessor string, migration string) string {
	if strings.TrimSpace(actual) == "" {
		return fmt.Sprintf("%s schema_version is unsupported; a missing or unversioned schema_version is refused and %s is required.", artifact, expected)
	}
	if actual == predecessor && migration != "" {
		return fmt.Sprintf("%s schema_version is unsupported; %s is refused and %s is required %s", artifact, actual, expected, migration)
	}
	return fmt.Sprintf("%s schema_version is unsupported; %s is refused and %s is required.", artifact, actual, expected)
}

func RequireValidExecutionReceipt(document ExecutionReceipt) error {
	return ErrorFromDiagnostics(ValidateExecutionReceipt(document))
}

func ValidateExecutionReceipt(document ExecutionReceipt) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ExecutionReceiptV2 {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidReceipt, "execution receipt schema_version must be review-execution-receipt-v2.", "/schema_version", map[string]any{"expected": ExecutionReceiptV2, "actual": document.SchemaVersion}))
	}
	review.RequireStableID(&diagnostics, "/receipt_id", "receipt ID", document.ReceiptID)
	review.RequireStableID(&diagnostics, "/finding_id", "finding ID", document.FindingID)
	review.RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	review.RequireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/frozen_source", validateArtifactRef(document.FrozenSource, ""))...)
	diagnostics = append(diagnostics, validateHarness(document.Harness, "/harness")...)
	diagnostics = append(diagnostics, validateIssuer(document.Issuer, "/issuer")...)
	diagnostics = append(diagnostics, validateAuthentication(document.Authentication, "/authentication")...)
	diagnostics = append(diagnostics, validateExecutableSpec(document.Command, "/command", false)...)
	diagnostics = append(diagnostics, validateContainment(document.Containment, "/containment")...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/source_inventory_before", validateArtifactRef(document.SourceInventoryBefore, ""))...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/source_inventory_after", validateArtifactRef(document.SourceInventoryAfter, ""))...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/workspace_inventory_before", validateArtifactRef(document.WorkspaceInventoryBefore, ""))...)
	diagnostics = append(diagnostics, review.PrefixDiagnostics("/workspace_inventory_after", validateArtifactRef(document.WorkspaceInventoryAfter, ""))...)
	diagnostics = append(diagnostics, validateCaptures(document.Captures, "/captures")...)
	review.RequireString(&diagnostics, "/expected_observation", "expected observation", document.ExpectedObservation)
	review.RequireString(&diagnostics, "/observed_observation", "observed observation", document.ObservedObservation)
	review.RequireEnum(&diagnostics, "/execution_status", "execution status", document.ExecutionStatus, review.StringSet(ExecutionStatusSatisfied, ExecutionStatusContradicted, ExecutionStatusFailed, ExecutionStatusUnavailable, ExecutionStatusNotRequired), CodeInvalidReceipt)
	diagnostics = append(diagnostics, validateArtifactRefPointer(document.TransformationRef, "/transformation_ref", false)...)
	if document.ResultWorkspaceDigest != "" {
		review.RequireDigest(&diagnostics, "/result_workspace_digest", "result_workspace_digest", document.ResultWorkspaceDigest)
	}
	return diagnostics
}

func validateHarness(harness HarnessIdentity, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireStableID(&diagnostics, path+"/id", "harness ID", harness.ID)
	review.RequireString(&diagnostics, path+"/version", "harness version", harness.Version)
	review.RequireDigest(&diagnostics, path+"/build_digest", "harness build_digest", harness.BuildDigest)
	return diagnostics
}

func validateIssuer(issuer ReceiptIssuer, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireStableID(&diagnostics, path+"/id", "issuer ID", issuer.ID)
	review.RequireString(&diagnostics, path+"/actor", "issuer actor", issuer.Actor)
	review.RequireString(&diagnostics, path+"/method", "issuer method", issuer.Method)
	return diagnostics
}

func validateAuthentication(auth ReceiptAuthentication, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireString(&diagnostics, path+"/scheme", "authentication scheme", auth.Scheme)
	review.RequireString(&diagnostics, path+"/key_id", "authentication key_id", auth.KeyID)
	review.RequireDigest(&diagnostics, path+"/signed_digest", "authentication signed_digest", auth.SignedDigest)
	review.RequireString(&diagnostics, path+"/signature", "authentication signature", auth.Signature)
	return diagnostics
}

func validateContainment(containment ContainmentReport, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireString(&diagnostics, path+"/filesystem", "filesystem containment statement", containment.Filesystem)
	review.RequireString(&diagnostics, path+"/network", "network containment statement", containment.Network)
	review.RequireString(&diagnostics, path+"/process", "process containment statement", containment.Process)
	return diagnostics
}

func validateCaptures(captures ExecutionCaptures, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, validateArtifactRefPointer(captures.Stdout, path+"/stdout", false)...)
	diagnostics = append(diagnostics, validateArtifactRefPointer(captures.Stderr, path+"/stderr", false)...)
	for index, ref := range captures.ProducedArtifacts {
		diagnostics = append(diagnostics, review.PrefixDiagnostics(path+"/produced_artifacts/"+itoa(index), validateArtifactRef(ref, ""))...)
	}
	return diagnostics
}

func VerificationManifestDigest(document VerificationManifest) (string, error) {
	return SemanticDigest(document)
}

func VerificationManifestCanonicalBytes(document VerificationManifest) ([]byte, error) {
	return CanonicalBytes(document)
}

func ExecutionReceiptDigest(document ExecutionReceipt) (string, error) {
	return SemanticDigest(document)
}

func ExecutionReceiptCanonicalBytes(document ExecutionReceipt) ([]byte, error) {
	return CanonicalBytes(document)
}

func rawDigest(data []byte) string {
	return digest.RawBytes(data)
}
