package contracts

import (
	"io"

	"witness/internal/changesurface"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
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
	return strictjson.Decode[VerificationManifest](reader, strictjson.DefaultMaxBytes)
}

func ReadVerificationManifestBytes(data []byte) (VerificationManifest, error) {
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
	if document.SchemaVersion != VerificationManifestV4 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "verification manifest schema_version must be review-verification-manifest-v4.", "/schema_version", map[string]any{"expected": VerificationManifestV4, "actual": document.SchemaVersion}))
	}
	requireDigest(&diagnostics, "/plan_digest", "plan_digest", document.PlanDigest)
	requireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	requireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	diagnostics = append(diagnostics, validateManifestChangeSurface(document)...)
	diagnostics = append(diagnostics, prefixDiagnostics("/compatibility_manifest", validateArtifactRef(document.CompatibilityManifest, ""))...)
	diagnostics = append(diagnostics, prefixDiagnostics("/relay_capabilities", validateArtifactRef(document.RelayCapabilities, ""))...)
	diagnostics = append(diagnostics, prefixDiagnostics("/integration_bundle", validateArtifactRef(document.IntegrationBundle, ""))...)
	for index, ref := range document.SelectedContracts {
		diagnostics = append(diagnostics, prefixDiagnostics("/selected_contracts/"+itoa(index), validateArtifactRef(ref, ""))...)
	}
	if !identityPresent(document.ConsumerIdentity) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "consumer_identity is required.", "/consumer_identity", nil))
	}
	for index, batch := range document.Batches {
		diagnostics = append(diagnostics, validateManifestBatch(batch, "/batches/"+itoa(index))...)
	}
	for index, receipt := range document.ExecutionReceipts {
		diagnostics = append(diagnostics, validateExecutionReceiptRecord(receipt, "/execution_receipts/"+itoa(index))...)
	}
	return diagnostics
}

func validateManifestChangeSurface(document VerificationManifest) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	scopePolicy := EffectiveScopePolicy(ReviewPolicy{ScopePolicy: document.ScopePolicy})
	if document.ScopePolicy != "" && document.ScopePolicy != ScopePolicyDeltaObligating && document.ScopePolicy != ScopePolicyWholeTree {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "scope_policy must be delta_obligating or whole_tree when set.", "/scope_policy", map[string]any{"value": document.ScopePolicy}))
	}
	if document.ChangeSurface != nil {
		surfaceDiagnostics := changesurface.Validate(*document.ChangeSurface)
		for _, item := range surfaceDiagnostics {
			item.Code = CodeInvalidManifest
			diagnostics = append(diagnostics, prefixDiagnostics("/change_surface", []diag.Diagnostic{item})...)
		}
		if len(surfaceDiagnostics) == 0 {
			surfaceDigest, err := changesurface.Digest(*document.ChangeSurface)
			if err != nil {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "change surface digest could not be computed.", "/change_surface_digest", map[string]any{"error": err.Error()}))
			} else {
				compareDigest(&diagnostics, "/change_surface_digest", "change surface", document.ChangeSurfaceDigest, surfaceDigest)
				compareDigest(&diagnostics, "/change_surface/head_artifact_digest", "change surface head artifact", document.ChangeSurface.HeadArtifactDigest, document.ArtifactDigest)
			}
		}
	} else if document.ChangeSurfaceDigest != "" {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "change_surface_digest requires an embedded change_surface document.", "/change_surface_digest", nil))
	}
	if document.BaselinePass != nil {
		if !document.BaselinePass.Declared {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "baseline_pass marker must be declared when present.", "/baseline_pass/declared", nil))
		}
		if document.BaselinePass.Reason == "" {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "baseline_pass reason is required.", "/baseline_pass/reason", nil))
		}
		if document.ChangeSurface != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "baseline_pass and change_surface are mutually exclusive.", "/baseline_pass", nil))
		}
	}
	if scopePolicy == ScopePolicyDeltaObligating && document.ChangeSurface == nil && document.BaselinePass == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "delta_obligating manifests require a change_surface or explicit baseline_pass.", "/change_surface", map[string]any{"scope_policy": scopePolicy}))
	}
	return diagnostics
}

func validateManifestBatch(batch VerificationManifestBatch, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/batch_id", "batch ID", batch.BatchID)
	requireEnum(&diagnostics, path+"/status", "manifest record status", batch.Status, stringSet(RecordStatusValid, RecordStatusFailed, RecordStatusUnavailable, RecordStatusNotRequired), CodeInvalidManifest)
	diagnostics = append(diagnostics, prefixDiagnostics(path+"/batch_ref", validateArtifactRef(batch.BatchRef, ""))...)
	requireDigest(&diagnostics, path+"/batch_digest", "batch digest", batch.BatchDigest)
	if batch.BatchRef.Digest != "" {
		compareDigest(&diagnostics, path+"/batch_ref/digest", "batch ref", batch.BatchRef.Digest, batch.BatchDigest)
	}
	if batch.Status == RecordStatusValid {
		diagnostics = append(diagnostics, validateArtifactRefPointer(batch.PortableExportRef, path+"/portable_export_ref", true)...)
		requireDigest(&diagnostics, path+"/portable_export_digest", "portable_export_digest", batch.PortableExportDigest)
		requireDigest(&diagnostics, path+"/canonical_result_digest", "canonical_result_digest", batch.CanonicalResultDigest)
		if batch.PortableExportRef != nil && batch.PortableExportDigest != "" {
			compareDigest(&diagnostics, path+"/portable_export_ref/digest", "portable export ref", batch.PortableExportRef.Digest, batch.PortableExportDigest)
		}
		if batch.RelayVerdicts == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "valid relay manifest records require relay_verdicts.", path+"/relay_verdicts", nil))
		} else {
			diagnostics = append(diagnostics, prefixDiagnostics(path+"/relay_verdicts", ValidateRelayWitnessVerdicts(*batch.RelayVerdicts, nil))...)
			relayVerdictsDigest, err := RelayWitnessVerdictsDigest(*batch.RelayVerdicts)
			if err != nil {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "embedded relay_verdicts digest could not be recomputed.", path+"/canonical_result_digest", map[string]any{"error": err.Error()}))
			} else {
				compareDigest(&diagnostics, path+"/canonical_result_digest", "embedded relay_verdicts", batch.CanonicalResultDigest, relayVerdictsDigest)
			}
		}
		return diagnostics
	}
	if batch.RelayVerdicts != nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "relay_verdicts may be present only when relay verification status is valid.", path+"/relay_verdicts", map[string]any{"status": batch.Status}))
	}
	return diagnostics
}

func validateExecutionReceiptRecord(record ExecutionReceiptManifestRecord, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/finding_id", "finding ID", record.FindingID)
	requireEnum(&diagnostics, path+"/status", "execution status", record.Status, stringSet(ExecutionStatusSatisfied, ExecutionStatusContradicted, ExecutionStatusFailed, ExecutionStatusUnavailable, ExecutionStatusNotRequired), CodeInvalidManifest)
	requiredReceipt := record.Status == ExecutionStatusSatisfied || record.Status == ExecutionStatusContradicted
	diagnostics = append(diagnostics, validateArtifactRefPointer(record.ReceiptRef, path+"/receipt_ref", requiredReceipt)...)
	if requiredReceipt {
		requireDigest(&diagnostics, path+"/receipt_digest", "receipt digest", record.ReceiptDigest)
	}
	if record.ReceiptRef != nil && record.ReceiptDigest != "" {
		compareDigest(&diagnostics, path+"/receipt_ref/digest", "receipt ref", record.ReceiptRef.Digest, record.ReceiptDigest)
	}
	return diagnostics
}

func RequireValidExecutionReceipt(document ExecutionReceipt) error {
	return ErrorFromDiagnostics(ValidateExecutionReceipt(document))
}

func ValidateExecutionReceipt(document ExecutionReceipt) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ExecutionReceiptV2 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidReceipt, "execution receipt schema_version must be review-execution-receipt-v2.", "/schema_version", map[string]any{"expected": ExecutionReceiptV2, "actual": document.SchemaVersion}))
	}
	requireStableID(&diagnostics, "/receipt_id", "receipt ID", document.ReceiptID)
	requireStableID(&diagnostics, "/finding_id", "finding ID", document.FindingID)
	requireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	requireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	diagnostics = append(diagnostics, prefixDiagnostics("/frozen_source", validateArtifactRef(document.FrozenSource, ""))...)
	diagnostics = append(diagnostics, validateHarness(document.Harness, "/harness")...)
	diagnostics = append(diagnostics, validateIssuer(document.Issuer, "/issuer")...)
	diagnostics = append(diagnostics, validateAuthentication(document.Authentication, "/authentication")...)
	diagnostics = append(diagnostics, validateExecutableSpec(document.Command, "/command", false)...)
	diagnostics = append(diagnostics, validateContainment(document.Containment, "/containment")...)
	diagnostics = append(diagnostics, prefixDiagnostics("/source_inventory_before", validateArtifactRef(document.SourceInventoryBefore, ""))...)
	diagnostics = append(diagnostics, prefixDiagnostics("/source_inventory_after", validateArtifactRef(document.SourceInventoryAfter, ""))...)
	diagnostics = append(diagnostics, prefixDiagnostics("/workspace_inventory_before", validateArtifactRef(document.WorkspaceInventoryBefore, ""))...)
	diagnostics = append(diagnostics, prefixDiagnostics("/workspace_inventory_after", validateArtifactRef(document.WorkspaceInventoryAfter, ""))...)
	diagnostics = append(diagnostics, validateCaptures(document.Captures, "/captures")...)
	requireString(&diagnostics, "/expected_observation", "expected observation", document.ExpectedObservation)
	requireString(&diagnostics, "/observed_observation", "observed observation", document.ObservedObservation)
	requireEnum(&diagnostics, "/execution_status", "execution status", document.ExecutionStatus, stringSet(ExecutionStatusSatisfied, ExecutionStatusContradicted, ExecutionStatusFailed, ExecutionStatusUnavailable, ExecutionStatusNotRequired), CodeInvalidReceipt)
	diagnostics = append(diagnostics, validateArtifactRefPointer(document.TransformationRef, "/transformation_ref", false)...)
	if document.ResultWorkspaceDigest != "" {
		requireDigest(&diagnostics, "/result_workspace_digest", "result_workspace_digest", document.ResultWorkspaceDigest)
	}
	return diagnostics
}

func validateHarness(harness HarnessIdentity, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/id", "harness ID", harness.ID)
	requireString(&diagnostics, path+"/version", "harness version", harness.Version)
	requireDigest(&diagnostics, path+"/build_digest", "harness build_digest", harness.BuildDigest)
	return diagnostics
}

func validateIssuer(issuer ReceiptIssuer, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/id", "issuer ID", issuer.ID)
	requireString(&diagnostics, path+"/actor", "issuer actor", issuer.Actor)
	requireString(&diagnostics, path+"/method", "issuer method", issuer.Method)
	return diagnostics
}

func validateAuthentication(auth ReceiptAuthentication, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireString(&diagnostics, path+"/scheme", "authentication scheme", auth.Scheme)
	requireString(&diagnostics, path+"/key_id", "authentication key_id", auth.KeyID)
	requireDigest(&diagnostics, path+"/signed_digest", "authentication signed_digest", auth.SignedDigest)
	requireString(&diagnostics, path+"/signature", "authentication signature", auth.Signature)
	return diagnostics
}

func validateContainment(containment ContainmentReport, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireString(&diagnostics, path+"/filesystem", "filesystem containment statement", containment.Filesystem)
	requireString(&diagnostics, path+"/network", "network containment statement", containment.Network)
	requireString(&diagnostics, path+"/process", "process containment statement", containment.Process)
	return diagnostics
}

func validateCaptures(captures ExecutionCaptures, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, validateArtifactRefPointer(captures.Stdout, path+"/stdout", false)...)
	diagnostics = append(diagnostics, validateArtifactRefPointer(captures.Stderr, path+"/stderr", false)...)
	for index, ref := range captures.ProducedArtifacts {
		diagnostics = append(diagnostics, prefixDiagnostics(path+"/produced_artifacts/"+itoa(index), validateArtifactRef(ref, ""))...)
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
