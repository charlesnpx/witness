package planning

import (
	"fmt"
	"sort"
	"strings"

	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/harness"
	"witness/internal/portable"
)

const (
	CodeMissingEvidenceRef   = "assemble_missing_evidence_ref"
	CodeMissingBatch         = "assemble_missing_batch"
	CodeInvalidAssembleBatch = "assemble_invalid_batch"
	CodeInvalidRelay         = "assemble_invalid_relay_verification"
	CodeInvalidReceipt       = "assemble_invalid_execution_receipt"
	CodeInvalidManifest      = "assemble_invalid_manifest"
	CodeInvalidCompatibility = "assemble_invalid_relay_compatibility"
	CodeInvalidPlanDigest    = "assemble_invalid_plan_digest"
)

type AssembleOptions struct {
	Plan         PlanDocument
	Batches      []BatchEvidence
	RelayResults []RelayEvidence
	Receipts     []contracts.ExecutionReceipt
	EvidenceRefs ManifestEvidenceRefs

	ReceiptOutputDir   string
	ReceiptHMACKey     []byte
	ReceiptHMACKeyFile string
}

type BatchEvidence struct {
	BatchID  string
	Document contracts.VerificationBatchDocument
	Path     string
	RawBytes []byte
}

type RelayEvidence struct {
	BatchID           string
	RecipeFamily      string
	Backend           string
	PortableExportDir string
	PortableExportRef *contracts.ArtifactRef
	Verdicts          *contracts.RelayWitnessVerdictsDocument
}

type ManifestEvidenceRefs struct {
	CompatibilityManifest    contracts.ArtifactRef
	RelayCompatibility       *contracts.RelayCompatibility
	RelayCapabilities        contracts.ArtifactRef
	IntegrationBundle        contracts.ArtifactRef
	SelectedContracts        []contracts.ArtifactRef
	SelectedContractEvidence []SelectedContractEvidence
	ConsumerIdentity         map[string]any
}

type AssembleResult struct {
	Manifest                contracts.VerificationManifest   `json:"manifest"`
	PendingVerification     []string                         `json:"pending_verification,omitempty"`
	ReceiptContradictions   []string                         `json:"receipt_contradictions,omitempty"`
	UnverifiedRelationships []ManifestUnverifiedRelationship `json:"unverified_relationships,omitempty"`
	Diagnostics             []diag.Diagnostic                `json:"diagnostics,omitempty"`
}

type ManifestUnverifiedRelationship struct {
	BatchID        string `json:"batch_id"`
	Classification string `json:"classification"`
	Code           string `json:"code"`
	Relationship   string `json:"relationship"`
	Reason         string `json:"reason"`
}

func Assemble(options AssembleOptions) (*AssembleResult, error) {
	if diagnostics := validatePlanDigest(options.Plan); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	result := &AssembleResult{}
	var diagnostics []diag.Diagnostic
	manifest := contracts.VerificationManifest{
		SchemaVersion:         contracts.VerificationManifestV4,
		PlanDigest:            options.Plan.PlanDigest,
		CharterHash:           options.Plan.CharterHash,
		ArtifactDigest:        options.Plan.ArtifactDigest,
		ScopePolicy:           options.Plan.ScopePolicy,
		ChangeSurface:         options.Plan.ChangeSurface,
		ChangeSurfaceDigest:   options.Plan.ChangeSurfaceDigest,
		BaselinePass:          options.Plan.BaselinePass,
		CompatibilityManifest: options.EvidenceRefs.CompatibilityManifest,
		RelayCapabilities:     options.EvidenceRefs.RelayCapabilities,
		IntegrationBundle:     options.EvidenceRefs.IntegrationBundle,
		SelectedContracts:     append([]contracts.ArtifactRef(nil), options.EvidenceRefs.SelectedContracts...),
		ConsumerIdentity:      cloneIdentity(options.EvidenceRefs.ConsumerIdentity),
	}
	if len(manifest.ConsumerIdentity) == 0 {
		manifest.ConsumerIdentity = cloneIdentity(options.Plan.ConsumerIdentity)
	}
	if refDiagnostics := validateManifestEvidenceRefs(options.Plan, options.EvidenceRefs); len(refDiagnostics) > 0 {
		diagnostics = append(diagnostics, refDiagnostics...)
		for _, planned := range options.Plan.Batches {
			manifest.Batches = append(manifest.Batches, contracts.VerificationManifestBatch{
				BatchID:       planned.BatchID,
				Status:        contracts.RecordStatusFailed,
				FailureReason: "manifest_evidence_invalid",
				BatchRef:      planned.BatchRef,
				BatchDigest:   planned.BatchDigest,
			})
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
		}
		if manifest.ConsumerIdentity == nil {
			manifest.ConsumerIdentity = map[string]any{"kind": "witness", "id": "verification-assemble"}
		}
		result.Manifest = manifest
		result.Diagnostics = diagnostics
		return result, &ValidationError{Diagnostics: diagnostics}
	}
	batchesByID := map[string]BatchEvidence{}
	for _, batch := range options.Batches {
		id := batch.BatchID
		if id == "" {
			id = batch.Document.BatchID
		}
		batchesByID[id] = batch
	}
	relayByID := map[string]RelayEvidence{}
	for _, relay := range options.RelayResults {
		relayByID[relay.BatchID] = relay
	}
	receiptRecords, receiptDiagnostics, contradictions := assembleReceiptRecords(options)
	diagnostics = append(diagnostics, receiptDiagnostics...)
	result.ReceiptContradictions = contradictions
	manifest.ExecutionReceipts = receiptRecords
	for _, planned := range options.Plan.Batches {
		record := contracts.VerificationManifestBatch{
			BatchID:     planned.BatchID,
			Status:      contracts.RecordStatusUnavailable,
			BatchRef:    planned.BatchRef,
			BatchDigest: planned.BatchDigest,
		}
		relay, hasRelay := relayByID[planned.BatchID]
		attachRelayBatchMetadata(&manifest, planned, relay)
		batchEvidence, hasBatch := batchesByID[planned.BatchID]
		if !hasBatch {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeMissingBatch,
				"assemble requires the planned verification-batch document to validate relay coverage.",
				diag.WithDetail("batch_id", planned.BatchID),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		batchDoc := batchEvidence.Document
		if batchDiagnostics := validateBatchEvidenceMatchesPlan(planned, batchEvidence); len(batchDiagnostics) > 0 {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "verification_batch_mismatch"
			diagnostics = append(diagnostics, batchDiagnostics...)
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if !hasRelay || relay.PortableExportDir == "" {
			record.FailureReason = "relay_verification_unavailable"
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		portableReport, err := portable.VerifyDirectoryDetailed(relay.PortableExportDir)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_invalid"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "portable export failed Witness validation.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		exportResult, err := portable.ReducerResultFromReport(portableReport)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_missing_canonical_result"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "portable export canonical reducer result could not be validated.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		findingsDigest, err := portable.NamedInputRawDigest(portableReport, "findings")
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_batch_input_invalid"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "portable export contract-designated findings input could not be validated.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if findingsDigest != planned.BatchDigest {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_batch_input_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"portable export contract-designated findings input does not match the planned verification-batch digest.",
				diag.WithDetail("batch_id", planned.BatchID),
				diag.WithDetail("actual_batch_digest", findingsDigest),
				diag.WithDetail("expected_batch_digest", planned.BatchDigest),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if bindingDiagnostics, failureReason := validatePortablePassBindings(portableReport, options.Plan, planned); len(bindingDiagnostics) > 0 {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = failureReason
			diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidRelay, planned.BatchID, bindingDiagnostics)...)
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		contractBinding, err := portable.ContractBindingFromReport(portableReport)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_contract_binding_invalid"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "portable export selected contract binding could not be validated.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if !selectedContractDigestClaimed(options.EvidenceRefs.SelectedContracts, contractBinding.ContractDigest) {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_contract_manifest_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"portable export selected contract digest is not claimed by verification manifest selected_contracts.",
				diag.WithDetail("batch_id", planned.BatchID),
				diag.WithDetail("contract_id", contractBinding.ContractID),
				diag.WithDetail("contract_digest", contractBinding.ContractDigest),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		contractDigestPresent, err := selectedContractEvidenceDigestPresent(options.EvidenceRefs.SelectedContractEvidence, contractBinding.ContractDigest)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_contract_evidence_invalid"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "selected-contract evidence could not be authenticated.", diag.WithDetail("batch_id", planned.BatchID), diag.WithDetail("contract_id", contractBinding.ContractID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if !contractDigestPresent {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_contract_digest_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"portable export selected contract digest does not match authenticated retained selected-contract evidence.",
				diag.WithDetail("batch_id", planned.BatchID),
				diag.WithDetail("contract_id", contractBinding.ContractID),
				diag.WithDetail("contract_digest", contractBinding.ContractDigest),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		unverified, requiredMissing := classifyPortableUnverifiedRelationships(planned.BatchID, portableReport.UnverifiedRelationships)
		result.UnverifiedRelationships = append(result.UnverifiedRelationships, unverified...)
		if len(requiredMissing) > 0 {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "portable_export_required_relationship_unverified"
			for _, item := range requiredMissing {
				diagnostics = append(diagnostics, diag.FromError(diag.New(
					CodeInvalidRelay,
					"portable export is missing required relationship evidence.",
					diag.WithDetail("batch_id", planned.BatchID),
					diag.WithDetail("relationship", item.Relationship),
					diag.WithDetail("unverified_code", item.Code),
					diag.WithDetail("reason", item.Reason),
				)))
			}
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		verdicts := relay.Verdicts
		if verdicts == nil {
			decoded, err := decodeExportVerdicts(exportResult.Value)
			if err != nil {
				record.Status = contracts.RecordStatusFailed
				record.FailureReason = "portable_export_canonical_result_invalid"
				diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "portable export canonical reducer result is not a relay verdict document.", diag.WithDetail("batch_id", planned.BatchID))))
				result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
				manifest.Batches = append(manifest.Batches, record)
				continue
			}
			verdicts = &decoded
		}
		verdictDiagnostics := contracts.ValidateRelayWitnessVerdicts(*verdicts, &batchDoc)
		if len(verdictDiagnostics) > 0 {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "relay_verdicts_invalid"
			diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidRelay, planned.BatchID, verdictDiagnostics)...)
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		resultDigest, err := contracts.RelayWitnessVerdictsDigest(*verdicts)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "relay_verdicts_digest_failed"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "relay verdict digest could not be recomputed.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		if resultDigest != exportResult.Digest {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "relay_verdicts_export_digest_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"relay verdicts are not the portable export canonical reducer result.",
				diag.WithDetail("batch_id", planned.BatchID),
				diag.WithDetail("verdict_digest", resultDigest),
				diag.WithDetail("export_canonical_result_digest", exportResult.Digest),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		record.Status = contracts.RecordStatusValid
		record.PortableExportDigest = portableReport.ManifestDigest
		record.CanonicalResultDigest = resultDigest
		if record.CanonicalResultDigest != exportResult.Digest {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "manifest_canonical_result_digest_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"verification manifest canonical_result_digest does not match the portable export canonical reducer result.",
				diag.WithDetail("batch_id", planned.BatchID),
			)))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		record.RelayVerdicts = verdicts
		if relay.PortableExportRef != nil {
			record.PortableExportRef = relay.PortableExportRef
		} else {
			record.PortableExportRef = &contracts.ArtifactRef{
				Kind:          "relay-root-portable-export",
				ID:            planned.BatchID,
				Digest:        portableReport.ManifestDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			}
		}
		manifest.Batches = append(manifest.Batches, record)
	}
	if manifest.ConsumerIdentity == nil {
		manifest.ConsumerIdentity = map[string]any{"kind": "witness", "id": "verification-assemble"}
	}
	if manifest.PlanDigest == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidManifest, "assemble requires a digest-stamped verification plan.")))
	}
	if manifest.CharterHash == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidManifest, "assemble requires a plan charter_hash.")))
	}
	if manifest.ArtifactDigest == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidManifest, "assemble requires a plan artifact_digest.")))
	}
	if len(diagnostics) == 0 {
		if manifestDiagnostics := contracts.ValidateVerificationManifest(manifest); len(manifestDiagnostics) > 0 {
			diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidManifest, "", manifestDiagnostics)...)
		}
	}
	result.Manifest = manifest
	result.Diagnostics = diagnostics
	if len(diagnostics) > 0 {
		return result, &ValidationError{Diagnostics: diagnostics}
	}
	return result, nil
}

func attachRelayBatchMetadata(manifest *contracts.VerificationManifest, planned BatchPlan, relay RelayEvidence) {
	if manifest.ConsumerIdentity == nil {
		manifest.ConsumerIdentity = map[string]any{}
	}
	raw, _ := manifest.ConsumerIdentity["witness_relay_batches"].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
		manifest.ConsumerIdentity["witness_relay_batches"] = raw
	}
	recipeFamily := strings.TrimSpace(relay.RecipeFamily)
	if recipeFamily == "" {
		recipeFamily = planned.RecipeFamily
	}
	entry := map[string]any{
		"recipe_family": recipeFamily,
		"finding_ids":   append([]string(nil), planned.FindingIDs...),
	}
	if backend := strings.TrimSpace(relay.Backend); backend != "" {
		entry["backend"] = backend
	}
	raw[planned.BatchID] = entry
}

func validateBatchEvidenceMatchesPlan(planned BatchPlan, evidence BatchEvidence) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	document := evidence.Document
	if document.BatchID != planned.BatchID {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidAssembleBatch,
			"assembled verification-batch document batch_id does not match the plan.",
			diag.WithDetail("batch_id", planned.BatchID),
			diag.WithDetail("actual_batch_id", document.BatchID),
		)))
	}
	if document.TaskShape != planned.TaskShape {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidAssembleBatch,
			"assembled verification-batch document task_shape does not match the plan.",
			diag.WithDetail("batch_id", planned.BatchID),
			diag.WithDetail("actual_task_shape", document.TaskShape),
			diag.WithDetail("expected_task_shape", planned.TaskShape),
		)))
	}
	actualDigest, err := batchEvidenceDigest(evidence)
	if err != nil {
		diagnostics = append(diagnostics, diag.FromError(diag.Wrap(
			err,
			CodeInvalidAssembleBatch,
			"assembled verification-batch digest could not be recomputed.",
			diag.WithDetail("batch_id", planned.BatchID),
		)))
		return diagnostics
	}
	if actualDigest != planned.BatchDigest {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidAssembleBatch,
			"assembled verification-batch digest does not match the plan.",
			diag.WithDetail("batch_id", planned.BatchID),
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", planned.BatchDigest),
		)))
	}
	return diagnostics
}

func batchEvidenceDigest(evidence BatchEvidence) (string, error) {
	if len(evidence.RawBytes) > 0 {
		return digest.RawBytes(evidence.RawBytes), nil
	}
	return persistedVerificationBatchDigest(evidence.Document)
}

func validatePlanDigest(plan PlanDocument) []diag.Diagnostic {
	if plan.PlanDigest == "" {
		return []diag.Diagnostic{diag.FromError(diag.New(CodeInvalidPlanDigest, "assemble requires a digest-stamped verification plan."))}
	}
	unstamped := plan
	unstamped.PlanDigest = ""
	actual, err := contracts.SemanticDigest(unstamped)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidPlanDigest, "verification plan digest could not be recomputed."))}
	}
	if actual != plan.PlanDigest {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidPlanDigest,
			"verification plan_digest does not match the supplied plan content.",
			diag.WithDetail("actual_digest", actual),
			diag.WithDetail("expected_digest", plan.PlanDigest),
		))}
	}
	return nil
}

func decodeExportVerdicts(value any) (contracts.RelayWitnessVerdictsDocument, error) {
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		return contracts.RelayWitnessVerdictsDocument{}, err
	}
	return contracts.ReadRelayWitnessVerdictsBytes(data)
}

func assembleReceiptRecords(options AssembleOptions) ([]contracts.ExecutionReceiptManifestRecord, []diag.Diagnostic, []string) {
	var records []contracts.ExecutionReceiptManifestRecord
	var diagnostics []diag.Diagnostic
	var contradictions []string
	plannedFindingIDs := map[string]bool{}
	for _, batch := range options.Plan.Batches {
		for _, findingID := range batch.FindingIDs {
			plannedFindingIDs[findingID] = true
		}
	}
	for _, receipt := range options.Receipts {
		record := contracts.ExecutionReceiptManifestRecord{
			FindingID: receipt.FindingID,
			Status:    receipt.ExecutionStatus,
		}
		receiptDigest, err := contracts.ExecutionReceiptDigest(receipt)
		if err == nil {
			record.ReceiptDigest = receiptDigest
			record.ReceiptRef = &contracts.ArtifactRef{
				Kind:          "execution-receipt",
				ID:            receipt.ReceiptID,
				Digest:        receiptDigest,
				DigestProfile: "relay-root-digests-v1",
				MediaType:     "application/json",
			}
		}
		verification := harness.VerifyReceipt(harness.VerifyOptions{
			Receipt:              receipt,
			OutputDir:            options.ReceiptOutputDir,
			HMACKey:              options.ReceiptHMACKey,
			HMACKeyFile:          options.ReceiptHMACKeyFile,
			ExpectedSourceDigest: options.Plan.ArtifactDigest,
		})
		if verification.Classification == harness.ClassificationInvalid {
			record.Status = contracts.ExecutionStatusFailed
			record.FailureReason = "receipt_invalid"
			diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidReceipt, receipt.FindingID, verification.Diagnostics)...)
		}
		if verification.Classification == harness.ClassificationUnavailable {
			record.Status = contracts.ExecutionStatusUnavailable
			record.FailureReason = "receipt_unavailable"
			diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidReceipt, receipt.FindingID, verification.Diagnostics)...)
		}
		if verification.Classification == harness.ClassificationContradictory {
			record.Status = contracts.ExecutionStatusContradicted
		}
		if receipt.CharterHash != "" && receipt.CharterHash != options.Plan.CharterHash {
			record.Status = contracts.ExecutionStatusFailed
			record.FailureReason = "receipt_charter_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidReceipt, "execution receipt charter_hash does not match the plan.", diag.WithDetail("finding_id", receipt.FindingID))))
		}
		if receipt.ArtifactDigest != "" && receipt.ArtifactDigest != options.Plan.ArtifactDigest {
			record.Status = contracts.ExecutionStatusFailed
			record.FailureReason = "receipt_artifact_mismatch"
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidReceipt, "execution receipt artifact_digest does not match the plan.", diag.WithDetail("finding_id", receipt.FindingID))))
		}
		if !plannedFindingIDs[receipt.FindingID] {
			record.Status = contracts.ExecutionStatusFailed
			record.FailureReason = "receipt_unplanned_finding"
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidReceipt, "execution receipt references a finding outside the verification plan.", diag.WithDetail("finding_id", receipt.FindingID))))
		}
		if record.Status == contracts.ExecutionStatusContradicted {
			contradictions = append(contradictions, receipt.FindingID)
		}
		records = append(records, record)
	}
	return records, diagnostics, contradictions
}

func validateManifestEvidenceRefs(plan PlanDocument, refs ManifestEvidenceRefs) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "preflight_snapshot", value: plan.PreflightSnapshotDigest},
		{label: "preflight_compatibility", value: plan.PreflightCompatibilityDigest},
		{label: "preflight_relay_capabilities", value: plan.PreflightRelayCapabilitiesDigest},
		{label: "integration_bundle", value: plan.IntegrationBundleDigest},
	} {
		if strings.TrimSpace(item.value) == "" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidManifest,
				"assemble requires a preflight-stamped verification plan.",
				diag.WithDetail("ref", item.label),
			)))
		}
	}
	for _, item := range []struct {
		label string
		ref   contracts.ArtifactRef
	}{
		{label: "compatibility_manifest", ref: refs.CompatibilityManifest},
		{label: "relay_capabilities", ref: refs.RelayCapabilities},
		{label: "integration_bundle", ref: refs.IntegrationBundle},
	} {
		if item.ref.Digest == "" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeMissingEvidenceRef,
				"assemble requires verification evidence references.",
				diag.WithDetail("ref", item.label),
			)))
		}
	}
	if len(refs.SelectedContracts) == 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeMissingEvidenceRef,
			"assemble requires selected relay contract references.",
			diag.WithDetail("ref", "selected_contracts"),
		)))
	}
	if len(refs.SelectedContractEvidence) == 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidSelectedContract,
			"assemble requires authenticated selected-contract evidence with retained contract bytes.",
			diag.WithDetail("ref", "selected_contracts"),
		)))
	} else {
		diagnostics = append(diagnostics, selectedContractManifestDiagnostics(refs.SelectedContracts, refs.SelectedContractEvidence)...)
	}
	if refs.RelayCompatibility == nil {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidCompatibility,
			"assemble requires a strictly decoded relay compatibility manifest.",
			diag.WithDetail("ref", "compatibility_manifest"),
		)))
		return diagnostics
	}
	compatibility := *refs.RelayCompatibility
	if compatibilityDiagnostics := contracts.ValidateRelayCompatibility(compatibility); len(compatibilityDiagnostics) > 0 {
		diagnostics = append(diagnostics, prefixAssembleDiagnostics(CodeInvalidCompatibility, "", compatibilityDiagnostics)...)
	}
	compatibilityDigest, err := contracts.RelayCompatibilityDigest(compatibility)
	if err != nil {
		diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidCompatibility, "relay compatibility manifest digest could not be recomputed.")))
	} else {
		appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "compatibility manifest ref does not match retained compatibility content.", "compatibility_manifest", refs.CompatibilityManifest.Digest, compatibilityDigest)
		appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "verification plan compatibility digest does not match retained compatibility content.", "preflight_compatibility", plan.PreflightCompatibilityDigest, compatibilityDigest)
	}
	appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "relay capabilities ref does not match retained compatibility state.", "relay_capabilities", refs.RelayCapabilities.Digest, compatibility.CapabilitiesDigest)
	appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "verification plan relay capabilities digest does not match retained compatibility state.", "preflight_relay_capabilities", plan.PreflightRelayCapabilitiesDigest, compatibility.CapabilitiesDigest)
	appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "integration bundle ref does not match retained compatibility state.", "integration_bundle", refs.IntegrationBundle.Digest, compatibility.IntegrationBundleDigest)
	appendDigestMismatch(&diagnostics, CodeInvalidCompatibility, "verification plan integration bundle digest does not match retained compatibility state.", "integration_bundle", plan.IntegrationBundleDigest, compatibility.IntegrationBundleDigest)
	for _, contract := range compatibility.SelectedContracts {
		if strings.TrimSpace(contract.Digest) == "" {
			continue
		}
		if !selectedContractDigestClaimed(refs.SelectedContracts, contract.Digest) {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidCompatibility,
				"selected-contract ref does not match retained compatibility state.",
				diag.WithDetail("contract_id", contract.ContractID),
				diag.WithDetail("contract_digest", contract.Digest),
			)))
		}
	}
	return diagnostics
}

func validatePortablePassBindings(report *portable.DetailedReport, plan PlanDocument, planned BatchPlan) ([]diag.Diagnostic, string) {
	var diagnostics []diag.Diagnostic
	charterDigest := firstNonEmpty(planned.CharterDigest, plan.CharterDigest)
	if charterDigest != "" {
		actual, err := portable.NamedInputRawDigest(report, "charter")
		if err != nil {
			return []diag.Diagnostic{diag.FromError(err)}, "portable_export_charter_input_invalid"
		}
		if actual != charterDigest {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidRelay,
				"portable export charter named input does not match the planned frozen Charter bytes.",
				diag.WithDetail("actual_digest", actual),
				diag.WithDetail("expected_digest", charterDigest),
			)))
			return diagnostics, "portable_export_charter_input_mismatch"
		}
	}
	expectedArtifactDigests := plannedArtifactDigests(planned.ArtifactDigest, plan.ArtifactDigest)
	if len(expectedArtifactDigests) == 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"portable export artifact named input requires a planned reviewed artifact digest.",
		)))
		return diagnostics, "portable_export_artifact_input_missing"
	}
	artifactDigestSets, err := portable.NamedInputArtifactDigestSets(report, "artifact")
	if err != nil {
		return []diag.Diagnostic{diag.FromError(err)}, "portable_export_artifact_input_invalid"
	}
	if len(artifactDigestSets) == 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"portable export requires at least one artifact named input.",
			diag.WithDetail("expected_digests", expectedArtifactDigests),
		)))
		return diagnostics, "portable_export_artifact_input_missing"
	}
	plannedArtifactSet := stringSet(expectedArtifactDigests)
	presentArtifactDigests := map[string]bool{}
	var unplannedArtifactDigests []string
	for _, digestSet := range artifactDigestSets {
		if matched := markPlannedArtifactDigests(presentArtifactDigests, plannedArtifactSet, digestSet); !matched {
			unplannedArtifactDigests = append(unplannedArtifactDigests, digestSet...)
		}
	}
	missingArtifactDigests := missingPlannedArtifactDigests(expectedArtifactDigests, presentArtifactDigests)
	if len(unplannedArtifactDigests) > 0 || len(missingArtifactDigests) > 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"portable export artifact named inputs do not match the planned reviewed artifact digests.",
			diag.WithDetail("actual_digest_sets", artifactDigestSets),
			diag.WithDetail("expected_digests", expectedArtifactDigests),
			diag.WithDetail("missing_digests", missingArtifactDigests),
			diag.WithDetail("unplanned_digests", uniqueStrings(unplannedArtifactDigests)),
		)))
		return diagnostics, "portable_export_artifact_input_mismatch"
	}
	expectedBundleDigest := firstNonEmpty(planned.IntegrationBundleDigest, plan.IntegrationBundleDigest)
	if expectedBundleDigest == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"portable export integration bundle binding requires a planned pass bundle digest.",
		)))
		return diagnostics, "portable_export_bundle_identity_missing"
	}
	binding, err := portable.IntegrationBundleBindingFromReport(report)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(err)}, "portable_export_bundle_identity_invalid"
	}
	if binding.BundleDigest != expectedBundleDigest {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"portable export root recipe plan integration bundle digest does not match the planned pass bundle.",
			diag.WithDetail("actual_digest", binding.BundleDigest),
			diag.WithDetail("expected_digest", expectedBundleDigest),
		)))
		return diagnostics, "portable_export_bundle_identity_mismatch"
	}
	return nil, ""
}

func appendDigestMismatch(diagnostics *[]diag.Diagnostic, code string, message string, label string, actual string, expected string) {
	actual = strings.TrimSpace(actual)
	expected = strings.TrimSpace(expected)
	if actual == "" || expected == "" {
		*diagnostics = append(*diagnostics, diag.FromError(diag.New(
			code,
			"digest binding requires non-empty digests.",
			diag.WithDetail("ref", label),
			diag.WithDetail("actual_digest", actual),
			diag.WithDetail("expected_digest", expected),
		)))
		return
	}
	if actual == expected {
		return
	}
	*diagnostics = append(*diagnostics, diag.FromError(diag.New(
		code,
		message,
		diag.WithDetail("ref", label),
		diag.WithDetail("actual_digest", actual),
		diag.WithDetail("expected_digest", expected),
	)))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
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

func classifyPortableUnverifiedRelationships(batchID string, items []portable.UnverifiedRelationship) ([]ManifestUnverifiedRelationship, []ManifestUnverifiedRelationship) {
	records := make([]ManifestUnverifiedRelationship, 0, len(items))
	var requiredMissing []ManifestUnverifiedRelationship
	for _, item := range items {
		classification := "supplementary"
		// The signed root recipe/selected-contract prompt_context contract makes
		// trace-only facilitator-ledger projection checkable only through retained
		// rendered_prompt artifacts. When that evidence is absent, the relationship
		// is REQUIRED-missing; ambiguous retained strings remain supplementary and
		// are surfaced without invalidating the batch.
		if item.Relationship == "trace_only_facilitator_ledger_prompt_projection" &&
			(item.Code == "rendered_prompt_ref_missing" || item.Code == "rendered_prompt_unavailable") {
			classification = "required"
		}
		record := ManifestUnverifiedRelationship{
			BatchID:        batchID,
			Classification: classification,
			Code:           item.Code,
			Relationship:   item.Relationship,
			Reason:         item.Reason,
		}
		records = append(records, record)
		if classification == "required" {
			requiredMissing = append(requiredMissing, record)
		}
	}
	return records, requiredMissing
}

func prefixAssembleDiagnostics(code string, batchID string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	result := make([]diag.Diagnostic, len(diagnostics))
	for index, diagnostic := range diagnostics {
		result[index] = diagnostic
		result[index].Code = code
		if result[index].Details == nil {
			result[index].Details = map[string]any{}
		}
		if batchID != "" {
			result[index].Details["batch_id"] = batchID
		}
		result[index].Details["source_code"] = diagnostic.Code
		result[index].Message = fmt.Sprintf("%s: %s", diagnostic.Code, diagnostic.Message)
	}
	return result
}
