package planning

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	relayplan "github.com/charlesnpx/convo-relay/v2/plan"
	relayresult "github.com/charlesnpx/convo-relay/v2/result"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/harness"
)

const (
	AssembleResultSchemaVersion         = "witness-verification-assemble-result-v2"
	CodeMissingEvidenceRef              = "assemble_missing_evidence_ref"
	CodeMissingBatch                    = "assemble_missing_batch"
	CodeInvalidAssembleBatch            = "assemble_invalid_batch"
	CodeInvalidRelay                    = "assemble_invalid_relay_verification"
	CodeInvalidReceipt                  = "assemble_invalid_execution_receipt"
	CodeInvalidManifest                 = "assemble_invalid_manifest"
	CodeInvalidPlanDigest               = "assemble_invalid_plan_digest"
	CodeInvalidRelayRunRecord           = "assemble_invalid_relay_run_record"
	CodeUnsupportedAssembleResultSchema = "assemble_unsupported_result_schema"
)

type AssembleOptions struct {
	Plan         PlanDocument
	Batches      []BatchEvidence
	RelayResults []RelayEvidence
	Receipts     []contracts.ExecutionReceipt
	EvidenceRefs ManifestEvidenceRefs
	BaseManifest *freeze.Manifest
	HeadManifest *freeze.Manifest

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
	VerifiedBundle    *bundle.Verification
	RunRecords        []map[string]any
}

type ManifestEvidenceRefs struct {
	IntegrationBundle        contracts.ArtifactRef
	SelectedContracts        []contracts.ArtifactRef
	SelectedContractEvidence []SelectedContractEvidence
	ConsumerIdentity         map[string]any
}

type AssembleResult struct {
	SchemaVersion         string                         `json:"schema_version"`
	Manifest              contracts.VerificationManifest `json:"manifest"`
	PendingVerification   []string                       `json:"pending_verification,omitempty"`
	ReceiptContradictions []string                       `json:"receipt_contradictions,omitempty"`
	Diagnostics           []diag.Diagnostic              `json:"diagnostics,omitempty"`
}

func ReadAssembleResultBytes(data []byte) (AssembleResult, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return AssembleResult{}, err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return AssembleResult{}, diag.New(CodeUnsupportedAssembleResultSchema, "verification assemble result must be a JSON object.", diag.WithPath("/schema_version"))
	}
	actual, _ := document["schema_version"].(string)
	if actual != AssembleResultSchemaVersion {
		return AssembleResult{}, diag.New(
			CodeUnsupportedAssembleResultSchema,
			unsupportedSchemaVersionMessage("verification assemble result", actual, AssembleResultSchemaVersion, "witness-verification-assemble-result-v1", "after the embedded verification manifest expanded its exclusion reasons."),
			diag.WithPath("/schema_version"),
			diag.WithDetail("expected", AssembleResultSchemaVersion),
			diag.WithDetail("actual", actual),
		)
	}
	return strictjson.DecodeBytes[AssembleResult](data, strictjson.DefaultMaxBytes*8)
}

func Assemble(options AssembleOptions) (*AssembleResult, error) {
	if diagnostics := validatePlanDigest(options.Plan); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	if diagnostics := validatePlanChangeSurfaceDerivation(options.Plan, options.BaseManifest, options.HeadManifest); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	if diagnostics := validatePlanExclusionChangeSurface(options.Plan); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	result := &AssembleResult{SchemaVersion: AssembleResultSchemaVersion}
	var diagnostics []diag.Diagnostic
	manifest := contracts.VerificationManifest{
		SchemaVersion:       contracts.VerificationManifestV6,
		PlanDigest:          options.Plan.PlanDigest,
		CharterHash:         options.Plan.CharterHash,
		ArtifactDigest:      options.Plan.ArtifactDigest,
		ScopePolicy:         options.Plan.ScopePolicy,
		ChangeSurface:       options.Plan.ChangeSurface,
		ChangeSurfaceDigest: options.Plan.ChangeSurfaceDigest,
		BaselinePass:        options.Plan.BaselinePass,
		IntegrationBundle:   options.EvidenceRefs.IntegrationBundle,
		SelectedContracts:   append(make([]contracts.ArtifactRef, 0, len(options.EvidenceRefs.SelectedContracts)), options.EvidenceRefs.SelectedContracts...),
		Batches:             make([]contracts.VerificationManifestBatch, 0, len(options.Plan.Batches)),
		ExcludedFindings:    manifestExcludedFindings(options.Plan.ExcludedFindings),
		ConsumerIdentity:    sanitizedManifestConsumerIdentity(options.EvidenceRefs.ConsumerIdentity),
	}
	if len(manifest.ConsumerIdentity) == 0 {
		manifest.ConsumerIdentity = sanitizedManifestConsumerIdentity(options.Plan.ConsumerIdentity)
	}
	relayLaunchStatus := relayLaunchStatusForPreflight(options.Plan.PreflightRelayPresent)
	attachRelayLaunchStatus(&manifest, relayLaunchStatus)
	diagnostics = append(diagnostics, validateRelayEvidencePlanMembership(options.Plan, options.RelayResults)...)
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
		if hasRelay {
			if relayDiagnostics := validateRelayRunRecordEvidence(planned, relay); len(relayDiagnostics) > 0 {
				record.Status = contracts.RecordStatusFailed
				record.FailureReason = "relay_run_record_provenance_mismatch"
				diagnostics = append(diagnostics, relayDiagnostics...)
				result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
				attachRelayBatchMetadata(&manifest, planned, RelayEvidence{}, relayLaunchStatus)
				manifest.Batches = append(manifest.Batches, record)
				continue
			}
		}
		attachRelayBatchMetadata(&manifest, planned, relay, relayLaunchStatus)
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
		if !hasRelay || relay.VerifiedBundle == nil {
			record.FailureReason = relayUnavailableFailureReason(relay)
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		assembled, err := assembleRelayV2Evidence(relay, planned, options.Plan, batchDoc)
		if err != nil {
			record.Status = contracts.RecordStatusFailed
			record.FailureReason = "relay_v2_bundle_invalid"
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(err, CodeInvalidRelay, "relay v2 bundle evidence could not be bound to the planned verification batch.", diag.WithDetail("batch_id", planned.BatchID))))
			result.PendingVerification = append(result.PendingVerification, planned.FindingIDs...)
			manifest.Batches = append(manifest.Batches, record)
			continue
		}
		record.Status = contracts.RecordStatusValid
		record.PortableExportDigest = assembled.verified.Manifest.ManifestDigest
		record.CanonicalResultDigest = assembled.resultDigest
		record.RelayVerdicts = &assembled.verdicts
		if relay.PortableExportRef != nil {
			record.PortableExportRef = relay.PortableExportRef
		} else {
			record.PortableExportRef = &contracts.ArtifactRef{
				Kind:          "relay-bundle",
				ID:            planned.BatchID,
				Digest:        assembled.verified.Manifest.ManifestDigest,
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

type relayV2Assembly struct {
	verified     bundle.Verification
	verdicts     contracts.RelayWitnessVerdictsDocument
	resultDigest string
}

func assembleRelayV2Evidence(relay RelayEvidence, planned BatchPlan, verificationPlan PlanDocument, batch contracts.VerificationBatchDocument) (relayV2Assembly, error) {
	if relay.VerifiedBundle == nil {
		return relayV2Assembly{}, fmt.Errorf("relay v2 verified bundle is required")
	}
	verified := *relay.VerifiedBundle
	if strings.TrimSpace(relay.PortableExportDir) != "" {
		fresh, err := bundle.VerifyPortableDirectory(relay.PortableExportDir)
		if err != nil {
			return relayV2Assembly{}, fmt.Errorf("verify portable bundle: %w", err)
		}
		verified = fresh
	} else {
		if err := bundle.Validate(verified.Manifest); err != nil {
			return relayV2Assembly{}, fmt.Errorf("validate portable bundle manifest: %w", err)
		}
		if err := relayplan.Validate(verified.Session.Plan); err != nil {
			return relayV2Assembly{}, fmt.Errorf("validate portable bundle plan: %w", err)
		}
		if err := relayresult.ValidateRoot(verified.Session.Root); err != nil {
			return relayV2Assembly{}, fmt.Errorf("validate portable bundle root: %w", err)
		}
		if err := relayresult.ValidateTranscript(verified.Transcript); err != nil {
			return relayV2Assembly{}, fmt.Errorf("validate portable bundle transcript: %w", err)
		}
		if err := relayresult.ValidateDiagnostics(verified.Diagnostics); err != nil {
			return relayV2Assembly{}, fmt.Errorf("validate portable bundle diagnostics: %w", err)
		}
	}

	value := verified.Session.Plan
	if value.SessionID != planned.BatchID {
		return relayV2Assembly{}, fmt.Errorf("plan.session_id %q does not match planned batch_id %q", value.SessionID, planned.BatchID)
	}
	if value.RecipeID != planned.RecipeFamily {
		return relayV2Assembly{}, fmt.Errorf("plan.recipe_id %q does not match planned recipe_family %q", value.RecipeID, planned.RecipeFamily)
	}
	actualPlanDigest, err := relayplan.Digest(value)
	if err != nil {
		return relayV2Assembly{}, fmt.Errorf("compute verified Relay v2 plan digest: %w", err)
	}
	if consuming := consumingRelayRunRecord(relay.RunRecords); consuming != nil {
		recordedPlanDigest, _ := consuming["plan_digest"].(string)
		if !digest.WellFormed(strings.TrimSpace(recordedPlanDigest)) {
			return relayV2Assembly{}, fmt.Errorf("consuming relay run record is missing a well-formed plan_digest")
		}
		if strings.TrimSpace(recordedPlanDigest) != actualPlanDigest {
			return relayV2Assembly{}, fmt.Errorf("relay run record plan_digest %q does not match verified Relay v2 plan digest %q", recordedPlanDigest, actualPlanDigest)
		}
	}
	if err := validateRelayV2PlanInputs(verified, relay.PortableExportDir, value, verificationPlan, planned); err != nil {
		return relayV2Assembly{}, err
	}

	verdicts, err := relayV2Verdicts(relay.Verdicts, verified.Session.Root.Result.Value)
	if err != nil {
		return relayV2Assembly{}, err
	}
	if diagnostics := contracts.ValidateRelayWitnessVerdicts(verdicts, &batch); len(diagnostics) > 0 {
		return relayV2Assembly{}, fmt.Errorf("validate relay witness verdicts: %s", diagnostics[0].Message)
	}
	resultDigest, err := contracts.RelayWitnessVerdictsDigest(verdicts)
	if err != nil {
		return relayV2Assembly{}, fmt.Errorf("compute relay witness verdict digest: %w", err)
	}
	return relayV2Assembly{verified: verified, verdicts: verdicts, resultDigest: resultDigest}, nil
}

func validateRelayV2PlanInputs(verified bundle.Verification, directory string, value relayplan.Plan, verificationPlan PlanDocument, planned BatchPlan) error {
	findings, ok := relayPlanInput(value, "findings")
	if !ok || len(findings.Contents) != 1 {
		return fmt.Errorf("plan.inputs.findings must contain exactly one blob")
	}
	if got := relayBlobWitnessDigest(findings.Contents[0]); got != planned.BatchDigest {
		return fmt.Errorf("plan.inputs.findings digest %q does not match planned batch_digest %q", got, planned.BatchDigest)
	}

	charterDigest := firstNonEmpty(planned.CharterDigest, verificationPlan.CharterDigest)
	if charterDigest != "" {
		charter, ok := relayPlanInput(value, "charter")
		if !ok || len(charter.Contents) != 1 {
			return fmt.Errorf("plan.inputs.charter must contain exactly one blob")
		}
		if got := relayBlobWitnessDigest(charter.Contents[0]); got != charterDigest {
			return fmt.Errorf("plan.inputs.charter digest %q does not match planned charter_digest %q", got, charterDigest)
		}
	}

	expectedArtifacts := plannedArtifactDigests(planned.ArtifactDigestSet...)
	if len(expectedArtifacts) == 0 {
		expectedArtifacts = plannedArtifactDigests(planned.ArtifactDigest, verificationPlan.ArtifactDigest)
	}
	artifacts, ok := relayPlanInput(value, "artifact")
	if !ok || len(artifacts.Contents) == 0 {
		return fmt.Errorf("plan.inputs.artifact must contain at least one blob")
	}
	actualArtifacts := map[string]bool{}
	for _, ref := range artifacts.Contents {
		candidates := relayBlobWitnessDigests(verified, directory, ref)
		matched := false
		for _, candidate := range candidates {
			if stringSliceContains(expectedArtifacts, candidate) {
				actualArtifacts[candidate] = true
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("plan.inputs.artifact blob %q does not match planned artifact_digest_set", relayBlobWitnessDigest(ref))
		}
	}
	missing := make([]string, 0)
	for _, expected := range expectedArtifacts {
		if !actualArtifacts[expected] {
			missing = append(missing, expected)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("plan.inputs.artifact digests do not match planned artifact_digest_set; missing %v", missing)
	}
	return nil
}

func relayV2Verdicts(embedded *contracts.RelayWitnessVerdictsDocument, value string) (contracts.RelayWitnessVerdictsDocument, error) {
	var decoded contracts.RelayWitnessVerdictsDocument
	if strings.TrimSpace(value) != "" {
		candidate, err := contracts.ReadRelayWitnessVerdictsBytes([]byte(value))
		if err != nil {
			return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("decode embedded relay result: %w", err)
		}
		decoded = candidate
	}
	if embedded == nil {
		if strings.TrimSpace(value) == "" {
			return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("relay bundle contains no embedded Witness verdicts")
		}
		return decoded, nil
	}
	if strings.TrimSpace(value) != "" {
		embeddedDigest, err := contracts.RelayWitnessVerdictsDigest(*embedded)
		if err != nil {
			return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("digest embedded relay verdicts: %w", err)
		}
		decodedDigest, err := contracts.RelayWitnessVerdictsDigest(decoded)
		if err != nil {
			return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("digest bundle relay verdicts: %w", err)
		}
		if embeddedDigest != decodedDigest {
			return contracts.RelayWitnessVerdictsDocument{}, fmt.Errorf("embedded relay verdicts do not match the bundle result")
		}
	}
	return *embedded, nil
}

func relayPlanInput(value relayplan.Plan, name string) (relayplan.Input, bool) {
	for _, input := range value.Inputs {
		if input.Name == name {
			return input, true
		}
	}
	return relayplan.Input{}, false
}

func relayBlobWitnessDigest(ref relayplan.BlobRef) string {
	return "sha256:" + ref.SHA256
}

func relayBlobWitnessDigests(verified bundle.Verification, directory string, ref relayplan.BlobRef) []string {
	result := []string{relayBlobWitnessDigest(ref)}
	if strings.TrimSpace(directory) == "" {
		return result
	}
	for _, entry := range verified.Manifest.PayloadInventory {
		if entry.Kind != "input" || entry.Blob.SHA256 != ref.SHA256 {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(entry.Path)))
		if err != nil {
			return result
		}
		if snapshotDigest, ok := frozenSnapshotManifestDigest(body); ok {
			result = appendUniqueString(result, snapshotDigest)
		}
		break
	}
	return result
}

func frozenSnapshotManifestDigest(data []byte) (string, bool) {
	manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*32)
	if err != nil || manifest.SchemaVersion != freeze.SchemaVersion {
		return "", false
	}
	manifestDigest, err := freeze.ManifestDigest(manifest)
	if err != nil || manifest.Source.ManifestDigest != manifestDigest || manifest.Workspace.ManifestDigest != manifestDigest {
		return "", false
	}
	return manifestDigest, true
}

func attachRelayLaunchStatus(manifest *contracts.VerificationManifest, status string) {
	if strings.TrimSpace(status) == "" {
		return
	}
	if manifest.ConsumerIdentity == nil {
		manifest.ConsumerIdentity = map[string]any{}
	}
	manifest.ConsumerIdentity[contracts.VerificationManifestRelayLaunchStatusKey] = status
}

func attachRelayBatchMetadata(manifest *contracts.VerificationManifest, planned BatchPlan, relay RelayEvidence, relayLaunchStatus string) {
	if manifest.ConsumerIdentity == nil {
		manifest.ConsumerIdentity = map[string]any{}
	}
	raw, _ := manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
		manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey] = raw
	}
	recipeFamily := strings.TrimSpace(relay.RecipeFamily)
	if recipeFamily == "" {
		recipeFamily = planned.RecipeFamily
	}
	entry := map[string]any{
		"recipe_family": recipeFamily,
		"finding_ids":   append([]string(nil), planned.FindingIDs...),
	}
	if strings.TrimSpace(relayLaunchStatus) != "" {
		entry[contracts.VerificationManifestBatchRelayLaunchStatusKey] = relayLaunchStatus
	}
	if backend := strings.TrimSpace(relay.Backend); backend != "" {
		entry["backend"] = backend
	}
	if len(relay.RunRecords) > 0 {
		entry["run_records"] = cloneRelayRunRecords(relay.RunRecords)
	}
	raw[planned.BatchID] = entry
}

func relayUnavailableFailureReason(relay RelayEvidence) string {
	if consumingRelayRunRecord(relay.RunRecords) != nil {
		return "relay_run_recorded_unavailable"
	}
	for _, record := range relay.RunRecords {
		status, _ := record["status"].(string)
		providerInvoked, _ := record["provider_invoked"].(string)
		launch, _ := record["relay_launch"].(map[string]any)
		startFailed, _ := launch["start_failed"].(bool)
		if status == "launch_failed" && providerInvoked == "false" && startFailed {
			return "relay_launch_failed"
		}
	}
	if len(relay.RunRecords) > 0 {
		return "relay_run_recorded_unavailable"
	}
	return "relay_verification_unavailable"
}

func consumingRelayRunRecord(records []map[string]any) map[string]any {
	for _, record := range records {
		consumesBatch, _ := record["consumes_batch"].(bool)
		if consumesBatch {
			return record
		}
	}
	return nil
}

func validateRelayRunRecordEvidence(planned BatchPlan, relay RelayEvidence) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	expectedFamily := strings.TrimSpace(planned.RecipeFamily)
	expectedBackend := strings.TrimSpace(relay.Backend)
	consumingRecordIndexes := make([]int, 0, 1)
	for index, record := range relay.RunRecords {
		recordBatchID, batchIDOK := record["batch_id"].(string)
		if !batchIDOK || strings.TrimSpace(recordBatchID) != planned.BatchID {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"relay run record batch_id does not bind to the planned batch.",
				diag.WithDetail("actual_batch_id", recordBatchID),
			))
		}
		recipeID, recipeIDOK := record["recipe_id"].(string)
		if !recipeIDOK || strings.TrimSpace(recipeID) == "" {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"relay run record recipe_id is required for planned-batch provenance.",
			))
			continue
		}
		recipeFamily, backend := relayRunRecordRecipeIdentity(recipeID)
		if expectedFamily != "" && recipeFamily != expectedFamily {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"relay run record recipe_id does not match the planned recipe family.",
				diag.WithDetail("actual_recipe_id", recipeID),
				diag.WithDetail("actual_recipe_family", recipeFamily),
				diag.WithDetail("expected_recipe_family", expectedFamily),
			))
		}
		if expectedBackend != "" && backend != expectedBackend {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"relay run record recipe_id does not match the expected relay backend.",
				diag.WithDetail("actual_recipe_id", recipeID),
				diag.WithDetail("actual_backend", backend),
				diag.WithDetail("expected_backend", expectedBackend),
			))
		}
		consumesBatch, consumesBatchOK := record["consumes_batch"].(bool)
		if !consumesBatchOK {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"relay run record consumes_batch must be a boolean.",
			))
			continue
		}
		if consumesBatch {
			consumingRecordIndexes = append(consumingRecordIndexes, index)
			planDigest, _ := record["plan_digest"].(string)
			if !digest.WellFormed(strings.TrimSpace(planDigest)) {
				diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
					planned.BatchID,
					index,
					"consuming relay run record plan_digest must be a well-formed digest.",
				))
			}
			continue
		}
		if !relayRunRecordIsStartFailure(record) {
			diagnostics = append(diagnostics, invalidRelayRunRecordDiagnostic(
				planned.BatchID,
				index,
				"non-consuming relay run records must be launch_failed records with relay_launch.start_failed=true.",
			))
		}
	}
	if len(consumingRecordIndexes) > 1 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelayRunRecord,
			"relay run records contain multiple consuming attempts for one batch; refusing reviewer-shopping evidence.",
			diag.WithDetail("batch_id", planned.BatchID),
			diag.WithDetail("consuming_record_indexes", consumingRecordIndexes),
		)))
	}
	return diagnostics
}

func invalidRelayRunRecordDiagnostic(batchID string, recordIndex int, message string, options ...diag.Option) diag.Diagnostic {
	options = append(options, diag.WithDetail("batch_id", batchID), diag.WithDetail("record_index", recordIndex))
	return diag.FromError(diag.New(CodeInvalidRelayRunRecord, message, options...))
}

func relayRunRecordRecipeIdentity(recipeID string) (string, string) {
	recipeID = strings.TrimSpace(recipeID)
	for _, backend := range []string{"codex", "claude"} {
		suffix := "-" + backend
		if strings.HasSuffix(recipeID, suffix) {
			return strings.TrimSuffix(recipeID, suffix), backend
		}
	}
	return recipeID, ""
}

func relayRunRecordIsStartFailure(record map[string]any) bool {
	status, _ := record["status"].(string)
	providerInvoked, _ := record["provider_invoked"].(string)
	launch, _ := record["relay_launch"].(map[string]any)
	startFailed, _ := launch["start_failed"].(bool)
	return status == "launch_failed" && providerInvoked == "false" && startFailed
}

func cloneRelayRunRecords(records []map[string]any) []map[string]any {
	cloned := make([]map[string]any, 0, len(records))
	for _, record := range records {
		cloned = append(cloned, SanitizeRelayRunRecordMetadata(record))
	}
	return cloned
}

// SanitizeRelayRunRecordMetadata builds a manifest projection from an explicit
// allow-list. Retained relay run records can include raw process output and
// provider payloads, which must remain local-only.
func SanitizeRelayRunRecordMetadata(record map[string]any) map[string]any {
	metadata := make(map[string]any, 10)
	for _, key := range []string{
		"schema_version",
		"batch_id",
		"recipe_id",
		"plan_digest",
		"status",
		"provider_invoked",
	} {
		if value, ok := record[key].(string); ok {
			metadata[key] = value
		}
	}
	if consumesBatch, ok := record["consumes_batch"].(bool); ok {
		metadata["consumes_batch"] = consumesBatch
	}
	if diagnosticCodes := relayRunRecordDiagnosticCodes(record["diagnostics"]); len(diagnosticCodes) > 0 {
		metadata["diagnostics"] = diagnosticCodes
	}
	if launch := relayLaunchMetadataSummary(record["relay_launch"]); len(launch) > 0 {
		metadata["relay_launch"] = launch
	}
	if runRecordDigest, ok := record["run_record_digest"].(string); ok && digest.WellFormed(runRecordDigest) {
		metadata["run_record_digest"] = runRecordDigest
	}
	return metadata
}

// manifestSafeIdentifier bounds the identifier-like strings the manifest
// projection will carry: run records can be supplied externally, so anything
// not matching this conservative shape is dropped rather than published.
var manifestSafeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func relayRunRecordDiagnosticCodes(value any) []map[string]any {
	codes := make([]map[string]any, 0)
	appendCode := func(code string) {
		if code = strings.TrimSpace(code); manifestSafeIdentifier.MatchString(code) {
			codes = append(codes, map[string]any{"code": code})
		}
	}
	switch diagnostics := value.(type) {
	case []any:
		for _, diagnostic := range diagnostics {
			if diagnostic, ok := diagnostic.(map[string]any); ok {
				if code, ok := diagnostic["code"].(string); ok {
					appendCode(code)
				}
			}
		}
	case []map[string]any:
		for _, diagnostic := range diagnostics {
			if code, ok := diagnostic["code"].(string); ok {
				appendCode(code)
			}
		}
	case []diag.Diagnostic:
		for _, diagnostic := range diagnostics {
			appendCode(diagnostic.Code)
		}
	}
	return codes
}

func relayLaunchMetadataSummary(value any) map[string]any {
	launch, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	summary := make(map[string]any, 9)
	if argv, ok := relayLaunchArgv(launch["argv"]); ok {
		if len(argv) > 0 {
			if executable := filepath.Base(argv[0]); manifestSafeIdentifier.MatchString(executable) {
				summary["executable"] = executable
			}
		}
		if argvDigest, err := digest.SemanticJSON(argv); err == nil {
			summary["argv_digest"] = argvDigest
		}
	} else {
		if executable, ok := launch["executable"].(string); ok && manifestSafeIdentifier.MatchString(strings.TrimSpace(executable)) {
			summary["executable"] = strings.TrimSpace(executable)
		}
		if argvDigest, ok := launch["argv_digest"].(string); ok && digest.WellFormed(argvDigest) {
			summary["argv_digest"] = argvDigest
		}
	}
	if exitCode, ok := relayLaunchInteger(launch["exit_code"], false); ok {
		summary["exit_code"] = exitCode
	}
	if startFailed, ok := launch["start_failed"].(bool); ok {
		summary["start_failed"] = startFailed
	}
	appendRelayLaunchStreamSummary(summary, launch, "stdout")
	appendRelayLaunchStreamSummary(summary, launch, "stderr")
	return summary
}

func relayLaunchArgv(value any) ([]string, bool) {
	switch argv := value.(type) {
	case []string:
		return append([]string(nil), argv...), true
	case []any:
		values := make([]string, 0, len(argv))
		for _, value := range argv {
			argument, ok := value.(string)
			if !ok {
				return nil, false
			}
			values = append(values, argument)
		}
		return values, true
	default:
		return nil, false
	}
}

func appendRelayLaunchStreamSummary(summary, launch map[string]any, stream string) {
	digestKey := stream + "_digest"
	bytesKey := stream + "_bytes"
	truncatedKey := stream + "_truncated"
	if capture, ok := relayLaunchRetainedStream(launch, stream); ok {
		summary[digestKey] = digest.RawBytes(capture)
		summary[bytesKey] = len(capture)
		summary[truncatedKey] = relayLaunchTruncated(launch, truncatedKey)
		return
	}
	if captureDigest, ok := launch[digestKey].(string); ok && digest.WellFormed(captureDigest) {
		summary[digestKey] = captureDigest
	}
	if captureBytes, ok := relayLaunchInteger(launch[bytesKey], true); ok {
		summary[bytesKey] = captureBytes
	}
	if truncated, ok := launch[truncatedKey].(bool); ok {
		summary[truncatedKey] = truncated
	}
}

func relayLaunchRetainedStream(launch map[string]any, stream string) ([]byte, bool) {
	if encodedCapture, ok := launch[stream+"_b64"].(string); ok {
		if capture, err := base64.StdEncoding.DecodeString(encodedCapture); err == nil {
			return capture, true
		}
	}
	if capture, ok := launch[stream].([]byte); ok {
		return capture, true
	}
	if capture, ok := launch[stream].(string); ok {
		return []byte(capture), true
	}
	return nil, false
}

func relayLaunchTruncated(launch map[string]any, key string) bool {
	truncated, _ := launch[key].(bool)
	return truncated
}

func relayLaunchInteger(value any, nonNegative bool) (int, bool) {
	var result int64
	switch value := value.(type) {
	case int:
		result = int64(value)
	case int64:
		result = value
	case json.Number:
		parsed, err := strictjson.ParseInt64JSON([]byte(value.String()))
		if err != nil {
			return 0, false
		}
		result = parsed
	case strictjson.Int:
		result = int64(value)
	default:
		return 0, false
	}
	if nonNegative && result < 0 {
		return 0, false
	}
	converted := int(result)
	if int64(converted) != result {
		return 0, false
	}
	return converted, true
}

func relayLaunchStatusForPreflight(relayPresent bool) string {
	if relayPresent {
		return contracts.RelayLaunchStatusPresent
	}
	return contracts.RelayLaunchStatusAbsent
}

func sanitizedManifestConsumerIdentity(input map[string]any) map[string]any {
	identity := cloneIdentity(input)
	if len(identity) == 0 {
		return nil
	}
	delete(identity, contracts.VerificationManifestRelayLaunchStatusKey)
	rawBatches, ok := identity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	if !ok {
		return identity
	}
	batches := make(map[string]any, len(rawBatches))
	for batchID, raw := range rawBatches {
		object, ok := raw.(map[string]any)
		if !ok {
			batches[batchID] = raw
			continue
		}
		copied := make(map[string]any, len(object))
		for key, value := range object {
			if key == contracts.VerificationManifestBatchRelayLaunchStatusKey {
				continue
			}
			copied[key] = value
		}
		batches[batchID] = copied
	}
	identity[contracts.VerificationManifestRelayBatchesKey] = batches
	return identity
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
	if plan.SchemaVersion != SchemaVersion {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidPlanDigest,
			"verification plan schema_version is unsupported.",
			diag.WithPath("/schema_version"),
			diag.WithDetail("actual", plan.SchemaVersion),
			diag.WithDetail("expected", SchemaVersion),
		))}
	}
	if plan.DigestProfile != digest.Profile {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeInvalidPlanDigest,
			"verification plan digest_profile is unsupported.",
			diag.WithPath("/digest_profile"),
			diag.WithDetail("actual", plan.DigestProfile),
			diag.WithDetail("expected", digest.Profile),
		))}
	}
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

func validatePlanChangeSurfaceDerivation(plan PlanDocument, base *freeze.Manifest, head *freeze.Manifest) []diag.Diagnostic {
	if plan.ChangeSurface == nil {
		return nil
	}
	diagnostics := changesurface.ValidateDeclaredDerivation(*plan.ChangeSurface, plan.ChangeSurfaceDigest, base, head, plan.ArtifactDigest)
	return prefixDiagnosticPaths("/change_surface", diagnostics)
}

func validatePlanExclusionChangeSurface(plan PlanDocument) []diag.Diagnostic {
	if plan.ScopePolicy == changesurface.ScopePolicyDeltaObligating && plan.ChangeSurface != nil {
		return nil
	}
	var diagnostics []diag.Diagnostic
	for index, item := range plan.ExcludedFindings {
		if item.Reason != contracts.ReasonOutOfDelta {
			continue
		}
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidManifest,
			"out_of_delta excluded findings require delta_obligating scope policy with a derived change surface.",
			diag.WithPath(fmt.Sprintf("/excluded_findings/%d", index)),
			diag.WithDetail("scope_policy", plan.ScopePolicy),
			diag.WithDetail("has_change_surface", plan.ChangeSurface != nil),
		)))
	}
	return diagnostics
}

func manifestExcludedFindings(excluded []ExcludedFinding) []contracts.ExcludedFindingRecord {
	records := make([]contracts.ExcludedFindingRecord, 0, len(excluded))
	for _, item := range excluded {
		if !manifestExcludedFindingReason(item.Reason) {
			continue
		}
		records = append(records, contracts.ExcludedFindingRecord{
			Role:                   item.Role,
			FindingID:              item.FindingID,
			SourceRoleOutputRef:    item.SourceRoleOutputRef,
			SourceRoleOutputDigest: item.SourceRoleOutputDigest,
			Reason:                 item.Reason,
			Disposition:            item.Disposition,
		})
	}
	return records
}

func manifestExcludedFindingReason(reason string) bool {
	switch reason {
	case contracts.ReasonOutOfDelta, contracts.ReasonPreExisting, contracts.ReasonAttributionUnattributed:
		return true
	default:
		return false
	}
}

func prefixDiagnosticPaths(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		result[index] = item
		if result[index].Path == "" {
			result[index].Path = prefix
		} else {
			result[index].Path = prefix + result[index].Path
		}
	}
	return result
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

func validateRelayEvidencePlanMembership(plan PlanDocument, relays []RelayEvidence) []diag.Diagnostic {
	plannedBatchIDs := make(map[string]bool, len(plan.Batches))
	for _, planned := range plan.Batches {
		plannedBatchIDs[planned.BatchID] = true
	}
	unplannedBatchIDs := make([]string, 0)
	for _, relay := range relays {
		if !plannedBatchIDs[relay.BatchID] {
			unplannedBatchIDs = append(unplannedBatchIDs, relay.BatchID)
		}
	}
	sort.Strings(unplannedBatchIDs)
	diagnostics := make([]diag.Diagnostic, 0, len(unplannedBatchIDs))
	for _, batchID := range unplannedBatchIDs {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidRelay,
			"relay evidence references a batch outside the verification plan.",
			diag.WithDetail("batch_id", batchID),
		)))
	}
	return diagnostics
}

func validateManifestEvidenceRefs(plan PlanDocument, refs ManifestEvidenceRefs) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	// A plan with no batches launches no relay work, so no relay contract is consumed;
	// preflight neither produces nor needs selected-contract evidence for that manifest.
	consumesRelayContracts := len(plan.Batches) > 0
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "preflight_snapshot", value: plan.PreflightSnapshotDigest},
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
	if consumesRelayContracts && len(refs.SelectedContracts) == 0 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeMissingEvidenceRef,
			"assemble requires selected relay contract references.",
			diag.WithDetail("ref", "selected_contracts"),
		)))
	}
	if len(refs.SelectedContractEvidence) == 0 {
		if consumesRelayContracts {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidSelectedContract,
				"assemble requires authenticated selected-contract evidence with retained contract bytes.",
				diag.WithDetail("ref", "selected_contracts"),
			)))
		}
	} else {
		diagnostics = append(diagnostics, selectedContractManifestDiagnostics(refs.SelectedContracts, refs.SelectedContractEvidence)...)
	}
	appendDigestMismatch(&diagnostics, CodeInvalidManifest, "integration bundle ref does not match the verification plan.", "integration_bundle", refs.IntegrationBundle.Digest, plan.IntegrationBundleDigest)
	return diagnostics
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
