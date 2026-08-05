package adjudicate

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/harness"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	ResultSchemaVersionV1 = "witness-adjudication-run-result-v1"
	ResultSchemaVersion   = "witness-adjudication-run-result-v2"

	CodeInvalidInput              = "adjudicate_invalid_input"
	CodeInvalidFrozenCharter      = "adjudicate_invalid_frozen_charter"
	CodeInvalidRoleOutput         = "adjudicate_invalid_role_output"
	CodeInvalidManifest           = "adjudicate_invalid_manifest"
	CodeInvalidRules              = "adjudicate_invalid_rules"
	CodeInvalidPolicy             = "adjudicate_invalid_policy"
	CodeInvalidRecurrenceLineage  = "adjudicate_invalid_recurrence_lineage"
	CodeReceiptLoadFailed         = "adjudicate_receipt_load_failed"
	CodeReceiptRelationshipFailed = "adjudicate_receipt_relationship_failed"
	CodeDuplicateRelayBatch       = "adjudicate_duplicate_relay_batch"

	ReasonValidationFailed             = "validation_failed"
	ReasonInvalidRecurrenceLineage     = "invalid_recurrence_lineage"
	ReasonExecutionReceiptMissing      = "execution_receipt_missing"
	ReasonExecutionReceiptInvalid      = "execution_receipt_invalid"
	ReasonExecutionReceiptUnavailable  = "execution_receipt_unavailable"
	ReasonExecutionReceiptNotSatisfied = "execution_receipt_not_satisfied"
	ReasonExecutionReceiptContradicted = "execution_receipt_contradicted"
	ReasonRecurrenceLineageUnavailable = "recurrence_lineage_unavailable"
	ReasonSeverityCapped               = "severity_capped"
	ReasonRelayVerificationUnavailable = "relay_verification_unavailable"
	ReasonRelayVerificationInvalid     = "relay_verification_invalid"
	ReasonRelaySurvived                = "relay_survived"
	ReasonRelayWeakened                = "relay_weakened"
	ReasonRelayBroken                  = "relay_broken"
	ReasonWitnessWeakenedBelowFloor    = "witness_weakened_below_floor"
	ReasonOutOfDelta                   = contracts.ReasonOutOfDelta
)

type Options struct {
	FrozenCharter *charter.FrozenCharter
	RoleOutputs   []RoleOutputInput
	Manifest      contracts.VerificationManifest
	BaseManifest  *freeze.Manifest
	HeadManifest  *freeze.Manifest

	ReceiptOutputDir   string
	ReceiptHMACKey     []byte
	ReceiptHMACKeyFile string

	Rules                        contracts.ReviewRules
	Policy                       contracts.ReviewPolicy
	PolicyCapReleaseLedgerBacked bool

	PriorLineage         []PriorLineageRecord
	PriorLineageProvided bool
}

type RoleOutputInput struct {
	Path     string
	Document contracts.RoleOutputDocument
}

type PriorLineageRecord struct {
	FindingID        string                        `json:"finding_id"`
	FindingKey       string                        `json:"finding_key"`
	CharterHash      string                        `json:"charter_hash"`
	ArtifactDigest   string                        `json:"artifact_digest"`
	WitnessDigest    string                        `json:"witness_digest"`
	Disposition      string                        `json:"disposition"`
	ResolutionEvents []PriorLineageResolutionEvent `json:"resolution_events,omitempty"`
}

type PriorLineageResolutionEvent struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	Summary        string `json:"summary,omitempty"`
}

type Result struct {
	SchemaVersion             string            `json:"schema_version"`
	DigestProfile             string            `json:"digest_profile"`
	ResultDigest              string            `json:"result_digest,omitempty"`
	RulesVersion              string            `json:"rules_version"`
	RulesID                   string            `json:"rules_id"`
	PolicyVersion             string            `json:"policy_version"`
	PolicyID                  string            `json:"policy_id"`
	PolicyDigest              string            `json:"policy_digest,omitempty"`
	RulesDigest               string            `json:"rules_digest,omitempty"`
	CapReleaseCharterMismatch bool              `json:"cap_release_charter_mismatch"`
	CapReleaseUnit            string            `json:"cap_release_unit,omitempty"`
	CharterHash               string            `json:"charter_hash"`
	ArtifactDigest            string            `json:"artifact_digest"`
	ManifestDigest            string            `json:"manifest_digest"`
	Findings                  []FindingVerdict  `json:"findings"`
	Summary                   Summary           `json:"summary"`
	Diagnostics               []diag.Diagnostic `json:"diagnostics,omitempty"`
}

type Summary struct {
	Admitted            int  `json:"admitted"`
	Advisory            int  `json:"advisory"`
	PendingVerification int  `json:"pending_verification"`
	AutomaticCandidate  int  `json:"automatic_candidate"`
	CallerDecision      int  `json:"caller_decision"`
	None                int  `json:"none"`
	FixpointEligible    bool `json:"fixpoint_eligible"`
}

type summaryJSON struct {
	Admitted            strictjson.Int `json:"admitted"`
	Advisory            strictjson.Int `json:"advisory"`
	PendingVerification strictjson.Int `json:"pending_verification"`
	AutomaticCandidate  strictjson.Int `json:"automatic_candidate"`
	CallerDecision      strictjson.Int `json:"caller_decision"`
	None                strictjson.Int `json:"none"`
	FixpointEligible    bool           `json:"fixpoint_eligible"`
}

func (summary *Summary) UnmarshalJSON(data []byte) error {
	decoded, err := strictjson.DecodeBytes[summaryJSON](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return err
	}
	*summary = Summary{
		Admitted:            int(decoded.Admitted),
		Advisory:            int(decoded.Advisory),
		PendingVerification: int(decoded.PendingVerification),
		AutomaticCandidate:  int(decoded.AutomaticCandidate),
		CallerDecision:      int(decoded.CallerDecision),
		None:                int(decoded.None),
		FixpointEligible:    decoded.FixpointEligible,
	}
	return nil
}

type FindingVerdict struct {
	FindingID string `json:"finding_id"`
	// FindingKey and EstimatedDelta are in-memory transport only (populated in
	// adjudicateFinding, consumed by cmd/witness when emitting `finding` ledger
	// events). They are json:"-" so they do NOT enter the witness-adjudication-run-
	// result-v1 wire schema or the result SemanticDigest: adding them would break
	// strict decoding by older binaries and change the run digest (ContainsRunDigest
	// duplicate detection). finding_digest already binds the source finding (incl.
	// recurrence and estimated delta).
	FindingKey         string                       `json:"-"`
	Role               string                       `json:"role"`
	Kind               string                       `json:"kind"`
	Title              string                       `json:"title"`
	SourceRoleOutput   string                       `json:"source_role_output,omitempty"`
	FindingDigest      string                       `json:"finding_digest,omitempty"`
	WitnessDigest      string                       `json:"witness_digest,omitempty"`
	EstimatedDelta     contracts.SplitDeltaEstimate `json:"-"`
	ClaimedSeverity    string                       `json:"claimed_severity"`
	EffectiveSeverity  string                       `json:"effective_severity,omitempty"`
	SeverityCap        string                       `json:"severity_cap,omitempty"`
	Disposition        string                       `json:"disposition"`
	ApplicationClass   string                       `json:"application_class"`
	Reasons            []string                     `json:"reasons,omitempty"`
	StrengthTrajectory []StrengthStep               `json:"strength_trajectory,omitempty"`
	Execution          *ExecutionMetadata           `json:"execution,omitempty"`
	Relay              *RelayMetadata               `json:"relay,omitempty"`
	VerdictClass       *string                      `json:"verdict_class"`
	Diagnostics        []diag.Diagnostic            `json:"diagnostics,omitempty"`
}

type StrengthStep struct {
	Step     string `json:"step"`
	Strength string `json:"strength,omitempty"`
	Reason   string `json:"reason"`
}

type ExecutionMetadata struct {
	Required                   bool              `json:"required"`
	ManifestStatus             string            `json:"manifest_status,omitempty"`
	ReceiptID                  string            `json:"receipt_id,omitempty"`
	ReceiptDigest              string            `json:"receipt_digest,omitempty"`
	VerificationClassification string            `json:"verification_classification,omitempty"`
	Reason                     string            `json:"reason,omitempty"`
	Diagnostics                []diag.Diagnostic `json:"diagnostics,omitempty"`
}

type RelayMetadata struct {
	Required      bool    `json:"required"`
	BatchID       string  `json:"batch_id,omitempty"`
	RecipeFamily  string  `json:"recipe_family,omitempty"`
	Backend       string  `json:"backend,omitempty"`
	Status        string  `json:"status"`
	FailureReason string  `json:"failure_reason,omitempty"`
	Verdict       string  `json:"verdict,omitempty"`
	VerdictClass  *string `json:"verdict_class"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "adjudication validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func Run(options Options) (*Result, error) {
	rules := options.Rules
	if rules.SchemaVersion == "" {
		rules = contracts.DefaultReviewRules()
	}
	if diagnostics := contracts.ValidateReviewRules(rules); len(diagnostics) > 0 {
		return nil, validationError(CodeInvalidRules, diagnostics)
	}
	policy := options.Policy
	if policy.SchemaVersion == "" {
		policy = contracts.DefaultReviewPolicy()
	}
	if !options.PolicyCapReleaseLedgerBacked {
		policy.CapRelease = nil
	}
	scopePolicy := contracts.EffectiveScopePolicy(policy)
	if scopePolicy == contracts.ScopePolicyDeltaObligating {
		if policy.SchemaVersion != contracts.ReviewPolicyV3 {
			return nil, validationError(CodeInvalidPolicy, []diag.Diagnostic{diagnostic(contracts.CodeInvalidPolicy, "delta_obligating scope policy requires review-policy-v3.", "/schema_version", map[string]any{"actual": policy.SchemaVersion, "expected": contracts.ReviewPolicyV3})})
		}
		if rules.SchemaVersion != contracts.ReviewRulesV3 {
			return nil, validationError(CodeInvalidRules, []diag.Diagnostic{diagnostic(contracts.CodeInvalidRules, "delta_obligating scope policy requires review-rules-v3.", "/schema_version", map[string]any{"actual": rules.SchemaVersion, "expected": contracts.ReviewRulesV3})})
		}
	}
	validationContext := policyContext(rules, policy, options.FrozenCharter)
	policyValidation := contracts.ValidateReviewPolicy(policy, validationContext)
	if len(policyValidation.Diagnostics) > 0 {
		return nil, validationError(CodeInvalidPolicy, policyValidation.Diagnostics)
	}
	capReleaseUnit := ""
	if policy.CapRelease != nil {
		capReleaseUnit = policy.CapRelease.Unit
	}

	var global []diag.Diagnostic
	if options.FrozenCharter == nil {
		global = append(global, diagnostic(CodeInvalidInput, "adjudication requires a frozen Charter.", "/charter", nil))
	} else {
		global = append(global, validateFrozenCharter(*options.FrozenCharter)...)
	}
	if len(options.RoleOutputs) == 0 {
		global = append(global, diagnostic(CodeInvalidInput, "adjudication requires at least one role-output document.", "/role_outputs", nil))
	}
	if options.PriorLineageProvided {
		global = append(global, ValidatePriorLineage(options.PriorLineage)...)
	}
	global = append(global, validateManifestEnvelope(options.Manifest, options.FrozenCharter)...)
	global = append(global, validateManifestScopePolicy(options.Manifest, scopePolicy)...)
	global = append(global, validateManifestChangeSurfaceDerivation(options.Manifest, options.BaseManifest, options.HeadManifest)...)
	global = append(global, validateManifestExclusionChangeSurface(options.Manifest, scopePolicy)...)
	global = append(global, validateManifestExclusionCoverage(options.Manifest, options.RoleOutputs)...)
	if len(global) > 0 {
		return nil, &ValidationError{Diagnostics: global}
	}

	manifestDigest, err := contracts.VerificationManifestDigest(options.Manifest)
	if err != nil {
		return nil, &ValidationError{Diagnostics: []diag.Diagnostic{diagnostic(CodeInvalidManifest, "verification manifest digest could not be computed.", "/manifest", map[string]any{"error": err.Error()})}}
	}

	loadedFindings, documentDiagnostics := collectFindings(options.RoleOutputs, options.FrozenCharter, options.Manifest, options)
	receipts := indexExecutionReceipts(options.Manifest.ExecutionReceipts)
	relay := indexRelay(options.Manifest)

	result := &Result{
		SchemaVersion:             ResultSchemaVersion,
		DigestProfile:             digest.Profile,
		RulesVersion:              rules.SchemaVersion,
		RulesID:                   rules.RulesID,
		PolicyVersion:             policy.SchemaVersion,
		PolicyID:                  policy.PolicyID,
		PolicyDigest:              validationContext.PolicyDigest,
		RulesDigest:               validationContext.RulesDigest,
		CapReleaseCharterMismatch: policyValidation.CapReleaseCharterMismatch,
		CapReleaseUnit:            capReleaseUnit,
		CharterHash:               options.Manifest.CharterHash,
		ArtifactDigest:            options.Manifest.ArtifactDigest,
		ManifestDigest:            manifestDigest,
		Diagnostics:               append([]diag.Diagnostic(nil), documentDiagnostics...),
	}
	for _, finding := range loadedFindings {
		verdict := adjudicateFinding(finding, receipts, relay, options, rules, policy, scopePolicy)
		result.Findings = append(result.Findings, verdict)
		result.Diagnostics = append(result.Diagnostics, verdict.Diagnostics...)
	}
	result.Summary = summarize(result.Findings)
	if err := stampResultDigest(result); err != nil {
		return nil, err
	}
	if len(documentDiagnostics) > 0 {
		return result, &ValidationError{Diagnostics: documentDiagnostics}
	}
	return result, nil
}

func ReadPriorLineage(reader io.Reader) ([]PriorLineageRecord, error) {
	records, err := strictjson.DecodeJSONL[PriorLineageRecord](reader, strictjson.DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	if diagnostics := ValidatePriorLineage(records); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	return records, nil
}

func ReadPriorLineageFile(path string) ([]PriorLineageRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ReadPriorLineage(file)
}

func ValidatePriorLineage(records []PriorLineageRecord) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	seen := map[string]int{}
	for index, record := range records {
		path := "/prior_lineage/" + itoa(index)
		if !validStableID(record.FindingID) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage finding_id requires a stable ID.", path+"/finding_id", map[string]any{"finding_id": record.FindingID}))
		}
		if strings.TrimSpace(record.FindingKey) == "" {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage finding_key is required.", path+"/finding_key", nil))
		}
		if !validDigest(record.CharterHash) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage charter_hash must be a relay-root-digests-v1 sha256 digest.", path+"/charter_hash", map[string]any{"charter_hash": record.CharterHash}))
		}
		if !validDigest(record.ArtifactDigest) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage artifact_digest must be a relay-root-digests-v1 sha256 digest.", path+"/artifact_digest", map[string]any{"artifact_digest": record.ArtifactDigest}))
		}
		if !validDigest(record.WitnessDigest) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage witness_digest must be a relay-root-digests-v1 sha256 digest.", path+"/witness_digest", map[string]any{"witness_digest": record.WitnessDigest}))
		}
		if !validDisposition(record.Disposition) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage disposition is unsupported.", path+"/disposition", map[string]any{"disposition": record.Disposition}))
		}
		if first, exists := seen[record.FindingID]; exists {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage finding_id must be unique.", path+"/finding_id", map[string]any{"finding_id": record.FindingID, "duplicate_of": "/prior_lineage/" + itoa(first) + "/finding_id"}))
		}
		seen[record.FindingID] = index
		for eventIndex, event := range record.ResolutionEvents {
			eventPath := path + "/resolution_events/" + itoa(eventIndex)
			if !validStableID(event.ID) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage resolution event ID requires a stable ID.", eventPath+"/id", map[string]any{"id": event.ID}))
			}
			if strings.TrimSpace(event.Type) == "" {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage resolution event type is required.", eventPath+"/type", nil))
			}
			if event.ArtifactDigest != "" && !validDigest(event.ArtifactDigest) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior lineage resolution event artifact_digest must be a relay-root-digests-v1 sha256 digest.", eventPath+"/artifact_digest", map[string]any{"artifact_digest": event.ArtifactDigest}))
			}
		}
	}
	return diagnostics
}

func policyContext(rules contracts.ReviewRules, policy contracts.ReviewPolicy, frozen *charter.FrozenCharter) *contracts.PolicyValidationContext {
	rulesDigest, _ := contracts.ReviewRulesDigest(rules)
	policyForDigest := policy
	policyForDigest.CapRelease = nil
	policyDigest, _ := contracts.ReviewPolicyDigest(policyForDigest)
	context := &contracts.PolicyValidationContext{
		RulesDigest:  rulesDigest,
		PolicyDigest: policyDigest,
	}
	if frozen != nil {
		context.CharterHash = frozen.CharterHash
	}
	return context
}

func validateFrozenCharter(frozen charter.FrozenCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if frozen.SchemaVersion != charter.FrozenSchemaVersion {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter schema_version must be review-charter-freeze-v1.", "/charter/schema_version", map[string]any{"actual": frozen.SchemaVersion, "expected": charter.FrozenSchemaVersion}))
	}
	if frozen.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter digest_profile must be relay-root-digests-v1.", "/charter/digest_profile", map[string]any{"actual": frozen.DigestProfile, "expected": digest.Profile}))
	}
	diagnostics = append(diagnostics, validateEmbeddedNormalizedCharter(frozen.Charter)...)
	hash, err := charter.Hash(frozen.Charter)
	if err != nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter hash could not be recomputed.", "/charter/charter_hash", map[string]any{"error": err.Error()}))
	} else if hash != frozen.CharterHash {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter charter_hash does not match the embedded normalized Charter.", "/charter/charter_hash", map[string]any{"actual": frozen.CharterHash, "expected": hash}))
	}
	properties := charter.Properties(frozen.Charter.OperationalEnvelope)
	if frozen.ReachabilityRulesActive != properties.ReachabilityRulesActive {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter reachability flag does not match the embedded Operational Envelope.", "/charter/reachability_rules_active", map[string]any{"actual": frozen.ReachabilityRulesActive, "expected": properties.ReachabilityRulesActive}))
	}
	if frozen.AdditiveRemediesAutomatic != properties.AdditiveRemediesAutomatic {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "frozen Charter additive automation flag does not match the embedded Operational Envelope.", "/charter/additive_remedies_automatic", map[string]any{"actual": frozen.AdditiveRemediesAutomatic, "expected": properties.AdditiveRemediesAutomatic}))
	}
	return diagnostics
}

func validateEmbeddedNormalizedCharter(normalized charter.NormalizedCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	input := charter.Charter{
		SchemaVersion:       normalized.SchemaVersion,
		Goals:               normalized.Goals,
		NonGoals:            normalized.NonGoals,
		OwnerEvents:         normalized.OwnerEvents,
		OperationalEnvelope: normalized.OperationalEnvelope,
	}
	for _, item := range charter.Validate(input, nil) {
		details := cloneDetails(item.Details)
		details["source_code"] = item.Code
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "embedded normalized Charter failed validation.", "/charter/charter"+item.Path, details))
	}
	if len(normalized.StandingNoGoals) != 1 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "embedded normalized Charter must contain exactly one standing no-goals statement.", "/charter/charter/standing_no_goals", map[string]any{"count": len(normalized.StandingNoGoals)}))
		return diagnostics
	}
	standing := normalized.StandingNoGoals[0]
	if standing.ID != charter.StandingNoGoalsID || standing.Statement != charter.StandingNoGoalsStatement {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidFrozenCharter, "embedded normalized Charter standing no-goals statement is not the required invariant.", "/charter/charter/standing_no_goals/0", map[string]any{
			"actual_id":        standing.ID,
			"actual_statement": standing.Statement,
			"expected_id":      charter.StandingNoGoalsID,
		}))
	}
	return diagnostics
}

func validateManifestEnvelope(manifest contracts.VerificationManifest, frozen *charter.FrozenCharter) []diag.Diagnostic {
	diagnostics := prefixDiagnostics("/manifest", contracts.ValidateVerificationManifest(manifest))
	if frozen != nil && manifest.CharterHash != "" && manifest.CharterHash != frozen.CharterHash {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "verification manifest charter_hash does not match the frozen Charter.", "/manifest/charter_hash", map[string]any{"actual": manifest.CharterHash, "expected": frozen.CharterHash}))
	}
	return diagnostics
}

func validateManifestScopePolicy(manifest contracts.VerificationManifest, scopePolicy string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	manifestScopePolicy := contracts.EffectiveScopePolicy(contracts.ReviewPolicy{ScopePolicy: manifest.ScopePolicy})
	if manifest.ScopePolicy != "" && manifestScopePolicy != scopePolicy {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "verification manifest scope_policy does not match the loaded review policy.", "/manifest/scope_policy", map[string]any{"actual": manifestScopePolicy, "expected": scopePolicy}))
	}
	if scopePolicy == contracts.ScopePolicyDeltaObligating && manifest.ScopePolicy == "" {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "delta_obligating adjudication requires the verification manifest to declare scope_policy.", "/manifest/scope_policy", map[string]any{"expected": scopePolicy}))
	}
	if scopePolicy == contracts.ScopePolicyDeltaObligating && manifest.ChangeSurface == nil && manifest.BaselinePass == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "delta_obligating adjudication requires a verification manifest with a change_surface or explicit baseline_pass.", "/manifest/change_surface", map[string]any{"scope_policy": scopePolicy}))
	}
	return diagnostics
}

func validateManifestChangeSurfaceDerivation(manifest contracts.VerificationManifest, base *freeze.Manifest, head *freeze.Manifest) []diag.Diagnostic {
	if manifest.ChangeSurface == nil {
		return nil
	}
	diagnostics := changesurface.ValidateDeclaredDerivation(*manifest.ChangeSurface, manifest.ChangeSurfaceDigest, base, head, manifest.ArtifactDigest)
	return prefixDiagnostics("/manifest/change_surface", diagnostics)
}

func validateManifestExclusionChangeSurface(manifest contracts.VerificationManifest, scopePolicy string) []diag.Diagnostic {
	if len(manifest.ExcludedFindings) == 0 {
		return nil
	}
	if scopePolicy == contracts.ScopePolicyDeltaObligating && manifest.ChangeSurface != nil {
		return nil
	}
	diagnostics := make([]diag.Diagnostic, 0, len(manifest.ExcludedFindings))
	for index := range manifest.ExcludedFindings {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidManifest,
			"excluded findings require delta_obligating scope policy with a derived change surface.",
			"/manifest/excluded_findings/"+itoa(index),
			map[string]any{
				"scope_policy":       scopePolicy,
				"has_change_surface": manifest.ChangeSurface != nil,
			},
		))
	}
	return diagnostics
}

type exclusionCoverageFinding struct {
	role    string
	finding contracts.Finding
}

func validateManifestExclusionCoverage(manifest contracts.VerificationManifest, inputs []RoleOutputInput) []diag.Diagnostic {
	if len(manifest.ExcludedFindings) == 0 {
		return nil
	}
	byDigest := map[string]map[string]exclusionCoverageFinding{}
	for _, input := range inputs {
		roleDigest, err := contracts.RoleOutputDigest(input.Document)
		if err != nil {
			continue
		}
		findings := byDigest[roleDigest]
		if findings == nil {
			findings = map[string]exclusionCoverageFinding{}
			byDigest[roleDigest] = findings
		}
		for _, finding := range input.Document.Findings {
			findings[finding.ID] = exclusionCoverageFinding{role: input.Document.Role, finding: finding}
		}
	}
	var diagnostics []diag.Diagnostic
	for index, record := range manifest.ExcludedFindings {
		path := "/manifest/excluded_findings/" + itoa(index)
		findings := byDigest[record.SourceRoleOutputDigest]
		if findings == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "excluded finding source role-output is not supplied to adjudication.", path+"/source_role_output_digest", map[string]any{"finding_id": record.FindingID, "source_role_output_digest": record.SourceRoleOutputDigest}))
			continue
		}
		covered, exists := findings[record.FindingID]
		if !exists {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "excluded finding is not present in its supplied source role-output.", path+"/finding_id", map[string]any{"finding_id": record.FindingID, "source_role_output_digest": record.SourceRoleOutputDigest}))
			continue
		}
		if covered.role != record.Role {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "excluded finding role does not match its supplied source role-output.", path+"/role", map[string]any{"actual": record.Role, "expected": covered.role, "finding_id": record.FindingID}))
		}
		if manifest.ChangeSurface != nil && contracts.FindingInChangeSurface(covered.finding, *manifest.ChangeSurface) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidManifest, "excluded out-of-delta finding touches the verified change surface.", path+"/finding_id", map[string]any{"finding_id": record.FindingID, "reason": record.Reason}))
		}
	}
	return diagnostics
}

type loadedFinding struct {
	sourceIndex      int
	findingIndex     int
	sourceRoleOutput string
	sourceDigest     string
	role             string
	document         contracts.RoleOutputDocument
	finding          contracts.Finding
	witnessDigest    string
	findingDigest    string
	diagnostics      []diag.Diagnostic
}

func collectFindings(inputs []RoleOutputInput, frozen *charter.FrozenCharter, manifest contracts.VerificationManifest, options Options) ([]loadedFinding, []diag.Diagnostic) {
	var findings []loadedFinding
	var documentDiagnostics []diag.Diagnostic
	for sourceIndex, input := range inputs {
		roleDigest, err := contracts.RoleOutputDigest(input.Document)
		if err != nil {
			documentDiagnostics = append(documentDiagnostics, diagnostic(CodeInvalidRoleOutput, "role-output digest could not be computed.", "/role_outputs/"+itoa(sourceIndex), map[string]any{"error": err.Error(), "role_output": input.Path}))
		}
		roleOutputDiagnostics := contracts.ValidateRoleOutput(input.Document, frozen)
		byFinding, documentLevel := splitFindingDiagnostics(roleOutputDiagnostics)
		documentDiagnostics = append(documentDiagnostics, appendRoleOutputContext(documentLevel, sourceIndex, input.Path)...)
		for findingIndex, finding := range input.Document.Findings {
			item := loadedFinding{
				sourceIndex:      sourceIndex,
				findingIndex:     findingIndex,
				sourceRoleOutput: input.Path,
				sourceDigest:     roleDigest,
				role:             input.Document.Role,
				document:         input.Document,
				finding:          finding,
				diagnostics:      appendFindingContext(documentLevel, sourceIndex, findingIndex, input.Path, finding.ID),
			}
			item.diagnostics = append(item.diagnostics, appendFindingContext(byFinding[findingIndex], sourceIndex, findingIndex, input.Path, finding.ID)...)
			var err error
			item.witnessDigest, err = contracts.WitnessDigest(finding.Witness)
			if err != nil {
				item.diagnostics = append(item.diagnostics, diagnostic(CodeInvalidRoleOutput, "witness digest could not be computed.", findingPath(sourceIndex, findingIndex)+"/witness", map[string]any{"error": err.Error()}))
			}
			item.findingDigest, err = contracts.FindingDigest(finding)
			if err != nil {
				item.diagnostics = append(item.diagnostics, diagnostic(CodeInvalidRoleOutput, "finding digest could not be computed.", findingPath(sourceIndex, findingIndex), map[string]any{"error": err.Error()}))
			}
			item.diagnostics = append(item.diagnostics, validateFindingEnvelope(input.Document, finding, item.witnessDigest, manifest, options, sourceIndex, findingIndex)...)
			findings = append(findings, item)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if roleRank(left.role) != roleRank(right.role) {
			return roleRank(left.role) < roleRank(right.role)
		}
		if severityRank(left.finding.ClaimedSeverity) != severityRank(right.finding.ClaimedSeverity) {
			return severityRank(left.finding.ClaimedSeverity) < severityRank(right.finding.ClaimedSeverity)
		}
		if left.finding.ID != right.finding.ID {
			return left.finding.ID < right.finding.ID
		}
		if left.sourceIndex != right.sourceIndex {
			return left.sourceIndex < right.sourceIndex
		}
		return left.findingIndex < right.findingIndex
	})
	return findings, documentDiagnostics
}

func validateFindingEnvelope(document contracts.RoleOutputDocument, finding contracts.Finding, witnessDigest string, manifest contracts.VerificationManifest, options Options, sourceIndex int, findingIndex int) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	path := findingPath(sourceIndex, findingIndex)
	if document.CharterHash != "" && document.CharterHash != manifest.CharterHash {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "role-output charter_hash does not match the verification manifest.", path, map[string]any{"actual": document.CharterHash, "expected": manifest.CharterHash}))
	}
	if document.ArtifactDigest != "" && document.ArtifactDigest != manifest.ArtifactDigest {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "role-output artifact_digest does not match the verification manifest.", path, map[string]any{"actual": document.ArtifactDigest, "expected": manifest.ArtifactDigest}))
	}
	if finding.Recurrence == nil {
		return diagnostics
	}
	recurrence := *finding.Recurrence
	recurrencePath := path + "/recurrence"
	if recurrence.PriorFindingID == finding.ID {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "recurrence lineage must not point to the current finding.", recurrencePath+"/prior_finding_id", map[string]any{"finding_id": finding.ID}))
	}
	if recurrence.ArtifactDigest != manifest.ArtifactDigest {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "recurrence artifact_digest does not match the current manifest artifact.", recurrencePath+"/artifact_digest", map[string]any{"actual": recurrence.ArtifactDigest, "expected": manifest.ArtifactDigest}))
	}
	if witnessDigest != "" && recurrence.WitnessDigest != witnessDigest {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "recurrence witness_digest does not match the current witness.", recurrencePath+"/witness_digest", map[string]any{"actual": recurrence.WitnessDigest, "expected": witnessDigest}))
	}
	diagnostics = append(diagnostics, validateRecurrenceAgainstPriorLineage(recurrence, manifest, options, recurrencePath)...)
	return diagnostics
}

func validateRecurrenceAgainstPriorLineage(recurrence contracts.RecurrenceRef, manifest contracts.VerificationManifest, options Options, recurrencePath string) []diag.Diagnostic {
	if !options.PriorLineageProvided {
		return []diag.Diagnostic{diagnostic(CodeInvalidRecurrenceLineage, "recurrence claim requires prior-lineage input before it can carry forward.", recurrencePath, map[string]any{
			"prior_finding_id": recurrence.PriorFindingID,
			"reason_code":      ReasonRecurrenceLineageUnavailable,
		})}
	}
	var prior PriorLineageRecord
	found := false
	for _, candidate := range options.PriorLineage {
		if candidate.FindingID == recurrence.PriorFindingID {
			prior = candidate
			found = true
			break
		}
	}
	if !found {
		return []diag.Diagnostic{diagnostic(CodeInvalidRecurrenceLineage, "recurrence lineage does not reference a prior finding record.", recurrencePath+"/prior_finding_id", map[string]any{
			"prior_finding_id": recurrence.PriorFindingID,
		})}
	}
	var diagnostics []diag.Diagnostic
	if prior.CharterHash != manifest.CharterHash {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior recurrence charter_hash does not match the current manifest.", recurrencePath+"/prior_finding_id", map[string]any{"actual": prior.CharterHash, "expected": manifest.CharterHash, "field": "charter_hash", "prior_finding_id": prior.FindingID}))
	}
	if prior.ArtifactDigest != recurrence.ArtifactDigest {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior recurrence artifact_digest does not match the recurrence claim.", recurrencePath+"/artifact_digest", map[string]any{"actual": prior.ArtifactDigest, "expected": recurrence.ArtifactDigest, "field": "artifact_digest", "prior_finding_id": prior.FindingID}))
	}
	if prior.FindingKey != recurrence.FindingKey {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior recurrence finding_key does not match the recurrence claim.", recurrencePath+"/finding_key", map[string]any{"actual": prior.FindingKey, "expected": recurrence.FindingKey, "field": "finding_key", "prior_finding_id": prior.FindingID}))
	}
	if prior.WitnessDigest != recurrence.WitnessDigest {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior recurrence witness_digest does not match the recurrence claim.", recurrencePath+"/witness_digest", map[string]any{"actual": prior.WitnessDigest, "expected": recurrence.WitnessDigest, "field": "witness_digest", "prior_finding_id": prior.FindingID}))
	}
	if len(prior.ResolutionEvents) > 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRecurrenceLineage, "prior recurrence record has resolution events and is not unresolved.", recurrencePath+"/prior_finding_id", map[string]any{"prior_finding_id": prior.FindingID, "resolution_event_count": len(prior.ResolutionEvents)}))
	}
	return diagnostics
}

type receiptRecord struct {
	record contracts.ExecutionReceiptManifestRecord
}

func indexExecutionReceipts(records []contracts.ExecutionReceiptManifestRecord) map[string]receiptRecord {
	index := make(map[string]receiptRecord, len(records))
	for _, record := range records {
		index[record.FindingID] = receiptRecord{record: record}
	}
	return index
}

type relayIndex struct {
	byFinding         map[string][]relayFindingRecord
	metadataByBatch   map[string]relayLaunchMetadata
	metadataByFinding map[string]relayLaunchMetadata
	duplicateBatches  map[string][]string
	hasUnavailable    bool
	hasInvalid        bool
	hasValidBatches   bool
	hasNotRequired    bool
	fallbackReason    string
}

type relayFindingRecord struct {
	batchID      string
	status       string
	recipeFamily string
	backend      string
	verdict      contracts.WitnessVerdict
}

type relayLaunchMetadata struct {
	recipeFamily string
	backend      string
}

func indexRelay(manifest contracts.VerificationManifest) relayIndex {
	index := relayIndex{
		byFinding:         map[string][]relayFindingRecord{},
		metadataByBatch:   relayBatchMetadataFromManifest(manifest.ConsumerIdentity),
		metadataByFinding: map[string]relayLaunchMetadata{},
		duplicateBatches:  map[string][]string{},
	}
	metadataBatchIDs := make([]string, 0, len(index.metadataByBatch))
	for batchID := range index.metadataByBatch {
		metadataBatchIDs = append(metadataBatchIDs, batchID)
	}
	sort.Strings(metadataBatchIDs)
	for _, batchID := range metadataBatchIDs {
		metadata := index.metadataByBatch[batchID]
		for _, findingID := range relayMetadataFindingIDs(manifest.ConsumerIdentity, batchID) {
			if _, exists := index.metadataByFinding[findingID]; !exists {
				index.metadataByFinding[findingID] = metadata
			}
		}
	}
	for _, batch := range manifest.Batches {
		batchMetadata := index.metadataByBatch[batch.BatchID]
		switch batch.Status {
		case contracts.RecordStatusValid:
			index.hasValidBatches = true
			if batch.RelayVerdicts == nil {
				index.hasInvalid = true
				index.fallbackReason = nonEmpty(batch.FailureReason, "relay_verdicts_missing")
				continue
			}
			for _, verdict := range batch.RelayVerdicts.Verdicts {
				index.byFinding[verdict.FindingID] = append(index.byFinding[verdict.FindingID], relayFindingRecord{
					batchID:      batch.BatchID,
					status:       batch.Status,
					recipeFamily: batchMetadata.recipeFamily,
					backend:      batchMetadata.backend,
					verdict:      verdict,
				})
			}
		case contracts.RecordStatusFailed:
			index.hasInvalid = true
			index.fallbackReason = nonEmpty(batch.FailureReason, "relay_verification_failed")
		case contracts.RecordStatusUnavailable:
			index.hasUnavailable = true
			index.fallbackReason = nonEmpty(batch.FailureReason, "relay_verification_unavailable")
		case contracts.RecordStatusNotRequired:
			index.hasNotRequired = true
		}
	}
	for findingID, records := range index.byFinding {
		sort.SliceStable(records, func(i, j int) bool {
			return records[i].batchID < records[j].batchID
		})
		index.byFinding[findingID] = records
		batchIDs := uniqueRelayBatchIDs(records)
		if len(batchIDs) > 1 {
			index.duplicateBatches[findingID] = batchIDs
		}
	}
	return index
}

func uniqueRelayBatchIDs(records []relayFindingRecord) []string {
	seen := map[string]struct{}{}
	var batchIDs []string
	for _, record := range records {
		if _, exists := seen[record.batchID]; exists {
			continue
		}
		seen[record.batchID] = struct{}{}
		batchIDs = append(batchIDs, record.batchID)
	}
	sort.Strings(batchIDs)
	return batchIDs
}

func relayBatchMetadataFromManifest(identity map[string]any) map[string]relayLaunchMetadata {
	raw, _ := identity["witness_relay_batches"].(map[string]any)
	result := map[string]relayLaunchMetadata{}
	for batchID, value := range raw {
		object, _ := value.(map[string]any)
		if object == nil {
			continue
		}
		result[batchID] = relayLaunchMetadata{
			recipeFamily: stringMapValue(object, "recipe_family"),
			backend:      stringMapValue(object, "backend"),
		}
	}
	return result
}

func relayMetadataFindingIDs(identity map[string]any, batchID string) []string {
	raw, _ := identity["witness_relay_batches"].(map[string]any)
	object, _ := raw[batchID].(map[string]any)
	switch values := object["finding_ids"].(type) {
	case []string:
		ids := make([]string, 0, len(values))
		for _, id := range values {
			if strings.TrimSpace(id) != "" {
				ids = append(ids, id)
			}
		}
		return ids
	case []any:
		ids := make([]string, 0, len(values))
		for _, value := range values {
			if id, ok := value.(string); ok && strings.TrimSpace(id) != "" {
				ids = append(ids, id)
			}
		}
		return ids
	default:
		return nil
	}
}

func stringMapValue(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return strings.TrimSpace(value)
}

func adjudicateFinding(item loadedFinding, receipts map[string]receiptRecord, relay relayIndex, options Options, rules contracts.ReviewRules, policy contracts.ReviewPolicy, scopePolicy string) FindingVerdict {
	finding := item.finding
	verdict := FindingVerdict{
		FindingID:        finding.ID,
		FindingKey:       findingKey(finding),
		Role:             item.role,
		Kind:             finding.Kind,
		Title:            finding.Title,
		SourceRoleOutput: item.sourceRoleOutput,
		FindingDigest:    item.findingDigest,
		WitnessDigest:    item.witnessDigest,
		EstimatedDelta:   finding.EstimatedDelta,
		ClaimedSeverity:  finding.ClaimedSeverity,
		VerdictClass:     nil,
		Diagnostics:      append([]diag.Diagnostic(nil), item.diagnostics...),
	}
	currentStrength := finding.Witness.Strength
	verdict.StrengthTrajectory = append(verdict.StrengthTrajectory, StrengthStep{Step: "filed", Strength: currentStrength, Reason: "filed_witness"})

	if len(item.diagnostics) > 0 {
		verdict.Disposition = contracts.DispositionAdvisory
		verdict.ApplicationClass = contracts.ApplicationClassNone
		verdict.Reasons = appendValidationReasons(verdict.Reasons, item.diagnostics)
		return verdict
	}

	if excluded, ok := manifestExcludedFinding(options.Manifest, item); ok {
		verdict.Disposition = excluded.Disposition
		verdict.ApplicationClass = excluded.ApplicationClass
		verdict.Reasons = appendReason(verdict.Reasons, excluded.Reason)
		return verdict
	}

	if scopePolicy == contracts.ScopePolicyDeltaObligating && options.Manifest.ChangeSurface != nil && !contracts.FindingInChangeSurface(finding, *options.Manifest.ChangeSurface) {
		verdict.Disposition = contracts.DispositionAdvisory
		verdict.ApplicationClass = contracts.ApplicationClassCallerDecision
		verdict.Reasons = appendReason(verdict.Reasons, ReasonOutOfDelta)
		return verdict
	}

	if currentStrength == contracts.WitnessStrengthExecutable {
		execution := evaluateExecutionReceipt(finding, item.witnessDigest, receipts[finding.ID], options)
		verdict.Execution = &execution.metadata
		switch execution.classification {
		case "satisfied":
		case "contradicted":
			verdict.StrengthTrajectory = append(verdict.StrengthTrajectory, StrengthStep{Step: "execution_receipt", Reason: ReasonExecutionReceiptContradicted})
			verdict.Disposition = contracts.DispositionAdvisory
			verdict.ApplicationClass = contracts.ApplicationClassNone
			verdict.Reasons = appendReason(verdict.Reasons, ReasonExecutionReceiptContradicted)
			verdict.Diagnostics = append(verdict.Diagnostics, execution.metadata.Diagnostics...)
			return verdict
		default:
			currentStrength = contracts.WitnessStrengthConstructed
			verdict.StrengthTrajectory = append(verdict.StrengthTrajectory, StrengthStep{Step: "execution_receipt", Strength: currentStrength, Reason: execution.reason})
			verdict.Reasons = appendReason(verdict.Reasons, execution.reason)
			verdict.Diagnostics = append(verdict.Diagnostics, execution.metadata.Diagnostics...)
		}
	}

	effective, capSeverity, capped := applySeverityCap(finding.ClaimedSeverity, currentStrength, rules)
	if capSeverity == "" {
		verdict.Disposition = contracts.DispositionAdvisory
		verdict.ApplicationClass = contracts.ApplicationClassNone
		verdict.Reasons = appendReason(verdict.Reasons, ReasonValidationFailed)
		return verdict
	}
	verdict.EffectiveSeverity = effective
	verdict.SeverityCap = capSeverity
	if capped {
		verdict.Reasons = appendReason(verdict.Reasons, ReasonSeverityCapped)
	}

	relayResult := evaluateRelay(finding.ID, item.witnessDigest, relay)
	verdict.Relay = &relayResult.metadata
	verdict.Diagnostics = append(verdict.Diagnostics, relayResult.diagnostics...)
	if relayResult.pending {
		verdict.Disposition = contracts.DispositionPendingVerification
		verdict.ApplicationClass = classifyApplication(item.role, finding, verdict.Disposition, verdict.EffectiveSeverity, options.FrozenCharter, policy)
		verdict.Reasons = appendReason(verdict.Reasons, relayResult.reason)
		return verdict
	}
	if relayResult.metadata.Required {
		switch relayResult.verdict.Verdict {
		case contracts.VerdictSurvived:
			verdict.Reasons = appendReason(verdict.Reasons, ReasonRelaySurvived)
		case contracts.VerdictWeakened:
			verdict.VerdictClass = relayResult.verdict.VerdictClass
			currentStrength = downgradeStrength(currentStrength)
			if currentStrength == "" {
				verdict.StrengthTrajectory = append(verdict.StrengthTrajectory, StrengthStep{Step: "relay_result", Reason: ReasonWitnessWeakenedBelowFloor})
				verdict.Disposition = contracts.DispositionAdvisory
				verdict.ApplicationClass = contracts.ApplicationClassNone
				verdict.EffectiveSeverity = ""
				verdict.SeverityCap = ""
				verdict.Reasons = appendReason(verdict.Reasons, ReasonWitnessWeakenedBelowFloor)
				return verdict
			}
			verdict.StrengthTrajectory = append(verdict.StrengthTrajectory, StrengthStep{Step: "relay_result", Strength: currentStrength, Reason: ReasonRelayWeakened})
			verdict.Reasons = appendReason(verdict.Reasons, ReasonRelayWeakened)
			effective, capSeverity, capped = applySeverityCap(finding.ClaimedSeverity, currentStrength, rules)
			verdict.EffectiveSeverity = effective
			verdict.SeverityCap = capSeverity
			if capped {
				verdict.Reasons = appendReason(verdict.Reasons, ReasonSeverityCapped)
			}
		case contracts.VerdictBroken:
			verdict.VerdictClass = relayResult.verdict.VerdictClass
			verdict.Disposition = contracts.DispositionAdvisory
			verdict.ApplicationClass = contracts.ApplicationClassNone
			verdict.EffectiveSeverity = ""
			verdict.SeverityCap = ""
			verdict.Reasons = appendReason(verdict.Reasons, ReasonRelayBroken)
			return verdict
		default:
			verdict.Disposition = contracts.DispositionPendingVerification
			verdict.ApplicationClass = classifyApplication(item.role, finding, verdict.Disposition, verdict.EffectiveSeverity, options.FrozenCharter, policy)
			verdict.Reasons = appendReason(verdict.Reasons, ReasonRelayVerificationInvalid)
			return verdict
		}
	}

	verdict.Disposition = contracts.DispositionAdmitted
	verdict.ApplicationClass = classifyApplication(item.role, finding, verdict.Disposition, verdict.EffectiveSeverity, options.FrozenCharter, policy)
	return verdict
}

type executionEvaluation struct {
	classification string
	reason         string
	metadata       ExecutionMetadata
}

func evaluateExecutionReceipt(finding contracts.Finding, witnessDigest string, record receiptRecord, options Options) executionEvaluation {
	metadata := ExecutionMetadata{Required: true}
	if strings.TrimSpace(record.record.FindingID) == "" {
		metadata.Reason = ReasonExecutionReceiptMissing
		return executionEvaluation{classification: "missing", reason: ReasonExecutionReceiptMissing, metadata: metadata}
	}
	metadata.ManifestStatus = record.record.Status
	if record.record.ReceiptRef != nil {
		metadata.ReceiptID = record.record.ReceiptRef.ID
		metadata.ReceiptDigest = record.record.ReceiptDigest
	}
	switch record.record.Status {
	case contracts.ExecutionStatusSatisfied, contracts.ExecutionStatusContradicted:
	case contracts.ExecutionStatusUnavailable:
		metadata.VerificationClassification = harness.ClassificationUnavailable
		metadata.Reason = ReasonExecutionReceiptUnavailable
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt manifest record status does not provide executable credit.", "/execution_receipts/"+finding.ID+"/status", map[string]any{"status": record.record.Status, "failure_reason": record.record.FailureReason}))
		return executionEvaluation{classification: "unavailable", reason: ReasonExecutionReceiptUnavailable, metadata: metadata}
	default:
		metadata.VerificationClassification = harness.ClassificationInvalid
		metadata.Reason = ReasonExecutionReceiptInvalid
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt manifest record status does not provide executable credit.", "/execution_receipts/"+finding.ID+"/status", map[string]any{"status": record.record.Status, "failure_reason": record.record.FailureReason}))
		return executionEvaluation{classification: "invalid", reason: ReasonExecutionReceiptInvalid, metadata: metadata}
	}
	receipt, diagnostics := loadReceipt(record.record, options.ReceiptOutputDir)
	if len(diagnostics) > 0 {
		metadata.Diagnostics = diagnostics
		if record.record.Status == contracts.ExecutionStatusContradicted {
			metadata.VerificationClassification = harness.ClassificationContradictory
			metadata.Reason = ReasonExecutionReceiptContradicted
			return executionEvaluation{classification: "contradicted", reason: ReasonExecutionReceiptContradicted, metadata: metadata}
		}
		metadata.VerificationClassification = harness.ClassificationUnavailable
		metadata.Reason = ReasonExecutionReceiptUnavailable
		return executionEvaluation{classification: "unavailable", reason: ReasonExecutionReceiptUnavailable, metadata: metadata}
	}
	metadata.ReceiptID = receipt.ReceiptID
	receiptDigest, err := contracts.ExecutionReceiptDigest(receipt)
	if err != nil {
		diagnostic := diagnostic(CodeReceiptLoadFailed, "execution receipt digest could not be computed.", "/execution_receipts/"+finding.ID, map[string]any{"error": err.Error(), "finding_id": finding.ID})
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic)
		metadata.VerificationClassification = harness.ClassificationInvalid
		metadata.Reason = ReasonExecutionReceiptInvalid
		return executionEvaluation{classification: "invalid", reason: ReasonExecutionReceiptInvalid, metadata: metadata}
	}
	metadata.ReceiptDigest = receiptDigest
	if record.record.ReceiptDigest != "" && receiptDigest != record.record.ReceiptDigest {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt digest does not match the manifest record.", "/execution_receipts/"+finding.ID+"/receipt_digest", map[string]any{"actual": receiptDigest, "expected": record.record.ReceiptDigest}))
	}
	if record.record.ReceiptRef != nil && record.record.ReceiptRef.Digest != "" && receiptDigest != record.record.ReceiptRef.Digest {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt digest does not match the manifest receipt_ref.", "/execution_receipts/"+finding.ID+"/receipt_ref/digest", map[string]any{"actual": receiptDigest, "expected": record.record.ReceiptRef.Digest}))
	}
	if receipt.FindingID != finding.ID {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt finding_id does not match the filed finding.", "/execution_receipts/"+finding.ID+"/finding_id", map[string]any{"actual": receipt.FindingID, "expected": finding.ID}))
	}
	if options.Manifest.CharterHash != "" && receipt.CharterHash != options.Manifest.CharterHash {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt charter_hash does not match the verification manifest.", "/execution_receipts/"+finding.ID+"/charter_hash", map[string]any{"actual": receipt.CharterHash, "expected": options.Manifest.CharterHash}))
	}
	if finding.Witness.Executable == nil {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "executable receipt was supplied for a finding without an executable witness.", "/execution_receipts/"+finding.ID, map[string]any{"finding_id": finding.ID}))
	} else if !reflect.DeepEqual(receipt.Command, *finding.Witness.Executable) {
		metadata.Diagnostics = append(metadata.Diagnostics, diagnostic(CodeReceiptRelationshipFailed, "execution receipt command does not match the filed executable witness.", "/execution_receipts/"+finding.ID+"/command", map[string]any{"finding_id": finding.ID, "witness_digest": witnessDigest}))
	}
	relationshipInvalid := len(metadata.Diagnostics) > 0
	verification := harness.VerifyReceipt(harness.VerifyOptions{
		Receipt:              receipt,
		OutputDir:            options.ReceiptOutputDir,
		HMACKey:              options.ReceiptHMACKey,
		HMACKeyFile:          options.ReceiptHMACKeyFile,
		ExpectedSourceDigest: options.Manifest.ArtifactDigest,
	})
	metadata.VerificationClassification = verification.Classification
	metadata.Diagnostics = append(metadata.Diagnostics, verification.Diagnostics...)
	if relationshipInvalid {
		metadata.VerificationClassification = harness.ClassificationInvalid
		metadata.Reason = ReasonExecutionReceiptInvalid
		return executionEvaluation{classification: "invalid", reason: ReasonExecutionReceiptInvalid, metadata: metadata}
	}
	switch verification.Classification {
	case harness.ClassificationValid:
		if receipt.ExecutionStatus == contracts.ExecutionStatusSatisfied {
			return executionEvaluation{classification: "satisfied", metadata: metadata}
		}
		metadata.Reason = ReasonExecutionReceiptNotSatisfied
		return executionEvaluation{classification: "not_satisfied", reason: ReasonExecutionReceiptNotSatisfied, metadata: metadata}
	case harness.ClassificationContradictory:
		metadata.Reason = ReasonExecutionReceiptContradicted
		return executionEvaluation{classification: "contradicted", reason: ReasonExecutionReceiptContradicted, metadata: metadata}
	case harness.ClassificationUnavailable:
		if record.record.Status == contracts.ExecutionStatusContradicted {
			metadata.VerificationClassification = harness.ClassificationContradictory
			metadata.Reason = ReasonExecutionReceiptContradicted
			return executionEvaluation{classification: "contradicted", reason: ReasonExecutionReceiptContradicted, metadata: metadata}
		}
		metadata.Reason = ReasonExecutionReceiptUnavailable
		return executionEvaluation{classification: "unavailable", reason: ReasonExecutionReceiptUnavailable, metadata: metadata}
	default:
		if record.record.Status == contracts.ExecutionStatusContradicted {
			metadata.VerificationClassification = harness.ClassificationContradictory
			metadata.Reason = ReasonExecutionReceiptContradicted
			return executionEvaluation{classification: "contradicted", reason: ReasonExecutionReceiptContradicted, metadata: metadata}
		}
		metadata.Reason = ReasonExecutionReceiptInvalid
		return executionEvaluation{classification: "invalid", reason: ReasonExecutionReceiptInvalid, metadata: metadata}
	}
}

func loadReceipt(record contracts.ExecutionReceiptManifestRecord, outputDir string) (contracts.ExecutionReceipt, []diag.Diagnostic) {
	if record.ReceiptRef == nil {
		return contracts.ExecutionReceipt{}, []diag.Diagnostic{diagnostic(CodeReceiptLoadFailed, "execution receipt manifest record does not include a receipt_ref.", "/execution_receipts/"+record.FindingID+"/receipt_ref", map[string]any{"finding_id": record.FindingID})}
	}
	if strings.TrimSpace(outputDir) == "" {
		return contracts.ExecutionReceipt{}, []diag.Diagnostic{diagnostic(CodeReceiptLoadFailed, "receipt artifact directory is required to verify execution receipts.", "/receipt_output_dir", map[string]any{"finding_id": record.FindingID})}
	}
	path, err := harness.ReceiptPath(outputDir, *record.ReceiptRef)
	if err != nil {
		return contracts.ExecutionReceipt{}, []diag.Diagnostic{diag.FromError(err)}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.ExecutionReceipt{}, []diag.Diagnostic{diagnostic(CodeReceiptLoadFailed, "execution receipt could not be read from the receipt artifact directory.", "/execution_receipts/"+record.FindingID, map[string]any{"error": err.Error(), "path": path})}
	}
	receipt, err := contracts.ReadExecutionReceiptBytes(data)
	if err != nil {
		return contracts.ExecutionReceipt{}, []diag.Diagnostic{diagnostic(CodeReceiptLoadFailed, "execution receipt JSON could not be decoded.", "/execution_receipts/"+record.FindingID, map[string]any{"error": err.Error(), "path": path})}
	}
	return receipt, nil
}

type relayEvaluation struct {
	pending     bool
	reason      string
	verdict     contracts.WitnessVerdict
	metadata    RelayMetadata
	diagnostics []diag.Diagnostic
}

func evaluateRelay(findingID string, witnessDigest string, index relayIndex) relayEvaluation {
	records := index.byFinding[findingID]
	launchMetadata := index.metadataByFinding[findingID]
	if len(records) > 0 {
		record := records[0]
		diagnostics := duplicateRelayBatchDiagnostics(findingID, record.batchID, index.duplicateBatches[findingID])
		metadata := RelayMetadata{
			Required:     true,
			BatchID:      record.batchID,
			RecipeFamily: record.recipeFamily,
			Backend:      record.backend,
			Status:       contracts.RecordStatusValid,
			Verdict:      record.verdict.Verdict,
			VerdictClass: record.verdict.VerdictClass,
		}
		if len(index.duplicateBatches[findingID]) > 1 {
			metadata.Status = contracts.RecordStatusFailed
			metadata.FailureReason = "relay_verdict_finding_id_collision"
			return relayEvaluation{pending: true, reason: ReasonRelayVerificationInvalid, metadata: metadata, diagnostics: diagnostics}
		}
		if record.verdict.WitnessDigest != witnessDigest {
			metadata.Status = contracts.RecordStatusFailed
			metadata.FailureReason = "relay_verdict_witness_digest_mismatch"
			return relayEvaluation{pending: true, reason: ReasonRelayVerificationInvalid, metadata: metadata, diagnostics: diagnostics}
		}
		return relayEvaluation{verdict: record.verdict, metadata: metadata, diagnostics: diagnostics}
	}
	if index.hasInvalid || index.hasValidBatches {
		return relayEvaluation{
			pending: true,
			reason:  ReasonRelayVerificationInvalid,
			metadata: RelayMetadata{
				Required:      true,
				RecipeFamily:  launchMetadata.recipeFamily,
				Backend:       launchMetadata.backend,
				Status:        contracts.RecordStatusFailed,
				FailureReason: nonEmpty(index.fallbackReason, "relay_verdict_missing"),
			},
		}
	}
	if index.hasUnavailable {
		return relayEvaluation{
			pending: true,
			reason:  ReasonRelayVerificationUnavailable,
			metadata: RelayMetadata{
				Required:      true,
				RecipeFamily:  launchMetadata.recipeFamily,
				Backend:       launchMetadata.backend,
				Status:        contracts.RecordStatusUnavailable,
				FailureReason: nonEmpty(index.fallbackReason, "relay_verification_unavailable"),
			},
		}
	}
	if index.hasNotRequired {
		return relayEvaluation{metadata: RelayMetadata{Required: false, Status: contracts.RecordStatusNotRequired}}
	}
	return relayEvaluation{
		pending: true,
		reason:  ReasonRelayVerificationUnavailable,
		metadata: RelayMetadata{
			Required:      true,
			RecipeFamily:  launchMetadata.recipeFamily,
			Backend:       launchMetadata.backend,
			Status:        contracts.RecordStatusUnavailable,
			FailureReason: "relay_verification_missing",
		},
	}
}

func duplicateRelayBatchDiagnostics(findingID string, selectedBatchID string, batchIDs []string) []diag.Diagnostic {
	if len(batchIDs) < 2 {
		return nil
	}
	return []diag.Diagnostic{diagnostic(
		CodeDuplicateRelayBatch,
		"relay verdict finding appears in multiple batches; relay metadata failed closed as pending_verification.",
		"/manifest/batches",
		map[string]any{
			"finding_id":        findingID,
			"selected_batch_id": selectedBatchID,
			"batch_ids":         append([]string(nil), batchIDs...),
		},
	)}
}

func applySeverityCap(claimed string, strength string, rules contracts.ReviewRules) (string, string, bool) {
	capSeverity := rules.SeverityCaps[strength]
	if capSeverity == "" {
		return "", "", false
	}
	if severityRank(claimed) < severityRank(capSeverity) {
		return capSeverity, capSeverity, true
	}
	return claimed, capSeverity, false
}

func downgradeStrength(strength string) string {
	switch strength {
	case contracts.WitnessStrengthExecutable:
		return contracts.WitnessStrengthConstructed
	case contracts.WitnessStrengthConstructed:
		return contracts.WitnessStrengthArgued
	case contracts.WitnessStrengthArgued:
		return ""
	default:
		return ""
	}
}

func classifyApplication(role string, finding contracts.Finding, disposition string, severity string, frozen *charter.FrozenCharter, policy contracts.ReviewPolicy) string {
	if disposition == contracts.DispositionAdvisory {
		return contracts.ApplicationClassNone
	}
	if disposition == contracts.DispositionPendingVerification {
		return contracts.ApplicationClassCallerDecision
	}
	if severity == "" {
		return contracts.ApplicationClassNone
	}
	if severity == contracts.SeverityMedium || severity == contracts.SeverityLow {
		return contracts.ApplicationClassCallerDecision
	}
	if role == contracts.RoleDefect && finding.SmallestSufficientRemedy.Direction == contracts.RemedyDirectionAdd {
		if !policy.DefectAdditiveAutoApplyEnabled || policy.CapRelease == nil || frozen == nil || frozen.Charter.OperationalEnvelope == nil {
			return contracts.ApplicationClassCallerDecision
		}
		productionEstimate, productionKnown := estimatedDeltaValueForUnit(finding.EstimatedDelta.Production, policy.CapRelease.Unit)
		testEstimate, testKnown := estimatedDeltaValueForUnit(finding.EstimatedDelta.Test, policy.CapRelease.Unit)
		if !productionKnown || !testKnown || policy.ProductionCap == nil || policy.TestCap == nil {
			return contracts.ApplicationClassCallerDecision
		}
		if productionEstimate > *policy.ProductionCap || testEstimate > *policy.TestCap {
			return contracts.ApplicationClassCallerDecision
		}
		return contracts.ApplicationClassAutomaticCandidate
	}
	if nonPositiveDelta(finding.EstimatedDelta) {
		return contracts.ApplicationClassAutomaticCandidate
	}
	return contracts.ApplicationClassCallerDecision
}

func deltaKnown(delta contracts.SplitDeltaEstimate) bool {
	return delta.Production.Status == contracts.DeltaStatusKnown && delta.Test.Status == contracts.DeltaStatusKnown
}

func estimatedDeltaValueForUnit(delta contracts.DeltaEstimate, unit string) (int, bool) {
	if delta.Status != contracts.DeltaStatusKnown {
		return 0, false
	}
	switch strings.TrimSpace(unit) {
	case "files":
		if !delta.FilesPresent() {
			return 0, false
		}
		return delta.Files, true
	default:
		if !delta.LinesPresent() {
			return 0, false
		}
		return delta.Lines, true
	}
}

func nonPositiveDelta(delta contracts.SplitDeltaEstimate) bool {
	return deltaKnown(delta) && delta.Production.Lines <= 0 && delta.Test.Lines <= 0
}

func summarize(findings []FindingVerdict) Summary {
	var summary Summary
	for _, finding := range findings {
		switch finding.Disposition {
		case contracts.DispositionAdmitted:
			summary.Admitted++
		case contracts.DispositionAdvisory:
			summary.Advisory++
		case contracts.DispositionPendingVerification:
			summary.PendingVerification++
		}
		switch finding.ApplicationClass {
		case contracts.ApplicationClassAutomaticCandidate:
			summary.AutomaticCandidate++
		case contracts.ApplicationClassCallerDecision:
			summary.CallerDecision++
		case contracts.ApplicationClassNone:
			summary.None++
		}
	}
	summary.FixpointEligible = summary.Admitted == 0 &&
		summary.Advisory == 0 &&
		summary.PendingVerification == 0 &&
		summary.AutomaticCandidate == 0 &&
		summary.CallerDecision == 0
	return summary
}

func stampResultDigest(result *Result) error {
	unstamped := *result
	unstamped.ResultDigest = ""
	value, err := contracts.SemanticDigest(unstamped)
	if err != nil {
		return err
	}
	result.ResultDigest = value
	return nil
}

func appendValidationReasons(reasons []string, diagnostics []diag.Diagnostic) []string {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeInvalidRecurrenceLineage {
			if reason, ok := diagnostic.Details["reason_code"].(string); ok && reason != "" {
				reasons = appendReason(reasons, reason)
				continue
			}
			reasons = appendReason(reasons, ReasonInvalidRecurrenceLineage)
			continue
		}
	}
	if len(reasons) == 0 {
		reasons = appendReason(reasons, ReasonValidationFailed)
	}
	return reasons
}

func manifestExcludedFinding(manifest contracts.VerificationManifest, item loadedFinding) (contracts.ExcludedFindingRecord, bool) {
	for _, excluded := range manifest.ExcludedFindings {
		if excluded.FindingID == item.finding.ID && excluded.SourceRoleOutputDigest == item.sourceDigest {
			return excluded, true
		}
	}
	return contracts.ExcludedFindingRecord{}, false
}

func appendRoleOutputContext(diagnostics []diag.Diagnostic, sourceIndex int, roleOutputPath string) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		result[index] = item
		result[index].Path = "/role_outputs/" + itoa(sourceIndex) + result[index].Path
		if result[index].Details == nil {
			result[index].Details = map[string]any{}
		}
		if roleOutputPath != "" {
			result[index].Details["role_output"] = roleOutputPath
		}
	}
	return result
}

func appendReason(reasons []string, reason string) []string {
	if strings.TrimSpace(reason) == "" {
		return reasons
	}
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func validationError(code string, diagnostics []diag.Diagnostic) error {
	prefixed := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		prefixed[index] = item
		prefixed[index].Code = code
		if prefixed[index].Details == nil {
			prefixed[index].Details = map[string]any{}
		}
		prefixed[index].Details["source_code"] = item.Code
	}
	return &ValidationError{Diagnostics: prefixed}
}

func splitFindingDiagnostics(diagnostics []diag.Diagnostic) (map[int][]diag.Diagnostic, []diag.Diagnostic) {
	byFinding := map[int][]diag.Diagnostic{}
	var document []diag.Diagnostic
	for _, item := range diagnostics {
		index, ok := findingIndexFromPath(item.Path)
		if !ok {
			document = append(document, item)
			continue
		}
		byFinding[index] = append(byFinding[index], item)
	}
	return byFinding, document
}

func appendFindingContext(diagnostics []diag.Diagnostic, sourceIndex int, findingIndex int, roleOutputPath string, findingID string) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		result[index] = item
		result[index].Path = "/role_outputs/" + itoa(sourceIndex) + result[index].Path
		if result[index].Details == nil {
			result[index].Details = map[string]any{}
		}
		result[index].Details["finding_id"] = findingID
		result[index].Details["finding_index"] = findingIndex
		if roleOutputPath != "" {
			result[index].Details["role_output"] = roleOutputPath
		}
	}
	return result
}

func findingIndexFromPath(path string) (int, bool) {
	if !strings.HasPrefix(path, "/findings/") {
		return 0, false
	}
	rest := strings.TrimPrefix(path, "/findings/")
	segment, _, _ := strings.Cut(rest, "/")
	if segment == "" {
		return 0, false
	}
	var value int
	for _, r := range segment {
		if r < '0' || r > '9' {
			return 0, false
		}
		value = value*10 + int(r-'0')
	}
	return value, true
}

func findingPath(sourceIndex int, findingIndex int) string {
	return "/role_outputs/" + itoa(sourceIndex) + "/findings/" + itoa(findingIndex)
}

func prefixDiagnostics(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		result[index] = item
		result[index].Path = prefix + item.Path
	}
	return result
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Message: message, Path: path, Details: details}
}

func cloneDetails(input map[string]any) map[string]any {
	output := make(map[string]any, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func nonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func findingKey(finding contracts.Finding) string {
	if finding.Recurrence != nil && strings.TrimSpace(finding.Recurrence.FindingKey) != "" {
		return finding.Recurrence.FindingKey
	}
	return finding.ID
}

func severityRank(severity string) int {
	switch severity {
	case contracts.SeverityCritical:
		return 0
	case contracts.SeverityHigh:
		return 1
	case contracts.SeverityMedium:
		return 2
	case contracts.SeverityLow:
		return 3
	default:
		return 100
	}
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
		return 100
	}
}

func validDisposition(value string) bool {
	switch value {
	case contracts.DispositionAdmitted, contracts.DispositionAdvisory, contracts.DispositionPendingVerification, contracts.DispositionOwnerOverride:
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, digest.Prefix) {
		return false
	}
	hex := strings.TrimPrefix(value, digest.Prefix)
	if len(hex) != 64 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func validStableID(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if index > 0 && (r == '.' || r == '_' || r == ':' || r == '-') {
			continue
		}
		return false
	}
	return true
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
