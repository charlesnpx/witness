package policy

import (
	"fmt"
	"strings"

	"witness/internal/contracts"
	"witness/internal/diag"
)

const (
	ShowSchemaVersion     = "witness-policy-show-v1"
	DecisionSchemaVersion = "witness-policy-decision-v1"

	RemedySignPositive    = "positive"
	RemedySignNonPositive = "nonpositive"

	UnitLines = "lines"
	UnitFiles = "files"

	ReasonAllowed                           = "allowed"
	ReasonNonPositiveRemedy                 = "nonpositive_remedy"
	ReasonCallerDecision                    = "caller_decision"
	ReasonPolicyDisabled                    = "defect_additive_auto_apply_disabled"
	ReasonMissingOperationalEnvelope        = "missing_operational_envelope"
	ReasonUnknownEstimatedDelta             = "unknown_estimated_delta"
	ReasonEstimatedDeltaOverCap             = "estimated_delta_over_cap"
	ReasonMissingMeasuredDelta              = "missing_measured_delta"
	ReasonMeasuredDeltaOverCap              = "measured_delta_over_cap"
	ReasonMeasuredDeltaUnitMismatch         = "measured_delta_unit_mismatch"
	ReasonMeasuredDeltaContradictsRemedy    = "measured_delta_contradicts_remedy_sign"
	ReasonPolicyMissingCap                  = "policy_missing_cap"
	ReasonInvalidPolicy                     = "policy_invalid"
	CodeInvalidPolicyLoad                   = "invalid_policy_load"
	CodeInvalidPolicyApplication            = "invalid_policy_application"
	CodeCapReleaseDigestMismatch            = "cap_release_digest_mismatch"
	CodeCapReleasePolicyMismatch            = "cap_release_policy_mismatch"
	CodeCapReleaseRequiresEnabledAutomation = "cap_release_requires_enabled_automation"
)

type LoadOptions struct {
	Policy      contracts.ReviewPolicy
	Rules       contracts.ReviewRules
	CharterHash string
	Unit        string
	CapReleases []contracts.CapReleaseRecord
}

type Effective struct {
	Policy                     contracts.ReviewPolicy
	Rules                      contracts.ReviewRules
	PolicyDigest               string
	RulesDigest                string
	CharterHash                string
	CapRelease                 *contracts.CapReleaseRecord
	CapReleaseCharterMismatch  bool
	PositiveCapAllowanceUsable bool
}

type ShowDocument struct {
	SchemaVersion                  string                      `json:"schema_version"`
	PolicyVersion                  string                      `json:"policy_version"`
	PolicyID                       string                      `json:"policy_id"`
	RulesVersion                   string                      `json:"rules_version"`
	RulesID                        string                      `json:"rules_id"`
	PolicyDigest                   string                      `json:"policy_digest"`
	RulesDigest                    string                      `json:"rules_digest"`
	CharterHash                    string                      `json:"charter_hash,omitempty"`
	DefectAdditiveAutoApplyEnabled bool                        `json:"defect_additive_auto_apply_enabled"`
	ProductionCap                  *int                        `json:"production_cap,omitempty"`
	TestCap                        *int                        `json:"test_cap,omitempty"`
	CapRelease                     *contracts.CapReleaseRecord `json:"cap_release,omitempty"`
	CapReleaseCharterMismatch      bool                        `json:"cap_release_charter_mismatch"`
	PositiveCapAllowanceUsable     bool                        `json:"positive_cap_allowance_usable"`
}

type ReleaseInput struct {
	Policy           contracts.ReviewPolicy
	Rules            contracts.ReviewRules
	Unit             string
	ProductionCap    int
	TestCap          int
	Basis            string
	Evidence         string
	Rationale        string
	Actor            string
	PolicyDigest     string
	RulesDigest      string
	CharterHash      string
	ExpectedPolicyID string
}

type ApplicationCheck struct {
	Role                       string                       `json:"role"`
	RemedyDirection            string                       `json:"remedy_direction,omitempty"`
	RemedySign                 string                       `json:"remedy_sign"`
	Unit                       string                       `json:"unit,omitempty"`
	OperationalEnvelopePresent bool                         `json:"operational_envelope_present"`
	EstimatedDelta             contracts.SplitDeltaEstimate `json:"estimated_delta"`
	MeasuredDelta              *contracts.MeasuredDelta     `json:"measured_delta,omitempty"`
}

type Decision struct {
	SchemaVersion                string                       `json:"schema_version"`
	Allow                        bool                         `json:"allow"`
	Reasons                      []string                     `json:"reasons"`
	PolicyID                     string                       `json:"policy_id"`
	PolicyDigest                 string                       `json:"policy_digest"`
	RulesDigest                  string                       `json:"rules_digest"`
	CharterHash                  string                       `json:"charter_hash,omitempty"`
	CapReleaseCharterMismatch    bool                         `json:"cap_release_charter_mismatch"`
	CapReleaseUnit               string                       `json:"cap_release_unit,omitempty"`
	Unit                         string                       `json:"unit,omitempty"`
	PositiveCapAllowanceConsumed bool                         `json:"positive_cap_allowance_consumed"`
	EstimatedDelta               contracts.SplitDeltaEstimate `json:"estimated_delta"`
	MeasuredDelta                *contracts.MeasuredDelta     `json:"measured_delta,omitempty"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "policy validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func Load(options LoadOptions) (Effective, error) {
	rules := options.Rules
	if rules.SchemaVersion == "" {
		rules = contracts.DefaultReviewRules()
	}
	policy := policyWithoutEmbeddedRelease(options.Policy)
	if policy.SchemaVersion == "" {
		policy = contracts.DefaultReviewPolicy()
	}

	rulesDigest, err := contracts.ReviewRulesDigest(rules)
	if err != nil {
		return Effective{}, err
	}
	policyDigest, err := ReviewPolicyDigest(policy)
	if err != nil {
		return Effective{}, err
	}
	effective := Effective{
		Policy:       policy,
		Rules:        rules,
		PolicyDigest: policyDigest,
		RulesDigest:  rulesDigest,
		CharterHash:  options.CharterHash,
	}

	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, contracts.ValidateReviewRules(rules)...)
	if !policy.DefectAdditiveAutoApplyEnabled {
		validation := contracts.ValidateReviewPolicy(policy, nil)
		diagnostics = append(diagnostics, validation.Diagnostics...)
		if len(diagnostics) > 0 {
			return Effective{}, &ValidationError{Diagnostics: diagnostics}
		}
		return effective, nil
	}

	if policy.ProductionCap == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicyLoad, "additive automation fails closed without a production cap.", "/production_cap", nil))
	}
	if policy.TestCap == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicyLoad, "additive automation fails closed without a test cap.", "/test_cap", nil))
	}
	if len(diagnostics) == 0 && (*policy.ProductionCap <= 0 || *policy.TestCap <= 0) {
		validation := contracts.ValidateReviewPolicy(policy, nil)
		diagnostics = append(diagnostics, validation.Diagnostics...)
	}
	if len(diagnostics) == 0 {
		release := latestMatchingRelease(options.CapReleases, policy, policyDigest, rulesDigest, strings.TrimSpace(options.Unit))
		if release == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicyLoad, "additive automation fails closed without a matching append-only cap-release record.", "/cap_release", nil))
		} else {
			validationPolicy := policy
			validationPolicy.CapRelease = release
			validation := contracts.ValidateReviewPolicy(validationPolicy, &contracts.PolicyValidationContext{
				PolicyDigest: policyDigest,
				RulesDigest:  rulesDigest,
				CharterHash:  options.CharterHash,
			})
			diagnostics = append(diagnostics, validation.Diagnostics...)
			effective.Policy = validationPolicy
			effective.CapRelease = release
			effective.CapReleaseCharterMismatch = validation.CapReleaseCharterMismatch
			effective.PositiveCapAllowanceUsable = len(validation.Diagnostics) == 0
		}
	}
	if len(diagnostics) > 0 {
		return Effective{}, &ValidationError{Diagnostics: diagnostics}
	}
	return effective, nil
}

func BuildCapRelease(input ReleaseInput) (contracts.CapReleaseRecord, error) {
	rules := input.Rules
	if rules.SchemaVersion == "" {
		rules = contracts.DefaultReviewRules()
	}
	policy := policyWithoutEmbeddedRelease(input.Policy)
	if policy.SchemaVersion == "" {
		policy = contracts.DefaultReviewPolicy()
	}
	rulesDigest, err := contracts.ReviewRulesDigest(rules)
	if err != nil {
		return contracts.CapReleaseRecord{}, err
	}
	policyDigest, err := ReviewPolicyDigest(policy)
	if err != nil {
		return contracts.CapReleaseRecord{}, err
	}
	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, contracts.ValidateReviewRules(rules)...)
	if input.PolicyDigest != "" && input.PolicyDigest != policyDigest {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleaseDigestMismatch, "supplied policy digest does not match the canonical review policy digest.", "/policy_digest", map[string]any{"expected": policyDigest, "actual": input.PolicyDigest}))
	}
	if input.RulesDigest != "" && input.RulesDigest != rulesDigest {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleaseDigestMismatch, "supplied rules digest does not match the canonical review rules digest.", "/rules_digest", map[string]any{"expected": rulesDigest, "actual": input.RulesDigest}))
	}
	if strings.TrimSpace(input.ExpectedPolicyID) != "" && input.ExpectedPolicyID != policy.PolicyID {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleasePolicyMismatch, "cap release policy_id does not match the loaded policy.", "/policy_id", map[string]any{"expected": input.ExpectedPolicyID, "actual": policy.PolicyID}))
	}
	if !policy.DefectAdditiveAutoApplyEnabled {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleaseRequiresEnabledAutomation, "cap release requires defect additive automation to be enabled in the reviewed policy.", "/defect_additive_auto_apply_enabled", nil))
	}
	if policy.ProductionCap == nil || *policy.ProductionCap != input.ProductionCap {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleasePolicyMismatch, "cap release production cap must match the loaded policy cap.", "/production_cap", map[string]any{"expected": intPointerValue(policy.ProductionCap), "actual": input.ProductionCap}))
	}
	if policy.TestCap == nil || *policy.TestCap != input.TestCap {
		diagnostics = append(diagnostics, diagnostic(CodeCapReleasePolicyMismatch, "cap release test cap must match the loaded policy cap.", "/test_cap", map[string]any{"expected": intPointerValue(policy.TestCap), "actual": input.TestCap}))
	}
	release := contracts.CapReleaseRecord{
		Unit:          input.Unit,
		ProductionCap: input.ProductionCap,
		TestCap:       input.TestCap,
		Basis:         input.Basis,
		Evidence:      input.Evidence,
		Rationale:     input.Rationale,
		Actor:         input.Actor,
		PolicyDigest:  policyDigest,
		RulesDigest:   rulesDigest,
		CharterHash:   input.CharterHash,
	}
	validationPolicy := policy
	validationPolicy.CapRelease = &release
	validation := contracts.ValidateReviewPolicy(validationPolicy, &contracts.PolicyValidationContext{
		PolicyDigest: policyDigest,
		RulesDigest:  rulesDigest,
		CharterHash:  input.CharterHash,
	})
	diagnostics = append(diagnostics, validation.Diagnostics...)
	if len(diagnostics) > 0 {
		return contracts.CapReleaseRecord{}, &ValidationError{Diagnostics: diagnostics}
	}
	return release, nil
}

func CheckApplication(effective Effective, check ApplicationCheck) (Decision, error) {
	if diagnostics := validateApplicationCheck(check); len(diagnostics) > 0 {
		return Decision{}, &ValidationError{Diagnostics: diagnostics}
	}
	checkUnit := normalizeUnit(check.Unit)
	capReleaseUnit := ""
	if effective.CapRelease != nil {
		capReleaseUnit = effective.CapRelease.Unit
	}
	decision := Decision{
		SchemaVersion:             DecisionSchemaVersion,
		PolicyID:                  effective.Policy.PolicyID,
		PolicyDigest:              effective.PolicyDigest,
		RulesDigest:               effective.RulesDigest,
		CharterHash:               effective.CharterHash,
		CapReleaseCharterMismatch: effective.CapReleaseCharterMismatch,
		CapReleaseUnit:            capReleaseUnit,
		Unit:                      checkUnit,
		EstimatedDelta:            check.EstimatedDelta,
		MeasuredDelta:             check.MeasuredDelta,
	}
	if check.Role != contracts.RoleDefect {
		return decision.refuse(ReasonCallerDecision), nil
	}
	measuredNonPositive := check.MeasuredDelta != nil && check.MeasuredDelta.Production <= 0 && check.MeasuredDelta.Test <= 0
	if check.RemedySign == RemedySignNonPositive || measuredNonPositive {
		if check.MeasuredDelta == nil {
			return decision.refuse(ReasonMissingMeasuredDelta), nil
		}
		if !measuredNonPositive {
			return decision.refuse(ReasonMeasuredDeltaContradictsRemedy), nil
		}
		decision.Allow = true
		decision.Reasons = []string{ReasonNonPositiveRemedy}
		return decision, nil
	}
	if check.RemedyDirection != "" && check.RemedyDirection != contracts.RemedyDirectionAdd {
		return decision.refuse(ReasonCallerDecision), nil
	}
	if !effective.Policy.DefectAdditiveAutoApplyEnabled {
		return decision.refuse(ReasonPolicyDisabled), nil
	}
	if !check.OperationalEnvelopePresent {
		return decision.refuse(ReasonMissingOperationalEnvelope), nil
	}
	if !estimateKnown(check.EstimatedDelta) {
		return decision.refuse(ReasonUnknownEstimatedDelta), nil
	}
	if effective.Policy.ProductionCap == nil || effective.Policy.TestCap == nil {
		return decision.refuse(ReasonPolicyMissingCap), nil
	}
	if effective.CapRelease != nil && effective.CapRelease.Unit != checkUnit {
		return decision.refuse(ReasonMeasuredDeltaUnitMismatch), nil
	}
	if estimatedDeltaValue(check.EstimatedDelta.Production, checkUnit) > *effective.Policy.ProductionCap || estimatedDeltaValue(check.EstimatedDelta.Test, checkUnit) > *effective.Policy.TestCap {
		return decision.refuse(ReasonEstimatedDeltaOverCap), nil
	}
	if check.MeasuredDelta == nil {
		return decision.refuse(ReasonMissingMeasuredDelta), nil
	}
	if check.MeasuredDelta.Production > *effective.Policy.ProductionCap || check.MeasuredDelta.Test > *effective.Policy.TestCap {
		return decision.refuse(ReasonMeasuredDeltaOverCap), nil
	}
	decision.Allow = true
	decision.Reasons = []string{ReasonAllowed}
	decision.PositiveCapAllowanceConsumed = check.MeasuredDelta.Production > 0 || check.MeasuredDelta.Test > 0
	return decision, nil
}

func (effective Effective) ShowDocument() ShowDocument {
	return ShowDocument{
		SchemaVersion:                  ShowSchemaVersion,
		PolicyVersion:                  effective.Policy.SchemaVersion,
		PolicyID:                       effective.Policy.PolicyID,
		RulesVersion:                   effective.Rules.SchemaVersion,
		RulesID:                        effective.Rules.RulesID,
		PolicyDigest:                   effective.PolicyDigest,
		RulesDigest:                    effective.RulesDigest,
		CharterHash:                    effective.CharterHash,
		DefectAdditiveAutoApplyEnabled: effective.Policy.DefectAdditiveAutoApplyEnabled,
		ProductionCap:                  effective.Policy.ProductionCap,
		TestCap:                        effective.Policy.TestCap,
		CapRelease:                     effective.CapRelease,
		CapReleaseCharterMismatch:      effective.CapReleaseCharterMismatch,
		PositiveCapAllowanceUsable:     effective.PositiveCapAllowanceUsable,
	}
}

func ReviewPolicyDigest(document contracts.ReviewPolicy) (string, error) {
	return contracts.ReviewPolicyDigest(policyWithoutEmbeddedRelease(document))
}

func latestMatchingRelease(records []contracts.CapReleaseRecord, document contracts.ReviewPolicy, policyDigest string, rulesDigest string, unit string) *contracts.CapReleaseRecord {
	if document.ProductionCap == nil || document.TestCap == nil {
		return nil
	}
	for i := len(records) - 1; i >= 0; i-- {
		release := records[i]
		if unit != "" && release.Unit != unit {
			continue
		}
		if release.ProductionCap != *document.ProductionCap || release.TestCap != *document.TestCap {
			continue
		}
		if release.PolicyDigest != policyDigest || release.RulesDigest != rulesDigest {
			continue
		}
		return &records[i]
	}
	return nil
}

func validateApplicationCheck(check ApplicationCheck) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireEnum(&diagnostics, "/role", "role", check.Role, []string{contracts.RoleDefect, contracts.RoleEconomy, contracts.RoleGoalFit})
	if check.RemedyDirection != "" {
		requireEnum(&diagnostics, "/remedy_direction", "remedy_direction", check.RemedyDirection, []string{contracts.RemedyDirectionAdd, contracts.RemedyDirectionChange, contracts.RemedyDirectionRemove})
	}
	requireEnum(&diagnostics, "/remedy_sign", "remedy_sign", check.RemedySign, []string{RemedySignPositive, RemedySignNonPositive})
	if strings.TrimSpace(check.Unit) != "" {
		requireEnum(&diagnostics, "/unit", "unit", check.Unit, []string{UnitLines, UnitFiles})
	}
	validateDelta(&diagnostics, "/estimated_delta/production", check.EstimatedDelta.Production)
	validateDelta(&diagnostics, "/estimated_delta/test", check.EstimatedDelta.Test)
	return diagnostics
}

func validateDelta(diagnostics *[]diag.Diagnostic, path string, delta contracts.DeltaEstimate) {
	if delta.Status != contracts.DeltaStatusKnown && delta.Status != contracts.DeltaStatusUnknown {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidPolicyApplication, "delta status has an unsupported value.", path+"/status", map[string]any{"value": delta.Status}))
		return
	}
	if delta.Status == contracts.DeltaStatusUnknown && (delta.Lines != 0 || delta.Files != 0) {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidPolicyApplication, "unknown deltas must not carry line or file counts.", path, nil))
	}
}

func estimateKnown(delta contracts.SplitDeltaEstimate) bool {
	return delta.Production.Status == contracts.DeltaStatusKnown && delta.Test.Status == contracts.DeltaStatusKnown
}

func estimatedDeltaValue(delta contracts.DeltaEstimate, unit string) int {
	if unit == UnitFiles {
		return delta.Files
	}
	return delta.Lines
}

func normalizeUnit(unit string) string {
	if strings.TrimSpace(unit) == "" {
		return UnitLines
	}
	return strings.TrimSpace(unit)
}

func (decision Decision) refuse(reason string) Decision {
	decision.Allow = false
	decision.Reasons = []string{reason}
	return decision
}

func policyWithoutEmbeddedRelease(document contracts.ReviewPolicy) contracts.ReviewPolicy {
	document.CapRelease = nil
	return document
}

func intPointerValue(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func requireEnum(diagnostics *[]diag.Diagnostic, path string, label string, value string, allowed []string) {
	for _, allowedValue := range allowed {
		if value == allowedValue {
			return
		}
	}
	*diagnostics = append(*diagnostics, diagnostic(CodeInvalidPolicyApplication, label+" has an unsupported value.", path, map[string]any{"value": value, "allowed": allowed}))
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Message: message, Path: path, Details: details}
}
