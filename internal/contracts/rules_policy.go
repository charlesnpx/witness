package contracts

import (
	"io"
	"strings"

	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/strictjson"
)

type ReviewPolicy struct {
	SchemaVersion                  string            `json:"schema_version"`
	PolicyID                       string            `json:"policy_id"`
	ScopePolicy                    string            `json:"scope_policy,omitempty"`
	DefectAdditiveAutoApplyEnabled bool              `json:"defect_additive_auto_apply_enabled"`
	ProductionCap                  *int              `json:"production_cap,omitempty"`
	TestCap                        *int              `json:"test_cap,omitempty"`
	CapRelease                     *CapReleaseRecord `json:"cap_release,omitempty"`
}

type CapReleaseRecord struct {
	Unit                 string `json:"unit"`
	ProductionCap        int    `json:"production_cap"`
	TestCap              int    `json:"test_cap"`
	Basis                string `json:"basis"`
	Evidence             string `json:"evidence,omitempty"`
	Rationale            string `json:"rationale,omitempty"`
	Actor                string `json:"actor"`
	PolicyDigest         string `json:"policy_digest"`
	DecisionRulesVersion string `json:"decision_rules_version"`
	CharterHash          string `json:"charter_hash"`
}

type PolicyValidationContext struct {
	PolicyDigest string
	CharterHash  string
}

type PolicyValidationResult struct {
	Diagnostics               []diag.Diagnostic `json:"diagnostics,omitempty"`
	CapReleaseCharterMismatch bool              `json:"cap_release_charter_mismatch"`
}

type ApplicationCheck struct {
	Role                       string             `json:"role"`
	RemedyDirection            string             `json:"remedy_direction"`
	OperationalEnvelopePresent bool               `json:"operational_envelope_present"`
	EstimatedDelta             SplitDeltaEstimate `json:"estimated_delta"`
	MeasuredDelta              *MeasuredDelta     `json:"measured_delta,omitempty"`
}

type MeasuredDelta struct {
	Production int `json:"production"`
	Test       int `json:"test"`
}

type PolicyDecision struct {
	Allow                     bool   `json:"allow"`
	Reason                    string `json:"reason"`
	CapReleaseCharterMismatch bool   `json:"cap_release_charter_mismatch"`
}

func ReadReviewPolicy(reader io.Reader) (ReviewPolicy, error) {
	return strictjson.Decode[ReviewPolicy](reader, strictjson.DefaultMaxBytes)
}

func ReadReviewPolicyBytes(data []byte) (ReviewPolicy, error) {
	return strictjson.DecodeBytes[ReviewPolicy](data, strictjson.DefaultMaxBytes)
}

func DefaultReviewPolicy() ReviewPolicy {
	return ReviewPolicy{
		SchemaVersion:                  ReviewPolicyV3,
		PolicyID:                       "bootstrap-review-policy-v3",
		ScopePolicy:                    ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: false,
	}
}

func ValidateReviewPolicy(document ReviewPolicy, context *PolicyValidationContext) PolicyValidationResult {
	var diagnostics []diag.Diagnostic
	result := PolicyValidationResult{}
	if document.SchemaVersion != ReviewPolicyV2 && document.SchemaVersion != ReviewPolicyV3 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "review policy schema_version must be review-policy-v3.", "/schema_version", map[string]any{"expected": ReviewPolicyV3, "actual": document.SchemaVersion}))
	}
	requireStableID(&diagnostics, "/policy_id", "policy ID", document.PolicyID)
	if !validScopePolicy(document.ScopePolicy) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "scope_policy must be delta_obligating or whole_tree when set.", "/scope_policy", map[string]any{"value": document.ScopePolicy}))
	}
	if document.ProductionCap != nil && *document.ProductionCap <= 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "production_cap must be positive when set.", "/production_cap", map[string]any{"value": *document.ProductionCap}))
	}
	if document.TestCap != nil && *document.TestCap <= 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "test_cap must be positive when set.", "/test_cap", map[string]any{"value": *document.TestCap}))
	}
	if document.DefectAdditiveAutoApplyEnabled {
		if document.ProductionCap == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "additive automation fails closed without a production cap.", "/production_cap", nil))
		}
		if document.TestCap == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "additive automation fails closed without a test cap.", "/test_cap", nil))
		}
		if document.CapRelease == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "additive automation fails closed without a matching cap-release record.", "/cap_release", nil))
		}
	}
	if document.CapRelease != nil {
		diagnostics = append(diagnostics, validateCapRelease(*document.CapRelease, document, context, &result)...)
	}
	result.Diagnostics = diagnostics
	return result
}

func RequireValidReviewPolicy(document ReviewPolicy, context *PolicyValidationContext) error {
	result := ValidateReviewPolicy(document, context)
	return ErrorFromDiagnostics(result.Diagnostics)
}

func CheckApplication(policy ReviewPolicy, context *PolicyValidationContext, check ApplicationCheck) PolicyDecision {
	validation := ValidateReviewPolicy(policy, context)
	if len(validation.Diagnostics) > 0 {
		return PolicyDecision{Allow: false, Reason: "policy_invalid", CapReleaseCharterMismatch: validation.CapReleaseCharterMismatch}
	}
	decision := PolicyDecision{CapReleaseCharterMismatch: validation.CapReleaseCharterMismatch}
	if !policy.DefectAdditiveAutoApplyEnabled {
		decision.Reason = "defect_additive_auto_apply_disabled"
		return decision
	}
	if check.Role != RoleDefect || check.RemedyDirection != RemedyDirectionAdd {
		decision.Reason = "caller_decision"
		return decision
	}
	if !check.OperationalEnvelopePresent {
		decision.Reason = "missing_operational_envelope"
		return decision
	}
	if !deltaEstimateKnown(check.EstimatedDelta.Production) || !deltaEstimateKnown(check.EstimatedDelta.Test) {
		decision.Reason = "unknown_estimated_delta"
		return decision
	}
	if policy.ProductionCap == nil || policy.TestCap == nil {
		decision.Reason = "policy_missing_cap"
		return decision
	}
	if check.EstimatedDelta.Production.Lines > *policy.ProductionCap || check.EstimatedDelta.Test.Lines > *policy.TestCap {
		decision.Reason = "estimated_delta_over_cap"
		return decision
	}
	if check.MeasuredDelta == nil {
		decision.Reason = "missing_measured_delta"
		return decision
	}
	if check.MeasuredDelta.Production > *policy.ProductionCap || check.MeasuredDelta.Test > *policy.TestCap {
		decision.Reason = "measured_delta_over_cap"
		return decision
	}
	decision.Allow = true
	decision.Reason = "allowed"
	return decision
}

func deltaEstimateKnown(delta DeltaEstimate) bool {
	return delta.Status == DeltaStatusKnown
}

func EffectiveScopePolicy(document ReviewPolicy) string {
	if strings.TrimSpace(document.ScopePolicy) == ScopePolicyDeltaObligating {
		return ScopePolicyDeltaObligating
	}
	return ScopePolicyWholeTree
}

func ReviewPolicyDigest(document ReviewPolicy) (string, error) {
	return SemanticDigest(document)
}

func ReviewPolicyCanonicalBytes(document ReviewPolicy) ([]byte, error) {
	return CanonicalBytes(document)
}

func validateCapRelease(release CapReleaseRecord, policy ReviewPolicy, context *PolicyValidationContext, result *PolicyValidationResult) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireString(&diagnostics, "/cap_release/unit", "cap release unit", release.Unit)
	if release.ProductionCap <= 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release production cap must be positive.", "/cap_release/production_cap", map[string]any{"value": release.ProductionCap}))
	}
	if release.TestCap <= 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release test cap must be positive.", "/cap_release/test_cap", map[string]any{"value": release.TestCap}))
	}
	if policy.ProductionCap != nil && release.ProductionCap != *policy.ProductionCap {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release production cap must match the loaded policy cap.", "/cap_release/production_cap", map[string]any{"expected": *policy.ProductionCap, "actual": release.ProductionCap}))
	}
	if policy.TestCap != nil && release.TestCap != *policy.TestCap {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release test cap must match the loaded policy cap.", "/cap_release/test_cap", map[string]any{"expected": *policy.TestCap, "actual": release.TestCap}))
	}
	requireEnum(&diagnostics, "/cap_release/basis", "cap-release basis", release.Basis, stringSet(CapReleaseBasisMeasuredHistory, CapReleaseBasisOwnerJudgment), CodeInvalidPolicy)
	if release.Evidence == "" && release.Rationale == "" {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release record requires evidence or rationale.", "/cap_release", nil))
	}
	requireString(&diagnostics, "/cap_release/actor", "cap-release actor", release.Actor)
	requireDigest(&diagnostics, "/cap_release/policy_digest", "cap-release policy_digest", release.PolicyDigest)
	if release.DecisionRulesVersion != DecisionRulesVersion {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidPolicy, "cap-release decision_rules_version must match the current decision engine.", "/cap_release/decision_rules_version", map[string]any{"expected": DecisionRulesVersion, "actual": release.DecisionRulesVersion}))
	}
	requireDigest(&diagnostics, "/cap_release/charter_hash", "cap-release charter_hash", release.CharterHash)
	if context == nil {
		return diagnostics
	}
	if context.PolicyDigest != "" {
		compareDigest(&diagnostics, "/cap_release/policy_digest", "cap-release policy", release.PolicyDigest, context.PolicyDigest)
	}
	if context.CharterHash != "" && release.CharterHash != context.CharterHash {
		result.CapReleaseCharterMismatch = true
	}
	return diagnostics
}

func validScopePolicy(value string) bool {
	switch strings.TrimSpace(value) {
	case "", ScopePolicyDeltaObligating, ScopePolicyWholeTree:
		return true
	default:
		return false
	}
}
