package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/diag"
	"witness/internal/digest"
)

const (
	RoleOutputV3                       = "review-role-output-v3"
	VerificationBatchV2                = "review-verification-batch-v2"
	RelayWitnessVerdictsV2             = "relay-witness-verdicts-v2"
	VerificationManifestV3             = "review-verification-manifest-v3"
	VerificationManifestV4             = "review-verification-manifest-v4"
	ExecutionReceiptV2                 = "review-execution-receipt-v2"
	RelayCompatibilityV3               = "review-relay-compatibility-v3"
	ReviewRulesV2                      = "review-rules-v2"
	ReviewRulesV3                      = "review-rules-v3"
	ReviewPolicyV2                     = "review-policy-v2"
	ReviewPolicyV3                     = "review-policy-v3"
	RoleDefect                         = "defect"
	RoleEconomy                        = "economy"
	RoleGoalFit                        = "goal_fit"
	FindingKindDefect                  = "defect"
	FindingKindEconomy                 = "economy"
	WitnessKindDefect                  = "defect"
	WitnessKindEquivalence             = "equivalence"
	WitnessStrengthExecutable          = "executable"
	WitnessStrengthConstructed         = "constructed"
	WitnessStrengthArgued              = "argued"
	SeverityCritical                   = "critical"
	SeverityHigh                       = "high"
	SeverityMedium                     = "medium"
	SeverityLow                        = "low"
	DeltaStatusKnown                   = "known"
	DeltaStatusUnknown                 = "unknown"
	RemedyDirectionAdd                 = "add"
	RemedyDirectionChange              = "change"
	RemedyDirectionRemove              = "remove"
	BatchTaskDefect                    = "defect"
	BatchTaskEconomy                   = "economy"
	RecordStatusValid                  = "valid"
	RecordStatusFailed                 = "failed"
	RecordStatusUnavailable            = "unavailable"
	RecordStatusNotRequired            = "not-required"
	RelayLaunchStatusAbsent            = "relay_absent"
	RelayLaunchStatusPresent           = "relay_present"
	ExecutionStatusSatisfied           = "satisfied"
	ExecutionStatusContradicted        = "contradicted"
	ExecutionStatusFailed              = "failed"
	ExecutionStatusUnavailable         = "unavailable"
	ExecutionStatusNotRequired         = "not-required"
	VerdictSurvived                    = "survived"
	VerdictWeakened                    = "weakened"
	VerdictBroken                      = "broken"
	VerdictClassLogic                  = "logic"
	VerdictClassUnreachable            = "unreachable"
	VerdictClassOutsideEnvelope        = "outside_envelope"
	VerdictClassMissingPremise         = "missing_premise"
	VerdictClassOther                  = "other"
	ApplicationClassAutomaticCandidate = "automatic_candidate"
	ApplicationClassCallerDecision     = "caller_decision"
	ApplicationClassNone               = "none"
	DispositionAdmitted                = "admitted"
	DispositionAdvisory                = "advisory"
	DispositionPendingVerification     = "pending_verification"
	DispositionOwnerOverride           = "owner_override"
	CapReleaseBasisMeasuredHistory     = "measured_history"
	CapReleaseBasisOwnerJudgment       = "explicit_owner_judgment"
	ScopePolicyDeltaObligating         = "delta_obligating"
	ScopePolicyWholeTree               = "whole_tree"
	ReasonOutOfDelta                   = "out_of_delta"
)

const (
	CodeInvalidContract          = "invalid_contract"
	CodeInvalidRoleOutput        = "invalid_role_output"
	CodeInvalidVerificationBatch = "invalid_verification_batch"
	CodeInvalidRelayVerdicts     = "invalid_relay_witness_verdicts"
	CodeInvalidManifest          = "invalid_verification_manifest"
	CodeInvalidReceipt           = "invalid_execution_receipt"
	CodeInvalidCompatibility     = "invalid_relay_compatibility"
	CodeInvalidRules             = "invalid_review_rules"
	CodeInvalidPolicy            = "invalid_review_policy"
	CodeDigestMismatch           = "digest_mismatch"
	CodeCoverageMismatch         = "coverage_mismatch"
	CodeForbiddenExecutionField  = "forbidden_execution_field"
	CodeMissingCharterTrace      = "missing_charter_trace"
	CodeInvalidDelta             = "invalid_delta"
	CodeInvalidRemedy            = "invalid_remedy"
	CodeInvalidWitness           = "invalid_witness"
	CodeFiledValueMutated        = "contracts_filed_value_mutated"
)

var stableIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "contract validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func ErrorFromDiagnostics(diagnostics []diag.Diagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	return &ValidationError{Diagnostics: diagnostics}
}

func CanonicalBytes(value any) ([]byte, error) {
	return canonjson.Marshal(value)
}

func SemanticDigest(value any) (string, error) {
	return digest.SemanticJSON(value)
}

func decodeStrictContractJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func canonicalRawMessage(data []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	canonical, err := CanonicalBytes(value)
	if err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), canonical...), nil
}

func canonicalJSONWithVerifiedCache(value any, cached json.RawMessage, label string) (json.RawMessage, error) {
	projectionCanonical, err := CanonicalBytes(value)
	if err != nil {
		return nil, err
	}
	if len(cached) == 0 {
		return append(json.RawMessage(nil), projectionCanonical...), nil
	}
	projectionValue, err := decodeCanonicalJSONValue(projectionCanonical)
	if err != nil {
		return nil, err
	}
	cachedValue, err := decodeCanonicalJSONValue(cached)
	if err != nil {
		return nil, err
	}
	cachedCanonical, err := CanonicalBytes(cachedValue)
	if err != nil {
		return nil, err
	}
	mergedProjection := mergeOmittedCachedJSONValues(projectionValue, cachedValue)
	mergedCanonical, err := CanonicalBytes(mergedProjection)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(mergedCanonical, cachedCanonical) {
		return nil, filedValueMutatedError(label)
	}
	return append(json.RawMessage(nil), cachedCanonical...), nil
}

func decodeCanonicalJSONValue(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func mergeOmittedCachedJSONValues(projected any, cached any) any {
	switch projectedValue := projected.(type) {
	case map[string]any:
		cachedValue, ok := cached.(map[string]any)
		if !ok {
			return projected
		}
		merged := make(map[string]any, len(projectedValue)+len(cachedValue))
		for key, value := range projectedValue {
			if cachedItem, exists := cachedValue[key]; exists {
				merged[key] = mergeOmittedCachedJSONValues(value, cachedItem)
				continue
			}
			merged[key] = value
		}
		for key, cachedItem := range cachedValue {
			if _, exists := projectedValue[key]; !exists && isOmittedJSONZeroValue(cachedItem) {
				merged[key] = cachedItem
			}
		}
		return merged
	case []any:
		cachedValue, ok := cached.([]any)
		if !ok || len(projectedValue) != len(cachedValue) {
			return projected
		}
		merged := make([]any, len(projectedValue))
		for index, value := range projectedValue {
			merged[index] = mergeOmittedCachedJSONValues(value, cachedValue[index])
		}
		return merged
	default:
		return projected
	}
}

func isOmittedJSONZeroValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case bool:
		return !typed
	case string:
		return typed == ""
	case json.Number:
		canonical, err := CanonicalBytes(typed)
		return err == nil && string(canonical) == "0"
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

func filedValueMutatedError(label string) error {
	return &ValidationError{Diagnostics: []diag.Diagnostic{diagnostic(
		CodeFiledValueMutated,
		label+" was mutated after decode; cached canonical JSON no longer matches the current value.",
		"",
		map[string]any{"value": label},
	)}}
}

func appendValidationErrorDiagnostics(diagnostics *[]diag.Diagnostic, path string, err error) bool {
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		return false
	}
	*diagnostics = append(*diagnostics, prefixDiagnostics(path, validationErr.Diagnostics)...)
	return true
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

func requireDigest(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	if !validDigest(value) {
		*diagnostics = append(*diagnostics, diagnostic(
			CodeInvalidContract,
			field+" must be a relay-root-digests-v1 sha256 digest.",
			path,
			map[string]any{"value": value},
		))
	}
}

func requireString(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	if strings.TrimSpace(value) == "" {
		*diagnostics = append(*diagnostics, diagnostic(
			CodeInvalidContract,
			field+" is required.",
			path,
			nil,
		))
	}
}

func requireStableID(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	if !stableIDPattern.MatchString(value) {
		*diagnostics = append(*diagnostics, diagnostic(
			CodeInvalidContract,
			field+" requires a stable ID.",
			path,
			map[string]any{"id": value},
		))
	}
}

func requireEnum(diagnostics *[]diag.Diagnostic, path string, field string, value string, allowed map[string]bool, code string) {
	if !allowed[value] {
		*diagnostics = append(*diagnostics, diagnostic(
			code,
			field+" has an unsupported value.",
			path,
			map[string]any{"value": value},
		))
	}
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{
		Code:    code,
		Message: message,
		Path:    path,
		Details: details,
	}
}

func prefixDiagnostics(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	prefixed := make([]diag.Diagnostic, len(diagnostics))
	for i, item := range diagnostics {
		prefixed[i] = item
		prefixed[i].Path = prefix + item.Path
	}
	return prefixed
}

func appendPointer(path string, segment string) string {
	escaped := strings.ReplaceAll(segment, "~", "~0")
	escaped = strings.ReplaceAll(escaped, "/", "~1")
	return path + "/" + escaped
}

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func compareDigest(diagnostics *[]diag.Diagnostic, path string, label string, actual string, expected string) {
	if actual != expected {
		*diagnostics = append(*diagnostics, diagnostic(
			CodeDigestMismatch,
			label+" digest mismatch.",
			path,
			map[string]any{"actual": actual, "expected": expected},
		))
	}
}

func identityPresent(identity map[string]any) bool {
	return len(identity) > 0
}

func hasForbiddenExecutionFieldName(name string) bool {
	switch name {
	case "execution_attestation", "execution-attestation", "execution_contradiction":
		return true
	default:
		return false
	}
}
