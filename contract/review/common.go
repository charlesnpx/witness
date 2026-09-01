package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/internal/validate"
)

const (
	RoleOutputV3                   = "review-role-output-v3"
	RoleOutputV4                   = "review-role-output-v4"
	RoleOutputV5                   = "review-role-output-v5"
	RoleDefect                     = "defect"
	RoleEconomy                    = "economy"
	RoleGoalFit                    = "goal_fit"
	FindingKindDefect              = "defect"
	FindingKindEconomy             = "economy"
	WitnessKindDefect              = "defect"
	WitnessKindEquivalence         = "equivalence"
	WitnessStrengthExecutable      = "executable"
	WitnessStrengthConstructed     = "constructed"
	WitnessStrengthArgued          = "argued"
	SeverityCritical               = "critical"
	SeverityHigh                   = "high"
	SeverityMedium                 = "medium"
	SeverityLow                    = "low"
	DeltaStatusKnown               = "known"
	DeltaStatusUnknown             = "unknown"
	RemedyDirectionAdd             = "add"
	RemedyDirectionChange          = "change"
	RemedyDirectionRemove          = "remove"
	FindingAttributionIntroduced   = "introduced"
	FindingAttributionWorsened     = "worsened"
	FindingAttributionPreExisting  = "pre-existing"
	FindingAttributionUnattributed = "unattributed"
)

const (
	CodeInvalidContract     = "invalid_contract"
	CodeInvalidRoleOutput   = "invalid_role_output"
	CodeDigestMismatch      = "digest_mismatch"
	CodeMissingCharterTrace = "missing_charter_trace"
	CodeInvalidDelta        = "invalid_delta"
	CodeInvalidRemedy       = "invalid_remedy"
	CodeInvalidWitness      = "invalid_witness"
	CodeFiledValueMutated   = "contracts_filed_value_mutated"
)

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

func requireDigest(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	validate.RequireDigest(diagnostics, path, field, value, CodeInvalidContract)
}

func requireString(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	validate.RequireString(diagnostics, path, field, value, CodeInvalidContract)
}

func requireStableID(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	validate.RequireStableID(diagnostics, path, field, value, CodeInvalidContract)
}

func requireEnum(diagnostics *[]diag.Diagnostic, path string, field string, value string, allowed map[string]bool, code string) {
	validate.RequireEnum(diagnostics, path, field, value, allowed, code)
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return validate.Diagnostic(code, message, path, details)
}

func prefixDiagnostics(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	return validate.PrefixDiagnostics(prefix, diagnostics)
}

func stringSet(values ...string) map[string]bool {
	return validate.StringSet(values...)
}

func compareDigest(diagnostics *[]diag.Diagnostic, path string, label string, actual string, expected string) {
	validate.CompareDigest(diagnostics, path, label, actual, expected, CodeDigestMismatch)
}

func identityPresent(identity map[string]any) bool {
	return validate.IdentityPresent(identity)
}
