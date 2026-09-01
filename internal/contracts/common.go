package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
)

const (
	VerificationBatchV2            = "review-verification-batch-v2"
	RelayWitnessVerdictsV2         = "relay-witness-verdicts-v2"
	VerificationManifestV3         = "review-verification-manifest-v3"
	VerificationManifestV4         = "review-verification-manifest-v4"
	VerificationManifestV5         = "review-verification-manifest-v5"
	VerificationManifestV6         = "review-verification-manifest-v6"
	ExecutionReceiptV2             = "review-execution-receipt-v2"
	RelayCompatibilityV3           = "review-relay-compatibility-v3"
	DecisionRulesVersion           = "witness-decision-rules-v1"
	BatchTaskDefect                = "defect"
	BatchTaskEconomy               = "economy"
	RecordStatusValid              = "valid"
	RecordStatusFailed             = "failed"
	RecordStatusUnavailable        = "unavailable"
	RecordStatusNotRequired        = "not-required"
	RelayLaunchStatusAbsent        = "relay_absent"
	RelayLaunchStatusPresent       = "relay_present"
	ExecutionStatusSatisfied       = "satisfied"
	ExecutionStatusContradicted    = "contradicted"
	ExecutionStatusFailed          = "failed"
	ExecutionStatusUnavailable     = "unavailable"
	ExecutionStatusNotRequired     = "not-required"
	VerdictSurvived                = "survived"
	VerdictWeakened                = "weakened"
	VerdictBroken                  = "broken"
	VerdictClassLogic              = "logic"
	VerdictClassUnreachable        = "unreachable"
	VerdictClassOutsideEnvelope    = "outside_envelope"
	VerdictClassMissingPremise     = "missing_premise"
	VerdictClassOther              = "other"
	DispositionAdmitted            = "admitted"
	DispositionAdvisory            = "advisory"
	DispositionPendingVerification = "pending_verification"
	DispositionOwnerOverride       = "owner_override"
	ReasonOutOfDelta               = "out_of_delta"
	ReasonPreExisting              = "pre_existing"
	ReasonAttributionUnattributed  = "attribution_unattributed"
)

const (
	CodeInvalidVerificationBatch = "invalid_verification_batch"
	CodeInvalidRelayVerdicts     = "invalid_relay_witness_verdicts"
	CodeInvalidManifest          = "invalid_verification_manifest"
	CodeInvalidReceipt           = "invalid_execution_receipt"
	CodeInvalidCompatibility     = "invalid_relay_compatibility"
	CodeCoverageMismatch         = "coverage_mismatch"
	CodeForbiddenExecutionField  = "forbidden_execution_field"
)

var stableIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func decodeStrictContractJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
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
	for index, item := range diagnostics {
		prefixed[index] = item
		prefixed[index].Path = prefix + item.Path
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

func itoa(value int) string {
	return strconvAppend(value)
}

func strconvAppend(value int) string {
	var buffer [20]byte
	return string(strconvAppendInt(buffer[:0], value))
}

func strconvAppendInt(destination []byte, value int) []byte {
	if value == 0 {
		return append(destination, '0')
	}
	if value < 0 {
		destination = append(destination, '-')
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return append(destination, digits[index:]...)
}
