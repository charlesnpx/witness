package contracts

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/review"
)

const (
	VerificationBatchV2            = "review-verification-batch-v2"
	RelayWitnessVerdictsV2         = "relay-witness-verdicts-v2"
	VerificationManifestV3         = "review-verification-manifest-v3"
	VerificationManifestV4         = "review-verification-manifest-v4"
	VerificationManifestV5         = "review-verification-manifest-v5"
	VerificationManifestV6         = "review-verification-manifest-v6"
	ExecutionReceiptV2             = "review-execution-receipt-v2"
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
	CodeCoverageMismatch         = "coverage_mismatch"
	CodeForbiddenExecutionField  = "forbidden_execution_field"
)

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
	*diagnostics = append(*diagnostics, review.PrefixDiagnostics(path, validationErr.Diagnostics)...)
	return true
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
