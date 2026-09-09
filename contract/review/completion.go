package review

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// ReviewCompletionV1 identifies the shared review completion boundary.
	ReviewCompletionV1 = "review-completion-v1"

	// CompletionVerdictSatisfied records that every required report was valid,
	// available, and produced by a complete execution.
	CompletionVerdictSatisfied = "satisfied"
	// CompletionVerdictNotSatisfied records a completed review that does not
	// satisfy the consumer's review outcome.
	CompletionVerdictNotSatisfied = "not_satisfied"
	// CompletionVerdictFailedToRun records that the requested review could not
	// complete or could not produce usable results.
	CompletionVerdictFailedToRun = "failed_to_run"

	// ExecutionReportValid identifies a host-observed valid reviewer report.
	ExecutionReportValid = "valid"
	// ExecutionReportInvalid identifies a host-observed report that failed
	// document validation.
	ExecutionReportInvalid = "invalid"
	// ExecutionReportUnavailable identifies a report artifact unavailable to the
	// host after execution.
	ExecutionReportUnavailable = "unavailable"
	// ExecutionReportMissing identifies a required report that was not produced.
	ExecutionReportMissing = "missing"

	// CodeInvalidReviewCompletion identifies a completion document that does not
	// satisfy the shared completion boundary.
	CodeInvalidReviewCompletion = "invalid_review_completion"
)

// ObservedReportOutcome is a host observation about one report artifact. It
// is invalid when Status is not one of the execution report outcome values.
// This type is an input to host evidence construction, not model report data.
type ObservedReportOutcome struct {
	// Status records the host's observed report state; unsupported values are
	// rejected before they can become execution evidence.
	Status string `json:"status"`
}

// ObservedReviewExecution is the host-observed outcome of running a requested
// review. It is invalid when report statuses are unsupported or report IDs are
// malformed; it is intentionally separate from any decoded model report.
type ObservedReviewExecution struct {
	// Complete says whether the adapter reached a terminal execution outcome;
	// false evidence cannot support a satisfied completion.
	Complete bool `json:"complete"`
	// ResultArtifactAvailable says whether the host can access the result
	// artifacts needed for validation; false evidence cannot support satisfied.
	ResultArtifactAvailable bool `json:"result_artifact_available"`
	// ReportOutcomes records host observations by open reviewer identifier;
	// missing required keys represent missing outputs and unsupported statuses
	// are invalid.
	ReportOutcomes map[string]ObservedReportOutcome `json:"report_outcomes"`
}

// HostExecutionEvidence is an opaque, host-produced execution attestation.
// Its state is private and can only be initialized by
// NewHostExecutionEvidence; JSON decoding deliberately leaves it untrusted,
// so model-authored report bytes cannot provide execution evidence.
type HostExecutionEvidence struct {
	completed               bool
	resultArtifactAvailable bool
	reportOutcomes          map[string]string
	initialized             bool
}

// NewHostExecutionEvidence constructs execution evidence from an observed
// runtime outcome. It rejects malformed reviewer IDs and unknown report
// statuses; the returned opaque value is the only value accepted as host
// execution evidence by completion validation.
func NewHostExecutionEvidence(observed ObservedReviewExecution) (HostExecutionEvidence, error) {
	outcomes := make(map[string]string, len(observed.ReportOutcomes))
	for reviewer, outcome := range observed.ReportOutcomes {
		if !validStableID(reviewer) {
			return HostExecutionEvidence{}, fmt.Errorf("execution report reviewer %q is not a stable identifier", reviewer)
		}
		switch outcome.Status {
		case ExecutionReportValid, ExecutionReportInvalid, ExecutionReportUnavailable, ExecutionReportMissing:
		default:
			return HostExecutionEvidence{}, fmt.Errorf("execution report %q has unsupported status %q", reviewer, outcome.Status)
		}
		outcomes[reviewer] = outcome.Status
	}
	return HostExecutionEvidence{
		completed:               observed.Complete,
		resultArtifactAvailable: observed.ResultArtifactAvailable,
		reportOutcomes:          outcomes,
		initialized:             true,
	}, nil
}

// HostProduced reports whether this evidence was constructed by
// NewHostExecutionEvidence rather than decoded from JSON.
func (evidence HostExecutionEvidence) HostProduced() bool {
	return evidence.initialized
}

// Completed reports the observed terminal execution state.
func (evidence HostExecutionEvidence) Completed() bool {
	return evidence.completed
}

// ResultArtifactAvailable reports whether the host observed accessible result
// artifacts.
func (evidence HostExecutionEvidence) ResultArtifactAvailable() bool {
	return evidence.resultArtifactAvailable
}

// ReportOutcome returns the host-observed status for reviewer, if one was
// observed. It returns false when the output was not observed.
func (evidence HostExecutionEvidence) ReportOutcome(reviewer string) (string, bool) {
	status, ok := evidence.reportOutcomes[reviewer]
	return status, ok
}

// MarshalJSON serializes host-produced evidence for a completion digest. A
// zero or JSON-decoded value cannot be serialized as trusted evidence.
func (evidence HostExecutionEvidence) MarshalJSON() ([]byte, error) {
	if !evidence.initialized {
		return nil, fmt.Errorf("execution evidence was not constructed by host code")
	}
	outcomes := make(map[string]ObservedReportOutcome, len(evidence.reportOutcomes))
	for reviewer, status := range evidence.reportOutcomes {
		outcomes[reviewer] = ObservedReportOutcome{Status: status}
	}
	return json.Marshal(struct {
		Complete                bool                             `json:"complete"`
		ResultArtifactAvailable bool                             `json:"result_artifact_available"`
		ReportOutcomes          map[string]ObservedReportOutcome `json:"report_outcomes"`
	}{
		Complete:                evidence.completed,
		ResultArtifactAvailable: evidence.resultArtifactAvailable,
		ReportOutcomes:          outcomes,
	})
}

// UnmarshalJSON intentionally discards decoded evidence. A model-authored
// JSON object can be syntactically inspected, but it can never initialize the
// opaque host-produced state used by ValidateReviewCompletion.
func (evidence *HostExecutionEvidence) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("execution evidence must not be null")
	}
	type wire struct {
		Complete                bool                             `json:"complete"`
		ResultArtifactAvailable bool                             `json:"result_artifact_available"`
		ReportOutcomes          map[string]ObservedReportOutcome `json:"report_outcomes"`
	}
	var decoded wire
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"complete", "result_artifact_available", "report_outcomes"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*evidence = HostExecutionEvidence{}
	return nil
}

// ReviewCompletionDocument records the host's completion of a v2 request. It
// binds the request digest, adapter, available required report digests, opaque
// host execution evidence, and a terminal verdict. It is invalid when report
// set, bindings, evidence provenance, or satisfied-verdict prerequisites fail.
type ReviewCompletionDocument struct {
	// SchemaVersion identifies the shared completion boundary; any other value
	// is invalid.
	SchemaVersion string `json:"schema_version"`
	// RequestDigest identifies the v2 request completed by this document; it is
	// invalid unless it matches the supplied request's canonical digest.
	RequestDigest string `json:"request_digest"`
	// Adapter identifies the implementation whose run is completed; it is
	// invalid unless it matches the request adapter.
	Adapter string `json:"adapter"`
	// RequiredReportDigests maps each available required reviewer identifier to
	// its report digest. A missing required digest blocks satisfied, while a
	// failed-to-run completion may omit a digest for an output the host observed
	// as missing; extra, malformed, or null entries are invalid.
	RequiredReportDigests map[string]string `json:"required_report_digests"`
	// ExecutionEvidence is accepted as trustworthy only when produced by
	// NewHostExecutionEvidence; decoded JSON leaves it uninitialized.
	ExecutionEvidence HostExecutionEvidence `json:"execution_evidence"`
	// Verdict is the terminal consumer outcome and must be satisfied,
	// not_satisfied, or failed_to_run.
	Verdict string `json:"verdict"`
}

func (document *ReviewCompletionDocument) UnmarshalJSON(data []byte) error {
	type alias ReviewCompletionDocument
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"schema_version", "request_digest", "adapter", "required_report_digests", "execution_evidence", "verdict"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*document = ReviewCompletionDocument(decoded)
	return nil
}

// NewReviewCompletionDocument constructs a completion document for request
// using host-produced evidence and the required report digest set. It returns
// validation errors instead of creating a completion that cannot be trusted.
func NewReviewCompletionDocument(request ReviewRequestV2Document, evidence HostExecutionEvidence, reportDigests map[string]string, verdict string) (ReviewCompletionDocument, error) {
	if err := RequireValidReviewRequestV2(request); err != nil {
		return ReviewCompletionDocument{}, err
	}
	requestDigest, err := ReviewRequestV2Digest(request)
	if err != nil {
		return ReviewCompletionDocument{}, err
	}
	copiedDigests := make(map[string]string, len(reportDigests))
	for reviewer, reportDigest := range reportDigests {
		copiedDigests[reviewer] = reportDigest
	}
	document := ReviewCompletionDocument{
		SchemaVersion:         ReviewCompletionV1,
		RequestDigest:         requestDigest,
		Adapter:               request.Adapter,
		RequiredReportDigests: copiedDigests,
		ExecutionEvidence:     evidence,
		Verdict:               verdict,
	}
	if err := RequireValidReviewCompletion(document, request); err != nil {
		return ReviewCompletionDocument{}, err
	}
	return document, nil
}

// DecodeAndValidateReviewCompletion strictly decodes a completion document
// and validates it against request. JSON evidence remains untrusted after
// decode, so a persisted model-authored completion cannot become satisfied;
// host code must attach a HostExecutionEvidence value first.
func DecodeAndValidateReviewCompletion(data []byte, request ReviewRequestV2Document) (ReviewCompletionDocument, error) {
	document, err := strictjson.DecodeBytes[ReviewCompletionDocument](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewCompletionDocument{}, err
	}
	if err := RequireValidReviewCompletion(document, request); err != nil {
		return ReviewCompletionDocument{}, err
	}
	return document, nil
}

// RequireValidReviewCompletion returns an aggregated validation error when a
// completion document cannot prove the requested review outcome.
func RequireValidReviewCompletion(document ReviewCompletionDocument, request ReviewRequestV2Document) error {
	return ErrorFromDiagnostics(ValidateReviewCompletion(document, request))
}

// ValidateReviewCompletion returns diagnostics for completion bindings,
// required report coverage, evidence provenance, and verdict prerequisites.
// In particular, satisfied is impossible without complete host-observed
// execution, accessible result artifacts, valid required reports, and every
// required report digest.
func ValidateReviewCompletion(document ReviewCompletionDocument, request ReviewRequestV2Document) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ReviewCompletionV1 {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "completion schema_version must be review-completion-v1.", "/schema_version", map[string]any{"expected": ReviewCompletionV1, "actual": document.SchemaVersion}))
	}
	requestDiagnostics := ValidateReviewRequestV2(request)
	diagnostics = append(diagnostics, PrefixDiagnostics("/request", requestDiagnostics)...)
	RequireDigest(&diagnostics, "/request_digest", "request_digest", document.RequestDigest)
	if expected, err := ReviewRequestV2Digest(request); err != nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "request digest could not be computed.", "/request_digest", map[string]any{"error": err.Error()}))
	} else {
		CompareDigest(&diagnostics, "/request_digest", "request", document.RequestDigest, expected)
	}
	RequireStableID(&diagnostics, "/adapter", "adapter", document.Adapter)
	if document.Adapter != request.Adapter {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "adapter must match the request adapter.", "/adapter", map[string]any{"actual": document.Adapter, "expected": request.Adapter}))
	}

	reportDigestSetComplete := true
	missingReportDigestReviewers := make([]string, 0)
	if document.RequiredReportDigests == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "required_report_digests is required and must be an object.", "/required_report_digests", nil))
		reportDigestSetComplete = false
	}
	for _, reviewer := range request.RequiredOutputs {
		path := AppendPointer("/required_report_digests", reviewer)
		reportDigest, exists := document.RequiredReportDigests[reviewer]
		if !exists {
			missingReportDigestReviewers = append(missingReportDigestReviewers, reviewer)
			reportDigestSetComplete = false
			continue
		}
		if !validDigest(reportDigest) {
			RequireDigest(&diagnostics, path, "required report digest", reportDigest)
			reportDigestSetComplete = false
		}
	}
	for reviewer := range document.RequiredReportDigests {
		if !containsReviewerID(request.RequiredOutputs, reviewer) {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "required_report_digests contains an unrequested reviewer.", AppendPointer("/required_report_digests", reviewer), map[string]any{"reviewer": reviewer}))
			reportDigestSetComplete = false
		}
	}

	RequireEnum(&diagnostics, "/verdict", "completion verdict", document.Verdict, StringSet(CompletionVerdictSatisfied, CompletionVerdictNotSatisfied, CompletionVerdictFailedToRun), CodeInvalidReviewCompletion)
	if document.Verdict == CompletionVerdictSatisfied {
		for _, reviewer := range missingReportDigestReviewers {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "required report digest is missing.", AppendPointer("/required_report_digests", reviewer), map[string]any{"reviewer": reviewer}))
		}
	}
	satisfiedPrerequisites := reportDigestSetComplete
	if !document.ExecutionEvidence.initialized {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "execution_evidence must be constructed by host code from an observed runtime outcome.", "/execution_evidence", nil))
		satisfiedPrerequisites = false
	} else {
		if !document.ExecutionEvidence.resultArtifactAvailable {
			satisfiedPrerequisites = false
		}
		if !document.ExecutionEvidence.completed {
			satisfiedPrerequisites = false
		}
		for _, reviewer := range request.RequiredOutputs {
			status, observed := document.ExecutionEvidence.reportOutcomes[reviewer]
			if !observed {
				satisfiedPrerequisites = false
				continue
			}
			if status != ExecutionReportValid {
				satisfiedPrerequisites = false
			}
		}
	}
	if document.Verdict == CompletionVerdictSatisfied && !satisfiedPrerequisites {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewCompletion, "satisfied requires every required report digest, complete execution, available result artifacts, and valid required reports.", "/verdict", nil))
	}
	return diagnostics
}

// ReviewCompletionDigest returns the canonical semantic JSON digest of a
// host-produced completion document.
func ReviewCompletionDigest(document ReviewCompletionDocument) (string, error) {
	return digest.SemanticJSON(document)
}

// ReviewVerdictSatisfied is an alias for CompletionVerdictSatisfied for callers
// that name terminal values by their review meaning.
const ReviewVerdictSatisfied = CompletionVerdictSatisfied

// ReviewVerdictNotSatisfied is an alias for CompletionVerdictNotSatisfied for
// callers that name terminal values by their review meaning.
const ReviewVerdictNotSatisfied = CompletionVerdictNotSatisfied

// ReviewVerdictFailedToRun is an alias for CompletionVerdictFailedToRun for
// callers that name terminal values by their review meaning.
const ReviewVerdictFailedToRun = CompletionVerdictFailedToRun
