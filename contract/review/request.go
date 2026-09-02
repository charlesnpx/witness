package review

import (
	"encoding/json"
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// ReviewRequestV1 identifies the review-request boundary.
	ReviewRequestV1 = "review-request-v1"

	// CodeInvalidReviewRequest identifies a request that does not satisfy this
	// boundary's structural or semantic rules.
	CodeInvalidReviewRequest = "invalid_review_request"
)

// ReviewRequestDocument binds a consumer, source revision, frozen intent, and
// exact reviewer input before a review-report-v1 document is requested.
type ReviewRequestDocument struct {
	SchemaVersion     string         `json:"schema_version"`
	ConsumerIdentity  Identity       `json:"consumer_identity"`
	Subject           RequestSubject `json:"subject"`
	CharterHash       string         `json:"charter_hash"`
	ReviewInputDigest string         `json:"review_input_digest"`
}

// RequestSubject identifies the source revision under review. Head is
// required; Tree and Branch are optional supplemental revision labels.
type RequestSubject struct {
	Head   string `json:"head"`
	Tree   string `json:"tree,omitempty"`
	Branch string `json:"branch,omitempty"`

	treePresent   bool
	branchPresent bool
}

func (subject *RequestSubject) UnmarshalJSON(data []byte) error {
	type alias RequestSubject
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := rejectRequiredJSONNull(fields, "head"); err != nil {
		return err
	}
	for _, field := range []string{"tree", "branch"} {
		if err := rejectPresentJSONNull(fields, field, "subject "+field+" must be a string when present"); err != nil {
			return err
		}
	}
	*subject = RequestSubject(decoded)
	_, subject.treePresent = fields["tree"]
	_, subject.branchPresent = fields["branch"]
	return nil
}

func (document *ReviewRequestDocument) UnmarshalJSON(data []byte) error {
	type alias ReviewRequestDocument
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"schema_version", "consumer_identity", "subject", "charter_hash", "review_input_digest"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*document = ReviewRequestDocument(decoded)
	return nil
}

// DecodeAndValidateReviewRequest strictly decodes data and validates the
// request boundary before returning it.
func DecodeAndValidateReviewRequest(data []byte) (ReviewRequestDocument, error) {
	document, err := strictjson.DecodeBytes[ReviewRequestDocument](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewRequestDocument{}, err
	}
	if err := RequireValidReviewRequest(document); err != nil {
		return ReviewRequestDocument{}, err
	}
	return document, nil
}

// RequireValidReviewRequest returns an aggregated validation error when a
// request does not satisfy its boundary rules.
func RequireValidReviewRequest(document ReviewRequestDocument) error {
	return ErrorFromDiagnostics(ValidateReviewRequest(document))
}

// ValidateReviewRequest returns every structural and semantic violation in a
// review-request-v1 document.
func ValidateReviewRequest(document ReviewRequestDocument) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ReviewRequestV1 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"review request schema_version must be review-request-v1.",
			"/schema_version",
			map[string]any{"expected": ReviewRequestV1, "actual": document.SchemaVersion},
		))
	}
	validateReviewIdentity(&diagnostics, "/consumer_identity", "consumer_identity", document.ConsumerIdentity, CodeInvalidReviewRequest)
	if strings.TrimSpace(document.Subject.Head) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject head is required.", "/subject/head", nil))
	}
	if (document.Subject.treePresent || document.Subject.Tree != "") && strings.TrimSpace(document.Subject.Tree) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject tree must be non-empty when present.", "/subject/tree", nil))
	}
	if (document.Subject.branchPresent || document.Subject.Branch != "") && strings.TrimSpace(document.Subject.Branch) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject branch must be non-empty when present.", "/subject/branch", nil))
	}
	RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	RequireDigest(&diagnostics, "/review_input_digest", "review_input_digest", document.ReviewInputDigest)
	return diagnostics
}

// ReviewRequestDigest returns the canonical semantic JSON digest of document.
// That digest is the request digest; it has no self-referential field.
func ReviewRequestDigest(document ReviewRequestDocument) (string, error) {
	return digest.SemanticJSON(document)
}
