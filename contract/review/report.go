package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// ReviewReportV1 identifies the defect-review report boundary.
	ReviewReportV1 = "review-report-v1"

	// CodeInvalidReviewReport identifies a report that does not satisfy this
	// boundary's structural or semantic rules.
	CodeInvalidReviewReport = "invalid_review_report"
)

// ReviewReportDocument is the signed-off boundary between a defect reviewer
// and its consumer. It deliberately does not accept role-output documents.
type ReviewReportDocument struct {
	SchemaVersion        string                        `json:"schema_version"`
	Role                 string                        `json:"role"`
	CharterHash          string                        `json:"charter_hash"`
	ReviewInputDigest    string                        `json:"review_input_digest"`
	SourceIdentity       map[string]any                `json:"source_identity"`
	ConsumerIdentity     map[string]any                `json:"consumer_identity"`
	Findings             []ReportFinding               `json:"findings"`
	Evaluation           *ReportEvaluation             `json:"evaluation,omitempty"`
	MissingGoalQuestions []charter.MissingGoalQuestion `json:"missing_goal_questions,omitempty"`

	findingsPresent bool
}

// ReportFinding is a defect finding submitted at the report boundary.
type ReportFinding struct {
	ID              string             `json:"id"`
	Title           string             `json:"title"`
	ClaimedSeverity string             `json:"claimed_severity"`
	CharterGoalIDs  []string           `json:"charter_goal_ids"`
	Witness         Witness            `json:"witness"`
	Annotation      *FindingAnnotation `json:"annotation,omitempty"`
	Remedy          *ReportRemedy      `json:"remedy,omitempty"`

	charterGoalIDsPresent bool
}

// FindingAnnotation is presentation-only location metadata. It carries no
// epistemic weight; the witness is the report's evidence.
type FindingAnnotation struct {
	Path     string `json:"path,omitempty"`
	Line     uint32 `json:"line,omitempty"`
	Category string `json:"category,omitempty"`

	linePresent     bool
	categoryPresent bool
}

// ReportRemedy describes a minimally scoped direction for resolving a report
// finding. It is optional and is not itself evidence for the finding.
type ReportRemedy struct {
	Direction          string `json:"direction"`
	Summary            string `json:"summary"`
	MinimalityArgument string `json:"minimality_argument"`
}

// ReportEvaluation attests to an empty defect review. An evaluation is also
// allowed alongside findings when it provides useful coverage context.
type ReportEvaluation struct {
	EvaluatedPaths   []string `json:"evaluated_paths"`
	EvaluatedGoalIDs []string `json:"evaluated_goal_ids"`

	evaluatedGoalIDsPresent bool
}

func (document *ReviewReportDocument) UnmarshalJSON(data []byte) error {
	type alias ReviewReportDocument
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"schema_version", "role", "charter_hash", "review_input_digest", "source_identity", "consumer_identity", "findings"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*document = ReviewReportDocument(decoded)
	_, document.findingsPresent = fields["findings"]
	return nil
}

func (finding *ReportFinding) UnmarshalJSON(data []byte) error {
	type alias ReportFinding
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"id", "title", "claimed_severity", "charter_goal_ids", "witness"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*finding = ReportFinding(decoded)
	_, finding.charterGoalIDsPresent = fields["charter_goal_ids"]
	return nil
}

func (annotation *FindingAnnotation) UnmarshalJSON(data []byte) error {
	type alias FindingAnnotation
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := rejectPresentJSONNull(fields, "line", "annotation line must be an unsigned integer"); err != nil {
		return err
	}
	*annotation = FindingAnnotation(decoded)
	_, annotation.linePresent = fields["line"]
	_, annotation.categoryPresent = fields["category"]
	return nil
}

func (evaluation *ReportEvaluation) UnmarshalJSON(data []byte) error {
	type alias ReportEvaluation
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"evaluated_paths", "evaluated_goal_ids"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*evaluation = ReportEvaluation(decoded)
	_, evaluation.evaluatedGoalIDsPresent = fields["evaluated_goal_ids"]
	return nil
}

func rejectRequiredJSONNull(fields map[string]json.RawMessage, field string) error {
	return rejectPresentJSONNull(fields, field, "required field \""+field+"\" must not be null")
}

func rejectPresentJSONNull(fields map[string]json.RawMessage, field string, message string) error {
	raw, present := fields[field]
	if present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("json: %s", message)
	}
	return nil
}

// DecodeAndValidateReviewReport strictly decodes data and validates its
// bindings to frozen intent before returning it.
func DecodeAndValidateReviewReport(data []byte, frozen charter.FrozenCharter) (ReviewReportDocument, error) {
	document, err := strictjson.DecodeBytes[ReviewReportDocument](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewReportDocument{}, err
	}
	if err := RequireValidReviewReport(document, frozen); err != nil {
		return ReviewReportDocument{}, err
	}
	return document, nil
}

// RequireValidReviewReport returns an aggregated validation error when a
// report does not satisfy its boundary rules.
func RequireValidReviewReport(document ReviewReportDocument, frozen charter.FrozenCharter) error {
	return ErrorFromDiagnostics(ValidateReviewReport(document, frozen))
}

// ValidateReviewReport returns every structural and semantic violation in a
// review-report-v1 document.
func ValidateReviewReport(document ReviewReportDocument, frozen charter.FrozenCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ReviewReportV1 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"review report schema_version must be review-report-v1.",
			"/schema_version",
			map[string]any{"expected": ReviewReportV1, "actual": document.SchemaVersion},
		))
	}
	RequireEnum(&diagnostics, "/role", "role", document.Role, StringSet(RoleDefect), CodeInvalidReviewReport)
	RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	RequireDigest(&diagnostics, "/review_input_digest", "review_input_digest", document.ReviewInputDigest)
	CompareDigest(&diagnostics, "/charter_hash", "charter", document.CharterHash, frozen.CharterHash)
	validateReviewIdentity(&diagnostics, "/source_identity", "source_identity", document.SourceIdentity, CodeInvalidReviewReport)
	validateReviewIdentity(&diagnostics, "/consumer_identity", "consumer_identity", document.ConsumerIdentity, CodeInvalidReviewReport)

	if document.Findings == nil {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"findings is required and must be an array.",
			"/findings",
			nil,
		))
	}
	if len(document.Findings) == 0 && document.Evaluation == nil {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"an empty findings array requires an evaluation attestation.",
			"/evaluation",
			nil,
		))
	}

	goalIDs := charterGoalIDs(&frozen)
	if document.Evaluation != nil {
		diagnostics = append(diagnostics, validateReportEvaluation(*document.Evaluation, "/evaluation", goalIDs)...)
	}

	seen := map[string]int{}
	for index, finding := range document.Findings {
		path := "/findings/" + itoa(index)
		if first, exists := seen[finding.ID]; exists {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"finding IDs must be unique.",
				path+"/id",
				map[string]any{"id": finding.ID, "duplicate_of": "/findings/" + itoa(first) + "/id"},
			))
		}
		seen[finding.ID] = index
		diagnostics = append(diagnostics, validateReportFinding(finding, path, goalIDs)...)
	}
	return diagnostics
}

// ReviewReportDigest returns the semantic JSON digest of document.
func ReviewReportDigest(document ReviewReportDocument) (string, error) {
	return digest.SemanticJSON(document)
}

func validateReviewIdentity(diagnostics *[]diag.Diagnostic, path string, label string, identity map[string]any, code string) {
	if len(identity) == 0 {
		*diagnostics = append(*diagnostics, Diagnostic(code, label+" is required.", path, nil))
		return
	}
	for _, field := range []string{"kind", "id"} {
		value, ok := identity[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			*diagnostics = append(*diagnostics, Diagnostic(
				code,
				label+" requires a non-empty "+field+".",
				path+"/"+field,
				nil,
			))
		}
	}
}

func validateReportEvaluation(evaluation ReportEvaluation, path string, goalIDs map[string]bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if len(evaluation.EvaluatedPaths) == 0 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"evaluation requires at least one evaluated path.",
			path+"/evaluated_paths",
			nil,
		))
	}
	for index, evaluatedPath := range evaluation.EvaluatedPaths {
		if strings.TrimSpace(evaluatedPath) == "" {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"evaluated paths must be non-empty strings.",
				path+"/evaluated_paths/"+itoa(index),
				nil,
			))
		}
	}
	if evaluation.EvaluatedGoalIDs == nil && !evaluation.evaluatedGoalIDsPresent {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"evaluation requires an evaluated_goal_ids array.",
			path+"/evaluated_goal_ids",
			nil,
		))
	}
	for index, goalID := range evaluation.EvaluatedGoalIDs {
		goalPath := path + "/evaluated_goal_ids/" + itoa(index)
		RequireStableID(&diagnostics, goalPath, "evaluated Charter goal ID", goalID)
		if !goalIDs[goalID] {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"evaluation references a Charter goal that is not declared.",
				goalPath,
				map[string]any{"goal_id": goalID},
			))
		}
	}
	return diagnostics
}

func validateReportFinding(finding ReportFinding, path string, goalIDs map[string]bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireStableID(&diagnostics, path+"/id", "finding ID", finding.ID)
	if strings.TrimSpace(finding.Title) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "finding title is required.", path+"/title", nil))
	}
	if len(finding.Title) > 8192 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"finding title must not exceed 8192 bytes.",
			path+"/title",
			map[string]any{"length_bytes": len(finding.Title), "maximum_bytes": 8192},
		))
	}
	RequireEnum(&diagnostics, path+"/claimed_severity", "claimed_severity", finding.ClaimedSeverity, StringSet(SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow), CodeInvalidReviewReport)
	if finding.CharterGoalIDs == nil && !finding.charterGoalIDsPresent {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"charter_goal_ids is required and must be an array; use [] for an unbound finding.",
			path+"/charter_goal_ids",
			nil,
		))
	}
	for index, goalID := range finding.CharterGoalIDs {
		goalPath := path + "/charter_goal_ids/" + itoa(index)
		RequireStableID(&diagnostics, goalPath, "Charter goal ID", goalID)
		if !goalIDs[goalID] {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"finding references a Charter goal that is not declared.",
				goalPath,
				map[string]any{"goal_id": goalID},
			))
		}
	}
	diagnostics = append(diagnostics, validateReportWitness(finding.Witness, path+"/witness")...)
	if severityWithinEvidenceCap(finding.ClaimedSeverity, finding.Witness.Strength) == false {
		if maximum, ok := maximumSeverityForEvidence(finding.Witness.Strength); ok {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"claimed_severity exceeds the witness strength cap.",
				path+"/claimed_severity",
				map[string]any{"claimed_severity": finding.ClaimedSeverity, "maximum_severity": maximum, "witness_strength": finding.Witness.Strength},
			))
		}
	}
	if finding.Annotation != nil {
		diagnostics = append(diagnostics, validateFindingAnnotation(*finding.Annotation, path+"/annotation")...)
	}
	if finding.Remedy != nil {
		diagnostics = append(diagnostics, validateReportRemedy(*finding.Remedy, path+"/remedy")...)
	}
	return diagnostics
}

func validateReportWitness(witness Witness, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireEnum(&diagnostics, path+"/kind", "witness kind", witness.Kind, StringSet(WitnessKindDefect, WitnessKindEquivalence), CodeInvalidReviewReport)
	RequireEnum(&diagnostics, path+"/strength", "witness strength", witness.Strength, StringSet(WitnessStrengthExecutable, WitnessStrengthConstructed, WitnessStrengthArgued), CodeInvalidReviewReport)
	if strings.TrimSpace(witness.Content) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "witness content is required.", path+"/content", nil))
	}
	return diagnostics
}

func severityWithinEvidenceCap(severity string, strength string) bool {
	maximum, ok := maximumSeverityForEvidence(strength)
	if !ok {
		return true
	}
	severityRank, knownSeverity := severityRanks[severity]
	maximumRank, knownMaximum := severityRanks[maximum]
	return !knownSeverity || !knownMaximum || severityRank <= maximumRank
}

var severityRanks = map[string]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func maximumSeverityForEvidence(strength string) (string, bool) {
	switch strength {
	case WitnessStrengthArgued:
		return SeverityMedium, true
	case WitnessStrengthConstructed:
		return SeverityHigh, true
	case WitnessStrengthExecutable:
		return SeverityCritical, true
	default:
		return "", false
	}
}

func validateFindingAnnotation(annotation FindingAnnotation, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if annotation.linePresent || annotation.Line != 0 {
		if strings.TrimSpace(annotation.Path) == "" {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"annotation line requires a non-empty path.",
				path+"/path",
				nil,
			))
		}
	}
	if annotation.categoryPresent || annotation.Category != "" {
		RequireStableID(&diagnostics, path+"/category", "annotation category", annotation.Category)
	}
	return diagnostics
}

func validateReportRemedy(remedy ReportRemedy, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireEnum(&diagnostics, path+"/direction", "remedy direction", remedy.Direction, StringSet(RemedyDirectionAdd, RemedyDirectionChange, RemedyDirectionRemove), CodeInvalidReviewReport)
	if strings.TrimSpace(remedy.Summary) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "remedy summary is required.", path+"/summary", nil))
	}
	if strings.TrimSpace(remedy.MinimalityArgument) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "remedy minimality_argument is required.", path+"/minimality_argument", nil))
	}
	return diagnostics
}
