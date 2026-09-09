package review

import (
	"encoding/json"
	"strings"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// ReviewReportV2 identifies the recipe-bound review report boundary.
	ReviewReportV2 = "review-report-v2"
)

// ReviewReportV2Document is a report from one named reviewer requested by a
// ReviewRequestV2Document. It retains the v1 Charter, input, identity,
// finding, evaluation, remedy, and missing-goal surfaces while adding request,
// recipe, reviewer, attribution, and economy bindings. It is invalid when any
// binding or carried report surface is invalid.
type ReviewReportV2Document struct {
	// SchemaVersion identifies this document as review-report-v2; a v1 value is
	// an explicit version mismatch and cannot satisfy a v2 request.
	SchemaVersion string `json:"schema_version"`
	// RequestDigest binds the report to the complete request; it is invalid
	// unless it matches the canonical digest of the supplied v2 request.
	RequestDigest string `json:"request_digest"`
	// RecipeDigest binds the report to the frozen recipe selected by the
	// request; it is invalid unless it matches the request's recipe digest.
	RecipeDigest string `json:"recipe_digest"`
	// Reviewer identifies the open reviewer output this document answers as; it
	// is invalid when malformed or not required by the request.
	Reviewer string `json:"reviewer"`
	// CharterHash carries the v1 Charter binding and must match both the request
	// and the frozen Charter supplied to validation.
	CharterHash string `json:"charter_hash"`
	// ReviewInputDigest carries the v1 exact-input binding and must match the
	// request's input digest.
	ReviewInputDigest string `json:"review_input_digest"`
	// SourceIdentity identifies the reviewed source as in the v1 report; its
	// kind and ID must be non-empty.
	SourceIdentity Identity `json:"source_identity"`
	// ConsumerIdentity identifies the requesting consumer as in v1 and must
	// match the request's consumer identity.
	ConsumerIdentity Identity `json:"consumer_identity"`
	// Findings carries defect and economy findings; nil is invalid, while an
	// empty array is valid when coverage evaluation is present.
	Findings []ReviewReportV2Finding `json:"findings"`
	// Evaluation attests to evaluated paths and Charter goals; it is required
	// and invalid when it does not satisfy the v1 coverage rules.
	Evaluation *ReportEvaluation `json:"evaluation"`
	// MissingGoalQuestions carries the v1 missing-goal question surface; each
	// question must identify a declared finding and valid Charter dimension.
	MissingGoalQuestions []charter.MissingGoalQuestion `json:"missing_goal_questions,omitempty"`
}

// ReviewReportV2Finding carries a v1-shaped finding with open kind and
// attribution values from the established vocabulary. It is invalid when the
// finding evidence, severity cap, Charter references, or economy evidence do
// not agree.
type ReviewReportV2Finding struct {
	// ID identifies the finding and must be unique and stable within the report.
	ID string `json:"id"`
	// Kind identifies whether the finding is a defect or economy finding; other
	// values are invalid.
	Kind string `json:"kind"`
	// Title describes the finding and is invalid when blank or over 8192 bytes.
	Title string `json:"title"`
	// ClaimedSeverity is capped by Witness.Strength using the v1 severity
	// ladder; values outside the ladder or above the cap are invalid.
	ClaimedSeverity string `json:"claimed_severity"`
	// Attribution identifies the finding's origin; it is invalid when outside
	// the established attribution vocabulary.
	Attribution string `json:"attribution"`
	// CharterGoalIDs names declared goals served by the finding; nil is invalid,
	// while an empty array retains v1's unbound-finding meaning.
	CharterGoalIDs []string `json:"charter_goal_ids"`
	// Witness is the finding's evidence. Defect findings require a defect
	// witness and economy findings require an equivalence witness.
	Witness ReportWitness `json:"witness"`
	// Annotation is optional presentation-only location metadata and carries no
	// epistemic weight; if present it follows the v1 annotation rules.
	Annotation *FindingAnnotation `json:"annotation,omitempty"`
	// Remedy is the optional smallest direction for resolving the finding; a
	// remove remedy requires EconomyEquivalence.
	Remedy *ReportRemedy `json:"remedy,omitempty"`
	// EconomyEquivalence records what a removal preserves and which declared
	// goals that preserved behavior serves. It is required for economy findings
	// and for any finding whose remedy direction is remove.
	EconomyEquivalence *EconomyEquivalenceEvidence `json:"economy_equivalence,omitempty"`
}

// EconomyEquivalenceEvidence proves the behavior preserved by an economy
// finding or code-removal remedy. It is invalid when the preserved behavior is
// blank, when no goals are named, or when any goal is absent from the frozen
// Charter.
type EconomyEquivalenceEvidence struct {
	// PreservedBehavior states the behavior that remains after the proposed
	// removal; it is invalid when blank.
	PreservedBehavior string `json:"preserved_behavior"`
	// CharterGoalIDs names the declared goals served by PreservedBehavior; it is
	// invalid when nil, empty, duplicated, malformed, or undeclared.
	CharterGoalIDs []string `json:"charter_goal_ids"`
}

func (document *ReviewReportV2Document) UnmarshalJSON(data []byte) error {
	type alias ReviewReportV2Document
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{
		"schema_version",
		"request_digest",
		"recipe_digest",
		"reviewer",
		"charter_hash",
		"review_input_digest",
		"source_identity",
		"consumer_identity",
		"findings",
		"evaluation",
	} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*document = ReviewReportV2Document(decoded)
	return nil
}

func (finding *ReviewReportV2Finding) UnmarshalJSON(data []byte) error {
	type alias ReviewReportV2Finding
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"id", "kind", "title", "claimed_severity", "attribution", "charter_goal_ids", "witness"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*finding = ReviewReportV2Finding(decoded)
	return nil
}

func (evidence *EconomyEquivalenceEvidence) UnmarshalJSON(data []byte) error {
	type alias EconomyEquivalenceEvidence
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"preserved_behavior", "charter_goal_ids"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*evidence = EconomyEquivalenceEvidence(decoded)
	return nil
}

// DecodeAndValidateReviewReportV2 strictly decodes data and validates all
// request, Charter, reviewer, evidence, and coverage bindings before returning
// the report. A review-report-v1 object is rejected before its fields can be
// interpreted as v2 evidence.
func DecodeAndValidateReviewReportV2(data []byte, request ReviewRequestV2Document, frozen charter.FrozenCharter) (ReviewReportV2Document, error) {
	envelope, err := strictjson.DecodeBytes[map[string]json.RawMessage](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewReportV2Document{}, err
	}
	if raw, ok := envelope["schema_version"]; ok {
		var schemaVersion string
		if err := json.Unmarshal(raw, &schemaVersion); err == nil && schemaVersion == ReviewReportV1 {
			return ReviewReportV2Document{}, ErrorFromDiagnostics([]diag.Diagnostic{Diagnostic(
				CodeInvalidReviewReport,
				"review-report-v1 cannot satisfy review-report-v2 for a review-request-v2; v2 evidence must bind request_digest, recipe_digest, and reviewer.",
				"/schema_version",
				map[string]any{"expected": ReviewReportV2, "actual": ReviewReportV1},
			)})
		}
	}
	document, err := strictjson.DecodeBytes[ReviewReportV2Document](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewReportV2Document{}, err
	}
	if err := RequireValidReviewReportV2(document, request, frozen); err != nil {
		return ReviewReportV2Document{}, err
	}
	return document, nil
}

// RequireValidReviewReportV2 returns an aggregated validation error when a v2
// report does not satisfy its request and frozen Charter boundary.
func RequireValidReviewReportV2(document ReviewReportV2Document, request ReviewRequestV2Document, frozen charter.FrozenCharter) error {
	return ErrorFromDiagnostics(ValidateReviewReportV2(document, request, frozen))
}

// ValidateReviewReportV2 returns every structural and semantic violation in a
// review-report-v2 document. In particular, a v1-shaped report cannot pass by
// merely echoing the v1 Charter and input fields.
func ValidateReviewReportV2(document ReviewReportV2Document, request ReviewRequestV2Document, frozen charter.FrozenCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ReviewReportV2 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"review report schema_version must be review-report-v2.",
			"/schema_version",
			map[string]any{"expected": ReviewReportV2, "actual": document.SchemaVersion},
		))
	}
	requestDiagnostics := ValidateReviewRequestV2(request)
	diagnostics = append(diagnostics, PrefixDiagnostics("/request", requestDiagnostics)...)

	RequireDigest(&diagnostics, "/request_digest", "request_digest", document.RequestDigest)
	if expected, err := ReviewRequestV2Digest(request); err != nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "request digest could not be computed.", "/request_digest", map[string]any{"error": err.Error()}))
	} else {
		CompareDigest(&diagnostics, "/request_digest", "request", document.RequestDigest, expected)
	}
	RequireDigest(&diagnostics, "/recipe_digest", "recipe_digest", document.RecipeDigest)
	CompareDigest(&diagnostics, "/recipe_digest", "recipe", document.RecipeDigest, request.RecipeDigest)
	RequireStableID(&diagnostics, "/reviewer", "reviewer identifier", document.Reviewer)
	if !containsReviewerID(request.RequiredOutputs, document.Reviewer) {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"reviewer is not a required output of the request.",
			"/reviewer",
			map[string]any{"reviewer": document.Reviewer},
		))
	}
	RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	CompareDigest(&diagnostics, "/charter_hash", "request Charter", document.CharterHash, request.CharterHash)
	CompareDigest(&diagnostics, "/charter_hash", "Charter", document.CharterHash, frozen.CharterHash)
	RequireDigest(&diagnostics, "/review_input_digest", "review_input_digest", document.ReviewInputDigest)
	CompareDigest(&diagnostics, "/review_input_digest", "request input", document.ReviewInputDigest, request.ReviewInputDigest)
	validateReviewIdentity(&diagnostics, "/source_identity", "source_identity", document.SourceIdentity, CodeInvalidReviewReport)
	validateReviewIdentity(&diagnostics, "/consumer_identity", "consumer_identity", document.ConsumerIdentity, CodeInvalidReviewReport)
	if !sameIdentity(document.ConsumerIdentity, request.ConsumerIdentity) {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewReport,
			"consumer_identity must match the request consumer.",
			"/consumer_identity",
			map[string]any{"actual": document.ConsumerIdentity, "expected": request.ConsumerIdentity},
		))
	}

	if document.Findings == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "findings is required and must be an array.", "/findings", nil))
	}
	goalIDs := charterGoalIDs(&frozen)
	if document.Evaluation == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "evaluation is required.", "/evaluation", nil))
	} else {
		diagnostics = append(diagnostics, validateReportEvaluation(*document.Evaluation, "/evaluation", goalIDs)...)
	}

	findingIDs := make(map[string]bool, len(document.Findings))
	seenFindings := map[string]int{}
	for index, finding := range document.Findings {
		path := "/findings/" + itoa(index)
		if first, exists := seenFindings[finding.ID]; exists {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"finding IDs must be unique.",
				path+"/id",
				map[string]any{"id": finding.ID, "duplicate_of": "/findings/" + itoa(first) + "/id"},
			))
		}
		seenFindings[finding.ID] = index
		findingIDs[finding.ID] = true
		diagnostics = append(diagnostics, validateReviewReportV2Finding(finding, path, goalIDs)...)
	}
	questionPaths := map[string]string{}
	for index, question := range document.MissingGoalQuestions {
		path := "/missing_goal_questions/" + itoa(index)
		diagnostics = append(diagnostics, validateReportMissingGoalQuestion(question, path, findingIDs)...)
		if firstPath, exists := questionPaths[question.ID]; exists {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewReport,
				"missing-goal question IDs must be unique.",
				path+"/id",
				map[string]any{"id": question.ID, "duplicate_of": firstPath + "/id"},
			))
		}
		questionPaths[question.ID] = path
	}
	return diagnostics
}

// ReviewReportV2Digest returns the canonical semantic JSON digest of a v2
// report.
func ReviewReportV2Digest(document ReviewReportV2Document) (string, error) {
	return digest.SemanticJSON(document)
}

func validateReviewReportV2Finding(finding ReviewReportV2Finding, path string, goalIDs map[string]bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireStableID(&diagnostics, path+"/id", "finding ID", finding.ID)
	RequireEnum(&diagnostics, path+"/kind", "finding kind", finding.Kind, StringSet(FindingKindDefect, FindingKindEconomy), CodeInvalidReviewReport)
	if strings.TrimSpace(finding.Title) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "finding title is required.", path+"/title", nil))
	}
	if len(finding.Title) > 8192 {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "finding title must not exceed 8192 bytes.", path+"/title", map[string]any{"length_bytes": len(finding.Title), "maximum_bytes": 8192}))
	}
	RequireEnum(&diagnostics, path+"/claimed_severity", "claimed_severity", finding.ClaimedSeverity, StringSet(SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow), CodeInvalidReviewReport)
	RequireEnum(&diagnostics, path+"/attribution", "attribution", finding.Attribution, StringSet(FindingAttributionIntroduced, FindingAttributionWorsened, FindingAttributionPreExisting, FindingAttributionUnattributed), CodeInvalidReviewReport)
	if finding.CharterGoalIDs == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "charter_goal_ids is required and must be an array; use [] for an unbound finding.", path+"/charter_goal_ids", nil))
	}
	for index, goalID := range finding.CharterGoalIDs {
		goalPath := path + "/charter_goal_ids/" + itoa(index)
		RequireStableID(&diagnostics, goalPath, "Charter goal ID", goalID)
		if !goalIDs[goalID] {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "finding references a Charter goal that is not declared.", goalPath, map[string]any{"goal_id": goalID}))
		}
	}
	diagnostics = append(diagnostics, validateV2ReportWitness(finding.Witness, path+"/witness")...)
	if finding.Kind == FindingKindDefect && finding.Witness.Kind != WitnessKindDefect {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "defect findings require defect witnesses.", path+"/witness/kind", map[string]any{"kind": finding.Witness.Kind}))
	}
	if finding.Kind == FindingKindEconomy && finding.Witness.Kind != WitnessKindEquivalence {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "economy findings require equivalence witnesses.", path+"/witness/kind", map[string]any{"kind": finding.Witness.Kind}))
	}
	if !severityWithinEvidenceCap(finding.ClaimedSeverity, finding.Witness.Strength) {
		if maximum, ok := maximumSeverityForEvidence(finding.Witness.Strength); ok {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "claimed_severity exceeds the witness strength cap.", path+"/claimed_severity", map[string]any{"claimed_severity": finding.ClaimedSeverity, "maximum_severity": maximum, "witness_strength": finding.Witness.Strength}))
		}
	}
	if finding.Annotation != nil {
		diagnostics = append(diagnostics, validateFindingAnnotation(*finding.Annotation, path+"/annotation")...)
	}
	if finding.Remedy != nil {
		diagnostics = append(diagnostics, validateReportRemedy(*finding.Remedy, path+"/remedy")...)
	}
	if finding.Kind == FindingKindEconomy && finding.EconomyEquivalence == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "economy findings require economy equivalence evidence.", path+"/economy_equivalence", nil))
	}
	if finding.Remedy != nil && finding.Remedy.Direction == RemedyDirectionRemove && finding.EconomyEquivalence == nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "a remove remedy requires economy equivalence evidence.", path+"/economy_equivalence", nil))
	}
	if finding.EconomyEquivalence != nil {
		diagnostics = append(diagnostics, validateEconomyEquivalence(*finding.EconomyEquivalence, path+"/economy_equivalence", goalIDs)...)
	}
	return diagnostics
}

func validateV2ReportWitness(witness ReportWitness, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireEnum(&diagnostics, path+"/kind", "witness kind", witness.Kind, StringSet(WitnessKindDefect, WitnessKindEquivalence), CodeInvalidReviewReport)
	RequireEnum(&diagnostics, path+"/strength", "witness strength", witness.Strength, StringSet(WitnessStrengthExecutable, WitnessStrengthConstructed, WitnessStrengthArgued), CodeInvalidReviewReport)
	if strings.TrimSpace(witness.Content) == "" {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "witness content is required.", path+"/content", nil))
	}
	if witness.Strength == WitnessStrengthExecutable {
		if witness.Executable == nil {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "executable witness strength requires an executable specification.", path+"/executable", nil))
		} else {
			diagnostics = append(diagnostics, validateExecutableSpec(*witness.Executable, path+"/executable", false)...)
		}
	} else if witness.Executable != nil {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "an executable specification requires executable witness strength.", path+"/executable", nil))
	}
	return diagnostics
}

func validateEconomyEquivalence(evidence EconomyEquivalenceEvidence, path string, goalIDs map[string]bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireString(&diagnostics, path+"/preserved_behavior", "preserved behavior", evidence.PreservedBehavior)
	if evidence.CharterGoalIDs == nil || len(evidence.CharterGoalIDs) == 0 {
		diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "economy equivalence evidence must name at least one Charter goal.", path+"/charter_goal_ids", nil))
	}
	seen := map[string]int{}
	for index, goalID := range evidence.CharterGoalIDs {
		goalPath := path + "/charter_goal_ids/" + itoa(index)
		RequireStableID(&diagnostics, goalPath, "economy equivalence Charter goal ID", goalID)
		if !goalIDs[goalID] {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "economy equivalence evidence references a Charter goal that is not declared.", goalPath, map[string]any{"goal_id": goalID}))
		}
		if first, exists := seen[goalID]; exists {
			diagnostics = append(diagnostics, Diagnostic(CodeInvalidReviewReport, "economy equivalence Charter goal IDs must be unique.", goalPath, map[string]any{"duplicate_of": path + "/charter_goal_ids/" + itoa(first)}))
		}
		seen[goalID] = index
	}
	return diagnostics
}

func containsReviewerID(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func sameIdentity(left Identity, right Identity) bool {
	return left.Kind == right.Kind && left.ID == right.ID
}
