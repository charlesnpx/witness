package pass

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/strictjson"
)

type AdjudicationOptions struct {
	FrozenCharter                charter.FrozenCharter
	RoleOutputs                  []adjudicate.RoleOutputInput
	Manifest                     contracts.VerificationManifest
	BaseManifest                 *freeze.Manifest
	HeadManifest                 *freeze.Manifest
	LedgerPath                   string
	ReceiptOutputDir             string
	ReceiptHMACKeyFile           string
	Rules                        contracts.ReviewRules
	Policy                       contracts.ReviewPolicy
	PolicyCapReleaseLedgerBacked bool
	PriorLineage                 []adjudicate.PriorLineageRecord
	PriorLineageProvided         bool
	DriverResumeMode             bool
}

type AdjudicationServiceResult struct {
	Result        *adjudicate.Result
	LedgerRecords []ledger.Record
	RunErr        error
}

func RunAdjudicationService(options AdjudicationOptions) (AdjudicationServiceResult, error) {
	result, runErr := adjudicate.Run(adjudicate.Options{
		FrozenCharter:                &options.FrozenCharter,
		RoleOutputs:                  options.RoleOutputs,
		Manifest:                     options.Manifest,
		BaseManifest:                 options.BaseManifest,
		HeadManifest:                 options.HeadManifest,
		ReceiptOutputDir:             options.ReceiptOutputDir,
		ReceiptHMACKeyFile:           options.ReceiptHMACKeyFile,
		Rules:                        options.Rules,
		Policy:                       options.Policy,
		PolicyCapReleaseLedgerBacked: options.PolicyCapReleaseLedgerBacked,
		PriorLineage:                 options.PriorLineage,
		PriorLineageProvided:         options.PriorLineageProvided,
	})
	service := AdjudicationServiceResult{Result: result, RunErr: runErr}
	if result == nil {
		return service, nil
	}
	if options.LedgerPath != "" {
		appended, err := appendAdjudicationLineage(options.LedgerPath, result, options.RoleOutputs, options.FrozenCharter, options.DriverResumeMode)
		if err != nil {
			return service, err
		}
		service.LedgerRecords = appended
	}
	return service, nil
}

func AppendAdjudicationLineage(path string, result *adjudicate.Result, inputs []adjudicate.RoleOutputInput, frozen charter.FrozenCharter) ([]ledger.Record, error) {
	return appendAdjudicationLineage(path, result, inputs, frozen, false)
}

func appendAdjudicationLineage(path string, result *adjudicate.Result, inputs []adjudicate.RoleOutputInput, frozen charter.FrozenCharter, driverResumeMode bool) ([]ledger.Record, error) {
	if result == nil || result.ResultDigest == "" {
		return nil, diag.New(diag.CodeInvalidCommand, "adjudication result is missing a run digest.")
	}
	events := AdjudicationLedgerEvents(result, inputs, frozen)
	records, err := ledger.ReadFile(path)
	if err != nil {
		return nil, err
	}
	duplicate, err := ledger.ContainsRunDigest(records, result.ResultDigest)
	if err != nil {
		return nil, err
	}
	if duplicate {
		if driverResumeMode {
			if existing, ok, err := completeIdenticalLineage(records, result.ResultDigest, events); err != nil {
				return nil, err
			} else if ok {
				return existing, nil
			}
			if completed, ok, err := completePartialIdenticalLineage(path, records, result.ResultDigest, events); err != nil {
				return nil, err
			} else if ok {
				return completed, nil
			}
		}
		return nil, ledger.DuplicateRunDigestError(result.ResultDigest)
	}
	return ledger.AppendEvents(path, events)
}

func completeIdenticalLineage(records []ledger.Record, runDigest string, events []ledger.EventToAppend) ([]ledger.Record, bool, error) {
	expected, err := canonicalLineage(events)
	if err != nil {
		return nil, false, err
	}
	for start := 0; start+len(expected) <= len(records); start++ {
		if !ledgerRecordMatchesExpected(records[start], expected[0]) {
			continue
		}
		matched := true
		for offset := 1; offset < len(expected); offset++ {
			if !ledgerRecordMatchesExpected(records[start+offset], expected[offset]) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for index, record := range records {
			if index >= start && index < start+len(expected) {
				continue
			}
			recordRunDigest, err := lineageRecordRunDigest(record)
			if err != nil {
				return nil, false, err
			}
			if recordRunDigest == runDigest {
				return nil, false, nil
			}
		}
		return append([]ledger.Record(nil), records[start:start+len(expected)]...), true, nil
	}
	return nil, false, nil
}

func completePartialIdenticalLineage(path string, records []ledger.Record, runDigest string, events []ledger.EventToAppend) ([]ledger.Record, bool, error) {
	expected, err := canonicalLineage(events)
	if err != nil {
		return nil, false, err
	}
	for prefixLen := minInt(len(records), len(expected)-1); prefixLen > 0; prefixLen-- {
		start := len(records) - prefixLen
		matched := true
		for offset := 0; offset < prefixLen; offset++ {
			if !ledgerRecordMatchesExpected(records[start+offset], expected[offset]) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for index, record := range records {
			if index >= start {
				continue
			}
			recordRunDigest, err := lineageRecordRunDigest(record)
			if err != nil {
				return nil, false, err
			}
			if recordRunDigest == runDigest {
				return nil, false, nil
			}
		}
		appended, err := ledger.AppendEvents(path, events[prefixLen:])
		if err != nil {
			return nil, false, err
		}
		completed := append([]ledger.Record(nil), records[start:]...)
		completed = append(completed, appended...)
		return completed, true, nil
	}
	return nil, false, nil
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

type expectedLedgerRecord struct {
	kind  string
	event json.RawMessage
}

func canonicalLineage(events []ledger.EventToAppend) ([]expectedLedgerRecord, error) {
	expected := make([]expectedLedgerRecord, 0, len(events))
	for _, event := range events {
		raw, err := diag.CanonicalBytes(event.Payload)
		if err != nil {
			return nil, err
		}
		expected = append(expected, expectedLedgerRecord{kind: event.Kind, event: append(json.RawMessage(nil), raw...)})
	}
	return expected, nil
}

func ledgerRecordMatchesExpected(record ledger.Record, expected expectedLedgerRecord) bool {
	return record.EventKind == expected.kind && bytes.Equal(record.Event, expected.event)
}

func lineageRecordRunDigest(record ledger.Record) (string, error) {
	switch record.EventKind {
	case ledger.EventKindAdjudicationRun:
		event, err := strictjson.DecodeBytes[ledger.AdjudicationRunEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case ledger.EventKindVerdict:
		event, err := strictjson.DecodeBytes[ledger.VerdictEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case ledger.EventKindQuestion:
		event, err := strictjson.DecodeBytes[ledger.QuestionEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case ledger.EventKindPendingVerification:
		event, err := strictjson.DecodeBytes[ledger.PendingVerificationEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case ledger.EventKindPolicyDecision:
		event, err := strictjson.DecodeBytes[ledger.PolicyDecisionEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	default:
		return "", nil
	}
}

func AdjudicationLedgerEvents(result *adjudicate.Result, inputs []adjudicate.RoleOutputInput, frozen charter.FrozenCharter) []ledger.EventToAppend {
	questions := adjudicationMissingGoalQuestions(inputs)
	events := []ledger.EventToAppend{{
		Kind: ledger.EventKindAdjudicationRun,
		Payload: ledger.AdjudicationRunEvent{
			RunDigest:                 result.ResultDigest,
			ResultSchemaVersion:       result.SchemaVersion,
			PolicyID:                  result.PolicyID,
			PolicyDigest:              result.PolicyDigest,
			RulesDigest:               result.RulesDigest,
			CharterHash:               result.CharterHash,
			ArtifactDigest:            result.ArtifactDigest,
			ManifestDigest:            result.ManifestDigest,
			CapReleaseCharterMismatch: result.CapReleaseCharterMismatch,
			FindingCount:              len(result.Findings),
			PendingVerificationCount:  result.Summary.PendingVerification,
			AutomaticCandidateCount:   result.Summary.AutomaticCandidate,
			CallerDecisionCount:       result.Summary.CallerDecision,
			PolicyDecisionRecordCount: len(result.Findings),
			MissingGoalQuestionCount:  len(questions),
		},
	}}
	for _, finding := range result.Findings {
		events = append(events, ledger.EventToAppend{
			Kind: ledger.EventKindFinding,
			Payload: ledger.FindingEvent{
				FindingID:      finding.FindingID,
				FindingKey:     finding.FindingKey,
				WitnessDigest:  finding.WitnessDigest,
				CharterHash:    result.CharterHash,
				ArtifactDigest: result.ArtifactDigest,
				Finding:        findingPayloadForLedger(finding),
			},
		})
		events = append(events, ledger.EventToAppend{
			Kind: ledger.EventKindVerdict,
			Payload: ledger.VerdictEvent{
				RunDigest:         result.ResultDigest,
				FindingID:         finding.FindingID,
				Role:              finding.Role,
				Kind:              finding.Kind,
				Disposition:       finding.Disposition,
				ApplicationClass:  finding.ApplicationClass,
				ClaimedSeverity:   finding.ClaimedSeverity,
				EffectiveSeverity: finding.EffectiveSeverity,
				SeverityCap:       finding.SeverityCap,
				Reasons:           finding.Reasons,
				FindingDigest:     finding.FindingDigest,
				WitnessDigest:     finding.WitnessDigest,
				VerdictClass:      finding.VerdictClass,
			},
		})
	}
	for _, question := range questions {
		events = append(events, ledger.EventToAppend{
			Kind: ledger.EventKindQuestion,
			Payload: ledger.QuestionEvent{
				RunDigest:        result.ResultDigest,
				QuestionID:       question.ID,
				FindingID:        question.FindingID,
				Dimension:        question.Dimension,
				AnchorIndex:      ledger.IntPtr(question.AnchorIndex),
				Property:         question.Property,
				Value:            question.Value,
				AffectedDecision: question.AffectedDecision,
				CharterHash:      result.CharterHash,
				Statement:        question.Statement,
			},
		})
	}
	for _, finding := range result.Findings {
		if finding.Disposition != contracts.DispositionPendingVerification {
			continue
		}
		events = append(events, ledger.EventToAppend{
			Kind: ledger.EventKindPendingVerification,
			Payload: ledger.PendingVerificationEvent{
				RunDigest:      result.ResultDigest,
				FindingID:      finding.FindingID,
				VerificationID: pendingVerificationID(result.ResultDigest, finding.FindingID),
				Status:         finding.Disposition,
			},
		})
	}
	operationalEnvelopePresent := frozen.Charter.OperationalEnvelope != nil
	for _, finding := range result.Findings {
		allow := finding.ApplicationClass == contracts.ApplicationClassAutomaticCandidate
		events = append(events, ledger.EventToAppend{
			Kind: ledger.EventKindPolicyDecision,
			Payload: ledger.PolicyDecisionEvent{
				RunDigest:                  result.ResultDigest,
				Allow:                      ledger.BoolPtr(allow),
				Reasons:                    policyDecisionReasons(finding),
				PolicyID:                   result.PolicyID,
				PolicyDigest:               result.PolicyDigest,
				RulesDigest:                result.RulesDigest,
				CharterHash:                result.CharterHash,
				CapReleaseCharterMismatch:  result.CapReleaseCharterMismatch,
				CapReleaseUnit:             result.CapReleaseUnit,
				PositiveCapAllowanceUsed:   false,
				FindingID:                  finding.FindingID,
				ApplicationClass:           finding.ApplicationClass,
				OperationalEnvelopePresent: operationalEnvelopePresent,
			},
		})
	}
	return events
}

type adjudicationQuestion struct {
	ID               string
	FindingID        string
	Dimension        string
	AnchorIndex      int
	Property         string
	Value            string
	AffectedDecision string
	Statement        string
	source           int
	index            int
}

func adjudicationMissingGoalQuestions(inputs []adjudicate.RoleOutputInput) []adjudicationQuestion {
	var questions []adjudicationQuestion
	for sourceIndex, input := range inputs {
		for questionIndex, question := range input.Document.MissingGoalQuestions {
			questions = append(questions, adjudicationQuestion{
				ID:               question.ID,
				FindingID:        question.FindingID,
				Dimension:        question.Dimension,
				AnchorIndex:      question.AnchorIndex,
				Property:         question.Property,
				Value:            question.Value,
				AffectedDecision: question.AffectedDecision,
				Statement:        question.Statement,
				source:           sourceIndex,
				index:            questionIndex,
			})
		}
	}
	sortAdjudicationQuestions(questions)
	return questions
}

func sortAdjudicationQuestions(questions []adjudicationQuestion) {
	sort.SliceStable(questions, func(i, j int) bool {
		if questions[i].ID != questions[j].ID {
			return questions[i].ID < questions[j].ID
		}
		if questions[i].FindingID != questions[j].FindingID {
			return questions[i].FindingID < questions[j].FindingID
		}
		if questions[i].source != questions[j].source {
			return questions[i].source < questions[j].source
		}
		return questions[i].index < questions[j].index
	})
}

func pendingVerificationID(runDigest string, findingID string) string {
	suffix := strings.TrimPrefix(runDigest, digest.Prefix)
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	return "pending-" + findingID + "-" + suffix
}

func policyDecisionReasons(finding adjudicate.FindingVerdict) []string {
	if len(finding.Reasons) > 0 {
		return append([]string(nil), finding.Reasons...)
	}
	if finding.ApplicationClass != "" {
		return []string{finding.ApplicationClass}
	}
	return []string{"adjudicated"}
}

func findingPayloadForLedger(finding adjudicate.FindingVerdict) map[string]any {
	return map[string]any{
		"estimated_delta": map[string]any{
			"production": deltaEstimatePayload(finding.EstimatedDelta.Production),
			"test":       deltaEstimatePayload(finding.EstimatedDelta.Test),
		},
	}
}

func deltaEstimatePayload(estimate contracts.DeltaEstimate) map[string]any {
	payload := map[string]any{"status": estimate.Status}
	if estimate.LinesPresent() {
		payload["lines"] = estimate.Lines
	}
	if estimate.FilesPresent() {
		payload["files"] = estimate.Files
	}
	return payload
}
