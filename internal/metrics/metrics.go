package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"witness/internal/adjudicate"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/ledger"
	"witness/internal/preflight"
	"witness/internal/strictjson"
)

const (
	SchemaVersion = "witness-metrics-v1"

	CodeInvalidRunResult = "metrics_invalid_run_result"
	CodeInvalidPreflight = "metrics_invalid_preflight"
)

const (
	InputStatusLoaded  = "loaded"
	InputStatusMissing = "missing"

	ReasonLedgerMissing                      = "ledger_missing"
	ReasonPreflightMissing                   = "preflight_missing"
	ReasonRunResultsMissing                  = "run_results_missing"
	ReasonBackendStatusMissing               = "backend_auth_status_missing"
	ReasonBackendAttributionMissing          = "backend_attribution_missing"
	ReasonReceiptLineageMissing              = "receipt_lineage_missing"
	ReasonNoPairedEstimatedAndMeasuredDeltas = "no_paired_estimated_and_measured_deltas"
	ReasonEstimatedDeltaMissing              = "estimated_delta_missing"
	ReasonEstimatedProductionMissing         = "estimated_production_missing"
	ReasonEstimatedTestMissing               = "estimated_test_missing"
	ReasonEstimatedProductionUnitMissing     = "estimated_production_unit_missing"
	ReasonEstimatedTestUnitMissing           = "estimated_test_unit_missing"
	ReasonMeasuredDeltaMissing               = "measured_missing"
	ReasonMeasuredProductionMissing          = "measured_production_missing"
	ReasonMeasuredTestMissing                = "measured_test_missing"
	BackendAuthStatusAuthenticated           = "authenticated"
	BackendAuthStatusInstalledAuthUnknown    = "installed_auth_unknown"
	BackendAuthStatusFailed                  = "failed"
	BackendAuthStatusUnattributed            = "unattributed"
	VerdictClassNone                         = "none"
	MetricStatusReceiptBasedContradiction    = "receipt_based_contradiction"
	MetricStatusUnattributedContradiction    = "unattributed_contradiction"
	MetricStatusInvalidResult                = "invalid_result"
)

var backendAuthStatuses = []string{
	BackendAuthStatusAuthenticated,
	BackendAuthStatusInstalledAuthUnknown,
	BackendAuthStatusFailed,
}

var verdictClasses = []string{
	VerdictClassNone,
	contracts.VerdictClassLogic,
	contracts.VerdictClassUnreachable,
	contracts.VerdictClassOutsideEnvelope,
	contracts.VerdictClassMissingPremise,
	contracts.VerdictClassOther,
}

type Options struct {
	LedgerPath     string
	PreflightPath  string
	RunResultPaths []string
}

type Document struct {
	SchemaVersion       string                     `json:"schema_version"`
	Inputs              Inputs                     `json:"inputs"`
	PendingVerification PendingVerificationMetrics `json:"pending_verification"`
	OperationalEnvelope OperationalEnvelopeMetrics `json:"operational_envelope"`
	Verdicts            VerdictMetrics             `json:"verdicts"`
	CapRelease          CapReleaseMetrics          `json:"cap_release"`
	DeltaComparison     DeltaComparisonMetrics     `json:"delta_comparison"`
	Diagnostics         []diag.Diagnostic          `json:"diagnostics,omitempty"`
}

type Inputs struct {
	Ledger     InputStatus   `json:"ledger"`
	Preflight  InputStatus   `json:"preflight"`
	RunResults []InputStatus `json:"run_results"`
}

type InputStatus struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Count  int    `json:"count,omitempty"`
}

type PendingVerificationMetrics struct {
	Total                   int                          `json:"total"`
	Unstratified            int                          `json:"unstratified,omitempty"`
	UnstratifiedReason      string                       `json:"unstratified_reason,omitempty"`
	LaunchBackendAuthStatus string                       `json:"launch_backend_auth_status,omitempty"`
	Strata                  []PendingVerificationStratum `json:"strata"`
}

type PendingVerificationStratum struct {
	Backend           string `json:"backend,omitempty"`
	BackendAuthStatus string `json:"backend_auth_status"`
	Count             int    `json:"count"`
	Reason            string `json:"reason,omitempty"`
}

type OperationalEnvelopeMetrics struct {
	EmittedMissingGoalQuestions CountWithReason  `json:"emitted_missing_goal_questions"`
	Promotions                  CountWithReason  `json:"promotions"`
	GenericMissingGoalQuestions *CountWithReason `json:"generic_missing_goal_questions,omitempty"`
	GenericPromotions           *CountWithReason `json:"generic_promotions,omitempty"`
}

type CountWithReason struct {
	Count  int    `json:"count"`
	Reason string `json:"reason,omitempty"`
}

type VerdictMetrics struct {
	Survived                   int                 `json:"survived"`
	Weakened                   int                 `json:"weakened"`
	Broken                     int                 `json:"broken"`
	InvalidResult              int                 `json:"invalid_result"`
	ReceiptBasedContradictions int                 `json:"receipt_based_contradictions"`
	UnattributedContradictions *CountWithReason    `json:"unattributed_contradictions,omitempty"`
	ByVerdictClass             []VerdictClassCount `json:"by_verdict_class"`
}

type VerdictClassCount struct {
	VerdictClass               string `json:"verdict_class"`
	Survived                   int    `json:"survived"`
	Weakened                   int    `json:"weakened"`
	Broken                     int    `json:"broken"`
	InvalidResult              int    `json:"invalid_result"`
	ReceiptBasedContradictions int    `json:"receipt_based_contradictions"`
	UnattributedContradictions int    `json:"unattributed_contradictions,omitempty"`
	Reason                     string `json:"reason,omitempty"`
}

type CapReleaseMetrics struct {
	CharterMismatchCount     int             `json:"charter_mismatch_count"`
	RunResultMismatchCount   CountWithReason `json:"run_result_mismatch_count"`
	LedgerEventMismatchCount CountWithReason `json:"ledger_event_mismatch_count"`
}

type DeltaComparisonMetrics struct {
	PairedFindings   int                     `json:"paired_findings"`
	ExcludedFindings int                     `json:"excluded_findings,omitempty"`
	ExcludedStrata   []DeltaExclusionStratum `json:"excluded_strata,omitempty"`
	Production       DeltaComponentMetrics   `json:"production"`
	Test             DeltaComponentMetrics   `json:"test"`
	Reason           string                  `json:"reason,omitempty"`
}

type DeltaExclusionStratum struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type DeltaComponentMetrics struct {
	Equal           int `json:"equal"`
	OverEstimate    int `json:"over_estimate"`
	UnderEstimate   int `json:"under_estimate"`
	EstimateUnknown int `json:"estimate_unknown"`
	EstimateMissing int `json:"estimate_missing"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "metrics validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

type runResultInput struct {
	result adjudicate.Result
}

func Run(options Options) (Document, error) {
	document := Document{
		SchemaVersion:       SchemaVersion,
		Inputs:              inputStatuses(options),
		PendingVerification: emptyPendingVerificationMetrics(""),
		Verdicts:            emptyVerdictMetrics(""),
	}

	records, ledgerLoaded, err := readLedger(options.LedgerPath)
	if err != nil {
		return document, err
	}
	preflightResult, preflightLoaded, err := readPreflight(options.PreflightPath)
	if err != nil {
		return document, err
	}
	runResults, err := readRunResults(options.RunResultPaths)
	if err != nil {
		return document, err
	}
	document.Inputs = loadedInputStatuses(options, ledgerLoaded, len(records), preflightLoaded, len(runResults))

	document.PendingVerification = pendingVerificationMetrics(runResults, preflightResult, preflightLoaded)
	document.OperationalEnvelope = operationalEnvelopeMetrics(records, ledgerLoaded)
	document.Verdicts = verdictMetrics(runResults)
	document.CapRelease = capReleaseMetrics(runResults, records, ledgerLoaded)
	document.DeltaComparison = deltaComparisonMetrics(records, ledgerLoaded)
	return document, nil
}

func inputStatuses(options Options) Inputs {
	inputs := Inputs{
		Ledger:    missingInputStatus(options.LedgerPath, ReasonLedgerMissing),
		Preflight: missingInputStatus(options.PreflightPath, ReasonPreflightMissing),
	}
	if len(options.RunResultPaths) == 0 {
		inputs.RunResults = []InputStatus{{Status: InputStatusMissing, Reason: ReasonRunResultsMissing}}
		return inputs
	}
	for _, path := range options.RunResultPaths {
		inputs.RunResults = append(inputs.RunResults, missingInputStatus(path, ReasonRunResultsMissing))
	}
	return inputs
}

func loadedInputStatuses(options Options, ledgerLoaded bool, ledgerCount int, preflightLoaded bool, runResultCount int) Inputs {
	inputs := inputStatuses(options)
	if ledgerLoaded {
		inputs.Ledger = InputStatus{Status: InputStatusLoaded, Count: ledgerCount}
	}
	if preflightLoaded {
		inputs.Preflight = InputStatus{Status: InputStatusLoaded, Count: 1}
	}
	if len(options.RunResultPaths) > 0 {
		inputs.RunResults = make([]InputStatus, 0, len(options.RunResultPaths))
		for range options.RunResultPaths {
			inputs.RunResults = append(inputs.RunResults, InputStatus{Status: InputStatusLoaded, Count: 1})
		}
	} else if runResultCount > 0 {
		inputs.RunResults = []InputStatus{{Status: InputStatusLoaded, Count: runResultCount}}
	}
	return inputs
}

func missingInputStatus(path string, reason string) InputStatus {
	return InputStatus{Status: InputStatusMissing, Reason: reason}
}

func readLedger(path string) ([]ledger.Record, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, nil
	}
	records, err := ledger.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return records, true, nil
}

func readPreflight(path string) (preflight.Result, bool, error) {
	if strings.TrimSpace(path) == "" {
		return preflight.Result{}, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return preflight.Result{}, false, err
	}
	result, err := strictjson.DecodeBytes[preflight.Result](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return preflight.Result{}, false, validationError(CodeInvalidPreflight, "preflight state could not be decoded.", "/preflight", path, err)
	}
	if result.SchemaVersion != preflight.SchemaVersion {
		return preflight.Result{}, false, &ValidationError{Diagnostics: []diag.Diagnostic{{
			Code:    CodeInvalidPreflight,
			Message: "preflight state schema_version is unsupported.",
			Path:    "/preflight/schema_version",
			Details: map[string]any{"expected": preflight.SchemaVersion, "actual": result.SchemaVersion, "path": path},
		}}}
	}
	return result, true, nil
}

func readRunResults(paths []string) ([]runResultInput, error) {
	results := make([]runResultInput, 0, len(paths))
	for index, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result, err := strictjson.DecodeBytes[adjudicate.Result](data, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return nil, validationError(CodeInvalidRunResult, "run-result document could not be decoded.", "/run_results/"+itoa(index), path, err)
		}
		if result.SchemaVersion != adjudicate.ResultSchemaVersion {
			return nil, &ValidationError{Diagnostics: []diag.Diagnostic{{
				Code:    CodeInvalidRunResult,
				Message: "run-result document schema_version is unsupported.",
				Path:    "/run_results/" + itoa(index) + "/schema_version",
				Details: map[string]any{"expected": adjudicate.ResultSchemaVersion, "actual": result.SchemaVersion, "path": path},
			}}}
		}
		results = append(results, runResultInput{result: result})
	}
	return results, nil
}

func validationError(code string, message string, path string, filePath string, cause error) error {
	diagnostic := diag.FromError(cause)
	if diagnostic.Code == "internal_error" {
		diagnostic.Code = code
		diagnostic.Message = message
	}
	if diagnostic.Path == "" {
		diagnostic.Path = path
	} else {
		diagnostic.Path = path + diagnostic.Path
	}
	if diagnostic.Details == nil {
		diagnostic.Details = map[string]any{}
	}
	diagnostic.Details["path"] = filePath
	return &ValidationError{Diagnostics: []diag.Diagnostic{diagnostic}}
}

func pendingVerificationMetrics(results []runResultInput, preflightResult preflight.Result, preflightLoaded bool) PendingVerificationMetrics {
	reason := ""
	if len(results) == 0 {
		reason = ReasonRunResultsMissing
	}
	metrics := emptyPendingVerificationMetrics(reason)
	summaryPending := 0
	var pending []adjudicate.FindingVerdict
	for _, input := range results {
		summaryPending += input.result.Summary.PendingVerification
		for _, finding := range input.result.Findings {
			if finding.Disposition == contracts.DispositionPendingVerification {
				pending = append(pending, finding)
			}
		}
	}
	if len(pending) > 0 {
		metrics.Total = len(pending)
	} else {
		metrics.Total = summaryPending
	}
	if len(results) == 0 {
		return metrics
	}
	if !preflightLoaded {
		metrics.Unstratified = metrics.Total
		metrics.UnstratifiedReason = ReasonPreflightMissing
		for index := range metrics.Strata {
			metrics.Strata[index].Reason = ReasonPreflightMissing
		}
		return metrics
	}
	if len(pending) == 0 {
		if metrics.Total > 0 {
			metrics.Strata = []PendingVerificationStratum{{
				Backend:           BackendAuthStatusUnattributed,
				BackendAuthStatus: BackendAuthStatusUnattributed,
				Count:             metrics.Total,
				Reason:            ReasonBackendAttributionMissing,
			}}
		}
		return metrics
	}
	metrics.Strata = pendingVerificationStrata(pending, preflightResult.BackendStrata)
	return metrics
}

func emptyPendingVerificationMetrics(reason string) PendingVerificationMetrics {
	metrics := PendingVerificationMetrics{
		Strata: make([]PendingVerificationStratum, 0, len(backendAuthStatuses)),
	}
	for _, status := range backendAuthStatuses {
		metrics.Strata = append(metrics.Strata, PendingVerificationStratum{
			BackendAuthStatus: status,
			Reason:            reason,
		})
	}
	return metrics
}

func pendingVerificationStrata(pending []adjudicate.FindingVerdict, backendStrata map[string]string) []PendingVerificationStratum {
	type stratumKey struct {
		backend string
		status  string
		reason  string
	}
	byKey := map[stratumKey]int{}
	for _, finding := range pending {
		backend := ""
		if finding.Relay != nil {
			backend = strings.TrimSpace(finding.Relay.Backend)
		}
		if backend == "" {
			byKey[stratumKey{backend: BackendAuthStatusUnattributed, status: BackendAuthStatusUnattributed, reason: ReasonBackendAttributionMissing}]++
			continue
		}
		rawStatus, ok := backendStrata[backend]
		if !ok || strings.TrimSpace(rawStatus) == "" {
			byKey[stratumKey{backend: backend, status: BackendAuthStatusUnattributed, reason: ReasonBackendStatusMissing}]++
			continue
		}
		byKey[stratumKey{backend: backend, status: normalizeBackendAuthStatus(rawStatus)}]++
	}
	keys := make([]stratumKey, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := keys[i], keys[j]
		if backendAuthStatusRank(left.status) != backendAuthStatusRank(right.status) {
			return backendAuthStatusRank(left.status) < backendAuthStatusRank(right.status)
		}
		if left.backend != right.backend {
			return left.backend < right.backend
		}
		return left.reason < right.reason
	})
	strata := make([]PendingVerificationStratum, 0, len(keys))
	for _, key := range keys {
		strata = append(strata, PendingVerificationStratum{
			Backend:           key.backend,
			BackendAuthStatus: key.status,
			Count:             byKey[key],
			Reason:            key.reason,
		})
	}
	return strata
}

func backendAuthStatusRank(status string) int {
	switch status {
	case BackendAuthStatusAuthenticated:
		return 0
	case BackendAuthStatusInstalledAuthUnknown:
		return 1
	case BackendAuthStatusFailed:
		return 2
	case BackendAuthStatusUnattributed:
		return 3
	default:
		return 4
	}
}

func normalizeBackendAuthStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "ready", "authenticated", "ok":
		return BackendAuthStatusAuthenticated
	case "installed_auth_unknown", "auth_unknown", "installed":
		return BackendAuthStatusInstalledAuthUnknown
	default:
		return BackendAuthStatusFailed
	}
}

func operationalEnvelopeMetrics(records []ledger.Record, ledgerLoaded bool) OperationalEnvelopeMetrics {
	if !ledgerLoaded {
		missing := CountWithReason{Reason: ReasonLedgerMissing}
		return OperationalEnvelopeMetrics{
			EmittedMissingGoalQuestions: missing,
			Promotions:                  missing,
		}
	}
	var metrics OperationalEnvelopeMetrics
	oeQuestionIDs := map[string]bool{}
	genericQuestionIDs := map[string]bool{}
	for _, record := range records {
		if record.EventKind != ledger.EventKindQuestion {
			continue
		}
		event, err := decodeLedgerEvent[ledger.QuestionEvent](record)
		if err != nil || strings.TrimSpace(event.QuestionID) == "" {
			continue
		}
		if isOperationalEnvelopeQuestion(event) {
			metrics.EmittedMissingGoalQuestions.Count++
			oeQuestionIDs[event.QuestionID] = true
		} else {
			genericQuestionIDs[event.QuestionID] = true
		}
	}
	genericQuestionCount := len(genericQuestionIDs)
	genericPromotionCount := 0
	for _, record := range records {
		if record.EventKind != ledger.EventKindPromotion {
			continue
		}
		event, err := decodeLedgerEvent[ledger.PromotionEvent](record)
		if err != nil {
			continue
		}
		if oeQuestionIDs[event.QuestionID] {
			metrics.Promotions.Count++
		} else if genericQuestionIDs[event.QuestionID] {
			genericPromotionCount++
		}
	}
	if genericQuestionCount > 0 {
		metrics.GenericMissingGoalQuestions = &CountWithReason{Count: genericQuestionCount}
	}
	if genericPromotionCount > 0 {
		metrics.GenericPromotions = &CountWithReason{Count: genericPromotionCount}
	}
	return metrics
}

func isOperationalEnvelopeQuestion(event ledger.QuestionEvent) bool {
	return strings.TrimSpace(event.Dimension) != "" && event.AnchorIndex != nil
}

func verdictMetrics(results []runResultInput) VerdictMetrics {
	reason := ""
	if len(results) == 0 {
		reason = ReasonRunResultsMissing
	}
	metrics := emptyVerdictMetrics(reason)
	byClass := map[string]int{}
	for index := range metrics.ByVerdictClass {
		byClass[metrics.ByVerdictClass[index].VerdictClass] = index
	}
	for _, input := range results {
		for _, finding := range input.result.Findings {
			class := verdictClassValue(finding.VerdictClass)
			rowIndex, ok := byClass[class]
			if !ok {
				metrics.ByVerdictClass = append(metrics.ByVerdictClass, VerdictClassCount{VerdictClass: class})
				rowIndex = len(metrics.ByVerdictClass) - 1
				byClass[class] = rowIndex
			}
			row := &metrics.ByVerdictClass[rowIndex]
			switch findingMetricStatus(finding) {
			case MetricStatusReceiptBasedContradiction:
				metrics.ReceiptBasedContradictions++
				row.ReceiptBasedContradictions++
			case MetricStatusUnattributedContradiction:
				if metrics.UnattributedContradictions == nil {
					metrics.UnattributedContradictions = &CountWithReason{Reason: ReasonReceiptLineageMissing}
				}
				metrics.UnattributedContradictions.Count++
				row.UnattributedContradictions++
			case MetricStatusInvalidResult:
				metrics.InvalidResult++
				row.InvalidResult++
			case contracts.VerdictSurvived:
				metrics.Survived++
				row.Survived++
			case contracts.VerdictWeakened:
				metrics.Weakened++
				row.Weakened++
			case contracts.VerdictBroken:
				metrics.Broken++
				row.Broken++
			}
		}
	}
	sort.SliceStable(metrics.ByVerdictClass, func(i, j int) bool {
		return verdictClassRank(metrics.ByVerdictClass[i].VerdictClass) < verdictClassRank(metrics.ByVerdictClass[j].VerdictClass)
	})
	return metrics
}

func emptyVerdictMetrics(reason string) VerdictMetrics {
	metrics := VerdictMetrics{
		ByVerdictClass: make([]VerdictClassCount, 0, len(verdictClasses)),
	}
	for _, class := range verdictClasses {
		metrics.ByVerdictClass = append(metrics.ByVerdictClass, VerdictClassCount{
			VerdictClass: class,
			Reason:       reason,
		})
	}
	return metrics
}

func findingMetricStatus(finding adjudicate.FindingVerdict) string {
	if hasReason(finding.Reasons, adjudicate.ReasonExecutionReceiptContradicted) ||
		(finding.Execution != nil && finding.Execution.VerificationClassification == "contradictory") {
		if !hasReceiptLineage(finding.Execution) {
			return MetricStatusUnattributedContradiction
		}
		return MetricStatusReceiptBasedContradiction
	}
	if finding.Relay != nil {
		if finding.Relay.Status == contracts.RecordStatusFailed ||
			hasReason(finding.Reasons, adjudicate.ReasonRelayVerificationInvalid) {
			return MetricStatusInvalidResult
		}
		if finding.Relay.Status == contracts.RecordStatusValid {
			return finding.Relay.Verdict
		}
	}
	return ""
}

func hasReceiptLineage(execution *adjudicate.ExecutionMetadata) bool {
	return execution != nil &&
		strings.TrimSpace(execution.ReceiptID) != "" &&
		strings.TrimSpace(execution.ReceiptDigest) != ""
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func verdictClassValue(value *string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return VerdictClassNone
	}
	return *value
}

func verdictClassRank(value string) int {
	for index, class := range verdictClasses {
		if value == class {
			return index
		}
	}
	return len(verdictClasses)
}

func capReleaseMetrics(results []runResultInput, records []ledger.Record, ledgerLoaded bool) CapReleaseMetrics {
	metrics := CapReleaseMetrics{}
	if len(results) == 0 {
		metrics.RunResultMismatchCount.Reason = ReasonRunResultsMissing
	}
	for _, input := range results {
		if input.result.CapReleaseCharterMismatch {
			metrics.RunResultMismatchCount.Count++
		}
	}
	if !ledgerLoaded {
		metrics.LedgerEventMismatchCount.Reason = ReasonLedgerMissing
	} else {
		for _, record := range records {
			switch record.EventKind {
			case ledger.EventKindAdjudicationRun:
				event, err := decodeLedgerEvent[ledger.AdjudicationRunEvent](record)
				if err == nil && event.CapReleaseCharterMismatch {
					metrics.LedgerEventMismatchCount.Count++
				}
			case ledger.EventKindPolicyDecision:
				event, err := decodeLedgerEvent[ledger.PolicyDecisionEvent](record)
				if err == nil && event.CapReleaseCharterMismatch {
					metrics.LedgerEventMismatchCount.Count++
				}
			}
		}
	}
	metrics.CharterMismatchCount = metrics.RunResultMismatchCount.Count + metrics.LedgerEventMismatchCount.Count
	return metrics
}

type findingEstimate struct {
	production componentEstimate
	test       componentEstimate
}

type componentEstimate struct {
	present      bool
	known        bool
	lines        int
	linesPresent bool
	files        int
	filesPresent bool
}

func deltaComparisonMetrics(records []ledger.Record, ledgerLoaded bool) DeltaComparisonMetrics {
	metrics := DeltaComparisonMetrics{}
	if !ledgerLoaded {
		metrics.Reason = ReasonLedgerMissing
		return metrics
	}
	estimates := map[string]findingEstimate{}
	measured := map[string]ledger.MeasuredDeltaEvent{}
	for _, record := range records {
		switch record.EventKind {
		case ledger.EventKindFinding:
			event, err := decodeLedgerEvent[ledger.FindingEvent](record)
			if err == nil && event.FindingID != "" {
				estimate, ok := estimateFromFindingPayload(event.Finding)
				if ok {
					estimates[event.FindingID] = estimate
				}
			}
		case ledger.EventKindMeasuredDelta:
			event, err := decodeLedgerEvent[ledger.MeasuredDeltaEvent](record)
			if err == nil && event.FindingID != "" {
				measured[event.FindingID] = event
			}
		}
	}
	findingIDs := map[string]struct{}{}
	for findingID := range estimates {
		findingIDs[findingID] = struct{}{}
	}
	for findingID := range measured {
		findingIDs[findingID] = struct{}{}
	}
	orderedFindingIDs := make([]string, 0, len(findingIDs))
	for findingID := range findingIDs {
		orderedFindingIDs = append(orderedFindingIDs, findingID)
	}
	sort.Strings(orderedFindingIDs)
	for _, findingID := range orderedFindingIDs {
		estimate, estimatePresent := estimates[findingID]
		measuredDelta, measuredPresent := measured[findingID]
		if reasons := deltaPairExclusionReasons(estimate, estimatePresent, measuredDelta, measuredPresent); len(reasons) > 0 {
			metrics.ExcludedFindings++
			addDeltaExclusionReasons(&metrics, reasons)
			continue
		}
		metrics.PairedFindings++
		compareComponent(&metrics.Production, estimate.production, measuredDelta.Production, measuredDelta.Unit)
		compareComponent(&metrics.Test, estimate.test, measuredDelta.Test, measuredDelta.Unit)
	}
	if metrics.PairedFindings == 0 {
		metrics.Reason = ReasonNoPairedEstimatedAndMeasuredDeltas
	}
	return metrics
}

func deltaPairExclusionReasons(estimate findingEstimate, estimatePresent bool, measured ledger.MeasuredDeltaEvent, measuredPresent bool) []string {
	var reasons []string
	if !measuredPresent {
		return []string{ReasonMeasuredDeltaMissing}
	}
	if !estimatePresent {
		reasons = append(reasons, ReasonEstimatedDeltaMissing)
	} else {
		if !estimate.production.present {
			reasons = append(reasons, ReasonEstimatedProductionMissing)
		} else if estimate.production.known && !estimate.production.valuePresent(measured.Unit) {
			reasons = append(reasons, ReasonEstimatedProductionUnitMissing)
		}
		if !estimate.test.present {
			reasons = append(reasons, ReasonEstimatedTestMissing)
		} else if estimate.test.known && !estimate.test.valuePresent(measured.Unit) {
			reasons = append(reasons, ReasonEstimatedTestUnitMissing)
		}
	}
	if measured.Production == nil {
		reasons = append(reasons, ReasonMeasuredProductionMissing)
	}
	if measured.Test == nil {
		reasons = append(reasons, ReasonMeasuredTestMissing)
	}
	return reasons
}

func addDeltaExclusionReasons(metrics *DeltaComparisonMetrics, reasons []string) {
	byReason := map[string]int{}
	for index, stratum := range metrics.ExcludedStrata {
		byReason[stratum.Reason] = index
	}
	for _, reason := range reasons {
		if index, ok := byReason[reason]; ok {
			metrics.ExcludedStrata[index].Count++
			continue
		}
		metrics.ExcludedStrata = append(metrics.ExcludedStrata, DeltaExclusionStratum{Reason: reason, Count: 1})
		byReason[reason] = len(metrics.ExcludedStrata) - 1
	}
	sort.SliceStable(metrics.ExcludedStrata, func(i, j int) bool {
		return metrics.ExcludedStrata[i].Reason < metrics.ExcludedStrata[j].Reason
	})
}

func compareComponent(metrics *DeltaComponentMetrics, estimate componentEstimate, measured *int, unit string) {
	if measured == nil {
		return
	}
	if !estimate.present {
		metrics.EstimateMissing++
		return
	}
	if !estimate.known {
		metrics.EstimateUnknown++
		return
	}
	value := estimate.lines
	if strings.TrimSpace(unit) == ledger.UnitFiles {
		value = estimate.files
	}
	switch {
	case value == *measured:
		metrics.Equal++
	case value > *measured:
		metrics.OverEstimate++
	default:
		metrics.UnderEstimate++
	}
}

func (estimate componentEstimate) valuePresent(unit string) bool {
	if strings.TrimSpace(unit) == ledger.UnitFiles {
		return estimate.filesPresent
	}
	return estimate.linesPresent
}

func estimateFromFindingPayload(payload map[string]any) (findingEstimate, bool) {
	raw, ok := payload["estimated_delta"]
	if !ok {
		return findingEstimate{}, false
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return findingEstimate{}, false
	}
	return findingEstimate{
		production: componentEstimateFromObject(object["production"]),
		test:       componentEstimateFromObject(object["test"]),
	}, true
}

func componentEstimateFromObject(raw any) componentEstimate {
	object, ok := raw.(map[string]any)
	if !ok {
		return componentEstimate{}
	}
	status, _ := object["status"].(string)
	estimate := componentEstimate{present: true, known: status == contracts.DeltaStatusKnown}
	if value, ok := intValue(object["lines"]); ok {
		estimate.lines = value
		estimate.linesPresent = true
	}
	if value, ok := intValue(object["files"]); ok {
		estimate.files = value
		estimate.filesPresent = true
	}
	return estimate
}

func intValue(raw any) (int, bool) {
	switch value := raw.(type) {
	case json.Number:
		parsed, err := value.Int64()
		return int(parsed), err == nil
	case float64:
		return int(value), value == float64(int(value))
	case int:
		return value, true
	case int64:
		return int(value), true
	default:
		return 0, false
	}
}

func decodeLedgerEvent[T any](record ledger.Record) (T, error) {
	return strictjson.DecodeBytes[T](record.Event, strictjson.DefaultMaxBytes*8)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
