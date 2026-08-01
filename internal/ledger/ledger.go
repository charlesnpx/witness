package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

const (
	RecordSchemaVersion = "witness-ledger-record-v1"
	ShowSchemaVersion   = "witness-ledger-show-v1"

	UnitLines = "lines"
	UnitFiles = "files"

	EventKindAdjudicationRun     = "adjudication_run"
	EventKindFinding             = "finding"
	EventKindVerdict             = "verdict"
	EventKindQuestion            = "question"
	EventKindPendingVerification = "pending_verification"
	EventKindOwnerOverride       = "owner_override"
	EventKindCapRelease          = "cap_release"
	EventKindMeasuredDelta       = "measured_delta"
	EventKindPolicyDecision      = "policy_decision"
	EventKindPromotion           = "promotion"
	EventKindAcceptUnverified    = "accept_unverified"

	CodeInvalidLedger      = "invalid_ledger"
	CodeInvalidLedgerEvent = "invalid_ledger_event"
	CodeLedgerTamper       = "ledger_tamper"
	CodeDuplicateRunDigest = "duplicate_run_digest"
	CodeFileIO             = "file_io"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Record struct {
	SchemaVersion  string          `json:"schema_version"`
	Sequence       int             `json:"sequence"`
	PreviousDigest string          `json:"previous_digest,omitempty"`
	EventKind      string          `json:"event_kind"`
	Event          json.RawMessage `json:"event"`
	Digest         string          `json:"digest"`
}

type EventToAppend struct {
	Kind    string
	Payload any
}

type AdjudicationRunEvent struct {
	RunDigest                 string `json:"run_digest"`
	ResultSchemaVersion       string `json:"result_schema_version"`
	PolicyID                  string `json:"policy_id"`
	PolicyDigest              string `json:"policy_digest"`
	RulesDigest               string `json:"rules_digest"`
	CharterHash               string `json:"charter_hash"`
	ArtifactDigest            string `json:"artifact_digest"`
	ManifestDigest            string `json:"manifest_digest"`
	CapReleaseCharterMismatch bool   `json:"cap_release_charter_mismatch"`
	FindingCount              int    `json:"finding_count"`
	PendingVerificationCount  int    `json:"pending_verification_count"`
	AutomaticCandidateCount   int    `json:"automatic_candidate_count"`
	CallerDecisionCount       int    `json:"caller_decision_count"`
	PolicyDecisionRecordCount int    `json:"policy_decision_record_count"`
	MissingGoalQuestionCount  int    `json:"missing_goal_question_count"`
}

type FindingEvent struct {
	FindingID      string         `json:"finding_id"`
	FindingKey     string         `json:"finding_key"`
	WitnessDigest  string         `json:"witness_digest"`
	CharterHash    string         `json:"charter_hash"`
	ArtifactDigest string         `json:"artifact_digest"`
	Finding        map[string]any `json:"finding,omitempty"`
}

type VerdictEvent struct {
	RunDigest         string   `json:"run_digest"`
	FindingID         string   `json:"finding_id"`
	Role              string   `json:"role"`
	Kind              string   `json:"kind"`
	Disposition       string   `json:"disposition"`
	ApplicationClass  string   `json:"application_class"`
	ClaimedSeverity   string   `json:"claimed_severity"`
	EffectiveSeverity string   `json:"effective_severity,omitempty"`
	SeverityCap       string   `json:"severity_cap,omitempty"`
	Reasons           []string `json:"reasons,omitempty"`
	FindingDigest     string   `json:"finding_digest,omitempty"`
	WitnessDigest     string   `json:"witness_digest,omitempty"`
	VerdictClass      *string  `json:"verdict_class"`
}

type QuestionEvent struct {
	RunDigest  string `json:"run_digest,omitempty"`
	QuestionID string `json:"question_id"`
	// FindingID is optional for questions that originate from envelope anchors rather than a filed finding.
	FindingID        string `json:"finding_id,omitempty"`
	Dimension        string `json:"dimension,omitempty"`
	AnchorIndex      *int   `json:"anchor_index,omitempty"`
	Property         string `json:"property,omitempty"`
	Value            string `json:"value,omitempty"`
	AffectedDecision string `json:"affected_decision,omitempty"`
	CharterHash      string `json:"charter_hash"`
	Statement        string `json:"statement"`
}

type PendingVerificationEvent struct {
	RunDigest      string `json:"run_digest,omitempty"`
	FindingID      string `json:"finding_id"`
	VerificationID string `json:"verification_id"`
	Status         string `json:"status"`
}

type OwnerOverrideEvent struct {
	FindingID  string `json:"finding_id"`
	Actor      string `json:"actor"`
	Rationale  string `json:"rationale"`
	OverrideID string `json:"override_id,omitempty"`
}

type CapReleaseEvent struct {
	Release contracts.CapReleaseRecord `json:"release"`
}

type MeasuredDeltaEvent struct {
	Production *int   `json:"production"`
	Test       *int   `json:"test"`
	Unit       string `json:"unit"`
	FindingID  string `json:"finding_id,omitempty"`
}

type PolicyDecisionEvent struct {
	RunDigest                  string   `json:"run_digest,omitempty"`
	Allow                      *bool    `json:"allow"`
	Reasons                    []string `json:"reasons"`
	PolicyID                   string   `json:"policy_id"`
	PolicyDigest               string   `json:"policy_digest"`
	RulesDigest                string   `json:"rules_digest"`
	CharterHash                string   `json:"charter_hash,omitempty"`
	CapReleaseCharterMismatch  bool     `json:"cap_release_charter_mismatch"`
	CapReleaseUnit             string   `json:"cap_release_unit,omitempty"`
	Unit                       string   `json:"unit,omitempty"`
	PositiveCapAllowanceUsed   bool     `json:"positive_cap_allowance_used"`
	DecisionID                 string   `json:"decision_id,omitempty"`
	FindingID                  string   `json:"finding_id,omitempty"`
	ApplicationClass           string   `json:"application_class,omitempty"`
	OperationalEnvelopePresent bool     `json:"operational_envelope_present"`
}

type PromotionEvent struct {
	QuestionID string `json:"question_id"`
	GoalRef    string `json:"goal_ref"`
	Actor      string `json:"actor"`
	Rationale  string `json:"rationale"`
}

type AcceptUnverifiedEvent struct {
	FindingID             string `json:"finding_id"`
	PendingVerificationID string `json:"pending_verification_id"`
	Actor                 string `json:"actor"`
	Rationale             string `json:"rationale"`
}

type ShowOptions struct {
	Kinds []string
}

type ShowDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Records       []RecordView `json:"records"`
}

type RecordView struct {
	SchemaVersion  string `json:"schema_version"`
	Sequence       int    `json:"sequence"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	EventKind      string `json:"event_kind"`
	Event          any    `json:"event"`
	Digest         string `json:"digest"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "ledger validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func ReadFile(path string) ([]Record, error) {
	if strings.TrimSpace(path) == "" {
		return nil, diag.New(CodeInvalidLedger, "ledger path is required.")
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fileError(err, path, "open ledger")
	}
	defer file.Close()
	records, err := strictjson.DecodeJSONL[Record](file, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecords(records); err != nil {
		return nil, err
	}
	return records, nil
}

func ValidateRecords(records []Record) error {
	var diagnostics []diag.Diagnostic
	previous := ""
	for index, record := range records {
		path := fmt.Sprintf("/records/%d", index)
		if record.SchemaVersion != RecordSchemaVersion {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedger, "ledger record schema_version is unsupported.", path+"/schema_version", map[string]any{"expected": RecordSchemaVersion, "actual": record.SchemaVersion}))
		}
		expectedSequence := index + 1
		if record.Sequence != expectedSequence {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedger, "ledger record sequence must be contiguous.", path+"/sequence", map[string]any{"expected": expectedSequence, "actual": record.Sequence}))
		}
		if record.PreviousDigest != previous {
			diagnostics = append(diagnostics, diagnostic(CodeLedgerTamper, "ledger record previous_digest does not match the prior record digest.", path+"/previous_digest", map[string]any{"expected": previous, "actual": record.PreviousDigest}))
		}
		diagnostics = append(diagnostics, validateEvent(record.EventKind, record.Event, path+"/event")...)
		actualDigest, err := recordDigest(record)
		if err != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedger, "ledger record digest could not be computed.", path, map[string]any{"error": err.Error()}))
		} else if record.Digest != actualDigest {
			diagnostics = append(diagnostics, diagnostic(CodeLedgerTamper, "ledger record digest does not match its canonical content.", path+"/digest", map[string]any{"expected": actualDigest, "actual": record.Digest}))
		}
		previous = record.Digest
	}
	if len(diagnostics) > 0 {
		return &ValidationError{Diagnostics: diagnostics}
	}
	return nil
}

// AppendEvent performs an un-serialized read-modify-append and requires a
// single writer per ledger path. Witness is a single-pass CLI; concurrent
// writers are unsupported and would corrupt the hash chain.
func AppendEvent(path string, kind string, payload any) (Record, error) {
	records, err := AppendEvents(path, []EventToAppend{{Kind: kind, Payload: payload}})
	if err != nil {
		return Record{}, err
	}
	return records[0], nil
}

// AppendEvents performs an un-serialized read-modify-append and requires a
// single writer per ledger path. Witness is a single-pass CLI; concurrent
// writers are unsupported and would corrupt the hash chain.
func AppendEvents(path string, events []EventToAppend) ([]Record, error) {
	if strings.TrimSpace(path) == "" {
		return nil, diag.New(CodeInvalidLedger, "ledger path is required.")
	}
	existing, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	previous := ""
	sequence := 0
	if len(existing) > 0 {
		last := existing[len(existing)-1]
		previous = last.Digest
		sequence = last.Sequence
	}
	appended := make([]Record, 0, len(events))
	for _, event := range events {
		raw, err := canonicalRaw(event.Payload)
		if err != nil {
			return nil, err
		}
		if diagnostics := validateEvent(event.Kind, raw, "/event"); len(diagnostics) > 0 {
			return nil, &ValidationError{Diagnostics: diagnostics}
		}
		record := Record{
			SchemaVersion:  RecordSchemaVersion,
			Sequence:       sequence + 1,
			PreviousDigest: previous,
			EventKind:      event.Kind,
			Event:          raw,
		}
		recordDigest, err := recordDigest(record)
		if err != nil {
			return nil, err
		}
		record.Digest = recordDigest
		appended = append(appended, record)
		previous = record.Digest
		sequence = record.Sequence
	}
	if len(appended) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fileError(err, path, "create ledger directory")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fileError(err, path, "append ledger")
	}
	defer file.Close()
	for _, record := range appended {
		encoded, err := marshalRecord(record)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			return nil, fileError(err, path, "write ledger")
		}
	}
	return appended, nil
}

func Show(path string, options ShowOptions) (ShowDocument, error) {
	records, err := ReadFile(path)
	if err != nil {
		return ShowDocument{}, err
	}
	filter := map[string]bool{}
	for _, kind := range options.Kinds {
		if strings.TrimSpace(kind) != "" {
			filter[strings.TrimSpace(kind)] = true
		}
	}
	document := ShowDocument{SchemaVersion: ShowSchemaVersion}
	for _, record := range records {
		if len(filter) > 0 && !filter[record.EventKind] {
			continue
		}
		event, err := strictjson.DecodeAnyBytes(record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return ShowDocument{}, err
		}
		document.Records = append(document.Records, RecordView{
			SchemaVersion:  record.SchemaVersion,
			Sequence:       record.Sequence,
			PreviousDigest: record.PreviousDigest,
			EventKind:      record.EventKind,
			Event:          event,
			Digest:         record.Digest,
		})
	}
	return document, nil
}

func CapReleases(records []Record) ([]contracts.CapReleaseRecord, error) {
	releases := make([]contracts.CapReleaseRecord, 0)
	for _, record := range records {
		if record.EventKind != EventKindCapRelease {
			continue
		}
		event, err := strictjson.DecodeBytes[CapReleaseEvent](record.Event, strictjson.DefaultMaxBytes)
		if err != nil {
			return nil, err
		}
		releases = append(releases, event.Release)
	}
	return releases, nil
}

func ContainsRunDigest(records []Record, runDigest string) (bool, error) {
	if strings.TrimSpace(runDigest) == "" {
		return false, nil
	}
	for _, record := range records {
		digest, err := runDigestForRecord(record)
		if err != nil {
			return false, err
		}
		if digest == runDigest {
			return true, nil
		}
	}
	return false, nil
}

func DuplicateRunDigestError(runDigest string) error {
	return diag.New(
		CodeDuplicateRunDigest,
		"adjudication run digest already exists in the append-only ledger.",
		diag.WithDetail("run_digest", runDigest),
	)
}

func BoolPtr(value bool) *bool {
	return &value
}

func IntPtr(value int) *int {
	return &value
}

type digestPayload struct {
	SchemaVersion  string `json:"schema_version"`
	Sequence       int    `json:"sequence"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	EventKind      string `json:"event_kind"`
	Event          any    `json:"event"`
}

func recordDigest(record Record) (string, error) {
	event, err := strictjson.DecodeAnyBytes(record.Event, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return "", err
	}
	return digest.SemanticJSON(digestPayload{
		SchemaVersion:  record.SchemaVersion,
		Sequence:       record.Sequence,
		PreviousDigest: record.PreviousDigest,
		EventKind:      record.EventKind,
		Event:          event,
	})
}

func canonicalRaw(value any) (json.RawMessage, error) {
	encoded, err := canonjson.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), encoded...), nil
}

func marshalRecord(record Record) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func runDigestForRecord(record Record) (string, error) {
	switch record.EventKind {
	case EventKindAdjudicationRun:
		event, err := strictjson.DecodeBytes[AdjudicationRunEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case EventKindVerdict:
		event, err := strictjson.DecodeBytes[VerdictEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case EventKindQuestion:
		event, err := strictjson.DecodeBytes[QuestionEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case EventKindPendingVerification:
		event, err := strictjson.DecodeBytes[PendingVerificationEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	case EventKindPolicyDecision:
		event, err := strictjson.DecodeBytes[PolicyDecisionEvent](record.Event, strictjson.DefaultMaxBytes*8)
		if err != nil {
			return "", err
		}
		return event.RunDigest, nil
	default:
		return "", nil
	}
}

func validateEvent(kind string, raw json.RawMessage, path string) []diag.Diagnostic {
	if len(raw) == 0 {
		return []diag.Diagnostic{diagnostic(CodeInvalidLedgerEvent, "ledger event payload is required.", path, nil)}
	}
	switch kind {
	case EventKindAdjudicationRun:
		event, diagnostics := decodePayload[AdjudicationRunEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireDigest(&diagnostics, path+"/run_digest", "run_digest", event.RunDigest)
		requireString(&diagnostics, path+"/result_schema_version", "result_schema_version", event.ResultSchemaVersion)
		requireString(&diagnostics, path+"/policy_id", "policy_id", event.PolicyID)
		requireDigest(&diagnostics, path+"/policy_digest", "policy_digest", event.PolicyDigest)
		requireDigest(&diagnostics, path+"/rules_digest", "rules_digest", event.RulesDigest)
		requireDigest(&diagnostics, path+"/charter_hash", "charter_hash", event.CharterHash)
		requireDigest(&diagnostics, path+"/artifact_digest", "artifact_digest", event.ArtifactDigest)
		requireDigest(&diagnostics, path+"/manifest_digest", "manifest_digest", event.ManifestDigest)
		return diagnostics
	case EventKindFinding:
		event, diagnostics := decodePayload[FindingEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireString(&diagnostics, path+"/finding_id", "finding_id", event.FindingID)
		requireString(&diagnostics, path+"/finding_key", "finding_key", event.FindingKey)
		requireDigest(&diagnostics, path+"/witness_digest", "witness_digest", event.WitnessDigest)
		requireDigest(&diagnostics, path+"/charter_hash", "charter_hash", event.CharterHash)
		requireDigest(&diagnostics, path+"/artifact_digest", "artifact_digest", event.ArtifactDigest)
		return diagnostics
	case EventKindVerdict:
		event, diagnostics := decodePayload[VerdictEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireDigest(&diagnostics, path+"/run_digest", "run_digest", event.RunDigest)
		requireString(&diagnostics, path+"/finding_id", "finding_id", event.FindingID)
		requireString(&diagnostics, path+"/role", "role", event.Role)
		requireString(&diagnostics, path+"/kind", "kind", event.Kind)
		requireString(&diagnostics, path+"/disposition", "disposition", event.Disposition)
		requireString(&diagnostics, path+"/application_class", "application_class", event.ApplicationClass)
		requireString(&diagnostics, path+"/claimed_severity", "claimed_severity", event.ClaimedSeverity)
		if event.FindingDigest != "" {
			requireDigest(&diagnostics, path+"/finding_digest", "finding_digest", event.FindingDigest)
		}
		if event.WitnessDigest != "" {
			requireDigest(&diagnostics, path+"/witness_digest", "witness_digest", event.WitnessDigest)
		}
		return diagnostics
	case EventKindQuestion:
		event, diagnostics := decodePayload[QuestionEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		if event.RunDigest != "" {
			requireDigest(&diagnostics, path+"/run_digest", "run_digest", event.RunDigest)
		}
		requireString(&diagnostics, path+"/question_id", "question_id", event.QuestionID)
		if event.AnchorIndex != nil && *event.AnchorIndex < 0 {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedgerEvent, "question anchor_index must identify the originating anchor.", path+"/anchor_index", map[string]any{"anchor_index": *event.AnchorIndex}))
		}
		requireDigest(&diagnostics, path+"/charter_hash", "charter_hash", event.CharterHash)
		requireString(&diagnostics, path+"/statement", "statement", event.Statement)
		return diagnostics
	case EventKindPendingVerification:
		event, diagnostics := decodePayload[PendingVerificationEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		if event.RunDigest != "" {
			requireDigest(&diagnostics, path+"/run_digest", "run_digest", event.RunDigest)
		}
		requireString(&diagnostics, path+"/finding_id", "finding_id", event.FindingID)
		requireString(&diagnostics, path+"/verification_id", "verification_id", event.VerificationID)
		requireString(&diagnostics, path+"/status", "status", event.Status)
		return diagnostics
	case EventKindOwnerOverride:
		event, diagnostics := decodePayload[OwnerOverrideEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireString(&diagnostics, path+"/finding_id", "finding_id", event.FindingID)
		requireString(&diagnostics, path+"/actor", "actor", event.Actor)
		requireString(&diagnostics, path+"/rationale", "rationale", event.Rationale)
		return diagnostics
	case EventKindCapRelease:
		event, diagnostics := decodePayload[CapReleaseEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		validateCapRelease(&diagnostics, path+"/release", event.Release)
		return diagnostics
	case EventKindMeasuredDelta:
		event, diagnostics := decodePayload[MeasuredDeltaEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		if event.Production == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedgerEvent, "measured_delta production is required.", path+"/production", nil))
		}
		if event.Test == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedgerEvent, "measured_delta test is required.", path+"/test", nil))
		}
		requireUnit(&diagnostics, path+"/unit", "unit", event.Unit)
		return diagnostics
	case EventKindPolicyDecision:
		event, diagnostics := decodePayload[PolicyDecisionEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		if event.RunDigest != "" {
			requireDigest(&diagnostics, path+"/run_digest", "run_digest", event.RunDigest)
		}
		if event.Allow == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidLedgerEvent, "policy_decision allow is required.", path+"/allow", nil))
		}
		requireReasons(&diagnostics, path+"/reasons", event.Reasons)
		requireString(&diagnostics, path+"/policy_id", "policy_id", event.PolicyID)
		requireDigest(&diagnostics, path+"/policy_digest", "policy_digest", event.PolicyDigest)
		requireDigest(&diagnostics, path+"/rules_digest", "rules_digest", event.RulesDigest)
		if event.CharterHash != "" {
			requireDigest(&diagnostics, path+"/charter_hash", "charter_hash", event.CharterHash)
		}
		if event.CapReleaseUnit != "" {
			requireUnit(&diagnostics, path+"/cap_release_unit", "cap_release_unit", event.CapReleaseUnit)
		}
		if event.Unit != "" {
			requireUnit(&diagnostics, path+"/unit", "unit", event.Unit)
		}
		return diagnostics
	case EventKindPromotion:
		event, diagnostics := decodePayload[PromotionEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireString(&diagnostics, path+"/question_id", "question_id", event.QuestionID)
		requireString(&diagnostics, path+"/goal_ref", "goal_ref", event.GoalRef)
		requireString(&diagnostics, path+"/actor", "actor", event.Actor)
		requireString(&diagnostics, path+"/rationale", "rationale", event.Rationale)
		return diagnostics
	case EventKindAcceptUnverified:
		event, diagnostics := decodePayload[AcceptUnverifiedEvent](raw, path)
		if len(diagnostics) > 0 {
			return diagnostics
		}
		requireString(&diagnostics, path+"/finding_id", "finding_id", event.FindingID)
		requireString(&diagnostics, path+"/pending_verification_id", "pending_verification_id", event.PendingVerificationID)
		requireString(&diagnostics, path+"/actor", "actor", event.Actor)
		requireString(&diagnostics, path+"/rationale", "rationale", event.Rationale)
		return diagnostics
	default:
		return []diag.Diagnostic{diagnostic(CodeInvalidLedgerEvent, "ledger event kind is unsupported.", path, map[string]any{"event_kind": kind})}
	}
}

func decodePayload[T any](raw json.RawMessage, path string) (T, []diag.Diagnostic) {
	event, err := strictjson.DecodeBytes[T](raw, strictjson.DefaultMaxBytes*8)
	if err != nil {
		diagnostic := diag.FromError(err)
		if diagnostic.Path == "" {
			diagnostic.Path = path
		}
		var zero T
		return zero, []diag.Diagnostic{diagnostic}
	}
	return event, nil
}

func validateCapRelease(diagnostics *[]diag.Diagnostic, path string, release contracts.CapReleaseRecord) {
	requireUnit(diagnostics, path+"/unit", "unit", release.Unit)
	if release.ProductionCap <= 0 {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "cap release production_cap must be positive.", path+"/production_cap", map[string]any{"value": release.ProductionCap}))
	}
	if release.TestCap <= 0 {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "cap release test_cap must be positive.", path+"/test_cap", map[string]any{"value": release.TestCap}))
	}
	requireEnum(diagnostics, path+"/basis", "basis", release.Basis, []string{contracts.CapReleaseBasisMeasuredHistory, contracts.CapReleaseBasisOwnerJudgment})
	if strings.TrimSpace(release.Evidence) == "" && strings.TrimSpace(release.Rationale) == "" {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "cap release requires evidence or rationale.", path, nil))
	}
	requireString(diagnostics, path+"/actor", "actor", release.Actor)
	requireDigest(diagnostics, path+"/policy_digest", "policy_digest", release.PolicyDigest)
	requireDigest(diagnostics, path+"/rules_digest", "rules_digest", release.RulesDigest)
	requireDigest(diagnostics, path+"/charter_hash", "charter_hash", release.CharterHash)
}

func requireUnit(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	requireEnum(diagnostics, path, label, value, []string{UnitLines, UnitFiles})
}

func requireString(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if strings.TrimSpace(value) == "" {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, label+" is required.", path, nil))
	}
}

func requireReasons(diagnostics *[]diag.Diagnostic, path string, values []string) {
	if len(values) == 0 {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "policy_decision reasons are required.", path, nil))
		return
	}
	for index, value := range values {
		if strings.TrimSpace(value) == "" {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "policy_decision reason must not be empty.", fmt.Sprintf("%s/%d", path, index), nil))
		}
	}
}

func requireDigest(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if !digestPattern.MatchString(value) {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, label+" must be a sha256 digest.", path, map[string]any{"value": value}))
	}
}

func requireEnum(diagnostics *[]diag.Diagnostic, path string, label string, value string, allowed []string) {
	for _, allowedValue := range allowed {
		if value == allowedValue {
			return
		}
	}
	*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, label+" has an unsupported value.", path, map[string]any{"value": value, "allowed": allowed}))
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Message: message, Path: path, Details: details}
}

func fileError(err error, path string, action string) error {
	return diag.Wrap(
		err,
		CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", action),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}
