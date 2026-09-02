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
	"time"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
)

const (
	RecordSchemaVersion = "witness-ledger-record-v4"
	ShowSchemaVersion   = "witness-ledger-show-v4"

	EventKindAdjudicationRun     = "adjudication_run"
	EventKindFinding             = "finding"
	EventKindVerdict             = "verdict"
	EventKindQuestion            = "question"
	EventKindPendingVerification = "pending_verification"
	EventKindOwnerOverride       = "owner_override"
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
	RunDigest                string `json:"run_digest"`
	ResultSchemaVersion      string `json:"result_schema_version"`
	DecisionRulesVersion     string `json:"decision_rules_version"`
	CharterHash              string `json:"charter_hash"`
	ArtifactDigest           string `json:"artifact_digest"`
	ManifestDigest           string `json:"manifest_digest"`
	FindingCount             int    `json:"finding_count"`
	PendingVerificationCount int    `json:"pending_verification_count"`
	MissingGoalQuestionCount int    `json:"missing_goal_question_count"`
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

type adjudicationRunEventJSON struct {
	RunDigest                string         `json:"run_digest"`
	ResultSchemaVersion      string         `json:"result_schema_version"`
	DecisionRulesVersion     string         `json:"decision_rules_version"`
	CharterHash              string         `json:"charter_hash"`
	ArtifactDigest           string         `json:"artifact_digest"`
	ManifestDigest           string         `json:"manifest_digest"`
	FindingCount             strictjson.Int `json:"finding_count"`
	PendingVerificationCount strictjson.Int `json:"pending_verification_count"`
	MissingGoalQuestionCount strictjson.Int `json:"missing_goal_question_count"`
}

type questionEventJSON struct {
	RunDigest        string          `json:"run_digest,omitempty"`
	QuestionID       string          `json:"question_id"`
	FindingID        string          `json:"finding_id,omitempty"`
	Dimension        string          `json:"dimension,omitempty"`
	AnchorIndex      *strictjson.Int `json:"anchor_index,omitempty"`
	Property         string          `json:"property,omitempty"`
	Value            string          `json:"value,omitempty"`
	AffectedDecision string          `json:"affected_decision,omitempty"`
	CharterHash      string          `json:"charter_hash"`
	Statement        string          `json:"statement"`
}

func (event *AdjudicationRunEvent) UnmarshalJSON(data []byte) error {
	decoded, err := strictjson.DecodeBytes[adjudicationRunEventJSON](data, int64(len(data)))
	if err != nil {
		return err
	}
	*event = AdjudicationRunEvent{
		RunDigest:                decoded.RunDigest,
		ResultSchemaVersion:      decoded.ResultSchemaVersion,
		DecisionRulesVersion:     decoded.DecisionRulesVersion,
		CharterHash:              decoded.CharterHash,
		ArtifactDigest:           decoded.ArtifactDigest,
		ManifestDigest:           decoded.ManifestDigest,
		FindingCount:             int(decoded.FindingCount),
		PendingVerificationCount: int(decoded.PendingVerificationCount),
		MissingGoalQuestionCount: int(decoded.MissingGoalQuestionCount),
	}
	return nil
}

func (event *QuestionEvent) UnmarshalJSON(data []byte) error {
	decoded, err := strictjson.DecodeBytes[questionEventJSON](data, int64(len(data)))
	if err != nil {
		return err
	}
	*event = QuestionEvent{
		RunDigest:        decoded.RunDigest,
		QuestionID:       decoded.QuestionID,
		FindingID:        decoded.FindingID,
		Dimension:        decoded.Dimension,
		AnchorIndex:      strictIntPointer(decoded.AnchorIndex),
		Property:         decoded.Property,
		Value:            decoded.Value,
		AffectedDecision: decoded.AffectedDecision,
		CharterHash:      decoded.CharterHash,
		Statement:        decoded.Statement,
	}
	return nil
}

func strictIntPointer(value *strictjson.Int) *int {
	if value == nil {
		return nil
	}
	converted := int(*value)
	return &converted
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
	data, err := readLedgerBytes(path)
	if err != nil {
		return nil, err
	}
	return decodeLedgerRecords(data)
}

func readLedgerBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fileError(err, path, "read ledger")
	}
	return data, nil
}

func decodeLedgerRecords(data []byte) ([]Record, error) {
	records, err := strictjson.DecodeJSONL[Record](bytes.NewReader(data), strictjson.DefaultMaxBytes*8)
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
	for index, record := range records {
		if record.SchemaVersion != RecordSchemaVersion {
			return &ValidationError{Diagnostics: []diag.Diagnostic{diagnostic(
				CodeInvalidLedger,
				fmt.Sprintf("ledger schema_version %q is unsupported; witness-ledger-record-v3 is refused and %q is required after application_class fields were removed.", record.SchemaVersion, RecordSchemaVersion),
				fmt.Sprintf("/records/%d/schema_version", index),
				map[string]any{"expected": RecordSchemaVersion, "actual": record.SchemaVersion},
			)}}
		}
	}
	previous := ""
	for index, record := range records {
		path := fmt.Sprintf("/records/%d", index)
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
	existingBytes, err := readLedgerBytes(path)
	if err != nil {
		return nil, err
	}
	existing, err := decodeLedgerRecords(existingBytes)
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
	block := make([]byte, 0)
	for _, record := range appended {
		encoded, err := marshalRecord(record)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
		block = append(block, '\n')
	}
	complete := append([]byte(nil), existingBytes...)
	if len(complete) > 0 && !bytes.HasSuffix(complete, []byte("\n")) {
		complete = append(complete, '\n')
	}
	complete = append(complete, block...)
	if err := WriteFileAtomic(path, complete, 0o644); err != nil {
		return nil, fileError(err, path, "write ledger")
	}
	return appended, nil
}

func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	perm := mode.Perm()
	preserveMode := false
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return diag.New(
				CodeInvalidLedger,
				"refusing atomic write over non-regular file.",
				diag.WithPath(path),
				diag.WithDetail("mode", info.Mode().String()),
			)
		}
		perm = info.Mode().Perm()
		preserveMode = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temp, tempPath, err := openAtomicTempFile(dir, filepath.Base(path), perm)
	if err != nil {
		return err
	}
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if preserveMode {
		if err := temp.Chmod(perm); err != nil {
			return err
		}
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := rejectNonRegularDestination(path); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return syncDirectory(dir)
}

func openAtomicTempFile(dir string, base string, perm os.FileMode) (*os.File, string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		tempPath := filepath.Join(dir, fmt.Sprintf("%s.tmp-%d-%d-%d", base, os.Getpid(), time.Now().UnixNano(), attempt))
		temp, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, perm)
		if err == nil {
			return temp, tempPath, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return nil, "", err
	}
	return nil, "", fmt.Errorf("create unique temporary file in %s: %w", dir, os.ErrExist)
}

func rejectNonRegularDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		return nil
	}
	return diag.New(
		CodeInvalidLedger,
		"refusing atomic write over non-regular file.",
		diag.WithPath(path),
		diag.WithDetail("mode", info.Mode().String()),
	)
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
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
		requireDecisionRulesVersion(&diagnostics, path+"/decision_rules_version", event.DecisionRulesVersion)
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

func requireDecisionRulesVersion(diagnostics *[]diag.Diagnostic, path string, value string) {
	if value != contracts.DecisionRulesVersion {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, "decision_rules_version is unsupported.", path, map[string]any{"expected": contracts.DecisionRulesVersion, "actual": value}))
	}
}

func requireString(diagnostics *[]diag.Diagnostic, path string, label string, value string) {
	if strings.TrimSpace(value) == "" {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidLedgerEvent, label+" is required.", path, nil))
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
