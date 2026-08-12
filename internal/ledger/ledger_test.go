package ledger

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestAppendReplayRoundTripAndFilteredShow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	events := []EventToAppend{
		{Kind: EventKindAdjudicationRun, Payload: validAdjudicationRunEvent()},
		{Kind: EventKindFinding, Payload: validFindingEvent()},
		{Kind: EventKindVerdict, Payload: validVerdictEvent()},
		{Kind: EventKindQuestion, Payload: validQuestionEvent()},
		{Kind: EventKindPendingVerification, Payload: validPendingVerificationEvent()},
		{Kind: EventKindOwnerOverride, Payload: validOwnerOverrideEvent()},
		{Kind: EventKindPromotion, Payload: validPromotionEvent()},
		{Kind: EventKindAcceptUnverified, Payload: validAcceptUnverifiedEvent()},
	}
	appended, err := AppendEvents(path, events)
	if err != nil {
		t.Fatalf("AppendEvents: %v", err)
	}
	if len(appended) != len(events) {
		t.Fatalf("appended records = %d, want %d", len(appended), len(events))
	}
	replayed, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(replayed) != len(events) {
		t.Fatalf("replayed records = %d, want %d", len(replayed), len(events))
	}
	for index, record := range replayed {
		if record.Sequence != index+1 {
			t.Fatalf("record %d sequence = %d", index, record.Sequence)
		}
		if record.Digest == "" {
			t.Fatalf("record %d missing digest", index)
		}
	}
	show, err := Show(path, ShowOptions{Kinds: []string{EventKindVerdict}})
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if show.SchemaVersion != ShowSchemaVersion {
		t.Fatalf("show schema_version = %q, want %q", show.SchemaVersion, ShowSchemaVersion)
	}
	if len(show.Records) != 1 || show.Records[0].EventKind != EventKindVerdict {
		t.Fatalf("filtered show = %#v", show.Records)
	}
	if show.Records[0].SchemaVersion != RecordSchemaVersion {
		t.Fatalf("shown record schema_version = %q, want %q", show.Records[0].SchemaVersion, RecordSchemaVersion)
	}
}

func TestReadFileRejectsV2LedgerBeforeDecodingLegacyEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	legacy := Record{
		SchemaVersion: "witness-ledger-record-v2",
		Sequence:      1,
		EventKind:     "removed_legacy_event",
		Event: json.RawMessage(`{
			"legacy": true
		}`),
	}
	var err error
	legacy.Digest, err = recordDigest(legacy)
	if err != nil {
		t.Fatalf("recordDigest: %v", err)
	}
	encoded, err := marshalRecord(legacy)
	if err != nil {
		t.Fatalf("marshalRecord: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = ReadFile(path)
	if err == nil {
		t.Fatal("ReadFile accepted a v1 ledger")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) != 1 {
		t.Fatalf("error = %#v, want one explicit version diagnostic", err)
	}
	diagnostic := validation.Diagnostics[0]
	if diagnostic.Code != CodeInvalidLedger || diagnostic.Path != "/records/0/schema_version" {
		t.Fatalf("diagnostic = %#v, want explicit unsupported ledger version", diagnostic)
	}
	if strings.Contains(diagnostic.Message, "unknown_json_field") {
		t.Fatalf("diagnostic = %#v, want version refusal rather than field decode error", diagnostic)
	}
	if diagnostic.Details["actual"] != "witness-ledger-record-v2" || diagnostic.Details["expected"] != RecordSchemaVersion {
		t.Fatalf("schema diagnostic details = %#v, want v2 and %s", diagnostic.Details, RecordSchemaVersion)
	}
}

func TestContainsRunDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	run := validAdjudicationRunEvent()
	if _, err := AppendEvent(path, EventKindAdjudicationRun, run); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contains, err := ContainsRunDigest(records, run.RunDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !contains {
		t.Fatalf("ContainsRunDigest(%q) = false, want true", run.RunDigest)
	}
	contains, err = ContainsRunDigest(records, td("other-run"))
	if err != nil {
		t.Fatal(err)
	}
	if contains {
		t.Fatal("ContainsRunDigest found a run digest that was not appended")
	}
}

func TestDigestChainTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if _, err := AppendEvent(path, EventKindVerdict, validVerdictEvent()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"finding_id":"finding-1"`, `"finding_id":"finding-2"`, 1)
	if tampered == string(data) {
		t.Fatal("test did not tamper ledger content")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadFile(path)
	if err == nil {
		t.Fatal("ReadFile accepted tampered ledger")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want ValidationError", err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != CodeLedgerTamper {
		t.Fatalf("diagnostics = %#v", validation.Diagnostics)
	}
}

func TestWriteFileAtomicRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.jsonl")
	targetData := []byte("target\n")
	if err := os.WriteFile(targetPath, targetData, 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "ledger.jsonl")
	linkTarget := "target.jsonl"
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}

	err := WriteFileAtomic(linkPath, []byte("replacement\n"), 0o644)
	if err == nil {
		t.Fatal("WriteFileAtomic accepted a symlink destination")
	}
	if diagnostic := diag.FromError(err); diagnostic.Code != CodeInvalidLedger {
		t.Fatalf("diagnostic code = %s, want %s", diagnostic.Code, CodeInvalidLedger)
	}
	gotTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if gotTarget != linkTarget {
		t.Fatalf("link target = %q, want %q", gotTarget, linkTarget)
	}
	linkInfo, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat link: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("destination mode = %s, want symlink", linkInfo.Mode())
	}
	gotData, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	if string(gotData) != string(targetData) {
		t.Fatalf("target data = %q, want %q", gotData, targetData)
	}
}

func TestWriteFileAtomicHonorsUmaskForNewFilesAndPreservesExistingMode(t *testing.T) {
	oldUmask := syscall.Umask(0o077)
	t.Cleanup(func() {
		syscall.Umask(oldUmask)
	})

	dir := t.TempDir()
	newPath := filepath.Join(dir, "new-ledger.jsonl")
	if err := WriteFileAtomic(newPath, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic new file: %v", err)
	}
	newInfo, err := os.Stat(newPath)
	if err != nil {
		t.Fatalf("Stat new file: %v", err)
	}
	if got, want := newInfo.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("new file mode = %o, want %o", got, want)
	}

	existingPath := filepath.Join(dir, "existing-ledger.jsonl")
	if err := os.WriteFile(existingPath, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(existingPath, []byte("replacement\n"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic existing file: %v", err)
	}
	existingInfo, err := os.Stat(existingPath)
	if err != nil {
		t.Fatalf("Stat existing file: %v", err)
	}
	if got, want := existingInfo.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("existing file mode = %o, want %o", got, want)
	}
	gotData, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("ReadFile existing file: %v", err)
	}
	if string(gotData) != "replacement\n" {
		t.Fatalf("existing data = %q, want replacement", gotData)
	}
}

func TestEventKindRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		payload any
	}{
		{name: "adjudication run", kind: EventKindAdjudicationRun, payload: AdjudicationRunEvent{RunDigest: td("run")}},
		{name: "finding", kind: EventKindFinding, payload: FindingEvent{FindingID: "finding-1", WitnessDigest: td("witness"), CharterHash: td("charter"), ArtifactDigest: td("artifact")}},
		{name: "verdict", kind: EventKindVerdict, payload: VerdictEvent{RunDigest: td("run"), FindingID: "finding-1", Disposition: "admitted"}},
		{name: "question", kind: EventKindQuestion, payload: QuestionEvent{FindingID: "finding-1", CharterHash: td("charter"), Statement: "Should this be a goal?"}},
		{name: "pending verification", kind: EventKindPendingVerification, payload: PendingVerificationEvent{FindingID: "finding-1", Status: "unavailable"}},
		{name: "owner override", kind: EventKindOwnerOverride, payload: OwnerOverrideEvent{FindingID: "finding-1", Actor: "owner"}},
		{name: "promotion", kind: EventKindPromotion, payload: PromotionEvent{QuestionID: "question-1", Actor: "owner", Rationale: "Promote to goal."}},
		{name: "accept unverified", kind: EventKindAcceptUnverified, payload: AcceptUnverifiedEvent{FindingID: "finding-1", Actor: "owner", Rationale: "Risk accepted."}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AppendEvent(filepath.Join(t.TempDir(), "ledger.jsonl"), test.kind, test.payload)
			if err == nil {
				t.Fatal("AppendEvent accepted payload missing a required field")
			}
			var validation *ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error = %T, want ValidationError", err)
			}
			if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != CodeInvalidLedgerEvent {
				t.Fatalf("diagnostics = %#v", validation.Diagnostics)
			}
		})
	}
}

func validAdjudicationRunEvent() AdjudicationRunEvent {
	return AdjudicationRunEvent{
		RunDigest:            td("run"),
		ResultSchemaVersion:  "witness-adjudication-run-result-v5",
		DecisionRulesVersion: "witness-decision-rules-v1",
		CharterHash:          td("charter"),
		ArtifactDigest:       td("artifact"),
		ManifestDigest:       td("manifest"),
		FindingCount:         1,
	}
}

func validFindingEvent() FindingEvent {
	return FindingEvent{
		FindingID:      "finding-1",
		FindingKey:     "defect:entry-point",
		WitnessDigest:  td("witness"),
		CharterHash:    td("charter"),
		ArtifactDigest: td("artifact"),
		Finding:        map[string]any{"title": "A reachable defect exists."},
	}
}

func validVerdictEvent() VerdictEvent {
	return VerdictEvent{
		RunDigest:         td("run"),
		FindingID:         "finding-1",
		Role:              contracts.RoleDefect,
		Kind:              contracts.FindingKindDefect,
		Disposition:       contracts.DispositionAdmitted,
		ApplicationClass:  contracts.ApplicationClassCallerDecision,
		ClaimedSeverity:   contracts.SeverityHigh,
		EffectiveSeverity: contracts.SeverityHigh,
		SeverityCap:       contracts.SeverityHigh,
		Reasons:           []string{"relay_survived"},
		FindingDigest:     td("finding"),
		WitnessDigest:     td("witness"),
	}
}

func validQuestionEvent() QuestionEvent {
	return QuestionEvent{
		RunDigest:   td("run"),
		QuestionID:  "question-1",
		FindingID:   "finding-1",
		CharterHash: td("charter"),
		Statement:   "Should this behavior be an explicit goal?",
	}
}

func validPendingVerificationEvent() PendingVerificationEvent {
	return PendingVerificationEvent{
		RunDigest:      td("run"),
		FindingID:      "finding-1",
		VerificationID: "verify-1",
		Status:         "unavailable",
	}
}

func validOwnerOverrideEvent() OwnerOverrideEvent {
	return OwnerOverrideEvent{
		FindingID: "finding-1",
		Actor:     "owner",
		Rationale: "Owner override for this finding.",
	}
}

func validPromotionEvent() PromotionEvent {
	return PromotionEvent{
		QuestionID: "question-1",
		GoalRef:    "goal-1",
		Actor:      "owner",
		Rationale:  "The owner made the missing goal explicit.",
	}
}

func validAcceptUnverifiedEvent() AcceptUnverifiedEvent {
	return AcceptUnverifiedEvent{
		FindingID:             "finding-1",
		PendingVerificationID: "verify-1",
		Actor:                 "owner",
		Rationale:             "Owner accepts the pending risk.",
	}
}

func td(value string) string {
	return digest.RawBytes([]byte(value))
}

func TestQuestionEventDecodeHonorsCallerLimitAboveDefault(t *testing.T) {
	event := validQuestionEvent()
	event.Statement = strings.Repeat("q", int(strictjson.DefaultMaxBytes)+1024)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if int64(len(encoded)) <= strictjson.DefaultMaxBytes {
		t.Fatalf("test payload must exceed DefaultMaxBytes, got %d", len(encoded))
	}
	decoded, err := strictjson.DecodeBytes[QuestionEvent](encoded, strictjson.DefaultMaxBytes*4)
	if err != nil {
		t.Fatalf("decode with enlarged caller limit: %v", err)
	}
	if decoded.Statement != event.Statement {
		t.Fatalf("statement round-trip mismatch")
	}
}
