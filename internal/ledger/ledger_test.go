package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
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
		{Kind: EventKindCapRelease, Payload: CapReleaseEvent{Release: validCapRelease()}},
		{Kind: EventKindMeasuredDelta, Payload: validMeasuredDeltaEvent()},
		{Kind: EventKindPolicyDecision, Payload: validPolicyDecisionEvent()},
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
	releases, err := CapReleases(replayed)
	if err != nil {
		t.Fatalf("CapReleases: %v", err)
	}
	if len(releases) != 1 || releases[0].Actor != "owner" {
		t.Fatalf("cap releases = %#v", releases)
	}
	show, err := Show(path, ShowOptions{Kinds: []string{EventKindPolicyDecision}})
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if len(show.Records) != 1 || show.Records[0].EventKind != EventKindPolicyDecision {
		t.Fatalf("filtered show = %#v", show.Records)
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
	if _, err := AppendEvent(path, EventKindMeasuredDelta, validMeasuredDeltaEvent()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"production":1`, `"production":2`, 1)
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
		{name: "cap release", kind: EventKindCapRelease, payload: CapReleaseEvent{Release: contracts.CapReleaseRecord{
			Unit:          "lines",
			ProductionCap: 1,
			TestCap:       1,
			Basis:         contracts.CapReleaseBasisOwnerJudgment,
			Rationale:     "Owner accepted caps.",
			PolicyDigest:  td("policy"),
			RulesDigest:   td("rules"),
			CharterHash:   td("charter"),
		}}},
		{name: "measured delta", kind: EventKindMeasuredDelta, payload: MeasuredDeltaEvent{Test: IntPtr(1), Unit: "lines"}},
		{name: "policy decision", kind: EventKindPolicyDecision, payload: PolicyDecisionEvent{Allow: BoolPtr(false), PolicyID: "policy-1", PolicyDigest: td("policy"), RulesDigest: td("rules")}},
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
		RunDigest:                 td("run"),
		ResultSchemaVersion:       "witness-adjudication-run-result-v1",
		PolicyID:                  "policy-1",
		PolicyDigest:              td("policy"),
		RulesDigest:               td("rules"),
		CharterHash:               td("charter"),
		ArtifactDigest:            td("artifact"),
		ManifestDigest:            td("manifest"),
		FindingCount:              1,
		PolicyDecisionRecordCount: 1,
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

func validCapRelease() contracts.CapReleaseRecord {
	return contracts.CapReleaseRecord{
		Unit:          "lines",
		ProductionCap: 5,
		TestCap:       5,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner accepted conservative caps.",
		Actor:         "owner",
		PolicyDigest:  td("policy"),
		RulesDigest:   td("rules"),
		CharterHash:   td("charter"),
	}
}

func validMeasuredDeltaEvent() MeasuredDeltaEvent {
	return MeasuredDeltaEvent{
		Production: IntPtr(1),
		Test:       IntPtr(1),
		Unit:       "lines",
		FindingID:  "finding-1",
	}
}

func validPolicyDecisionEvent() PolicyDecisionEvent {
	return PolicyDecisionEvent{
		RunDigest:                  td("run"),
		Allow:                      BoolPtr(true),
		Reasons:                    []string{"allowed"},
		PolicyID:                   "policy-1",
		PolicyDigest:               td("policy"),
		RulesDigest:                td("rules"),
		CharterHash:                td("charter"),
		CapReleaseUnit:             UnitLines,
		Unit:                       UnitLines,
		PositiveCapAllowanceUsed:   true,
		OperationalEnvelopePresent: true,
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
