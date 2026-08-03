package metrics

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"witness/internal/adjudicate"
	"witness/internal/canonjson"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/digest"
	"witness/internal/ledger"
	"witness/internal/preflight"
	"witness/internal/strictjson"
)

type ledgerFixtureEvent struct {
	Kind  string          `json:"kind"`
	Event json.RawMessage `json:"event"`
}

func TestMetricsGolden(t *testing.T) {
	tests := []struct {
		name         string
		ledgerEvents string
		preflight    string
		runResults   []string
		golden       string
	}{
		{
			name:       "pending stratification",
			preflight:  "preflight-installed-auth-unknown.json",
			runResults: []string{"run-result-pending.json"},
			golden:     "pending-stratification.golden.json",
		},
		{
			name:         "operational envelope questions",
			ledgerEvents: "ledger-events-questions.json",
			golden:       "operational-envelope-questions.golden.json",
		},
		{
			name:       "verdict class contradictions",
			runResults: []string{"run-result-verdicts.json"},
			golden:     "verdict-class-contradictions.golden.json",
		},
		{
			name:         "cap release mismatch",
			ledgerEvents: "ledger-events-cap-mismatch.json",
			runResults:   []string{"run-result-cap-mismatch.json"},
			golden:       "cap-release-mismatch.golden.json",
		},
		{
			name:         "delta comparison",
			ledgerEvents: "ledger-events-deltas.json",
			golden:       "delta-comparison.golden.json",
		},
		{
			name:   "missing input reasons",
			golden: "missing-input-reasons.golden.json",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			options := Options{}
			if test.ledgerEvents != "" {
				options.LedgerPath = buildLedgerFixture(t, dir, test.ledgerEvents)
			}
			if test.preflight != "" {
				options.PreflightPath = fixturePath(test.preflight)
			}
			for _, runResult := range test.runResults {
				options.RunResultPaths = append(options.RunResultPaths, fixturePath(runResult))
			}
			document, err := Run(options)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			actual := append(canonjson.MustMarshal(document), '\n')
			expected, err := os.ReadFile(fixturePath(test.golden))
			if err != nil {
				t.Fatalf("read golden: %v\nactual:\n%s", err, actual)
			}
			if !bytes.Equal(bytes.TrimSpace(actual), bytes.TrimSpace(expected)) {
				t.Fatalf("metrics mismatch\nactual:\n%s\nexpected:\n%s", actual, expected)
			}
		})
	}
}

func TestPendingVerificationMetricsStratifyRelayAbsent(t *testing.T) {
	dir := t.TempDir()
	preflightPath := writeMetricsJSON(t, dir, "preflight.json", preflight.Result{
		SchemaVersion: preflight.SchemaVersion,
		OK:            true,
		BackendStrata: map[string]string{
			"codex":  contracts.RelayLaunchStatusAbsent,
			"claude": contracts.RelayLaunchStatusAbsent,
		},
	})
	runResultPath := writeMetricsJSON(t, dir, "run-result.json", adjudicate.Result{
		SchemaVersion: adjudicate.ResultSchemaVersion,
		Summary: adjudicate.Summary{
			PendingVerification: 1,
		},
		Findings: []adjudicate.FindingVerdict{{
			FindingID:   "finding-high",
			Disposition: contracts.DispositionPendingVerification,
			Relay: &adjudicate.RelayMetadata{
				Required:      true,
				Status:        contracts.RecordStatusUnavailable,
				FailureReason: "relay_verification_unavailable",
			},
		}},
	})

	document, err := Run(Options{
		PreflightPath:  preflightPath,
		RunResultPaths: []string{runResultPath},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if document.PendingVerification.Total != 1 {
		t.Fatalf("pending total = %d, want 1", document.PendingVerification.Total)
	}
	if len(document.PendingVerification.Strata) != 1 {
		t.Fatalf("pending strata = %#v, want one relay_absent stratum", document.PendingVerification.Strata)
	}
	stratum := document.PendingVerification.Strata[0]
	if stratum.BackendAuthStatus != BackendAuthStatusRelayAbsent || stratum.Count != 1 {
		t.Fatalf("pending stratum = %#v, want relay_absent count 1", stratum)
	}
}

func TestOperationalEnvelopeQuestionClassificationUsesQuestionLinkage(t *testing.T) {
	records := []ledger.Record{
		ledgerRecordForEvent(t, ledger.EventKindQuestion, ledger.QuestionEvent{
			QuestionID:  "question-finding-only",
			FindingID:   "finding-1",
			CharterHash: testDigest("charter"),
			Statement:   "Should this finding-only question become a goal?",
		}),
		ledgerRecordForEvent(t, ledger.EventKindPromotion, ledger.PromotionEvent{
			QuestionID: "question-finding-only",
			GoalRef:    "goal-finding-only",
			Actor:      "owner",
			Rationale:  "Promote generic question.",
		}),
		ledgerRecordForEvent(t, ledger.EventKindQuestion, ledger.QuestionEvent{
			QuestionID:       "question-anchor",
			Dimension:        charter.DimensionScaleBounds,
			AnchorIndex:      ledger.IntPtr(0),
			Property:         "maximum reviewed size",
			Value:            "100 files",
			AffectedDecision: "automatic application",
			CharterHash:      testDigest("charter"),
			Statement:        "Should this anchor question become a goal?",
		}),
		ledgerRecordForEvent(t, ledger.EventKindPromotion, ledger.PromotionEvent{
			QuestionID: "question-anchor",
			GoalRef:    "goal-anchor",
			Actor:      "owner",
			Rationale:  "Promote anchor question.",
		}),
	}
	got := operationalEnvelopeMetrics(records, true)
	if got.EmittedMissingGoalQuestions.Count != 1 || got.Promotions.Count != 1 {
		t.Fatalf("operational envelope metrics = %#v, want one linked question and promotion", got)
	}
	if got.GenericMissingGoalQuestions == nil || got.GenericMissingGoalQuestions.Count != 1 {
		t.Fatalf("generic questions = %#v, want one finding-only question", got.GenericMissingGoalQuestions)
	}
	if got.GenericPromotions == nil || got.GenericPromotions.Count != 1 {
		t.Fatalf("generic promotions = %#v, want one finding-only promotion", got.GenericPromotions)
	}
}

func TestDeltaComparisonExcludesUnpairedEstimateAndMeasuredDelta(t *testing.T) {
	records := []ledger.Record{
		ledgerRecordForEvent(t, ledger.EventKindFinding, ledger.FindingEvent{
			FindingID:      "finding-estimate-only",
			FindingKey:     "defect:estimate-only",
			WitnessDigest:  testDigest("witness-estimate"),
			CharterHash:    testDigest("charter"),
			ArtifactDigest: testDigest("artifact"),
			Finding: map[string]any{
				"estimated_delta": map[string]any{
					"production": map[string]any{"status": "known", "lines": 2},
					"test":       map[string]any{"status": "known", "lines": 1},
				},
			},
		}),
		ledgerRecordForEvent(t, ledger.EventKindMeasuredDelta, ledger.MeasuredDeltaEvent{
			FindingID:  "finding-measured-only",
			Production: ledger.IntPtr(2),
			Test:       ledger.IntPtr(1),
			Unit:       ledger.UnitLines,
		}),
	}
	got := deltaComparisonMetrics(records, true)
	if got.PairedFindings != 0 || got.ExcludedFindings != 2 {
		t.Fatalf("delta comparison = %#v, want two excluded unpaired findings", got)
	}
	assertDeltaExclusionStratum(t, got, ReasonEstimatedDeltaMissing, 1)
	assertDeltaExclusionStratum(t, got, ReasonMeasuredDeltaMissing, 1)
	if got.Reason != ReasonNoPairedEstimatedAndMeasuredDeltas {
		t.Fatalf("reason = %q, want %q", got.Reason, ReasonNoPairedEstimatedAndMeasuredDeltas)
	}
}

func TestSkillLint(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "skill", "SKILL.md"))
	if err != nil {
		t.Fatalf("read skill: %v", err)
	}
	text := string(data)
	required := []string{
		"Finder roles are exactly: defect, economy, and optional goal-fit.",
		"smallest sufficient remedy",
		"at most one test per distinct reachable behavioral partition",
		"unreachable states",
		"runtime guarantees",
		"repeated internal layers",
		"unsupported Cartesian combinations",
		"implementation-only details",
		"unbounded fuzz/property work",
		"role-output document",
		"verification-batch documents",
		"run-result document",
		"Operational Envelope",
		"existing code, tests, defenses, and review machinery create no goals",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("skill missing %q", want)
		}
	}
	forbidden := []string{
		"arbiter role",
		"judge role",
		"approver role",
		"approval gate",
		"new model role",
	}
	lower := strings.ToLower(text)
	for _, phrase := range forbidden {
		if strings.Contains(lower, phrase) {
			t.Fatalf("skill contains forbidden role/gate addition phrase %q", phrase)
		}
	}
}

func writeMetricsJSON(t *testing.T, dir string, name string, value any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := append(canonjson.MustMarshal(value), '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDeltaExclusionStratum(t *testing.T, metrics DeltaComparisonMetrics, reason string, count int) {
	t.Helper()
	for _, stratum := range metrics.ExcludedStrata {
		if stratum.Reason == reason && stratum.Count == count {
			return
		}
	}
	t.Fatalf("excluded strata = %#v, missing %s count %d", metrics.ExcludedStrata, reason, count)
}

func ledgerRecordForEvent(t *testing.T, kind string, payload any) ledger.Record {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return ledger.Record{EventKind: kind, Event: data}
}

func testDigest(seed string) string {
	return digest.RawBytes([]byte(seed))
}

func buildLedgerFixture(t *testing.T, dir string, eventsFixture string) string {
	t.Helper()
	data, err := os.ReadFile(fixturePath(eventsFixture))
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := strictjson.DecodeBytes[[]ledgerFixtureEvent](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	events := make([]ledger.EventToAppend, 0, len(fixtures))
	for _, fixture := range fixtures {
		events = append(events, ledger.EventToAppend{
			Kind:    fixture.Kind,
			Payload: decodeLedgerFixturePayload(t, fixture),
		})
	}
	path := filepath.Join(dir, "ledger.jsonl")
	if _, err := ledger.AppendEvents(path, events); err != nil {
		t.Fatalf("append ledger fixture: %v", err)
	}
	return path
}

func decodeLedgerFixturePayload(t *testing.T, fixture ledgerFixtureEvent) any {
	t.Helper()
	switch fixture.Kind {
	case ledger.EventKindFinding:
		return decodeFixture[ledger.FindingEvent](t, fixture.Event)
	case ledger.EventKindQuestion:
		return decodeFixture[ledger.QuestionEvent](t, fixture.Event)
	case ledger.EventKindPromotion:
		return decodeFixture[ledger.PromotionEvent](t, fixture.Event)
	case ledger.EventKindAdjudicationRun:
		return decodeFixture[ledger.AdjudicationRunEvent](t, fixture.Event)
	case ledger.EventKindPolicyDecision:
		return decodeFixture[ledger.PolicyDecisionEvent](t, fixture.Event)
	case ledger.EventKindMeasuredDelta:
		return decodeFixture[ledger.MeasuredDeltaEvent](t, fixture.Event)
	default:
		t.Fatalf("unsupported fixture ledger event kind %q", fixture.Kind)
		return nil
	}
}

func decodeFixture[T any](t *testing.T, data []byte) T {
	t.Helper()
	value, err := strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", "metrics", name)
}
