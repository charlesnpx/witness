package metrics

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/adjudicate"
	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/ledger"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/preflight"
	"github.com/charlesnpx/witness/internal/strictjson"
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

func TestMetricsRetainsAuthenticatedCodexPendingStratumAfterRelayStatusSanitization(t *testing.T) {
	frozen := metricsPlanningTestFrozenCharter(t)
	artifactDigest := testDigest("artifact")
	roleOutput := contracts.RoleOutputDocument{
		SchemaVersion:  contracts.RoleOutputV3,
		Role:           contracts.RoleDefect,
		CharterHash:    frozen.CharterHash,
		ArtifactDigest: artifactDigest,
		SourceIdentity: map[string]any{"kind": "test", "id": "source"},
		ConsumerIdentity: map[string]any{
			"kind": "test",
			"id":   "consumer",
		},
		Findings: []contracts.Finding{metricsPlanningTestFinding("finding-1")},
	}
	refs := metricsRelayPresentEvidenceRefs(t)
	planResult, err := planning.Run(planning.Options{
		FrozenCharter: frozen,
		RoleOutputs:   []planning.RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Preflight: planning.PreflightBinding{
			SnapshotDigest:          artifactDigest,
			CompatibilityDigest:     refs.CompatibilityManifest.Digest,
			RelayCapabilitiesDigest: refs.RelayCapabilities.Digest,
			IntegrationBundleDigest: refs.IntegrationBundle.Digest,
		},
	})
	if err != nil {
		t.Fatalf("planning Run: %v", err)
	}
	if len(planResult.Batches) != 1 {
		t.Fatalf("planned batches = %#v, want one", planResult.Batches)
	}
	batch := planResult.Batches[0]
	refs.ConsumerIdentity = map[string]any{
		"kind": "test",
		"id":   "consumer",
		contracts.VerificationManifestRelayLaunchStatusKey: contracts.RelayLaunchStatusAbsent,
		contracts.VerificationManifestRelayBatchesKey: map[string]any{
			batch.Plan.BatchID: map[string]any{
				"recipe_family": "forged-family",
				"backend":       "forged-backend",
				"finding_ids":   []string{"forged-finding"},
				contracts.VerificationManifestBatchRelayLaunchStatusKey: contracts.RelayLaunchStatusAbsent,
			},
		},
	}

	assembled, err := planning.Assemble(planning.AssembleOptions{
		Plan: planResult.Plan,
		Batches: []planning.BatchEvidence{{
			BatchID:  batch.Plan.BatchID,
			Document: batch.Document,
		}},
		RelayResults: []planning.RelayEvidence{{
			BatchID:      batch.Plan.BatchID,
			RecipeFamily: batch.Plan.RecipeFamily,
			Backend:      "codex",
		}},
		EvidenceRefs: refs,
	})
	if err != nil {
		t.Fatalf("planning Assemble: %v", err)
	}
	if got := assembled.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayLaunchStatusKey]; got != contracts.RelayLaunchStatusPresent {
		t.Fatalf("consumer identity launch status = %#v, want %q", got, contracts.RelayLaunchStatusPresent)
	}
	rawBatches, ok := assembled.Manifest.ConsumerIdentity[contracts.VerificationManifestRelayBatchesKey].(map[string]any)
	if !ok {
		t.Fatalf("consumer identity = %#v, missing relay batch metadata", assembled.Manifest.ConsumerIdentity)
	}
	batchMetadata, ok := rawBatches[batch.Plan.BatchID].(map[string]any)
	if !ok {
		t.Fatalf("relay batch metadata = %#v, missing batch %s", rawBatches, batch.Plan.BatchID)
	}
	if got := batchMetadata[contracts.VerificationManifestBatchRelayLaunchStatusKey]; got != contracts.RelayLaunchStatusPresent {
		t.Fatalf("relay batch launch status = %#v, want %q", got, contracts.RelayLaunchStatusPresent)
	}
	if got := batchMetadata["backend"]; got != "codex" {
		t.Fatalf("relay batch backend = %#v, want codex", got)
	}
	if diagnostics := contracts.ValidateVerificationManifest(assembled.Manifest); len(diagnostics) > 0 {
		t.Fatalf("manifest diagnostics = %#v", diagnostics)
	}

	adjudicated, err := adjudicate.Run(adjudicate.Options{
		FrozenCharter: frozen,
		RoleOutputs:   []adjudicate.RoleOutputInput{{Path: "defect.json", Document: roleOutput}},
		Manifest:      assembled.Manifest,
	})
	if err != nil {
		t.Fatalf("adjudicate Run: %v", err)
	}

	dir := t.TempDir()
	preflightPath := writeMetricsJSON(t, dir, "preflight.json", preflight.Result{
		SchemaVersion: preflight.SchemaVersion,
		OK:            true,
		BackendStrata: map[string]string{
			"claude": "ready",
			"codex":  "ready",
		},
	})
	runResultPath := writeMetricsJSON(t, dir, "run-result.json", adjudicated)
	document, err := Run(Options{
		PreflightPath:  preflightPath,
		RunResultPaths: []string{runResultPath},
	})
	if err != nil {
		t.Fatalf("metrics Run: %v", err)
	}
	if document.PendingVerification.Total != 1 {
		t.Fatalf("pending total = %d, want 1", document.PendingVerification.Total)
	}
	if len(document.PendingVerification.Strata) != 1 {
		t.Fatalf("pending strata = %#v, want one authenticated codex stratum", document.PendingVerification.Strata)
	}
	stratum := document.PendingVerification.Strata[0]
	if stratum.Backend != "codex" || stratum.BackendAuthStatus != BackendAuthStatusAuthenticated || stratum.Count != 1 {
		t.Fatalf("pending stratum = %#v, want authenticated codex count 1", stratum)
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

func metricsRelayPresentEvidenceRefs(t *testing.T) planning.ManifestEvidenceRefs {
	t.Helper()
	bundlePath := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read integration bundle: %v", err)
	}
	bundle, err := strictjson.DecodeAnyBytes(bundleBytes, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatalf("decode integration bundle: %v", err)
	}
	selectedDigests, diagnostics := preflight.SelectedContractDigestsFromBundle(bundle)
	if len(diagnostics) > 0 {
		t.Fatalf("selected contract digests = %#v", diagnostics)
	}
	canonicalBundle := canonjson.MustMarshal(bundle)
	contractIDs := []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	}
	selectedContracts := make([]contracts.ContractDigest, 0, len(contractIDs))
	selectedContractRefs := make([]contracts.ArtifactRef, 0, len(contractIDs))
	selectedContractEvidence := make([]planning.SelectedContractEvidence, 0, len(contractIDs))
	for index, contractID := range contractIDs {
		contractDigest := selectedDigests[contractID]
		if contractDigest == "" {
			t.Fatalf("missing selected contract digest for %s", contractID)
		}
		ref := contracts.ArtifactRef{
			Kind:          "selected-contract",
			ID:            "contract-" + string(rune('1'+index)),
			Digest:        contractDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		}
		selectedContracts = append(selectedContracts, contracts.ContractDigest{
			ContractID: contractID,
			Digest:     contractDigest,
		})
		selectedContractRefs = append(selectedContractRefs, ref)
		selectedContractEvidence = append(selectedContractEvidence, planning.SelectedContractEvidence{
			Ref:        ref,
			ContractID: contractID,
			RawBytes:   append([]byte(nil), canonicalBundle...),
		})
	}
	capabilities := map[string]bool{}
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		capabilities[requirement.Key] = true
	}
	capabilitiesDigest := testDigest("capabilities")
	integrationBundleDigest := testDigest("bundle")
	recipePlans := make([]contracts.RecipePlanDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	compileReports := make([]contracts.CompileReportRef, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		planDigest := testDigest("recipe:" + requirement.RecipeID)
		reportDigest := testDigest("compile:" + requirement.RecipeID)
		recipePlans = append(recipePlans, contracts.RecipePlanDigest{
			RecipeID:   requirement.RecipeID,
			ContractID: requirement.ContractID,
			Digest:     planDigest,
		})
		compileReports = append(compileReports, contracts.CompileReportRef{
			RecipeID: requirement.RecipeID,
			Status:   "retained",
			Ref: contracts.ArtifactRef{
				Kind:          "compile-report",
				ID:            requirement.RecipeID,
				Digest:        reportDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			},
			Digest: reportDigest,
		})
	}
	compatibility := contracts.RelayCompatibility{
		SchemaVersion:           contracts.RelayCompatibilityV3,
		ConvoRelayVersion:       "v1.4.0",
		DigestProfile:           digest.Profile,
		Capabilities:            capabilities,
		CapabilitiesDigest:      capabilitiesDigest,
		IntegrationBundleDigest: integrationBundleDigest,
		SelectedContracts:       selectedContracts,
		RecipePlans:             recipePlans,
		CompileReports:          compileReports,
		BackendStatus: []contracts.BackendStatus{
			{Backend: "codex", Status: "available"},
			{Backend: "claude", Status: "available"},
		},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
	compatibilityDigest, err := contracts.RelayCompatibilityDigest(compatibility)
	if err != nil {
		t.Fatalf("compatibility digest: %v", err)
	}
	return planning.ManifestEvidenceRefs{
		CompatibilityManifest: contracts.ArtifactRef{
			Kind:          "compatibility-manifest",
			ID:            "compatibility",
			Digest:        compatibilityDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		RelayCompatibility: &compatibility,
		RelayCapabilities: contracts.ArtifactRef{
			Kind:          "relay-capabilities",
			ID:            "capabilities",
			Digest:        capabilitiesDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		IntegrationBundle: contracts.ArtifactRef{
			Kind:          "integration-bundle",
			ID:            "bundle",
			Digest:        integrationBundleDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		},
		SelectedContracts:        selectedContractRefs,
		SelectedContractEvidence: selectedContractEvidence,
		ConsumerIdentity:         map[string]any{"kind": "test", "id": "consumer"},
	}
}

func metricsPlanningTestFinding(id string) contracts.Finding {
	return contracts.Finding{
		ID:              id,
		Kind:            contracts.FindingKindDefect,
		Title:           "Finding " + id,
		CharterGoalIDs:  []string{"goal-cli"},
		ClaimedSeverity: contracts.SeverityHigh,
		ScopeAnchors:    []contracts.ScopeAnchor{{Dimension: charter.DimensionEntryPoints, EntryID: "cli"}},
		Witness: contracts.Witness{
			Kind:     contracts.WitnessKindDefect,
			Strength: contracts.WitnessStrengthConstructed,
			Content:  "The filed witness is specific to the declared CLI behavior.",
			EntryPoint: &contracts.ScopeAnchor{
				Dimension: charter.DimensionEntryPoints,
				EntryID:   "cli",
			},
			ReachabilityChain: []contracts.ScopeAnchor{
				{Dimension: charter.DimensionEntryPoints, EntryID: "cli"},
				{Dimension: charter.DimensionInputSurface, Value: "config"},
				{Dimension: charter.DimensionValidStates, EntryID: "normal"},
			},
		},
		EstimatedDelta: contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: 1, Files: 1},
		},
		SmallestSufficientRemedy: contracts.SmallestSufficientRemedy{
			Direction:          contracts.RemedyDirectionChange,
			Summary:            "Change the smallest reachable branch.",
			MinimalityArgument: "The fix is limited to the branch named by the witness.",
		},
		ProposedTests: []contracts.ProposedTest{{
			ID:                 "test-" + id,
			Name:               "covers " + id,
			ReachablePartition: "partition-" + id,
			CharterRefs:        []contracts.CharterRef{{GoalID: "goal-cli"}},
		}},
	}
}

func metricsPlanningTestFrozenCharter(t *testing.T) *charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-cli",
			Statement: "The CLI accepts declared valid inputs deterministically.",
		}},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial charter.",
		}},
		OperationalEnvelope: &charter.OperationalEnvelope{
			EntryPoints: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared entry points.",
				Entries:   []charter.Entry{{ID: "cli", Statement: "Command line interface."}},
			},
			InputSurface: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Caller supplied files.",
				Entries:   []charter.Entry{},
			},
			ValidStates: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared valid states.",
				Entries:   []charter.Entry{{ID: "normal", Statement: "Normal configured operation."}},
			},
			Environments: &charter.Dimension{
				State:     charter.StateNotApplicable,
				Statement: "No environment distinction.",
				Entries:   []charter.Entry{},
			},
			ScaleBounds: &charter.Dimension{
				State:     charter.StateUnspecified,
				Statement: "Scale is unspecified.",
				Entries:   []charter.Entry{},
			},
			CompatibilityPromises: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared compatibility promises.",
				Entries:   []charter.Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
			},
			ThreatModel: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Threat scenarios must be concrete.",
				Entries:   []charter.Entry{},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &frozen
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
