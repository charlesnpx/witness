package charter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"witness/internal/diag"
)

func TestAbsentEnvelopeKeepsReachabilityInactiveAndStandingInvariant(t *testing.T) {
	input := Charter{
		SchemaVersion: SchemaVersion,
		Goals:         []Statement{},
		NonGoals:      []Statement{},
		OwnerEvents: []OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial charter.",
		}},
	}
	normalized, err := Normalize(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.OperationalEnvelope != nil {
		t.Fatal("normalized charter unexpectedly has an Operational Envelope")
	}
	if got := normalized.StandingNoGoals; len(got) != 1 || got[0].Statement != StandingNoGoalsStatement {
		t.Fatalf("standing no-goals invariant = %#v", got)
	}
	properties := Properties(normalized.OperationalEnvelope)
	if properties.ReachabilityRulesActive {
		t.Fatal("reachability rules active without an Operational Envelope")
	}
	if properties.AdditiveRemediesAutomatic {
		t.Fatal("additive remedies became automatic")
	}
}

func TestOperationalEnvelopeDimensionStateValidation(t *testing.T) {
	tests := []struct {
		name      string
		dimension Dimension
		wantOK    bool
	}{
		{
			name: "bounded valid",
			dimension: Dimension{
				State:     StateBounded,
				Statement: "Declared values.",
				Entries:   []Entry{{ID: "declared", Statement: "Declared entry."}},
			},
			wantOK: true,
		},
		{
			name: "bounded empty entries rejected",
			dimension: Dimension{
				State:     StateBounded,
				Statement: "Declared values.",
				Entries:   []Entry{},
			},
		},
		{
			name: "unbounded non-empty entries rejected",
			dimension: Dimension{
				State:     StateUnbounded,
				Statement: "Concrete values required.",
				Entries:   []Entry{{ID: "not-allowed", Statement: "Should not be here."}},
			},
		},
		{
			name: "not_applicable non-empty entries rejected",
			dimension: Dimension{
				State:     StateNotApplicable,
				Statement: "Excluded dimension.",
				Entries:   []Entry{{ID: "not-allowed", Statement: "Should not be here."}},
			},
		},
		{
			name: "unspecified non-empty entries rejected",
			dimension: Dimension{
				State:     StateUnspecified,
				Statement: "Missing goal area.",
				Entries:   []Entry{{ID: "not-allowed", Statement: "Should not be here."}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validCharter()
			input.OperationalEnvelope.EntryPoints = &test.dimension
			err := normalizeError(input)
			if test.wantOK && err != nil {
				t.Fatalf("Normalize returned error: %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("Normalize succeeded, want validation failure")
			}
		})
	}
}

func TestOperationalEnvelopeDimensionEntriesPresenceValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "absent entries rejected",
			mutate: func(dimension map[string]any) {
				delete(dimension, "entries")
			},
		},
		{
			name: "null entries rejected",
			mutate: func(dimension map[string]any) {
				dimension["entries"] = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := charterWithMutatedDimension(t, DimensionInputSurface, test.mutate)
			err := normalizeError(input)
			if err == nil {
				t.Fatal("Normalize succeeded, want validation failure")
			}
			assertValidationDiagnostic(t, err, CodeInvalidCharter, "/operational_envelope/input_surface/entries")
		})
	}
}

func TestScopeAnchorValidation(t *testing.T) {
	envelope := validEnvelope()
	tests := []struct {
		name            string
		anchors         []ScopeAnchor
		wantAdvisory    bool
		wantObligating  bool
		wantDiagnostics string
	}{
		{
			name:           "bounded reference valid",
			anchors:        []ScopeAnchor{{Dimension: DimensionEntryPoints, EntryID: "http"}},
			wantObligating: true,
		},
		{
			name:            "bounded invalid reference advisory",
			anchors:         []ScopeAnchor{{Dimension: DimensionEntryPoints, EntryID: "missing"}},
			wantAdvisory:    true,
			wantDiagnostics: CodeInvalidScopeAnchor,
		},
		{
			name:           "unbounded concrete value valid",
			anchors:        []ScopeAnchor{{Dimension: DimensionInputSurface, Value: "POST /v1/items"}},
			wantObligating: true,
		},
		{
			name:            "unspecified routes to missing-goal question",
			anchors:         []ScopeAnchor{{Dimension: DimensionScaleBounds, Property: "request_rate", Value: "10k requests", AffectedDecision: "whether to require load-handling work"}},
			wantAdvisory:    true,
			wantDiagnostics: CodeMissingGoalQuestion,
		},
		{
			name:            "unspecified missing property is invalid anchor",
			anchors:         []ScopeAnchor{{Dimension: DimensionScaleBounds, Value: "10k requests", AffectedDecision: "whether to require load-handling work"}},
			wantAdvisory:    true,
			wantDiagnostics: CodeInvalidScopeAnchor,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ValidateFindingScope(envelope, FindingScope{
				FindingID: "finding-1",
				Kind:      FindingKindDefect,
				Anchors:   test.anchors,
			})
			if result.Advisory != test.wantAdvisory {
				t.Fatalf("Advisory = %v, want %v; result=%#v", result.Advisory, test.wantAdvisory, result)
			}
			if result.Obligating != test.wantObligating {
				t.Fatalf("Obligating = %v, want %v; result=%#v", result.Obligating, test.wantObligating, result)
			}
			if test.wantDiagnostics != "" {
				assertDiagnosticCode(t, result.Diagnostics, test.wantDiagnostics)
			}
			if test.wantDiagnostics == CodeMissingGoalQuestion {
				if len(result.Questions) != 1 {
					t.Fatalf("Questions = %#v, want one linked missing-goal question", result.Questions)
				}
				question := result.Questions[0]
				if question.Property != "request_rate" || question.Value != "10k requests" || question.AffectedDecision != "whether to require load-handling work" {
					t.Fatalf("Question = %#v, want property/value/affected decision carried through", question)
				}
				if !strings.Contains(question.Statement, "request_rate") || !strings.Contains(question.Statement, "whether to require load-handling work") || question.Dimension != DimensionScaleBounds {
					t.Fatalf("Question statement/linkage = %#v", question)
				}
			} else if len(result.Questions) != 0 {
				t.Fatalf("Questions = %#v, want none", result.Questions)
			}
		})
	}

	first := ValidateFindingScope(envelope, FindingScope{
		FindingID: "finding-question-id",
		Kind:      FindingKindDefect,
		Anchors: []ScopeAnchor{{
			Dimension:        DimensionScaleBounds,
			Property:         "request_rate",
			Value:            "10k requests",
			AffectedDecision: "whether to require load-handling work",
		}},
	})
	second := ValidateFindingScope(envelope, FindingScope{
		FindingID: "finding-question-id",
		Kind:      FindingKindDefect,
		Anchors: []ScopeAnchor{{
			Dimension:        DimensionScaleBounds,
			Property:         "request_rate",
			Value:            "20k requests",
			AffectedDecision: "whether to require load-handling work",
		}},
	})
	if len(first.Questions) != 1 || len(second.Questions) != 1 {
		t.Fatalf("Questions = %#v and %#v, want one question from each anchor", first.Questions, second.Questions)
	}
	if first.Questions[0].ID == second.Questions[0].ID {
		t.Fatalf("question IDs are not value-distinct: %s", first.Questions[0].ID)
	}
}

func TestDefectScopeRequiresAnchorUnderEnvelope(t *testing.T) {
	result := ValidateFindingScope(validEnvelope(), FindingScope{
		FindingID: "finding-1",
		Kind:      FindingKindDefect,
	})
	if !result.Advisory || result.Obligating {
		t.Fatalf("result = %#v, want advisory non-obligating", result)
	}
	assertDiagnosticCode(t, result.Diagnostics, CodeMissingScopeAnchor)
}

func TestWitnessReachabilityStructure(t *testing.T) {
	envelope := validEnvelope()
	tests := []struct {
		name     string
		witness  Witness
		wantOK   bool
		wantCode string
	}{
		{
			name: "passing constructed witness",
			witness: Witness{
				Strength:   WitnessStrengthConstructed,
				EntryPoint: &ScopeAnchor{Dimension: DimensionEntryPoints, EntryID: "http"},
				ReachabilityChain: []ScopeAnchor{
					{Dimension: DimensionEntryPoints, EntryID: "http"},
					{Dimension: DimensionInputSurface, Value: "POST /v1/items"},
					{Dimension: DimensionValidStates, EntryID: "normal"},
				},
			},
			wantOK: true,
		},
		{
			name: "missing entry point",
			witness: Witness{
				Strength: WitnessStrengthConstructed,
				ReachabilityChain: []ScopeAnchor{
					{Dimension: DimensionInputSurface, Value: "POST /v1/items"},
				},
			},
			wantCode: CodeMissingEntryPoint,
		},
		{
			name: "dangling reference",
			witness: Witness{
				Strength:   WitnessStrengthExecutable,
				EntryPoint: &ScopeAnchor{Dimension: DimensionEntryPoints, EntryID: "http"},
				ReachabilityChain: []ScopeAnchor{
					{Dimension: DimensionValidStates, EntryID: "missing"},
				},
			},
			wantCode: CodeDanglingReachabilityReference,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ValidateWitnessStructure(envelope, FindingKindDefect, test.witness)
			if result.Valid != test.wantOK {
				t.Fatalf("Valid = %v, want %v; result=%#v", result.Valid, test.wantOK, result)
			}
			if test.wantCode != "" {
				assertDiagnosticCode(t, result.Diagnostics, test.wantCode)
			}
		})
	}
}

func TestCharterHashStableAcrossKeyOrderAndWhitespace(t *testing.T) {
	first := hashFixture(t, "base-charter.json")
	second := hashFixture(t, "reordered-charter.json")
	if first != second {
		t.Fatalf("hash changed across key order/whitespace: %s != %s", first, second)
	}
}

func TestAmendmentAppendProducesNewHash(t *testing.T) {
	input := validCharter()
	before, err := Freeze(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "amendments.jsonl")
	event := OwnerEvent{
		ID:      "event-2",
		Type:    "charter_amended",
		Actor:   "owner",
		Summary: "Record owner clarification.",
		Details: map[string]any{"note": "amendment changes charter hash"},
	}
	if err := AppendAmendment(path, event); err != nil {
		t.Fatal(err)
	}
	amendments, err := ReadAmendmentsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Freeze(input, amendments)
	if err != nil {
		t.Fatal(err)
	}
	if before.CharterHash == after.CharterHash {
		t.Fatalf("amendment did not change hash: %s", before.CharterHash)
	}
	if len(after.Charter.OwnerEvents) != len(input.OwnerEvents)+1 {
		t.Fatalf("owner events = %#v", after.Charter.OwnerEvents)
	}
}

func TestShowCanonicalOutputIncludesStandingInvariant(t *testing.T) {
	input := validCharter()
	normalized, err := Normalize(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalBytes(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"standing_no_goals":[{"id":"standing-no-derived-goals","statement":"Existing code, tests, defenses, and review-introduced machinery create no goals."}]`) {
		t.Fatalf("canonical normalized charter missing standing invariant: %s", encoded)
	}
}

func hashFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "charter", name))
	if err != nil {
		t.Fatal(err)
	}
	input, err := ReadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := Normalize(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := Hash(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func normalizeError(input Charter) error {
	_, err := Normalize(input, nil)
	return err
}

func charterWithMutatedDimension(t *testing.T, dimensionName string, mutate func(map[string]any)) Charter {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "charter", "base-charter.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	envelope, ok := payload["operational_envelope"].(map[string]any)
	if !ok {
		t.Fatalf("operational_envelope missing from fixture: %#v", payload)
	}
	dimension, ok := envelope[dimensionName].(map[string]any)
	if !ok {
		t.Fatalf("dimension %q missing from fixture: %#v", dimensionName, envelope)
	}
	mutate(dimension)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input, err := ReadBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func assertDiagnosticCode(t *testing.T, diagnostics []diag.Diagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want code %s", diagnostics, code)
}

func assertValidationDiagnostic(t *testing.T, err error, code string, path string) {
	t.Helper()
	validation, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error = %T %v, want ValidationError", err, err)
	}
	for _, diagnostic := range validation.Diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want code %s at %s", validation.Diagnostics, code, path)
}

func validCharter() Charter {
	return Charter{
		SchemaVersion:       SchemaVersion,
		Goals:               []Statement{{ID: "goal-api", Statement: "The API reports accepted input deterministically."}},
		NonGoals:            []Statement{},
		OwnerEvents:         []OwnerEvent{{ID: "event-1", Type: "charter_initialized", Actor: "owner", Summary: "Initial charter."}},
		OperationalEnvelope: validEnvelope(),
	}
}

func validEnvelope() *OperationalEnvelope {
	return &OperationalEnvelope{
		EntryPoints: &Dimension{
			State:     StateBounded,
			Statement: "Declared entry points.",
			Entries: []Entry{
				{ID: "cli", Statement: "Command line interface."},
				{ID: "http", Statement: "HTTP API."},
			},
		},
		InputSurface: &Dimension{
			State:     StateUnbounded,
			Statement: "Caller supplied request payloads.",
			Entries:   []Entry{},
		},
		ValidStates: &Dimension{
			State:     StateBounded,
			Statement: "Declared valid runtime states.",
			Entries:   []Entry{{ID: "normal", Statement: "Normal configured operation."}},
		},
		Environments: &Dimension{
			State:     StateNotApplicable,
			Statement: "No environment distinction is declared.",
			Entries:   []Entry{},
		},
		ScaleBounds: &Dimension{
			State:     StateUnspecified,
			Statement: "Scale is intentionally unspecified.",
			Entries:   []Entry{},
		},
		CompatibilityPromises: &Dimension{
			State:     StateBounded,
			Statement: "Declared compatibility promises.",
			Entries:   []Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
		},
		ThreatModel: &Dimension{
			State:     StateUnbounded,
			Statement: "Threat scenarios must name concrete exercised behavior.",
			Entries:   []Entry{},
		},
	}
}
