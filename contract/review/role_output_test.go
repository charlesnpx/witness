package review

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/strictjson"
)

func TestRoleOutputFixturesRemainValid(t *testing.T) {
	frozen := reviewTestFrozenCharter(t)
	for _, name := range []string{
		"role-output-defect.json",
		"role-output-defect-v3.json",
		"role-output-economy.json",
		"role-output-goal-fit.json",
	} {
		t.Run(name, func(t *testing.T) {
			document := readRoleFixture(t, name)
			document.CharterHash = frozen.CharterHash
			if diagnostics := ValidateRoleOutput(document, frozen); len(diagnostics) > 0 {
				t.Fatalf("ValidateRoleOutput diagnostics = %#v", diagnostics)
			}
			if _, err := RoleOutputDigest(document); err != nil {
				t.Fatalf("RoleOutputDigest: %v", err)
			}
		})
	}
}

func TestRoleOutputValidationAndV3Compatibility(t *testing.T) {
	frozen := reviewTestFrozenCharter(t)

	t.Run("invalid anchor surfaces charter diagnostic", func(t *testing.T) {
		document := readRoleFixture(t, "role-output-defect.json")
		document.CharterHash = frozen.CharterHash
		document.Findings[0].ScopeAnchors[0].EntryID = "missing"
		assertDiagnosticCode(t, ValidateRoleOutput(document, frozen), charter.CodeInvalidScopeAnchor)
	})

	t.Run("proposed test lacking Charter trace rejected", func(t *testing.T) {
		document := readRoleFixture(t, "role-output-defect.json")
		document.CharterHash = frozen.CharterHash
		document.Findings[0].ProposedTests[0].CharterRefs = nil
		assertDiagnosticCode(t, ValidateRoleOutput(document, frozen), CodeMissingCharterTrace)
	})

	t.Run("v4 attribution is constrained", func(t *testing.T) {
		for _, attribution := range []string{
			FindingAttributionIntroduced,
			FindingAttributionWorsened,
			FindingAttributionPreExisting,
			FindingAttributionUnattributed,
		} {
			t.Run(attribution, func(t *testing.T) {
				document := readRoleFixture(t, "role-output-defect.json")
				document.CharterHash = frozen.CharterHash
				document.Findings[0].Attribution = attribution
				if diagnostics := ValidateRoleOutput(document, frozen); len(diagnostics) != 0 {
					t.Fatalf("ValidateRoleOutput diagnostics = %#v", diagnostics)
				}
			})
		}
		document := readRoleFixture(t, "role-output-defect.json")
		document.CharterHash = frozen.CharterHash
		document.Findings[0].Attribution = "unknown"
		assertDiagnosticCode(t, ValidateRoleOutput(document, frozen), CodeInvalidRoleOutput)
	})

	t.Run("v3 findings remain unattributed", func(t *testing.T) {
		document := readRoleFixture(t, "role-output-defect-v3.json")
		document.CharterHash = frozen.CharterHash
		if diagnostics := ValidateRoleOutput(document, frozen); len(diagnostics) != 0 {
			t.Fatalf("ValidateRoleOutput diagnostics = %#v", diagnostics)
		}
		if got := document.EffectiveFindingAttribution(document.Findings[0]); got != FindingAttributionUnattributed {
			t.Fatalf("effective attribution = %q, want %q", got, FindingAttributionUnattributed)
		}
	})
}

func TestRoleOutputEvaluationRequiresV5(t *testing.T) {
	frozen := reviewTestFrozenCharter(t)
	for _, schemaVersion := range []string{RoleOutputV3, RoleOutputV4} {
		t.Run(schemaVersion, func(t *testing.T) {
			name := "role-output-defect.json"
			if schemaVersion == RoleOutputV3 {
				name = "role-output-defect-v3.json"
			}
			document := readRoleFixture(t, name)
			document.CharterHash = frozen.CharterHash
			document.Evaluation = &RoleEvaluation{
				EvaluatedPaths:          []string{"cmd/witness/main.go"},
				EvaluatedCharterGoalIDs: []string{"goal-cli"},
			}
			assertDiagnosticCode(t, ValidateRoleOutput(document, frozen), CodeInvalidRoleOutput)
		})
	}

	valid := readRoleFixture(t, "role-output-defect.json")
	valid.SchemaVersion = RoleOutputV5
	valid.CharterHash = frozen.CharterHash
	valid.Evaluation = &RoleEvaluation{
		EvaluatedPaths:          []string{"cmd/witness/main.go"},
		EvaluatedCharterGoalIDs: []string{"goal-cli"},
	}
	if diagnostics := ValidateRoleOutput(valid, frozen); len(diagnostics) != 0 {
		t.Fatalf("valid v5 evaluation diagnostics = %#v", diagnostics)
	}
	valid.Evaluation.EvaluatedPaths = []string{"cmd/witness/main.go", "cmd/witness/main.go"}
	assertDiagnosticCode(t, ValidateRoleOutput(valid, frozen), CodeInvalidRoleOutput)
}

func TestDeltaEstimateTracksExplicitZeroPresence(t *testing.T) {
	explicit, err := strictjson.DecodeBytes[DeltaEstimate]([]byte(`{"status":"known","files":0}`), strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !explicit.FilesPresent() || explicit.Files != 0 {
		t.Fatalf("files presence/value = %v/%d, want explicit zero", explicit.FilesPresent(), explicit.Files)
	}
	if explicit.LinesPresent() {
		t.Fatal("lines presence = true, want omitted")
	}

	malformed, err := strictjson.DecodeBytes[DeltaEstimate]([]byte(`{"status":"model-specific","files":2}`), strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if malformed.Status != DeltaStatusUnknown || malformed.Files != 0 || malformed.FilesPresent() {
		t.Fatalf("malformed delta = %#v, want unknown without file presence", malformed)
	}
}

func TestCanonicalJSONRejectsDecodedValueMutation(t *testing.T) {
	document := readRoleFixture(t, "role-output-defect.json")

	finding := document.Findings[0]
	finding.Title = "mutated finding"
	if _, err := FindingCanonicalJSON(finding); err == nil {
		t.Fatal("FindingCanonicalJSON accepted a mutated decoded finding")
	} else {
		assertFiledValueMutation(t, err)
	}

	witness := document.Findings[0].Witness
	witness.Content = "mutated witness"
	if _, err := WitnessCanonicalJSON(witness); err == nil {
		t.Fatal("WitnessCanonicalJSON accepted a mutated decoded witness")
	} else {
		assertFiledValueMutation(t, err)
	}
}

func TestRoleOutputRejectsEmptyMissingGoalQuestion(t *testing.T) {
	frozen := reviewTestFrozenCharter(t)
	document := readRoleFixture(t, "role-output-goal-fit.json")
	document.CharterHash = frozen.CharterHash
	document.MissingGoalQuestions = []MissingGoalQuestion{{}}
	assertDiagnosticCode(t, ValidateRoleOutput(document, frozen), CodeInvalidRoleOutput)
}

func readRoleFixture(t *testing.T, name string) RoleOutputDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", name))
	if err != nil {
		t.Fatal(err)
	}
	document, err := ReadRoleOutputBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func reviewTestFrozenCharter(t *testing.T) *charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-cli",
			Statement: "The CLI accepts declared valid inputs deterministically.",
		}},
		NonGoals: []charter.Statement{},
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

func assertFiledValueMutation(t *testing.T, err error) {
	t.Helper()
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || len(validationErr.Diagnostics) == 0 {
		t.Fatalf("error = %v, want ValidationError", err)
	}
	if validationErr.Diagnostics[0].Code != CodeFiledValueMutated {
		t.Fatalf("diagnostics = %#v, want %s", validationErr.Diagnostics, CodeFiledValueMutated)
	}
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
