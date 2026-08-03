package preflight

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
	"witness/internal/relayclient"
	"witness/internal/strictjson"
)

type fakeRunner struct {
	t        *testing.T
	fixtures string
}

func (runner fakeRunner) Run(ctx context.Context, executable string, args ...string) relayclient.CommandResult {
	runner.t.Helper()
	switch {
	case len(args) == 2 && args[0] == "capabilities" && args[1] == "--json":
		return relayclient.CommandResult{Stdout: runner.fixture("relay-capabilities-v1.json")}
	case len(args) == 3 && args[0] == "recipes" && args[1] == "list" && args[2] == "--json":
		return relayclient.CommandResult{Stdout: runner.fixture("recipes-list-v1.json")}
	case len(args) == 3 && args[0] == "backends" && args[1] == "status" && args[2] == "--json":
		return relayclient.CommandResult{Stdout: runner.fixture("backend-status-v1.json")}
	case len(args) >= 2 && args[0] == "compile-recipe":
		recipeID := argValue(args, "--recipe")
		contractID := contractForRecipe(recipeID)
		if contractID == "" {
			return relayclient.CommandResult{Stdout: []byte(`{"message":"unknown recipe"}`), ExitCode: 1, Err: errors.New("exit status 1")}
		}
		return relayclient.CommandResult{Stdout: runner.fixture("compile-" + recipeID + ".json")}
	default:
		runner.t.Fatalf("unexpected relay args: %v", args)
		return relayclient.CommandResult{}
	}
}

func (runner fakeRunner) fixture(name string) []byte {
	data, err := os.ReadFile(filepath.Join(runner.fixtures, name))
	if err != nil {
		runner.t.Fatal(err)
	}
	return data
}

func TestValidateCapabilitiesReportsMissingExactCapability(t *testing.T) {
	capabilities := loadFixture[relayclient.Capabilities](t, "relay-capabilities-v1.json")
	capabilities.ProviderInvocation = nil
	diagnostics := ValidateCapabilities(capabilities)
	if !hasDiagnostic(diagnostics, CodeMissingCapability) {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if got := diagnostics[0].Details["family"]; got != "provider_invocation" {
		t.Fatalf("family = %v, want provider_invocation", got)
	}
}

func TestValidateCapabilitiesReportsRelayVersionMismatch(t *testing.T) {
	capabilities := loadFixture[relayclient.Capabilities](t, "relay-capabilities-v1.json")
	capabilities.ConvoRelayVersion = "v1.4.1"
	diagnostics := ValidateCapabilities(capabilities)
	if !hasDiagnostic(diagnostics, CodeRelayVersionMismatch) {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestEvaluateCompileReportStatuses(t *testing.T) {
	requirement := RecipeRequirement{ID: "witness-falsify-v2", ContractID: "witnessed-review/witness-falsification-v2"}
	contractDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tests := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{
			name: "usable",
			raw: map[string]any{
				"recipe_id":            requirement.ID,
				"status":               "usable",
				"integration_contract": requirement.ContractID,
				"root_recipe_plan": map[string]any{
					"recipe_id":                   requirement.ID,
					"integration_contract_digest": contractDigest,
				},
			},
		},
		{
			name: "requires integration",
			raw: map[string]any{
				"recipe_id":            requirement.ID,
				"status":               "requires_integration",
				"integration_contract": requirement.ContractID,
				"root_recipe_plan": map[string]any{
					"recipe_id":                   requirement.ID,
					"integration_contract_digest": contractDigest,
				},
			},
			want: CodeCompileRequiresIntegration,
		},
		{
			name: "error",
			raw: map[string]any{
				"recipe_id":            requirement.ID,
				"status":               "error",
				"integration_contract": requirement.ContractID,
				"root_recipe_plan": map[string]any{
					"recipe_id":                   requirement.ID,
					"integration_contract_digest": contractDigest,
				},
			},
			want: CodeCompileReportError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := relayclient.NewCompileReport(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics := EvaluateCompileReport(requirement, report)
			if test.want == "" {
				if len(diagnostics) != 0 {
					t.Fatalf("diagnostics = %#v", diagnostics)
				}
				return
			}
			if !hasDiagnostic(diagnostics, test.want) {
				t.Fatalf("diagnostics = %#v, want %s", diagnostics, test.want)
			}
		})
	}
}

func TestCompileReportMissingDigestRejectedPerRecipe(t *testing.T) {
	missingRequirement := RequiredRecipes[1]
	siblingRequirement := RequiredRecipes[0]
	otherRequirement := RequiredRecipes[3]
	siblingDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	raw := map[string]any{
		"recipe_id":            missingRequirement.ID,
		"status":               "usable",
		"integration_contract": missingRequirement.ContractID,
		"compiled_plan": map[string]any{
			"recipe_id":               missingRequirement.ID,
			"integration_contract_id": missingRequirement.ContractID,
		},
	}
	if _, err := relayclient.NewCompileReport(raw); err == nil {
		t.Fatal("NewCompileReport succeeded without integration_contract_digest")
	} else if diagnostic := diag.FromError(err); diagnostic.Code != relayclient.ErrorContractDigestMissing {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, relayclient.ErrorContractDigestMissing)
	}

	missingReport := relayclient.CompileReport{
		RecipeID:            missingRequirement.ID,
		IntegrationContract: missingRequirement.ContractID,
		RootRecipePlan:      map[string]any{"recipe_id": missingRequirement.ID},
		ContractDigests:     map[string]string{},
	}
	if diagnostics := EvaluateCompileReport(missingRequirement, missingReport); !hasDiagnostic(diagnostics, CodeContractDigestMissing) {
		t.Fatalf("diagnostics = %#v, want %s", diagnostics, CodeContractDigestMissing)
	}

	_, diagnostics := selectedContractDigests(nil, map[string]relayclient.CompileReport{
		missingRequirement.ID: missingReport,
		siblingRequirement.ID: {
			RecipeID:                  siblingRequirement.ID,
			IntegrationContract:       siblingRequirement.ContractID,
			IntegrationContractDigest: siblingDigest,
			RootRecipePlan:            map[string]any{"recipe_id": siblingRequirement.ID},
			ContractDigests:           map[string]string{siblingRequirement.ContractID: siblingDigest},
		},
		otherRequirement.ID: {
			RecipeID:                  otherRequirement.ID,
			IntegrationContract:       otherRequirement.ContractID,
			IntegrationContractDigest: otherDigest,
			RootRecipePlan:            map[string]any{"recipe_id": otherRequirement.ID},
			ContractDigests:           map[string]string{otherRequirement.ContractID: otherDigest},
		},
	})
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want only %s", diagnostics, CodeContractDigestMissing)
	}
	diagnostic, ok := findDiagnostic(diagnostics, CodeContractDigestMissing)
	if !ok {
		t.Fatalf("diagnostics = %#v, want %s", diagnostics, CodeContractDigestMissing)
	}
	if got := diagnostic.Details["recipe_id"]; got != missingRequirement.ID {
		t.Fatalf("recipe_id = %v, want %s", got, missingRequirement.ID)
	}
}

func TestEvaluateCompileReportAcceptsRealCompiledPlanShape(t *testing.T) {
	requirement := RecipeRequirement{ID: "witness-falsify-v2", ContractID: "witnessed-review/witness-falsification-v2"}
	raw := loadFixture[map[string]any](t, "compile-witness-falsify-v2.json")
	report, err := relayclient.NewCompileReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if report.RootRecipePlan == nil {
		t.Fatal("RootRecipePlan is nil")
	}
	if report.IntegrationContract != requirement.ContractID {
		t.Fatalf("IntegrationContract = %s, want %s", report.IntegrationContract, requirement.ContractID)
	}
	if report.IntegrationContractDigest == "" {
		t.Fatal("IntegrationContractDigest is empty")
	}
	if got := report.ContractDigests[requirement.ContractID]; got != report.IntegrationContractDigest {
		t.Fatalf("contract digest = %s, want %s", got, report.IntegrationContractDigest)
	}
	diagnostics := EvaluateCompileReport(requirement, report)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestCompileCommandDiagnosticUsesTypedRelayCodes(t *testing.T) {
	commandError := &relayclient.CommandError{
		Kind: relayclient.ErrorNonzeroExit,
		Diagnostic: diag.Diagnostic{
			Code:    "integration_contract_not_found",
			Message: "Integration bundle does not implement the requested contract.",
			Path:    "/contracts/witnessed-review~1witness-falsification-v2",
			Details: map[string]any{
				"contract_id": "witnessed-review/witness-falsification-v2",
			},
		},
		ExitCode: 1,
	}
	diagnostic := compileCommandDiagnostic("witness-falsify-v2", commandError)
	if diagnostic.Code != CodeCompileIncompatible {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeCompileIncompatible)
	}
}

func TestRunRecordsAuthUnknownStrata(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "preflight")
	stateDir := t.TempDir()
	result, err := Run(context.Background(), Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: filepath.Join(fixtures, "integration-bundle-v2.fixture.json"),
		StateDir:              stateDir,
		Runner:                fakeRunner{t: t, fixtures: fixtures},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v\nDiagnostics: %#v", err, result.Diagnostics)
	}
	if result.BackendStrata["codex"] != "installed_auth_unknown" || result.BackendStrata["claude"] != "installed_auth_unknown" {
		t.Fatalf("backend strata = %#v", result.BackendStrata)
	}
	for _, requirement := range RequiredRecipes {
		if result.CompileReportDigests[requirement.ID] == "" {
			t.Fatalf("missing compile report digest for %s", requirement.ID)
		}
		if result.RecipePlanDigests[requirement.ID] == "" {
			t.Fatalf("missing recipe plan digest for %s", requirement.ID)
		}
		if result.ContractDigests[requirement.ContractID] == "" {
			t.Fatalf("missing contract digest for %s", requirement.ContractID)
		}
	}
	for _, path := range []string{
		"relay-capabilities.json",
		"backend-status.json",
		filepath.ToSlash(filepath.Join("compile-reports", "witness-falsify-v2.json")),
		"compatibility-manifest.json",
	} {
		if _, err := os.Stat(filepath.Join(stateDir, filepath.FromSlash(path))); err != nil {
			t.Fatalf("retained artifact %s: %v", path, err)
		}
	}
	compatibilityBytes, compatibilityPayloadDigest := retainedPreflightPayloadBytes(t, filepath.Join(stateDir, "compatibility-manifest.json"))
	compatibility, err := contracts.ReadRelayCompatibilityBytes(compatibilityBytes)
	if err != nil {
		t.Fatalf("compatibility round-trip decode: %v", err)
	}
	if diagnostics := contracts.ValidateRelayCompatibility(compatibility); len(diagnostics) != 0 {
		t.Fatalf("compatibility diagnostics = %#v", diagnostics)
	}
	compatibilityDigest, err := contracts.RelayCompatibilityDigest(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	if compatibilityPayloadDigest != compatibilityDigest || result.ArtifactDigests["compatibility-manifest.json"] != compatibilityDigest {
		t.Fatalf("compatibility digest payload=%s result=%s recomputed=%s", compatibilityPayloadDigest, result.ArtifactDigests["compatibility-manifest.json"], compatibilityDigest)
	}
}

func TestRunRelayPresentRetainsFixtureCapabilitiesByteIdentical(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "preflight")
	stateDir := t.TempDir()
	result, err := Run(context.Background(), Options{
		RelayPath:             "fake-relay",
		IntegrationBundlePath: filepath.Join(fixtures, "integration-bundle-v2.fixture.json"),
		StateDir:              stateDir,
		Runner:                fakeRunner{t: t, fixtures: fixtures},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v\nDiagnostics: %#v", err, result.Diagnostics)
	}
	if RelayAbsent(*result) {
		t.Fatalf("backend strata = %#v, unexpectedly relay_absent", result.BackendStrata)
	}
	retainedCapabilities, _ := retainedPreflightPayloadBytes(t, filepath.Join(stateDir, "relay-capabilities.json"))
	expectedCapabilities, err := canonjson.Marshal(loadFixture[any](t, "relay-capabilities-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retainedCapabilities, expectedCapabilities) {
		t.Fatalf("retained capabilities payload changed\nactual: %s\nwant:   %s", retainedCapabilities, expectedCapabilities)
	}
	compatibilityBytes, _ := retainedPreflightPayloadBytes(t, filepath.Join(stateDir, "compatibility-manifest.json"))
	compatibility, err := contracts.ReadRelayCompatibilityBytes(compatibilityBytes)
	if err != nil {
		t.Fatal(err)
	}
	if contracts.RelayCompatibilityRelayAbsent(compatibility) {
		t.Fatalf("compatibility backend status = %#v, unexpectedly relay_absent", compatibility.BackendStatus)
	}
}

func TestRunBindsExistingSnapshotManifestAndRejectsForgedReference(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	snapshotDir := filepath.Join(root, "snapshot")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "app.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := freeze.Create(context.Background(), freeze.Options{
		SourceDir:   sourceDir,
		OutputDir:   snapshotDir,
		AllowNonGit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixtureBundle := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")
	result, err := Run(context.Background(), Options{
		RelayPath:              filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath:  fixtureBundle,
		StateDir:               filepath.Join(root, "state-ok"),
		SnapshotManifestPath:   snapshot.ManifestPath,
		ExpectedSnapshotDigest: snapshot.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v\nDiagnostics: %#v", err, result.Diagnostics)
	}
	if result.SnapshotDigest != snapshot.ManifestDigest || result.ArtifactDigests["source-snapshot-manifest"] != snapshot.ManifestDigest {
		t.Fatalf("snapshot binding digest=%s artifact=%s want %s", result.SnapshotDigest, result.ArtifactDigests["source-snapshot-manifest"], snapshot.ManifestDigest)
	}

	forgedDigest := digest.RawBytes([]byte("forged snapshot"))
	result, err = Run(context.Background(), Options{
		RelayPath:              filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath:  fixtureBundle,
		StateDir:               filepath.Join(root, "state-forged"),
		SnapshotManifestPath:   snapshot.ManifestPath,
		ExpectedSnapshotDigest: forgedDigest,
	})
	if err == nil {
		t.Fatal("Run accepted forged snapshot reference")
	}
	if !hasDiagnostic(result.Diagnostics, CodeSnapshotDigestMismatch) {
		t.Fatalf("diagnostics = %#v, want %s", result.Diagnostics, CodeSnapshotDigestMismatch)
	}
}

func TestRunRejectsStateDirInsideSourceBeforeMkdirAll(t *testing.T) {
	sourceDir := t.TempDir()
	stateDir := filepath.Join(sourceDir, "state")
	result, err := Run(context.Background(), Options{
		StateDir:  stateDir,
		SourceDir: sourceDir,
	})
	if err == nil {
		t.Fatal("Run succeeded with state dir inside source")
	}
	if !hasDiagnostic(result.Diagnostics, CodeStateDirInsideSource) {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	if _, statErr := os.Stat(stateDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state dir was created before rejection: %v", statErr)
	}
}

func TestLiveRelayCompileReports(t *testing.T) {
	if os.Getenv("WITNESS_LIVE_RELAY") != "1" {
		t.Skip("set WITNESS_LIVE_RELAY=1 to compile recipes against the installed relay")
	}
	client := relayclient.New("convo-relay")
	bundlePath := shippedRelayIntegrationBundlePath()
	for _, requirement := range RequiredRecipes {
		report, err := client.CompileRecipe(context.Background(), requirement.ID, bundlePath)
		if err != nil {
			t.Fatalf("%s compile: %v", requirement.ID, err)
		}
		if diagnostics := EvaluateCompileReport(requirement, report); len(diagnostics) != 0 {
			t.Fatalf("%s diagnostics = %#v", requirement.ID, diagnostics)
		}
		if report.RootRecipePlan == nil {
			t.Fatalf("%s missing compiled plan", requirement.ID)
		}
		contractDigest := report.ContractDigests[requirement.ContractID]
		if contractDigest == "" {
			t.Fatalf("%s missing contract digest for %s", requirement.ID, requirement.ContractID)
		}
		t.Logf("%s retained compiled_plan and %s digest %s", requirement.ID, requirement.ContractID, contractDigest)
	}
}

func loadFixture[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "preflight", name))
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func retainedPreflightPayloadBytes(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("retained artifact is %T, want object", value)
	}
	payload, ok := envelope["payload"]
	if !ok {
		t.Fatal("retained artifact missing payload")
	}
	payloadDigest, ok := envelope["payload_digest"].(string)
	if !ok || payloadDigest == "" {
		t.Fatalf("payload_digest = %#v, want non-empty string", envelope["payload_digest"])
	}
	payloadBytes, err := canonjson.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return payloadBytes, payloadDigest
}

func hasDiagnostic(diagnostics []diag.Diagnostic, code string) bool {
	_, ok := findDiagnostic(diagnostics, code)
	return ok
}

func findDiagnostic(diagnostics []diag.Diagnostic, code string) (diag.Diagnostic, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return diagnostic, true
		}
	}
	return diag.Diagnostic{}, false
}

func argValue(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func contractForRecipe(recipeID string) string {
	for _, requirement := range RequiredRecipes {
		if requirement.ID == recipeID {
			return requirement.ContractID
		}
	}
	return ""
}
