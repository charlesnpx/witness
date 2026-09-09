package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayv2"
)

func TestDecodeCompileReportContractDigestsRejectsEmptyDigest(t *testing.T) {
	reportID := RequiredRecipes[0].ID
	contractID := RequiredRecipes[0].ContractID
	_, err := DecodeCompileReportContractDigests(reportID, map[string]any{contractID: " "})
	if err == nil {
		t.Fatal("shared compile-report digest decoder accepted a blank digest")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeContractDigestMalformed {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeContractDigestMalformed)
	}
	if diagnostic.Details["report_id"] != reportID || diagnostic.Details["contract_id"] != contractID || diagnostic.Details["value_type"] != "string" {
		t.Fatalf("diagnostic details = %#v", diagnostic.Details)
	}
}

func TestDecodeCompileReportContractDigestsRejectsMalformedDigestSyntax(t *testing.T) {
	reportID := RequiredRecipes[0].ID
	contractID := RequiredRecipes[0].ContractID
	_, err := DecodeCompileReportContractDigests(reportID, map[string]any{contractID: "not-a-digest"})
	if err == nil {
		t.Fatal("shared compile-report digest decoder accepted a syntactically invalid digest")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeContractDigestMalformed {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeContractDigestMalformed)
	}
	if diagnostic.Details["contract_id"] != contractID || diagnostic.Details["value"] != "not-a-digest" {
		t.Fatalf("diagnostic details = %#v", diagnostic.Details)
	}
}

func TestResolveRelayReportedContractDigestsRejectsMalformedPlanDigest(t *testing.T) {
	contractID := RequiredRecipes[0].ContractID
	_, err := ResolveRelayReportedContractDigests(map[string]string{}, contractID, "not-a-digest")
	if err == nil {
		t.Fatal("resolver accepted a syntactically invalid plan digest")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeContractDigestMalformed {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeContractDigestMalformed)
	}
}

func TestSelectedContractPreflightAuthenticationMatchesAssemblyDiagnostic(t *testing.T) {
	contractID := "witnessed-review/economy-equivalence-v2"
	_, contractBody := requiredContractForTest(t)
	payload := map[string]any{"contracts": map[string]any{contractID: contractBody}}
	raw := canonjson.MustMarshal(payload)
	witnessDigest, err := digest.SemanticJSON(contractBody)
	if err != nil {
		t.Fatal(err)
	}
	relayDigest := digest.RawBytes([]byte("relay-projection:" + contractID))
	ref := contracts.ArtifactRef{
		Kind:          "selected-contract",
		ID:            "selected-contract",
		Digest:        relayDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
	assemblyDiagnostics := planning.SelectedContractManifestDiagnostics(
		[]contracts.ArtifactRef{ref},
		[]planning.SelectedContractEvidence{{
			Ref:        ref,
			ContractID: contractID,
			RawBytes:   raw,
		}},
	)
	if len(assemblyDiagnostics) != 1 {
		t.Fatalf("assembly diagnostics = %#v, want one", assemblyDiagnostics)
	}

	preflightDiagnostics := selectedContractAuthenticationDiagnostics(
		[]contracts.ArtifactRef{ref},
		[]planning.SelectedContractEvidence{{
			Ref:        ref,
			ContractID: contractID,
			RawBytes:   raw,
		}},
	)
	if len(preflightDiagnostics) != 1 {
		t.Fatalf("preflight diagnostics = %#v, want one", preflightDiagnostics)
	}
	if !reflect.DeepEqual(preflightDiagnostics[0], assemblyDiagnostics[0]) {
		t.Fatalf("preflight diagnostic = %#v, want assembly diagnostic %#v", preflightDiagnostics[0], assemblyDiagnostics[0])
	}
	if got := preflightDiagnostics[0].Details["contract_id"]; got != contractID {
		t.Fatalf("contract_id detail = %v, want %s", got, contractID)
	}
	if got := preflightDiagnostics[0].Details["witness_digest"]; got != witnessDigest {
		t.Fatalf("witness_digest = %v, want %s", got, witnessDigest)
	}
	if got := preflightDiagnostics[0].Details["relay_reported_digest"]; got != relayDigest {
		t.Fatalf("relay_reported_digest = %v, want %s", got, relayDigest)
	}
}

func TestRelayAbsentRejectsMalformedWitnessIntegrationBundle(t *testing.T) {
	root := t.TempDir()
	fixture := loadFixture[map[string]any](t, "integration-bundle-v2.fixture.json")
	fixtureContracts := fixture["contracts"].(map[string]any)
	economyContract := fixtureContracts["witnessed-review/economy-equivalence-v2"].(map[string]any)
	economyContract["turns"].([]any)[0].(map[string]any)["participant_turn"] = 0
	economyContract["inputs"].(map[string]any)["charter"].(map[string]any)["max_bytes"] = -1
	economyContract["result"].(map[string]any)["transport"] = "nonsense"
	nestedContracts := map[string]any{
		"witnessed-review/witness-falsification-v2": fixtureContracts["witnessed-review/witness-falsification-v2"],
	}
	bundlePath := filepath.Join(root, "bundle.json")
	writeCanonicalForTest(t, bundlePath, map[string]any{
		"schema_version": "relay-integration-bundle-v1",
		"id":             "",
		"contracts": map[string]any{
			"witnessed-review/economy-equivalence-v2": economyContract,
		},
		"nested": map[string]any{
			"contracts": nestedContracts,
		},
	})

	result, err := Run(context.Background(), Options{
		RelayPath:             filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath: bundlePath,
		StateDir:              filepath.Join(root, "state"),
	})
	if err == nil {
		t.Fatal("relay-absent preflight accepted a malformed integration bundle")
	}
	if result.OK {
		t.Fatalf("result.OK = true, diagnostics = %#v", result.Diagnostics)
	}
	if !hasDiagnostic(result.Diagnostics, CodeRecipeContractMismatch) {
		t.Fatalf("diagnostics = %#v, want %s", result.Diagnostics, CodeRecipeContractMismatch)
	}
}

func TestValidateWitnessIntegrationBundleRejectsMalformedRequiredContracts(t *testing.T) {
	tests := []struct {
		name            string
		canonicalBundle bool
		mutate          func(string, map[string]any, map[string]any)
		wantPath        string
	}{
		{
			name: "body contract id matching map key",
			mutate: func(contractID string, _ map[string]any, contract map[string]any) {
				contract["id"] = contractID
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/id",
		},
		{
			name: "missing reducer object",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				delete(contract, "reducer")
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/reducer",
		},
		{
			name: "empty reducer instructions",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["reducer"].(map[string]any)["instructions"] = ""
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/reducer/instructions",
		},
		{
			name: "empty turn slot",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["turns"].([]any)[0].(map[string]any)["slot"] = ""
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/turns/0/slot",
		},
		{
			name: "empty turn instructions",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["turns"].([]any)[0].(map[string]any)["instructions"] = " "
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/turns/0/instructions",
		},
		{
			name: "turn slots do not match alternating schedule",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				slots := []string{"slot_0", "slot_0", "slot_0", "slot_1"}
				for index, slot := range slots {
					contract["turns"].([]any)[index].(map[string]any)["slot"] = slot
				}
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/turns/1/slot",
		},
		{
			name: "unknown bundle root field",
			mutate: func(_ string, bundle map[string]any, _ map[string]any) {
				bundle["extra"] = true
			},
			wantPath: "/extra",
		},
		{
			name: "unknown contract field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["extra"] = true
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/extra",
		},
		{
			name: "unknown result field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["result"].(map[string]any)["extra"] = true
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/result/extra",
		},
		{
			name: "unknown turn field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["turns"].([]any)[0].(map[string]any)["extra"] = true
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/turns/0/extra",
		},
		{
			name: "unknown reducer field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["reducer"].(map[string]any)["extra"] = true
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/reducer/extra",
		},
		{
			name: "unknown prompt context field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["prompt_context"].(map[string]any)["extra"] = true
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/prompt_context/extra",
		},
		{
			name: "unknown input field",
			mutate: func(_ string, _ map[string]any, contract map[string]any) {
				contract["inputs"].(map[string]any)["charter"].(map[string]any)["path"] = "/tmp/value"
			},
			wantPath: "/contracts/witnessed-review~1economy-equivalence-v2/inputs/charter/path",
		},
		{
			name:            "unknown top-level contract",
			canonicalBundle: true,
			mutate: func(_ string, bundle map[string]any, _ map[string]any) {
				bundle["contracts"].(map[string]any)["unused"] = map[string]any{"extra": true}
			},
			wantPath: "/contracts/unused",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contractID, contract := requiredContractForTest(t)

			bundle := map[string]any{
				"schema_version": relayIntegrationBundleV2,
				"id":             "test-bundle",
				"contracts": map[string]any{
					contractID: contract,
				},
			}
			if test.canonicalBundle {
				bundle = loadFixture[map[string]any](t, "integration-bundle-v2.fixture.json")
				contracts, ok := bundle["contracts"].(map[string]any)
				if !ok {
					t.Fatalf("contracts = %T, want object", bundle["contracts"])
				}
				contract, ok = contracts[contractID].(map[string]any)
				if !ok {
					t.Fatalf("%s contract = %T, want object", contractID, contracts[contractID])
				}
			}
			test.mutate(contractID, bundle, contract)

			_, diagnostics := validateWitnessIntegrationBundle(bundle)
			requireContractMismatchAtPath(t, diagnostics, test.wantPath)
		})
	}

	t.Run("canonical fixture is accepted unchanged", func(t *testing.T) {
		fixture := loadFixture[map[string]any](t, "integration-bundle-v2.fixture.json")
		contracts, ok := fixture["contracts"].(map[string]any)
		if !ok {
			t.Fatalf("contracts = %T, want object", fixture["contracts"])
		}

		contractsByID, diagnostics := validateWitnessIntegrationBundle(fixture)
		if len(diagnostics) > 0 {
			t.Fatalf("expected no diagnostics for canonical fixture, got %v", diagnostics)
		}
		for contractID := range contracts {
			if _, ok := contractsByID[contractID]; !ok {
				t.Fatalf("expected contract %q to be accepted from canonical fixture", contractID)
			}
		}
	})
}

func TestValidateRequiredContractStructureRejectsUnexpectedArtifactMediaTypePresence(t *testing.T) {
	contractID, contract := requiredContractForTest(t)
	artifact := contract["inputs"].(map[string]any)["artifact"].(map[string]any)
	artifact["media_type"] = json.Number("7")

	diagnostics := validateRequiredContractStructure(contractID, contract)
	requireContractMismatchAtPath(t, diagnostics, "/contracts/witnessed-review~1economy-equivalence-v2/inputs/artifact/media_type")
}

func TestValidateRequiredContractStructureRejectsFractionalMaxBytes(t *testing.T) {
	contractID, contract := requiredContractForTest(t)
	artifact := contract["inputs"].(map[string]any)["artifact"].(map[string]any)
	artifact["max_bytes"] = json.Number("0.5")

	diagnostics := validateRequiredContractStructure(contractID, contract)
	requireContractMismatchAtPath(t, diagnostics, "/contracts/witnessed-review~1economy-equivalence-v2/inputs/artifact/max_bytes")
}

func TestRunRecordsAuthUnknownStrata(t *testing.T) {
	stateDir := t.TempDir()
	bundlePath := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")
	result, err := Run(context.Background(), Options{
		RelayPath:             presentRelayPath(t),
		IntegrationBundlePath: bundlePath,
		StateDir:              stateDir,
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

func TestRunReportsRetainedArtifactPaths(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "app.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		RelayPath:             filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath: filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json"),
		StateDir:              stateDir,
		SourceDir:             sourceDir,
		SnapshotDir:           filepath.Join(stateDir, "source-snapshot"),
		AllowNonGitSource:     true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v\nDiagnostics: %#v", err, result.Diagnostics)
	}
	want := map[string]string{
		"compatibility_manifest": "compatibility-manifest.json",
		"relay_capabilities":     "relay-capabilities.json",
		"integration_bundle":     RetainedIntegrationBundleBodyFile,
		"source_manifest":        "source-snapshot/manifest.json",
		"workspace_manifest":     "source-snapshot/manifest.json",
	}
	for role, relativePath := range want {
		if got := result.RetainedArtifacts[role]; got != relativePath {
			t.Fatalf("retained artifact %s = %q, want %q; all = %#v", role, got, relativePath, result.RetainedArtifacts)
		}
	}
	for role, relativePath := range result.RetainedArtifacts {
		if _, err := os.Stat(filepath.Join(stateDir, filepath.FromSlash(relativePath))); err != nil {
			t.Fatalf("retained artifact %s at %s: %v", role, relativePath, err)
		}
	}
}

func TestRetainedIntegrationBundleBodyAuthenticatesPlannedBinding(t *testing.T) {
	stateDir := t.TempDir()
	bundlePath := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")
	authoredBody, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		RelayPath:             filepath.Join(t.TempDir(), "missing-convo-relay"),
		IntegrationBundlePath: bundlePath,
		StateDir:              stateDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	bodyPath := filepath.Join(stateDir, RetainedIntegrationBundleBodyFile)
	retainedBody, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retainedBody, authoredBody) {
		t.Fatalf("retained integration bundle body differs from authored bytes")
	}
	actualDigest, err := digest.SemanticJSONBytes(retainedBody)
	if err != nil {
		t.Fatal(err)
	}
	if actualDigest != result.ContractDigests["integration_bundle"] || actualDigest != result.ArtifactDigests[RetainedIntegrationBundleBodyFile] {
		t.Fatalf("retained body digest = %q, contracts=%#v, artifacts=%#v", actualDigest, result.ContractDigests, result.ArtifactDigests)
	}
	if result.RetainedArtifacts["integration_bundle"] != RetainedIntegrationBundleBodyFile {
		t.Fatalf("retained integration bundle = %q, want %q", result.RetainedArtifacts["integration_bundle"], RetainedIntegrationBundleBodyFile)
	}
}

func TestRunRelayPresentRetainsLocalCompatibilityProjection(t *testing.T) {
	stateDir := t.TempDir()
	bundlePath := filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json")
	result, err := Run(context.Background(), Options{
		RelayPath:             presentRelayPath(t),
		IntegrationBundlePath: bundlePath,
		StateDir:              stateDir,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v\nDiagnostics: %#v", err, result.Diagnostics)
	}
	if RelayAbsent(*result) {
		t.Fatalf("backend strata = %#v, unexpectedly relay_absent", result.BackendStrata)
	}
	retainedCapabilities, _ := retainedPreflightPayloadBytes(t, filepath.Join(stateDir, "relay-capabilities.json"))
	capabilities, err := strictjson.DecodeBytes[map[string]any](retainedCapabilities, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities["source"] != nil || capabilities["schema_version"] != "witness-relay-v2-compatibility-projection-v1" {
		t.Fatalf("retained local Relay projection = %#v", capabilities)
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

func TestRunRejectsSnapshotManifestMissingEmbeddedDigest(t *testing.T) {
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
	manifest := readJSONForTest[freeze.Manifest](t, snapshot.ManifestPath)
	manifest.Source.ManifestDigest = ""
	writeCanonicalForTest(t, snapshot.ManifestPath, manifest)

	result, err := Run(context.Background(), Options{
		RelayPath:              filepath.Join(root, "missing-convo-relay"),
		IntegrationBundlePath:  filepath.Join("..", "..", "testdata", "preflight", "integration-bundle-v2.fixture.json"),
		StateDir:               filepath.Join(root, "state"),
		SnapshotManifestPath:   snapshot.ManifestPath,
		ExpectedSnapshotDigest: snapshot.ManifestDigest,
	})
	if err == nil {
		t.Fatal("Run accepted a snapshot manifest missing an embedded digest")
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

func requiredContractForTest(t *testing.T) (string, map[string]any) {
	t.Helper()
	const contractID = "witnessed-review/economy-equivalence-v2"
	fixture := loadFixture[map[string]any](t, "integration-bundle-v2.fixture.json")
	contracts, ok := fixture["contracts"].(map[string]any)
	if !ok {
		t.Fatalf("contracts = %T, want object", fixture["contracts"])
	}
	contract, ok := contracts[contractID].(map[string]any)
	if !ok {
		t.Fatalf("%s contract = %T, want object", contractID, contracts[contractID])
	}
	return contractID, contract
}

func readJSONForTest[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func writeCanonicalForTest(t *testing.T, path string, value any) {
	t.Helper()
	data, err := canonjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
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

func requireContractMismatchAtPath(t *testing.T, diagnostics []diag.Diagnostic, path string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeRecipeContractMismatch && diagnostic.Path == path {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want %s at %s", diagnostics, CodeRecipeContractMismatch, path)
}

func findDiagnostic(diagnostics []diag.Diagnostic, code string) (diag.Diagnostic, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return diagnostic, true
		}
	}
	return diag.Diagnostic{}, false
}

func presentRelayPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), relayv2.DefaultExecutable)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
