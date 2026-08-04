package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/relayclient"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	SchemaVersion = "witness-verification-preflight-v1"

	relayIntegrationBundleV2 = "relay-integration-bundle-v2"

	CodeMissingStateDir             = "preflight_missing_state_dir"
	CodeStateDirInsideSource        = "preflight_state_dir_inside_source"
	CodeMissingIntegrationBundle    = "preflight_missing_integration_bundle"
	CodeIntegrationBundleReadFailed = "preflight_integration_bundle_read_failed"
	CodeRelayVersionMismatch        = "preflight_relay_version_mismatch"
	CodeMissingCapability           = "preflight_missing_relay_capability"
	CodeMissingRecipe               = "preflight_missing_recipe"
	CodeRecipeContractMismatch      = "preflight_recipe_contract_mismatch"
	CodeRecipeUnavailable           = "preflight_recipe_unavailable"
	CodeBackendMissing              = "preflight_backend_missing"
	CodeBackendUnavailable          = "preflight_backend_unavailable"
	CodeCompileCommandFailed        = "preflight_compile_command_failed"
	CodeCompileRequiresIntegration  = "preflight_compile_requires_integration"
	CodeCompileIncompatible         = "preflight_compile_incompatible"
	CodeCompileReportError          = "preflight_compile_report_error"
	CodeCompileReportMismatch       = "preflight_compile_report_mismatch"
	CodeCompilePlanMissing          = "preflight_compile_plan_missing"
	CodeContractDigestMissing       = "preflight_contract_digest_missing"
	CodeInvalidRecipeID             = "preflight_invalid_recipe_id"
	CodeMissingFreezeInput          = "preflight_missing_freeze_input"
	CodeSnapshotDigestMismatch      = "preflight_snapshot_digest_mismatch"
	CodeInvalidSnapshotManifest     = "preflight_invalid_snapshot_manifest"
)

type Options struct {
	RelayPath              string
	IntegrationBundlePath  string
	StateDir               string
	SourceDir              string
	SnapshotDir            string
	SnapshotManifestPath   string
	ExpectedSnapshotDigest string
	AllowNonGitSource      bool
	ConsumerIdentity       map[string]any
	Runner                 relayclient.Runner
}

type Result struct {
	SchemaVersion        string            `json:"schema_version"`
	OK                   bool              `json:"ok"`
	StateDir             string            `json:"state_dir"`
	RelayVersion         string            `json:"relay_version,omitempty"`
	ArtifactDigests      map[string]string `json:"artifact_digests"`
	CompileReportDigests map[string]string `json:"compile_report_digests"`
	RecipePlanDigests    map[string]string `json:"recipe_plan_digests"`
	ContractDigests      map[string]string `json:"contract_digests"`
	BackendStrata        map[string]string `json:"backend_strata"`
	SnapshotDigest       string            `json:"snapshot_digest,omitempty"`
	ConsumerIdentity     map[string]any    `json:"consumer_identity"`
	Diagnostics          []diag.Diagnostic `json:"diagnostics,omitempty"`
}

type Error struct {
	Diagnostics []diag.Diagnostic
}

func (err *Error) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return ""
	}
	if len(err.Diagnostics) == 1 {
		return fmt.Sprintf("%s: %s", err.Diagnostics[0].Code, err.Diagnostics[0].Message)
	}
	return fmt.Sprintf("%s: %s (%d diagnostics)", err.Diagnostics[0].Code, err.Diagnostics[0].Message, len(err.Diagnostics))
}

type CapabilityRequirement struct {
	Family     string `json:"family"`
	Capability any    `json:"capability"`
	Location   string `json:"location"`
}

type RecipeRequirement struct {
	ID         string `json:"id"`
	ContractID string `json:"contract_id"`
}

type requiredContractInput struct {
	name         string
	required     bool
	cardinality  string
	mediaType    string
	schemaObject bool
}

var RequiredCapabilities = []CapabilityRequirement{
	{Family: "portable_export", Capability: "relay-root-portable-export-v2", Location: "/portable_export"},
	{Family: "provider_invocation", Capability: "relay-provider-invocation-v2", Location: "/provider_invocation"},
	{Family: "digest_profile", Capability: digest.Profile, Location: "/digest_profile"},
	{Family: "prompt_policy", Capability: "prompt-policy/v2", Location: "/prompt_policy"},
	{Family: "isolation_report", Capability: "relay-workspace-isolation-v1", Location: "/isolation_report"},
	{Family: "prompt_context_projection", Capability: "relay-prompt-context-v1", Location: "/prompt_context_projection"},
	{Family: "provider_retry_policy", Capability: "relay-provider-retry-policy-v1", Location: "/provider_retry_policy"},
	{Family: "rendered_prompt", Capability: "relay-rendered-prompt-v1", Location: "/rendered_prompt"},
	{Family: "contracts.integration_bundle", Capability: "relay-integration-bundle-v2", Location: "/contracts/integration_bundle"},
	{Family: "contracts.selected_integration_contract", Capability: json.Number("2"), Location: "/contracts/selected_integration_contract"},
	{Family: "contracts.recipe", Capability: json.Number("2"), Location: "/contracts/recipe"},
	{Family: "contracts.root_artifact", Capability: json.Number("2"), Location: "/contracts/root_artifact"},
	{Family: "contracts.root_recipe_plan", Capability: json.Number("2"), Location: "/contracts/root_recipe_plan"},
	{Family: "contracts.root_session_result", Capability: json.Number("2"), Location: "/contracts/root_session_result"},
	{Family: "contracts.execution_workspace", Capability: json.Number("2"), Location: "/contracts/execution_workspace"},
}

var RequiredRecipes = []RecipeRequirement{
	{ID: "witness-falsify-v2", ContractID: "witnessed-review/witness-falsification-v2"},
	{ID: "witness-falsify-v2-codex", ContractID: "witnessed-review/witness-falsification-v2"},
	{ID: "witness-falsify-v2-claude", ContractID: "witnessed-review/witness-falsification-v2"},
	{ID: "economy-equivalence-v2", ContractID: "witnessed-review/economy-equivalence-v2"},
	{ID: "economy-equivalence-v2-codex", ContractID: "witnessed-review/economy-equivalence-v2"},
	{ID: "economy-equivalence-v2-claude", ContractID: "witnessed-review/economy-equivalence-v2"},
}

var requiredWitnessContractInputs = []requiredContractInput{
	{name: "charter", required: true, cardinality: "one", mediaType: "application/json", schemaObject: true},
	{name: "findings", required: true, cardinality: "one", mediaType: "application/json", schemaObject: true},
	{name: "artifact", required: false, cardinality: "many"},
}

var requiredBackends = []string{"claude", "codex"}

func Run(ctx context.Context, options Options) (*Result, error) {
	result := &Result{
		SchemaVersion:        SchemaVersion,
		StateDir:             options.StateDir,
		ArtifactDigests:      map[string]string{},
		CompileReportDigests: map[string]string{},
		RecipePlanDigests:    map[string]string{},
		ContractDigests:      map[string]string{},
		BackendStrata:        map[string]string{},
		ConsumerIdentity:     consumerIdentity(options.ConsumerIdentity),
	}
	var diagnostics []diag.Diagnostic
	if options.StateDir == "" {
		return result, &Error{Diagnostics: []diag.Diagnostic{diag.FromError(diag.New(CodeMissingStateDir, "preflight state directory is required."))}}
	}
	if options.SourceDir != "" {
		if diagnostic, err := stateDirInsideSourceDiagnostic(options.SourceDir, options.StateDir); err != nil {
			return result, err
		} else if diagnostic.Code != "" {
			return finish(result, []diag.Diagnostic{diagnostic})
		}
	}
	if err := os.MkdirAll(options.StateDir, 0o755); err != nil {
		return result, err
	}

	if options.SnapshotManifestPath != "" {
		snapshotDigest, err := existingSnapshotDigest(options.SnapshotManifestPath, options.ExpectedSnapshotDigest)
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
		} else {
			result.SnapshotDigest = snapshotDigest
			result.ArtifactDigests["source-snapshot-manifest"] = snapshotDigest
		}
	} else if options.SourceDir != "" || options.SnapshotDir != "" {
		if options.SourceDir == "" || options.SnapshotDir == "" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeMissingFreezeInput, "source_dir and snapshot_dir must be provided together.")))
		} else {
			snapshot, err := freeze.Create(ctx, freeze.Options{
				SourceDir:   options.SourceDir,
				OutputDir:   options.SnapshotDir,
				AllowNonGit: options.AllowNonGitSource,
			})
			if err != nil {
				diagnostics = append(diagnostics, diag.FromError(err))
			} else {
				result.SnapshotDigest = snapshot.ManifestDigest
				result.ArtifactDigests["source-snapshot-manifest"] = snapshot.ManifestDigest
			}
		}
	}

	client := relayclient.Client{
		Executable: options.RelayPath,
		Runner:     options.Runner,
	}

	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		if relayMissing(err) {
			return runRelayAbsentPreflight(result, options, err, diagnostics)
		}
		diagnostics = append(diagnostics, commandDiagnostic("capabilities", err))
		return finish(result, diagnostics)
	}
	result.RelayVersion = capabilities.ConvoRelayVersion
	if retainedDigest, err := retain(options.StateDir, "relay-capabilities.json", capabilities); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["relay-capabilities.json"] = retainedDigest
	}
	diagnostics = append(diagnostics, ValidateCapabilities(capabilities)...)

	recipes, err := client.RecipesList(ctx)
	if err != nil {
		diagnostics = append(diagnostics, commandDiagnostic("recipes list", err))
		return finish(result, diagnostics)
	}
	if retainedDigest, err := retain(options.StateDir, "recipes-list.json", recipes); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["recipes-list.json"] = retainedDigest
	}
	diagnostics = append(diagnostics, ValidateRecipes(recipes)...)

	backends, err := client.BackendStatus(ctx)
	if err != nil {
		diagnostics = append(diagnostics, commandDiagnostic("backends status", err))
		return finish(result, diagnostics)
	}
	if retainedDigest, err := retain(options.StateDir, "backend-status.json", backends); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["backend-status.json"] = retainedDigest
	}
	strata, backendDiagnostics := BackendStrata(backends)
	result.BackendStrata = strata
	diagnostics = append(diagnostics, backendDiagnostics...)

	bundlePayload, bundleDigest, bundleDiagnostics := loadIntegrationBundle(options.IntegrationBundlePath)
	diagnostics = append(diagnostics, bundleDiagnostics...)
	if len(bundleDiagnostics) == 0 {
		result.ContractDigests["integration_bundle"] = bundleDigest
		if retainedDigest, err := retain(options.StateDir, "integration-bundle.json", bundlePayload); err != nil {
			return result, err
		} else {
			result.ArtifactDigests["integration-bundle.json"] = retainedDigest
		}
	}

	compileReports := map[string]relayclient.CompileReport{}
	if len(diagnostics) == 0 {
		for _, requirement := range RequiredRecipes {
			report, err := client.CompileRecipe(ctx, requirement.ID, options.IntegrationBundlePath)
			relative := filepath.ToSlash(filepath.Join("compile-reports", requirement.ID+".json"))
			if err != nil {
				if retainedDigest, retainErr := retainCommandFailure(options.StateDir, relative, err); retainErr != nil {
					return result, retainErr
				} else if retainedDigest != "" {
					result.CompileReportDigests[requirement.ID] = retainedDigest
					result.ArtifactDigests[relative] = retainedDigest
				}
				diagnostics = append(diagnostics, compileCommandDiagnostic(requirement.ID, err))
				continue
			}
			compileReports[requirement.ID] = report
			if retainedDigest, err := retain(options.StateDir, relative, report.Payload); err != nil {
				return result, err
			} else {
				result.CompileReportDigests[requirement.ID] = retainedDigest
				result.ArtifactDigests[relative] = retainedDigest
			}
			diagnostics = append(diagnostics, EvaluateCompileReport(requirement, report)...)
			if report.RootRecipePlan != nil {
				planRelative := filepath.ToSlash(filepath.Join("recipe-plans", requirement.ID+".json"))
				if retainedDigest, err := retain(options.StateDir, planRelative, report.RootRecipePlan); err != nil {
					return result, err
				} else {
					result.RecipePlanDigests[requirement.ID] = retainedDigest
					result.ArtifactDigests[planRelative] = retainedDigest
				}
			}
		}
	}

	contractDigests, contractDiagnostics := selectedContractDigests(bundlePayload, compileReports)
	diagnostics = append(diagnostics, contractDiagnostics...)
	for contractID, contractDigest := range contractDigests {
		result.ContractDigests[contractID] = contractDigest
	}
	contractDigestDoc := map[string]any{
		"schema_version":   "witness-preflight-contract-digests-v1",
		"digest_profile":   digest.Profile,
		"contract_digests": result.ContractDigests,
	}
	if retainedDigest, err := retain(options.StateDir, "contract-digests.json", contractDigestDoc); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["contract-digests.json"] = retainedDigest
	}

	compatibility := compatibilityManifest(result, diagnostics)
	if retainedDigest, err := retain(options.StateDir, "compatibility-manifest.json", compatibility); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["compatibility-manifest.json"] = retainedDigest
	}

	return finish(result, diagnostics)
}

func existingSnapshotDigest(path string, expectedDigest string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", diag.Wrap(
			err,
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest could not be read.",
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return "", diag.Wrap(
			err,
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest could not be decoded.",
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if manifest.SchemaVersion != freeze.SchemaVersion {
		return "", diag.New(
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest schema_version is unsupported.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual", manifest.SchemaVersion),
			diag.WithDetail("expected", freeze.SchemaVersion),
		)
	}
	if manifest.DigestProfile != digest.Profile {
		return "", diag.New(
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest digest_profile is unsupported.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual", manifest.DigestProfile),
			diag.WithDetail("expected", digest.Profile),
		)
	}
	actualDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return "", diag.Wrap(
			err,
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest digest could not be recomputed.",
			diag.WithDetail("path", path),
		)
	}
	for label, embedded := range map[string]string{
		"source":    manifest.Source.ManifestDigest,
		"workspace": manifest.Workspace.ManifestDigest,
	} {
		if strings.TrimSpace(embedded) == "" {
			return "", diag.New(
				CodeSnapshotDigestMismatch,
				"existing snapshot manifest is missing an embedded digest.",
				diag.WithDetail("path", path),
				diag.WithDetail("location", label),
				diag.WithDetail("expected_digest", actualDigest),
			)
		}
		if embedded != actualDigest {
			return "", diag.New(
				CodeSnapshotDigestMismatch,
				"existing snapshot manifest embedded digest does not match its content.",
				diag.WithDetail("path", path),
				diag.WithDetail("location", label),
				diag.WithDetail("actual_digest", actualDigest),
				diag.WithDetail("expected_digest", embedded),
			)
		}
	}
	if expectedDigest != "" && actualDigest != expectedDigest {
		return "", diag.New(
			CodeSnapshotDigestMismatch,
			"existing snapshot manifest digest does not match the expected frozen snapshot.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", expectedDigest),
		)
	}
	return actualDigest, nil
}

func runRelayAbsentPreflight(result *Result, options Options, launchErr error, diagnostics []diag.Diagnostic) (*Result, error) {
	result.BackendStrata = relayAbsentBackendStrata()
	if retainedDigest, err := retain(options.StateDir, "relay-capabilities.json", relayAbsentCapabilitiesPayload(options.RelayPath, launchErr)); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["relay-capabilities.json"] = retainedDigest
	}
	if retainedDigest, err := retain(options.StateDir, "backend-status.json", relayAbsentBackendStatusPayload(options.RelayPath, launchErr)); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["backend-status.json"] = retainedDigest
	}
	if retainedDigest, err := retain(options.StateDir, "recipes-list.json", relayAbsentRecipesListPayload(options.RelayPath, launchErr)); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["recipes-list.json"] = retainedDigest
	}
	for _, requirement := range RequiredRecipes {
		relative := filepath.ToSlash(filepath.Join("compile-reports", requirement.ID+".json"))
		payload := relayAbsentCompileReportPayload(requirement, options.RelayPath, launchErr)
		if retainedDigest, err := retain(options.StateDir, relative, payload); err != nil {
			return result, err
		} else {
			result.CompileReportDigests[requirement.ID] = retainedDigest
			result.ArtifactDigests[relative] = retainedDigest
		}
	}

	bundlePayload, bundleDigest, bundleDiagnostics := loadIntegrationBundle(options.IntegrationBundlePath)
	diagnostics = append(diagnostics, bundleDiagnostics...)
	if len(bundleDiagnostics) == 0 {
		result.ContractDigests["integration_bundle"] = bundleDigest
		if retainedDigest, err := retain(options.StateDir, "integration-bundle.json", bundlePayload); err != nil {
			return result, err
		} else {
			result.ArtifactDigests["integration-bundle.json"] = retainedDigest
		}
		contractDigests, contractDiagnostics := selectedContractDigestsFromBundle(bundlePayload)
		diagnostics = append(diagnostics, contractDiagnostics...)
		for contractID, contractDigest := range contractDigests {
			result.ContractDigests[contractID] = contractDigest
		}
	}

	contractDigestDoc := map[string]any{
		"schema_version":   "witness-preflight-contract-digests-v1",
		"digest_profile":   digest.Profile,
		"contract_digests": result.ContractDigests,
	}
	if retainedDigest, err := retain(options.StateDir, "contract-digests.json", contractDigestDoc); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["contract-digests.json"] = retainedDigest
	}

	compatibility := compatibilityManifest(result, diagnostics)
	if retainedDigest, err := retain(options.StateDir, "compatibility-manifest.json", compatibility); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["compatibility-manifest.json"] = retainedDigest
	}
	return finish(result, diagnostics)
}

func ValidateCapabilities(capabilities relayclient.Capabilities) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if capabilities.ConvoRelayVersion != relayclient.RequiredConvoRelayVersion {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRelayVersionMismatch,
			"relay version does not exactly match the supported compatibility baseline.",
			diag.WithDetail("got", capabilities.ConvoRelayVersion),
			diag.WithDetail("want", relayclient.RequiredConvoRelayVersion),
		)))
	}
	for _, requirement := range RequiredCapabilities {
		if !capabilityPresent(capabilities, requirement) {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeMissingCapability,
				"relay capabilities are missing an exact required public contract.",
				diag.WithPath(requirement.Location),
				diag.WithDetail("family", requirement.Family),
				diag.WithDetail("capability", requirement.Capability),
			)))
		}
	}
	return diagnostics
}

func ValidateRecipes(list relayclient.RecipesList) []diag.Diagnostic {
	recipes := map[string]relayclient.Recipe{}
	for _, recipe := range list.Recipes {
		recipes[recipe.ID] = recipe
	}
	var diagnostics []diag.Diagnostic
	for _, requirement := range RequiredRecipes {
		recipe, ok := recipes[requirement.ID]
		if !ok {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeMissingRecipe,
				"required v2 structural relay recipe is missing.",
				diag.WithDetail("recipe_id", requirement.ID),
			)))
			continue
		}
		if recipe.Status != "usable" && recipe.Status != "requires_integration" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeRecipeUnavailable,
				"required v2 structural relay recipe is not usable or waiting for integration.",
				diag.WithDetail("recipe_id", requirement.ID),
				diag.WithDetail("status", recipe.Status),
			)))
		}
		if declaredContract, _ := recipe.Declared["integration_contract"].(string); declaredContract != requirement.ContractID {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeRecipeContractMismatch,
				"required v2 structural relay recipe is bound to an unexpected integration contract.",
				diag.WithDetail("recipe_id", requirement.ID),
				diag.WithDetail("got", declaredContract),
				diag.WithDetail("want", requirement.ContractID),
			)))
		}
	}
	return diagnostics
}

func BackendStrata(status relayclient.BackendStatus) (map[string]string, []diag.Diagnostic) {
	records := map[string]relayclient.BackendRecord{}
	for _, backend := range status.Backends {
		records[backend.Backend] = backend
	}
	strata := map[string]string{}
	var diagnostics []diag.Diagnostic
	for _, name := range requiredBackends {
		record, ok := records[name]
		if !ok {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeBackendMissing,
				"required relay backend family is missing.",
				diag.WithDetail("backend", name),
			)))
			continue
		}
		strata[name] = record.Status
		if !backendAttemptable(record.Status) {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeBackendUnavailable,
				"required relay backend family is not attemptable.",
				diag.WithDetail("backend", name),
				diag.WithDetail("status", record.Status),
			)))
		}
	}
	return strata, diagnostics
}

func EvaluateCompileReport(requirement RecipeRequirement, report relayclient.CompileReport) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if report.RecipeID != "" && report.RecipeID != requirement.ID {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeCompileReportMismatch,
			"compile report recipe_id does not match the requested recipe.",
			diag.WithDetail("recipe_id", requirement.ID),
			diag.WithDetail("reported_recipe_id", report.RecipeID),
		)))
	}
	if report.IntegrationContract != "" && report.IntegrationContract != requirement.ContractID {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"compile report selected an unexpected integration contract.",
			diag.WithDetail("recipe_id", requirement.ID),
			diag.WithDetail("got", report.IntegrationContract),
			diag.WithDetail("want", requirement.ContractID),
		)))
	}
	for _, relayDiagnostic := range report.Diagnostics {
		switch {
		case integrationRequiredFailure(relayDiagnostic.Code):
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeCompileRequiresIntegration,
				"compile report still requires an integration binding.",
				diag.WithDetail("recipe_id", requirement.ID),
				diag.WithDetail("relay_code", relayDiagnostic.Code),
				diag.WithDetail("relay_message", relayDiagnostic.Message),
			)))
		case integrationBindingFailure(relayDiagnostic.Code):
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeCompileIncompatible,
				"compile report indicates the recipe is unbound or incompatible with the integration bundle.",
				diag.WithDetail("recipe_id", requirement.ID),
				diag.WithDetail("relay_code", relayDiagnostic.Code),
				diag.WithDetail("relay_message", relayDiagnostic.Message),
			)))
		}
	}
	switch report.Status {
	case "", "usable", "ok":
	case "requires_integration":
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeCompileRequiresIntegration,
			"compile report still requires an integration binding.",
			diag.WithDetail("recipe_id", requirement.ID),
		)))
	case "error", "failed":
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeCompileReportError,
			"compile report returned an error status.",
			diag.WithDetail("recipe_id", requirement.ID),
			diag.WithDetail("status", report.Status),
		)))
	default:
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeCompileReportError,
			"compile report returned an unsupported status.",
			diag.WithDetail("recipe_id", requirement.ID),
			diag.WithDetail("status", report.Status),
		)))
	}
	if report.RootRecipePlan == nil {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeCompilePlanMissing,
			"compile report did not include a retained root recipe plan.",
			diag.WithDetail("recipe_id", requirement.ID),
		)))
	}
	if strings.TrimSpace(report.IntegrationContractDigest) == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeContractDigestMissing,
			"compile report did not include the selected integration contract digest.",
			diag.WithDetail("recipe_id", requirement.ID),
			diag.WithDetail("contract_id", requirement.ContractID),
		)))
	}
	return diagnostics
}

func capabilityPresent(capabilities relayclient.Capabilities, requirement CapabilityRequirement) bool {
	if strings.HasPrefix(requirement.Family, "contracts.") {
		name := strings.TrimPrefix(requirement.Family, "contracts.")
		return anySliceContains(capabilities.Contracts[name], requirement.Capability)
	}
	return stringSliceContains(capabilityStrings(capabilities, requirement.Family), fmt.Sprint(requirement.Capability))
}

func capabilityStrings(capabilities relayclient.Capabilities, family string) []string {
	switch family {
	case "portable_export":
		return capabilities.PortableExport
	case "provider_invocation":
		return capabilities.ProviderInvocation
	case "digest_profile":
		return capabilities.DigestProfile
	case "prompt_policy":
		return capabilities.PromptPolicy
	case "isolation_report":
		return capabilities.IsolationReport
	case "prompt_context_projection":
		return capabilities.PromptContextProjection
	case "provider_retry_policy":
		return capabilities.ProviderRetryPolicy
	case "rendered_prompt":
		return capabilities.RenderedPrompt
	default:
		return nil
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func anySliceContains(values []any, want any) bool {
	for _, value := range values {
		if capabilityValueEqual(value, want) {
			return true
		}
	}
	return false
}

func capabilityValueEqual(got any, want any) bool {
	switch want := want.(type) {
	case json.Number:
		switch got := got.(type) {
		case json.Number:
			return got.String() == want.String()
		case int:
			return fmt.Sprint(got) == want.String()
		case int64:
			return fmt.Sprint(got) == want.String()
		case float64:
			return fmt.Sprintf("%.0f", got) == want.String()
		default:
			return false
		}
	case string:
		gotString, ok := got.(string)
		return ok && gotString == want
	default:
		return fmt.Sprint(got) == fmt.Sprint(want)
	}
}

func backendAttemptable(status string) bool {
	switch status {
	case "ready", "installed", "installed_auth_unknown", "auth_unknown":
		return true
	default:
		return false
	}
}

func RelayAbsent(result Result) bool {
	for _, backend := range requiredBackends {
		if result.BackendStrata[backend] != contracts.RelayLaunchStatusAbsent {
			return false
		}
	}
	return len(result.BackendStrata) > 0
}

func relayMissing(err error) bool {
	var commandError *relayclient.CommandError
	return errors.As(err, &commandError) && commandError.Kind == relayclient.ErrorRelayMissing
}

func relayAbsentBackendStrata() map[string]string {
	strata := make(map[string]string, len(requiredBackends))
	for _, backend := range requiredBackends {
		strata[backend] = contracts.RelayLaunchStatusAbsent
	}
	return strata
}

func relayAbsentCapabilitiesPayload(relayPath string, err error) map[string]any {
	payload := relayAbsentPayload("witness-relay-absent-capabilities-v1", relayPath, err)
	payload["capabilities"] = relayAbsentCapabilities()
	return payload
}

func relayAbsentRecipesListPayload(relayPath string, err error) map[string]any {
	payload := relayAbsentPayload("witness-relay-absent-recipes-list-v1", relayPath, err)
	payload["recipes"] = []any{}
	return payload
}

func relayAbsentBackendStatusPayload(relayPath string, err error) map[string]any {
	payload := relayAbsentPayload("witness-relay-absent-backend-status-v1", relayPath, err)
	backends := make([]map[string]string, 0, len(requiredBackends))
	for _, backend := range requiredBackends {
		backends = append(backends, map[string]string{
			"backend": backend,
			"status":  contracts.RelayLaunchStatusAbsent,
		})
	}
	payload["backends"] = backends
	return payload
}

func relayAbsentCompileReportPayload(requirement RecipeRequirement, relayPath string, err error) map[string]any {
	payload := relayAbsentPayload("witness-relay-absent-compile-report-v1", relayPath, err)
	payload["recipe_id"] = requirement.ID
	payload["contract_id"] = requirement.ContractID
	payload["status"] = contracts.RelayLaunchStatusAbsent
	return payload
}

func relayAbsentPayload(schemaVersion string, relayPath string, err error) map[string]any {
	payload := map[string]any{
		"schema_version":       schemaVersion,
		"digest_profile":       digest.Profile,
		"relay_launch_status":  contracts.RelayLaunchStatusAbsent,
		"relay_error_kind":     relayclient.ErrorRelayMissing,
		"relay_error_message":  err.Error(),
		"relay_executable":     relayExecutable(relayPath),
		"verification_effect":  contracts.DispositionPendingVerification,
		"verification_status":  contracts.RecordStatusUnavailable,
		"verification_reason":  "relay_verification_unavailable",
		"recorded_degradation": true,
	}
	var commandError *relayclient.CommandError
	if errors.As(err, &commandError) {
		payload["relay_command"] = commandError.Command
		payload["relay_args"] = append([]string(nil), commandError.Args...)
	}
	return payload
}

func relayAbsentCapabilities() map[string]bool {
	capabilities := make(map[string]bool, len(contracts.RequiredRelayCapabilityClosureV3))
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		capabilities[requirement.Key] = false
	}
	return capabilities
}

func relayExecutable(path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	return relayclient.DefaultExecutable
}

func integrationBindingFailure(code string) bool {
	switch strings.ToLower(code) {
	case "invalid_integration_bundle",
		"integration_contract_not_found",
		"integration_contract_incompatible",
		"integration_contract_id_mismatch":
		return true
	default:
		return false
	}
}

func integrationRequiredFailure(code string) bool {
	return strings.ToLower(code) == "integration_required"
}

func loadIntegrationBundle(path string) (any, string, []diag.Diagnostic) {
	if path == "" {
		return nil, "", []diag.Diagnostic{diag.FromError(diag.New(CodeMissingIntegrationBundle, "integration bundle path is required for root recipe compilation."))}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", []diag.Diagnostic{diag.FromError(diag.Wrap(
			err,
			CodeIntegrationBundleReadFailed,
			"integration bundle could not be read.",
			diag.WithDetail("path", path),
		))}
	}
	payload, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return nil, "", []diag.Diagnostic{diag.FromError(diag.Wrap(
			err,
			CodeIntegrationBundleReadFailed,
			"integration bundle must be strict JSON.",
			diag.WithDetail("path", path),
		))}
	}
	bundleDigest, err := digest.SemanticJSON(payload)
	if err != nil {
		return nil, "", []diag.Diagnostic{diag.FromError(diag.Wrap(
			err,
			CodeIntegrationBundleReadFailed,
			"integration bundle digest could not be computed.",
			diag.WithDetail("path", path),
		))}
	}
	return payload, bundleDigest, nil
}

func selectedContractDigests(bundlePayload any, reports map[string]relayclient.CompileReport) (map[string]string, []diag.Diagnostic) {
	digests := map[string]string{}
	var diagnostics []diag.Diagnostic
	for _, recipeID := range sortedCompileReportKeys(reports) {
		report := reports[recipeID]
		if report.RootRecipePlan != nil && strings.TrimSpace(report.IntegrationContractDigest) == "" {
			reportRecipeID := report.RecipeID
			if reportRecipeID == "" {
				reportRecipeID = recipeID
			}
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeContractDigestMissing,
				"compile report did not include the selected integration contract digest.",
				diag.WithDetail("recipe_id", reportRecipeID),
				diag.WithDetail("contract_id", report.IntegrationContract),
			)))
		}
		for _, contractID := range sortedStringMapKeys(report.ContractDigests) {
			contractDigest := report.ContractDigests[contractID]
			if contractID != "" && contractDigest != "" {
				digests[contractID] = contractDigest
			}
		}
	}
	if bundlePayload != nil {
		_, bundleDiagnostics := validateWitnessIntegrationBundle(bundlePayload)
		diagnostics = append(diagnostics, bundleDiagnostics...)
	}
	for _, contractID := range requiredWitnessContractIDs() {
		if len(reports) > 0 && digests[contractID] == "" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeContractDigestMissing,
				"compile reports did not include the required selected integration contract digest.",
				diag.WithDetail("contract_id", contractID),
			)))
		}
	}
	return digests, diagnostics
}

func selectedContractDigestsFromBundle(bundlePayload any) (map[string]string, []diag.Diagnostic) {
	digests := map[string]string{}
	contractsByID, diagnostics := validateWitnessIntegrationBundle(bundlePayload)
	if len(diagnostics) > 0 {
		return digests, diagnostics
	}
	for _, contractID := range requiredWitnessContractIDs() {
		contractDigest, err := digest.SemanticJSON(contractsByID[contractID])
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(diag.Wrap(
				err,
				CodeContractDigestMissing,
				"integration bundle required Witness contract digest could not be computed.",
				diag.WithDetail("contract_id", contractID),
			)))
			continue
		}
		digests[contractID] = contractDigest
	}
	return digests, diagnostics
}

func validateWitnessIntegrationBundle(bundlePayload any) (map[string]map[string]any, []diag.Diagnostic) {
	contractsByID := map[string]map[string]any{}
	var diagnostics []diag.Diagnostic
	root, ok := bundlePayload.(map[string]any)
	if !ok {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"integration bundle root must be a JSON object.",
		)))
		return contractsByID, diagnostics
	}
	if schemaVersion, _ := root["schema_version"].(string); schemaVersion != relayIntegrationBundleV2 {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"integration bundle schema_version must be relay-integration-bundle-v2.",
			diag.WithPath("/schema_version"),
			diag.WithDetail("actual", root["schema_version"]),
			diag.WithDetail("expected", relayIntegrationBundleV2),
		)))
	}
	if id, _ := root["id"].(string); strings.TrimSpace(id) == "" {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"integration bundle id must be a non-empty string.",
			diag.WithPath("/id"),
		)))
	}
	contractsMap, ok := root["contracts"].(map[string]any)
	if !ok {
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"integration bundle contracts must be a top-level object.",
			diag.WithPath("/contracts"),
		)))
		return contractsByID, diagnostics
	}
	for _, contractID := range requiredWitnessContractIDs() {
		payload, ok := contractsMap[contractID]
		if !ok {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeRecipeContractMismatch,
				"integration bundle top-level contracts object does not contain a required Witness contract.",
				diag.WithPath("/contracts"),
				diag.WithDetail("contract_id", contractID),
			)))
			continue
		}
		object, ok := payload.(map[string]any)
		if !ok {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeRecipeContractMismatch,
				"integration bundle required Witness contract must be a JSON object.",
				diag.WithPath("/contracts/"+jsonPointerEscape(contractID)),
				diag.WithDetail("contract_id", contractID),
			)))
			continue
		}
		if bodyID := contractIDValue(object); bodyID != "" && bodyID != contractID {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeRecipeContractMismatch,
				"integration bundle contract body id does not match the contract map key.",
				diag.WithPath("/contracts/"+jsonPointerEscape(contractID)+"/id"),
				diag.WithDetail("contract_id", contractID),
				diag.WithDetail("body_id", bodyID),
			)))
			continue
		}
		if contractDiagnostics := validateRequiredContractStructure(contractID, object); len(contractDiagnostics) > 0 {
			diagnostics = append(diagnostics, contractDiagnostics...)
			continue
		}
		contractsByID[contractID] = object
	}
	return contractsByID, diagnostics
}

func requiredWitnessContractIDs() []string {
	wanted := map[string]bool{}
	for _, requirement := range RequiredRecipes {
		wanted[requirement.ContractID] = true
	}
	return sortedBoolMapKeys(wanted)
}

func validateRequiredContractStructure(contractID string, object map[string]any) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireTurns(&diagnostics, contractID, object["turns"])
	requirePromptContext(&diagnostics, contractID, object)
	requireContractInputs(&diagnostics, contractID, object)
	result, ok := object["result"].(map[string]any)
	if !ok {
		diagnostics = append(diagnostics, contractStructureDiagnostic(contractID, "/result", "integration bundle required Witness contract result must be an object."))
		return diagnostics
	}
	if transport, _ := result["transport"].(string); transport != "json" {
		diagnostics = append(diagnostics, contractStructureDiagnostic(contractID, "/result/transport", "integration bundle required Witness contract result transport must be json."))
	}
	if _, ok := result["schema"].(map[string]any); !ok {
		diagnostics = append(diagnostics, contractStructureDiagnostic(contractID, "/result/schema", "integration bundle required Witness contract result schema must be an object."))
	}
	if _, ok := result["assertions"].([]any); !ok {
		diagnostics = append(diagnostics, contractStructureDiagnostic(contractID, "/result/assertions", "integration bundle required Witness contract result assertions must be an array."))
	}
	return diagnostics
}

func requireTurns(diagnostics *[]diag.Diagnostic, contractID string, value any) {
	turns, ok := value.([]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/turns", "integration bundle required Witness contract turns must be an array."))
		return
	}
	if len(turns) != 4 {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/turns", "integration bundle required Witness contract turns must contain exactly four participant turns."))
		return
	}
	for index, turn := range turns {
		object, ok := turn.(map[string]any)
		if !ok {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d", index), "integration bundle required Witness contract turn must be an object."))
			continue
		}
		expected := index + 1
		actual, ok := jsonNumberInt(object["participant_turn"])
		if !ok || actual != expected {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d/participant_turn", index), "integration bundle required Witness contract participant_turn numbering is invalid."))
		}
	}
}

func requirePromptContext(diagnostics *[]diag.Diagnostic, contractID string, object map[string]any) {
	promptContext, ok := object["prompt_context"].(map[string]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/prompt_context", "integration bundle required Witness contract prompt_context must be an object."))
		return
	}
	if participantTranscript, _ := promptContext["participant_transcript"].(string); participantTranscript != "complete" {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/prompt_context/participant_transcript", "integration bundle required Witness contract prompt_context participant_transcript must be complete."))
	}
	if facilitatorLedger, _ := promptContext["facilitator_ledger"].(string); facilitatorLedger != "trace_only" {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/prompt_context/facilitator_ledger", "integration bundle required Witness contract prompt_context facilitator_ledger must be trace_only."))
	}
}

func requireContractInputs(diagnostics *[]diag.Diagnostic, contractID string, contract map[string]any) {
	inputs, ok := contract["inputs"].(map[string]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs", "integration bundle required Witness contract inputs must be an object."))
		return
	}
	expectedInputs := map[string]bool{}
	for _, expected := range requiredWitnessContractInputs {
		expectedInputs[expected.name] = true
		requireContractInput(diagnostics, contractID, inputs, expected)
	}
	for inputName := range inputs {
		if !expectedInputs[inputName] {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+jsonPointerEscape(inputName), "integration bundle required Witness contract inputs must contain only charter, findings, and artifact."))
		}
	}
}

func requireContractInput(diagnostics *[]diag.Diagnostic, contractID string, inputs map[string]any, expected requiredContractInput) {
	input, ok := inputs[expected.name].(map[string]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name, "integration bundle required Witness contract input must be an object."))
		return
	}
	if value, ok := input["required"].(bool); !ok || value != expected.required {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/required", "integration bundle required Witness contract input required flag is invalid."))
	}
	if cardinality, _ := input["cardinality"].(string); cardinality != expected.cardinality {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/cardinality", "integration bundle required Witness contract input cardinality is invalid."))
	}
	if !positiveJSONNumber(input["max_bytes"]) {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/max_bytes", "integration bundle required Witness contract input max_bytes must be a positive number."))
	}
	mediaType, hasMediaType := input["media_type"].(string)
	if expected.mediaType == "" {
		if hasMediaType && strings.TrimSpace(mediaType) != "" {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/media_type", "integration bundle required Witness contract input media_type is not expected."))
		}
	} else if mediaType != expected.mediaType {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/media_type", "integration bundle required Witness contract input media_type is invalid."))
	}
	_, hasSchema := input["schema"].(map[string]any)
	if expected.schemaObject && !hasSchema {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/schema", "integration bundle required Witness contract input schema must be an object."))
	}
	if !expected.schemaObject {
		if _, exists := input["schema"]; exists {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/schema", "integration bundle required Witness contract input schema is not expected."))
		}
	}
}

func jsonNumberInt(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func positiveJSONNumber(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Float64()
	return err == nil && parsed > 0
}

func contractStructureDiagnostic(contractID string, path string, message string) diag.Diagnostic {
	return diag.FromError(diag.New(
		CodeRecipeContractMismatch,
		message,
		diag.WithPath("/contracts/"+jsonPointerEscape(contractID)+path),
		diag.WithDetail("contract_id", contractID),
	))
}

func jsonPointerEscape(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func contractIDValue(object map[string]any) string {
	for _, key := range []string{"id", "contract_id"} {
		if value, ok := object[key].(string); ok {
			return value
		}
	}
	return ""
}

func retain(stateDir string, relativePath string, payload any) (string, error) {
	if err := validateRelativeOutput(relativePath); err != nil {
		return "", err
	}
	payloadBytes, err := canonjson.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadDigest := digest.RawBytes(payloadBytes)
	envelope := map[string]any{
		"schema_version": "witness-retained-artifact-v1",
		"digest_profile": digest.Profile,
		"payload_digest": payloadDigest,
		"payload":        payload,
	}
	encoded, err := canonjson.Marshal(envelope)
	if err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return "", err
	}
	return payloadDigest, nil
}

func retainCommandFailure(stateDir string, relativePath string, err error) (string, error) {
	var commandError *relayclient.CommandError
	if !errors.As(err, &commandError) || strings.TrimSpace(commandError.Stdout) == "" {
		return "", nil
	}
	payload, decodeErr := strictjson.DecodeAnyBytes([]byte(commandError.Stdout), strictjson.DefaultMaxBytes)
	if decodeErr != nil {
		payload = map[string]any{
			"relay_error_kind": commandError.Kind,
			"stdout":           commandError.Stdout,
			"stderr":           commandError.Stderr,
			"exit_code":        commandError.ExitCode,
		}
	}
	return retain(stateDir, relativePath, payload)
}

func validateRelativeOutput(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return diag.New(CodeInvalidRecipeID, "preflight retained artifact path must be relative.", diag.WithDetail("path", path))
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return diag.New(CodeInvalidRecipeID, "preflight retained artifact path contains an unsafe segment.", diag.WithDetail("path", path))
		}
	}
	return nil
}

func stateDirInsideSourceDiagnostic(sourceDir string, stateDir string) (diag.Diagnostic, error) {
	sourceAbs, err := canonicalPath(sourceDir)
	if err != nil {
		return diag.Diagnostic{}, err
	}
	stateAbs, err := canonicalPath(stateDir)
	if err != nil {
		return diag.Diagnostic{}, err
	}
	if !pathInside(sourceAbs, stateAbs) {
		return diag.Diagnostic{}, nil
	}
	return diag.FromError(diag.New(
		CodeStateDirInsideSource,
		"preflight state directory must resolve outside the reviewed source tree.",
		diag.WithDetail("source_dir", sourceAbs),
		diag.WithDetail("state_dir", stateAbs),
	)), nil
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	}
	var missing []string
	current := absolute
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return absolute, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
	}
}

func pathInside(root string, child string) bool {
	if child == root {
		return true
	}
	relative, err := filepath.Rel(root, child)
	if err != nil {
		return false
	}
	return relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!filepath.IsAbs(relative)
}

func commandDiagnostic(command string, err error) diag.Diagnostic {
	var commandError *relayclient.CommandError
	if errors.As(err, &commandError) {
		return diag.FromError(diag.New(
			commandError.Kind,
			"relay command failed.",
			diag.WithDetail("command", command),
			diag.WithDetail("args", commandError.Args),
			diag.WithDetail("exit_code", commandError.ExitCode),
			diag.WithDetail("relay_diagnostic", commandError.Diagnostic),
		))
	}
	return diag.FromError(err)
}

func compileCommandDiagnostic(recipeID string, err error) diag.Diagnostic {
	var commandError *relayclient.CommandError
	if errors.As(err, &commandError) {
		if commandError.Kind == relayclient.ErrorNonzeroExit || commandError.Kind == relayclient.ErrorSchemaInvalid {
			if diagnostic, ok := typedCompileFailureDiagnostic(recipeID, commandError.Diagnostic); ok {
				return diagnostic
			}
		}
		return diag.FromError(diag.New(
			CodeCompileCommandFailed,
			"relay compile-recipe command failed.",
			diag.WithDetail("recipe_id", recipeID),
			diag.WithDetail("relay_error_kind", commandError.Kind),
			diag.WithDetail("exit_code", commandError.ExitCode),
			diag.WithDetail("stdout", commandError.Stdout),
			diag.WithDetail("stderr", commandError.Stderr),
		))
	}
	return diag.FromError(diag.Wrap(err, CodeCompileCommandFailed, "relay compile-recipe command failed.", diag.WithDetail("recipe_id", recipeID)))
}

func typedCompileFailureDiagnostic(recipeID string, relayDiagnostic diag.Diagnostic) (diag.Diagnostic, bool) {
	if relayDiagnostic.Code == "" {
		return diag.Diagnostic{}, false
	}
	details := map[string]any{
		"recipe_id":     recipeID,
		"relay_code":    relayDiagnostic.Code,
		"relay_message": relayDiagnostic.Message,
	}
	if relayDiagnostic.Path != "" {
		details["relay_path"] = relayDiagnostic.Path
	}
	for key, value := range relayDiagnostic.Details {
		details["relay_"+key] = value
	}
	switch {
	case relayDiagnostic.Code == relayclient.ErrorContractDigestMissing:
		if contractID, ok := relayDiagnostic.Details["integration_contract"].(string); ok && contractID != "" {
			details["contract_id"] = contractID
		}
		return diag.FromError(diag.New(
			CodeContractDigestMissing,
			"relay compile-recipe omitted the selected integration contract digest.",
			diag.WithDetails(details),
		)), true
	case integrationRequiredFailure(relayDiagnostic.Code):
		return diag.FromError(diag.New(
			CodeCompileRequiresIntegration,
			"relay compile-recipe still requires an integration binding.",
			diag.WithDetails(details),
		)), true
	case integrationBindingFailure(relayDiagnostic.Code):
		return diag.FromError(diag.New(
			CodeCompileIncompatible,
			"relay compile-recipe reported an unbound or incompatible integration bundle.",
			diag.WithDetails(details),
		)), true
	case relayDiagnostic.Code == relayclient.ErrorSchemaInvalid:
		return diag.FromError(diag.New(
			CodeCompileReportError,
			"relay compile-recipe emitted a schema-invalid diagnostic payload.",
			diag.WithDetails(details),
		)), true
	default:
		return diag.FromError(diag.New(
			CodeCompileReportError,
			"relay compile-recipe emitted a typed failure diagnostic.",
			diag.WithDetails(details),
		)), true
	}
}

func compatibilityManifest(result *Result, diagnostics []diag.Diagnostic) contracts.RelayCompatibility {
	relayAbsent := RelayAbsent(*result)
	capabilities := make(map[string]bool, len(contracts.RequiredRelayCapabilityClosureV3))
	missing := map[string]bool{}
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeMissingCapability {
			family, _ := diagnostic.Details["family"].(string)
			capability := fmt.Sprint(diagnostic.Details["capability"])
			for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
				if requirement.Family == family && fmt.Sprint(requirement.Capability) == capability {
					missing[requirement.Key] = true
				}
			}
		}
	}
	for _, requirement := range contracts.RequiredRelayCapabilityClosureV3 {
		capabilities[requirement.Key] = !relayAbsent && !missing[requirement.Key]
	}
	return contracts.RelayCompatibility{
		SchemaVersion:           contracts.RelayCompatibilityV3,
		ConvoRelayVersion:       result.RelayVersion,
		DigestProfile:           digest.Profile,
		Capabilities:            capabilities,
		CapabilitiesDigest:      result.ArtifactDigests["relay-capabilities.json"],
		IntegrationBundleDigest: result.ContractDigests["integration_bundle"],
		SelectedContracts:       relayCompatibilitySelectedContracts(result.ContractDigests),
		RecipePlans:             relayCompatibilityRecipePlans(result.RecipePlanDigests, relayAbsent),
		CompileReports:          relayCompatibilityCompileReports(result.CompileReportDigests, relayAbsent),
		BackendStatus:           relayCompatibilityBackendStatus(result.BackendStrata),
		ConsumerIdentity:        consumerIdentity(result.ConsumerIdentity),
	}
}

func relayCompatibilitySelectedContracts(contractDigests map[string]string) []contracts.ContractDigest {
	seen := map[string]bool{}
	selected := make([]contracts.ContractDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		if seen[requirement.ContractID] {
			continue
		}
		seen[requirement.ContractID] = true
		selected = append(selected, contracts.ContractDigest{
			ContractID: requirement.ContractID,
			Digest:     contractDigests[requirement.ContractID],
		})
	}
	return selected
}

func relayCompatibilityRecipePlans(recipePlanDigests map[string]string, relayAbsent bool) []contracts.RecipePlanDigest {
	if relayAbsent {
		return nil
	}
	plans := make([]contracts.RecipePlanDigest, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		plans = append(plans, contracts.RecipePlanDigest{
			RecipeID:   requirement.RecipeID,
			ContractID: requirement.ContractID,
			Digest:     recipePlanDigests[requirement.RecipeID],
		})
	}
	return plans
}

func relayCompatibilityCompileReports(compileReportDigests map[string]string, relayAbsent bool) []contracts.CompileReportRef {
	reports := make([]contracts.CompileReportRef, 0, len(contracts.RequiredWitnessRecipeContractsV2))
	for _, requirement := range contracts.RequiredWitnessRecipeContractsV2 {
		reportDigest := compileReportDigests[requirement.RecipeID]
		status := "retained"
		if relayAbsent {
			status = contracts.RelayLaunchStatusAbsent
		}
		reports = append(reports, contracts.CompileReportRef{
			RecipeID: requirement.RecipeID,
			Status:   status,
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
	return reports
}

func relayCompatibilityBackendStatus(strata map[string]string) []contracts.BackendStatus {
	status := make([]contracts.BackendStatus, 0, len(requiredBackends))
	for _, backend := range requiredBackends {
		status = append(status, contracts.BackendStatus{
			Backend: backend,
			Status:  strata[backend],
		})
	}
	return status
}

func consumerIdentity(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{"kind": "witness", "id": "verification-preflight"}
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func sortedCompileReportKeys(reports map[string]relayclient.CompileReport) []string {
	keys := make([]string, 0, len(reports))
	for key := range reports {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedBoolMapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func finish(result *Result, diagnostics []diag.Diagnostic) (*Result, error) {
	diag.Sort(diagnostics)
	result.Diagnostics = diagnostics
	result.OK = len(diagnostics) == 0
	if result.OK {
		return result, nil
	}
	return result, &Error{Diagnostics: diagnostics}
}
