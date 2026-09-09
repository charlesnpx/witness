package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayv2"

	"github.com/charlesnpx/convo-relay/v2/plan"
)

const (
	SchemaVersion = "witness-verification-preflight-v1"

	ContractDigestDocumentV2 = "witness-preflight-contract-digests-v2"

	// RetainedIntegrationBundleEnvelopeFile preserves the authenticated
	// retention envelope. RetainedIntegrationBundleBodyFile is the exact
	// authored JSON supplied to relay so a planned integration-bundle binding
	// can be satisfied without treating envelope bytes as bundle bytes.
	RetainedIntegrationBundleEnvelopeFile = "integration-bundle.json"
	RetainedIntegrationBundleBodyFile     = "integration-bundle.body.json"

	relayIntegrationBundleV2 = "relay-integration-bundle-v2"

	CodeMissingStateDir             = "preflight_missing_state_dir"
	CodeStateDirInsideSource        = "preflight_state_dir_inside_source"
	CodeMissingIntegrationBundle    = "preflight_missing_integration_bundle"
	CodeIntegrationBundleReadFailed = "preflight_integration_bundle_read_failed"
	CodeRecipeContractMismatch      = "preflight_recipe_contract_mismatch"
	CodeRecipePlanInvalid           = "preflight_recipe_plan_invalid"
	CodeContractDigestMissing       = "preflight_contract_digest_missing"
	CodeContractDigestDocument      = "preflight_contract_digest_document_invalid"
	CodeInvalidRecipeID             = "preflight_invalid_recipe_id"
	CodeMissingFreezeInput          = "preflight_missing_freeze_input"
	CodeSnapshotDigestMismatch      = "preflight_snapshot_digest_mismatch"
	CodeInvalidSnapshotManifest     = "preflight_invalid_snapshot_manifest"
	CodeCharterZeroGoals            = "charter_zero_goals"
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
	AllowDirtySource       bool
	FrozenCharter          *charter.FrozenCharter
	AllowEmptyCharter      bool
	ConsumerIdentity       map[string]any
}

type Result struct {
	SchemaVersion     string            `json:"schema_version"`
	OK                bool              `json:"ok"`
	StateDir          string            `json:"state_dir"`
	RetainedArtifacts map[string]string `json:"retained_artifacts"`
	RelayPresent      bool              `json:"relay_present"`
	ArtifactDigests   map[string]string `json:"artifact_digests"`
	ContractDigests   map[string]string `json:"contract_digests"`
	SnapshotDigest    string            `json:"snapshot_digest,omitempty"`
	SourceDirty       bool              `json:"source_dirty,omitempty"`
	SourceDirtyStatus string            `json:"source_dirty_status,omitempty"`
	ConsumerIdentity  map[string]any    `json:"consumer_identity"`
	Diagnostics       []diag.Diagnostic `json:"diagnostics,omitempty"`
}

// ContractDigestDocumentData is the version-aware interpretation of a retained
// contract-digests document.
type ContractDigestDocumentData struct {
	SchemaVersion  string
	WitnessDigests map[string]string
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

var requiredWitnessTurnSlots = []string{"slot_0", "slot_1", "slot_0", "slot_1"}

func Run(ctx context.Context, options Options) (*Result, error) {
	result := &Result{
		SchemaVersion:     SchemaVersion,
		StateDir:          options.StateDir,
		RetainedArtifacts: map[string]string{},
		ArtifactDigests:   map[string]string{},
		ContractDigests:   map[string]string{},
		ConsumerIdentity:  consumerIdentity(options.ConsumerIdentity),
	}
	var diagnostics []diag.Diagnostic
	if options.StateDir == "" {
		return result, &Error{Diagnostics: []diag.Diagnostic{diag.FromError(diag.New(CodeMissingStateDir, "preflight state directory is required."))}}
	}
	if diagnostic := reviewCharterDiagnostic(options.FrozenCharter, options.AllowEmptyCharter); diagnostic != nil {
		return finish(result, options, []diag.Diagnostic{*diagnostic})
	}
	if options.SourceDir != "" {
		if diagnostic, err := stateDirInsideSourceDiagnostic(options.SourceDir, options.StateDir); err != nil {
			return result, err
		} else if diagnostic.Code != "" {
			return finish(result, options, []diag.Diagnostic{diagnostic})
		}
	}
	if err := os.MkdirAll(options.StateDir, 0o755); err != nil {
		return result, err
	}

	if options.SnapshotManifestPath != "" {
		manifest, snapshotDigest, err := existingSnapshotDigest(options.SnapshotManifestPath, options.ExpectedSnapshotDigest)
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
		} else {
			result.SnapshotDigest = snapshotDigest
			result.ArtifactDigests["source-snapshot-manifest"] = snapshotDigest
			result.SourceDirty = manifest.Source.GitDirty
			result.SourceDirtyStatus = manifest.Source.GitDirtyStatus
		}
	} else if options.SourceDir != "" || options.SnapshotDir != "" {
		if options.SourceDir == "" || options.SnapshotDir == "" {
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeMissingFreezeInput, "source_dir and snapshot_dir must be provided together.")))
		} else {
			snapshot, err := freeze.Create(ctx, freeze.Options{
				SourceDir:        options.SourceDir,
				OutputDir:        options.SnapshotDir,
				AllowNonGit:      options.AllowNonGitSource,
				AllowDirtySource: options.AllowDirtySource,
			})
			if err != nil {
				diagnostics = append(diagnostics, diag.FromError(err))
			} else {
				result.SnapshotDigest = snapshot.ManifestDigest
				result.ArtifactDigests["source-snapshot-manifest"] = snapshot.ManifestDigest
				result.SourceDirty = snapshot.Manifest.Source.GitDirty
				result.SourceDirtyStatus = snapshot.Manifest.Source.GitDirtyStatus
			}
		}
	}

	if err := requireRelayExecutable(options.RelayPath); err != nil {
		if relayv2.IsRelayNotInstalled(err) {
			return runRelayAbsentPreflight(result, options, diagnostics)
		}
		diagnostics = append(diagnostics, diag.FromError(err))
		return finish(result, options, diagnostics)
	}

	result.RelayPresent = true

	bundlePayload, bundleDigest, bundleDiagnostics := loadIntegrationBundle(options.IntegrationBundlePath)
	diagnostics = append(diagnostics, bundleDiagnostics...)
	if len(bundleDiagnostics) == 0 {
		result.ContractDigests["integration_bundle"] = bundleDigest
		if retainedDigest, err := retain(options.StateDir, RetainedIntegrationBundleEnvelopeFile, bundlePayload); err != nil {
			return result, err
		} else {
			result.ArtifactDigests[RetainedIntegrationBundleEnvelopeFile] = retainedDigest
		}
		if retainedDigest, err := retainIntegrationBundleBody(options.StateDir, options.IntegrationBundlePath, bundleDigest); err != nil {
			return result, err
		} else {
			result.ArtifactDigests[RetainedIntegrationBundleBodyFile] = retainedDigest
		}
		selectedDigests, selectedDiagnostics := selectedContractDigestsFromBundle(bundlePayload)
		diagnostics = append(diagnostics, selectedDiagnostics...)
		for contractID, contractDigest := range selectedDigests {
			result.ContractDigests[contractID] = contractDigest
		}
	}

	if len(diagnostics) == 0 {
		for _, requirement := range RequiredRecipes {
			if err := validateRequiredRecipe(requirement); err != nil {
				diagnostics = append(diagnostics, diag.FromError(err))
			}
		}
	}

	contractDigestDoc := ContractDigestDocument(*result)
	if retainedDigest, err := retain(options.StateDir, "contract-digests.json", contractDigestDoc); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["contract-digests.json"] = retainedDigest
	}

	return finish(result, options, diagnostics)
}

func existingSnapshotDigest(path string, expectedDigest string) (freeze.Manifest, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return freeze.Manifest{}, "", diag.Wrap(
			err,
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest could not be read.",
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	manifest, err := strictjson.DecodeBytes[freeze.Manifest](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return freeze.Manifest{}, "", diag.Wrap(
			err,
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest could not be decoded.",
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if manifest.SchemaVersion != freeze.SchemaVersion {
		return freeze.Manifest{}, "", diag.New(
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest schema_version is unsupported.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual", manifest.SchemaVersion),
			diag.WithDetail("expected", freeze.SchemaVersion),
		)
	}
	if manifest.DigestProfile != digest.Profile {
		return freeze.Manifest{}, "", diag.New(
			CodeInvalidSnapshotManifest,
			"existing snapshot manifest digest_profile is unsupported.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual", manifest.DigestProfile),
			diag.WithDetail("expected", digest.Profile),
		)
	}
	actualDigest, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return freeze.Manifest{}, "", diag.Wrap(
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
			return freeze.Manifest{}, "", diag.New(
				CodeSnapshotDigestMismatch,
				"existing snapshot manifest is missing an embedded digest.",
				diag.WithDetail("path", path),
				diag.WithDetail("location", label),
				diag.WithDetail("expected_digest", actualDigest),
			)
		}
		if embedded != actualDigest {
			return freeze.Manifest{}, "", diag.New(
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
		return freeze.Manifest{}, "", diag.New(
			CodeSnapshotDigestMismatch,
			"existing snapshot manifest digest does not match the expected frozen snapshot.",
			diag.WithDetail("path", path),
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", expectedDigest),
		)
	}
	return manifest, actualDigest, nil
}

func reviewCharterDiagnostic(frozen *charter.FrozenCharter, allowEmptyCharter bool) *diag.Diagnostic {
	if frozen == nil || len(frozen.Charter.Goals) != 0 || allowEmptyCharter {
		return nil
	}
	diagnostic := diag.Diagnostic{
		Code:    CodeCharterZeroGoals,
		Message: "review requires at least one Charter goal because an empty Charter makes review vacuous; pass -allow-empty-charter to override.",
		Path:    "/charter/goals",
	}
	return &diagnostic
}

// requireRelayExecutable is deliberately a presence check. Relay v2 owns
// execution and validates supplied plans at run time; preflight has no command
// for capability, catalog, backend, or recipe negotiation anymore.
func requireRelayExecutable(path string) error {
	executable := relayExecutable(path)
	resolved, err := exec.LookPath(executable)
	if err == nil || (resolved != "" && errors.Is(err, exec.ErrDot)) {
		return nil
	}
	kind := relayv2.ErrorRelayCommandFailed
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		kind = relayv2.ErrorRelayNotInstalled
	}
	return &relayv2.CommandError{
		Operation:   "preflight",
		Executable:  executable,
		ExitCode:    -1,
		Kind:        kind,
		StartFailed: true,
		Cause:       err,
	}
}

func validateRequiredRecipe(requirement RecipeRequirement) error {
	recipeID, profileID, err := recipeCompileSelection(requirement.ID)
	if err != nil {
		return err
	}

	compiled, err := relayv2.Compile(relayv2.CompileOptions{
		SessionID: "preflight-" + requirement.ID,
		Task:      "Validate Witness recipe " + requirement.ID + ".",
		RecipeID:  recipeID,
		ProfileID: profileID,
		BatchID:   requirement.ID,
		Charter:   []byte(`{"goals":[]}`),
		Findings:  []byte(`{"findings":[]}`),
	})
	if err != nil {
		return diag.New(
			CodeRecipePlanInvalid,
			fmt.Sprintf("recipe %q did not compile to a valid Relay v2 plan: %v", requirement.ID, err),
			diag.WithDetail("recipe_id", requirement.ID),
		)
	}
	if err := plan.Validate(compiled.Plan); err != nil {
		return diag.New(
			CodeRecipePlanInvalid,
			fmt.Sprintf("recipe %q compiled to a plan that failed validation: %v", requirement.ID, err),
			diag.WithDetail("recipe_id", requirement.ID),
		)
	}
	return nil
}

func recipeCompileSelection(recipeID string) (string, string, error) {
	for _, base := range []string{relayv2.DefaultRecipeID, relayv2.EconomyRecipeID} {
		switch recipeID {
		case base:
			return base, relayv2.DefaultProfileID, nil
		case base + "-codex":
			return base, "codex", nil
		case base + "-claude":
			return base, "claude", nil
		}
	}
	return "", "", diag.New(
		CodeRecipePlanInvalid,
		fmt.Sprintf("recipe %q is not a supported Witness Relay v2 recipe/profile selection.", recipeID),
		diag.WithDetail("recipe_id", recipeID),
	)
}

func runRelayAbsentPreflight(result *Result, options Options, diagnostics []diag.Diagnostic) (*Result, error) {

	bundlePayload, bundleDigest, bundleDiagnostics := loadIntegrationBundle(options.IntegrationBundlePath)
	diagnostics = append(diagnostics, bundleDiagnostics...)
	if len(bundleDiagnostics) == 0 {
		result.ContractDigests["integration_bundle"] = bundleDigest
		if retainedDigest, err := retain(options.StateDir, RetainedIntegrationBundleEnvelopeFile, bundlePayload); err != nil {
			return result, err
		} else {
			result.ArtifactDigests[RetainedIntegrationBundleEnvelopeFile] = retainedDigest
		}
		if retainedDigest, err := retainIntegrationBundleBody(options.StateDir, options.IntegrationBundlePath, bundleDigest); err != nil {
			return result, err
		} else {
			result.ArtifactDigests[RetainedIntegrationBundleBodyFile] = retainedDigest
		}
		contractDigests, contractDiagnostics := selectedContractDigestsFromBundle(bundlePayload)
		diagnostics = append(diagnostics, contractDiagnostics...)
		for contractID, contractDigest := range contractDigests {
			result.ContractDigests[contractID] = contractDigest
		}
	}

	contractDigestDoc := ContractDigestDocument(*result)
	if retainedDigest, err := retain(options.StateDir, "contract-digests.json", contractDigestDoc); err != nil {
		return result, err
	} else {
		result.ArtifactDigests["contract-digests.json"] = retainedDigest
	}

	return finish(result, options, diagnostics)
}

func RelayAbsent(result Result) bool {
	return !result.RelayPresent
}

func relayExecutable(path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	return relayv2.DefaultExecutable
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

func ContractDigestDocument(result Result) map[string]any {
	document := map[string]any{
		"schema_version":   ContractDigestDocumentV2,
		"digest_profile":   digest.Profile,
		"contract_digests": result.ContractDigests,
	}
	return document
}

// ReadContractDigestDocument decodes the retained Witness-computed contract
// body digests.
func ReadContractDigestDocument(payload any) (ContractDigestDocumentData, error) {
	decoded := ContractDigestDocumentData{WitnessDigests: map[string]string{}}
	document, ok := payload.(map[string]any)
	if !ok {
		return decoded, diag.New(CodeContractDigestDocument, "contract-digests document must be an object.")
	}
	schemaVersion, _ := document["schema_version"].(string)
	if schemaVersion != ContractDigestDocumentV2 {
		return decoded, diag.New(
			CodeContractDigestDocument,
			"contract-digests document schema_version is unsupported.",
			diag.WithPath("/schema_version"),
			diag.WithDetail("actual", schemaVersion),
			diag.WithDetail("supported", []string{ContractDigestDocumentV2}),
		)
	}
	if digestProfile, _ := document["digest_profile"].(string); digestProfile != digest.Profile {
		return decoded, diag.New(
			CodeContractDigestDocument,
			"contract-digests document digest_profile is unsupported.",
			diag.WithPath("/digest_profile"),
			diag.WithDetail("actual", digestProfile),
			diag.WithDetail("expected", digest.Profile),
		)
	}
	contractDigests, err := contractDigestDocumentMap(document, "contract_digests", true)
	if err != nil {
		return decoded, err
	}
	decoded.SchemaVersion = schemaVersion
	decoded.WitnessDigests = contractDigests
	return decoded, nil
}

func contractDigestDocumentMap(document map[string]any, field string, required bool) (map[string]string, error) {
	value, found := document[field]
	if !found || value == nil {
		if required {
			return nil, diag.New(
				CodeContractDigestDocument,
				"contract-digests document is missing a required digest map.",
				diag.WithPath("/"+field),
				diag.WithDetail("field", field),
			)
		}
		return map[string]string{}, nil
	}
	result := map[string]string{}
	switch digests := value.(type) {
	case map[string]string:
		for contractID, contractDigest := range digests {
			result[contractID] = contractDigest
		}
	case map[string]any:
		for contractID, rawDigest := range digests {
			contractDigest, ok := rawDigest.(string)
			if !ok {
				return nil, diag.New(
					CodeContractDigestDocument,
					"contract-digests document digest values must be strings.",
					diag.WithPath("/"+field+"/"+jsonPointerEscape(contractID)),
				)
			}
			result[contractID] = contractDigest
		}
	default:
		return nil, diag.New(
			CodeContractDigestDocument,
			"contract-digests document digest map must be an object.",
			diag.WithPath("/"+field),
		)
	}
	return result, nil
}

func selectedContractDigestsFromBundle(bundlePayload any) (map[string]string, []diag.Diagnostic) {
	digests := map[string]string{}
	refs, evidence, diagnostics := selectedContractRefsAndEvidenceFromBundle(bundlePayload)
	if len(diagnostics) > 0 {
		return digests, diagnostics
	}
	for _, diagnostic := range selectedContractAuthenticationDiagnostics(refs, evidence) {
		diagnostics = append(diagnostics, diagnostic)
	}
	if len(diagnostics) > 0 {
		return digests, diagnostics
	}
	_, diagnostics = validateWitnessIntegrationBundle(bundlePayload)
	if len(diagnostics) > 0 {
		return digests, diagnostics
	}
	required := map[string]bool{}
	for _, contractID := range requiredWitnessContractIDs() {
		required[contractID] = true
	}
	for _, item := range evidence {
		if required[item.ContractID] && item.Ref.Digest != "" {
			digests[item.ContractID] = item.Ref.Digest
		}
	}
	return digests, diagnostics
}

func SelectedContractDigestsFromBundle(bundlePayload any) (map[string]string, []diag.Diagnostic) {
	return selectedContractDigestsFromBundle(bundlePayload)
}

func selectedContractAuthenticationDiagnostics(refs []contracts.ArtifactRef, evidence []planning.SelectedContractEvidence) []diag.Diagnostic {
	return planning.SelectedContractManifestDiagnostics(refs, evidence)
}

func selectedContractRefsAndEvidenceFromBundle(bundlePayload any) ([]contracts.ArtifactRef, []planning.SelectedContractEvidence, []diag.Diagnostic) {
	payloadBytes, err := canonjson.Marshal(bundlePayload)
	if err != nil {
		return nil, nil, []diag.Diagnostic{diag.FromError(diag.Wrap(
			err,
			CodeContractDigestMissing,
			"integration bundle selected-contract evidence could not be canonicalized.",
		))}
	}
	authenticated, err := planning.AuthenticatedSelectedContractsFromBytes(payloadBytes)
	if err != nil {
		return nil, nil, []diag.Diagnostic{diag.FromError(err)}
	}
	refs := make([]contracts.ArtifactRef, 0, len(authenticated))
	evidence := make([]planning.SelectedContractEvidence, 0, len(authenticated))
	for _, contract := range authenticated {
		ref := contracts.ArtifactRef{
			Kind:          "selected-contract",
			ID:            "integration-bundle:" + strings.ReplaceAll(contract.ContractID, "/", ":"),
			Digest:        contract.ContractDigest,
			DigestProfile: digest.Profile,
			MediaType:     "application/json",
		}
		refs = append(refs, ref)
		evidence = append(evidence, planning.SelectedContractEvidence{
			Ref:        ref,
			ContractID: contract.ContractID,
			RawBytes:   append([]byte(nil), payloadBytes...),
		})
	}
	return refs, evidence, nil
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
	rejectUnknownIntegrationBundleFields(&diagnostics, root, []string{"schema_version", "id", "contracts"}, "", "integration bundle")
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
	requiredContractIDs := requiredWitnessContractIDs()
	requiredContractIDSet := map[string]bool{}
	for _, contractID := range requiredContractIDs {
		requiredContractIDSet[contractID] = true
	}
	for _, contractID := range requiredContractIDs {
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
		contractPath := "/contracts/" + jsonPointerEscape(contractID)
		if rejectUnknownIntegrationBundleFields(&diagnostics, object, []string{"turns", "reducer", "inputs", "result", "prompt_context"}, contractPath, "integration contract") {
			continue
		}
		if contractDiagnostics := validateRequiredContractStructure(contractID, object); len(contractDiagnostics) > 0 {
			diagnostics = append(diagnostics, contractDiagnostics...)
			continue
		}
		contractsByID[contractID] = object
	}
	contractIDs := make([]string, 0, len(contractsMap))
	for contractID := range contractsMap {
		contractIDs = append(contractIDs, contractID)
	}
	sort.Strings(contractIDs)
	for _, contractID := range contractIDs {
		if requiredContractIDSet[contractID] {
			continue
		}
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeRecipeContractMismatch,
			"degraded Witness bundle must contain exactly the required Witness contracts.",
			diag.WithPath("/contracts/"+jsonPointerEscape(contractID)),
			diag.WithDetail("contract_id", contractID),
		)))
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
	requireReducer(&diagnostics, contractID, object["reducer"])
	requirePromptContext(&diagnostics, contractID, object)
	requireContractInputs(&diagnostics, contractID, object)
	result, ok := object["result"].(map[string]any)
	if !ok {
		diagnostics = append(diagnostics, contractStructureDiagnostic(contractID, "/result", "integration bundle required Witness contract result must be an object."))
		return diagnostics
	}
	rejectUnknownIntegrationBundleFields(&diagnostics, result, []string{"transport", "schema", "assertions"}, "/contracts/"+jsonPointerEscape(contractID)+"/result", "result declaration")
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
		turnPath := fmt.Sprintf("/contracts/%s/turns/%d", jsonPointerEscape(contractID), index)
		if rejectUnknownIntegrationBundleFields(diagnostics, object, []string{"participant_turn", "slot", "instructions"}, turnPath, "turn declaration") {
			continue
		}
		if !nonEmptyString(object["slot"]) {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d/slot", index), "integration bundle required Witness contract turn slot must be a non-empty string."))
		}
		if !nonEmptyString(object["instructions"]) {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d/instructions", index), "integration bundle required Witness contract turn instructions must be a non-empty string."))
		}
		expected := index + 1
		actual, ok := jsonNumberInt(object["participant_turn"])
		if !ok || actual != expected {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d/participant_turn", index), "integration bundle required Witness contract participant_turn numbering is invalid."))
		}
		if slot, _ := object["slot"].(string); strings.TrimSpace(slot) != "" && slot != requiredWitnessTurnSlots[index] {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, fmt.Sprintf("/turns/%d/slot", index), "integration bundle required Witness contract turn slot must match the compiled alternating schedule."))
		}
	}
}

func requireReducer(diagnostics *[]diag.Diagnostic, contractID string, value any) {
	reducer, ok := value.(map[string]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/reducer", "integration bundle required Witness contract reducer must be an object."))
		return
	}
	rejectUnknownIntegrationBundleFields(diagnostics, reducer, []string{"instructions"}, "/contracts/"+jsonPointerEscape(contractID)+"/reducer", "reducer declaration")
	if !nonEmptyString(reducer["instructions"]) {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/reducer/instructions", "integration bundle required Witness contract reducer instructions must be a non-empty string."))
	}
}

func requirePromptContext(diagnostics *[]diag.Diagnostic, contractID string, object map[string]any) {
	promptContext, ok := object["prompt_context"].(map[string]any)
	if !ok {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/prompt_context", "integration bundle required Witness contract prompt_context must be an object."))
		return
	}
	rejectUnknownIntegrationBundleFields(diagnostics, promptContext, []string{"participant_transcript", "facilitator_ledger"}, "/contracts/"+jsonPointerEscape(contractID)+"/prompt_context", "prompt context projection")
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
	rejectUnknownIntegrationBundleFields(diagnostics, input, []string{"required", "cardinality", "media_type", "max_bytes", "schema"}, "/contracts/"+jsonPointerEscape(contractID)+"/inputs/"+jsonPointerEscape(expected.name), "input declaration")
	if value, ok := input["required"].(bool); !ok || value != expected.required {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/required", "integration bundle required Witness contract input required flag is invalid."))
	}
	if cardinality, _ := input["cardinality"].(string); cardinality != expected.cardinality {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/cardinality", "integration bundle required Witness contract input cardinality is invalid."))
	}
	if !positiveJSONNumber(input["max_bytes"]) {
		*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/max_bytes", "integration bundle required Witness contract input max_bytes must be a positive number."))
	}
	if expected.mediaType == "" {
		if _, exists := input["media_type"]; exists {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/media_type", "integration bundle required Witness contract input media_type is not expected."))
		}
	} else {
		mediaType, _ := input["media_type"].(string)
		if mediaType != expected.mediaType {
			*diagnostics = append(*diagnostics, contractStructureDiagnostic(contractID, "/inputs/"+expected.name+"/media_type", "integration bundle required Witness contract input media_type is invalid."))
		}
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

func rejectUnknownIntegrationBundleFields(diagnostics *[]diag.Diagnostic, object map[string]any, allowed []string, path string, label string) bool {
	allowedSet := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = true
	}
	unknown := make([]string, 0)
	for key := range object {
		if !allowedSet[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return false
	}
	sort.Strings(unknown)
	fields := make([]any, len(unknown))
	for index, field := range unknown {
		fields[index] = field
	}
	*diagnostics = append(*diagnostics, diag.FromError(diag.New(
		CodeRecipeContractMismatch,
		fmt.Sprintf("%s contains unsupported field(s): %s.", label, strings.Join(unknown, ", ")),
		diag.WithPath(appendJSONPointer(path, unknown[0])),
		diag.WithDetail("fields", fields),
	)))
	return true
}

func appendJSONPointer(path string, segment string) string {
	if path == "" {
		return "/" + jsonPointerEscape(segment)
	}
	return path + "/" + jsonPointerEscape(segment)
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
	parsed, err := number.Int64()
	return err == nil && parsed > 0
}

func nonEmptyString(value any) bool {
	text, ok := value.(string)
	return ok && strings.TrimSpace(text) != ""
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

// retainIntegrationBundleBody keeps the authored integration-bundle bytes
// alongside its authenticated envelope. The returned digest is semantic JSON
// because the pass and relay bindings authenticate bundle meaning, while the
// retained file remains directly consumable by relay.
func retainIntegrationBundleBody(stateDir string, sourcePath string, expectedDigest string) (string, error) {
	if err := validateRelativeOutput(RetainedIntegrationBundleBodyFile); err != nil {
		return "", err
	}
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", err
	}
	payload, err := strictjson.DecodeAnyBytes(body, strictjson.DefaultMaxBytes)
	if err != nil {
		return "", err
	}
	actualDigest, err := digest.SemanticJSON(payload)
	if err != nil {
		return "", err
	}
	if actualDigest != expectedDigest {
		return "", diag.New(
			CodeIntegrationBundleReadFailed,
			"integration bundle changed while preflight was retaining its authored body.",
			diag.WithDetail("actual_digest", actualDigest),
			diag.WithDetail("expected_digest", expectedDigest),
		)
	}
	path := filepath.Join(stateDir, RetainedIntegrationBundleBodyFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return actualDigest, nil
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

// RetainedArtifacts returns the state-directory-relative artifact paths that
// downstream Witness phases can reuse directly. A source snapshot keeps both
// source and workspace identities in one manifest, so those roles intentionally
// point to the same retained file.
func RetainedArtifacts(stateDir string, snapshotManifestPath string, artifactDigests map[string]string) map[string]string {
	artifacts := map[string]string{}
	for _, item := range []struct {
		role string
		path string
	}{
		{role: "integration_bundle", path: RetainedIntegrationBundleBodyFile},
	} {
		if strings.TrimSpace(artifactDigests[item.path]) != "" {
			artifacts[item.role] = item.path
		}
	}
	// v0.4.0 states retained only the envelope. Keep their inventory readable
	// when a pass is resumed after upgrading; newly created states always carry
	// the body above.
	if artifacts["integration_bundle"] == "" && strings.TrimSpace(artifactDigests[RetainedIntegrationBundleEnvelopeFile]) != "" {
		artifacts["integration_bundle"] = RetainedIntegrationBundleEnvelopeFile
	}
	if strings.TrimSpace(artifactDigests["source-snapshot-manifest"]) == "" {
		return artifacts
	}
	if relativePath, ok := stateDirRelativePath(stateDir, snapshotManifestPath); ok {
		artifacts["source_manifest"] = relativePath
		artifacts["workspace_manifest"] = relativePath
	}
	return artifacts
}

func stateDirRelativePath(stateDir string, path string) (string, bool) {
	if strings.TrimSpace(stateDir) == "" || strings.TrimSpace(path) == "" {
		return "", false
	}
	relativePath, err := filepath.Rel(stateDir, path)
	if err != nil {
		return "", false
	}
	if relativePath == "." || relativePath == ".." || filepath.IsAbs(relativePath) || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(relativePath), true
}

func finish(result *Result, options Options, diagnostics []diag.Diagnostic) (*Result, error) {
	snapshotManifestPath := options.SnapshotManifestPath
	if snapshotManifestPath == "" && options.SnapshotDir != "" {
		snapshotManifestPath = filepath.Join(options.SnapshotDir, "manifest.json")
	}
	result.RetainedArtifacts = RetainedArtifacts(options.StateDir, snapshotManifestPath, result.ArtifactDigests)
	diag.Sort(diagnostics)
	result.Diagnostics = diagnostics
	result.OK = len(diagnostics) == 0
	if result.OK {
		return result, nil
	}
	return result, &Error{Diagnostics: diagnostics}
}
