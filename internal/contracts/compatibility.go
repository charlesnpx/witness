package contracts

import (
	"io"
	"strings"

	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

type RelayCapabilityRequirementV3 struct {
	Key        string
	Family     string
	Capability string
}

var RequiredRelayCapabilityClosureV3 = []RelayCapabilityRequirementV3{
	{Key: "portable_export_v2", Family: "portable_export", Capability: "relay-root-portable-export-v2"},
	{Key: "provider_invocation_v2", Family: "provider_invocation", Capability: "relay-provider-invocation-v2"},
	{Key: "integration_bundle_v2", Family: "contracts.integration_bundle", Capability: "relay-integration-bundle-v2"},
	{Key: "selected_contract_v2", Family: "contracts.selected_integration_contract", Capability: "2"},
	{Key: "prompt_policy_v2", Family: "prompt_policy", Capability: "prompt-policy/v2"},
	{Key: "relay_root_digests_v1", Family: "digest_profile", Capability: "relay-root-digests-v1"},
	{Key: "recipe_v2", Family: "contracts.recipe", Capability: "2"},
	{Key: "root_artifact_v2", Family: "contracts.root_artifact", Capability: "2"},
	{Key: "root_recipe_plan_v2", Family: "contracts.root_recipe_plan", Capability: "2"},
	{Key: "root_session_result_v2", Family: "contracts.root_session_result", Capability: "2"},
	{Key: "execution_workspace_v2", Family: "contracts.execution_workspace", Capability: "2"},
	{Key: "relay_workspace_isolation_v1", Family: "isolation_report", Capability: "relay-workspace-isolation-v1"},
	{Key: "relay_prompt_context_v1", Family: "prompt_context_projection", Capability: "relay-prompt-context-v1"},
	{Key: "relay_provider_retry_policy_v1", Family: "provider_retry_policy", Capability: "relay-provider-retry-policy-v1"},
	{Key: "relay_rendered_prompt_v1", Family: "rendered_prompt", Capability: "relay-rendered-prompt-v1"},
}

var RequiredRelayCapabilitiesV3 = relayCapabilityKeys(RequiredRelayCapabilityClosureV3)

var RequiredWitnessRecipeContractsV2 = []RecipePlanDigest{
	{RecipeID: "witness-falsify-v2", ContractID: "witnessed-review/witness-falsification-v2"},
	{RecipeID: "witness-falsify-v2-codex", ContractID: "witnessed-review/witness-falsification-v2"},
	{RecipeID: "witness-falsify-v2-claude", ContractID: "witnessed-review/witness-falsification-v2"},
	{RecipeID: "economy-equivalence-v2", ContractID: "witnessed-review/economy-equivalence-v2"},
	{RecipeID: "economy-equivalence-v2-codex", ContractID: "witnessed-review/economy-equivalence-v2"},
	{RecipeID: "economy-equivalence-v2-claude", ContractID: "witnessed-review/economy-equivalence-v2"},
}

type RelayCompatibility struct {
	SchemaVersion           string             `json:"schema_version"`
	ConvoRelayVersion       string             `json:"convo_relay_version"`
	DigestProfile           string             `json:"digest_profile"`
	Capabilities            map[string]bool    `json:"capabilities"`
	CapabilitiesDigest      string             `json:"capabilities_digest"`
	IntegrationBundleDigest string             `json:"integration_bundle_digest"`
	SelectedContracts       []ContractDigest   `json:"selected_contracts"`
	RecipePlans             []RecipePlanDigest `json:"recipe_plans"`
	CompileReports          []CompileReportRef `json:"compile_reports"`
	BackendStatus           []BackendStatus    `json:"backend_status"`
	ConsumerIdentity        map[string]any     `json:"consumer_identity"`
}

type ContractDigest struct {
	ContractID string `json:"contract_id"`
	Digest     string `json:"digest"`
}

type RecipePlanDigest struct {
	RecipeID   string `json:"recipe_id"`
	ContractID string `json:"contract_id"`
	Digest     string `json:"digest"`
}

type CompileReportRef struct {
	RecipeID string      `json:"recipe_id"`
	Status   string      `json:"status"`
	Ref      ArtifactRef `json:"ref"`
	Digest   string      `json:"digest"`
}

type BackendStatus struct {
	Backend string `json:"backend"`
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

func ReadRelayCompatibility(reader io.Reader) (RelayCompatibility, error) {
	return strictjson.Decode[RelayCompatibility](reader, strictjson.DefaultMaxBytes)
}

func ReadRelayCompatibilityBytes(data []byte) (RelayCompatibility, error) {
	return strictjson.DecodeBytes[RelayCompatibility](data, strictjson.DefaultMaxBytes)
}

func RequireValidRelayCompatibility(document RelayCompatibility) error {
	return ErrorFromDiagnostics(ValidateRelayCompatibility(document))
}

func ValidateRelayCompatibility(document RelayCompatibility) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != RelayCompatibilityV3 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay compatibility schema_version must be review-relay-compatibility-v3.", "/schema_version", map[string]any{"expected": RelayCompatibilityV3, "actual": document.SchemaVersion}))
	}
	if RelayCompatibilityRelayAbsent(document) {
		return append(diagnostics, validateRelayAbsentCompatibility(document)...)
	}
	if relayCompatibilityHasRelayAbsentStatus(document) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay_absent backend status is valid only when every required backend records relay_absent.", "/backend_status", map[string]any{"expected": RelayLaunchStatusAbsent}))
	}
	requireString(&diagnostics, "/convo_relay_version", "convo_relay_version", document.ConvoRelayVersion)
	if document.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "digest_profile must be relay-root-digests-v1.", "/digest_profile", map[string]any{"expected": digest.Profile, "actual": document.DigestProfile}))
	}
	requireDigest(&diagnostics, "/capabilities_digest", "capabilities_digest", document.CapabilitiesDigest)
	requireDigest(&diagnostics, "/integration_bundle_digest", "integration_bundle_digest", document.IntegrationBundleDigest)
	for _, requirement := range RequiredRelayCapabilityClosureV3 {
		if !document.Capabilities[requirement.Key] {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCompatibility,
				"relay compatibility manifest is missing a required capability.",
				"/capabilities/"+requirement.Key,
				map[string]any{
					"capability":        requirement.Key,
					"relay_capability":  requirement.Capability,
					"relay_family":      requirement.Family,
					"compatibility_key": requirement.Key,
				},
			))
		}
	}
	if !identityPresent(document.ConsumerIdentity) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "consumer_identity is required.", "/consumer_identity", nil))
	}
	for index, contract := range document.SelectedContracts {
		path := "/selected_contracts/" + itoa(index)
		requireString(&diagnostics, path+"/contract_id", "contract ID", contract.ContractID)
		requireDigest(&diagnostics, path+"/digest", "contract digest", contract.Digest)
	}
	requiredContracts := []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	}
	presentContracts := map[string]bool{}
	for _, contract := range document.SelectedContracts {
		presentContracts[contract.ContractID] = true
	}
	for _, contractID := range requiredContracts {
		if !presentContracts[contractID] {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay compatibility manifest must bind the Witness v2 integration contract.", "/selected_contracts", map[string]any{"contract_id": contractID}))
		}
	}
	for index, plan := range document.RecipePlans {
		path := "/recipe_plans/" + itoa(index)
		requireString(&diagnostics, path+"/recipe_id", "recipe ID", plan.RecipeID)
		requireString(&diagnostics, path+"/contract_id", "contract ID", plan.ContractID)
		requireDigest(&diagnostics, path+"/digest", "recipe plan digest", plan.Digest)
	}
	plansByID := make(map[string]RecipePlanDigest, len(document.RecipePlans))
	for _, plan := range document.RecipePlans {
		plansByID[plan.RecipeID] = plan
	}
	for _, required := range RequiredWitnessRecipeContractsV2 {
		plan, exists := plansByID[required.RecipeID]
		if !exists {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay compatibility manifest must retain all six Witness v2 recipe plans.", "/recipe_plans", map[string]any{"recipe_id": required.RecipeID}))
			continue
		}
		if plan.ContractID != required.ContractID {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "Witness v2 recipe plan is bound to the wrong integration contract.", "/recipe_plans", map[string]any{"recipe_id": required.RecipeID, "expected_contract_id": required.ContractID, "actual_contract_id": plan.ContractID}))
		}
	}
	for index, report := range document.CompileReports {
		path := "/compile_reports/" + itoa(index)
		requireString(&diagnostics, path+"/recipe_id", "recipe ID", report.RecipeID)
		requireString(&diagnostics, path+"/status", "compile report status", report.Status)
		diagnostics = append(diagnostics, prefixDiagnostics(path+"/ref", validateArtifactRef(report.Ref, ""))...)
		requireDigest(&diagnostics, path+"/digest", "compile report digest", report.Digest)
		if report.Ref.Digest != "" {
			compareDigest(&diagnostics, path+"/ref/digest", "compile report ref", report.Ref.Digest, report.Digest)
		}
	}
	for index, status := range document.BackendStatus {
		path := "/backend_status/" + itoa(index)
		requireString(&diagnostics, path+"/backend", "backend", status.Backend)
		requireString(&diagnostics, path+"/status", "backend status", status.Status)
	}
	return diagnostics
}

func RelayCompatibilityRelayAbsent(document RelayCompatibility) bool {
	statuses := relayBackendStatusByName(document.BackendStatus)
	if len(statuses) == 0 {
		return false
	}
	for _, backend := range []string{"codex", "claude"} {
		if statuses[backend] != RelayLaunchStatusAbsent {
			return false
		}
	}
	return true
}

func relayCompatibilityHasRelayAbsentStatus(document RelayCompatibility) bool {
	for _, status := range document.BackendStatus {
		if status.Status == RelayLaunchStatusAbsent {
			return true
		}
	}
	return false
}

func validateRelayAbsentCompatibility(document RelayCompatibility) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if strings.TrimSpace(document.ConvoRelayVersion) != "" {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "convo_relay_version must be omitted when relay launch status is relay_absent.", "/convo_relay_version", map[string]any{"relay_launch_status": RelayLaunchStatusAbsent}))
	}
	if document.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "digest_profile must be relay-root-digests-v1.", "/digest_profile", map[string]any{"expected": digest.Profile, "actual": document.DigestProfile}))
	}
	requireDigest(&diagnostics, "/capabilities_digest", "capabilities_digest", document.CapabilitiesDigest)
	requireDigest(&diagnostics, "/integration_bundle_digest", "integration_bundle_digest", document.IntegrationBundleDigest)
	for _, requirement := range RequiredRelayCapabilityClosureV3 {
		value, exists := document.Capabilities[requirement.Key]
		if !exists {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must explicitly record every required capability as unavailable.", "/capabilities/"+requirement.Key, map[string]any{"capability": requirement.Key, "relay_launch_status": RelayLaunchStatusAbsent}))
			continue
		}
		if value {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must not claim relay capabilities are available.", "/capabilities/"+requirement.Key, map[string]any{"capability": requirement.Key, "relay_launch_status": RelayLaunchStatusAbsent}))
		}
	}
	validateSelectedContractCompatibility(&diagnostics, document.SelectedContracts)
	if len(document.RecipePlans) > 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must not claim retained recipe plans.", "/recipe_plans", map[string]any{"relay_launch_status": RelayLaunchStatusAbsent}))
	}
	validateRelayAbsentCompileReports(&diagnostics, document.CompileReports)
	validateRelayAbsentBackendStatus(&diagnostics, document.BackendStatus)
	if !identityPresent(document.ConsumerIdentity) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidCompatibility, "consumer_identity is required.", "/consumer_identity", nil))
	}
	return diagnostics
}

func validateSelectedContractCompatibility(diagnostics *[]diag.Diagnostic, contracts []ContractDigest) {
	for index, contract := range contracts {
		path := "/selected_contracts/" + itoa(index)
		requireString(diagnostics, path+"/contract_id", "contract ID", contract.ContractID)
		requireDigest(diagnostics, path+"/digest", "contract digest", contract.Digest)
	}
	requiredContracts := []string{
		"witnessed-review/witness-falsification-v2",
		"witnessed-review/economy-equivalence-v2",
	}
	presentContracts := map[string]bool{}
	for _, contract := range contracts {
		presentContracts[contract.ContractID] = true
	}
	for _, contractID := range requiredContracts {
		if !presentContracts[contractID] {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidCompatibility, "relay compatibility manifest must bind the Witness v2 integration contract.", "/selected_contracts", map[string]any{"contract_id": contractID}))
		}
	}
}

func validateRelayAbsentCompileReports(diagnostics *[]diag.Diagnostic, reports []CompileReportRef) {
	byRecipe := make(map[string]CompileReportRef, len(reports))
	for index, report := range reports {
		path := "/compile_reports/" + itoa(index)
		requireString(diagnostics, path+"/recipe_id", "recipe ID", report.RecipeID)
		requireString(diagnostics, path+"/status", "compile report status", report.Status)
		if report.Status != RelayLaunchStatusAbsent {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compile reports must record relay_absent status.", path+"/status", map[string]any{"actual": report.Status, "expected": RelayLaunchStatusAbsent}))
		}
		*diagnostics = append(*diagnostics, prefixDiagnostics(path+"/ref", validateArtifactRef(report.Ref, ""))...)
		requireDigest(diagnostics, path+"/digest", "compile report digest", report.Digest)
		if report.Ref.Digest != "" {
			compareDigest(diagnostics, path+"/ref/digest", "compile report ref", report.Ref.Digest, report.Digest)
		}
		byRecipe[report.RecipeID] = report
	}
	for _, required := range RequiredWitnessRecipeContractsV2 {
		report, exists := byRecipe[required.RecipeID]
		if !exists {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must retain a relay_absent compile report for every Witness v2 recipe.", "/compile_reports", map[string]any{"recipe_id": required.RecipeID}))
			continue
		}
		if report.Status != RelayLaunchStatusAbsent {
			continue
		}
	}
}

func validateRelayAbsentBackendStatus(diagnostics *[]diag.Diagnostic, statuses []BackendStatus) {
	byBackend := relayBackendStatusByName(statuses)
	for index, status := range statuses {
		path := "/backend_status/" + itoa(index)
		requireString(diagnostics, path+"/backend", "backend", status.Backend)
		requireString(diagnostics, path+"/status", "backend status", status.Status)
		if status.Status != RelayLaunchStatusAbsent {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must record relay_absent for every backend status.", path+"/status", map[string]any{"backend": status.Backend, "actual": status.Status, "expected": RelayLaunchStatusAbsent}))
		}
	}
	for _, backend := range []string{"codex", "claude"} {
		if byBackend[backend] != RelayLaunchStatusAbsent {
			*diagnostics = append(*diagnostics, diagnostic(CodeInvalidCompatibility, "relay-absent compatibility must record every required backend stratum.", "/backend_status", map[string]any{"backend": backend, "expected": RelayLaunchStatusAbsent}))
		}
	}
}

func relayBackendStatusByName(statuses []BackendStatus) map[string]string {
	byBackend := make(map[string]string, len(statuses))
	for _, status := range statuses {
		byBackend[status.Backend] = status.Status
	}
	return byBackend
}

func RelayCompatibilityDigest(document RelayCompatibility) (string, error) {
	return SemanticDigest(document)
}

func RelayCompatibilityCanonicalBytes(document RelayCompatibility) ([]byte, error) {
	return CanonicalBytes(document)
}

func relayCapabilityKeys(requirements []RelayCapabilityRequirementV3) []string {
	keys := make([]string, len(requirements))
	for index, requirement := range requirements {
		keys[index] = requirement.Key
	}
	return keys
}
