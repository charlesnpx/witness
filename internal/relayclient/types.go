package relayclient

import (
	"fmt"
	"strings"

	"witness/internal/diag"
)

const RequiredConvoRelayVersion = "v1.4.0"

type Capabilities struct {
	SchemaVersion           string           `json:"schema_version"`
	ConvoRelayVersion       string           `json:"convo_relay_version"`
	BuildPlatform           BuildPlatform    `json:"build_platform"`
	Contracts               map[string][]any `json:"contracts"`
	DigestProfile           []string         `json:"digest_profile"`
	IsolationReport         []string         `json:"isolation_report"`
	PortableExport          []string         `json:"portable_export"`
	PromptContextProjection []string         `json:"prompt_context_projection"`
	PromptPolicy            []string         `json:"prompt_policy"`
	ProviderInvocation      []string         `json:"provider_invocation"`
	ProviderRetryPolicy     []string         `json:"provider_retry_policy"`
	RenderedPrompt          []string         `json:"rendered_prompt"`
	WorkspaceMechanisms     []string         `json:"workspace_mechanisms"`
}

type BuildPlatform struct {
	GOArch string `json:"goarch"`
	GOOS   string `json:"goos"`
}

type RecipesList struct {
	Scope        string       `json:"scope"`
	Status       string       `json:"status"`
	SettingsPath string       `json:"settings_path"`
	Recipes      []Recipe     `json:"recipes"`
	IssueGroups  []IssueGroup `json:"issue_groups,omitempty"`
}

type Recipe struct {
	ID               string             `json:"id"`
	Status           string             `json:"status"`
	Source           string             `json:"source"`
	Declared         map[string]any     `json:"declared"`
	Resolved         RecipeResolution   `json:"resolved"`
	BackendReadiness []BackendRecord    `json:"backend_readiness,omitempty"`
	Integration      *RecipeIntegration `json:"integration,omitempty"`
	Diagnostics      []RelayDiagnostic  `json:"diagnostics,omitempty"`
}

type RecipeResolution struct {
	Backends     []string `json:"backends"`
	Facilitator  Slot     `json:"facilitator"`
	Participants []Slot   `json:"participants"`
	Reducer      Slot     `json:"reducer"`
}

type Slot struct {
	Backend         string   `json:"backend"`
	Capabilities    []string `json:"capabilities"`
	CompositionPath string   `json:"composition_path"`
	Effort          *string  `json:"effort"`
	Model           *string  `json:"model"`
	ProfileID       string   `json:"profile_id"`
	SlotID          string   `json:"slot_id"`
}

type RecipeIntegration struct {
	Status     string `json:"status"`
	ContractID string `json:"contract_id"`
}

type IssueGroup struct {
	Code    string            `json:"code"`
	Count   int               `json:"count"`
	Issues  []RelayDiagnostic `json:"issues"`
	Recipes []string          `json:"recipes"`
}

type BackendStatus struct {
	Scope     string          `json:"scope"`
	ProbeAuth bool            `json:"probe_auth"`
	Backends  []BackendRecord `json:"backends"`
}

type BackendRecord struct {
	Backend              string         `json:"backend"`
	ExecutablePath       string         `json:"executable_path"`
	Version              string         `json:"version"`
	AuthenticationStatus string         `json:"authentication_status"`
	Status               string         `json:"status"`
	ProbeDetail          map[string]any `json:"probe_detail"`
}

type RelayDiagnostic struct {
	Category string         `json:"category,omitempty"`
	Code     string         `json:"code,omitempty"`
	Message  string         `json:"message,omitempty"`
	Path     string         `json:"path,omitempty"`
	Phase    string         `json:"phase,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	Payload  map[string]any `json:"-"`
}

type CompileReport struct {
	RecipeID                  string
	Status                    string
	IntegrationContract       string
	Diagnostics               []RelayDiagnostic
	RootRecipePlan            any
	IntegrationContractDigest string
	ContractDigests           map[string]string
	Payload                   map[string]any
}

type RunRecipeOptions struct {
	Task                  string
	RecipeID              string
	IntegrationBundlePath string
	InputBindings         []string
	WorkspaceIsolation    string
	SessionDir            string
	SessionID             string
	RelayHome             string
	LaunchCWD             string
	SettingsPath          string
	AllowDirtySource      bool
}

type ExportOptions struct {
	SessionDir string
	SessionID  string
	RelayHome  string
	OutputDir  string
}

type ShowOptions struct {
	SessionDir string
	SessionID  string
	RelayHome  string
}

func NewCompileReport(raw map[string]any) (CompileReport, error) {
	if raw == nil {
		return CompileReport{}, diag.New(ErrorSchemaInvalid, "compile-recipe output must be a JSON object.")
	}
	recipeID, _, err := stringField(raw, "recipe_id")
	if err != nil {
		return CompileReport{}, err
	}
	status, _, err := stringField(raw, "status")
	if err != nil {
		return CompileReport{}, err
	}
	integrationContract, _, err := stringField(raw, "integration_contract")
	if err != nil {
		return CompileReport{}, err
	}
	diagnostics, err := diagnosticsField(raw, "diagnostics")
	if err != nil {
		return CompileReport{}, err
	}
	contractDigests, err := contractDigestField(raw, "contract_digests")
	if err != nil {
		return CompileReport{}, err
	}
	if contractDigests == nil {
		contractDigests = map[string]string{}
	}
	rootRecipePlan, rootRecipePlanKey, err := planField(raw)
	if err != nil {
		return CompileReport{}, err
	}
	if planObject, ok := rootRecipePlan.(map[string]any); ok {
		if integrationContract == "" {
			integrationContract, _, err = stringField(planObject, "integration_contract_id")
			if err != nil {
				return CompileReport{}, err
			}
		}
	}
	integrationContractDigest, err := integrationContractDigestField(rootRecipePlan, rootRecipePlanKey, recipeID, integrationContract)
	if err != nil {
		return CompileReport{}, err
	}
	if integrationContract != "" && integrationContractDigest != "" {
		contractDigests[integrationContract] = integrationContractDigest
	}
	return CompileReport{
		RecipeID:                  recipeID,
		Status:                    status,
		IntegrationContract:       integrationContract,
		Diagnostics:               diagnostics,
		RootRecipePlan:            rootRecipePlan,
		IntegrationContractDigest: integrationContractDigest,
		ContractDigests:           contractDigests,
		Payload:                   raw,
	}, nil
}

func validateCapabilitiesDocument(capabilities Capabilities) error {
	if capabilities.SchemaVersion != "relay-capabilities-v1" {
		return diag.New(ErrorSchemaInvalid, "relay capabilities schema_version is unsupported.", diag.WithDetail("schema_version", capabilities.SchemaVersion))
	}
	if capabilities.ConvoRelayVersion == "" {
		return diag.New(ErrorSchemaInvalid, "relay capabilities must include convo_relay_version.")
	}
	if capabilities.Contracts == nil {
		return diag.New(ErrorSchemaInvalid, "relay capabilities must include contracts.")
	}
	return nil
}

func validateRecipesList(list RecipesList) error {
	if list.Scope != "recipes" {
		return diag.New(ErrorSchemaInvalid, "recipes list scope must be recipes.", diag.WithDetail("scope", list.Scope))
	}
	if list.Status == "" {
		return diag.New(ErrorSchemaInvalid, "recipes list must include status.")
	}
	if list.Recipes == nil {
		return diag.New(ErrorSchemaInvalid, "recipes list must include recipes.")
	}
	for i, recipe := range list.Recipes {
		if recipe.ID == "" {
			return diag.New(ErrorSchemaInvalid, "recipe must include id.", diag.WithPath(fmt.Sprintf("/recipes/%d/id", i)))
		}
	}
	return nil
}

func validateBackendStatus(status BackendStatus) error {
	if status.Scope != "backends" {
		return diag.New(ErrorSchemaInvalid, "backend status scope must be backends.", diag.WithDetail("scope", status.Scope))
	}
	if status.Backends == nil {
		return diag.New(ErrorSchemaInvalid, "backend status must include backends.")
	}
	for i, backend := range status.Backends {
		if backend.Backend == "" {
			return diag.New(ErrorSchemaInvalid, "backend status entries must include backend.", diag.WithPath(fmt.Sprintf("/backends/%d/backend", i)))
		}
		if backend.Status == "" {
			return diag.New(ErrorSchemaInvalid, "backend status entries must include status.", diag.WithPath(fmt.Sprintf("/backends/%d/status", i)))
		}
	}
	return nil
}

func planField(object map[string]any) (any, string, error) {
	for _, key := range []string{"compiled_plan", "root_recipe_plan", "recipe_plan", "plan"} {
		value, ok := object[key]
		if !ok || value == nil {
			continue
		}
		if _, ok := value.(map[string]any); !ok {
			return nil, "", diag.New(ErrorSchemaInvalid, "compile-recipe plan field must be an object.", diag.WithPath("/"+key))
		}
		return value, key, nil
	}
	return nil, "", nil
}

func integrationContractDigestField(plan any, planKey string, recipeID string, integrationContract string) (string, error) {
	if plan == nil {
		return "", nil
	}
	object, ok := plan.(map[string]any)
	if !ok {
		return "", diag.New(ErrorSchemaInvalid, "compile-recipe plan field must be an object.")
	}
	digestPath := "/integration_contract_digest"
	if planKey != "" {
		digestPath = "/" + planKey + digestPath
	}
	digest, found, err := stringField(object, "integration_contract_digest")
	if err != nil {
		return "", err
	}
	if !found || strings.TrimSpace(digest) == "" {
		return "", diag.New(
			ErrorContractDigestMissing,
			"compile-recipe compiled plan must include integration_contract_digest.",
			diag.WithPath(digestPath),
			diag.WithDetail("recipe_id", recipeID),
			diag.WithDetail("integration_contract", integrationContract),
		)
	}
	return digest, nil
}

func contractDigestField(object map[string]any, key string) (map[string]string, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return nil, nil
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return nil, diag.New(ErrorSchemaInvalid, "contract digests field must be an object.", diag.WithPath("/"+key))
	}
	result := map[string]string{}
	for name, digestValue := range raw {
		text, ok := digestValue.(string)
		if !ok {
			return nil, diag.New(ErrorSchemaInvalid, "contract digest values must be strings.", diag.WithPath("/"+key+"/"+name))
		}
		result[name] = text
	}
	return result, nil
}
