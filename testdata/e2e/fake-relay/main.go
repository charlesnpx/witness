package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/contracts"
	"witness/internal/digest"
)

const (
	convoRelayVersion = "v1.4.0"

	contractFalsification = "witnessed-review/witness-falsification-v2"
	contractEconomy       = "witnessed-review/economy-equivalence-v2"
)

var recipeContracts = map[string]string{
	"witness-falsify-v2":            contractFalsification,
	"witness-falsify-v2-codex":      contractFalsification,
	"witness-falsify-v2-claude":     contractFalsification,
	"economy-equivalence-v2":        contractEconomy,
	"economy-equivalence-v2-codex":  contractEconomy,
	"economy-equivalence-v2-claude": contractEconomy,
}

type sessionState struct {
	RecipeID              string            `json:"recipe_id"`
	IntegrationBundlePath string            `json:"integration_bundle_path"`
	Inputs                map[string]string `json:"inputs"`
}

type portablePayload struct {
	Kind         string
	PortableID   string
	Value        any
	SourceID     string
	SourceDigest string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_ = writeJSON(os.Stderr, map[string]any{
			"ok": false,
			"diagnostics": []map[string]any{{
				"code":    "fake_relay_error",
				"message": err.Error(),
			}},
		})
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("missing fake relay command")
	}
	switch args[0] {
	case "capabilities":
		return writeJSON(os.Stdout, capabilitiesDocument())
	case "recipes":
		if len(args) >= 2 && args[1] == "list" {
			return writeJSON(os.Stdout, recipesListDocument())
		}
	case "backends":
		if len(args) >= 2 && args[1] == "status" {
			return writeJSON(os.Stdout, backendStatusDocument())
		}
	case "compile-recipe":
		return compileRecipe(args[1:])
	case "run":
		return runRecipe(args[1:])
	case "export":
		return exportPortable(args[1:])
	case "verify-export":
		return verifyExport(args[1:])
	}
	return fmt.Errorf("unsupported fake relay command %q", args[0])
}

func capabilitiesDocument() map[string]any {
	return map[string]any{
		"schema_version":      "relay-capabilities-v1",
		"convo_relay_version": convoRelayVersion,
		"build_platform": map[string]any{
			"goarch": "test",
			"goos":   "test",
		},
		"contracts": map[string]any{
			"execution_workspace":           []any{1, 2},
			"integration_bundle":            []any{"relay-integration-bundle-v2"},
			"recipe":                        []any{2},
			"root_artifact":                 []any{2},
			"root_recipe_plan":              []any{2},
			"root_session_result":           []any{2},
			"selected_integration_contract": []any{2},
		},
		"digest_profile":            []any{digest.Profile},
		"isolation_report":          []any{"relay-workspace-isolation-v1"},
		"portable_export":           []any{"relay-root-portable-export-v2"},
		"prompt_context_projection": []any{"relay-prompt-context-v1"},
		"prompt_policy":             []any{"prompt-policy/v2"},
		"provider_invocation":       []any{"relay-provider-invocation-v2"},
		"provider_retry_policy":     []any{"relay-provider-retry-policy-v1"},
		"rendered_prompt":           []any{"relay-rendered-prompt-v1"},
		"workspace_mechanisms":      []any{"inherited", "detached_writable_git_worktree"},
	}
}

func recipesListDocument() map[string]any {
	ids := sortedRecipeIDs()
	recipes := make([]any, 0, len(ids))
	for _, id := range ids {
		recipes = append(recipes, map[string]any{
			"id":     id,
			"status": "usable",
			"source": "fake-relay-e2e",
			"declared": map[string]any{
				"integration_contract": recipeContracts[id],
			},
			"resolved": map[string]any{},
		})
	}
	return map[string]any{
		"scope":         "recipes",
		"status":        "usable",
		"settings_path": "",
		"recipes":       recipes,
	}
}

func backendStatusDocument() map[string]any {
	return map[string]any{
		"scope":      "backends",
		"probe_auth": false,
		"backends": []any{
			map[string]any{
				"backend":               "claude",
				"executable_path":       "fake-claude",
				"version":               "fake",
				"authentication_status": "unknown",
				"status":                "installed_auth_unknown",
				"probe_detail":          map[string]any{},
			},
			map[string]any{
				"backend":               "codex",
				"executable_path":       "fake-codex",
				"version":               "fake",
				"authentication_status": "unknown",
				"status":                "installed_auth_unknown",
				"probe_detail":          map[string]any{},
			},
		},
	}
}

func compileRecipe(args []string) error {
	recipeID := flagValue(args, "--recipe")
	contractID := recipeContracts[recipeID]
	if contractID == "" {
		return fmt.Errorf("unknown recipe %q", recipeID)
	}
	bundlePath := flagValue(args, "--integration-bundle")
	bundle, contractBody, contractDigest, err := contractFromBundle(bundlePath, contractID)
	if err != nil {
		return err
	}
	bundleDigest, err := digest.SemanticJSON(bundle)
	if err != nil {
		return err
	}
	plan := rootRecipePlan(recipeID, contractID, contractDigest, bundleDigest, artifactRef("integration_contract:selected", contractDigest))
	return writeJSON(os.Stdout, map[string]any{
		"recipe_id":            recipeID,
		"status":               "usable",
		"integration_contract": contractID,
		"diagnostics":          []any{},
		"compiled_plan":        plan,
		"contract_digests": map[string]any{
			contractID: contractDigest,
		},
		"contract": contractBody,
		"target":   "root",
	})
}

func runRecipe(args []string) error {
	if os.Getenv("WITNESS_FAKE_RELAY_FAIL_RUN") == "1" {
		return errors.New("simulated relay launch failure")
	}
	recipeID := flagValue(args, "--recipe")
	if recipeContracts[recipeID] == "" {
		return fmt.Errorf("unknown recipe %q", recipeID)
	}
	home := flagValue(args, "--home")
	if home == "" {
		home = os.TempDir()
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return err
	}
	sessionDir, err := os.MkdirTemp(home, "fake-relay-session-*")
	if err != nil {
		return err
	}
	state := sessionState{
		RecipeID:              recipeID,
		IntegrationBundlePath: flagValue(args, "--integration-bundle"),
		Inputs:                inputBindings(args),
	}
	if state.Inputs["findings"] == "" {
		return errors.New("missing findings input")
	}
	if state.Inputs["charter"] == "" {
		return errors.New("missing charter input")
	}
	if err := writeJSONFile(filepath.Join(sessionDir, "session-state.json"), state); err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{
		"schema_version": "fake-relay-run-v1",
		"status":         "completed",
		"session_dir":    sessionDir,
	})
}

func exportPortable(args []string) error {
	sessionDir := flagValue(args, "--session-dir")
	outputDir := flagValue(args, "--output")
	if sessionDir == "" || outputDir == "" {
		return errors.New("export requires --session-dir and --output")
	}
	var state sessionState
	if err := readJSONFile(filepath.Join(sessionDir, "session-state.json"), &state); err != nil {
		return err
	}
	manifestDigest, err := writePortableExport(outputDir, state)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{
		"schema_version":   "relay-root-portable-export-v2",
		"status":           "valid",
		"manifest_digest":  manifestDigest,
		"portable_export":  outputDir,
		"terminal_status":  "completed",
		"convo_relay_fake": true,
	})
}

func verifyExport(args []string) error {
	exportDir := ""
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		exportDir = arg
		break
	}
	if exportDir == "" {
		return errors.New("verify-export requires export directory")
	}
	var manifest map[string]any
	if err := readJSONFile(filepath.Join(exportDir, "manifest.json"), &manifest); err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{
		"schema_version":  manifest["schema_version"],
		"status":          "valid",
		"manifest_digest": manifest["manifest_digest"],
	})
}

func writePortableExport(outputDir string, state sessionState) (string, error) {
	contractID := recipeContracts[state.RecipeID]
	_, contractBody, contractDigest, err := contractFromBundle(state.IntegrationBundlePath, contractID)
	if err != nil {
		return "", err
	}
	batch, batchBytes, err := readBatch(state.Inputs["findings"])
	if err != nil {
		return "", err
	}
	charterBytes, err := os.ReadFile(state.Inputs["charter"])
	if err != nil {
		return "", err
	}
	verdicts := verdictDocument(batch)
	verdictBytes, err := canonjson.Marshal(verdicts)
	if err != nil {
		return "", err
	}
	integrationContractPayload := map[string]any{
		"kind":            "integration_contract",
		"schema_version":  2,
		"digest_profile":  digest.Profile,
		"contract_id":     contractID,
		"contract_digest": contractDigest,
		"contract":        contractBody,
	}
	integrationContractDigest, err := digest.StorageEnvelope("integration_contract", integrationContractPayload)
	if err != nil {
		return "", err
	}
	integrationContractRef := portableRef("integration-contract", "integration_contract:selected", integrationContractDigest)
	rootPlanPayload := rootRecipePlan(state.RecipeID, contractID, contractDigest, "", integrationContractRef)
	namedInputs, inputPayloads, err := namedInputPayloads(contractID, charterBytes, batchBytes)
	if err != nil {
		return "", err
	}
	providerPayloads, transcript, err := providerPayloadsForRecipe(state.RecipeID)
	if err != nil {
		return "", err
	}
	canonicalResultPayload := map[string]any{
		"kind":           "canonical_result",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"value":          verdicts,
		"canonical_json": string(verdictBytes),
	}
	canonicalResultDigest, err := digest.StorageEnvelope("canonical_result", canonicalResultPayload)
	if err != nil {
		return "", err
	}
	resultValidationPayload := map[string]any{
		"kind":                 "result_validation",
		"schema_version":       2,
		"digest_profile":       digest.Profile,
		"status":               "validated",
		"canonical_result_ref": portableRef("canonical-result", "canonical_result:canonical-result", canonicalResultDigest),
	}
	payloads := []portablePayload{
		{
			Kind:       "diagnostics",
			PortableID: "diagnostics",
			Value: map[string]any{
				"execution_kind": "recipe",
				"diagnostics":    []any{},
			},
		},
		{
			Kind:         "integration_contract",
			PortableID:   "integration-contract",
			Value:        integrationContractPayload,
			SourceID:     "integration_contract:selected",
			SourceDigest: integrationContractDigest,
		},
		{
			Kind:         "root_recipe_plan",
			PortableID:   "root-plan",
			Value:        rootPlanPayload,
			SourceID:     "root_recipe_plan:" + safeID(state.RecipeID),
			SourceDigest: storageDigest("root_recipe_plan", rootPlanPayload),
		},
	}
	payloads = append(payloads, inputPayloads...)
	payloads = append(payloads, providerPayloads...)
	payloads = append(payloads,
		portablePayload{
			Kind:         "canonical_result",
			PortableID:   "canonical-result",
			Value:        canonicalResultPayload,
			SourceID:     "canonical_result:canonical-result",
			SourceDigest: canonicalResultDigest,
		},
		portablePayload{
			Kind:       "participant_transcript",
			PortableID: "transcript",
			Value:      transcript,
		},
		portablePayload{
			Kind:         "result_validation",
			PortableID:   "result-validation",
			Value:        resultValidationPayload,
			SourceID:     "result_validation:result-validation",
			SourceDigest: storageDigest("result_validation", resultValidationPayload),
		},
		portablePayload{
			Kind:       "root_session",
			PortableID: "session",
			Value: map[string]any{
				"execution_kind":  "recipe",
				"status":          "completed",
				"terminal_status": "completed",
				"result_source":   "reducer",
				"recipe_id":       state.RecipeID,
			},
		},
	)
	payloads = append(payloads, namedInputs)
	return writePortablePayloads(outputDir, payloads)
}

func rootRecipePlan(recipeID string, contractID string, contractDigest string, bundleDigest string, contractRef map[string]any) map[string]any {
	plan := map[string]any{
		"kind":                        "root_recipe_plan",
		"schema_version":              2,
		"digest_profile":              digest.Profile,
		"recipe_id":                   recipeID,
		"integration_contract_id":     contractID,
		"integration_contract_digest": contractDigest,
		"integration_contract_ref":    contractRef,
		"provider_retry":              "forbid",
		"participant_turns":           4,
		"prompt_context": map[string]any{
			"participant_transcript": "complete",
			"facilitator_ledger":     "trace_only",
		},
		"result_source": "reducer",
		"participants":  recipeParticipants(recipeID),
		"facilitator":   map[string]any{"backend": backendForRecipe(recipeID, 0), "slot_id": "facilitator"},
		"reducer":       map[string]any{"backend": backendForRecipe(recipeID, 1), "slot_id": "reducer"},
	}
	if bundleDigest != "" {
		plan["integration_bundle_digest"] = bundleDigest
	}
	return plan
}

func namedInputPayloads(contractID string, charterBytes []byte, batchBytes []byte) (portablePayload, []portablePayload, error) {
	type input struct {
		name      string
		ordinal   int
		data      []byte
		mediaType string
	}
	inputs := []input{
		{name: "charter", ordinal: 1, data: charterBytes, mediaType: "application/json"},
		{name: "findings", ordinal: 2, data: batchBytes, mediaType: "application/json"},
	}
	manifestEntries := make([]any, 0, len(inputs))
	payloads := make([]portablePayload, 0, len(inputs))
	for _, input := range inputs {
		rawDigest := digest.RawBytes(input.data)
		portableID := "named-input-" + input.name
		content := map[string]any{
			"kind":           "named_input_content",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"ordinal":        input.ordinal,
			"name":           input.name,
			"name_ordinal":   1,
			"encoding":       "base64",
			"bytes_base64":   base64.StdEncoding.EncodeToString(input.data),
			"size_bytes":     len(input.data),
			"raw_digest":     rawDigest,
			"media_type":     input.mediaType,
			"schema_status":  "not_validated",
		}
		sourceID := "named_input_content:" + portableID
		sourceDigest := storageDigest("named_input_content", content)
		payloads = append(payloads, portablePayload{
			Kind:         "named_input_content",
			PortableID:   portableID,
			Value:        content,
			SourceID:     sourceID,
			SourceDigest: sourceDigest,
		})
		manifestEntries = append(manifestEntries, map[string]any{
			"ordinal":       input.ordinal,
			"name":          input.name,
			"name_ordinal":  1,
			"size_bytes":    len(input.data),
			"raw_digest":    rawDigest,
			"media_type":    input.mediaType,
			"schema_status": "not_validated",
			"content_ref":   portableRef(portableID, sourceID, sourceDigest),
		})
	}
	manifest := map[string]any{
		"kind":           "named_input_manifest",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"contract_id":    contractID,
		"input_count":    len(manifestEntries),
		"inputs":         manifestEntries,
	}
	return portablePayload{
		Kind:         "named_input_manifest",
		PortableID:   "named-input-manifest",
		Value:        manifest,
		SourceID:     "named_input_manifest:named-input-manifest",
		SourceDigest: storageDigest("named_input_manifest", manifest),
	}, payloads, nil
}

func providerPayloadsForRecipe(recipeID string) ([]portablePayload, []any, error) {
	var payloads []portablePayload
	var transcript []any
	addInvocation := func(phase string, ordinal int) error {
		id := phase
		if ordinal > 0 {
			id = fmt.Sprintf("%s-%d", phase, ordinal)
		}
		backend := backendForRecipe(recipeID, ordinal)
		promptText := fmt.Sprintf("Witness fake %s prompt %d for %s.", phase, ordinal, recipeID)
		promptPayload, promptDigest, promptRawDigest, err := renderedPromptPayload(id, promptText)
		if err != nil {
			return err
		}
		resultPortableID := "provider-result-" + id
		invocationSourceID := "provider_invocation:" + id
		resultSourceID := "provider_result:" + id
		promptSourceID := "rendered_prompt:" + id
		invocationBase := map[string]any{
			"schema_version":            "relay-provider-invocation-v2",
			"invocation_id":             id,
			"phase":                     phase,
			"actor":                     actorForPhase(phase, ordinal),
			"runner_attempt":            1,
			"provider_launch_attempted": true,
			"provider_retry":            "forbid",
			"backend":                   backend,
			"started_at":                "2026-01-01T00:00:00Z",
			"completed_at":              "2026-01-01T00:00:01Z",
			"outcome":                   "completed",
			"failure_stage":             "",
			"classification":            "success",
			"mapped_working_directory":  "workspace",
			"rendered_prompt_ref":       portableRef("rendered-prompt-"+id, promptSourceID, promptDigest),
			"rendered_prompt_digest":    promptRawDigest,
		}
		if ordinal > 0 {
			invocationBase["participant_ordinal"] = ordinal
		}
		if phase == "reducer" {
			invocationBase["reducer_fresh"] = true
		}
		resultInvocation := cloneMap(invocationBase)
		resultInvocation["provider_result_ref"] = nil
		resultPayload := map[string]any{
			"kind":            "provider_result",
			"schema_version":  2,
			"digest_profile":  digest.Profile,
			"invocation":      resultInvocation,
			"provider_result": map[string]any{"backend": backend, "content": "ok"},
		}
		for _, key := range []string{"invocation_id", "phase", "actor", "runner_attempt", "provider_retry", "backend", "started_at", "completed_at", "outcome", "failure_stage", "classification"} {
			resultPayload[key] = invocationBase[key]
		}
		resultDigest := storageDigest("provider_result", resultPayload)
		invocationPayload := map[string]any{
			"kind":           "provider_invocation",
			"schema_version": 2,
			"digest_profile": digest.Profile,
			"invocation":     cloneMap(invocationBase),
		}
		invocationPayload["invocation"].(map[string]any)["provider_result_ref"] = portableRef(resultPortableID, resultSourceID, resultDigest)
		invocationDigest := storageDigest("provider_invocation", invocationPayload)
		payloads = append(payloads,
			portablePayload{
				Kind:         "provider_invocation",
				PortableID:   "provider-invocation-" + id,
				Value:        invocationPayload,
				SourceID:     invocationSourceID,
				SourceDigest: invocationDigest,
			},
			portablePayload{
				Kind:         "provider_result",
				PortableID:   resultPortableID,
				Value:        resultPayload,
				SourceID:     resultSourceID,
				SourceDigest: resultDigest,
			},
			portablePayload{
				Kind:         "rendered_prompt",
				PortableID:   "rendered-prompt-" + id,
				Value:        promptPayload,
				SourceID:     promptSourceID,
				SourceDigest: promptDigest,
			},
		)
		if phase == "participant" {
			transcript = append(transcript, map[string]any{
				"participant_turn":        ordinal,
				"content":                 fmt.Sprintf("participant %d content", ordinal),
				"ledger":                  map[string]any{"settled": []any{}, "contested": []any{}, "withdrawn": []any{}},
				"provider_invocation_ref": portableRef("provider-invocation-"+id, invocationSourceID, invocationDigest),
			})
		}
		return nil
	}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		if err := addInvocation("participant", ordinal); err != nil {
			return nil, nil, err
		}
		if err := addInvocation("facilitator", ordinal); err != nil {
			return nil, nil, err
		}
	}
	if err := addInvocation("reducer", 0); err != nil {
		return nil, nil, err
	}
	return payloads, transcript, nil
}

func renderedPromptPayload(id string, text string) (map[string]any, string, string, error) {
	raw := []byte(text)
	rawDigest := digest.RawBytes(raw)
	payload := map[string]any{
		"kind":           "rendered_prompt",
		"schema_version": 2,
		"digest_profile": digest.Profile,
		"rendered_prompt": map[string]any{
			"schema_version": "relay-rendered-prompt-v1",
			"media_type":     "text/plain; charset=utf-8",
			"encoding":       "base64",
			"bytes_base64":   base64.StdEncoding.EncodeToString(raw),
			"size_bytes":     len(raw),
			"raw_digest":     rawDigest,
		},
	}
	return payload, storageDigest("rendered_prompt", payload), rawDigest, nil
}

func writePortablePayloads(outputDir string, payloads []portablePayload) (string, error) {
	if err := os.RemoveAll(outputDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloadPath(payloads[i]) < payloadPath(payloads[j])
	})
	inventory := make([]any, 0, len(payloads))
	for _, payload := range payloads {
		body, err := canonjson.Marshal(payload.Value)
		if err != nil {
			return "", err
		}
		relative := payloadPath(payload)
		if err := os.MkdirAll(filepath.Join(outputDir, filepath.Dir(relative)), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(outputDir, filepath.FromSlash(relative)), append(body, '\n'), 0o644); err != nil {
			return "", err
		}
		entry := map[string]any{
			"kind":         payload.Kind,
			"portable_id":  payload.PortableID,
			"path":         relative,
			"media_type":   "application/json",
			"size_bytes":   len(body) + 1,
			"digest_class": digest.ClassRawBytes,
			"digest":       digest.RawBytes(append(body, '\n')),
		}
		if payload.SourceID != "" {
			entry["source_artifact_id"] = payload.SourceID
			entry["source_artifact_digest"] = payload.SourceDigest
		}
		inventory = append(inventory, entry)
	}
	manifest := map[string]any{
		"schema_version":      "relay-root-portable-export-v2",
		"convo_relay_version": convoRelayVersion,
		"digest_profile":      digest.Profile,
		"terminal_status":     "completed",
		"stop_reason":         "completed",
		"session_payload":     "payloads/root_session/session.json",
		"transcript_payload":  "payloads/participant_transcript/transcript.json",
		"diagnostics_payload": "payloads/diagnostics/diagnostics.json",
		"payload_inventory":   inventory,
	}
	inventoryDigest, err := digest.SemanticJSON(inventory)
	if err != nil {
		return "", err
	}
	manifest["inventory_digest"] = inventoryDigest
	manifestDigest, err := digest.SemanticJSON(manifest)
	if err != nil {
		return "", err
	}
	manifest["manifest_digest"] = manifestDigest
	if err := writeJSONFile(filepath.Join(outputDir, "manifest.json"), manifest); err != nil {
		return "", err
	}
	return manifestDigest, nil
}

func verdictDocument(batch contracts.VerificationBatchDocument) contracts.RelayWitnessVerdictsDocument {
	verdicts := make([]contracts.WitnessVerdict, 0, len(batch.Findings))
	for _, finding := range batch.Findings {
		verdicts = append(verdicts, contracts.WitnessVerdict{
			FindingID:      finding.FindingID,
			WitnessDigest:  finding.WitnessDigest,
			Verdict:        contracts.VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
			Rationale:      "fake provider preserves the filed witness for E2E coverage",
		})
	}
	return contracts.RelayWitnessVerdictsDocument{
		SchemaVersion: contracts.RelayWitnessVerdictsV2,
		BatchID:       batch.BatchID,
		Verdicts:      verdicts,
	}
}

func readBatch(path string) (contracts.VerificationBatchDocument, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.VerificationBatchDocument{}, nil, err
	}
	batch, err := contracts.ReadVerificationBatchBytes(data)
	if err != nil {
		return contracts.VerificationBatchDocument{}, nil, err
	}
	return batch, data, nil
}

func contractFromBundle(path string, contractID string) (map[string]any, map[string]any, string, error) {
	if path == "" {
		return nil, nil, "", errors.New("missing integration bundle")
	}
	var bundle map[string]any
	if err := readJSONFile(path, &bundle); err != nil {
		return nil, nil, "", err
	}
	contractsRaw, ok := bundle["contracts"].(map[string]any)
	if !ok {
		return nil, nil, "", errors.New("integration bundle missing contracts")
	}
	body, ok := contractsRaw[contractID].(map[string]any)
	if !ok {
		return nil, nil, "", fmt.Errorf("integration bundle missing %s", contractID)
	}
	contractDigest, err := digest.SemanticJSON(body)
	if err != nil {
		return nil, nil, "", err
	}
	return bundle, body, contractDigest, nil
}

func portableRef(portableID string, sourceID string, sourceDigest string) map[string]any {
	return map[string]any{
		"kind":                   "portable_payload_ref",
		"portable_id":            portableID,
		"source_artifact_id":     sourceID,
		"source_artifact_digest": sourceDigest,
	}
}

func artifactRef(id string, refDigest string) map[string]any {
	return map[string]any{
		"kind":           "artifact_ref",
		"schema_version": 1,
		"id":             id,
		"digest":         refDigest,
	}
}

func storageDigest(kind string, value any) string {
	sum, err := digest.StorageEnvelope(kind, value)
	if err != nil {
		panic(err)
	}
	return sum
}

func payloadPath(payload portablePayload) string {
	return filepath.ToSlash(filepath.Join("payloads", payload.Kind, payload.PortableID+".json"))
}

func backendForRecipe(recipeID string, ordinal int) string {
	if strings.HasSuffix(recipeID, "-codex") {
		return "codex"
	}
	if strings.HasSuffix(recipeID, "-claude") {
		return "claude"
	}
	if ordinal%2 == 0 {
		return "codex"
	}
	return "claude"
}

func recipeParticipants(recipeID string) []any {
	return []any{
		map[string]any{"backend": backendForRecipe(recipeID, 1), "slot_id": "slot_0"},
		map[string]any{"backend": backendForRecipe(recipeID, 2), "slot_id": "slot_1"},
	}
}

func actorForPhase(phase string, ordinal int) string {
	switch phase {
	case "participant":
		if ordinal%2 == 1 {
			return "slot_0"
		}
		return "slot_1"
	case "facilitator":
		return "facilitator"
	default:
		return "reducer"
	}
}

func sortedRecipeIDs() []string {
	ids := make([]string, 0, len(recipeContracts))
	for id := range recipeContracts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func safeID(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	if builder.Len() == 0 {
		return "id"
	}
	return builder.String()
}

func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func inputBindings(args []string) map[string]string {
	bindings := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--input" {
			continue
		}
		name, value, ok := strings.Cut(args[i+1], "=")
		if ok {
			bindings[name] = value
		}
	}
	return bindings
}

func cloneMap(input map[string]any) map[string]any {
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func readJSONFile(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	return decoder.Decode(value)
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeJSON(file *os.File, value any) error {
	data, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func init() {
	json.Valid(nil)
}
