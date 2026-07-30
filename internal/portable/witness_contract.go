package portable

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"witness/internal/canonjson"
	"witness/internal/digest"
)

const (
	witnessContractFalsificationV2 = "witnessed-review/witness-falsification-v2"
	witnessContractEconomyV2       = "witnessed-review/economy-equivalence-v2"
)

type ReducerResult struct {
	Value  any
	Digest string
}

type ContractBinding struct {
	ContractID     string
	ContractDigest string
	ArtifactDigest string
	PortableID     string
}

type namedInputContent struct {
	Ordinal      int
	Name         string
	NameOrdinal  int
	SizeBytes    int
	RawDigest    string
	MediaType    string
	SchemaStatus string
	Data         []byte
}

type witnessInvocation struct {
	Phase            string
	Ordinal          int
	PortableID       string
	ResultPortableID string
	PromptText       string
	PromptAvailable  bool
}

type witnessInvocationSet struct {
	Participants map[int]witnessInvocation
	Facilitators map[int]witnessInvocation
	Reducer      *witnessInvocation
}

func ReducerResultFromReport(report *DetailedReport) (*ReducerResult, error) {
	if report == nil {
		return nil, invalidf("portable export report is required")
	}
	return reducerResultFromPayloads(report.Payloads)
}

func ContractBindingFromReport(report *DetailedReport) (*ContractBinding, error) {
	if report == nil {
		return nil, invalidf("portable export report is required")
	}
	rootPlan, err := singlePayloadObject(report.Payloads, rootArtifactKindRootRecipePlan)
	if err != nil {
		return nil, err
	}
	contractPayload, err := singlePayload(report.Payloads, rootArtifactKindIntegrationContract)
	if err != nil {
		return nil, err
	}
	inventoryByID := inventoryByPortableID(report.Payloads)
	return validateContractBinding(rootPlan, contractPayload, inventoryByID)
}

func NamedInputDigestPresent(report *DetailedReport, name string, rawDigest string) bool {
	if report == nil || strings.TrimSpace(rawDigest) == "" {
		return false
	}
	digestValue, err := NamedInputRawDigest(report, name)
	return err == nil && digestValue == rawDigest
}

func NamedInputRawDigest(report *DetailedReport, name string) (string, error) {
	if report == nil {
		return "", invalidf("portable export report is required")
	}
	manifest, err := singlePayloadObject(report.Payloads, rootArtifactKindNamedInputManifest)
	if err != nil {
		return "", err
	}
	inputs, ok := manifest["inputs"].([]any)
	if !ok {
		return "", invalidf("portable export requires named inputs with digests")
	}
	payloadsByID := payloadByPortableID(report.Payloads)
	var matched []map[string]any
	for _, raw := range inputs {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name != "" && stringValue(entry["name"]) != name {
			continue
		}
		matched = append(matched, entry)
	}
	if len(matched) != 1 {
		return "", invalidf("portable export named input %s must resolve to exactly one contract-designated entry, got %d", name, len(matched))
	}
	content, err := namedInputEntryContent(matched[0], payloadsByID)
	if err != nil {
		return "", err
	}
	return content.RawDigest, nil
}

func validateWitnessRunContract(manifest map[string]any, payloads []Payload, inventoryByID map[string]map[string]any) ([]UnverifiedRelationship, error) {
	if !terminalSucceeded(stringValue(manifest["terminal_status"])) {
		return nil, invalidf("portable export terminal_status must be a successful terminal status")
	}
	rootSession, err := singlePayloadObject(payloads, "root_session")
	if err != nil {
		return nil, err
	}
	diagnostics, _ := optionalPayloadObject(payloads, "diagnostics")
	executionKind := firstNonEmptyString(rootSession["execution_kind"], diagnostics["execution_kind"])
	if executionKind != "recipe" {
		return nil, invalidf("portable export requires execution_kind recipe")
	}
	sessionStatus := firstNonEmptyString(rootSession["status"], rootSession["terminal_status"])
	if sessionStatus != "" && !terminalSucceeded(sessionStatus) {
		return nil, invalidf("portable export root session status must be successful")
	}

	rootPlan, err := singlePayloadObject(payloads, rootArtifactKindRootRecipePlan)
	if err != nil {
		return nil, err
	}
	if err := validateRootArtifactEnvelope(rootPlan, rootArtifactKindRootRecipePlan); err != nil {
		return nil, err
	}
	if stringValue(rootPlan["provider_retry"]) != "forbid" {
		return nil, invalidf("portable export root plan requires provider_retry=forbid")
	}
	turns, ok := exactJSONInteger(rootPlan["participant_turns"])
	if !ok || turns != 4 {
		return nil, invalidf("portable export root plan requires exactly four participant turns")
	}
	if err := validatePromptContext(rootPlan["prompt_context"]); err != nil {
		return nil, err
	}
	contractID := stringValue(rootPlan["integration_contract_id"])
	if !expectedWitnessContract(contractID) {
		return nil, invalidf("portable export root plan must bind a witnessed-review verification contract")
	}
	if resultSource := firstNonEmptyString(rootPlan["result_source"], rootSession["result_source"]); resultSource != "reducer" {
		return nil, invalidf("portable export root plan requires result_source=reducer")
	}

	contractPayload, err := singlePayload(payloads, rootArtifactKindIntegrationContract)
	if err != nil {
		return nil, err
	}
	contractBinding, err := validateContractBinding(rootPlan, contractPayload, inventoryByID)
	if err != nil {
		return nil, err
	}
	if contractBinding.ContractID != contractID {
		return nil, invalidf("portable export integration contract does not match the root plan")
	}

	namedInputs, err := singlePayloadObject(payloads, rootArtifactKindNamedInputManifest)
	if err != nil {
		return nil, err
	}
	if err := validateRootArtifactEnvelope(namedInputs, rootArtifactKindNamedInputManifest); err != nil {
		return nil, err
	}
	contractBody := contractPayload.Value.(map[string]any)["contract"].(map[string]any)
	if err := validateNamedInputManifest(namedInputs, payloads, inventoryByID, contractID, contractBody); err != nil {
		return nil, err
	}

	transcript, err := singlePayloadArray(payloads, "participant_transcript")
	if err != nil {
		return nil, err
	}
	if len(transcript) != 4 {
		return nil, invalidf("portable export requires a complete four-turn participant transcript")
	}
	invocations, unverified, err := validateWitnessProviderInvocations(payloads, inventoryByID, turns)
	if err != nil {
		return nil, err
	}
	if err := validateParticipantTranscript(transcript, invocations, inventoryByID); err != nil {
		return nil, err
	}
	promptUnverified, err := validateTraceOnlyPromptProjection(transcript, invocations)
	if err != nil {
		return nil, err
	}
	unverified = append(unverified, promptUnverified...)

	resultValidation, err := singlePayloadObject(payloads, rootArtifactKindResultValidation)
	if err != nil {
		return nil, err
	}
	if err := validateRootArtifactEnvelope(resultValidation, rootArtifactKindResultValidation); err != nil {
		return nil, err
	}
	if status := stringValue(resultValidation["status"]); status != "validated" && status != "valid" {
		return nil, invalidf("portable export result validation status must be valid")
	}
	canonicalResultPayload, err := singlePayload(payloads, rootArtifactKindCanonicalResult)
	if err != nil {
		return nil, err
	}
	if err := validateResultValidationCanonicalRef(resultValidation, canonicalResultPayload, inventoryByID); err != nil {
		return nil, err
	}
	if _, err := reducerResultFromPayloads(payloads); err != nil {
		return nil, err
	}
	return unverified, nil
}

func validatePromptContext(value any) error {
	context, ok := value.(map[string]any)
	if !ok {
		return invalidf("portable export root plan requires prompt_context")
	}
	if stringValue(context["participant_transcript"]) != "complete" {
		return invalidf("portable export root plan requires complete participant transcript projection")
	}
	if stringValue(context["facilitator_ledger"]) != "trace_only" {
		return invalidf("portable export root plan requires trace-only facilitator ledger")
	}
	return nil
}

func validateContractBinding(rootPlan map[string]any, contractPayload Payload, inventoryByID map[string]map[string]any) (*ContractBinding, error) {
	integrationContract, ok := contractPayload.Value.(map[string]any)
	if !ok {
		return nil, invalidf("portable integration contract payload must be an object")
	}
	if err := validateRootArtifactEnvelope(integrationContract, rootArtifactKindIntegrationContract); err != nil {
		return nil, err
	}
	contractID := strings.TrimSpace(stringValue(rootPlan["integration_contract_id"]))
	if contractID == "" {
		return nil, invalidf("portable export root plan requires integration_contract_id")
	}
	ref, ok := rootPlan["integration_contract_ref"].(map[string]any)
	if !ok || ref == nil {
		return nil, invalidf("portable export root plan requires integration_contract_ref")
	}
	target, err := validatePortablePayloadRefObject(ref, inventoryByID)
	if err != nil {
		return nil, err
	}
	if target["kind"] != rootArtifactKindIntegrationContract {
		return nil, invalidf("portable export integration_contract_ref does not target integration_contract")
	}
	portableID := stringValue(contractPayload.Entry["portable_id"])
	if stringValue(target["portable_id"]) != portableID {
		return nil, invalidf("portable export integration_contract_ref does not target the retained integration contract payload")
	}
	artifactDigest, err := digest.StorageEnvelope(rootArtifactKindIntegrationContract, integrationContract)
	if err != nil {
		return nil, err
	}
	if sourceDigest := stringValue(target["source_artifact_digest"]); sourceDigest != artifactDigest {
		return nil, invalidf("portable export integration_contract_ref digest does not match the retained contract payload")
	}
	payloadContractID := strings.TrimSpace(stringValue(integrationContract["contract_id"]))
	if payloadContractID == "" {
		return nil, invalidf("portable export integration contract payload requires contract_id")
	}
	if payloadContractID != contractID {
		return nil, invalidf("portable export integration contract does not match the root plan")
	}
	contractBody, ok := integrationContract["contract"].(map[string]any)
	if !ok || contractBody == nil {
		return nil, invalidf("portable export integration contract payload requires contract body")
	}
	if bodyID := strings.TrimSpace(stringValue(contractBody["id"])); bodyID != "" && bodyID != contractID {
		return nil, invalidf("portable export integration contract body does not match contract_id")
	}
	contractDigest := strings.TrimSpace(stringValue(integrationContract["contract_digest"]))
	if !validDigest(contractDigest) {
		return nil, invalidf("portable export integration contract payload requires contract_digest")
	}
	actualContractDigest, err := digest.SemanticJSON(contractBody)
	if err != nil {
		return nil, err
	}
	if actualContractDigest != contractDigest {
		return nil, invalidf("portable export integration contract_digest does not match contract body")
	}
	planContractDigest := strings.TrimSpace(stringValue(rootPlan["integration_contract_digest"]))
	if !validDigest(planContractDigest) {
		return nil, invalidf("portable export root plan requires integration_contract_digest")
	}
	if planContractDigest != contractDigest {
		return nil, invalidf("portable export root plan integration_contract_digest does not match the selected contract body")
	}
	return &ContractBinding{
		ContractID:     contractID,
		ContractDigest: contractDigest,
		ArtifactDigest: artifactDigest,
		PortableID:     portableID,
	}, nil
}

type contractNamedInputSpec struct {
	Required    bool
	Cardinality string
}

func validateNamedInputManifest(manifest map[string]any, payloads []Payload, inventoryByID map[string]map[string]any, expectedContractID string, contractBody map[string]any) error {
	inputs, ok := manifest["inputs"].([]any)
	if !ok || len(inputs) == 0 {
		return invalidf("portable export requires named inputs with digests")
	}
	if contractID := strings.TrimSpace(stringValue(manifest["contract_id"])); contractID == "" || contractID != expectedContractID {
		return invalidf("portable export named input manifest contract_id does not match the selected contract")
	}
	if inputCount, ok := exactJSONInteger(manifest["input_count"]); ok && inputCount != len(inputs) {
		return invalidf("portable export named input manifest input_count does not match inputs")
	}
	contractInputs, err := contractNamedInputSpecs(contractBody)
	if err != nil {
		return err
	}
	payloadsByID := payloadByPortableID(payloads)
	counts := map[string]int{}
	for index, raw := range inputs {
		entry, ok := raw.(map[string]any)
		if !ok {
			return invalidf("portable export named input entry %d must be an object", index)
		}
		name := stringValue(entry["name"])
		if strings.TrimSpace(name) == "" {
			return invalidf("portable export named input entry %d requires name", index)
		}
		if _, declared := contractInputs[name]; !declared {
			return invalidf("portable export named input %s is not declared by the selected contract", name)
		}
		counts[name]++
		if !validDigest(stringValue(entry["raw_digest"])) {
			return invalidf("portable export named input %s requires raw_digest", name)
		}
		ref, ok := entry["content_ref"].(map[string]any)
		if !ok || ref == nil {
			return invalidf("portable export named input %s requires content_ref", name)
		}
		target, err := validatePortablePayloadRefObject(ref, inventoryByID)
		if err != nil {
			return err
		}
		if target["kind"] != rootArtifactKindNamedInputContent {
			return invalidf("portable export named input %s content_ref does not target named_input_content", name)
		}
		content, err := namedInputEntryContent(entry, payloadsByID)
		if err != nil {
			return err
		}
		if content.Name != name {
			return invalidf("portable export named input %s content name does not match manifest", name)
		}
		if ordinal, ok := exactJSONInteger(entry["ordinal"]); !ok || ordinal != content.Ordinal {
			return invalidf("portable export named input %s content ordinal does not match manifest", name)
		}
		if nameOrdinal, ok := exactJSONInteger(entry["name_ordinal"]); !ok || nameOrdinal != content.NameOrdinal {
			return invalidf("portable export named input %s content name_ordinal does not match manifest", name)
		}
		if sizeBytes, ok := exactJSONInteger(entry["size_bytes"]); !ok || sizeBytes != content.SizeBytes {
			return invalidf("portable export named input %s size_bytes does not match content", name)
		}
		if stringValue(entry["media_type"]) != content.MediaType || stringValue(entry["schema_status"]) != content.SchemaStatus {
			return invalidf("portable export named input %s metadata does not match content", name)
		}
		if stringValue(entry["raw_digest"]) != content.RawDigest {
			return invalidf("portable export named input %s raw_digest does not match content", name)
		}
	}
	for name, spec := range contractInputs {
		count := counts[name]
		if spec.Cardinality == "one" && count > 1 {
			return invalidf("portable export named input %s violates selected contract cardinality one", name)
		}
		if spec.Required && count == 0 {
			return invalidf("portable export missing required named input %s", name)
		}
		if spec.Required && spec.Cardinality == "one" && count != 1 {
			return invalidf("portable export named input %s must appear exactly once", name)
		}
	}
	return nil
}

func contractNamedInputSpecs(contractBody map[string]any) (map[string]contractNamedInputSpec, error) {
	inputs, ok := contractBody["inputs"].(map[string]any)
	if !ok || len(inputs) == 0 {
		return nil, invalidf("portable export selected contract requires named input declarations")
	}
	specs := map[string]contractNamedInputSpec{}
	for name, raw := range inputs {
		if strings.TrimSpace(name) == "" {
			return nil, invalidf("portable export selected contract has an empty named input")
		}
		object, ok := raw.(map[string]any)
		if !ok || object == nil {
			return nil, invalidf("portable export selected contract named input %s must be an object", name)
		}
		required, ok := object["required"].(bool)
		if !ok {
			required = false
		}
		cardinality := strings.TrimSpace(stringValue(object["cardinality"]))
		if cardinality == "" {
			cardinality = "one"
		}
		specs[name] = contractNamedInputSpec{Required: required, Cardinality: cardinality}
	}
	return specs, nil
}

func namedInputEntryContent(entry map[string]any, payloadsByID map[string]Payload) (*namedInputContent, error) {
	ref, ok := entry["content_ref"].(map[string]any)
	if !ok || ref == nil {
		return nil, invalidf("portable export named input %s requires content_ref", stringValue(entry["name"]))
	}
	portableID := stringValue(ref["portable_id"])
	payload, ok := payloadsByID[portableID]
	if !ok {
		return nil, invalidf("portable export payload closure is missing %s", portableID)
	}
	if payload.Entry["kind"] != rootArtifactKindNamedInputContent {
		return nil, invalidf("portable export named input %s content_ref does not target named_input_content", stringValue(entry["name"]))
	}
	object, ok := payload.Value.(map[string]any)
	if !ok || object == nil {
		return nil, invalidf("portable named input content payload must be an object")
	}
	return decodeNamedInputContent(object)
}

func decodeNamedInputContent(object map[string]any) (*namedInputContent, error) {
	if err := validateRootArtifactEnvelope(object, rootArtifactKindNamedInputContent); err != nil {
		return nil, err
	}
	ordinal, ok := exactJSONInteger(object["ordinal"])
	if !ok || ordinal < 1 {
		return nil, invalidf("portable named input content requires positive ordinal")
	}
	name := strings.TrimSpace(stringValue(object["name"]))
	if name == "" {
		return nil, invalidf("portable named input content requires name")
	}
	nameOrdinal, ok := exactJSONInteger(object["name_ordinal"])
	if !ok || nameOrdinal < 1 {
		return nil, invalidf("portable named input content requires positive name_ordinal")
	}
	if object["encoding"] != "base64" {
		return nil, invalidf("portable named input content requires base64 encoding")
	}
	encoded := stringValue(object["bytes_base64"])
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, invalidf("portable named input content bytes_base64 is invalid")
	}
	sizeBytes, ok := exactJSONInteger(object["size_bytes"])
	if !ok || sizeBytes != len(data) {
		return nil, invalidf("portable named input content size_bytes does not match decoded bytes")
	}
	rawDigest := stringValue(object["raw_digest"])
	if !validDigest(rawDigest) || rawDigest != digest.RawBytes(data) {
		return nil, invalidf("portable named input content raw_digest does not match decoded bytes")
	}
	mediaType := strings.TrimSpace(stringValue(object["media_type"]))
	if mediaType == "" {
		return nil, invalidf("portable named input content requires media_type")
	}
	schemaStatus := strings.TrimSpace(stringValue(object["schema_status"]))
	if schemaStatus == "" {
		return nil, invalidf("portable named input content requires schema_status")
	}
	return &namedInputContent{
		Ordinal:      ordinal,
		Name:         name,
		NameOrdinal:  nameOrdinal,
		SizeBytes:    sizeBytes,
		RawDigest:    rawDigest,
		MediaType:    mediaType,
		SchemaStatus: schemaStatus,
		Data:         append([]byte(nil), data...),
	}, nil
}

func validateWitnessProviderInvocations(payloads []Payload, inventoryByID map[string]map[string]any, participantTurns int) (*witnessInvocationSet, []UnverifiedRelationship, error) {
	result := &witnessInvocationSet{
		Participants: map[int]witnessInvocation{},
		Facilitators: map[int]witnessInvocation{},
	}
	payloadsByID := payloadByPortableID(payloads)
	var unverified []UnverifiedRelationship
	for _, payload := range payloads {
		if payload.Entry["kind"] != rootArtifactKindProviderInvocation {
			continue
		}
		portableID := stringValue(payload.Entry["portable_id"])
		object, ok := payload.Value.(map[string]any)
		if !ok {
			return nil, nil, invalidf("portable provider invocation payload must be an object")
		}
		invocation, ok := object["invocation"].(map[string]any)
		if !ok || invocation == nil {
			return nil, nil, invalidf("portable provider invocation payload is missing invocation")
		}
		if stringValue(invocation["provider_retry"]) != "forbid" {
			return nil, nil, invalidf("portable provider invocation requires provider_retry=forbid")
		}
		if invocation["provider_launch_attempted"] != true {
			return nil, nil, invalidf("portable witness provider invocation %s must be launched", stringValue(invocation["invocation_id"]))
		}
		if runnerAttempt, ok := exactJSONInteger(invocation["runner_attempt"]); !ok || runnerAttempt != 1 {
			return nil, nil, invalidf("portable witness provider invocation %s requires runner_attempt 1", stringValue(invocation["invocation_id"]))
		}
		if !successfulProviderOutcome(stringValue(invocation["outcome"])) {
			return nil, nil, invalidf("portable witness provider invocation %s requires successful outcome", stringValue(invocation["invocation_id"]))
		}
		resultRef, ok := invocation["provider_result_ref"].(map[string]any)
		if !ok || resultRef == nil {
			return nil, nil, invalidf("portable witness provider invocation %s requires provider_result_ref", stringValue(invocation["invocation_id"]))
		}
		resultEntry, err := validatePortablePayloadRefObject(resultRef, inventoryByID)
		if err != nil {
			return nil, nil, err
		}
		if resultEntry["kind"] != rootArtifactKindProviderResult {
			return nil, nil, invalidf("portable witness provider invocation %s result ref does not target provider_result", stringValue(invocation["invocation_id"]))
		}
		promptText, promptAvailable, promptUnverified, err := renderedPromptForInvocation(invocation, inventoryByID, payloadsByID)
		if err != nil {
			return nil, nil, err
		}
		unverified = append(unverified, promptUnverified...)
		record := witnessInvocation{
			Phase:            stringValue(invocation["phase"]),
			PortableID:       portableID,
			ResultPortableID: stringValue(resultEntry["portable_id"]),
			PromptText:       promptText,
			PromptAvailable:  promptAvailable,
		}
		switch record.Phase {
		case "participant":
			ordinal, ok := exactJSONInteger(invocation["participant_ordinal"])
			if !ok || ordinal < 1 || ordinal > participantTurns {
				return nil, nil, invalidf("portable participant invocation requires ordinal 1 through %d", participantTurns)
			}
			if _, exists := result.Participants[ordinal]; exists {
				return nil, nil, invalidf("portable export has duplicate participant invocation for ordinal %d", ordinal)
			}
			record.Ordinal = ordinal
			result.Participants[ordinal] = record
		case "facilitator":
			ordinal, ok := exactJSONInteger(invocation["participant_ordinal"])
			if !ok || ordinal < 1 || ordinal > participantTurns {
				return nil, nil, invalidf("portable facilitator invocation requires participant ordinal 1 through %d", participantTurns)
			}
			if _, exists := result.Facilitators[ordinal]; exists {
				return nil, nil, invalidf("portable export has duplicate facilitator invocation for ordinal %d", ordinal)
			}
			record.Ordinal = ordinal
			result.Facilitators[ordinal] = record
		case "reducer":
			if invocation["reducer_fresh"] != true {
				return nil, nil, invalidf("portable reducer invocation requires reducer_fresh=true")
			}
			if result.Reducer != nil {
				return nil, nil, invalidf("portable export has duplicate reducer invocation")
			}
			result.Reducer = &record
		default:
			return nil, nil, invalidf("portable witness provider invocation has unsupported phase %q", record.Phase)
		}
	}
	for ordinal := 1; ordinal <= participantTurns; ordinal++ {
		if _, exists := result.Participants[ordinal]; !exists {
			return nil, nil, invalidf("portable export requires participant invocation for ordinal %d", ordinal)
		}
		if _, exists := result.Facilitators[ordinal]; !exists {
			return nil, nil, invalidf("portable export requires facilitator invocation for ordinal %d", ordinal)
		}
	}
	if result.Reducer == nil {
		return nil, nil, invalidf("portable export requires reducer invocation lineage")
	}
	return result, unverified, nil
}

func renderedPromptForInvocation(invocation map[string]any, inventoryByID map[string]map[string]any, payloadsByID map[string]Payload) (string, bool, []UnverifiedRelationship, error) {
	refValue := invocation["rendered_prompt_ref"]
	if refValue == nil {
		return "", false, []UnverifiedRelationship{{
			Code:         "rendered_prompt_ref_missing",
			Relationship: "trace_only_facilitator_ledger_prompt_projection",
			Reason:       "provider invocation did not retain rendered_prompt_ref, so participant/reducer prompt contents cannot be inspected",
		}}, nil
	}
	ref, ok := refValue.(map[string]any)
	if !ok || ref == nil {
		return "", false, nil, invalidf("portable provider invocation rendered_prompt_ref must be a portable payload ref")
	}
	entry, err := validatePortablePayloadRefObject(ref, inventoryByID)
	if err != nil {
		return "", false, nil, err
	}
	if entry["kind"] != rootArtifactKindRenderedPrompt {
		return "", false, nil, invalidf("portable provider invocation rendered_prompt_ref does not target rendered_prompt")
	}
	payload := payloadsByID[stringValue(entry["portable_id"])]
	if payload.Value == nil {
		return "", false, nil, invalidf("portable export payload closure is missing %s", stringValue(entry["portable_id"]))
	}
	text, rawDigest, err := renderedPromptText(payload)
	if err != nil {
		return "", false, nil, err
	}
	if stringValue(invocation["rendered_prompt_digest"]) != rawDigest {
		return "", false, nil, invalidf("portable provider invocation rendered_prompt_digest does not match rendered prompt bytes")
	}
	return text, true, nil, nil
}

func renderedPromptText(payload Payload) (string, string, error) {
	object, ok := payload.Value.(map[string]any)
	if !ok || object == nil {
		return "", "", invalidf("portable rendered prompt payload must be an object")
	}
	if err := validateRootArtifactEnvelope(object, rootArtifactKindRenderedPrompt); err != nil {
		return "", "", err
	}
	record, ok := object["rendered_prompt"].(map[string]any)
	if !ok || record == nil {
		return "", "", invalidf("portable rendered prompt payload requires rendered_prompt")
	}
	if record["schema_version"] != RenderedPromptV1 {
		return "", "", invalidf("portable rendered prompt schema_version must be %s", RenderedPromptV1)
	}
	if record["media_type"] != "text/plain; charset=utf-8" || record["encoding"] != "base64" {
		return "", "", invalidf("portable rendered prompt requires UTF-8 text encoded as base64")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(stringValue(record["bytes_base64"]))
	if err != nil {
		return "", "", invalidf("portable rendered prompt bytes_base64 is invalid")
	}
	if !utf8.Valid(data) {
		return "", "", invalidf("portable rendered prompt bytes must be valid UTF-8")
	}
	sizeBytes, ok := exactJSONInteger(record["size_bytes"])
	if !ok || sizeBytes != len(data) {
		return "", "", invalidf("portable rendered prompt size_bytes does not match decoded bytes")
	}
	rawDigest := stringValue(record["raw_digest"])
	if !validDigest(rawDigest) || rawDigest != digest.RawBytes(data) {
		return "", "", invalidf("portable rendered prompt raw_digest does not match decoded bytes")
	}
	return string(data), rawDigest, nil
}

func validateParticipantTranscript(transcript []any, invocations *witnessInvocationSet, inventoryByID map[string]map[string]any) error {
	if invocations == nil {
		return invalidf("portable export requires provider invocation lineage")
	}
	for index, raw := range transcript {
		entry, ok := raw.(map[string]any)
		if !ok || entry == nil {
			return invalidf("portable participant transcript entry %d must be an object", index)
		}
		ordinal := index + 1
		if turn, ok := exactJSONInteger(entry["participant_turn"]); !ok || turn != ordinal {
			return invalidf("portable participant transcript entry %d must be participant_turn %d", index, ordinal)
		}
		invocation, exists := invocations.Participants[ordinal]
		if !exists {
			return invalidf("portable participant transcript entry %d has no matching participant invocation", index)
		}
		if ref, ok := entry["provider_invocation_ref"].(map[string]any); ok && ref != nil {
			target, err := validatePortablePayloadRefObject(ref, inventoryByID)
			if err != nil {
				return err
			}
			if target["kind"] != rootArtifactKindProviderInvocation || stringValue(target["portable_id"]) != invocation.PortableID {
				return invalidf("portable participant transcript entry %d provider_invocation_ref does not match participant invocation", index)
			}
			continue
		}
		ref, ok := entry["provider_result_ref"].(map[string]any)
		if !ok || ref == nil {
			return invalidf("portable participant transcript entry %d requires provider_result_ref or provider_invocation_ref", index)
		}
		target, err := validatePortablePayloadRefObject(ref, inventoryByID)
		if err != nil {
			return err
		}
		if target["kind"] != rootArtifactKindProviderResult || stringValue(target["portable_id"]) != invocation.ResultPortableID {
			return invalidf("portable participant transcript entry %d provider_result_ref does not match participant invocation", index)
		}
	}
	return nil
}

func validateTraceOnlyPromptProjection(transcript []any, invocations *witnessInvocationSet) ([]UnverifiedRelationship, error) {
	if invocations == nil {
		return nil, invalidf("portable export requires provider invocation lineage")
	}
	ledgerItems := transcriptLedgerItems(transcript)
	participantContents := transcriptContents(transcript)
	var unverified []UnverifiedRelationship
	for ordinal := 1; ordinal <= len(invocations.Participants); ordinal++ {
		invocation := invocations.Participants[ordinal]
		items, err := validateConsumerPromptTraceOnly(invocation, ledgerItems, participantContents)
		if err != nil {
			return nil, err
		}
		unverified = append(unverified, items...)
	}
	if invocations.Reducer != nil {
		items, err := validateConsumerPromptTraceOnly(*invocations.Reducer, ledgerItems, participantContents)
		if err != nil {
			return nil, err
		}
		unverified = append(unverified, items...)
	}
	return unverified, nil
}

func validateConsumerPromptTraceOnly(invocation witnessInvocation, ledgerItems []string, participantContents []string) ([]UnverifiedRelationship, error) {
	if !invocation.PromptAvailable {
		return []UnverifiedRelationship{{
			Code:         "rendered_prompt_unavailable",
			Relationship: "trace_only_facilitator_ledger_prompt_projection",
			Reason:       "rendered prompt bytes were not retained for " + invocation.Phase + " invocation",
		}}, nil
	}
	for _, marker := range []string{
		"--- Current Facilitator Ledger ---",
		"--- Facilitator Ledger (Data Only) ---",
	} {
		if strings.Contains(invocation.PromptText, marker) {
			return nil, invalidf("portable %s prompt embeds facilitator ledger section despite trace_only projection", invocation.Phase)
		}
	}
	var unverified []UnverifiedRelationship
	for _, item := range ledgerItems {
		if item == "" || !strings.Contains(invocation.PromptText, item) {
			continue
		}
		if stringContainedInAny(item, participantContents) {
			unverified = append(unverified, UnverifiedRelationship{
				Code:         "facilitator_ledger_content_collision",
				Relationship: "trace_only_facilitator_ledger_prompt_projection",
				Reason:       "a facilitator ledger string also appears in participant transcript content, so its prompt occurrence cannot be attributed",
			})
			continue
		}
		return nil, invalidf("portable %s prompt embeds facilitator ledger content despite trace_only projection", invocation.Phase)
	}
	return unverified, nil
}

func validateResultValidationCanonicalRef(resultValidation map[string]any, canonicalResultPayload Payload, inventoryByID map[string]map[string]any) error {
	ref, ok := resultValidation["canonical_result_ref"].(map[string]any)
	if !ok || ref == nil {
		return invalidf("portable export result validation requires canonical_result_ref")
	}
	target, err := validatePortablePayloadRefObject(ref, inventoryByID)
	if err != nil {
		return err
	}
	if target["kind"] != rootArtifactKindCanonicalResult {
		return invalidf("portable export result validation canonical_result_ref does not target canonical_result")
	}
	if stringValue(target["portable_id"]) != stringValue(canonicalResultPayload.Entry["portable_id"]) {
		return invalidf("portable export result validation canonical_result_ref does not match canonical result payload")
	}
	return nil
}

func reducerResultFromPayloads(payloads []Payload) (*ReducerResult, error) {
	canonicalResult, err := singlePayloadObject(payloads, rootArtifactKindCanonicalResult)
	if err != nil {
		return nil, err
	}
	if err := validateRootArtifactEnvelope(canonicalResult, rootArtifactKindCanonicalResult); err != nil {
		return nil, err
	}
	value, ok := canonicalResult["value"]
	if !ok || value == nil {
		return nil, invalidf("portable canonical result requires value")
	}
	valueObject, ok := value.(map[string]any)
	if !ok {
		return nil, invalidf("portable canonical result value must be an object")
	}
	if stringValue(valueObject["schema_version"]) != "relay-witness-verdicts-v2" {
		return nil, invalidf("portable canonical result must use relay-witness-verdicts-v2")
	}
	canonicalBytes, err := canonjson.Marshal(value)
	if err != nil {
		return nil, err
	}
	if stringValue(canonicalResult["canonical_json"]) != string(canonicalBytes) {
		return nil, invalidf("portable canonical result canonical_json does not match value")
	}
	valueDigest, err := digest.SemanticJSON(value)
	if err != nil {
		return nil, err
	}
	return &ReducerResult{Value: value, Digest: valueDigest}, nil
}

func validateRootArtifactEnvelope(object map[string]any, expectedKind string) error {
	if stringValue(object["kind"]) != expectedKind {
		return invalidf("root artifact kind %q does not match expected kind %q", stringValue(object["kind"]), expectedKind)
	}
	version, ok := exactJSONInteger(object["schema_version"])
	if !ok || (version != 1 && version != 2) {
		return invalidf("%s requires root artifact schema_version 1 or 2", expectedKind)
	}
	if version == 2 && object["digest_profile"] != digest.Profile {
		return invalidf("%s schema_version 2 requires digest_profile %s", expectedKind, digest.Profile)
	}
	return nil
}

func singlePayloadObject(payloads []Payload, kind string) (map[string]any, error) {
	payload, err := singlePayload(payloads, kind)
	if err != nil {
		return nil, err
	}
	object, ok := payload.Value.(map[string]any)
	if !ok {
		return nil, invalidf("portable %s payload must be an object", kind)
	}
	return object, nil
}

func singlePayload(payloads []Payload, kind string) (Payload, error) {
	var found Payload
	count := 0
	for _, payload := range payloads {
		if payload.Entry["kind"] != kind {
			continue
		}
		count++
		found = payload
	}
	if count == 0 {
		return Payload{}, invalidf("portable export requires %s payload", kind)
	}
	if count > 1 {
		return Payload{}, invalidf("portable export requires exactly one %s payload", kind)
	}
	return found, nil
}

func payloadByPortableID(payloads []Payload) map[string]Payload {
	result := map[string]Payload{}
	for _, payload := range payloads {
		result[stringValue(payload.Entry["portable_id"])] = payload
	}
	return result
}

func inventoryByPortableID(payloads []Payload) map[string]map[string]any {
	result := map[string]map[string]any{}
	for _, payload := range payloads {
		result[stringValue(payload.Entry["portable_id"])] = payload.Entry
	}
	return result
}

func optionalPayloadObject(payloads []Payload, kind string) (map[string]any, bool) {
	object, err := singlePayloadObject(payloads, kind)
	return object, err == nil
}

func singlePayloadArray(payloads []Payload, kind string) ([]any, error) {
	var found []any
	count := 0
	for _, payload := range payloads {
		if payload.Entry["kind"] != kind {
			continue
		}
		count++
		array, ok := payload.Value.([]any)
		if !ok {
			return nil, invalidf("portable %s payload must be an array", kind)
		}
		found = array
	}
	if count == 0 {
		return nil, invalidf("portable export requires %s payload", kind)
	}
	if count > 1 {
		return nil, invalidf("portable export requires exactly one %s payload", kind)
	}
	return found, nil
}

func terminalSucceeded(status string) bool {
	switch strings.TrimSpace(status) {
	case "completed", "success":
		return true
	default:
		return false
	}
}

func successfulProviderOutcome(status string) bool {
	switch strings.TrimSpace(status) {
	case "completed", "success":
		return true
	default:
		return false
	}
}

func expectedWitnessContract(contractID string) bool {
	switch strings.TrimSpace(contractID) {
	case witnessContractFalsificationV2, witnessContractEconomyV2:
		return true
	default:
		return false
	}
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(stringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func transcriptLedgerItems(transcript []any) []string {
	seen := map[string]bool{}
	var result []string
	for _, raw := range transcript {
		entry, _ := raw.(map[string]any)
		ledger, _ := entry["ledger"].(map[string]any)
		for _, key := range []string{"settled", "contested", "withdrawn"} {
			items, _ := ledger[key].([]any)
			for _, item := range items {
				text := strings.TrimSpace(stringValue(item))
				if text != "" && !seen[text] {
					seen[text] = true
					result = append(result, text)
				}
			}
		}
	}
	return result
}

func transcriptContents(transcript []any) []string {
	var result []string
	for _, raw := range transcript {
		entry, _ := raw.(map[string]any)
		if text := stringValue(entry["content"]); text != "" {
			result = append(result, text)
		}
	}
	return result
}

func stringContainedInAny(needle string, haystacks []string) bool {
	for _, haystack := range haystacks {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
