package portable

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

const (
	ExportSchemaVersion  = "relay-root-portable-export-v2"
	ProviderInvocationV2 = "relay-provider-invocation-v2"
	RenderedPromptV1     = "relay-rendered-prompt-v1"
	CodeInvalidPortable  = "invalid_portable_export"
	StatusValid          = "valid"
	StatusInvalid        = "invalid"
)

const (
	rootArtifactKindRootRecipePlan      = "root_recipe_plan"
	rootArtifactKindIntegrationBundle   = "integration_bundle"
	rootArtifactKindIntegrationContract = "integration_contract"
	rootArtifactKindNamedInputManifest  = "named_input_manifest"
	rootArtifactKindNamedInputContent   = "named_input_content"
	rootArtifactKindRetainedInputs      = "retained_input_materialization"
	rootArtifactKindExecutionWorkspace  = "execution_workspace"
	rootArtifactKindRootCheckpoint      = "root_checkpoint"
	rootArtifactKindReducerAttempt      = "reducer_attempt"
	rootArtifactKindRawResult           = "raw_result"
	rootArtifactKindResultValidation    = "result_validation"
	rootArtifactKindCanonicalResult     = "canonical_result"
	rootArtifactKindRenderedPrompt      = "rendered_prompt"
	rootArtifactKindProviderInvocation  = "provider_invocation"
	rootArtifactKindProviderResult      = "provider_result"
	rootArtifactKindIsolationReport     = "workspace_isolation_report"
)

var (
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sourceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
	portablePartRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

type Report struct {
	SchemaVersion           string                   `json:"schema_version"`
	Status                  string                   `json:"status"`
	TerminalStatus          string                   `json:"terminal_status,omitempty"`
	PayloadCount            int                      `json:"payload_count,omitempty"`
	ManifestDigest          string                   `json:"manifest_digest,omitempty"`
	UnverifiedRelationships []UnverifiedRelationship `json:"unverified_relationships,omitempty"`
	Diagnostics             []diag.Diagnostic        `json:"diagnostics,omitempty"`
}

type DetailedReport struct {
	Report
	Manifest map[string]any
	Payloads []Payload
}

// UnverifiedRelationship records a contract relationship the export did not
// retain enough data to prove. These are not validity failures, but callers can
// surface them instead of treating the relationship as silently checked.
type UnverifiedRelationship struct {
	Code         string `json:"code"`
	Relationship string `json:"relationship"`
	Reason       string `json:"reason"`
}

type Payload struct {
	Entry map[string]any
	Value any
	Body  []byte
}

func VerifyDirectory(directory string) (*Report, error) {
	detailed, err := VerifyDirectoryDetailed(directory)
	if err != nil {
		return &Report{
			SchemaVersion: ExportSchemaVersion,
			Status:        StatusInvalid,
			Diagnostics:   []diag.Diagnostic{diag.FromError(err)},
		}, err
	}
	report := detailed.Report
	return &report, nil
}

func VerifyDirectoryDetailed(directory string) (*DetailedReport, error) {
	root, err := canonicalDirectory(directory)
	if err != nil {
		return nil, err
	}
	manifestBody, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return nil, invalidf("portable export manifest.json could not be read: %v", err)
	}
	manifestValue, err := strictjson.DecodeAnyBytes(manifestBody, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, err
	}
	manifest, err := validateManifest(manifestValue)
	if err != nil {
		return nil, err
	}

	expectedFiles := map[string]bool{"manifest.json": true}
	inventoryByID := map[string]map[string]any{}
	sourceRefs := map[string]string{}
	payloads := make([]Payload, 0, len(manifest["payload_inventory"].([]any)))
	for _, raw := range manifest["payload_inventory"].([]any) {
		entry := raw.(map[string]any)
		if err := validateInventorySource(entry, sourceRefs); err != nil {
			return nil, err
		}
		inventoryByID[stringValue(entry["portable_id"])] = entry
		relative := stringValue(entry["path"])
		expectedFiles[relative] = true
		body, err := readInventoriedPayload(root, entry)
		if err != nil {
			return nil, err
		}
		value, err := strictjson.DecodeAnyBytes(body, strictjson.DefaultMaxBytes*32)
		if err != nil {
			return nil, invalidf("decode portable export payload %s: %v", relative, err)
		}
		payloads = append(payloads, Payload{Entry: entry, Value: value, Body: body})
	}

	for _, payload := range payloads {
		if err := validatePayloadMatchesInventory(payload); err != nil {
			return nil, err
		}
		if refs := findSourceArtifactRefs(payload.Value); len(refs) > 0 {
			return nil, invalidf("portable export retains a source-session artifact ref")
		}
		if err := validatePortablePayloadRefs(payload.Value, inventoryByID); err != nil {
			return nil, err
		}
	}
	if err := validateProviderLineage(payloads, inventoryByID); err != nil {
		return nil, err
	}
	unverified, err := validateWitnessRunContract(manifest, payloads, inventoryByID)
	if err != nil {
		return nil, err
	}
	if err := verifyClosedFileSet(root, expectedFiles); err != nil {
		return nil, err
	}
	report := Report{
		SchemaVersion:           ExportSchemaVersion,
		Status:                  StatusValid,
		TerminalStatus:          stringValue(manifest["terminal_status"]),
		PayloadCount:            len(payloads),
		ManifestDigest:          stringValue(manifest["manifest_digest"]),
		UnverifiedRelationships: unverified,
	}
	return &DetailedReport{Report: report, Manifest: manifest, Payloads: payloads}, nil
}

func validateManifest(value any) (map[string]any, error) {
	manifest, err := requireObject(value, "portable export manifest")
	if err != nil {
		return nil, err
	}
	if err := validateAllowedKeys("portable export manifest", manifest, []string{
		"schema_version", "convo_relay_version", "digest_profile", "terminal_status", "stop_reason",
		"session_payload", "transcript_payload", "diagnostics_payload", "payload_inventory",
		"inventory_digest", "manifest_digest",
	}); err != nil {
		return nil, err
	}
	if manifest["schema_version"] != ExportSchemaVersion {
		return nil, invalidf("portable export schema_version must be %s", ExportSchemaVersion)
	}
	if strings.TrimSpace(stringValue(manifest["convo_relay_version"])) == "" {
		return nil, invalidf("portable export requires convo_relay_version")
	}
	if manifest["digest_profile"] != digest.Profile {
		return nil, invalidf("portable export requires digest_profile %s", digest.Profile)
	}
	if strings.TrimSpace(stringValue(manifest["terminal_status"])) == "" {
		return nil, invalidf("portable export requires terminal_status")
	}
	if manifest["stop_reason"] != nil {
		if _, ok := manifest["stop_reason"].(string); !ok {
			return nil, invalidf("portable export stop_reason must be null or a string")
		}
	}
	rawInventory, ok := manifest["payload_inventory"].([]any)
	if !ok || len(rawInventory) == 0 {
		return nil, invalidf("portable export payload_inventory must be a non-empty array")
	}
	inventory := make([]any, 0, len(rawInventory))
	paths := map[string]bool{}
	portableIDs := map[string]bool{}
	previousPath := ""
	for index, raw := range rawInventory {
		entry, err := validateInventoryEntry(raw, index)
		if err != nil {
			return nil, err
		}
		entryPath := stringValue(entry["path"])
		portableID := stringValue(entry["portable_id"])
		if paths[entryPath] || portableIDs[portableID] || previousPath >= entryPath && previousPath != "" {
			return nil, invalidf("portable export payload_inventory must use unique ids and ascending paths")
		}
		paths[entryPath] = true
		portableIDs[portableID] = true
		previousPath = entryPath
		inventory = append(inventory, entry)
	}
	for _, field := range []string{"session_payload", "transcript_payload", "diagnostics_payload"} {
		payloadPath := stringValue(manifest[field])
		if payloadPath == "" || !paths[payloadPath] {
			return nil, invalidf("portable export %s must name an inventoried payload", field)
		}
	}
	manifest["payload_inventory"] = inventory
	if err := requireMatchingSemanticDigest(manifest["inventory_digest"], inventory, "portable export inventory"); err != nil {
		return nil, err
	}
	materialized, err := materializeObject(manifest)
	if err != nil {
		return nil, err
	}
	delete(materialized, "manifest_digest")
	if err := requireMatchingSemanticDigest(manifest["manifest_digest"], materialized, "portable export manifest"); err != nil {
		return nil, err
	}
	return manifest, nil
}

func validateInventoryEntry(value any, index int) (map[string]any, error) {
	entry, err := requireObject(value, "portable export inventory entry")
	if err != nil {
		return nil, err
	}
	if err := validateAllowedKeys("portable export inventory entry", entry, []string{
		"kind", "portable_id", "path", "media_type", "size_bytes", "digest_class", "digest", "source_artifact_id", "source_artifact_digest",
	}); err != nil {
		return nil, err
	}
	kind := stringValue(entry["kind"])
	portableID := stringValue(entry["portable_id"])
	payloadPath := stringValue(entry["path"])
	if !portablePathComponent(kind) || !portablePathComponent(portableID) ||
		payloadPath != path.Join("payloads", kind, portableID+".json") {
		return nil, invalidf("portable export payload_inventory[%d] has an invalid path identity", index)
	}
	if entry["media_type"] != "application/json" || entry["digest_class"] != digest.ClassRawBytes {
		return nil, invalidf("portable export payload_inventory[%d] must describe raw JSON bytes", index)
	}
	size, ok := exactJSONInteger(entry["size_bytes"])
	if !ok || size < 0 {
		return nil, invalidf("portable export payload_inventory[%d] size_bytes must be nonnegative", index)
	}
	entry["size_bytes"] = size
	payloadDigest := stringValue(entry["digest"])
	if !validDigest(payloadDigest) {
		return nil, invalidf("portable export payload_inventory[%d] digest is invalid", index)
	}
	if entry["source_artifact_id"] != nil {
		if err := requireSourceIdentity(entry, "portable export inventory entry"); err != nil {
			return nil, err
		}
	} else if entry["source_artifact_digest"] != nil {
		return nil, invalidf("portable export source_artifact_digest requires source_artifact_id")
	}
	return entry, nil
}

func readInventoriedPayload(root string, entry map[string]any) ([]byte, error) {
	relative := stringValue(entry["path"])
	filename := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalidf("portable export payload %s is missing or not a regular file", relative)
	}
	declaredSize := int64(entry["size_bytes"].(int))
	if info.Size() != declaredSize {
		return nil, invalidf("portable export payload %s size or digest mismatch", relative)
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != declaredSize || digest.RawBytes(body) != entry["digest"] {
		return nil, invalidf("portable export payload %s size or digest mismatch", relative)
	}
	return body, nil
}

func validatePayloadMatchesInventory(payload Payload) error {
	entryKind := stringValue(payload.Entry["kind"])
	if syntheticEntry(payload.Entry) {
		return nil
	}
	if err := requireSourceIdentity(payload.Entry, "portable "+entryKind+" payload"); err != nil {
		return err
	}
	object, ok := payload.Value.(map[string]any)
	if !ok {
		return invalidf("portable export payload %s must be an object", payload.Entry["portable_id"])
	}
	if stringValue(object["kind"]) != entryKind {
		return invalidf("portable export payload %s kind does not match inventory kind %s", payload.Entry["portable_id"], entryKind)
	}
	return nil
}

func validateInventorySource(entry map[string]any, seen map[string]string) error {
	if !syntheticEntry(entry) {
		if err := requireSourceIdentity(entry, "portable "+stringValue(entry["kind"])+" payload"); err != nil {
			return err
		}
	}
	if entry["source_artifact_id"] == nil {
		return nil
	}
	if err := requireSourceIdentity(entry, "portable "+stringValue(entry["kind"])+" payload"); err != nil {
		return err
	}
	sourceID := stringValue(entry["source_artifact_id"])
	sourceDigest := stringValue(entry["source_artifact_digest"])
	sourceKey := sourceID + "\x00" + sourceDigest
	if prior := seen[sourceKey]; prior != "" {
		return invalidf("portable export source artifact ref is duplicated by %s and %s", prior, entry["portable_id"])
	}
	seen[sourceKey] = stringValue(entry["portable_id"])
	entryKind := stringValue(entry["kind"])
	sourceKind, _, _ := strings.Cut(sourceID, ":")
	if (rootArtifactKind(entryKind) || rootArtifactKind(sourceKind)) && entryKind != sourceKind {
		return invalidf("portable export payload %s kind does not match source artifact kind %s", entry["portable_id"], sourceKind)
	}
	return nil
}

func validatePortablePayloadRefs(value any, inventoryByID map[string]map[string]any) error {
	if object, ok := value.(map[string]any); ok && portablePayloadRefShaped(object) {
		_, err := validatePortablePayloadRefObject(object, inventoryByID)
		return err
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, item := range typed {
			if err := validatePortablePayloadRefs(item, inventoryByID); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := validatePortablePayloadRefs(item, inventoryByID); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePortablePayloadRefObject(object map[string]any, inventoryByID map[string]map[string]any) (map[string]any, error) {
	if object["kind"] != "portable_payload_ref" {
		return nil, invalidf("portable payload ref requires kind portable_payload_ref")
	}
	portableID := stringValue(object["portable_id"])
	if portableID == "" {
		return nil, invalidf("portable payload ref requires portable_id")
	}
	entry := inventoryByID[portableID]
	if entry == nil {
		return nil, invalidf("portable export payload closure is missing %s", portableID)
	}
	if err := validateAllowedKeys("portable payload ref", object, []string{"kind", "portable_id", "source_artifact_id", "source_artifact_digest"}); err != nil {
		return nil, err
	}
	refSourceID := stringValue(object["source_artifact_id"])
	refSourceDigest := stringValue(object["source_artifact_digest"])
	if !validSourceIdentity(refSourceID, refSourceDigest) {
		return nil, invalidf("portable payload ref requires source artifact identity")
	}
	entrySourceID := stringValue(entry["source_artifact_id"])
	entrySourceDigest := stringValue(entry["source_artifact_digest"])
	if !validSourceIdentity(entrySourceID, entrySourceDigest) {
		return nil, invalidf("portable payload ref target %s requires source artifact identity", portableID)
	}
	if refSourceID != entrySourceID || refSourceDigest != entrySourceDigest {
		return nil, invalidf("portable payload ref source identity mismatch for %s", portableID)
	}
	return entry, nil
}

func validateProviderLineage(payloads []Payload, inventoryByID map[string]map[string]any) error {
	resultRecords := map[string]map[string]any{}
	resultKeys := map[string]string{}
	for _, payload := range payloads {
		if payload.Entry["kind"] != rootArtifactKindProviderResult {
			continue
		}
		portableID := stringValue(payload.Entry["portable_id"])
		object, ok := payload.Value.(map[string]any)
		if !ok {
			return invalidf("portable provider result payload must be an object")
		}
		if err := validateRootArtifact(object, rootArtifactKindProviderResult); err != nil {
			return invalidf("portable provider result root artifact is invalid: %v", err)
		}
		record, err := validateProviderResultRecord(object)
		if err != nil {
			return err
		}
		key := providerAttemptKey(record)
		if prior := resultKeys[key]; prior != "" {
			return invalidf("portable provider results %s and %s duplicate invocation_id and runner_attempt", prior, portableID)
		}
		resultKeys[key] = portableID
		resultRecords[portableID] = record
	}

	invocationKeys := map[string]string{}
	resultIncomingEdges := map[string]int{}
	for _, payload := range payloads {
		if payload.Entry["kind"] != rootArtifactKindProviderInvocation {
			continue
		}
		portableID := stringValue(payload.Entry["portable_id"])
		object, ok := payload.Value.(map[string]any)
		if !ok {
			return invalidf("portable provider invocation payload must be an object")
		}
		if err := validateRootArtifact(object, rootArtifactKindProviderInvocation); err != nil {
			return invalidf("portable provider invocation root artifact is invalid: %v", err)
		}
		rawInvocation, ok := object["invocation"].(map[string]any)
		if !ok || rawInvocation == nil {
			return invalidf("portable provider invocation payload is missing invocation")
		}
		invocationDraft, err := materializeObject(rawInvocation)
		if err != nil {
			return err
		}
		resultRefValue := invocationDraft["provider_result_ref"]
		invocationDraft["provider_result_ref"] = nil
		invocation, err := validateProviderInvocationDraftRecord(invocationDraft)
		if err != nil {
			return invalidf("portable provider invocation is invalid: %v", err)
		}
		key := providerAttemptKey(invocation)
		priorInvocation := invocationKeys[key]
		if invocation["provider_launch_attempted"] == false {
			if resultRefValue != nil {
				return invalidf("portable unlaunched provider invocation has provider_result_ref")
			}
			if priorInvocation != "" {
				return invalidf("portable provider invocations %s and %s duplicate invocation_id and runner_attempt", priorInvocation, portableID)
			}
			invocationKeys[key] = portableID
			continue
		}
		resultRef, ok := resultRefValue.(map[string]any)
		if !ok || resultRef == nil {
			return invalidf("portable launched provider invocation requires provider_result_ref")
		}
		entry, err := validatePortablePayloadRefObject(resultRef, inventoryByID)
		if err != nil {
			return err
		}
		if entry["kind"] != rootArtifactKindProviderResult {
			return invalidf("portable provider invocation result ref does not target provider_result")
		}
		resultPortableID := stringValue(entry["portable_id"])
		resultRecord := resultRecords[resultPortableID]
		if resultRecord == nil {
			return invalidf("portable provider invocation result ref does not target provider_result")
		}
		resultIncomingEdges[resultPortableID]++
		if resultIncomingEdges[resultPortableID] > 1 {
			return invalidf("portable provider result %s has multiple incoming invocation edges", resultPortableID)
		}
		if err := validateProviderResultBinding(invocation, resultRecord); err != nil {
			return err
		}
		if priorInvocation != "" {
			return invalidf("portable provider invocations %s and %s duplicate invocation_id and runner_attempt", priorInvocation, portableID)
		}
		invocationKeys[key] = portableID
	}
	for portableID := range resultRecords {
		switch resultIncomingEdges[portableID] {
		case 1:
			continue
		case 0:
			return invalidf("portable provider result %s is orphaned", portableID)
		default:
			return invalidf("portable provider result %s has multiple incoming invocation edges", portableID)
		}
	}
	return nil
}

func validateProviderInvocationDraftRecord(value any) (map[string]any, error) {
	object, err := requireObject(value, "provider invocation")
	if err != nil {
		return nil, err
	}
	if object["schema_version"] != ProviderInvocationV2 {
		return nil, invalidf("provider invocation schema_version must be %s", ProviderInvocationV2)
	}
	if strings.TrimSpace(stringValue(object["invocation_id"])) == "" ||
		strings.TrimSpace(stringValue(object["phase"])) == "" ||
		strings.TrimSpace(stringValue(object["actor"])) == "" {
		return nil, invalidf("provider invocation requires invocation_id, phase, and actor")
	}
	attempt, ok := exactJSONInteger(object["runner_attempt"])
	if !ok || attempt < 1 {
		return nil, invalidf("provider invocation runner_attempt must be a positive integer")
	}
	object["runner_attempt"] = attempt
	if object["provider_launch_attempted"] != true && object["provider_launch_attempted"] != false {
		return nil, invalidf("provider invocation provider_launch_attempted must be boolean")
	}
	if object["provider_launch_attempted"] == false && object["provider_result_ref"] != nil {
		return nil, invalidf("unlaunched provider invocation requires null provider_result_ref")
	}
	if object["provider_retry"] != "allow" && object["provider_retry"] != "forbid" {
		return nil, invalidf("provider invocation provider_retry must be allow or forbid")
	}
	if !portableRelativePath(stringValue(object["mapped_working_directory"])) {
		return nil, invalidf("provider invocation mapped_working_directory must be portable and relative")
	}
	if object["participant_ordinal"] != nil {
		ordinal, valid := exactJSONInteger(object["participant_ordinal"])
		if !valid || ordinal < 1 {
			return nil, invalidf("provider invocation participant_ordinal must be null or a positive integer")
		}
		object["participant_ordinal"] = ordinal
	}
	return object, nil
}

func validateProviderResultRecord(value any) (map[string]any, error) {
	object, err := requireObject(value, "provider result")
	if err != nil {
		return nil, err
	}
	invocation, err := validateProviderInvocationDraftRecord(object["invocation"])
	if err != nil {
		return nil, invalidf("provider result invocation draft is invalid: %v", err)
	}
	if invocation["provider_launch_attempted"] != true {
		return nil, invalidf("provider result requires a launched invocation draft")
	}
	if invocation["provider_result_ref"] != nil {
		return nil, invalidf("provider result invocation draft must not self-reference provider_result_ref")
	}
	result, err := requireObject(object["provider_result"], "provider result provider_result")
	if err != nil {
		return nil, err
	}
	for _, key := range []string{
		"invocation_id", "phase", "actor", "runner_attempt", "provider_retry", "backend",
		"started_at", "completed_at", "outcome", "failure_stage", "classification",
	} {
		if !semanticEqual(object[key], invocation[key]) {
			return nil, invalidf("provider result %s does not match invocation draft", key)
		}
	}
	if backend := stringValue(result["backend"]); strings.TrimSpace(backend) != "" && backend != object["backend"] {
		return nil, invalidf("provider result backend does not match wrapper backend")
	}
	object["invocation"] = invocation
	object["provider_result"] = result
	return object, nil
}

func validateProviderResultBinding(invocation map[string]any, resultRecord map[string]any) error {
	resultDraft, _ := resultRecord["invocation"].(map[string]any)
	if !semanticEqual(invocation, resultDraft) {
		return invalidf("portable provider invocation/result identity mismatch")
	}
	return nil
}

func validateRootArtifact(object map[string]any, expectedKind string) error {
	if stringValue(object["kind"]) != expectedKind {
		return invalidf("root artifact kind %q does not match expected kind %q", stringValue(object["kind"]), expectedKind)
	}
	version, ok := exactJSONInteger(object["schema_version"])
	if !ok || version != 2 {
		return invalidf("%s requires root artifact schema_version 2", expectedKind)
	}
	if object["digest_profile"] != digest.Profile {
		return invalidf("%s schema_version 2 requires digest_profile %s", expectedKind, digest.Profile)
	}
	return nil
}

func requireSourceIdentity(entry map[string]any, label string) error {
	sourceID := stringValue(entry["source_artifact_id"])
	sourceDigest := stringValue(entry["source_artifact_digest"])
	if !validSourceIdentity(sourceID, sourceDigest) {
		return invalidf("%s requires source artifact identity", label)
	}
	return nil
}

func validSourceIdentity(sourceID string, sourceDigest string) bool {
	return sourceIDPattern.MatchString(sourceID) && validDigest(sourceDigest)
}

func requireMatchingSemanticDigest(raw any, value any, label string) error {
	expected := stringValue(raw)
	if !validDigest(expected) {
		return invalidf("%s digest must be a digest string", label)
	}
	actual, err := digest.SemanticJSON(value)
	if err != nil {
		return err
	}
	if expected != actual {
		return invalidf("%s digest mismatch", label)
	}
	return nil
}

func verifyClosedFileSet(root string, expected map[string]bool) error {
	expectedDirectories := map[string]bool{}
	for filename := range expected {
		for directory := path.Dir(filename); directory != "."; directory = path.Dir(directory) {
			expectedDirectories[directory] = true
		}
	}
	return filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == root {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return invalidf("portable export contains a symlink at %s", relative)
		}
		if entry.IsDir() {
			if expectedDirectories[relative] {
				return nil
			}
			return invalidf("portable export contains an unexpected directory %s", relative)
		}
		if !expected[relative] {
			return invalidf("portable export contains an unexpected file %s", relative)
		}
		return nil
	})
}

func findSourceArtifactRefs(value any) []map[string]any {
	if isSourceArtifactRef(value) {
		object := value.(map[string]any)
		return []map[string]any{object}
	}
	var refs []map[string]any
	switch typed := value.(type) {
	case map[string]any:
		for _, item := range typed {
			refs = append(refs, findSourceArtifactRefs(item)...)
		}
	case []any:
		for _, item := range typed {
			refs = append(refs, findSourceArtifactRefs(item)...)
		}
	}
	return refs
}

func isSourceArtifactRef(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, versionOK := exactJSONInteger(object["schema_version"])
	return object["kind"] == "artifact_ref" &&
		versionOK &&
		stringValue(object["id"]) != "" &&
		stringValue(object["digest"]) != ""
}

func portablePayloadRefShaped(object map[string]any) bool {
	if object["kind"] == "portable_payload_ref" {
		return true
	}
	for _, key := range []string{"portable_id", "source_artifact_id", "source_artifact_digest"} {
		if _, ok := object[key]; ok {
			return true
		}
	}
	return false
}

func syntheticEntry(entry map[string]any) bool {
	kind := stringValue(entry["kind"])
	id := stringValue(entry["portable_id"])
	return kind == "root_session" && id == "session" ||
		kind == "participant_transcript" && id == "transcript" ||
		kind == "diagnostics" && id == "diagnostics"
}

func rootArtifactKind(value string) bool {
	switch value {
	case rootArtifactKindRootRecipePlan,
		rootArtifactKindIntegrationBundle,
		rootArtifactKindIntegrationContract,
		rootArtifactKindNamedInputManifest,
		rootArtifactKindNamedInputContent,
		rootArtifactKindRetainedInputs,
		rootArtifactKindExecutionWorkspace,
		rootArtifactKindRootCheckpoint,
		rootArtifactKindReducerAttempt,
		rootArtifactKindRawResult,
		rootArtifactKindResultValidation,
		rootArtifactKindCanonicalResult,
		rootArtifactKindRenderedPrompt,
		rootArtifactKindProviderInvocation,
		rootArtifactKindProviderResult,
		rootArtifactKindIsolationReport:
		return true
	default:
		return false
	}
}

func providerAttemptKey(record map[string]any) string {
	return stringValue(record["invocation_id"]) + "\x00" + fmt.Sprint(record["runner_attempt"])
}

func semanticEqual(left any, right any) bool {
	leftDigest, leftErr := digest.SemanticJSON(left)
	rightDigest, rightErr := digest.SemanticJSON(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func materializeObject(value any) (map[string]any, error) {
	materialized, err := canonjson.Materialize(value)
	if err != nil {
		return nil, err
	}
	object, ok := materialized.(map[string]any)
	if !ok {
		return nil, invalidf("JSON payload must be an object")
	}
	return object, nil
}

func requireObject(value any, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, invalidf("%s must be an object", label)
	}
	return object, nil
}

func validateAllowedKeys(label string, object map[string]any, keys []string) error {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return invalidf("%s contains unsupported field %q", label, key)
		}
	}
	return nil
}

func exactJSONInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case json.Number:
		return parseJSONIntegerText(typed.String())
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func parseJSONIntegerText(text string) (int, bool) {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
		return 0, false
	}
	integer := int(value)
	if float64(integer) != value {
		return 0, false
	}
	return integer, true
}

func portablePathComponent(value string) bool {
	value = strings.TrimSpace(value)
	return portablePartRegexp.MatchString(value) && value != "." && value != ".."
}

func portableRelativePath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, ":") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == ".." {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func canonicalDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", invalidf("path must resolve to a directory")
	}
	return filepath.Clean(resolved), nil
}

func invalidf(format string, args ...any) error {
	return diag.New(CodeInvalidPortable, fmt.Sprintf(format, args...))
}
