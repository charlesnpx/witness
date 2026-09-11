package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	"github.com/charlesnpx/convo-relay/v2/plan"
	"github.com/charlesnpx/convo-relay/v2/result"
	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/contracts"
)

const (
	convoRelayVersion = "v2.0.1-fake"
	completedStatus   = "completed"
	validatedStatus   = "validated"
)

type sessionState struct {
	Plan   plan.Plan     `json:"plan"`
	Result result.Result `json:"result"`
}

type portablePayload struct {
	Entry bundle.InventoryEntry
	Body  []byte
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
	case "run":
		return runPlan(args[1:])
	case "export":
		if len(args) < 2 || args[1] != "create" {
			return fmt.Errorf("unsupported fake relay export command %q", strings.Join(args[1:], " "))
		}
		return exportCreate(args[2:])
	default:
		return fmt.Errorf("unsupported fake relay command %q", args[0])
	}
}

func runPlan(args []string) error {
	if os.Getenv("WITNESS_FAKE_RELAY_FAIL_RUN") == "1" {
		return errors.New("simulated relay launch failure")
	}
	planPath := flagValue(args, "--plan")
	blobsPath := flagValue(args, "--blobs")
	if planPath == "" || blobsPath == "" {
		return errors.New("run requires --plan and --blobs")
	}
	planValue, planBytes, err := readPlan(planPath)
	if err != nil {
		return err
	}
	findings, err := findingsBatch(planValue, blobsPath)
	if err != nil {
		return err
	}
	verdicts := verdictDocument(findings)
	verdictBytes, err := contracts.RelayWitnessVerdictsCanonicalBytes(verdicts)
	if err != nil {
		return fmt.Errorf("encode fake relay verdicts: %w", err)
	}
	if err := contracts.RequireValidRelayWitnessVerdicts(verdicts, &findings); err != nil {
		return fmt.Errorf("validate fake relay verdicts: %w", err)
	}

	sessionDir, err := os.MkdirTemp("", "fake-relay-session-")
	if err != nil {
		return err
	}
	if err := persistSessionInputs(sessionDir, planValue, planBytes, blobsPath); err != nil {
		return err
	}
	runResult := resultForPlan(planValue, sessionDir, string(verdictBytes), verdictBytes)
	if os.Getenv("WITNESS_FAKE_RELAY_EMPTY_ROOT_RESULT") == "1" {
		runResult.Result = ""
		runResult.Root.Result.Value = ""
	}
	if err := writeJSONFile(filepath.Join(sessionDir, "result.json"), runResult); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(sessionDir, "session-state.json"), sessionState{Plan: planValue, Result: runResult}); err != nil {
		return err
	}
	return writeJSON(os.Stdout, runResult)
}

func exportCreate(args []string) error {
	sessionDir := flagValue(args, "--session-dir")
	outputDir := flagValue(args, "--output")
	if sessionDir == "" || outputDir == "" {
		return errors.New("export create requires --session-dir and --output")
	}
	state, err := readJSONFile[sessionState](filepath.Join(sessionDir, "session-state.json"))
	if err != nil {
		return err
	}
	if err := plan.Validate(state.Plan); err != nil {
		return fmt.Errorf("validate stored plan: %w", err)
	}
	if state.Result.Root == nil {
		return errors.New("stored relay result is missing root")
	}
	manifestDigest, err := writePortableBundle(outputDir, sessionDir, state)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{
		"output":          outputDir,
		"format":          bundle.Kind,
		"manifest_digest": manifestDigest,
		"terminal_status": state.Result.Status,
	})
}

func readPlan(path string) (plan.Plan, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return plan.Plan{}, nil, err
	}
	value, err := strictjson.DecodeBytes[plan.Plan](data, strictjson.DefaultMaxBytes*8)
	if err != nil {
		return plan.Plan{}, nil, fmt.Errorf("decode relay plan: %w", err)
	}
	if err := plan.Validate(value); err != nil {
		return plan.Plan{}, nil, fmt.Errorf("validate relay plan: %w", err)
	}
	canonical, err := plan.CanonicalBytes(value)
	if err != nil {
		return plan.Plan{}, nil, err
	}
	return value, canonical, nil
}

func findingsBatch(value plan.Plan, blobsPath string) (contracts.VerificationBatchDocument, error) {
	for _, input := range value.Inputs {
		if input.Name != "findings" {
			continue
		}
		if len(input.Contents) != 1 {
			return contracts.VerificationBatchDocument{}, errors.New("fake relay findings input must contain one blob")
		}
		ref := input.Contents[0]
		path := filepath.Join(blobsPath, "sha256", ref.SHA256)
		data, err := os.ReadFile(path)
		if err != nil {
			return contracts.VerificationBatchDocument{}, fmt.Errorf("read findings blob: %w", err)
		}
		if int64(len(data)) != ref.Size || digest.RawBytes(data) != "sha256:"+ref.SHA256 {
			return contracts.VerificationBatchDocument{}, errors.New("findings blob does not match the plan")
		}
		batch, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			return contracts.VerificationBatchDocument{}, fmt.Errorf("decode findings blob: %w", err)
		}
		if err := contracts.RequireValidVerificationBatch(batch, nil); err != nil {
			return contracts.VerificationBatchDocument{}, fmt.Errorf("validate findings blob: %w", err)
		}
		return batch, nil
	}
	return contracts.VerificationBatchDocument{}, errors.New("relay plan has no findings input")
}

func persistSessionInputs(sessionDir string, value plan.Plan, planBytes []byte, blobsPath string) error {
	if err := writeBytes(filepath.Join(sessionDir, "plan.json"), planBytes); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ref := range plan.BlobRefs(value) {
		if seen[ref.SHA256] {
			continue
		}
		seen[ref.SHA256] = true
		body, err := os.ReadFile(filepath.Join(blobsPath, "sha256", ref.SHA256))
		if err != nil {
			return fmt.Errorf("read plan blob %s: %w", ref.SHA256, err)
		}
		if int64(len(body)) != ref.Size || digest.RawBytes(body) != "sha256:"+ref.SHA256 {
			return fmt.Errorf("plan blob %s does not match its reference", ref.SHA256)
		}
		if err := writeBytes(filepath.Join(sessionDir, "blobs", "sha256", ref.SHA256), body); err != nil {
			return err
		}
	}
	return nil
}

func resultForPlan(value plan.Plan, sessionDir string, verdicts string, verdictBytes []byte) result.Result {
	transcript := make([]result.TranscriptEntry, 0, value.Schedule.Turns)
	for turn := 1; turn <= value.Schedule.Turns; turn++ {
		actor, err := plan.ParticipantActorForTurn(value, turn)
		if err != nil {
			actor = fmt.Sprintf("participant-%d", turn)
		}
		transcript = append(transcript, result.TranscriptEntry{
			Round:   turn,
			From:    actor,
			Content: fmt.Sprintf("fake relay participant turn %d", turn),
			Mode:    value.Mode,
			Ledger:  result.Ledger{Settled: []string{}, Contested: []string{}, Withdrawn: []string{}},
		})
	}
	root := &result.Root{
		ExecutionKind: value.Provenance,
		Status:        completedStatus,
		Recipe:        result.Recipe{ID: value.RecipeID},
		Turns:         result.Turns{Configured: value.Schedule.Turns, Completed: value.Schedule.Turns},
		Result:        result.RootResult{Source: value.Result.Source, ValidationStatus: validatedStatus, Value: verdicts},
		Workspace: result.Workspace{
			Mode:                       value.Workspace.Mode,
			WorkspaceContentSource:     workspaceContentSource(value),
			WorkingTreeChangesIncluded: value.Workspace.Mode == plan.WorkspaceModeCurrent,
		},
		Providers:       map[string]string{},
		ProviderRetry:   value.ProviderRetry.Mode,
		Invocations:     &result.Count{Count: value.Schedule.Turns + 1},
		ReducerAttempts: result.Count{Count: 1},
	}
	slots := make([]result.Slot, 0, len(value.Actors))
	agents := make([]string, 0, len(value.Actors))
	for _, actor := range value.Actors {
		if actor.Backend == plan.ActorBackendChild {
			continue
		}
		slots = append(slots, result.Slot{SlotID: actor.ID, ProfileID: actor.ProfileID, Backend: actor.Backend, Model: actor.Model, Effort: actor.Effort, State: result.SlotState{}})
		if actor.ID != "reducer" {
			agents = append(agents, actor.Backend)
		}
	}
	return result.Result{
		SessionID:                  value.SessionID,
		SessionDir:                 sessionDir,
		ExecutionKind:              value.Provenance,
		RecipeID:                   value.RecipeID,
		Task:                       value.Task,
		Title:                      value.Task,
		Mode:                       value.Mode,
		InvestigationMode:          value.Investigation,
		TimeoutSeconds:             value.Timeouts.TurnSeconds,
		StallTimeoutSeconds:        value.Timeouts.StallSeconds,
		Status:                     completedStatus,
		StopReason:                 completedStatus,
		Summary:                    result.Summary{Status: completedStatus, Mode: value.Mode, Agents: agents, ConfiguredRounds: value.Schedule.Turns, MaxRounds: value.Schedule.Turns, ActualRounds: value.Schedule.Turns, FilteredRounds: value.Schedule.Turns, LedgerCounts: result.LedgerCounts{}},
		Transcript:                 transcript,
		TranscriptPayload:          append([]result.TranscriptEntry(nil), transcript...),
		Result:                     string(verdictBytes),
		ResultSource:               value.Result.Source,
		ValidationStatus:           validatedStatus,
		ReducerAttempts:            result.Count{Count: 1},
		Recipe:                     result.Recipe{ID: value.RecipeID},
		Source:                     "fake-relay",
		Slots:                      slots,
		ActualRounds:               value.Schedule.Turns,
		ActualParticipantTurns:     value.Schedule.Turns,
		ParticipantTurns:           value.Schedule.Turns,
		MaxRounds:                  value.Schedule.Turns,
		RoundLimitMode:             "fixed",
		ProviderFailures:           []result.ProviderFailure{},
		ProviderRetry:              value.ProviderRetry.Mode,
		WorkspaceContentSource:     workspaceContentSource(value),
		WorkingTreeChangesIncluded: value.Workspace.Mode == plan.WorkspaceModeCurrent,
		Diagnostics:                result.Diagnostics{AbandonedAttempts: []result.AbandonedAttempt{}, UnreferencedBlobs: []result.BlobDiagnostic{}},
		Root:                       root,
	}
}

func writePortableBundle(outputDir, sessionDir string, state sessionState) (string, error) {
	root := state.Result.Root
	sessionPayload := bundle.SessionPayload{
		Plan:                       state.Plan,
		TerminalStatus:             state.Result.Status,
		StopReason:                 state.Result.StopReason,
		ResultSource:               state.Result.ResultSource,
		ValidationStatus:           state.Result.ValidationStatus,
		WorkspaceContentSource:     state.Result.WorkspaceContentSource,
		WorkingTreeChangesIncluded: state.Result.WorkingTreeChangesIncluded,
		Root:                       *root,
	}
	payloadValues := []struct {
		kind  string
		id    string
		value any
	}{
		{kind: "diagnostics", id: "diagnostics", value: state.Result.Diagnostics},
		{kind: "participant_transcript", id: "transcript", value: state.Result.TranscriptPayload},
		{kind: "root_session", id: "session", value: sessionPayload},
	}
	payloads := make([]portablePayload, 0, len(payloadValues)+len(plan.BlobRefs(state.Plan)))
	for _, item := range payloadValues {
		body, err := canonjson.Marshal(item.value)
		if err != nil {
			return "", err
		}
		payloads = append(payloads, portablePayload{
			Entry: bundle.InventoryEntry{Kind: item.kind, PortableID: item.id, Path: filepath.ToSlash(filepath.Join("payloads", item.kind, item.id+".json")), Blob: blobRef(body, "application/json")},
			Body:  body,
		})
	}
	seen := map[string]bool{}
	for _, ref := range plan.BlobRefs(state.Plan) {
		if seen[ref.SHA256] {
			continue
		}
		seen[ref.SHA256] = true
		body, err := os.ReadFile(filepath.Join(sessionDir, "blobs", "sha256", ref.SHA256))
		if err != nil {
			return "", fmt.Errorf("read session input blob %s: %w", ref.SHA256, err)
		}
		payloads = append(payloads, portablePayload{
			Entry: bundle.InventoryEntry{Kind: "input", PortableID: ref.SHA256, Path: filepath.ToSlash(filepath.Join("payloads", "input", ref.SHA256+".json")), Blob: ref},
			Body:  body,
		})
	}
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].Entry.Path < payloads[j].Entry.Path })
	inventory := make([]bundle.InventoryEntry, 0, len(payloads))
	for _, payload := range payloads {
		inventory = append(inventory, payload.Entry)
	}
	stopReason := state.Result.StopReason
	manifest := bundle.Manifest{
		Kind:               bundle.Kind,
		ConvoRelayVersion:  convoRelayVersion,
		TerminalStatus:     state.Result.Status,
		StopReason:         &stopReason,
		SessionPayload:     "payloads/root_session/session.json",
		TranscriptPayload:  "payloads/participant_transcript/transcript.json",
		DiagnosticsPayload: "payloads/diagnostics/diagnostics.json",
		PayloadInventory:   inventory,
	}
	var err error
	manifest.InventoryDigest, err = relaySemanticDigest(state.Plan, inventory)
	if err != nil {
		return "", err
	}
	manifest.ManifestDigest, err = relaySemanticDigest(state.Plan, map[string]any{
		"kind":                manifest.Kind,
		"convo_relay_version": manifest.ConvoRelayVersion,
		"terminal_status":     manifest.TerminalStatus,
		"stop_reason":         manifest.StopReason,
		"session_payload":     manifest.SessionPayload,
		"transcript_payload":  manifest.TranscriptPayload,
		"diagnostics_payload": manifest.DiagnosticsPayload,
		"payload_inventory":   manifest.PayloadInventory,
		"inventory_digest":    manifest.InventoryDigest,
	})
	if err != nil {
		return "", err
	}
	if err := bundle.Validate(manifest); err != nil {
		return "", fmt.Errorf("validate fake relay bundle: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	for _, payload := range payloads {
		if err := writeBytes(filepath.Join(outputDir, filepath.FromSlash(payload.Entry.Path)), payload.Body); err != nil {
			return "", err
		}
	}
	manifestBytes, err := canonjson.Marshal(manifest)
	if err != nil {
		return "", err
	}
	if err := writeBytes(filepath.Join(outputDir, "manifest.json"), manifestBytes); err != nil {
		return "", err
	}
	if _, err := bundle.VerifyPortableDirectory(outputDir); err != nil {
		return "", fmt.Errorf("verify fake relay bundle: %w", err)
	}
	return manifest.ManifestDigest, nil
}

// relaySemanticDigest reuses Relay's public plan canonicalizer to obtain the
// v2 semantic-JSON spelling for an otherwise arbitrary JSON value. The v2
// bundle package intentionally exposes validation, not a second manifest
// builder; keeping this test process on the public plan boundary avoids
// duplicating Relay's canonicalization implementation here.
func relaySemanticDigest(base plan.Plan, value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	probe := base
	probe.TaskPlan = body
	canonical, err := plan.CanonicalBytes(probe)
	if err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return "", err
	}
	taskPlan, ok := fields["task_plan"]
	if !ok {
		return "", errors.New("relay canonical plan omitted task_plan")
	}
	return digest.RawBytes(taskPlan), nil
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
			Rationale:      "fake Relay preserves the filed witness for E2E coverage",
		})
	}
	return contracts.RelayWitnessVerdictsDocument{SchemaVersion: contracts.RelayWitnessVerdictsV2, BatchID: batch.BatchID, Verdicts: verdicts}
}

func blobRef(body []byte, mediaType string) plan.BlobRef {
	return plan.BlobRef{SHA256: strings.TrimPrefix(digest.RawBytes(body), "sha256:"), Size: int64(len(body)), MediaType: mediaType}
}

func workspaceContentSource(value plan.Plan) string {
	if value.Workspace.Mode == plan.WorkspaceModeHeadCopy {
		return "committed_head"
	}
	return "working_tree"
}

func flagValue(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

func readJSONFile[T any](path string) (T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var zero T
		return zero, err
	}
	return strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes*32)
}

func writeBytes(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func writeJSONFile(path string, value any) error {
	body, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	return writeBytes(path, append(body, '\n'))
}

func writeJSON(file *os.File, value any) error {
	body, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	_, err = file.Write(append(body, '\n'))
	return err
}
