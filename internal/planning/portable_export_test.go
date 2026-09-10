package planning

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	"github.com/charlesnpx/witness/internal/relayv2"
)

func writePlanningRelayV2Bundle(t *testing.T, batch BatchOutput, charterBytes []byte) (*bundle.Verification, string) {
	t.Helper()
	root := t.TempDir()
	relay := buildPlanningFakeRelay(t, root)
	batchBytes, err := persistedVerificationBatchBytes(batch.Document)
	if err != nil {
		t.Fatalf("encode verification batch: %v", err)
	}
	compiled, err := relayv2.Compile(relayv2.CompileOptions{
		SessionID: batch.Plan.BatchID,
		Task:      "planning v2 bundle test",
		RecipeID:  batch.Plan.RecipeFamily,
		ProfileID: relayv2.DefaultProfileID,
		BatchID:   batch.Plan.BatchID,
		Charter:   charterBytes,
		Findings:  batchBytes,
		Artifacts: []relayv2.Input{{Name: "artifact-1", Bytes: []byte("artifact"), MediaType: "application/octet-stream"}},
	})
	if err != nil {
		t.Fatalf("compile relay v2 test plan: %v", err)
	}
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, compiled.Canonical, 0o600); err != nil {
		t.Fatalf("write relay v2 test plan: %v", err)
	}
	blobsPath := filepath.Join(root, "blobs")
	if err := relayv2.Materialize(blobsPath, compiled); err != nil {
		t.Fatalf("materialize relay v2 test plan: %v", err)
	}
	runValue, err := relayv2.Run(context.Background(), relay, planPath, blobsPath)
	if err != nil {
		t.Fatalf("run fake Relay: %v", err)
	}
	exportPath := filepath.Join(root, "portable")
	verified, err := relayv2.ExportAndVerify(context.Background(), relay, runValue.SessionDir, exportPath, compiled.Digest)
	if err != nil {
		t.Fatalf("export and verify fake Relay bundle: %v", err)
	}
	return &verified, exportPath
}

func buildPlanningFakeRelay(t *testing.T, root string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve planning test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	outputPath := filepath.Join(root, "fake-relay")
	command := exec.Command("go", "build", "-o", outputPath, "./testdata/e2e/fake-relay")
	command.Dir = repoRoot
	command.Env = append(os.Environ(), "GOCACHE=/tmp/witness-gocache")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fake Relay: %v\n%s", err, output)
	}
	return outputPath
}

func planningContractBody(contractID string) map[string]any {
	return map[string]any{
		"id": contractID,
		"turns": []any{
			map[string]any{"participant_turn": 1, "slot": "slot_0", "instructions": "Presenter verifies the filed witness."},
			map[string]any{"participant_turn": 2, "slot": "slot_1", "instructions": "Falsifier challenges the filed witness."},
			map[string]any{"participant_turn": 3, "slot": "slot_0", "instructions": "Presenter responds to challenges."},
			map[string]any{"participant_turn": 4, "slot": "slot_1", "instructions": "Falsifier gives final challenge."},
		},
		"reducer": map[string]any{"instructions": "Return relay witness verdict JSON."},
		"inputs": map[string]any{
			"artifact": map[string]any{"required": false, "cardinality": "many", "media_type": "application/json", "max_bytes": 1048576},
			"charter":  map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
			"findings": map[string]any{"required": true, "cardinality": "one", "media_type": "application/json", "max_bytes": 1048576},
		},
		"result": map[string]any{
			"transport":  "json",
			"schema":     map[string]any{"type": "object"},
			"assertions": []any{},
		},
		"prompt_context": map[string]any{
			"participant_transcript": "complete",
			"facilitator_ledger":     "trace_only",
		},
	}
}
