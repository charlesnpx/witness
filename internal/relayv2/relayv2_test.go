package relayv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/convo-relay/v2/plan"
	"github.com/charlesnpx/convo-relay/v2/result"
)

func TestBundledRecipesCompileToValidPlans(t *testing.T) {
	for _, recipe := range Recipes() {
		compiled, err := Compile(CompileOptions{
			SessionID: recipe.ID + "-test",
			RecipeID:  recipe.ID,
			Charter:   []byte(`{"goals":[]}`),
			Findings:  []byte(`{"findings":[]}`),
			Artifacts: []Input{
				{Name: "artifact-1", Bytes: []byte("first artifact"), MediaType: "text/plain"},
				{Name: "artifact-2", Bytes: []byte("second artifact"), MediaType: "text/plain"},
			},
		})
		if err != nil {
			t.Fatalf("compile %s: %v", recipe.ID, err)
		}
		if err := plan.Validate(compiled.Plan); err != nil {
			t.Fatalf("validate %s plan: %v", recipe.ID, err)
		}
		if compiled.Digest == "" || len(compiled.Canonical) == 0 {
			t.Fatalf("compile %s did not return plan identity and canonical bytes", recipe.ID)
		}
		wantDigest, err := plan.Digest(compiled.Plan)
		if err != nil {
			t.Fatalf("digest %s plan: %v", recipe.ID, err)
		}
		if compiled.Digest != wantDigest {
			t.Fatalf("compile %s digest = %q, want plan digest %q", recipe.ID, compiled.Digest, wantDigest)
		}
		if len(compiled.Plan.Inputs) != 3 || compiled.Plan.Inputs[2].Name != "artifact" || len(compiled.Plan.Inputs[2].Contents) != 2 {
			t.Fatalf("compile %s inputs = %#v, want charter, findings, and one ordered artifact group", recipe.ID, compiled.Plan.Inputs)
		}
		if len(compiled.Plan.Instructions.Turns) != VerificationTurns {
			t.Fatalf("%s instruction count = %d, want %d", recipe.ID, len(compiled.Plan.Instructions.Turns), VerificationTurns)
		}
		if compiled.Plan.Instructions.ReducerInstructions != recipe.ReducerInstructions {
			t.Fatalf("%s reducer instructions were not carried into the plan", recipe.ID)
		}
	}
}

func TestRunExportAndVerifyFullLoop(t *testing.T) {
	relay := requireRelayBinary(t)
	compiled, planPath, blobsPath := writeMinimalPlan(t)
	value, err := Run(context.Background(), relay, planPath, blobsPath)
	if err != nil {
		var commandErr *CommandError
		if errors.As(err, &commandErr) {
			t.Fatalf("run supplied plan: %v (stdout=%q stderr=%q)", err, commandErr.Stdout, commandErr.Stderr)
		}
		t.Fatalf("run supplied plan: %v", err)
	}
	if value.SessionDir == "" {
		t.Fatal("run result did not expose session_dir for export")
	}
	exportPath := filepath.Join(t.TempDir(), "portable")
	verified, err := ExportAndVerify(context.Background(), relay, value.SessionDir, exportPath, compiled.Digest)
	if err != nil {
		t.Fatalf("export and verify portable bundle: %v", err)
	}
	if verified.Session.Plan.SessionID != compiled.Plan.SessionID {
		t.Fatalf("verified session_id = %q, want %q", verified.Session.Plan.SessionID, compiled.Plan.SessionID)
	}
	if verified.PayloadCount < 3 {
		t.Fatalf("verified payload count = %d, want at least root session, transcript, and diagnostics", verified.PayloadCount)
	}
}

func TestVerifyDifferentExpectedDigestNamesBothDigests(t *testing.T) {
	relay := requireRelayBinary(t)
	compiled, planPath, blobsPath := writeMinimalPlan(t)
	value, err := Run(context.Background(), relay, planPath, blobsPath)
	if err != nil {
		var commandErr *CommandError
		if errors.As(err, &commandErr) {
			t.Fatalf("run supplied plan: %v (stdout=%q stderr=%q)", err, commandErr.Stdout, commandErr.Stderr)
		}
		t.Fatalf("run supplied plan: %v", err)
	}
	exportPath := filepath.Join(t.TempDir(), "portable")
	if err := Export(context.Background(), relay, value.SessionDir, exportPath); err != nil {
		t.Fatalf("export portable bundle: %v", err)
	}
	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	if wrongDigest == compiled.Digest {
		t.Fatal("test digest unexpectedly matched compiled digest")
	}
	_, err = Verify(exportPath, wrongDigest)
	if err == nil {
		t.Fatal("verification with a different expected digest succeeded")
	}
	if !strings.Contains(err.Error(), wrongDigest) || !strings.Contains(err.Error(), compiled.Digest) {
		t.Fatalf("digest mismatch error = %q, want both expected %s and actual %s", err, wrongDigest, compiled.Digest)
	}
}

func TestInvocationEvidenceDistinguishesAbsentFromExplicitZero(t *testing.T) {
	cases := []struct {
		name        string
		value       result.Result
		wantPresent bool
	}{
		{name: "missing invocation field", value: result.Result{Root: &result.Root{}}},
		{name: "explicit zero", value: result.Result{Root: &result.Root{Invocations: &result.Count{Count: 0}}}, wantPresent: true},
	}
	for i := range cases {
		t.Run(cases[i].name, func(t *testing.T) {
			count, present := InvocationEvidence(cases[i].value)
			wantPresent := cases[i].wantPresent
			if count != 0 || present != wantPresent {
				t.Fatalf("InvocationEvidence = (%d, %t), want (0, %t)", count, present, wantPresent)
			}
		})
	}
}

func TestAbsentRelayBinaryIsDistinguishable(t *testing.T) {
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write placeholder plan: %v", err)
	}
	missing := filepath.Join(root, "missing", "convo-relay")
	_, err := Run(context.Background(), missing, planPath, filepath.Join(root, "blobs"))
	if err == nil {
		t.Fatal("run with an absent Relay executable succeeded")
	}
	if !errors.Is(err, ErrRelayNotInstalled) || !IsRelayNotInstalled(err) {
		t.Fatalf("absent Relay error = %v, want ErrRelayNotInstalled", err)
	}
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Kind != ErrorRelayNotInstalled {
		t.Fatalf("absent Relay error type = %T/%#v, want CommandError kind %q", err, commandErr, ErrorRelayNotInstalled)
	}
}

func requireRelayBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath(DefaultExecutable)
	if err != nil {
		t.Skipf("convo-relay binary unavailable; install v2.0.1 with GOBIN under /tmp (go install github.com/charlesnpx/convo-relay/v2/cmd/convo-relay@v2.0.1): %v", err)
	}
	output, err := exec.Command(path, "version", "--json").Output()
	if err != nil {
		t.Skipf("convo-relay binary is not a usable v2 CLI; install v2.0.1 with GOBIN under /tmp (go install github.com/charlesnpx/convo-relay/v2/cmd/convo-relay@v2.0.1): %v", err)
	}
	var version struct {
		Formats       json.RawMessage `json:"formats"`
		DigestClasses json.RawMessage `json:"digest_classes"`
	}
	if err := json.Unmarshal(output, &version); err != nil || len(version.Formats) == 0 || len(version.DigestClasses) == 0 {
		if err == nil {
			err = fmt.Errorf("version response does not expose v2 formats")
		}
		t.Skipf("convo-relay binary is not the required v2 CLI; install v2.0.1 with GOBIN under /tmp (go install github.com/charlesnpx/convo-relay/v2/cmd/convo-relay@v2.0.1): %v", err)
	}
	return path
}

func writeMinimalPlan(t *testing.T) (CompiledPlan, string, string) {
	t.Helper()
	compiled, err := Compile(CompileOptions{
		SessionID: "relayv2-adapter-test",
		Charter:   []byte(`{"goals":[]}`),
		Findings:  []byte(`{"findings":[]}`),
		Artifacts: []Input{{Name: "artifact", Bytes: []byte("portable artifact"), MediaType: "text/plain"}},
	})
	if err != nil {
		t.Fatalf("compile test plan: %v", err)
	}

	value := compiled.Plan
	value.Provenance = plan.ProvenanceSupplied
	value.RecipeID = ""
	value.Actors = append([]plan.Actor(nil), value.Actors[:2]...)
	value.Schedule = plan.Schedule{Kind: plan.ScheduleDialogue, Turns: 1}
	value.Reducer = nil
	value.Result = plan.Result{Source: plan.ResultSourceLastTurn, Format: plan.ResultFormatText}
	value.Instructions = &plan.Instructions{Turns: []plan.TurnInstruction{{
		ParticipantTurn: 1,
		Actor:           "participant-1",
		Instructions:    "Reply with one short sentence.",
	}}}
	if err := plan.Validate(value); err != nil {
		t.Fatalf("validate minimal test plan: %v", err)
	}
	digest, err := plan.Digest(value)
	if err != nil {
		t.Fatalf("digest minimal test plan: %v", err)
	}
	canonical, err := plan.CanonicalBytes(value)
	if err != nil {
		t.Fatalf("canonicalize minimal test plan: %v", err)
	}
	compiled.Plan = value
	compiled.Digest = digest
	compiled.Canonical = canonical

	root := t.TempDir()
	t.Setenv("CODEX_CLAUDE_HOME", filepath.Join(root, "relay-home"))
	installFakeCodex(t)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, canonical, 0o600); err != nil {
		t.Fatalf("write minimal test plan: %v", err)
	}
	blobsPath := filepath.Join(root, "blobs")
	if err := Materialize(blobsPath, compiled); err != nil {
		t.Fatalf("materialize minimal test plan: %v", err)
	}
	return compiled, planPath, blobsPath
}

func installFakeCodex(t *testing.T) {
	t.Helper()
	directory := t.TempDir()
	filename := filepath.Join(directory, "codex")
	if err := os.WriteFile(filename, []byte(fakeCodexAppServerScript), 0o700); err != nil {
		t.Fatalf("write fake codex app server: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

const fakeCodexAppServerScript = `#!/usr/bin/env python3
import json
import sys

if len(sys.argv) < 2 or sys.argv[1] != "app-server":
    print("expected codex app-server", file=sys.stderr)
    raise SystemExit(2)

thread_id = "relayv2-test-thread"
turn_number = 0

def send(value):
    print(json.dumps(value), flush=True)

def response(request, value):
    send({"id": request.get("id"), "result": value})

for raw in sys.stdin:
    try:
        request = json.loads(raw)
    except json.JSONDecodeError:
        continue
    method = request.get("method", "")
    params = request.get("params", {}) or {}
    if method == "initialize":
        response(request, {"serverInfo": {"name": "relayv2-test"}})
    elif method in ("thread/start", "thread/resume"):
        thread_id = params.get("threadId") or thread_id
        response(request, {"thread": {"id": thread_id}})
    elif method == "model/list":
        response(request, {"data": [{"id": "relayv2-test", "supportedReasoningEfforts": ["low", "high"]}]})
    elif method == "turn/start":
        turn_number += 1
        turn_id = "turn-%d" % turn_number
        response(request, {"turn": {"id": turn_id}})
        send({"method": "item/completed", "params": {"item": {"id": "item-%d" % turn_number, "type": "agentMessage", "text": "ok"}}})
        send({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": "completed"}}})
    elif method == "turn/interrupt":
        response(request, {})
`
