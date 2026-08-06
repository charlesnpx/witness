package relayclient

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/charlesnpx/witness/internal/strictjson"
)

type runnerFunc func(ctx context.Context, executable string, args ...string) CommandResult

func (fn runnerFunc) Run(ctx context.Context, executable string, args ...string) CommandResult {
	return fn(ctx, executable, args...)
}

func TestRealRelayFixturesStrictDecode(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "preflight")
	if _, err := decodeFixture[Capabilities](filepath.Join(fixtures, "relay-capabilities-v1.json")); err != nil {
		t.Fatalf("capabilities fixture: %v", err)
	}
	if _, err := decodeFixture[RecipesList](filepath.Join(fixtures, "recipes-list-v1.json")); err != nil {
		t.Fatalf("recipes list fixture: %v", err)
	}
	if _, err := decodeFixture[BackendStatus](filepath.Join(fixtures, "backend-status-v1.json")); err != nil {
		t.Fatalf("backend status fixture: %v", err)
	}
	raw, err := decodeFixture[map[string]any](filepath.Join(fixtures, "compile-witness-falsify-v2-requires-bundle.json"))
	if err != nil {
		t.Fatalf("compile failure fixture: %v", err)
	}
	report, err := NewCompileReport(raw)
	if err != nil {
		t.Fatalf("compile failure report normalization: %v", err)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "invalid_integration_bundle" {
		t.Fatalf("diagnostics = %#v", report.Diagnostics)
	}
	raw, err = decodeFixture[map[string]any](filepath.Join(fixtures, "compile-witness-falsify-v2.json"))
	if err != nil {
		t.Fatalf("compile success fixture: %v", err)
	}
	report, err = NewCompileReport(raw)
	if err != nil {
		t.Fatalf("compile success report normalization: %v", err)
	}
	if report.RootRecipePlan == nil {
		t.Fatal("compile success fixture did not retain compiled_plan")
	}
	if report.IntegrationContractDigest == "" {
		t.Fatal("compile success fixture did not expose integration contract digest")
	}
}

func TestCommandErrorTaxonomy(t *testing.T) {
	tests := []struct {
		name   string
		result CommandResult
		want   string
	}{
		{
			name:   "relay missing",
			result: CommandResult{Err: exec.ErrNotFound, ExitCode: -1},
			want:   ErrorRelayMissing,
		},
		{
			name:   "nonzero",
			result: CommandResult{Stdout: []byte(`{"message":"failed"}`), ExitCode: 1, Err: errors.New("exit status 1")},
			want:   ErrorNonzeroExit,
		},
		{
			name:   "non json",
			result: CommandResult{Stdout: []byte(`not json`)},
			want:   ErrorNonJSON,
		},
		{
			name: "schema invalid",
			result: CommandResult{Stdout: []byte(`{
				"schema_version":"relay-capabilities-v1",
				"convo_relay_version":"v1.4.0",
				"contracts":{},
				"unexpected":true
			}`)},
			want: ErrorSchemaInvalid,
		},
		{
			name: "type mismatch schema invalid",
			result: CommandResult{Stdout: []byte(`{
				"schema_version":"relay-capabilities-v1",
				"convo_relay_version":"v1.4.0",
				"contracts":[],
				"digest_profile":[]
			}`)},
			want: ErrorSchemaInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := Client{
				Executable: "fake-relay",
				Runner: runnerFunc(func(context.Context, string, ...string) CommandResult {
					return test.result
				}),
			}
			_, err := client.Capabilities(context.Background())
			if err == nil {
				t.Fatal("Capabilities succeeded")
			}
			var commandError *CommandError
			if !errors.As(err, &commandError) {
				t.Fatalf("err = %T %v", err, err)
			}
			if commandError.Kind != test.want {
				t.Fatalf("kind = %s, want %s", commandError.Kind, test.want)
			}
		})
	}
}

func TestRunRecipeWithCommandResultRetainsSuccessfulCommand(t *testing.T) {
	client := Client{
		Executable: "fake-relay",
		Runner: runnerFunc(func(context.Context, string, ...string) CommandResult {
			return CommandResult{Stdout: []byte(`{"session_dir":"/tmp/relay-session"}`)}
		}),
	}
	result, command, err := client.RunRecipeWithCommandResult(context.Background(), RunRecipeOptions{
		Task:      "verify",
		RecipeID:  "witness-falsify-v2-codex",
		LaunchCWD: "/workspace",
	})
	if err != nil {
		t.Fatalf("RunRecipeWithCommandResult: %v", err)
	}
	if result["session_dir"] != "/tmp/relay-session" {
		t.Fatalf("result = %#v", result)
	}
	if command.Command != "fake-relay" || len(command.Args) < 2 || command.Args[0] != "run" || command.ExitCode != 0 {
		t.Fatalf("command = %#v", command)
	}
	if !containsCommandArgPair(command.Args, "--launch-cwd", "/workspace") {
		t.Fatalf("command args = %#v, want launch cwd", command.Args)
	}
}

func TestCompileRecipeNonzeroDecodesRelayDiagnostic(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "preflight")
	stdout, err := os.ReadFile(filepath.Join(fixtures, "compile-witness-falsify-v2-missing-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	client := Client{
		Executable: "fake-relay",
		Runner: runnerFunc(func(context.Context, string, ...string) CommandResult {
			return CommandResult{Stdout: stdout, ExitCode: 1, Err: errors.New("exit status 1")}
		}),
	}
	_, err = client.CompileRecipe(context.Background(), "witness-falsify-v2", "bundle.json")
	if err == nil {
		t.Fatal("CompileRecipe succeeded")
	}
	var commandError *CommandError
	if !errors.As(err, &commandError) {
		t.Fatalf("err = %T %v", err, err)
	}
	if commandError.Kind != ErrorNonzeroExit {
		t.Fatalf("kind = %s, want %s", commandError.Kind, ErrorNonzeroExit)
	}
	if commandError.Diagnostic.Code != "integration_contract_not_found" {
		t.Fatalf("diagnostic = %#v", commandError.Diagnostic)
	}
}

func containsCommandArgPair(args []string, key string, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == key && args[index+1] == value {
			return true
		}
	}
	return false
}

func decodeFixture[T any](path string) (T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var zero T
		return zero, err
	}
	return strictjson.DecodeBytes[T](data, strictjson.DefaultMaxBytes*32)
}
