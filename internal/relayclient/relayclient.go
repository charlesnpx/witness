package relayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	DefaultExecutable = "convo-relay"

	ErrorRelayMissing          = "relay_missing"
	ErrorNonJSON               = "relay_non_json"
	ErrorSchemaInvalid         = "relay_schema_invalid"
	ErrorNonzeroExit           = "relay_nonzero_exit"
	ErrorContractDigestMissing = "relay_contract_digest_missing"
)

type Runner interface {
	Run(ctx context.Context, executable string, args ...string) CommandResult
}

type CommandResult struct {
	Command  string
	Args     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, args ...string) CommandResult {
	command := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0, Err: err}
	if err == nil {
		return result
	}
	result.ExitCode = -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
	}
	return result
}

type CommandError struct {
	Kind       string
	Command    string
	Args       []string
	ExitCode   int
	Diagnostic diag.Diagnostic
	Stdout     string
	Stderr     string
	Cause      error
}

func (err *CommandError) Error() string {
	if err == nil {
		return ""
	}
	switch err.Kind {
	case ErrorRelayMissing:
		return fmt.Sprintf("%s: relay executable %q was not found", err.Kind, err.Command)
	case ErrorNonzeroExit:
		return fmt.Sprintf("%s: relay command exited with status %d", err.Kind, err.ExitCode)
	case ErrorNonJSON:
		return fmt.Sprintf("%s: relay command did not emit strict JSON", err.Kind)
	case ErrorSchemaInvalid:
		return fmt.Sprintf("%s: relay JSON did not match the expected schema", err.Kind)
	default:
		return fmt.Sprintf("%s: relay command failed", err.Kind)
	}
}

func (err *CommandError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

type Client struct {
	Executable string
	Runner     Runner
	MaxBytes   int64
}

func New(executable string) Client {
	return Client{Executable: executable}
}

func (client Client) Capabilities(ctx context.Context) (Capabilities, error) {
	return runStrict(ctx, client, []string{"capabilities", "--json"}, validateCapabilitiesDocument)
}

func (client Client) RecipesList(ctx context.Context) (RecipesList, error) {
	return runStrict(ctx, client, []string{"recipes", "list", "--json"}, validateRecipesList)
}

func (client Client) BackendStatus(ctx context.Context) (BackendStatus, error) {
	return runStrict(ctx, client, []string{"backends", "status", "--json"}, validateBackendStatus)
}

func (client Client) CompileRecipe(ctx context.Context, recipeID string, integrationBundlePath string) (CompileReport, error) {
	args := []string{"compile-recipe", "--recipe", recipeID, "--target", "root"}
	if integrationBundlePath != "" {
		args = append(args, "--integration-bundle", integrationBundlePath)
	}
	args = append(args, "--json")
	return runCompile(ctx, client, args)
}

func (client Client) RunRecipe(ctx context.Context, options RunRecipeOptions) (map[string]any, error) {
	value, _, err := client.RunRecipeWithCommandResult(ctx, options)
	return value, err
}

// RunRecipeWithCommandResult retains the executed command result alongside the
// decoded run response so callers can preserve launch evidence even on failure.
func (client Client) RunRecipeWithCommandResult(ctx context.Context, options RunRecipeOptions) (map[string]any, CommandResult, error) {
	args := []string{"run", "--task", options.Task, "--recipe", options.RecipeID}
	if options.IntegrationBundlePath != "" {
		args = append(args, "--integration-bundle", options.IntegrationBundlePath)
	}
	if options.WorkspaceIsolation != "" {
		args = append(args, "--workspace-isolation", options.WorkspaceIsolation)
	}
	if options.SessionDir != "" {
		args = append(args, "--session-dir", options.SessionDir)
	}
	if options.SessionID != "" {
		args = append(args, "--session-id", options.SessionID)
	}
	if options.RelayHome != "" {
		args = append(args, "--home", options.RelayHome)
	}
	if options.LaunchCWD != "" {
		args = append(args, "--launch-cwd", options.LaunchCWD)
	}
	if options.SettingsPath != "" {
		args = append(args, "--settings", options.SettingsPath)
	}
	if options.AllowDirtySource {
		args = append(args, "--allow-dirty-source")
	}
	for _, binding := range options.InputBindings {
		args = append(args, "--input", binding)
	}
	args = append(args, "--json")
	return runObjectWithCommandResult(ctx, client, args)
}

func (client Client) ExportPortable(ctx context.Context, options ExportOptions) (map[string]any, error) {
	args := []string{"export"}
	if options.SessionDir != "" {
		args = append(args, "--session-dir", options.SessionDir)
	}
	if options.SessionID != "" {
		args = append(args, "--session-id", options.SessionID)
	}
	if options.RelayHome != "" {
		args = append(args, "--home", options.RelayHome)
	}
	args = append(args, "--portable", "--output", options.OutputDir, "--json")
	return runObject(ctx, client, args)
}

func (client Client) VerifyExport(ctx context.Context, exportDir string) (map[string]any, error) {
	return runObject(ctx, client, []string{"verify-export", exportDir, "--json"})
}

func (client Client) Show(ctx context.Context, options ShowOptions) (map[string]any, error) {
	args := []string{"show"}
	if options.SessionDir != "" {
		args = append(args, "--session-dir", options.SessionDir)
	}
	if options.SessionID != "" {
		args = append(args, "--session-id", options.SessionID)
	}
	if options.RelayHome != "" {
		args = append(args, "--home", options.RelayHome)
	}
	args = append(args, "--json")
	return runObject(ctx, client, args)
}

func runStrict[T any](ctx context.Context, client Client, args []string, validate func(T) error) (T, error) {
	var zero T
	result := runCommand(ctx, client, args)
	if err := commandFailure(client.command(), args, result); err != nil {
		return zero, err
	}
	value, err := strictjson.DecodeBytes[T](result.Stdout, client.limit())
	if err != nil {
		return zero, decodeError(client.command(), args, result, err)
	}
	if err := validate(value); err != nil {
		return zero, &CommandError{
			Kind:       ErrorSchemaInvalid,
			Command:    client.command(),
			Args:       append([]string(nil), args...),
			Diagnostic: diag.FromError(err),
			Stdout:     string(result.Stdout),
			Stderr:     string(result.Stderr),
			Cause:      err,
		}
	}
	return value, nil
}

func runCompile(ctx context.Context, client Client, args []string) (CompileReport, error) {
	var zero CompileReport
	result := runCommand(ctx, client, args)
	if result.Err != nil || result.ExitCode != 0 {
		return zero, compileFailure(client.command(), args, result)
	}
	raw, err := strictjson.DecodeBytes[map[string]any](result.Stdout, client.limit())
	if err != nil {
		return zero, decodeError(client.command(), args, result, err)
	}
	report, err := NewCompileReport(raw)
	if err != nil {
		return zero, &CommandError{
			Kind:       ErrorSchemaInvalid,
			Command:    client.command(),
			Args:       append([]string(nil), args...),
			Diagnostic: diag.FromError(err),
			Stdout:     string(result.Stdout),
			Stderr:     string(result.Stderr),
			Cause:      err,
		}
	}
	return report, nil
}

func runObject(ctx context.Context, client Client, args []string) (map[string]any, error) {
	value, _, err := runObjectWithCommandResult(ctx, client, args)
	return value, err
}

func runObjectWithCommandResult(ctx context.Context, client Client, args []string) (map[string]any, CommandResult, error) {
	result := runCommand(ctx, client, args)
	if err := commandFailure(client.command(), args, result); err != nil {
		return nil, result, err
	}
	value, err := strictjson.DecodeBytes[map[string]any](result.Stdout, client.limit())
	if err != nil {
		return nil, result, decodeError(client.command(), args, result, err)
	}
	if value == nil {
		return nil, result, &CommandError{
			Kind:       ErrorSchemaInvalid,
			Command:    client.command(),
			Args:       append([]string(nil), args...),
			Diagnostic: diag.FromError(diag.New(ErrorSchemaInvalid, "relay command emitted null instead of a JSON object.")),
			Stdout:     string(result.Stdout),
			Stderr:     string(result.Stderr),
		}
	}
	return value, result, nil
}

func compileFailure(command string, args []string, result CommandResult) error {
	if baseErr := commandFailure(command, args, result); baseErr != nil {
		var commandError *CommandError
		if !errors.As(baseErr, &commandError) || commandError.Kind == ErrorRelayMissing {
			return baseErr
		}
	}
	diagnostic, decodeErr := decodeFailureDiagnostic(result.Stdout, result.Stderr)
	if decodeErr != nil {
		return commandFailure(command, args, result)
	}
	kind := ErrorNonzeroExit
	if diagnostic.Code == ErrorSchemaInvalid {
		kind = ErrorSchemaInvalid
	}
	return &CommandError{
		Kind:       kind,
		Command:    command,
		Args:       append([]string(nil), args...),
		ExitCode:   result.ExitCode,
		Diagnostic: diagnostic,
		Stdout:     string(result.Stdout),
		Stderr:     string(result.Stderr),
		Cause:      diag.New(diagnostic.Code, diagnostic.Message, diag.WithPath(diagnostic.Path), diag.WithDetails(diagnostic.Details)),
	}
}

func decodeFailureDiagnostic(stdout []byte, stderr []byte) (diag.Diagnostic, error) {
	var lastErr error
	for _, data := range [][]byte{stdout, stderr} {
		if strings.TrimSpace(string(data)) == "" {
			continue
		}
		payload, err := strictjson.DecodeBytes[map[string]any](data, strictjson.DefaultMaxBytes*32)
		if err != nil {
			lastErr = err
			continue
		}
		diagnostics, err := diagnosticsField(payload, "diagnostics")
		if err != nil {
			return diag.FromError(err), nil
		}
		if len(diagnostics) > 0 {
			first := diagnostics[0]
			return diag.Diagnostic{
				Code:    fallbackString(first.Code, ErrorNonzeroExit),
				Message: fallbackString(first.Message, "relay command failed."),
				Path:    first.Path,
				Details: mergeDiagnosticDetails(first.Detail, first.Details),
			}, nil
		}
		if message, _, err := stringField(payload, "message"); err != nil {
			return diag.FromError(err), nil
		} else if message != "" {
			return diag.Diagnostic{Code: ErrorNonzeroExit, Message: message}, nil
		}
		return diag.Diagnostic{Code: ErrorNonzeroExit, Message: "relay command failed."}, nil
	}
	if lastErr != nil {
		return diag.Diagnostic{}, lastErr
	}
	return diag.Diagnostic{}, diag.New(ErrorNonJSON, "relay command did not emit JSON diagnostics.")
}

func fallbackString(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func mergeDiagnosticDetails(values ...map[string]any) map[string]any {
	var merged map[string]any
	for _, value := range values {
		for key, item := range value {
			if merged == nil {
				merged = map[string]any{}
			}
			merged[key] = item
		}
	}
	return merged
}

func runCommand(ctx context.Context, client Client, args []string) CommandResult {
	runner := client.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	result := runner.Run(ctx, client.command(), args...)
	result.Command = client.command()
	result.Args = append([]string(nil), args...)
	return result
}

func commandFailure(command string, args []string, result CommandResult) error {
	if result.Err == nil && result.ExitCode == 0 {
		return nil
	}
	kind := ErrorNonzeroExit
	if errors.Is(result.Err, exec.ErrNotFound) || strings.Contains(result.ErrString(), "executable file not found") || strings.Contains(result.ErrString(), "no such file or directory") {
		kind = ErrorRelayMissing
	}
	return &CommandError{
		Kind:     kind,
		Command:  command,
		Args:     append([]string(nil), args...),
		ExitCode: result.ExitCode,
		Stdout:   string(result.Stdout),
		Stderr:   string(result.Stderr),
		Cause:    result.Err,
	}
}

func decodeError(command string, args []string, result CommandResult, err error) error {
	code := diag.FromError(err).Code
	kind := ErrorNonJSON
	var typeError *json.UnmarshalTypeError
	if code == diag.CodeUnknownJSONField ||
		code == diag.CodeDuplicateJSONKey ||
		code == diag.CodeJSONTooLarge ||
		errors.As(err, &typeError) {
		kind = ErrorSchemaInvalid
	}
	return &CommandError{
		Kind:       kind,
		Command:    command,
		Args:       append([]string(nil), args...),
		Diagnostic: diag.FromError(err),
		Stdout:     string(result.Stdout),
		Stderr:     string(result.Stderr),
		Cause:      err,
	}
}

func (result CommandResult) ErrString() string {
	if result.Err == nil {
		return ""
	}
	return result.Err.Error()
}

func (client Client) command() string {
	if client.Executable != "" {
		return client.Executable
	}
	return DefaultExecutable
}

func (client Client) limit() int64 {
	if client.MaxBytes > 0 {
		return client.MaxBytes
	}
	return strictjson.DefaultMaxBytes * 32
}

func stringField(object map[string]any, key string) (string, bool, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", true, diag.New(ErrorSchemaInvalid, "relay JSON field must be a string.", diag.WithPath("/"+key))
	}
	return text, true, nil
}

func mapField(object map[string]any, key string) (map[string]any, bool, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return nil, false, nil
	}
	typed, ok := value.(map[string]any)
	if !ok {
		return nil, true, diag.New(ErrorSchemaInvalid, "relay JSON field must be an object.", diag.WithPath("/"+key))
	}
	return typed, true, nil
}

func diagnosticsField(object map[string]any, key string) ([]RelayDiagnostic, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, diag.New(ErrorSchemaInvalid, "relay diagnostics field must be an array.", diag.WithPath("/"+key))
	}
	diagnostics := make([]RelayDiagnostic, 0, len(items))
	for i, item := range items {
		itemObject, ok := item.(map[string]any)
		if !ok {
			return nil, diag.New(ErrorSchemaInvalid, "relay diagnostic entries must be objects.", diag.WithPath(fmt.Sprintf("/%s/%d", key, i)))
		}
		code, _, err := stringField(itemObject, "code")
		if err != nil {
			return nil, err
		}
		message, _, err := stringField(itemObject, "message")
		if err != nil {
			return nil, err
		}
		path, _, err := stringField(itemObject, "path")
		if err != nil {
			return nil, err
		}
		category, _, err := stringField(itemObject, "category")
		if err != nil {
			return nil, err
		}
		phase, _, err := stringField(itemObject, "phase")
		if err != nil {
			return nil, err
		}
		detail, _, err := mapField(itemObject, "detail")
		if err != nil {
			return nil, err
		}
		details, _, err := mapField(itemObject, "details")
		if err != nil {
			return nil, err
		}
		diagnostics = append(diagnostics, RelayDiagnostic{
			Category: category,
			Code:     code,
			Message:  message,
			Path:     path,
			Phase:    phase,
			Detail:   detail,
			Details:  details,
			Payload:  itemObject,
		})
	}
	return diagnostics, nil
}
