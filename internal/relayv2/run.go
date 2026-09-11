package relayv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/charlesnpx/convo-relay/v2/bundle"
	"github.com/charlesnpx/convo-relay/v2/result"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// DefaultExecutable is the operator-installed Relay command used when a
	// caller does not supply an explicit executable path.
	DefaultExecutable = "convo-relay"

	// ErrorRelayNotInstalled identifies a command that could not be started
	// because the Relay executable was not found.
	ErrorRelayNotInstalled = "relay_not_installed"
	// ErrorRelayCommandFailed identifies a Relay command that started but did
	// not complete successfully, or failed to start for another reason.
	ErrorRelayCommandFailed = "relay_command_failed"

	runResultMaxBytes = strictjson.DefaultMaxBytes * 32
)

// ErrRelayNotInstalled is matched by errors.Is when convo-relay cannot be
// started because it is absent from PATH (or an explicit executable path is
// absent). Callers can use it to make Relay verification unavailable without
// treating that state as a failed verification result.
var ErrRelayNotInstalled = errors.New("convo-relay is not installed")

// CommandError retains the operator command's identity and captured command
// output while naming the operation that failed. It is returned for process
// start and non-zero-exit failures from Run and Export.
type CommandError struct {
	Operation   string
	Executable  string
	Args        []string
	ExitCode    int
	Stdout      string
	Stderr      string
	Kind        string
	StartFailed bool
	Cause       error
}

// RunOptions supplies the launch-only settings for a supplied Relay plan.
// The home and settings paths are passed to Relay unchanged when non-empty.
type RunOptions struct {
	WorkingDirectory string
	Home             string
	SettingsPath     string
}

// Invocation is the command identity retained by callers that record the
// exact Relay process launch.
type Invocation struct {
	Executable       string
	Args             []string
	WorkingDirectory string
}

// Argv returns the command's argv, including argv[0].
func (invocation Invocation) Argv() []string {
	argv := make([]string, 0, len(invocation.Args)+1)
	argv = append(argv, invocation.Executable)
	argv = append(argv, invocation.Args...)
	return argv
}

func (err *CommandError) Error() string {
	if err == nil {
		return ""
	}
	if err.Kind == ErrorRelayNotInstalled {
		return fmt.Sprintf("%s: executable %q was not found", ErrRelayNotInstalled, err.Executable)
	}
	if err.ExitCode >= 0 {
		return fmt.Sprintf("relay v2 %s failed: command exited with status %d", err.Operation, err.ExitCode)
	}
	if err.StartFailed {
		return fmt.Sprintf("relay v2 %s failed to start", err.Operation)
	}
	return fmt.Sprintf("relay v2 %s did not complete", err.Operation)
}

func (err *CommandError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// Is lets callers use errors.Is(err, ErrRelayNotInstalled) without depending
// on the command error's concrete representation.
func (err *CommandError) Is(target error) bool {
	return err != nil && err.Kind == ErrorRelayNotInstalled && target == ErrRelayNotInstalled
}

// IsRelayNotInstalled reports whether err means that convo-relay could not be
// started because the executable was absent.
func IsRelayNotInstalled(err error) bool {
	return errors.Is(err, ErrRelayNotInstalled)
}

// Run invokes the operator-facing supplied-plan command, decodes its JSON into
// Relay's public result.Result, and validates that result before returning it.
// The plan file and blob directory are passed unchanged to Relay as --plan and
// --blobs, respectively. workingDirectory is the directory in which Relay is
// actually launched.
func Run(ctx context.Context, executable string, planPath string, blobsDirectory string, workingDirectory string) (result.Result, error) {
	value, _, err := RunWithOptions(ctx, executable, planPath, blobsDirectory, RunOptions{WorkingDirectory: workingDirectory})
	return value, err
}

// RunWithOptions invokes the supplied-plan command and returns the exact
// invocation used alongside Relay's decoded result.
func RunWithOptions(ctx context.Context, executable string, planPath string, blobsDirectory string, options RunOptions) (result.Result, Invocation, error) {
	var zero result.Result
	invocation := Invocation{Executable: relayExecutable(executable), WorkingDirectory: options.WorkingDirectory}
	if err := requireContext(ctx, "run"); err != nil {
		return zero, invocation, err
	}
	if strings.TrimSpace(planPath) == "" {
		return zero, invocation, errors.New("relay v2 run requires a plan path")
	}
	if strings.TrimSpace(blobsDirectory) == "" {
		return zero, invocation, errors.New("relay v2 run requires a blob directory")
	}

	invocation.Args = suppliedPlanArgs(planPath, blobsDirectory, options.Home, options.SettingsPath)
	body, err := invoke(ctx, "run", invocation)
	if err != nil {
		return zero, invocation, err
	}
	value, err := decodeJSON[result.Result](body, "run result")
	if err != nil {
		return zero, invocation, fmt.Errorf("decode relay v2 run result: %w", err)
	}
	if err := result.Validate(value); err != nil {
		return zero, invocation, fmt.Errorf("validate relay v2 run result: %w", err)
	}
	return value, invocation, nil
}

type exportResponse struct {
	Output         string `json:"output"`
	Format         string `json:"format"`
	ManifestDigest string `json:"manifest_digest"`
	TerminalStatus string `json:"terminal_status"`
}

// Export creates Relay's portable root-session bundle through the operator
// CLI. The command's JSON response is checked so a successful process exit
// cannot silently produce a non-export response. Verify performs the separate
// in-Go bundle verification and binds the result to the pre-run plan digest.
func Export(ctx context.Context, executable string, sessionDirectory string, outputDirectory string) error {
	if err := requireContext(ctx, "export"); err != nil {
		return err
	}
	if strings.TrimSpace(sessionDirectory) == "" {
		return errors.New("relay v2 export requires a session directory")
	}
	if strings.TrimSpace(outputDirectory) == "" {
		return errors.New("relay v2 export requires an output directory")
	}

	args := []string{
		"export", "create",
		"--session-dir", sessionDirectory,
		"--portable",
		"--output", outputDirectory,
		"--json",
	}
	body, err := invoke(ctx, "export", Invocation{Executable: relayExecutable(executable), Args: args})
	if err != nil {
		return err
	}
	response, err := decodeJSON[exportResponse](body, "export result")
	if err != nil {
		return fmt.Errorf("decode relay v2 export result: %w", err)
	}
	if strings.TrimSpace(response.Output) == "" {
		return errors.New("validate relay v2 export result: output is required")
	}
	if response.Format != bundle.Kind {
		return fmt.Errorf("validate relay v2 export result: format %q does not match %q", response.Format, bundle.Kind)
	}
	if strings.TrimSpace(response.ManifestDigest) == "" {
		return errors.New("validate relay v2 export result: manifest_digest is required")
	}
	if strings.TrimSpace(response.TerminalStatus) == "" {
		return errors.New("validate relay v2 export result: terminal_status is required")
	}
	return nil
}

// Verify verifies a portable Relay bundle in Go and requires the caller to
// supply the digest returned by Compile before execution. Relay's verifier
// performs all bundle-internal checks; this wrapper only adds the adapter's
// required non-empty expectation and operation context.
func Verify(directory string, expectedPlanDigest string) (bundle.Verification, error) {
	var zero bundle.Verification
	if strings.TrimSpace(directory) == "" {
		return zero, errors.New("relay v2 bundle verification requires a bundle directory")
	}
	if strings.TrimSpace(expectedPlanDigest) == "" {
		return zero, errors.New("relay v2 bundle verification requires the expected plan digest")
	}
	verified, err := bundle.VerifyPortableDirectory(directory, bundle.VerifyOptions{
		ExpectedPlanDigest: expectedPlanDigest,
	})
	if err != nil {
		return zero, fmt.Errorf("verify relay v2 portable bundle %q: %w", directory, err)
	}
	return verified, nil
}

// ExportAndVerify performs the portable export and immediately verifies it
// against the digest recorded before the run.
func ExportAndVerify(ctx context.Context, executable string, sessionDirectory string, outputDirectory string, expectedPlanDigest string) (bundle.Verification, error) {
	if err := Export(ctx, executable, sessionDirectory, outputDirectory); err != nil {
		return bundle.Verification{}, err
	}
	return Verify(outputDirectory, expectedPlanDigest)
}

// InvocationEvidence returns the count and presence bit for durable provider
// invocation evidence. A nil Root or nil Root.Invocations returns (0, false);
// a non-nil Invocations with Count == 0 returns (0, true).
func InvocationEvidence(value result.Result) (count int, present bool) {
	if value.Root == nil || value.Root.Invocations == nil {
		return 0, false
	}
	return value.Root.Invocations.Count, true
}

func requireContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return fmt.Errorf("relay v2 %s requires a non-nil context", operation)
	}
	return nil
}

func invoke(ctx context.Context, operation string, invocation Invocation) ([]byte, error) {
	commandArgs := append([]string(nil), invocation.Args...)
	if _, err := exec.LookPath(invocation.Executable); err != nil {
		return nil, &CommandError{
			Operation:   operation,
			Executable:  invocation.Executable,
			Args:        commandArgs,
			ExitCode:    -1,
			Kind:        ErrorRelayNotInstalled,
			StartFailed: true,
			Cause:       err,
		}
	}
	command := exec.CommandContext(ctx, invocation.Executable, commandArgs...)
	command.Dir = invocation.WorkingDirectory
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Start(); err != nil {
		return nil, &CommandError{
			Operation:   operation,
			Executable:  invocation.Executable,
			Args:        commandArgs,
			ExitCode:    -1,
			Stdout:      stdout.String(),
			Stderr:      stderr.String(),
			Kind:        ErrorRelayCommandFailed,
			StartFailed: true,
			Cause:       err,
		}
	}

	err := command.Wait()
	if err == nil {
		return stdout.Bytes(), nil
	}
	exitCode := -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode = exitError.ExitCode()
	}
	return nil, &CommandError{
		Operation:  operation,
		Executable: invocation.Executable,
		Args:       commandArgs,
		ExitCode:   exitCode,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Kind:       ErrorRelayCommandFailed,
		Cause:      err,
	}
}

func relayExecutable(value string) string {
	if strings.TrimSpace(value) == "" {
		return DefaultExecutable
	}
	return value
}

func suppliedPlanArgs(planPath string, blobsDirectory string, home string, settingsPath string) []string {
	args := []string{"run", "--plan", planPath, "--blobs", blobsDirectory, "--json"}
	if home = strings.TrimSpace(home); home != "" {
		args = append(args, "--home", home)
	}
	if settingsPath = strings.TrimSpace(settingsPath); settingsPath != "" {
		args = append(args, "--settings", settingsPath)
	}
	return args
}

func decodeJSON[T any](body []byte, label string) (T, error) {
	var zero T
	if len(bytes.TrimSpace(body)) == 0 {
		return zero, fmt.Errorf("%s is empty", label)
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return zero, fmt.Errorf("%s is null", label)
	}
	value, err := strictjson.DecodeBytes[T](body, runResultMaxBytes)
	if err != nil {
		return zero, err
	}
	return value, nil
}
