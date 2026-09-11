// Package review contains the small runtime that prepares and observes the
// recipe-bound review documents in contract/review.
package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	contractreview "github.com/charlesnpx/witness/contract/review"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// DefaultAdapterID is the bundled adapter selected when no configuration
	// file exists.
	DefaultAdapterID = "simple"
	// DefaultRecipeID is the bundled recipe selected when no configuration
	// file exists.
	DefaultRecipeID = "defect-and-economy"
	// DefaultConsumerKind and DefaultConsumerID identify the bundled workflow
	// when a caller does not provide a different consumer identity.
	DefaultConsumerKind = "witness"
	DefaultConsumerID   = "review"
)

// AdapterDescriptor names an adapter implementation. The bundled simple
// adapter needs only ID. A custom adapter is named by ID and supplies either a
// skill name or an executable; no Go adapter registry is involved.
type AdapterDescriptor struct {
	ID         string `json:"id"`
	Executable string `json:"executable,omitempty"`
	Skill      string `json:"skill,omitempty"`
}

// Policy is the execution policy selected by a configuration. It deliberately
// has no adapter or storage settings: those are not review policy.
type Policy struct {
	RequireTranscript bool `json:"require_transcript"`
}

// Config contains exactly the three choices an ordinary review needs.
type Config struct {
	Adapter AdapterDescriptor `json:"adapter"`
	Recipe  string            `json:"recipe"`
	Policy  Policy            `json:"policy"`
}

// DefaultConfig returns the in-memory bundled configuration. It does not read
// or write a configuration file.
func DefaultConfig() Config {
	return Config{
		Adapter: AdapterDescriptor{ID: DefaultAdapterID},
		Recipe:  DefaultRecipeID,
		Policy:  Policy{},
	}
}

// BundledRecipe returns the recipe selected by the bundled configuration.
// The bool is false for an identifier this package does not ship.
func BundledRecipe(id string) (contractreview.ReviewRecipe, bool) {
	if id != DefaultRecipeID {
		return contractreview.ReviewRecipe{}, false
	}
	return contractreview.ReviewRecipe{
		RecipeID:     DefaultRecipeID,
		Instructions: "Inspect the frozen source and Charter independently for defects and avoidable implementation complexity. Emit one review-report-v2 JSON object for the named reviewer and nothing else. A valid empty report is allowed when the required evaluation coverage is present.",
		RequiredOutputs: []string{
			contractreview.RoleDefect,
			contractreview.RoleEconomy,
		},
		Policy: map[string]any{
			"require_transcript": false,
		},
	}, true
}

// ConfigPath resolves the active configuration location. XDG_CONFIG_HOME is
// used when non-empty; otherwise the conventional ~/.config path is used.
func ConfigPath() (string, error) {
	return ConfigPathFrom(os.Getenv, os.UserHomeDir)
}

// ConfigPathFrom is the environment-independent form of ConfigPath, useful to
// callers that provide their own environment or home directory.
func ConfigPathFrom(getenv func(string) string, homeDir func() (string, error)) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if homeDir == nil {
		homeDir = os.UserHomeDir
	}
	configRoot := strings.TrimSpace(getenv("XDG_CONFIG_HOME"))
	if configRoot == "" {
		home, err := homeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory for review configuration: %w", err)
		}
		if strings.TrimSpace(home) == "" {
			return "", errors.New("resolve home directory for review configuration: home directory is empty")
		}
		configRoot = filepath.Join(home, ".config")
	}
	return filepath.Join(configRoot, "review", "config.json"), nil
}

// LoadConfig loads the active configuration. An absent file is a complete
// state and returns DefaultConfig without creating anything. Any present file
// is parsed and validated; it never falls back to defaults after an error.
func LoadConfig() (Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}
	return LoadConfigAt(path)
}

// LoadConfigAt is LoadConfig with an explicit path.
func LoadConfigAt(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("review configuration path is empty")
	}
	resolvedPath, err := resolveReviewPath(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve review configuration path %q: %w", path, err)
	}
	data, err := os.ReadFile(resolvedPath)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read review configuration %q: %w", resolvedPath, err)
	}
	config, err := strictjson.DecodeBytes[Config](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return Config{}, fmt.Errorf("decode review configuration %q: %w", resolvedPath, err)
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, fmt.Errorf("validate review configuration %q: %w", resolvedPath, err)
	}
	return config, nil
}

// ValidateConfig validates the shape and supported selections in a config.
// It intentionally does not execute external implementations; callers that
// are about to select an adapter must also call ValidateImplementation.
func ValidateConfig(config Config) error {
	if err := validateAdapterDescriptor(config.Adapter); err != nil {
		return err
	}
	if strings.TrimSpace(config.Recipe) == "" {
		return errors.New(`configuration field "recipe" is required`)
	}
	if !stableIdentifier(config.Recipe) {
		return fmt.Errorf(`configuration field "recipe" has invalid identifier %q`, config.Recipe)
	}
	if _, ok := BundledRecipe(config.Recipe); !ok {
		return fmt.Errorf(`configuration field "recipe" names unsupported recipe %q`, config.Recipe)
	}
	return nil
}

// ValidateImplementation validates the selected adapter before it is written
// or used. The simple adapter must have both shipped process dependencies. A
// custom executable must answer --validate successfully; a custom skill is
// validated as an identifier because its implementation is supplied by the
// invoking agent rather than this Go process.
func ValidateImplementation(ctx context.Context, descriptor AdapterDescriptor) error {
	if err := validateAdapterDescriptor(descriptor); err != nil {
		return err
	}
	if descriptor.ID == DefaultAdapterID {
		for _, executable := range []string{"delegate", "agentbus"} {
			if _, err := exec.LookPath(executable); err != nil {
				return fmt.Errorf(`adapter %q validation failed for executable %q: %w`, descriptor.ID, executable, err)
			}
		}
		return nil
	}
	if descriptor.Skill != "" {
		return nil
	}
	resolved := descriptor.Executable
	if strings.ContainsAny(descriptor.Executable, `/\`) {
		var err error
		resolved, err = resolveReviewPath(descriptor.Executable)
		if err != nil {
			return fmt.Errorf(`configuration field "adapter.executable" could not be resolved: %w`, err)
		}
	} else {
		var err error
		resolved, err = exec.LookPath(descriptor.Executable)
		if err != nil {
			return fmt.Errorf(`configuration field "adapter.executable" could not be resolved: %w`, err)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	command := exec.CommandContext(ctx, resolved, "--validate")
	output, runErr := command.CombinedOutput()
	if runErr != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return fmt.Errorf(`adapter %q validation failed: %w: %s`, descriptor.ID, runErr, message)
		}
		return fmt.Errorf(`adapter %q validation failed: %w`, descriptor.ID, runErr)
	}
	return nil
}

// WriteConfig validates and writes a configuration at path. It does not run
// an external implementation; use ValidateImplementation before calling it
// when selecting an adapter from operator input.
func WriteConfig(path string, config Config) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("review configuration path is empty")
	}
	if err := ValidateConfig(config); err != nil {
		return err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode review configuration: %w", err)
	}
	resolvedPath, err := resolveReviewOutputPath(path)
	if err != nil {
		return fmt.Errorf("resolve review configuration path %q: %w", path, err)
	}
	return writeConfigBytes(resolvedPath, data)
}

func writeConfigBytes(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create review configuration directory %q: %w", parent, err)
	}
	if err := writePrivateFile(path, append(bytes.TrimSpace(data), '\n')); err != nil {
		return fmt.Errorf("write review configuration %q: %w", path, err)
	}
	return nil
}

func (descriptor *AdapterDescriptor) UnmarshalJSON(data []byte) error {
	type alias AdapterDescriptor
	var decoded alias
	if err := decodeStrictObject(data, &decoded); err != nil {
		return fmt.Errorf("configuration field \"adapter\": %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("configuration field \"adapter\": %w", err)
	}
	if err := requireField(fields, "id", "configuration field \"adapter.id\" is required"); err != nil {
		return err
	}
	for _, field := range []string{"executable", "skill"} {
		if raw, ok := fields[field]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("configuration field \"adapter.%s\" must not be null", field)
		}
	}
	*descriptor = AdapterDescriptor(decoded)
	return validateAdapterDescriptor(*descriptor)
}

func (policy *Policy) UnmarshalJSON(data []byte) error {
	type alias Policy
	var decoded alias
	if err := decodeStrictObject(data, &decoded); err != nil {
		return fmt.Errorf("configuration field \"policy\": %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("configuration field \"policy\": %w", err)
	}
	if err := requireField(fields, "require_transcript", "configuration field \"policy.require_transcript\" is required"); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(fields["require_transcript"]), []byte("null")) {
		return errors.New(`configuration field "policy.require_transcript" must be boolean`)
	}
	*policy = Policy(decoded)
	return nil
}

func (config *Config) UnmarshalJSON(data []byte) error {
	type alias Config
	var decoded alias
	if err := decodeStrictObject(data, &decoded); err != nil {
		return fmt.Errorf("decode review configuration: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode review configuration: %w", err)
	}
	for _, field := range []string{"adapter", "recipe", "policy"} {
		if err := requireField(fields, field, fmt.Sprintf("configuration field %q is required", field)); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(fields[field]), []byte("null")) {
			return fmt.Errorf("configuration field %q must not be null", field)
		}
	}
	*config = Config(decoded)
	return nil
}

func decodeStrictObject(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("configuration contains more than one JSON value")
		}
		return err
	}
	return nil
}

func requireField(fields map[string]json.RawMessage, field string, message string) error {
	if _, ok := fields[field]; !ok {
		return errors.New(message)
	}
	return nil
}

func validateAdapterDescriptor(descriptor AdapterDescriptor) error {
	if strings.TrimSpace(descriptor.ID) == "" {
		return errors.New(`configuration field "adapter.id" is required`)
	}
	if !stableIdentifier(descriptor.ID) {
		return fmt.Errorf(`configuration field "adapter.id" has invalid identifier %q`, descriptor.ID)
	}
	if descriptor.Executable != "" && descriptor.Skill != "" {
		return errors.New(`configuration fields "adapter.executable" and "adapter.skill" are mutually exclusive`)
	}
	if descriptor.ID == DefaultAdapterID {
		if descriptor.Executable != "" || descriptor.Skill != "" {
			return errors.New(`configuration field "adapter" for the simple adapter cannot select a custom executable or skill`)
		}
		return nil
	}
	if descriptor.Executable == "" && descriptor.Skill == "" {
		return fmt.Errorf(`configuration field "adapter" for custom adapter %q requires "executable" or "skill"`, descriptor.ID)
	}
	if descriptor.Skill != "" && !stableIdentifier(descriptor.Skill) {
		return fmt.Errorf(`configuration field "adapter.skill" has invalid identifier %q`, descriptor.Skill)
	}
	return nil
}

func stableIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if index == 0 && !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
			return false
		}
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}
