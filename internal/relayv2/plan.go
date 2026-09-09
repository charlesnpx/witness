// Package relayv2 is Witness's narrow adapter for the public convo-relay/v2
// plan, result, and bundle boundaries.
//
// Witness owns the review recipes and profiles. Relay owns execution and
// portable-bundle verification. Keeping those responsibilities separate is
// important: a plan is the complete execution document, not a recipe plus a
// second, consumer-defined integration contract.
package relayv2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/convo-relay/v2/plan"
	"github.com/charlesnpx/witness/internal/contracts"
)

const (
	DefaultRecipeID       = "witness-falsify-v2"
	EconomyRecipeID       = "economy-equivalence-v2"
	DefaultProfileID      = "codex"
	DefaultTurnSeconds    = 600
	DefaultStallSeconds   = 300
	VerificationTurns     = 4
	MaxVerificationInputs = 3
)

// Recipe describes the Witness-owned part of a Relay execution plan. The
// required outputs are deliberately carried here rather than inferred from a
// role switch in the pass driver.
type Recipe struct {
	ID                      string
	TaskShape               string
	RequiredFinders         []string
	ParticipantInstructions []string
	ReducerInstructions     string
	ResultSchema            json.RawMessage
	Profiles                map[string]Profile
}

// Profile selects the concrete provider slots used by a recipe. It is part of
// the recipe compilation input and is frozen into the resulting plan through
// actor backend/model/effort/profile fields.
type Profile struct {
	ID                   string
	ParticipantOne       string
	ParticipantOneModel  string
	ParticipantOneEffort string
	ParticipantTwo       string
	ParticipantTwoModel  string
	ParticipantTwoEffort string
	Reducer              string
	ReducerModel         string
	ReducerEffort        string
}

// Input is one raw payload in an ordered plan input group.
type Input struct {
	Name      string
	Bytes     []byte
	MediaType string
}

// CompileOptions supplies the frozen Witness evidence that becomes plan
// inputs. Inputs are copied before compilation so the digest cannot change if
// a caller reuses its buffers after Compile returns.
type CompileOptions struct {
	SessionID     string
	Task          string
	RecipeID      string
	ProfileID     string
	Investigation string
	Workspace     string
	TurnSeconds   int
	StallSeconds  int
	BatchID       string
	Charter       []byte
	Findings      []byte
	Artifacts     []Input
	Context       []Input
	Skills        []Input
}

// CompiledPlan is the exact plan and raw payload set that must be submitted to
// Relay. Digest is computed before any command is launched.
type CompiledPlan struct {
	Plan      plan.Plan
	Digest    string
	Canonical []byte
	Inputs    []Input
	Context   []Input
	Skills    []Input
}

// RecipeForRole returns the recipe selected by a Witness finding role. The
// role-to-recipe mapping is kept in this package so adding a recipe does not
// require changing the pass's finder selection logic.
func RecipeForRole(role string) (Recipe, error) {
	switch strings.TrimSpace(role) {
	case contracts.RoleDefect:
		return DefectRecipe(), nil
	case contracts.RoleEconomy:
		return EconomyRecipe(), nil
	default:
		return Recipe{}, fmt.Errorf("relay v2 has no verification recipe for finder role %q", role)
	}
}

// Recipes returns the immutable Witness recipe catalog in stable order.
func Recipes() []Recipe {
	return []Recipe{DefectRecipe(), EconomyRecipe()}
}

// DefectRecipe returns the Witness defect-falsification recipe.
func DefectRecipe() Recipe {
	return recipe(
		DefaultRecipeID,
		contracts.BatchTaskDefect,
		"Presenter filing pass: enumerate every supplied finding ID and restate each defect claim, witness, scope anchor, Charter goal reference, proposed test, and witness digest exactly as filed. Use only the bound charter, findings, and artifact inputs.",
		"Falsifier attack pass: attack every supplied defect witness. Test whether the filed witness establishes an in-envelope reachable Charter violation, and provide a concrete counter-witness for any claimed weakening or breakage.",
		"Presenter defense pass: defend only with material already present in the filed witness, deterministic batch, frozen Charter, bound artifact inputs, or immutable refs cited by those inputs. Do not add new findings, new goals, or stronger uncited evidence.",
		"Falsifier final pass: state the strongest remaining attack for every supplied ID, identify any presenter strengthening the reducer must ignore, and do not introduce new finding IDs.",
	)
}

// EconomyRecipe returns the Witness economy-equivalence recipe.
func EconomyRecipe() Recipe {
	return recipe(
		EconomyRecipeID,
		contracts.BatchTaskEconomy,
		"Presenter filing pass: enumerate every supplied finding ID and restate each economy claim, equivalence witness, proposed removal or simplification, Charter goal references, and witness digest exactly as filed. Use only the bound charter, findings, and artifact inputs.",
		"Falsifier attack pass: challenge every supplied equivalence witness. Identify a concrete Charter goal, required behavior, or bound artifact fact that would fail after the proposed removal or simplification, and provide a counter-witness for any claimed weakening or breakage.",
		"Presenter defense pass: defend only with material already present in the filed witness, deterministic batch, frozen Charter, bound artifact inputs, or immutable refs cited by those inputs. Do not add new findings, new goals, or stronger uncited evidence.",
		"Falsifier final pass: state the strongest remaining attack for every supplied ID, identify any presenter strengthening the reducer must ignore, and do not introduce new finding IDs.",
	)
}

func recipe(id string, taskShape string, instructions ...string) Recipe {
	return Recipe{
		ID:                      id,
		TaskShape:               taskShape,
		RequiredFinders:         []string{finderForTaskShape(taskShape)},
		ParticipantInstructions: append([]string(nil), instructions...),
		ReducerInstructions:     contracts.ReducerBriefText,
		ResultSchema:            append(json.RawMessage(nil), contracts.RelayWitnessVerdictsV2SchemaBytes()...),
		Profiles: map[string]Profile{
			"codex": {
				ID:                   "codex",
				ParticipantOne:       "codex",
				ParticipantOneEffort: "high",
				ParticipantTwo:       "codex",
				ParticipantTwoEffort: "high",
				Reducer:              "codex",
				ReducerEffort:        "high",
			},
			"claude": {
				ID:             "claude",
				ParticipantOne: "claude",
				ParticipantTwo: "claude",
				Reducer:        "codex",
				ReducerEffort:  "high",
			},
		},
	}
}

func finderForTaskShape(taskShape string) string {
	if taskShape == contracts.BatchTaskEconomy {
		return contracts.RoleEconomy
	}
	return contracts.RoleDefect
}

// Compile builds a complete plan accepted by plan.Validate. It does not call
// Relay and it does not apply Relay defaults. Every instruction, schema,
// profile selection, and input reference is explicit in the returned Plan.
func Compile(options CompileOptions) (CompiledPlan, error) {
	recipeID := strings.TrimSpace(options.RecipeID)
	if recipeID == "" {
		recipeID = DefaultRecipeID
	}
	recipe, ok := recipeByID(recipeID)
	if !ok {
		return CompiledPlan{}, fmt.Errorf("relay v2 recipe %q is not supported by Witness", recipeID)
	}
	profileID := strings.TrimSpace(options.ProfileID)
	if profileID == "" {
		profileID = DefaultProfileID
	}
	profile, ok := recipe.Profiles[profileID]
	if !ok {
		return CompiledPlan{}, fmt.Errorf("relay v2 recipe %q has no execution profile %q", recipe.ID, profileID)
	}
	sessionID := strings.TrimSpace(options.SessionID)
	if sessionID == "" {
		return CompiledPlan{}, errors.New("relay v2 plan compilation requires session_id")
	}
	task := strings.TrimSpace(options.Task)
	if task == "" {
		task = "Verify the filed Witness findings against the frozen Charter."
	}
	investigation := strings.TrimSpace(options.Investigation)
	if investigation == "" {
		investigation = plan.InvestigationNormal
	}
	workspace := strings.TrimSpace(options.Workspace)
	if workspace == "" {
		workspace = plan.WorkspaceModeCurrent
	}
	turnSeconds := options.TurnSeconds
	if turnSeconds == 0 {
		turnSeconds = DefaultTurnSeconds
	}
	stallSeconds := options.StallSeconds
	if stallSeconds == 0 {
		stallSeconds = DefaultStallSeconds
	}
	if turnSeconds < 1 || stallSeconds < 1 {
		return CompiledPlan{}, errors.New("relay v2 plan compilation requires positive turn and stall timeouts")
	}
	if len(options.Charter) == 0 {
		return CompiledPlan{}, errors.New("relay v2 plan compilation requires a frozen Charter input")
	}
	if len(options.Findings) == 0 {
		return CompiledPlan{}, errors.New("relay v2 plan compilation requires a verification findings input")
	}
	if len(options.Artifacts) > MaxVerificationInputs {
		return CompiledPlan{}, fmt.Errorf("relay v2 plan compilation accepts at most %d artifact inputs", MaxVerificationInputs)
	}

	inputs := []Input{
		{Name: "charter", Bytes: cloneBytes(options.Charter), MediaType: "application/json"},
		{Name: "findings", Bytes: cloneBytes(options.Findings), MediaType: "application/json"},
	}
	artifacts := cloneInputs(options.Artifacts)
	contextInputs := cloneInputs(options.Context)
	skillInputs := cloneInputs(options.Skills)
	inputRefs, err := refsForInputs(inputs)
	if err != nil {
		return CompiledPlan{}, err
	}
	artifactRef, err := refsForInputGroup("artifact", artifacts)
	if err != nil {
		return CompiledPlan{}, err
	}
	if len(artifactRef.Contents) > 0 {
		inputRefs = append(inputRefs, artifactRef)
	}
	contextRefs, err := refsForInputs(contextInputs)
	if err != nil {
		return CompiledPlan{}, err
	}
	skillRefs, err := refsForInputs(skillInputs)
	if err != nil {
		return CompiledPlan{}, err
	}

	batchID := strings.TrimSpace(options.BatchID)
	taskPlan, err := json.Marshal(map[string]any{
		"batch_id":         batchID,
		"required_finders": append([]string(nil), recipe.RequiredFinders...),
		"task_shape":       recipe.TaskShape,
		"recipe_id":        recipe.ID,
	})
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("encode relay v2 task plan: %w", err)
	}
	value := plan.Plan{
		Kind:          plan.PlanKind,
		SchemaVersion: plan.SchemaVersion,
		SessionID:     sessionID,
		Provenance:    plan.ProvenanceRecipe,
		RecipeID:      recipe.ID,
		Task:          task,
		Timeouts:      plan.Timeouts{TurnSeconds: turnSeconds, StallSeconds: stallSeconds},
		Mode:          plan.ModeAdversarial,
		Investigation: investigation,
		Actors: []plan.Actor{
			{ID: "participant-1", Backend: profile.ParticipantOne, Model: profile.ParticipantOneModel, Effort: profile.ParticipantOneEffort, ProfileID: profile.ID},
			{ID: "participant-2", Backend: profile.ParticipantTwo, Model: profile.ParticipantTwoModel, Effort: profile.ParticipantTwoEffort, ProfileID: profile.ID},
			{ID: "reducer", Backend: profile.Reducer, Model: profile.ReducerModel, Effort: profile.ReducerEffort, ProfileID: profile.ID},
		},
		Schedule: plan.Schedule{
			Kind:  plan.ScheduleSequence,
			Turns: VerificationTurns,
			Order: []string{"participant-1", "participant-2", "participant-1", "participant-2"},
		},
		Reducer:       &plan.Reducer{Actor: "reducer"},
		ProviderRetry: plan.ProviderRetry{Mode: plan.ProviderRetryForbid, MaxAttempts: 1},
		Workspace:     plan.Workspace{Mode: workspace},
		Inputs:        inputRefs,
		Context:       contextRefs,
		Skills:        skillRefs,
		TaskPlan:      json.RawMessage(taskPlan),
		ChildPolicy:   plan.ChildPolicy{Mode: plan.ChildPolicyDeny, MaxDepth: 0, MaxChildren: 0, MaxTurns: 0, AllowedRecipes: []string{}},
		Result:        plan.Result{Source: plan.ResultSourceReducer, Format: plan.ResultFormatJSON, Schema: append(json.RawMessage(nil), recipe.ResultSchema...)},
		Lifecycle:     &plan.Lifecycle{Resume: plan.LifecycleForbid, Steering: plan.LifecycleForbid, Dynamic: plan.LifecycleForbid},
		Instructions:  instructionsForRecipe(recipe),
	}
	if err := plan.Validate(value); err != nil {
		return CompiledPlan{}, fmt.Errorf("validate compiled relay v2 plan for recipe %q: %w", recipe.ID, err)
	}
	digestValue, err := plan.Digest(value)
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("digest compiled relay v2 plan for recipe %q: %w", recipe.ID, err)
	}
	canonical, err := plan.CanonicalBytes(value)
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("canonicalize compiled relay v2 plan for recipe %q: %w", recipe.ID, err)
	}
	return CompiledPlan{
		Plan:      value,
		Digest:    digestValue,
		Canonical: canonical,
		Inputs:    append(inputs, artifacts...),
		Context:   contextInputs,
		Skills:    skillInputs,
	}, nil
}

func recipeByID(id string) (Recipe, bool) {
	for _, recipe := range Recipes() {
		if recipe.ID == id {
			return recipe, true
		}
	}
	return Recipe{}, false
}

func instructionsForRecipe(recipe Recipe) *plan.Instructions {
	turns := make([]plan.TurnInstruction, 0, len(recipe.ParticipantInstructions))
	for index, text := range recipe.ParticipantInstructions {
		actor := "participant-1"
		if index%2 == 1 {
			actor = "participant-2"
		}
		turns = append(turns, plan.TurnInstruction{ParticipantTurn: index + 1, Actor: actor, Instructions: text})
	}
	return &plan.Instructions{Turns: turns, ReducerInstructions: recipe.ReducerInstructions}
}

func refsForInputs(inputs []Input) ([]plan.Input, error) {
	if len(inputs) == 0 {
		return []plan.Input{}, nil
	}
	refs := make([]plan.Input, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		name := strings.TrimSpace(input.Name)
		if name == "" {
			return nil, errors.New("relay v2 plan input name is required")
		}
		if seen[name] {
			return nil, fmt.Errorf("relay v2 plan input %q is duplicated", name)
		}
		seen[name] = true
		ref, err := refForInput(input, name)
		if err != nil {
			return nil, err
		}
		refs = append(refs, plan.Input{Name: name, Contents: []plan.BlobRef{ref}})
	}
	return refs, nil
}

func refsForInputGroup(name string, inputs []Input) (plan.Input, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return plan.Input{}, errors.New("relay v2 plan input group name is required")
	}
	if len(inputs) == 0 {
		return plan.Input{}, nil
	}
	contents := make([]plan.BlobRef, 0, len(inputs))
	for _, input := range inputs {
		inputName := strings.TrimSpace(input.Name)
		if inputName == "" {
			return plan.Input{}, fmt.Errorf("relay v2 %s input name is required", name)
		}
		ref, err := refForInput(input, inputName)
		if err != nil {
			return plan.Input{}, err
		}
		contents = append(contents, ref)
	}
	return plan.Input{Name: name, Contents: contents}, nil
}

func refForInput(input Input, name string) (plan.BlobRef, error) {
	if len(input.Bytes) == 0 {
		return plan.BlobRef{}, fmt.Errorf("relay v2 plan input %q is empty", name)
	}
	sum := sha256.Sum256(input.Bytes)
	return plan.BlobRef{
		SHA256:    hex.EncodeToString(sum[:]),
		Size:      int64(len(input.Bytes)),
		MediaType: inputMediaType(input.MediaType),
	}, nil
}

// Materialize writes all plan payloads into the v2 blob directory layout. It
// validates each payload against its plan reference and refuses a pre-existing
// digest whose bytes do not agree.
func Materialize(directory string, compiled CompiledPlan) error {
	if strings.TrimSpace(directory) == "" {
		return errors.New("relay v2 blob directory is required")
	}
	if err := plan.Validate(compiled.Plan); err != nil {
		return fmt.Errorf("validate plan before blob materialization: %w", err)
	}
	expected := make(map[string]plan.BlobRef)
	for _, ref := range plan.BlobRefs(compiled.Plan) {
		if previous, exists := expected[ref.SHA256]; exists && !previous.Equal(ref) {
			return fmt.Errorf("relay v2 plan references blob %s with conflicting metadata", ref.SHA256)
		}
		expected[ref.SHA256] = ref
	}
	all := make([]Input, 0, len(compiled.Inputs)+len(compiled.Context)+len(compiled.Skills))
	all = append(all, compiled.Inputs...)
	all = append(all, compiled.Context...)
	all = append(all, compiled.Skills...)
	byDigest := map[string]Input{}
	for _, input := range all {
		name := strings.TrimSpace(input.Name)
		if name == "" {
			return errors.New("relay v2 materialized input name is required")
		}
		ref, err := refForInput(input, name)
		if err != nil {
			return err
		}
		expectedRef, exists := expected[ref.SHA256]
		if !exists {
			return fmt.Errorf("relay v2 input %q is not referenced by the plan", name)
		}
		if !expectedRef.Equal(ref) {
			return fmt.Errorf("relay v2 input %q does not match plan blob %s: expected=%#v, actual=%#v", name, ref.SHA256, expectedRef, ref)
		}
		if previous, exists := byDigest[ref.SHA256]; exists {
			if inputMediaType(previous.MediaType) != ref.MediaType {
				return fmt.Errorf("relay v2 blob %s has conflicting input metadata", ref.SHA256)
			}
			continue
		}
		byDigest[ref.SHA256] = input
	}
	for digestValue := range expected {
		if _, exists := byDigest[digestValue]; !exists {
			return fmt.Errorf("relay v2 plan blob %s has no materialized input", digestValue)
		}
	}
	digests := make([]string, 0, len(byDigest))
	for digestValue := range byDigest {
		digests = append(digests, digestValue)
	}
	sort.Strings(digests)
	for _, digestValue := range digests {
		input := byDigest[digestValue]
		path := filepath.Join(directory, "sha256", digestValue)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create relay v2 blob directory: %w", err)
		}
		if existing, err := os.ReadFile(path); err == nil {
			if string(existing) != string(input.Bytes) {
				return fmt.Errorf("relay v2 blob %s already exists with different bytes", digestValue)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read existing relay v2 blob %s: %w", digestValue, err)
		}
		temporary, err := os.CreateTemp(filepath.Dir(path), ".blob-*")
		if err != nil {
			return fmt.Errorf("create relay v2 blob %s: %w", digestValue, err)
		}
		temporaryPath := temporary.Name()
		remove := true
		if _, err := temporary.Write(input.Bytes); err == nil {
			err = temporary.Chmod(0o600)
		}
		if closeErr := temporary.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(temporaryPath, path)
			if err == nil {
				remove = false
			}
		}
		if remove {
			_ = os.Remove(temporaryPath)
		}
		if err != nil {
			return fmt.Errorf("write relay v2 blob %s: %w", digestValue, err)
		}
	}
	return nil
}

func cloneInputs(values []Input) []Input {
	if len(values) == 0 {
		return []Input{}
	}
	result := make([]Input, len(values))
	for index, value := range values {
		result[index] = Input{
			Name:      strings.TrimSpace(value.Name),
			MediaType: inputMediaType(value.MediaType),
			Bytes:     cloneBytes(value.Bytes),
		}
	}
	return result
}

func inputMediaType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "application/octet-stream"
	}
	return value
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
