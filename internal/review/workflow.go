package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/digest"
	contractreview "github.com/charlesnpx/witness/contract/review"
	"github.com/charlesnpx/witness/contract/strictjson"
)

// PrepareOptions describes the caller-owned source and Charter inputs for an
// ordinary review. The caller supplies a frozen Charter or CharterPath; it
// does not assemble a request document by hand.
type PrepareOptions struct {
	Config            Config
	FrozenCharter     *charter.FrozenCharter
	CharterPath       string
	AmendmentsPath    string
	SourceDir         string
	PacketDirectory   string
	Subject           contractreview.RequestSubject
	ReviewInputDigest string
	ConsumerIdentity  contractreview.Identity
}

// PreparedReview contains the request and packet files produced before the
// adapter is invoked.
type PreparedReview struct {
	Request       contractreview.ReviewRequestV2Document
	FrozenCharter charter.FrozenCharter
	Recipe        contractreview.ReviewRecipe
	Packets       []ReviewerPacket
	// SourceDirectory and SourceDigest identify the source tree captured before
	// reviewer execution. The adapter re-hashes this directory after collection
	// and refuses a satisfied completion if the digest moved.
	SourceDirectory string
	SourceDigest    string
}

// Prepare freezes/loads the Charter, captures the source digest, derives a
// source input digest when the caller did not provide one, and writes one
// prompt/schema packet per required reviewer.
func Prepare(options PrepareOptions) (PreparedReview, error) {
	if err := ValidateConfig(options.Config); err != nil {
		return PreparedReview{}, fmt.Errorf("validate review configuration: %w", err)
	}
	frozen, err := resolveFrozenCharter(options)
	if err != nil {
		return PreparedReview{}, err
	}
	if err := validateFrozenCharter(frozen); err != nil {
		return PreparedReview{}, fmt.Errorf("validate frozen review Charter: %w", err)
	}
	if strings.TrimSpace(options.SourceDir) == "" {
		return PreparedReview{}, errors.New("review preparation requires source directory")
	}
	sourceDirectory, err := resolveReviewPath(options.SourceDir)
	if err != nil {
		return PreparedReview{}, fmt.Errorf("resolve review source directory %q: %w", options.SourceDir, err)
	}
	if info, statErr := os.Stat(sourceDirectory); statErr != nil || !info.IsDir() {
		if statErr != nil {
			return PreparedReview{}, fmt.Errorf("review source directory %q: %w", sourceDirectory, statErr)
		}
		return PreparedReview{}, fmt.Errorf("review source directory %q is not a directory", sourceDirectory)
	}
	recipe, ok := BundledRecipe(options.Config.Recipe)
	if !ok {
		return PreparedReview{}, fmt.Errorf("configuration field \"recipe\" names unsupported recipe %q", options.Config.Recipe)
	}
	recipe.Policy["require_transcript"] = options.Config.Policy.RequireTranscript
	recipeBytes, err := contractreview.ReviewRecipeCanonicalBytes(recipe)
	if err != nil {
		return PreparedReview{}, fmt.Errorf("encode frozen review recipe: %w", err)
	}
	recipeDigest, err := contractreview.ReviewRecipeDigest(recipeBytes)
	if err != nil {
		return PreparedReview{}, fmt.Errorf("digest frozen review recipe: %w", err)
	}
	sourceDigest, err := sourceDigestResolved(sourceDirectory)
	if err != nil {
		return PreparedReview{}, fmt.Errorf("derive review source digest: %w", err)
	}
	inputDigest := options.ReviewInputDigest
	if strings.TrimSpace(inputDigest) == "" {
		inputDigest = sourceDigest
	}
	if !digest.WellFormed(inputDigest) {
		return PreparedReview{}, fmt.Errorf("review input digest %q is not a relay-root-digests-v1 sha256 digest", inputDigest)
	}
	subject := options.Subject
	if strings.TrimSpace(subject.Head) == "" {
		subject.Head = sourceHead(sourceDirectory, inputDigest)
	}
	consumer := options.ConsumerIdentity
	if strings.TrimSpace(consumer.Kind) == "" {
		consumer.Kind = DefaultConsumerKind
	}
	if strings.TrimSpace(consumer.ID) == "" {
		consumer.ID = DefaultConsumerID
	}
	request := contractreview.ReviewRequestV2Document{
		SchemaVersion:     contractreview.ReviewRequestV2,
		ConsumerIdentity:  consumer,
		Subject:           subject,
		CharterHash:       frozen.CharterHash,
		ReviewInputDigest: inputDigest,
		FrozenRecipe:      append(json.RawMessage(nil), recipeBytes...),
		RecipeDigest:      recipeDigest,
		Adapter:           options.Config.Adapter.ID,
		RequiredOutputs:   append([]string(nil), recipe.RequiredOutputs...),
	}
	if err := contractreview.RequireValidReviewRequestV2(request); err != nil {
		return PreparedReview{}, fmt.Errorf("construct review request: %w", err)
	}
	if strings.TrimSpace(options.PacketDirectory) == "" {
		return PreparedReview{}, errors.New("review preparation requires PacketDirectory")
	}
	requestedPacketDirectory := options.PacketDirectory
	packetDirectory, err := resolveReviewPath(requestedPacketDirectory)
	if err != nil {
		return PreparedReview{}, fmt.Errorf("resolve review packet directory %q: %w", requestedPacketDirectory, err)
	}
	if pathWithin(sourceDirectory, packetDirectory) {
		return PreparedReview{}, fmt.Errorf("review packet directory %q resolves inside source directory %q; packets written into the reviewed tree would change the thing being reviewed", packetDirectory, sourceDirectory)
	}
	if err := os.MkdirAll(packetDirectory, 0o700); err != nil {
		return PreparedReview{}, fmt.Errorf("create review packet directory %q: %w", packetDirectory, err)
	}
	packets := make([]ReviewerPacket, 0, len(recipe.RequiredOutputs))
	for _, reviewer := range recipe.RequiredOutputs {
		promptPath := filepath.Join(packetDirectory, reviewer+".prompt.txt")
		schemaPath := filepath.Join(packetDirectory, reviewer+".schema.json")
		prompt, err := reviewerPrompt(request, frozen, recipe, reviewer, sourceDirectory)
		if err != nil {
			return PreparedReview{}, fmt.Errorf("prepare reviewer %q prompt: %w", reviewer, err)
		}
		if err := writePrivateFile(promptPath, []byte(prompt)); err != nil {
			return PreparedReview{}, fmt.Errorf("write reviewer %q prompt: %w", reviewer, err)
		}
		schema, err := reviewerSchema(request, frozen, reviewer)
		if err != nil {
			return PreparedReview{}, fmt.Errorf("prepare reviewer %q schema: %w", reviewer, err)
		}
		if err := writePrivateFile(schemaPath, schema); err != nil {
			return PreparedReview{}, fmt.Errorf("write reviewer %q schema: %w", reviewer, err)
		}
		packets = append(packets, ReviewerPacket{Reviewer: reviewer, PromptPath: promptPath, SchemaPath: schemaPath})
	}
	return PreparedReview{
		Request:         request,
		FrozenCharter:   frozen,
		Recipe:          recipe,
		Packets:         packets,
		SourceDirectory: sourceDirectory,
		SourceDigest:    sourceDigest,
	}, nil
}

// Run executes the bundled workflow after preparing its request and packets.
// The returned completion was constructed in this process from observed job
// outcomes; callers may persist it but must not reload it as proof.
func Run(ctx context.Context, prepareOptions PrepareOptions, adapterOptions SimpleAdapterOptions) (PreparedReview, SimpleRunResult, error) {
	prepared, err := Prepare(prepareOptions)
	if err != nil {
		return PreparedReview{}, SimpleRunResult{}, err
	}
	if prepareOptions.Config.Adapter.ID != DefaultAdapterID {
		return prepared, SimpleRunResult{}, fmt.Errorf("adapter %q is custom; invoke its configured skill or executable", prepareOptions.Config.Adapter.ID)
	}
	adapter := NewSimpleAdapter(adapterOptions)
	runResult, err := adapter.Run(ctx, SimpleRunOptions{
		Request:          prepared.Request,
		FrozenCharter:    prepared.FrozenCharter,
		Packets:          prepared.Packets,
		WorkingDirectory: prepared.SourceDirectory,
		SourceDigest:     prepared.SourceDigest,
	})
	if err != nil {
		return prepared, SimpleRunResult{}, err
	}
	return prepared, runResult, nil
}

// WriteCanonical persists a canonical JSON document. A file destination is
// resolved and written atomically; an empty destination writes to stdout.
func WriteCanonical(path string, document any) error {
	data, err := canonjson.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode canonical document: %w", err)
	}
	return writeReviewOutput(path, append(data, '\n'), "canonical document")
}

// WriteJSON persists a standard JSON document. It shares the same atomic file
// writer as WriteCanonical while retaining encoding/json's number notation for
// consumer-facing output that is not bound by a digest.
func WriteJSON(path string, document any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode JSON document: %w", err)
	}
	return writeReviewOutput(path, buffer.Bytes(), "JSON document")
}

// SourceDigest returns a deterministic semantic digest of all regular files
// below root, excluding the root's .git directory. File contents are read at
// the time of the call.
func SourceDigest(root string) (string, error) {
	resolvedRoot, err := resolveReviewPath(root)
	if err != nil {
		return "", fmt.Errorf("resolve source digest root %q: %w", root, err)
	}
	return sourceDigestResolved(resolvedRoot)
}

func sourceDigestResolved(root string) (string, error) {
	if root == "" {
		return "", errors.New("source digest root is empty")
	}
	type fileEntry struct {
		Path   string `json:"path"`
		Digest string `json:"digest"`
		Bytes  int64  `json:"bytes"`
	}
	entries := make([]fileEntry, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, fileEntry{Path: filepath.ToSlash(relative), Digest: digest.RawBytes(data), Bytes: int64(len(data))})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk source directory %q: %w", root, err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	return digest.SemanticJSON(map[string]any{"files": entries})
}

func resolveReviewPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	current := absolute
	missing := make([]string, 0)
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", fmt.Errorf("resolve path %q: %w", path, err)
			}
			for _, part := range missing {
				resolved = filepath.Join(resolved, part)
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve path %q: %w", path, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolve path %q: no existing ancestor", path)
		}
		missing = append([]string{filepath.Base(current)}, missing...)
		current = parent
	}
}

// resolveReviewOutputPath resolves the destination directory while retaining
// the final directory entry for Lstat. A final symlink must be rejected by the
// atomic writer rather than resolved into its target.
func resolveReviewOutputPath(path string) (string, error) {
	parent, err := resolveReviewPath(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func pathWithin(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func resolveFrozenCharter(options PrepareOptions) (charter.FrozenCharter, error) {
	if options.FrozenCharter != nil {
		return *options.FrozenCharter, nil
	}
	if strings.TrimSpace(options.CharterPath) == "" {
		return charter.FrozenCharter{}, errors.New("review preparation requires a Charter or frozen Charter path")
	}
	charterPath, err := resolveReviewPath(options.CharterPath)
	if err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("resolve review Charter %q: %w", options.CharterPath, err)
	}
	data, err := os.ReadFile(charterPath)
	if err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("read review Charter %q: %w", charterPath, err)
	}
	var envelope map[string]json.RawMessage
	if _, err := strictjson.DecodeBytes[map[string]json.RawMessage](data, strictjson.DefaultMaxBytes); err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("decode review Charter %q: %w", charterPath, err)
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("decode review Charter envelope %q: %w", charterPath, err)
	}
	var schemaVersion string
	if raw, ok := envelope["schema_version"]; ok {
		if err := json.Unmarshal(raw, &schemaVersion); err != nil {
			return charter.FrozenCharter{}, fmt.Errorf("decode review Charter schema_version: %w", err)
		}
	}
	if schemaVersion == charter.FrozenSchemaVersion {
		frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
		if err != nil {
			return charter.FrozenCharter{}, fmt.Errorf("decode frozen review Charter %q: %w", charterPath, err)
		}
		return frozen, nil
	}
	input, err := charter.ReadBytes(data)
	if err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("decode review Charter %q: %w", charterPath, err)
	}
	var amendments []charter.OwnerEvent
	if strings.TrimSpace(options.AmendmentsPath) != "" {
		amendmentsPath, resolveErr := resolveReviewPath(options.AmendmentsPath)
		if resolveErr != nil {
			return charter.FrozenCharter{}, fmt.Errorf("resolve review Charter amendments %q: %w", options.AmendmentsPath, resolveErr)
		}
		amendments, err = charter.ReadAmendmentsFile(amendmentsPath)
		if err != nil {
			return charter.FrozenCharter{}, fmt.Errorf("read review Charter amendments %q: %w", amendmentsPath, err)
		}
	}
	frozen, err := charter.Freeze(input, amendments)
	if err != nil {
		return charter.FrozenCharter{}, fmt.Errorf("freeze review Charter: %w", err)
	}
	return frozen, nil
}

func validateFrozenCharter(frozen charter.FrozenCharter) error {
	if frozen.SchemaVersion != charter.FrozenSchemaVersion {
		return fmt.Errorf("schema_version must be %q", charter.FrozenSchemaVersion)
	}
	if frozen.DigestProfile != digest.Profile {
		return fmt.Errorf("digest_profile must be %q", digest.Profile)
	}
	if !digest.WellFormed(frozen.CharterHash) {
		return errors.New("charter_hash is not a valid sha256 digest")
	}
	expectedHash, err := charter.Hash(frozen.Charter)
	if err != nil {
		return fmt.Errorf("recompute charter_hash: %w", err)
	}
	if frozen.CharterHash != expectedHash {
		return fmt.Errorf("charter_hash %q does not match normalized Charter hash %q", frozen.CharterHash, expectedHash)
	}
	properties := charter.Properties(frozen.Charter.OperationalEnvelope)
	if frozen.ReachabilityRulesActive != properties.ReachabilityRulesActive {
		return errors.New("reachability_rules_active does not match the frozen Charter")
	}
	if frozen.AdditiveRemediesAutomatic != properties.AdditiveRemediesAutomatic {
		return errors.New("additive_remedies_automatic does not match the frozen Charter")
	}
	return nil
}

func sourceHead(sourceDirectory string, inputDigest string) string {
	command := exec.Command("git", "-C", sourceDirectory, "rev-parse", "HEAD")
	output, err := command.Output()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		return strings.TrimSpace(string(output))
	}
	return "source-" + strings.TrimPrefix(inputDigest, digest.Prefix)[:12]
}

func sourceIdentityForRequest(request contractreview.ReviewRequestV2Document) contractreview.Identity {
	return contractreview.Identity{Kind: "git", ID: request.Subject.Head}
}

func reviewerPrompt(request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, recipe contractreview.ReviewRecipe, reviewer string, sourceDirectory string) (string, error) {
	requestBytes, err := canonjson.Marshal(request)
	if err != nil {
		return "", err
	}
	charterBytes, err := canonjson.Marshal(frozen)
	if err != nil {
		return "", err
	}
	recipeBytes, err := canonjson.Marshal(recipe)
	if err != nil {
		return "", err
	}
	sourceIdentityBytes, err := json.Marshal(sourceIdentityForRequest(request))
	if err != nil {
		return "", err
	}
	consumerIdentityBytes, err := json.Marshal(request.ConsumerIdentity)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "You are the independent %s reviewer in a Witness review.\n", reviewer)
	fmt.Fprintf(&builder, "Read the frozen source at %s. Do not modify it.\n", sourceDirectory)
	fmt.Fprintf(&builder, "Follow the recipe instructions and emit exactly one review-report-v2 JSON object, with no prose outside JSON. The reviewer field must be %q, source_identity must be %s, and consumer_identity must be %s. A valid empty findings array is allowed, but evaluation must truthfully cover the paths and goals you inspected.\n\n", reviewer, sourceIdentityBytes, consumerIdentityBytes)
	builder.WriteString("REQUEST:\n")
	builder.Write(requestBytes)
	builder.WriteString("\n\nFROZEN CHARTER:\n")
	builder.Write(charterBytes)
	builder.WriteString("\n\nFROZEN RECIPE:\n")
	builder.Write(recipeBytes)
	builder.WriteString("\n")
	return builder.String(), nil
}

func reviewerSchema(request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, reviewer string) ([]byte, error) {
	sourceIdentity := sourceIdentityForRequest(request)
	goalIDs := make([]string, len(frozen.Charter.Goals))
	for index, goal := range frozen.Charter.Goals {
		goalIDs[index] = goal.ID
	}
	properties := map[string]any{
		"schema_version":      map[string]any{"const": contractreview.ReviewReportV2},
		"request_digest":      map[string]any{"const": mustRequestDigest(request)},
		"recipe_digest":       map[string]any{"const": request.RecipeDigest},
		"reviewer":            map[string]any{"const": reviewer},
		"charter_hash":        map[string]any{"const": frozen.CharterHash},
		"review_input_digest": map[string]any{"const": request.ReviewInputDigest},
		"source_identity":     map[string]any{"const": sourceIdentity},
		"consumer_identity":   map[string]any{"const": request.ConsumerIdentity},
		"findings":            map[string]any{"type": "array"},
		"evaluation":          map[string]any{"type": "object"},
	}
	if len(goalIDs) > 0 {
		properties["evaluation"] = map[string]any{
			"type":     "object",
			"required": []string{"evaluated_paths", "evaluated_goal_ids"},
			"properties": map[string]any{
				"evaluated_paths":    map[string]any{"type": "array", "minItems": 1},
				"evaluated_goal_ids": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"enum": goalIDs}},
			},
		}
	} else {
		properties["evaluation"] = map[string]any{
			"type":     "object",
			"required": []string{"evaluated_paths", "evaluated_goal_ids"},
			"properties": map[string]any{
				"evaluated_paths":    map[string]any{"type": "array", "minItems": 1},
				"evaluated_goal_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
		}
	}
	return canonjson.Marshal(map[string]any{
		"type":       "object",
		"required":   []string{"schema_version", "request_digest", "recipe_digest", "reviewer", "charter_hash", "review_input_digest", "source_identity", "consumer_identity", "findings", "evaluation"},
		"properties": properties,
	})
}

func mustRequestDigest(request contractreview.ReviewRequestV2Document) string {
	digestValue, err := contractreview.ReviewRequestV2Digest(request)
	if err != nil {
		return ""
	}
	return digestValue
}

func writeReviewOutput(path string, data []byte, description string) error {
	if path == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("write %s to stdout: %w", description, err)
		}
		return nil
	}
	resolvedPath, err := resolveReviewOutputPath(path)
	if err != nil {
		return fmt.Errorf("resolve review output path %q: %w", path, err)
	}
	if err := writePrivateFile(resolvedPath, data); err != nil {
		return fmt.Errorf("write review output %q: %w", path, err)
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".witness-review-file-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	target, err := os.Lstat(path)
	if err == nil {
		if target.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse to write symlink target %q", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect write target %q: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}
