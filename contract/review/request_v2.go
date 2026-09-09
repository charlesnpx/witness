package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// ReviewRequestV2 identifies the recipe-bound review request boundary.
	ReviewRequestV2 = "review-request-v2"

	// ReviewRecipeDigestProfile identifies the semantic canonical-JSON digest
	// profile used for the frozen recipe bytes in a v2 request.
	ReviewRecipeDigestProfile = digest.Profile
)

// ReviewRecipe is the frozen, named instruction set a v2 review request gives
// to its reviewers. It is invalid when its ID or instructions are blank, when
// required outputs are absent, duplicated, or malformed, or when policy is
// not a JSON object.
type ReviewRecipe struct {
	// RecipeID is an open recipe identifier; it is invalid when it is not a
	// stable identifier.
	RecipeID string `json:"recipe_id"`
	// Instructions are the reviewer instructions frozen into the request; they
	// are invalid when blank.
	Instructions string `json:"instructions"`
	// RequiredOutputs names the reviewer identifiers whose reports the recipe
	// requires; it is invalid when nil, empty, duplicated, or malformed.
	RequiredOutputs []string `json:"required_outputs"`
	// Policy is the recipe's JSON-object policy. Its keys are deliberately open
	// so adding a policy does not require a contract-package code change; it is
	// invalid when nil or when the wire value is not an object.
	Policy map[string]any `json:"policy"`
}

// ReviewRequestV2Document binds a consumer, exact source, frozen Charter and
// input digest to the exact recipe bytes, adapter, and reviewer reports that
// were requested. It is invalid when any binding is malformed, when the
// recipe digest does not match its bytes, or when request and recipe output
// lists disagree.
type ReviewRequestV2Document struct {
	// SchemaVersion identifies this document as review-request-v2; any other
	// value is invalid.
	SchemaVersion string `json:"schema_version"`
	// ConsumerIdentity identifies the program that asked for the review; both
	// identity components must be non-empty, and no consumer enum is allowed.
	ConsumerIdentity Identity `json:"consumer_identity"`
	// Subject is the v1 source-revision shape; its head is required and present
	// optional labels must be non-empty.
	Subject RequestSubject `json:"subject"`
	// CharterHash is the frozen Charter digest; it is invalid unless it has the
	// relay-root-digests-v1 sha256 syntax.
	CharterHash string `json:"charter_hash"`
	// ReviewInputDigest is the exact reviewer-input digest; it is invalid unless
	// it has the relay-root-digests-v1 sha256 syntax.
	ReviewInputDigest string `json:"review_input_digest"`
	// FrozenRecipe contains the recipe JSON bytes given to reviewers; it is
	// invalid when it is absent, not a valid ReviewRecipe object, or does not
	// agree with RecipeDigest.
	FrozenRecipe json.RawMessage `json:"frozen_recipe"`
	// RecipeDigest is the semantic canonical-JSON digest of FrozenRecipe; it is
	// invalid when malformed or different from the frozen recipe's digest.
	RecipeDigest string `json:"recipe_digest"`
	// Adapter identifies the implementation asked to run the recipe; it is an
	// open stable identifier and is invalid when blank or malformed.
	Adapter string `json:"adapter"`
	// RequiredOutputs names every reviewer report required for satisfaction; it
	// is invalid when nil, empty, duplicated, malformed, or different from the
	// recipe's required_outputs set.
	RequiredOutputs []string `json:"required_outputs"`
}

func (recipe *ReviewRecipe) UnmarshalJSON(data []byte) error {
	type alias ReviewRecipe
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"recipe_id", "instructions", "required_outputs", "policy"} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*recipe = ReviewRecipe(decoded)
	return nil
}

func (document *ReviewRequestV2Document) UnmarshalJSON(data []byte) error {
	type alias ReviewRequestV2Document
	var decoded alias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{
		"schema_version",
		"consumer_identity",
		"subject",
		"charter_hash",
		"review_input_digest",
		"frozen_recipe",
		"recipe_digest",
		"adapter",
		"required_outputs",
	} {
		if err := rejectRequiredJSONNull(fields, field); err != nil {
			return err
		}
	}
	*document = ReviewRequestV2Document(decoded)
	return nil
}

// DecodeAndValidateReviewRequestV2 strictly decodes data and validates the
// recipe-bound request before returning it. Decode errors are returned through
// the strict JSON reader; document violations are returned as diagnostics.
func DecodeAndValidateReviewRequestV2(data []byte) (ReviewRequestV2Document, error) {
	document, err := strictjson.DecodeBytes[ReviewRequestV2Document](data, strictjson.DefaultMaxBytes)
	if err != nil {
		return ReviewRequestV2Document{}, err
	}
	if err := RequireValidReviewRequestV2(document); err != nil {
		return ReviewRequestV2Document{}, err
	}
	return document, nil
}

// RequireValidReviewRequestV2 returns an aggregated validation error when a
// recipe-bound request does not satisfy its document boundary.
func RequireValidReviewRequestV2(document ReviewRequestV2Document) error {
	return ErrorFromDiagnostics(ValidateReviewRequestV2(document))
}

// ValidateReviewRequestV2 returns every structural and semantic violation in a
// review-request-v2 document, including a mismatch between frozen recipe bytes
// and their digest.
func ValidateReviewRequestV2(document ReviewRequestV2Document) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != ReviewRequestV2 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"review request schema_version must be review-request-v2.",
			"/schema_version",
			map[string]any{"expected": ReviewRequestV2, "actual": document.SchemaVersion},
		))
	}
	validateReviewIdentity(&diagnostics, "/consumer_identity", "consumer_identity", document.ConsumerIdentity, CodeInvalidReviewRequest)
	validateV2RequestSubject(&diagnostics, document.Subject)
	RequireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	RequireDigest(&diagnostics, "/review_input_digest", "review_input_digest", document.ReviewInputDigest)
	RequireStableID(&diagnostics, "/adapter", "adapter", document.Adapter)
	validateRequiredReviewerIDs(&diagnostics, "/required_outputs", document.RequiredOutputs, "required output reviewer ID")

	var recipe ReviewRecipe
	recipeValid := false
	if len(bytes.TrimSpace(document.FrozenRecipe)) == 0 {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"frozen_recipe is required and must contain a ReviewRecipe object.",
			"/frozen_recipe",
			nil,
		))
	} else {
		decoded, err := strictjson.DecodeBytes[ReviewRecipe](document.FrozenRecipe, strictjson.DefaultMaxBytes)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewRequest,
				"frozen_recipe must be a strictly valid ReviewRecipe object.",
				"/frozen_recipe",
				map[string]any{"error": err.Error()},
			))
		} else {
			recipe = decoded
			recipeValid = true
			diagnostics = append(diagnostics, validateReviewRecipe(recipe, "/frozen_recipe")...)
		}
	}

	RequireDigest(&diagnostics, "/recipe_digest", "recipe_digest", document.RecipeDigest)
	if recipeValid {
		if expected, err := ReviewRecipeDigest(document.FrozenRecipe); err != nil {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewRequest,
				"frozen_recipe digest could not be computed.",
				"/frozen_recipe",
				map[string]any{"error": err.Error()},
			))
		} else {
			CompareDigest(&diagnostics, "/recipe_digest", "frozen recipe", document.RecipeDigest, expected)
		}
		if !sameReviewerIDSet(document.RequiredOutputs, recipe.RequiredOutputs) {
			diagnostics = append(diagnostics, Diagnostic(
				CodeInvalidReviewRequest,
				"required_outputs must name the same reviewers as frozen_recipe.required_outputs.",
				"/required_outputs",
				map[string]any{"request": document.RequiredOutputs, "recipe": recipe.RequiredOutputs},
			))
		}
	}
	return diagnostics
}

// ReviewRequestV2Recipe decodes the frozen recipe after the request has been
// decoded. It returns an error when the bytes do not contain a strict recipe
// object; callers that need diagnostics should use ValidateReviewRequestV2.
func ReviewRequestV2Recipe(document ReviewRequestV2Document) (ReviewRecipe, error) {
	return strictjson.DecodeBytes[ReviewRecipe](document.FrozenRecipe, strictjson.DefaultMaxBytes)
}

// ReviewRecipeDigest returns the semantic canonical-JSON digest of recipe
// bytes. Formatting differences do not change this digest, while the request
// still retains the original bytes for the reviewers.
func ReviewRecipeDigest(recipe []byte) (string, error) {
	if len(bytes.TrimSpace(recipe)) == 0 {
		return "", fmt.Errorf("recipe bytes are required")
	}
	return digest.SemanticJSONBytes(recipe)
}

// ReviewRecipeCanonicalBytes returns the canonical JSON form of a typed recipe
// for callers constructing frozen recipe bytes before putting them in a
// request.
func ReviewRecipeCanonicalBytes(recipe ReviewRecipe) ([]byte, error) {
	return canonjson.Marshal(recipe)
}

// ReviewRequestV2Digest returns the canonical semantic JSON digest of a valid
// or invalid request. The digest has no self-referential field.
func ReviewRequestV2Digest(document ReviewRequestV2Document) (string, error) {
	return digest.SemanticJSON(document)
}

func validateReviewRecipe(recipe ReviewRecipe, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	RequireStableID(&diagnostics, path+"/recipe_id", "recipe ID", recipe.RecipeID)
	RequireString(&diagnostics, path+"/instructions", "recipe instructions", recipe.Instructions)
	validateRequiredReviewerIDs(&diagnostics, path+"/required_outputs", recipe.RequiredOutputs, "recipe required output reviewer ID")
	if recipe.Policy == nil {
		diagnostics = append(diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"recipe policy is required and must be a JSON object.",
			path+"/policy",
			nil,
		))
	}
	return diagnostics
}

func validateRequiredReviewerIDs(diagnostics *[]diag.Diagnostic, path string, values []string, label string) {
	if values == nil {
		*diagnostics = append(*diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"required outputs must be an array; use at least one reviewer identifier.",
			path,
			nil,
		))
		return
	}
	if len(values) == 0 {
		*diagnostics = append(*diagnostics, Diagnostic(
			CodeInvalidReviewRequest,
			"required outputs must name at least one reviewer identifier.",
			path,
			nil,
		))
	}
	seen := map[string]int{}
	for index, value := range values {
		itemPath := path + "/" + itoa(index)
		RequireStableID(diagnostics, itemPath, label, value)
		if first, exists := seen[value]; exists {
			*diagnostics = append(*diagnostics, Diagnostic(
				CodeInvalidReviewRequest,
				"required output reviewer identifiers must be unique.",
				itemPath,
				map[string]any{"duplicate_of": path + "/" + itoa(first)},
			))
		}
		seen[value] = index
	}
}

func validateV2RequestSubject(diagnostics *[]diag.Diagnostic, subject RequestSubject) {
	if strings.TrimSpace(subject.Head) == "" {
		*diagnostics = append(*diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject head is required.", "/subject/head", nil))
	}
	if (subject.treePresent || subject.Tree != "") && strings.TrimSpace(subject.Tree) == "" {
		*diagnostics = append(*diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject tree must be non-empty when present.", "/subject/tree", nil))
	}
	if (subject.branchPresent || subject.Branch != "") && strings.TrimSpace(subject.Branch) == "" {
		*diagnostics = append(*diagnostics, Diagnostic(CodeInvalidReviewRequest, "subject branch must be non-empty when present.", "/subject/branch", nil))
	}
}

func sameReviewerIDSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := make(map[string]struct{}, len(left))
	for _, value := range left {
		leftSet[value] = struct{}{}
	}
	if len(leftSet) != len(left) {
		return false
	}
	for _, value := range right {
		if _, exists := leftSet[value]; !exists {
			return false
		}
	}
	return true
}
