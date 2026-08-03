package changesurface

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/freeze"
)

const (
	SchemaVersion = "witness-change-surface-v1"

	ChangeKindAdded       = "added"
	ChangeKindModified    = "modified"
	ChangeKindRemoved     = "removed"
	ChangeKindModeChanged = "mode_changed"

	ScopePolicyDeltaObligating = "delta_obligating"
	ScopePolicyWholeTree       = "whole_tree"

	BaselinePassReasonExplicit = "explicit_baseline_pass"

	CodeInvalidManifest           = "change_surface_invalid_manifest"
	CodeHeadArtifactMismatch      = "change_surface_head_artifact_mismatch"
	CodeInvalidChangeSurface      = "invalid_change_surface"
	CodeMissingDerivationManifest = "change_surface_missing_derivation_manifest"
)

type Document struct {
	SchemaVersion      string       `json:"schema_version"`
	DigestProfile      string       `json:"digest_profile"`
	BaseArtifactDigest string       `json:"base_artifact_digest"`
	HeadArtifactDigest string       `json:"head_artifact_digest"`
	ChangedPaths       []PathChange `json:"changed_paths"`
}

type PathChange struct {
	Path        string   `json:"path"`
	ChangeKinds []string `json:"change_kinds"`
}

type BaselinePass struct {
	Declared bool   `json:"declared"`
	Reason   string `json:"reason"`
}

func Derive(base freeze.Manifest, head freeze.Manifest, passArtifactDigest string) (Document, string, error) {
	baseDigest, err := manifestDigest(base, "base")
	if err != nil {
		return Document{}, "", err
	}
	headDigest, err := manifestDigest(head, "head")
	if err != nil {
		return Document{}, "", err
	}
	if strings.TrimSpace(passArtifactDigest) == "" || headDigest != strings.TrimSpace(passArtifactDigest) {
		return Document{}, "", diag.New(
			CodeHeadArtifactMismatch,
			"head freeze manifest digest must match the authoritative pass artifact digest.",
			diag.WithPath("/head_artifact_digest"),
			diag.WithDetail("actual", headDigest),
			diag.WithDetail("expected", strings.TrimSpace(passArtifactDigest)),
		)
	}
	document := Document{
		SchemaVersion:      SchemaVersion,
		DigestProfile:      digest.Profile,
		BaseArtifactDigest: baseDigest,
		HeadArtifactDigest: headDigest,
		ChangedPaths:       deriveChangedPaths(base.Files, head.Files),
	}
	documentDigest, err := Digest(document)
	if err != nil {
		return Document{}, "", err
	}
	return document, documentDigest, nil
}

func Digest(document Document) (string, error) {
	if diagnostics := Validate(document); len(diagnostics) > 0 {
		return "", &ValidationError{Diagnostics: diagnostics}
	}
	return digest.SemanticJSON(document)
}

func CanonicalBytes(document Document) ([]byte, error) {
	if diagnostics := Validate(document); len(diagnostics) > 0 {
		return nil, &ValidationError{Diagnostics: diagnostics}
	}
	return canonjson.Marshal(document)
}

func ChangedPathSet(document Document) map[string]struct{} {
	paths := make(map[string]struct{}, len(document.ChangedPaths))
	for _, change := range document.ChangedPaths {
		paths[change.Path] = struct{}{}
	}
	return paths
}

func ValidateDeclaredDerivation(document Document, declaredDigest string, base *freeze.Manifest, head *freeze.Manifest, passArtifactDigest string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if base == nil || head == nil {
		return []diag.Diagnostic{diagnostic(
			CodeMissingDerivationManifest,
			"declared change surface requires base and head freeze manifests for derivation verification.",
			"",
			map[string]any{"base_manifest": base != nil, "head_manifest": head != nil},
		)}
	}
	derived, derivedDigest, err := Derive(*base, *head, passArtifactDigest)
	if err != nil {
		return []diag.Diagnostic{diag.FromError(err)}
	}
	if derived.BaseArtifactDigest != document.BaseArtifactDigest {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidChangeSurface,
			"base freeze manifest digest does not match the declared change surface base_artifact_digest.",
			"/base_artifact_digest",
			map[string]any{"actual": derived.BaseArtifactDigest, "expected": document.BaseArtifactDigest},
		))
	}
	if derived.HeadArtifactDigest != document.HeadArtifactDigest {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidChangeSurface,
			"head freeze manifest digest does not match the declared change surface head_artifact_digest.",
			"/head_artifact_digest",
			map[string]any{"actual": derived.HeadArtifactDigest, "expected": document.HeadArtifactDigest},
		))
	}
	actualDigest, err := Digest(document)
	if err != nil {
		if validation, ok := err.(*ValidationError); ok {
			diagnostics = append(diagnostics, validation.Diagnostics...)
		} else {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "declared change surface digest could not be computed.", "/change_surface_digest", map[string]any{"error": err.Error()}))
		}
		return diagnostics
	}
	if strings.TrimSpace(declaredDigest) != actualDigest {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidChangeSurface,
			"declared change_surface_digest does not match the embedded change surface.",
			"/change_surface_digest",
			map[string]any{"actual": actualDigest, "expected": strings.TrimSpace(declaredDigest)},
		))
	}
	if actualDigest != derivedDigest {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidChangeSurface,
			"declared change surface digest does not match the surface derived from base and head manifests.",
			"/change_surface_digest",
			map[string]any{"actual": actualDigest, "expected": derivedDigest},
		))
	}
	declaredBytes, declaredErr := CanonicalBytes(document)
	derivedBytes, derivedErr := CanonicalBytes(derived)
	if declaredErr != nil || derivedErr != nil {
		if declaredErr != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "declared change surface canonical bytes could not be computed.", "", map[string]any{"error": declaredErr.Error()}))
		}
		if derivedErr != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "derived change surface canonical bytes could not be computed.", "", map[string]any{"error": derivedErr.Error()}))
		}
		return diagnostics
	}
	if !bytes.Equal(declaredBytes, derivedBytes) {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidChangeSurface,
			"declared change surface bytes do not match the surface derived from base and head manifests.",
			"",
			map[string]any{"actual_digest": actualDigest, "expected_digest": derivedDigest},
		))
	}
	return diagnostics
}

func ScopePolicy(value string) string {
	switch strings.TrimSpace(value) {
	case ScopePolicyDeltaObligating:
		return ScopePolicyDeltaObligating
	default:
		return ScopePolicyWholeTree
	}
}

func ValidateScopePolicy(value string) bool {
	switch strings.TrimSpace(value) {
	case "", ScopePolicyDeltaObligating, ScopePolicyWholeTree:
		return true
	default:
		return false
	}
}

func Validate(document Document) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != SchemaVersion {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "change surface schema_version is unsupported.", "/schema_version", map[string]any{"actual": document.SchemaVersion, "expected": SchemaVersion}))
	}
	if document.DigestProfile != digest.Profile {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "change surface digest_profile is unsupported.", "/digest_profile", map[string]any{"actual": document.DigestProfile, "expected": digest.Profile}))
	}
	requireDigest(&diagnostics, "/base_artifact_digest", "base artifact digest", document.BaseArtifactDigest)
	requireDigest(&diagnostics, "/head_artifact_digest", "head artifact digest", document.HeadArtifactDigest)
	seen := map[string]int{}
	for index, change := range document.ChangedPaths {
		path := "/changed_paths/" + itoa(index)
		if err := validatePath(change.Path); err != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "changed path is not a safe relative path.", path+"/path", map[string]any{"path": change.Path}))
		}
		if first, exists := seen[change.Path]; exists {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "changed paths must be unique.", path+"/path", map[string]any{"path": change.Path, "duplicate_of": "/changed_paths/" + itoa(first) + "/path"}))
		}
		seen[change.Path] = index
		if len(change.ChangeKinds) == 0 {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "changed path requires at least one change kind.", path+"/change_kinds", nil))
			continue
		}
		for kindIndex, kind := range change.ChangeKinds {
			if !validChangeKind(kind) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "change kind is unsupported.", path+"/change_kinds/"+itoa(kindIndex), map[string]any{"kind": kind}))
			}
			if kindIndex > 0 && changeKindRank(change.ChangeKinds[kindIndex-1]) >= changeKindRank(kind) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "change kinds must be unique and sorted.", path+"/change_kinds", map[string]any{"change_kinds": change.ChangeKinds}))
			}
		}
		if index > 0 && document.ChangedPaths[index-1].Path >= change.Path {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidChangeSurface, "changed paths must be unique and sorted.", "/changed_paths", nil))
		}
	}
	return diagnostics
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "change surface validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

func manifestDigest(manifest freeze.Manifest, label string) (string, error) {
	if manifest.SchemaVersion != freeze.SchemaVersion {
		return "", diag.New(
			CodeInvalidManifest,
			label+" freeze manifest schema_version is unsupported.",
			diag.WithPath("/"+label+"/schema_version"),
			diag.WithDetail("actual", manifest.SchemaVersion),
			diag.WithDetail("expected", freeze.SchemaVersion),
		)
	}
	if manifest.DigestProfile != digest.Profile {
		return "", diag.New(
			CodeInvalidManifest,
			label+" freeze manifest digest_profile is unsupported.",
			diag.WithPath("/"+label+"/digest_profile"),
			diag.WithDetail("actual", manifest.DigestProfile),
			diag.WithDetail("expected", digest.Profile),
		)
	}
	value, err := freeze.ManifestDigest(manifest)
	if err != nil {
		return "", diag.Wrap(err, CodeInvalidManifest, label+" freeze manifest digest could not be computed.")
	}
	return value, nil
}

func deriveChangedPaths(baseFiles []freeze.FileEntry, headFiles []freeze.FileEntry) []PathChange {
	base := indexFiles(baseFiles)
	head := indexFiles(headFiles)
	pathSet := map[string]struct{}{}
	for path := range base {
		pathSet[path] = struct{}{}
	}
	for path := range head {
		pathSet[path] = struct{}{}
	}
	paths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	changes := make([]PathChange, 0, len(paths))
	for _, path := range paths {
		baseEntry, inBase := base[path]
		headEntry, inHead := head[path]
		switch {
		case !inBase && inHead:
			changes = append(changes, PathChange{Path: path, ChangeKinds: []string{ChangeKindAdded}})
		case inBase && !inHead:
			changes = append(changes, PathChange{Path: path, ChangeKinds: []string{ChangeKindRemoved}})
		default:
			var kinds []string
			if baseEntry.Digest != headEntry.Digest {
				kinds = append(kinds, ChangeKindModified)
			}
			if baseEntry.Mode != headEntry.Mode {
				kinds = append(kinds, ChangeKindModeChanged)
			}
			if len(kinds) > 0 {
				changes = append(changes, PathChange{Path: path, ChangeKinds: kinds})
			}
		}
	}
	return changes
}

func indexFiles(files []freeze.FileEntry) map[string]freeze.FileEntry {
	index := make(map[string]freeze.FileEntry, len(files))
	for _, file := range files {
		index[file.Path] = file
	}
	return index
}

func validChangeKind(kind string) bool {
	switch kind {
	case ChangeKindAdded, ChangeKindModified, ChangeKindRemoved, ChangeKindModeChanged:
		return true
	default:
		return false
	}
}

func changeKindRank(kind string) int {
	switch kind {
	case ChangeKindAdded:
		return 0
	case ChangeKindModified:
		return 1
	case ChangeKindModeChanged:
		return 2
	case ChangeKindRemoved:
		return 3
	default:
		return 100
	}
}

func validatePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return fmt.Errorf("unsafe path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe path")
		}
	}
	return nil
}

func requireDigest(diagnostics *[]diag.Diagnostic, path string, field string, value string) {
	if !validDigest(value) {
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidChangeSurface, field+" must be a relay-root-digests-v1 sha256 digest.", path, map[string]any{"value": value}))
	}
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, digest.Prefix) {
		return false
	}
	hex := strings.TrimPrefix(value, digest.Prefix)
	if len(hex) != 64 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Message: message, Path: path, Details: details}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
