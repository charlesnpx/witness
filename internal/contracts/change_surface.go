package contracts

import (
	"path/filepath"
	"strings"

	"github.com/charlesnpx/witness/internal/changesurface"
)

func FindingInChangeSurface(finding Finding, surface changesurface.Document) bool {
	changed := changesurface.ChangedPathSet(surface)
	for _, anchor := range finding.ScopeAnchors {
		if anchorTouchesChangedPath(anchor, changed) {
			return true
		}
	}
	if finding.Witness.EntryPoint != nil && anchorTouchesChangedPath(*finding.Witness.EntryPoint, changed) {
		return true
	}
	for _, anchor := range finding.Witness.ReachabilityChain {
		if anchorTouchesChangedPath(anchor, changed) {
			return true
		}
	}
	for _, ref := range finding.Witness.ArtifactRefs {
		if artifactRefTouchesChangedPath(ref, changed) {
			return true
		}
	}
	if finding.Witness.Executable != nil && finding.Witness.Executable.TransformationRef != nil {
		if artifactRefTouchesChangedPath(*finding.Witness.Executable.TransformationRef, changed) {
			return true
		}
	}
	return false
}

func anchorTouchesChangedPath(anchor ScopeAnchor, changed map[string]struct{}) bool {
	for _, candidate := range []string{
		anchor.EntryID,
		anchor.Property,
		anchor.Value,
		anchor.AffectedDecision,
	} {
		if changedPathContains(changed, candidate) {
			return true
		}
	}
	return false
}

func artifactRefTouchesChangedPath(ref ArtifactRef, changed map[string]struct{}) bool {
	for _, candidate := range []string{ref.ID, ref.Kind} {
		if changedPathContains(changed, candidate) {
			return true
		}
	}
	return false
}

func changedPathContains(changed map[string]struct{}, candidate string) bool {
	normalized, ok := normalizeChangedPathCandidate(candidate)
	if !ok {
		return false
	}
	_, exists := changed[normalized]
	return exists
}

func normalizeChangedPathCandidate(candidate string) (string, bool) {
	value := filepath.ToSlash(strings.TrimSpace(candidate))
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\x00") {
		return "", false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return value, true
}
