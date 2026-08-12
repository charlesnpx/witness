package freeze

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	RefObservationSchemaVersion = "witness-ref-observation-v1"
	RefDriftSchemaVersion       = "witness-ref-drift-v1"

	RefObservationAvailable   = "available"
	RefObservationUnavailable = "unavailable"

	RefHeadAttached = "attached"
	RefHeadDetached = "detached"

	RefDriftFresh       = "fresh"
	RefDriftDrifted     = "drifted"
	RefDriftUnavailable = "unavailable"
)

// RefObservation is a point-in-time record of local Git refs. It is kept out
// of Manifest because mutable branch pointers are not immutable source content.
type RefObservation struct {
	SchemaVersion string      `json:"schema_version"`
	Status        string      `json:"status"`
	Reason        string      `json:"reason,omitempty"`
	SourcePath    string      `json:"source_path,omitempty"`
	GitRoot       string      `json:"git_root,omitempty"`
	Head          string      `json:"head,omitempty"`
	HeadState     string      `json:"head_state,omitempty"`
	CurrentBranch string      `json:"current_branch,omitempty"`
	Branches      []BranchRef `json:"branches"`
}

type BranchRef struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

// RefDrift is a non-fatal ref freshness fact. Unavailable is deliberately
// stale so downstream consumers cannot mistake unknown for green.
type RefDrift struct {
	SchemaVersion  string         `json:"schema_version"`
	Classification string         `json:"classification"`
	Stale          bool           `json:"stale"`
	Reason         string         `json:"reason,omitempty"`
	Frozen         RefObservation `json:"frozen"`
	Live           RefObservation `json:"live"`
	Changes        []RefChange    `json:"changes,omitempty"`
}

type RefChange struct {
	Kind         string `json:"kind"`
	Name         string `json:"name,omitempty"`
	FrozenCommit string `json:"frozen_commit,omitempty"`
	LiveCommit   string `json:"live_commit,omitempty"`
	FrozenValue  string `json:"frozen_value,omitempty"`
	LiveValue    string `json:"live_value,omitempty"`
}

func CaptureRefObservation(ctx context.Context, sourceDir string) (RefObservation, error) {
	sourcePath, err := canonicalPath(sourceDir)
	if err != nil {
		return RefObservation{}, err
	}
	observation := UnavailableRefObservation(sourcePath, "source_not_git")
	root, err := gitOutput(ctx, sourcePath, "rev-parse", "--show-toplevel")
	if err != nil {
		return observation, nil
	}
	if resolved, err := canonicalPath(strings.TrimSpace(root)); err == nil {
		root = resolved
	}
	head, err := gitOutput(ctx, sourcePath, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		observation.Reason = "git_head_unavailable"
		return observation, nil
	}
	currentBranch, err := gitOutput(ctx, sourcePath, "branch", "--show-current")
	if err != nil {
		observation.Reason = "git_current_branch_unavailable"
		return observation, nil
	}
	branches, err := localBranchRefs(ctx, sourcePath)
	if err != nil {
		observation.Reason = "git_branch_refs_unavailable"
		return observation, nil
	}
	observation.Status = RefObservationAvailable
	observation.Reason = ""
	observation.GitRoot = strings.TrimSpace(root)
	observation.Head = strings.TrimSpace(head)
	observation.CurrentBranch = strings.TrimSpace(currentBranch)
	observation.Branches = branches
	if observation.CurrentBranch == "" {
		observation.HeadState = RefHeadDetached
	} else {
		observation.HeadState = RefHeadAttached
	}
	return observation, nil
}

func UnavailableRefObservation(sourceDir string, reason string) RefObservation {
	sourcePath := strings.TrimSpace(sourceDir)
	if sourcePath != "" {
		if absolute, err := filepath.Abs(sourcePath); err == nil {
			sourcePath = filepath.Clean(absolute)
		}
	}
	return RefObservation{
		SchemaVersion: RefObservationSchemaVersion,
		Status:        RefObservationUnavailable,
		Reason:        reason,
		SourcePath:    sourcePath,
		Branches:      []BranchRef{},
	}
}

func localBranchRefs(ctx context.Context, sourcePath string) ([]BranchRef, error) {
	output, err := gitOutput(ctx, sourcePath, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	branches := make([]BranchRef, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("git for-each-ref output has an invalid branch record")
		}
		branches = append(branches, BranchRef{Name: parts[0], Commit: parts[1]})
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].Name < branches[j].Name })
	return branches, nil
}

func CompareRefObservation(ctx context.Context, frozen RefObservation) RefDrift {
	if err := ValidateRefObservation(frozen); err != nil {
		return UnavailableRefDrift(frozen, "invalid_frozen_observation")
	}
	live, err := CaptureRefObservation(ctx, frozen.SourcePath)
	if err != nil {
		return UnavailableRefDrift(frozen, "live_observation_unavailable")
	}
	if frozen.Status != RefObservationAvailable {
		return unavailableRefDrift(frozen, live, nonEmptyReason(frozen.Reason, "frozen_observation_unavailable"))
	}
	if live.Status != RefObservationAvailable {
		return unavailableRefDrift(frozen, live, nonEmptyReason(live.Reason, "live_observation_unavailable"))
	}
	changes := compareAvailableRefs(frozen, live)
	if len(changes) == 0 {
		return RefDrift{SchemaVersion: RefDriftSchemaVersion, Classification: RefDriftFresh, Frozen: frozen, Live: live}
	}
	return RefDrift{SchemaVersion: RefDriftSchemaVersion, Classification: RefDriftDrifted, Stale: true, Reason: "local_refs_changed", Frozen: frozen, Live: live, Changes: changes}
}

func UnavailableRefDrift(frozen RefObservation, reason string) RefDrift {
	return unavailableRefDrift(frozen, UnavailableRefObservation(frozen.SourcePath, reason), reason)
}

func unavailableRefDrift(frozen RefObservation, live RefObservation, reason string) RefDrift {
	return RefDrift{SchemaVersion: RefDriftSchemaVersion, Classification: RefDriftUnavailable, Stale: true, Reason: reason, Frozen: frozen, Live: live}
}

func compareAvailableRefs(frozen RefObservation, live RefObservation) []RefChange {
	var changes []RefChange
	frozenBranches := branchMap(frozen.Branches)
	liveBranches := branchMap(live.Branches)
	for _, name := range sortedBranchNames(frozenBranches) {
		if frozenBranches[name] != liveBranches[name] {
			changes = append(changes, RefChange{Kind: "branch", Name: name, FrozenCommit: frozenBranches[name], LiveCommit: liveBranches[name]})
		}
	}
	if frozen.Head != live.Head {
		changes = append(changes, RefChange{Kind: "head", FrozenCommit: frozen.Head, LiveCommit: live.Head})
	}
	if frozen.HeadState != live.HeadState || frozen.CurrentBranch != live.CurrentBranch {
		changes = append(changes, RefChange{Kind: "head_state", FrozenValue: frozen.HeadState + ":" + frozen.CurrentBranch, LiveValue: live.HeadState + ":" + live.CurrentBranch})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Name < changes[j].Name
	})
	return changes
}

func branchMap(branches []BranchRef) map[string]string {
	values := make(map[string]string, len(branches))
	for _, branch := range branches {
		values[branch.Name] = branch.Commit
	}
	return values
}

func sortedBranchNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ValidateRefObservation(observation RefObservation) error {
	if observation.SchemaVersion != RefObservationSchemaVersion {
		return fmt.Errorf("unsupported ref observation schema_version %q", observation.SchemaVersion)
	}
	switch observation.Status {
	case RefObservationUnavailable:
		if strings.TrimSpace(observation.Reason) == "" {
			return fmt.Errorf("unavailable ref observation is missing a reason")
		}
		return nil
	case RefObservationAvailable:
		if strings.TrimSpace(observation.SourcePath) == "" || strings.TrimSpace(observation.GitRoot) == "" || strings.TrimSpace(observation.Head) == "" {
			return fmt.Errorf("available ref observation is missing source identity")
		}
		if observation.HeadState == RefHeadAttached && strings.TrimSpace(observation.CurrentBranch) == "" {
			return fmt.Errorf("attached ref observation is missing current_branch")
		}
		if observation.HeadState == RefHeadDetached && observation.CurrentBranch != "" {
			return fmt.Errorf("detached ref observation must not record current_branch")
		}
		if observation.HeadState != RefHeadAttached && observation.HeadState != RefHeadDetached {
			return fmt.Errorf("available ref observation has invalid head_state %q", observation.HeadState)
		}
		last := ""
		for _, branch := range observation.Branches {
			if strings.TrimSpace(branch.Name) == "" || strings.TrimSpace(branch.Commit) == "" || (last != "" && branch.Name <= last) {
				return fmt.Errorf("available ref observation has invalid branches")
			}
			last = branch.Name
		}
		return nil
	default:
		return fmt.Errorf("invalid ref observation status %q", observation.Status)
	}
}

func ValidateRefDrift(status RefDrift) error {
	if status.SchemaVersion != RefDriftSchemaVersion {
		return fmt.Errorf("unsupported ref drift schema_version %q", status.SchemaVersion)
	}
	if err := ValidateRefObservation(status.Frozen); err != nil {
		return err
	}
	if err := ValidateRefObservation(status.Live); err != nil {
		return err
	}
	switch status.Classification {
	case RefDriftFresh:
		if status.Stale || len(status.Changes) != 0 {
			return fmt.Errorf("fresh ref drift status is inconsistent")
		}
	case RefDriftDrifted:
		if !status.Stale || len(status.Changes) == 0 {
			return fmt.Errorf("drifted ref status is inconsistent")
		}
	case RefDriftUnavailable:
		if !status.Stale || strings.TrimSpace(status.Reason) == "" {
			return fmt.Errorf("unavailable ref drift status is inconsistent")
		}
	default:
		return fmt.Errorf("invalid ref drift classification %q", status.Classification)
	}
	return nil
}

func nonEmptyReason(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
