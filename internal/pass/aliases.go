package pass

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/diag"
)

type driverGeneratedOutput struct {
	role string
	path string
	dir  bool
}

type driverConfiguredInput struct {
	role                   string
	path                   string
	roleOutput             bool
	rejectsContainedOutput bool
}

func rejectDriverOutputAliases(config Config) error {
	outputs := driverGeneratedOutputs(config)
	inputs := driverConfiguredInputs(config)
	resolvedOutputs := make([]comparablePathInfo, len(outputs))
	for index, output := range outputs {
		if strings.TrimSpace(output.path) == "" {
			continue
		}
		resolved, err := comparablePath(output.path)
		if err != nil {
			return err
		}
		resolvedOutputs[index] = resolved
	}
	for _, input := range inputs {
		if strings.TrimSpace(input.path) == "" {
			continue
		}
		resolvedInput, err := comparablePath(input.path)
		if err != nil {
			return err
		}
		var resolvedRoleOutputDir comparablePathInfo
		if input.roleOutput {
			resolvedRoleOutputDir, err = comparablePath(roleOutputDir(config))
			if err != nil {
				return err
			}
			if !resolvedInput.isInside(resolvedRoleOutputDir) {
				return outputPathConflict(
					driverGeneratedOutput{role: "role-output-dir", path: roleOutputDir(config), dir: true},
					input,
					resolvedRoleOutputDir,
					"role-output path must be inside the dedicated role-output directory.",
				)
			}
		}
		for index, output := range outputs {
			if strings.TrimSpace(output.path) == "" {
				continue
			}
			resolvedOutput := resolvedOutputs[index]
			if resolvedOutput.conflictsWith(resolvedInput) {
				return outputPathConflict(output, input, resolvedOutput, "output path must not overwrite required inputs.")
			}
			if output.dir && !inputAllowedInsideGenerated(input, output, resolvedInput, resolvedRoleOutputDir) && resolvedInput.isInside(resolvedOutput) {
				return outputPathConflict(output, input, resolvedOutput, "configured input path must not be inside driver-generated output directories.")
			}
			if input.rejectsContainedOutput && resolvedOutput.isInside(resolvedInput) {
				return outputPathConflict(output, input, resolvedOutput, "output path must not be inside protected input directories.")
			}
		}
	}
	return nil
}

func inputAllowedInsideGenerated(input driverConfiguredInput, output driverGeneratedOutput, resolvedInput comparablePathInfo, resolvedRoleOutputDir comparablePathInfo) bool {
	if !input.roleOutput {
		return false
	}
	if !resolvedInput.isInside(resolvedRoleOutputDir) {
		return false
	}
	return output.role == "state-dir" || output.role == "role-output-dir"
}

func driverGeneratedOutputs(config Config) []driverGeneratedOutput {
	return []driverGeneratedOutput{
		{role: "state-dir", path: config.StateDir, dir: true},
		{role: "snapshot-dir", path: config.SnapshotDir, dir: true},
		{role: "role-output-dir", path: roleOutputDir(config), dir: true},
		{role: "pass-state", path: config.Outputs.StatePath},
		{role: "charter-freeze", path: config.Outputs.CharterFreezePath},
		{role: "source-snapshot-manifest", path: config.SnapshotManifestPath},
		{role: "preflight", path: config.Outputs.PreflightPath},
		{role: "verification-plan", path: config.Outputs.PlanPath},
		{role: "verification-manifest", path: config.Outputs.ManifestPath},
		{role: "verification-index-skeleton", path: filepath.Join(config.StateDir, "verification", "index.skeleton.json")},
		{role: "assemble-result", path: assembleResultPath(config)},
		{role: roleOutputChangeSurfaceRole, path: roleOutputChangeSurfacePath(config)},
		{role: "run-result", path: config.Outputs.RunResultPath},
		{role: "metrics", path: config.Outputs.MetricsPath},
		{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json")},
		{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json")},
		{role: "backend-status", path: filepath.Join(config.StateDir, "backend-status.json")},
		{role: "recipes-list", path: filepath.Join(config.StateDir, "recipes-list.json")},
		{role: "contract-digests", path: filepath.Join(config.StateDir, "contract-digests.json")},
		{role: "integration-bundle-retained", path: retainedIntegrationBundleEnvelopePath(config)},
		{role: "integration-bundle-body", path: retainedIntegrationBundleBodyPath(config)},
		{role: "compile-reports", path: filepath.Join(config.StateDir, "compile-reports"), dir: true},
		{role: "recipe-plans", path: filepath.Join(config.StateDir, "recipe-plans"), dir: true},
		{role: "verification-dir", path: filepath.Join(config.StateDir, "verification"), dir: true},
		{role: "verification-batches", path: filepath.Join(config.StateDir, "verification", "batches"), dir: true},
		{role: "verification-sessions", path: filepath.Join(config.StateDir, "verification", "sessions"), dir: true},
		{role: "change-surface", path: filepath.Join(config.StateDir, "verification", "change-surface.json")},
	}
}

func driverConfiguredInputs(config Config) []driverConfiguredInput {
	inputs := []driverConfiguredInput{
		{role: "charter", path: config.CharterPath},
		{role: "amendments", path: config.AmendmentsPath},
		{role: "source-dir", path: config.SourceDir, rejectsContainedOutput: true},
		{role: "integration-bundle", path: config.IntegrationBundlePath},
		{role: "policy", path: config.PolicyPath},
		{role: "rules", path: config.RulesPath},
		{role: "ledger", path: config.LedgerPath},
		{role: "base-manifest", path: config.BaseManifestPath},
		{role: "head-manifest", path: config.HeadManifestPath},
		{role: "prior-lineage", path: config.PriorLineagePath},
		{role: "receipt-output-dir", path: config.ReceiptOutputDir, rejectsContainedOutput: true},
		{role: "receipt-hmac-key-file", path: config.ReceiptHMACKeyFile},
	}
	for _, item := range config.RoleOutputs {
		inputs = append(inputs, driverConfiguredInput{role: "role-output:" + item.Role, path: item.Path, roleOutput: true})
	}
	for _, path := range config.ReceiptPaths {
		inputs = append(inputs, driverConfiguredInput{role: "receipt", path: path})
	}
	return inputs
}

func outputPathConflict(output driverGeneratedOutput, input driverConfiguredInput, resolvedOutput comparablePathInfo, message string) error {
	return diag.New(
		charter.CodeOutputPathConflict,
		message,
		diag.WithDetail("input_path", input.path),
		diag.WithDetail("input_role", input.role),
		diag.WithDetail("output_path", output.path),
		diag.WithDetail("output_role", output.role),
		diag.WithDetail("resolved_path", resolvedOutput.canonical),
	)
}

type comparablePathInfo struct {
	canonical string
	paths     []string
	info      os.FileInfo
}

func (left comparablePathInfo) conflictsWith(right comparablePathInfo) bool {
	if left.info != nil && right.info != nil && os.SameFile(left.info, right.info) {
		return true
	}
	for _, leftPath := range left.paths {
		for _, rightPath := range right.paths {
			if leftPath == rightPath {
				return true
			}
		}
	}
	return false
}

func (left comparablePathInfo) isInside(right comparablePathInfo) bool {
	for _, leftPath := range left.paths {
		for _, rightPath := range right.paths {
			if pathInside(leftPath, rightPath) {
				return true
			}
		}
	}
	return false
}

func pathInside(child string, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil || rel == "." || rel == "" {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func comparablePath(path string) (comparablePathInfo, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return comparablePathInfo{}, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	info, err := os.Stat(absolute)
	if err != nil && !os.IsNotExist(err) {
		return comparablePathInfo{}, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	canonical, err := comparablePathString(absolute)
	if err != nil {
		return comparablePathInfo{}, err
	}
	comparable := comparablePathInfo{
		canonical: canonical,
		paths:     uniqueComparablePaths(canonical, filepath.Clean(absolute)),
		info:      info,
	}
	if info == nil {
		target, ok, err := finalSymlinkTarget(absolute)
		if err != nil {
			return comparablePathInfo{}, err
		}
		if ok {
			comparable.paths = appendComparablePath(comparable.paths, target)
			resolvedTarget, err := comparablePathString(target)
			if err != nil {
				return comparablePathInfo{}, err
			}
			comparable.paths = appendComparablePath(comparable.paths, resolvedTarget)
		}
	}
	return comparable, nil
}

func uniqueComparablePaths(paths ...string) []string {
	var unique []string
	for _, path := range paths {
		unique = appendComparablePath(unique, path)
	}
	return unique
}

func appendComparablePath(paths []string, path string) []string {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return paths
	}
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func comparablePathString(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if os.IsNotExist(err) {
		return resolveThroughDeepestExistingAncestor(absolute, path)
	}
	return "", diag.Wrap(
		err,
		charter.CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", "resolve path"),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}

func resolveThroughDeepestExistingAncestor(absolute string, displayPath string) (string, error) {
	current := filepath.Clean(absolute)
	var remainder []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			parts := append([]string{resolved}, remainder...)
			return filepath.Join(parts...), nil
		}
		if !os.IsNotExist(err) {
			return "", diag.Wrap(
				err,
				charter.CodeFileIO,
				"file operation failed.",
				diag.WithDetail("action", "resolve path"),
				diag.WithDetail("path", displayPath),
				diag.WithDetail("error", err.Error()),
			)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return current, nil
		}
		remainder = append([]string{filepath.Base(current)}, remainder...)
		current = parent
	}
}

func finalSymlinkTarget(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", false, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target), true, nil
}
