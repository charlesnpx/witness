package pass

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/harness"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/preflight"
)

func applyOutputDefaults(config *Config) {
	if config == nil || strings.TrimSpace(config.StateDir) == "" {
		return
	}
	if strings.TrimSpace(config.SnapshotDir) == "" {
		config.SnapshotDir = filepath.Join(config.StateDir, "source-snapshot")
	}
	if strings.TrimSpace(config.SnapshotManifestPath) == "" {
		config.SnapshotManifestPath = filepath.Join(config.SnapshotDir, "manifest.json")
	}
	if strings.TrimSpace(config.Outputs.StatePath) == "" {
		config.Outputs.StatePath = filepath.Join(config.StateDir, StateFileName)
	}
	if strings.TrimSpace(config.Outputs.CharterFreezePath) == "" {
		config.Outputs.CharterFreezePath = filepath.Join(config.StateDir, "charter.freeze.json")
	}
	if strings.TrimSpace(config.Outputs.PreflightPath) == "" {
		config.Outputs.PreflightPath = filepath.Join(config.StateDir, "preflight.json")
	}
	if strings.TrimSpace(config.Outputs.PlanPath) == "" {
		config.Outputs.PlanPath = filepath.Join(config.StateDir, "verification-plan.json")
	}
	if strings.TrimSpace(config.Outputs.ManifestPath) == "" {
		config.Outputs.ManifestPath = filepath.Join(config.StateDir, "verification", "index.json")
	}
	if strings.TrimSpace(config.Outputs.AssembleResultPath) == "" {
		config.Outputs.AssembleResultPath = assembleResultPath(*config)
	}
	if strings.TrimSpace(config.Outputs.RoleOutputChangeSurfacePath) == "" {
		config.Outputs.RoleOutputChangeSurfacePath = roleOutputChangeSurfacePath(*config)
	}
	if strings.TrimSpace(config.Outputs.RunResultPath) == "" {
		config.Outputs.RunResultPath = filepath.Join(config.StateDir, "verdict.json")
	}
	if strings.TrimSpace(config.Outputs.MetricsPath) == "" {
		config.Outputs.MetricsPath = filepath.Join(config.StateDir, "metrics.json")
	}
}

func assembleResultPath(config Config) string {
	if strings.TrimSpace(config.Outputs.AssembleResultPath) != "" {
		return config.Outputs.AssembleResultPath
	}
	return filepath.Join(config.StateDir, "verification", "assemble-result.json")
}

func retainedIntegrationBundlePath(config Config) (string, error) {
	if retainedIntegrationBundleBodyExists(config) {
		return retainedIntegrationBundleBodyPath(config), nil
	}
	return "", diag.New(
		CodeInvalidState,
		"pass state predates directly consumable retained integration bundle bodies or is missing its retained body; refusing to bind the retention envelope to relay.",
		diag.WithDetail("expected_body_path", retainedIntegrationBundleBodyPath(config)),
		diag.WithDetail("retained_envelope_path", retainedIntegrationBundleEnvelopePath(config)),
		diag.WithDetail("original_bundle_path", config.IntegrationBundlePath),
		diag.WithDetail("rebind_instruction", "re-run preflight with -integration-bundle set to the original authored bundle path so integration-bundle.body.json is retained"),
	)
}

func retainedIntegrationBundleBodyPath(config Config) string {
	return filepath.Join(config.StateDir, preflight.RetainedIntegrationBundleBodyFile)
}

func retainedIntegrationBundleBodyExists(config Config) bool {
	info, err := os.Stat(retainedIntegrationBundleBodyPath(config))
	return err == nil && !info.IsDir()
}

func retainedIntegrationBundleEnvelopePath(config Config) string {
	return filepath.Join(config.StateDir, preflight.RetainedIntegrationBundleEnvelopeFile)
}

// source_manifest and workspace_manifest are intentionally shared with
// preflight; only lifecycle artifacts owned by the pass driver are reserved.
var reservedPassRetainedArtifactRoles = map[string]struct{}{
	"pass_state":     {},
	"charter_freeze": {},
	"preflight":      {},
}

// passRetainedArtifacts reports the retained artifacts already written by the
// pass as state-directory-relative paths. It deliberately shares the
// preflight retained_artifacts map shape so callers need only consume one
// inventory format while a pass advances.
func passRetainedArtifacts(config Config, preflightResult preflight.Result) (map[string]string, error) {
	artifacts := map[string]string{}
	localManifestPaths := map[string]string{}
	for _, item := range []struct {
		role string
		path string
	}{
		{role: "pass_state", path: config.Outputs.StatePath},
		{role: "charter_freeze", path: config.Outputs.CharterFreezePath},
		{role: "preflight", path: config.Outputs.PreflightPath},
		{role: "source_manifest", path: config.SnapshotManifestPath},
		{role: "workspace_manifest", path: config.SnapshotManifestPath},
	} {
		if relativePath, ok := stateDirRelativeExistingFile(config.StateDir, item.path); ok {
			artifacts[item.role] = relativePath
			if item.role == "source_manifest" || item.role == "workspace_manifest" {
				localManifestPaths[item.role] = relativePath
			}
		}
	}
	for _, role := range sortedStringMapKeys(preflightResult.RetainedArtifacts) {
		relativePath := preflightResult.RetainedArtifacts[role]
		if _, reserved := reservedPassRetainedArtifactRoles[role]; reserved {
			return nil, validationError(
				CodeReservedRetainedArtifactRole,
				"preflight retained artifact role collides with a reserved pass core role.",
				"/retained_artifacts/"+jsonPointerEscape(role),
				map[string]any{"role": role},
			)
		}
		validatedPath, ok := stateDirRelativeExistingPreflightFile(config.StateDir, relativePath)
		if !ok {
			return nil, validationError(
				CodeInvalidRetainedArtifact,
				"preflight retained artifact path must be a state-directory-relative existing regular file.",
				"/retained_artifacts/"+jsonPointerEscape(role),
				map[string]any{"role": role, "path": relativePath},
			)
		}
		if role == "source_manifest" || role == "workspace_manifest" {
			localPath, found := localManifestPaths[role]
			if !found || validatedPath != localPath {
				return nil, validationError(
					CodeRetainedArtifactRoleConflict,
					"preflight manifest retained artifact path must match the locally computed snapshot manifest path.",
					"/retained_artifacts/"+jsonPointerEscape(role),
					map[string]any{"role": role, "path": validatedPath, "expected_path": localPath},
				)
			}
			continue
		}
		artifacts[role] = validatedPath
	}
	return artifacts, nil
}

func stateDirRelativeExistingPreflightFile(stateDir string, relativePath string) (string, bool) {
	if strings.TrimSpace(relativePath) == "" || filepath.IsAbs(relativePath) || strings.Contains(relativePath, "\x00") {
		return "", false
	}
	for _, part := range strings.Split(filepath.ToSlash(relativePath), "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return stateDirRelativeExistingFile(stateDir, filepath.Join(stateDir, filepath.FromSlash(relativePath)))
}

func stateDirRelativeExistingFile(stateDir string, path string) (string, bool) {
	if strings.TrimSpace(stateDir) == "" || strings.TrimSpace(path) == "" {
		return "", false
	}
	relativePath, err := filepath.Rel(stateDir, path)
	if err != nil || relativePath == "." || relativePath == ".." || filepath.IsAbs(relativePath) || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", false
	}
	if _, ok := stateDirRetainedArtifactPath(stateDir, relativePath); !ok {
		return "", false
	}
	return filepath.ToSlash(relativePath), true
}

// stateDirRetainedArtifactPath mirrors cmd/witness's U4 retained-artifact
// validation so pass output retains the same accident-prevention semantics.
func stateDirRetainedArtifactPath(stateDir string, relativePath string) (string, bool) {
	if !stateDirContainedRelativePath(relativePath) {
		return relativePath, false
	}
	candidate := filepath.Join(stateDir, relativePath)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return candidate, false
	}
	resolvedStateDir, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return candidate, false
	}
	relative, err := filepath.Rel(resolvedStateDir, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return candidate, false
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return candidate, false
	}
	return candidate, true
}

// stateDirContainedRelativePath reports whether a retained-artifact path is a
// clean relative path that stays inside the state directory. Absolute paths
// and any path that escapes upward (a leading ".." component after cleaning)
// are rejected, and stateDirRetainedArtifactPath additionally resolves
// symlinks and requires the resolved target to be a regular file inside the
// resolved state directory. This is accident prevention against stale or
// malformed inventories, not a security boundary against a local attacker
// racing filesystem state between validation and open.
func stateDirContainedRelativePath(relativePath string) bool {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return false
	}
	cleaned := filepath.Clean(relativePath)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func roleOutputDir(config Config) string {
	return filepath.Join(config.StateDir, "role-outputs")
}

func roleOutputChangeSurfacePath(config Config) string {
	if strings.TrimSpace(config.Outputs.RoleOutputChangeSurfacePath) != "" {
		return config.Outputs.RoleOutputChangeSurfacePath
	}
	return filepath.Join(config.StateDir, "role-output-change-surface.json")
}

func writeAssembleArtifacts(config Config, result *planning.AssembleResult) error {
	if result == nil {
		return nil
	}
	if err := writeCanonicalFile(config.Outputs.ManifestPath, result.Manifest); err != nil {
		return err
	}
	if !hasSupplementaryAssembleContent(result) {
		return nil
	}
	return writeCanonicalFile(assembleResultPath(config), result)
}

func assembleOutputSpecs(config Config, result *planning.AssembleResult) []artifactInput {
	specs := []artifactInput{{role: "verification-manifest", path: config.Outputs.ManifestPath, digestClass: digest.ClassRawBytes}}
	if hasSupplementaryAssembleContent(result) {
		specs = append(specs, artifactInput{role: "assemble-result", path: assembleResultPath(config), digestClass: digest.ClassRawBytes})
	}
	return specs
}

func preflightInputSpecs(config Config) []artifactInput {
	specs := []artifactInput{
		{role: "integration-bundle", path: config.IntegrationBundlePath, digestClass: digest.ClassRawBytes},
		{role: "source-snapshot-manifest", path: config.SnapshotManifestPath, digestClass: digestClassFreezeManifest},
	}
	if roleOutputChangeSurfaceExpected(config) {
		specs = append(specs, artifactInput{role: "base-manifest", path: config.BaseManifestPath, digestClass: digestClassFreezeManifest})
		if strings.TrimSpace(config.HeadManifestPath) != "" {
			specs = append(specs, artifactInput{role: "head-manifest", path: config.HeadManifestPath, digestClass: digestClassFreezeManifest})
		}
	}
	return specs
}

func preflightOutputSpecs(config Config, result *preflight.Result) []artifactInput {
	specs := []artifactInput{{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digest.ClassRawBytes}}
	if roleOutputChangeSurfaceExpected(config) {
		specs = append(specs, artifactInput{role: roleOutputChangeSurfaceRole, path: roleOutputChangeSurfacePath(config), digestClass: digest.ClassRawBytes})
	}
	if result == nil {
		return append(specs,
			artifactInput{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digest.ClassRawBytes},
			artifactInput{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digest.ClassRawBytes},
			artifactInput{role: "integration-bundle-retained", path: retainedIntegrationBundleEnvelopePath(config), digestClass: digest.ClassRawBytes},
			artifactInput{role: "integration-bundle-body", path: retainedIntegrationBundleBodyPath(config), digestClass: digest.ClassRawBytes},
		)
	}
	for _, relativePath := range sortedStringMapKeys(result.ArtifactDigests) {
		if relativePath == "source-snapshot-manifest" {
			continue
		}
		specs = append(specs, artifactInput{
			role:        preflightRetainedArtifactRole(relativePath),
			path:        filepath.Join(config.StateDir, filepath.FromSlash(relativePath)),
			digestClass: digest.ClassRawBytes,
		})
	}
	return specs
}

func preflightRetainedArtifactRole(relativePath string) string {
	switch relativePath {
	case "compatibility-manifest.json":
		return "compatibility-manifest"
	case "relay-capabilities.json":
		return "relay-capabilities"
	case "integration-bundle.json":
		return "integration-bundle-retained"
	case preflight.RetainedIntegrationBundleBodyFile:
		return "integration-bundle-body"
	case "backend-status.json":
		return "backend-status"
	case "recipes-list.json":
		return "recipes-list"
	case "contract-digests.json":
		return "contract-digests"
	default:
		if strings.HasPrefix(relativePath, "compile-reports/") && strings.HasSuffix(relativePath, ".json") {
			name := strings.TrimSuffix(strings.TrimPrefix(relativePath, "compile-reports/"), ".json")
			return "compile-report:" + name
		}
		if strings.HasPrefix(relativePath, "recipe-plans/") && strings.HasSuffix(relativePath, ".json") {
			name := strings.TrimSuffix(strings.TrimPrefix(relativePath, "recipe-plans/"), ".json")
			return "recipe-plan:" + name
		}
		return "preflight-retained:" + artifactIDFromText(relativePath)
	}
}

func sortedStringMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasSupplementaryAssembleContent(result *planning.AssembleResult) bool {
	return result != nil && len(result.UnverifiedRelationships) > 0
}

func receiptArtifactInputs(config Config, receipts []contracts.ExecutionReceipt) ([]artifactInput, error) {
	var inputs []artifactInput
	if len(receipts) > 0 && strings.TrimSpace(config.ReceiptHMACKeyFile) != "" {
		inputs = append(inputs, artifactInput{role: "receipt-hmac-key-file", path: config.ReceiptHMACKeyFile, digestClass: digest.ClassRawBytes})
	}
	if strings.TrimSpace(config.ReceiptOutputDir) == "" {
		return inputs, nil
	}
	seen := map[string]bool{}
	for _, receipt := range receipts {
		for _, item := range receiptArtifactRefs(receipt) {
			path, err := harness.ArtifactPath(config.ReceiptOutputDir, item.ref)
			if err != nil {
				return nil, err
			}
			key := item.role + "\x00" + path
			if seen[key] {
				continue
			}
			seen[key] = true
			inputs = append(inputs, artifactInput{role: item.role, path: path, digestClass: digest.ClassRawBytes})
		}
	}
	return inputs, nil
}

type receiptArtifactBinding struct {
	role string
	ref  contracts.ArtifactRef
}

func receiptArtifactRefs(receipt contracts.ExecutionReceipt) []receiptArtifactBinding {
	prefix := "receipt-artifact:" + artifactIDFromText(firstNonEmpty(receipt.ReceiptID, receipt.FindingID, "receipt"))
	refs := []receiptArtifactBinding{
		{role: prefix + ":source-inventory-before", ref: receipt.SourceInventoryBefore},
		{role: prefix + ":source-inventory-after", ref: receipt.SourceInventoryAfter},
		{role: prefix + ":workspace-inventory-before", ref: receipt.WorkspaceInventoryBefore},
		{role: prefix + ":workspace-inventory-after", ref: receipt.WorkspaceInventoryAfter},
	}
	if receipt.Captures.Stdout != nil {
		refs = append(refs, receiptArtifactBinding{role: prefix + ":stdout", ref: *receipt.Captures.Stdout})
	}
	if receipt.Captures.Stderr != nil {
		refs = append(refs, receiptArtifactBinding{role: prefix + ":stderr", ref: *receipt.Captures.Stderr})
	}
	for index, ref := range receipt.Captures.ProducedArtifacts {
		refs = append(refs, receiptArtifactBinding{role: fmt.Sprintf("%s:produced:%d", prefix, index), ref: ref})
	}
	return refs
}

func stageOutputDigest(state *State, role string) string {
	if state == nil {
		return ""
	}
	for _, stage := range state.Stages {
		for _, output := range stage.Outputs {
			if output.Role == role {
				return strings.TrimSpace(output.Digest)
			}
		}
	}
	return ""
}

func boundInput(name string, path string, valueDigest string) string {
	if strings.TrimSpace(valueDigest) == "" {
		return name + "=" + path
	}
	return name + "=" + path + "@" + valueDigest
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
