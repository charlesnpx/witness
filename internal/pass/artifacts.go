package pass

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"witness/internal/contracts"
	"witness/internal/digest"
	"witness/internal/harness"
	"witness/internal/planning"
	"witness/internal/preflight"
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

func retainedIntegrationBundlePath(config Config) string {
	return filepath.Join(config.StateDir, "integration-bundle.json")
}

func roleOutputDir(config Config) string {
	return filepath.Join(config.StateDir, "role-outputs")
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

func preflightOutputSpecs(config Config, result *preflight.Result) []artifactInput {
	specs := []artifactInput{{role: "preflight", path: config.Outputs.PreflightPath, digestClass: digest.ClassRawBytes}}
	if result == nil {
		return append(specs,
			artifactInput{role: "compatibility-manifest", path: filepath.Join(config.StateDir, "compatibility-manifest.json"), digestClass: digest.ClassRawBytes},
			artifactInput{role: "relay-capabilities", path: filepath.Join(config.StateDir, "relay-capabilities.json"), digestClass: digest.ClassRawBytes},
			artifactInput{role: "integration-bundle-retained", path: retainedIntegrationBundlePath(config), digestClass: digest.ClassRawBytes},
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
