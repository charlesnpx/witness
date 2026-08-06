package pass

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/planning"
	"github.com/charlesnpx/witness/internal/relayrun"
)

// recordedRelayRun is a validated, local relay-run record paired with the
// manifest-safe relay evidence derived from it. The pass reads these records
// only; it never invokes relay or a provider.
type recordedRelayRun struct {
	Path     string
	Record   relayrun.RunRecord
	Evidence planning.RelayEvidence
}

func relayRunRecordPath(config Config, batchID string) string {
	return filepath.Join(config.StateDir, "verification", "runs", batchID+".json")
}

func readRecordedRelayRuns(state *State, batches []RelayBatchRecord) (map[string]recordedRelayRun, error) {
	if state == nil {
		return nil, diag.New(CodeInvalidState, "cannot read retained relay run records without pass state.")
	}
	preflightResult, err := readPreflightResult(state.Config.Outputs.PreflightPath)
	if err != nil {
		return nil, err
	}
	integrationBundleDigest := preflightResult.ContractDigests["integration_bundle"]
	runs := make(map[string]recordedRelayRun, len(batches))
	for _, batch := range batches {
		path := relayRunRecordPath(state.Config, batch.BatchID)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fileError(err, path, "open retained relay run record")
		}
		records, err := relayrun.ReadRunRecordsBytes(data)
		if err != nil {
			return nil, err
		}
		if len(records) != 1 {
			return nil, diag.New(
				CodeInvalidState,
				"a per-batch retained relay run record must contain exactly one run.",
				diag.WithDetail("batch_id", batch.BatchID),
				diag.WithDetail("path", path),
				diag.WithDetail("run_count", len(records)),
			)
		}
		record := records[0]
		if record.BatchID != batch.BatchID {
			return nil, diag.New(
				CodeInvalidState,
				"retained relay run record batch_id does not match its planned batch path.",
				diag.WithDetail("actual_batch_id", record.BatchID),
				diag.WithDetail("expected_batch_id", batch.BatchID),
				diag.WithDetail("path", path),
			)
		}
		if record.RecipeID != batch.RecipeID {
			return nil, diag.New(
				CodeInvalidState,
				"retained relay run record recipe_id does not match the planned batch.",
				diag.WithDetail("actual_recipe_id", record.RecipeID),
				diag.WithDetail("expected_recipe_id", batch.RecipeID),
				diag.WithDetail("batch_id", batch.BatchID),
			)
		}
		if err := validateRecordedRelayRunBindings(state, batch, record, integrationBundleDigest); err != nil {
			return nil, err
		}
		metadata, err := relayrun.ManifestRunRecordMetadata(record)
		if err != nil {
			return nil, err
		}
		evidence := planning.RelayEvidence{
			BatchID:           record.BatchID,
			RecipeFamily:      relayRecipeFamily(record.RecipeID),
			Backend:           relayBackend(record.RecipeID),
			PortableExportDir: record.PortableExportDir,
			Verdicts:          record.RelayVerdicts,
			RunRecords:        []map[string]any{metadata},
		}
		if record.PortableExportDigest != "" {
			evidence.PortableExportRef = &contracts.ArtifactRef{
				Kind:          "relay-root-portable-export",
				ID:            record.BatchID,
				Digest:        record.PortableExportDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			}
		}
		runs[batch.BatchID] = recordedRelayRun{Path: path, Record: record, Evidence: evidence}
	}
	return runs, nil
}

// validateRecordedRelayRunBindings rejects rebinding to another planned input
// or digest. A record that consumes a batch must prove all of the frozen
// inputs it consumed. A non-consuming launch_failed record may omit bindings,
// but any binding it does provide must still identify the pass's planned input.
func validateRecordedRelayRunBindings(state *State, batch RelayBatchRecord, record relayrun.RunRecord, integrationBundleDigest string) error {
	if state == nil {
		return diag.New(CodeInvalidState, "cannot validate a retained relay run record without pass state.")
	}
	integrationBundlePath, err := retainedIntegrationBundlePath(state.Config)
	if err != nil {
		return err
	}
	type expectedBinding struct {
		path   string
		digest string
	}
	expected := map[string]expectedBinding{
		"charter": {
			path:   state.Config.Outputs.CharterFreezePath,
			digest: stageOutputDigest(state, "charter-freeze"),
		},
		"findings": {
			path:   batch.BatchPath,
			digest: batch.BatchDigest,
		},
		"artifact": {
			path:   state.Config.SnapshotManifestPath,
			digest: stageOutputDigest(state, "source-snapshot-manifest"),
		},
		"integration_bundle": {
			path:   integrationBundlePath,
			digest: integrationBundleDigest,
		},
	}
	requiredNames := []string{"charter", "findings", "artifact", "integration_bundle"}
	suppliedValues := make(map[string][]string, len(requiredNames))
	for _, binding := range record.InputBindings {
		name, value, found := strings.Cut(binding, "=")
		if !found {
			continue
		}
		_, relevant := expected[name]
		if !relevant {
			continue
		}
		suppliedValues[name] = append(suppliedValues[name], strings.TrimSpace(value))
	}
	if record.ConsumesBatch {
		missing := make([]string, 0, len(requiredNames))
		for _, name := range requiredNames {
			if len(suppliedValues[name]) == 0 {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return diag.New(
				CodeInvalidState,
				"a retained relay run record that consumes a batch is missing required input bindings.",
				diag.WithDetail("batch_id", batch.BatchID),
				diag.WithDetail("missing_bindings", missing),
			)
		}
	}
	for _, name := range requiredNames {
		want := expected[name]
		for _, value := range suppliedValues[name] {
			path := value
			suppliedDigest := ""
			if suffixStart := strings.LastIndex(path, "@"+digest.Prefix); suffixStart >= 0 {
				suppliedDigest = path[suffixStart+1:]
				path = path[:suffixStart]
			}
			if record.ConsumesBatch && suppliedDigest == "" {
				return diag.New(
					CodeInvalidState,
					"a retained relay run record that consumes a batch must bind each planned input with its digest.",
					diag.WithDetail("batch_id", batch.BatchID),
					diag.WithDetail("binding", name),
					diag.WithDetail("actual_path", path),
					diag.WithDetail("expected_digest", want.digest),
				)
			}
			if !recordedPathsEqual(path, want.path) {
				return diag.New(
					CodeInvalidState,
					"retained relay run record input binding does not match the planned batch input.",
					diag.WithDetail("batch_id", batch.BatchID),
					diag.WithDetail("binding", name),
					diag.WithDetail("actual_path", path),
					diag.WithDetail("expected_path", want.path),
				)
			}
			if record.ConsumesBatch {
				if suppliedDigest != want.digest {
					return diag.New(
						CodeInvalidState,
						"retained relay run record input binding digest does not match the planned batch input.",
						diag.WithDetail("batch_id", batch.BatchID),
						diag.WithDetail("binding", name),
						diag.WithDetail("actual_digest", suppliedDigest),
						diag.WithDetail("expected_digest", want.digest),
					)
				}
				continue
			}
			if suppliedDigest != "" && want.digest != "" && suppliedDigest != want.digest {
				return diag.New(
					CodeInvalidState,
					"retained relay run record input binding digest does not match the planned batch input.",
					diag.WithDetail("batch_id", batch.BatchID),
					diag.WithDetail("binding", name),
					diag.WithDetail("actual_digest", suppliedDigest),
					diag.WithDetail("expected_digest", want.digest),
				)
			}
		}
	}
	return nil
}

func relayRecipeFamily(recipeID string) string {
	recipeID = strings.TrimSpace(recipeID)
	recipeID = strings.TrimSuffix(recipeID, "-codex")
	recipeID = strings.TrimSuffix(recipeID, "-claude")
	return recipeID
}

func relayBackend(recipeID string) string {
	switch {
	case strings.HasSuffix(strings.TrimSpace(recipeID), "-codex"):
		return "codex"
	case strings.HasSuffix(strings.TrimSpace(recipeID), "-claude"):
		return "claude"
	default:
		return ""
	}
}

func relayEvidenceForAssembly(state *State, batches []RelayBatchRecord) ([]planning.RelayEvidence, map[string]recordedRelayRun, error) {
	runs, err := readRecordedRelayRuns(state, batches)
	if err != nil {
		return nil, nil, err
	}
	readyEvidence := relayEvidenceFromReadyBatches(state, batches)
	readyByBatchID := make(map[string]planning.RelayEvidence, len(readyEvidence))
	for _, evidence := range readyEvidence {
		readyByBatchID[evidence.BatchID] = evidence
	}
	evidence := make([]planning.RelayEvidence, 0, len(batches))
	for _, batch := range batches {
		if run, found := runs[batch.BatchID]; found {
			evidence = append(evidence, run.Evidence)
			continue
		}
		if ready, found := readyByBatchID[batch.BatchID]; found {
			evidence = append(evidence, ready)
		}
	}
	return evidence, runs, nil
}
