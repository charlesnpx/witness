package contracts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/strictjson"
	"github.com/charlesnpx/witness/internal/changesurface"
)

func TestVerificationBatchRejectsNarrativeAndDigestMismatch(t *testing.T) {
	roleOutput, batch := validRoleOutputAndBatch(t)
	raw := `{
	  "schema_version":"review-verification-batch-v2",
	  "task_shape":"defect",
	  "charter_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "artifact_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	  "source_role_output_ref":{"kind":"role-output","id":"defect","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	  "source_role_output_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	  "batch_id":"batch-1",
	  "findings":[],
	  "narrative":"finder explanation must not be carried into verification"
	}`
	if _, err := ReadVerificationBatchBytes([]byte(raw)); err == nil {
		t.Fatal("ReadVerificationBatchBytes accepted finder narrative field")
	} else if got := diag.FromError(err).Code; got != diag.CodeUnknownJSONField {
		t.Fatalf("diagnostic code = %s, want %s", got, diag.CodeUnknownJSONField)
	}

	batch.SourceRoleOutputDigest = digest.RawBytes([]byte("wrong role output"))
	diagnostics := ValidateVerificationBatch(batch, &roleOutput)
	assertDiagnosticCode(t, diagnostics, CodeDigestMismatch)
}

func TestVerificationBatchRejectsMutatedDecodedFiledWitness(t *testing.T) {
	roleOutput, batch := validRoleOutputAndBatch(t)
	raw, err := VerificationBatchCanonicalBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadVerificationBatchBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Findings[0].FiledFinding.Witness.Content = "Mutated witness content after decode."

	diagnostics := ValidateVerificationBatch(decoded, &roleOutput)
	assertDiagnosticCode(t, diagnostics, CodeFiledValueMutated)
}

func TestReducerVerdictCoverageAndClassRules(t *testing.T) {
	_, batch := validRoleOutputAndBatch(t)
	witnessDigest := batch.Findings[0].WitnessDigest
	classLogic := VerdictClassLogic
	classUnreachable := VerdictClassUnreachable
	tests := []struct {
		name     string
		document RelayWitnessVerdictsDocument
		code     string
	}{
		{
			name: "valid survived",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:      "defect-1",
					WitnessDigest:  witnessDigest,
					Verdict:        VerdictSurvived,
					VerdictClass:   nil,
					CounterWitness: nil,
				}},
			},
		},
		{
			name: "missing verdict rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts:      []WitnessVerdict{},
			},
			code: CodeCoverageMismatch,
		},
		{
			name: "extra verdict rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{
					{FindingID: "defect-1", WitnessDigest: witnessDigest, Verdict: VerdictSurvived},
					{FindingID: "extra-1", WitnessDigest: witnessDigest, Verdict: VerdictSurvived},
				},
			},
			code: CodeCoverageMismatch,
		},
		{
			name: "digest mismatch rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:     "defect-1",
					WitnessDigest: digest.RawBytes([]byte("wrong witness")),
					Verdict:       VerdictSurvived,
				}},
			},
			code: CodeDigestMismatch,
		},
		{
			name: "survived with class rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:     "defect-1",
					WitnessDigest: witnessDigest,
					Verdict:       VerdictSurvived,
					VerdictClass:  &classLogic,
				}},
			},
			code: CodeInvalidRelayVerdicts,
		},
		{
			name: "weakened without class rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:      "defect-1",
					WitnessDigest:  witnessDigest,
					Verdict:        VerdictWeakened,
					CounterWitness: validCounterWitness(),
				}},
			},
			code: CodeInvalidRelayVerdicts,
		},
		{
			name: "weakened without counter witness rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:     "defect-1",
					WitnessDigest: witnessDigest,
					Verdict:       VerdictWeakened,
					VerdictClass:  &classLogic,
				}},
			},
			code: CodeInvalidRelayVerdicts,
		},
		{
			name: "survived with counter witness rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:      "defect-1",
					WitnessDigest:  witnessDigest,
					Verdict:        VerdictSurvived,
					CounterWitness: validCounterWitness(),
				}},
			},
			code: CodeInvalidRelayVerdicts,
		},
		{
			name: "weakened unreachable rejected",
			document: RelayWitnessVerdictsDocument{
				SchemaVersion: RelayWitnessVerdictsV2,
				BatchID:       batch.BatchID,
				Verdicts: []WitnessVerdict{{
					FindingID:      "defect-1",
					WitnessDigest:  witnessDigest,
					Verdict:        VerdictWeakened,
					VerdictClass:   &classUnreachable,
					CounterWitness: validCounterWitness(),
				}},
			},
			code: CodeInvalidRelayVerdicts,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := ValidateRelayWitnessVerdicts(test.document, &batch)
			if test.code == "" {
				if len(diagnostics) > 0 {
					t.Fatalf("ValidateRelayWitnessVerdicts diagnostics = %#v", diagnostics)
				}
				return
			}
			assertDiagnosticCode(t, diagnostics, test.code)
		})
	}
}

func TestReducerRejectsExecutionAttestationFields(t *testing.T) {
	raw := `{
	  "schema_version":"relay-witness-verdicts-v2",
	  "batch_id":"batch-1",
	  "verdicts":[{
	    "finding_id":"defect-1",
	    "witness_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    "verdict":"survived",
	    "verdict_class":null,
	    "counter_witness":null,
	    "execution_attestation":{"claimed":"ran tests"}
	  }]
	}`
	if _, err := ReadRelayWitnessVerdictsBytes([]byte(raw)); err == nil {
		t.Fatal("ReadRelayWitnessVerdictsBytes accepted execution_attestation")
	} else if got := diag.FromError(err).Code; got != CodeForbiddenExecutionField {
		t.Fatalf("diagnostic code = %s, want %s", got, CodeForbiddenExecutionField)
	}
}

func TestReducerSchemaSourceContainsNoCommentAndIsStrictJSON(t *testing.T) {
	if strings.Contains(RelayWitnessVerdictsV2SchemaJSON, "$comment") {
		t.Fatal("relay schema source contains unsupported $comment keyword")
	}
	if _, err := strictjson.DecodeAnyBytes(RelayWitnessVerdictsV2SchemaBytes(), strictjson.DefaultMaxBytes); err != nil {
		t.Fatalf("relay schema source is not strict JSON: %v", err)
	}
	if !strings.Contains(ReducerBriefText, "valid only with broken") {
		t.Fatal("reducer brief is missing broken-only verdict-class rationale")
	}
}

func TestVerificationBatchPreservesExplicitEmptyWitnessArtifactRefs(t *testing.T) {
	frozen := validFrozenCharter(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "role-output-defect.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(
		string(data),
		`"content": "A request through the CLI entry point with the declared normal state reaches the rejecting branch.",`,
		`"content": "A request through the CLI entry point with the declared normal state reaches the rejecting branch.",`+"\n"+`        "artifact_refs": [],`,
		1,
	)
	if raw == string(data) {
		t.Fatal("test fixture mutation did not insert artifact_refs")
	}
	document, err := ReadRoleOutputBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	document.CharterHash = frozen.CharterHash
	if diagnostics := ValidateRoleOutput(document, frozen); len(diagnostics) > 0 {
		t.Fatalf("role output diagnostics = %#v", diagnostics)
	}
	canonicalWitness, err := WitnessCanonicalJSON(document.Findings[0].Witness)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonicalWitness, []byte(`"artifact_refs":[]`)) {
		t.Fatalf("witness canonical JSON = %s, want explicit empty artifact_refs", canonicalWitness)
	}
	batch, err := NewVerificationBatch(document, "batch-1", []string{"defect-1"})
	if err != nil {
		t.Fatal(err)
	}
	wantWitnessDigest := digest.RawBytes(canonicalWitness)
	if batch.Findings[0].WitnessDigest != wantWitnessDigest {
		t.Fatalf("witness digest = %s, want %s", batch.Findings[0].WitnessDigest, wantWitnessDigest)
	}
	canonicalBatch, err := VerificationBatchCanonicalBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonicalBatch, []byte(`"artifact_refs":[]`)) {
		t.Fatalf("batch canonical JSON = %s, want explicit empty artifact_refs", canonicalBatch)
	}
	roundTrip, err := ReadVerificationBatchBytes(canonicalBatch)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := ValidateVerificationBatch(roundTrip, &document); len(diagnostics) > 0 {
		t.Fatalf("round-trip batch diagnostics = %#v", diagnostics)
	}
}

func TestFindingInChangeSurfaceUsesExecutableTransformationRef(t *testing.T) {
	surface := changesurface.Document{
		SchemaVersion:      changesurface.SchemaVersion,
		DigestProfile:      digest.Profile,
		BaseArtifactDigest: testDigest("base"),
		HeadArtifactDigest: testDigest("head"),
		ChangedPaths: []changesurface.PathChange{{
			Path:        "changed.go",
			ChangeKinds: []string{changesurface.ChangeKindModified},
		}},
	}
	finding := Finding{
		ID: "finding-transform",
		Witness: Witness{
			Strength: WitnessStrengthExecutable,
			Executable: &ExecutableSpec{
				Argv:                []string{"go", "test"},
				CWD:                 ".",
				ExpectedObservation: "tests pass",
				TransformationRef: &ArtifactRef{
					Kind:          "patch",
					ID:            "changed.go",
					Digest:        testDigest("patch"),
					DigestProfile: digest.Profile,
					MediaType:     "text/plain",
				},
			},
		},
	}
	if !FindingInChangeSurface(finding, surface) {
		t.Fatal("FindingInChangeSurface returned false for executable transformation_ref path")
	}
}

func TestManifestCanonicalResultDigestBindsEmbeddedRelayVerdicts(t *testing.T) {
	_, batch := validRoleOutputAndBatch(t)
	verdicts := validSurvivedVerdicts(batch)
	manifest := validVerificationManifest(t, batch, verdicts)
	manifest.Batches[0].CanonicalResultDigest = testDigest("wrong canonical result")
	diagnostics := ValidateVerificationManifest(manifest)
	assertDiagnosticCode(t, diagnostics, CodeDigestMismatch)
}

func TestVerificationManifestRejectsInvalidRelayLaunchStatusMarkers(t *testing.T) {
	_, batch := validRoleOutputAndBatch(t)
	verdicts := validSurvivedVerdicts(batch)
	manifest := validVerificationManifest(t, batch, verdicts)
	manifest.Batches[0].Status = RecordStatusUnavailable
	manifest.Batches[0].PortableExportRef = nil
	manifest.Batches[0].PortableExportDigest = ""
	manifest.Batches[0].CanonicalResultDigest = ""
	manifest.Batches[0].RelayVerdicts = nil
	manifest.Batches[0].FailureReason = "relay_verification_unavailable"
	manifest.ConsumerIdentity = map[string]any{
		"kind": "test",
		"id":   "consumer",
		VerificationManifestRelayBatchesKey: map[string]any{
			batch.BatchID: map[string]any{
				"recipe_family": "witness-falsify-v2",
				"backend":       "codex",
				"finding_ids":   []string{batch.Findings[0].FindingID},
			},
		},
	}

	diagnostics := ValidateVerificationManifest(manifest)
	assertDiagnosticCode(t, diagnostics, CodeInvalidManifest)

	manifest.ConsumerIdentity[VerificationManifestRelayLaunchStatusKey] = RelayLaunchStatusAbsent
	manifest.ConsumerIdentity[VerificationManifestRelayBatchesKey].(map[string]any)[batch.BatchID].(map[string]any)[VerificationManifestBatchRelayLaunchStatusKey] = RelayLaunchStatusPresent
	diagnostics = ValidateVerificationManifest(manifest)
	assertDiagnosticCode(t, diagnostics, CodeInvalidManifest)
}

func TestReadVerificationManifestBytesRefusesActualSchemaVersion(t *testing.T) {
	for _, actual := range []string{VerificationManifestV5, "", "future-version"} {
		t.Run(contractSchemaVersionTestName(actual), func(t *testing.T) {
			data := []byte(`{"legacy_shape_field":true}`)
			if actual != "" {
				data = []byte(`{"schema_version":"` + actual + `","legacy_shape_field":true}`)
			}
			_, err := ReadVerificationManifestBytes(data)
			if err == nil {
				t.Fatalf("ReadVerificationManifestBytes accepted %q", actual)
			}
			diagnostic := diag.FromError(err)
			if diagnostic.Code != CodeInvalidManifest || diagnostic.Path != "/schema_version" {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
			if strings.Contains(diagnostic.Message, "unknown_json_field") || !strings.Contains(diagnostic.Message, VerificationManifestV6) {
				t.Fatalf("diagnostic = %#v, want version refusal before strict decode", diagnostic)
			}
			if actual == "" {
				if !strings.Contains(diagnostic.Message, "missing or unversioned") {
					t.Fatalf("diagnostic = %#v, want missing-version wording", diagnostic)
				}
			} else if !strings.Contains(diagnostic.Message, actual) {
				t.Fatalf("diagnostic = %#v, want message to name %q", diagnostic, actual)
			}
			if diagnostic.Details["actual"] != actual || diagnostic.Details["expected"] != VerificationManifestV6 {
				t.Fatalf("schema diagnostic details = %#v", diagnostic.Details)
			}
		})
	}
}

func contractSchemaVersionTestName(version string) string {
	if version == "" {
		return "missing"
	}
	return version
}

func TestDefectMalformedEstimateRoutesToUnknownDelta(t *testing.T) {
	frozen := validFrozenCharter(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "role-output-defect.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(string(data), `"status": "known",`, `"status": "model-specific",`, 1)
	if raw == string(data) {
		t.Fatal("test fixture mutation did not replace delta status")
	}
	document, err := ReadRoleOutputBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	document.CharterHash = frozen.CharterHash
	if got := document.Findings[0].EstimatedDelta.Production.Status; got != DeltaStatusUnknown {
		t.Fatalf("production delta status = %q, want %q", got, DeltaStatusUnknown)
	}
	if diagnostics := ValidateRoleOutput(document, frozen); len(diagnostics) > 0 {
		t.Fatalf("defect role output diagnostics = %#v", diagnostics)
	}
	batch, err := NewVerificationBatch(document, "batch-1", []string{"defect-1"})
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := ValidateVerificationBatch(batch, &document); len(diagnostics) > 0 {
		t.Fatalf("verification batch diagnostics = %#v", diagnostics)
	}
}

func TestReducerRequiresExplicitNullFieldsForRawSurvivedVerdict(t *testing.T) {
	raw := `{
	  "schema_version":"relay-witness-verdicts-v2",
	  "batch_id":"batch-1",
	  "verdicts":[{
	    "finding_id":"defect-1",
	    "witness_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    "verdict":"survived"
	  }]
	}`
	document, err := ReadRelayWitnessVerdictsBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := ValidateRelayWitnessVerdicts(document, nil)
	assertDiagnosticCode(t, diagnostics, CodeInvalidRelayVerdicts)
}

func readRoleFixture(t *testing.T, name string) RoleOutputDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", name))
	if err != nil {
		t.Fatal(err)
	}
	document, err := ReadRoleOutputBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func validRoleOutputAndBatch(t *testing.T) (RoleOutputDocument, VerificationBatchDocument) {
	t.Helper()
	frozen := validFrozenCharter(t)
	roleOutput := readRoleFixture(t, "role-output-defect.json")
	roleOutput.CharterHash = frozen.CharterHash
	if diagnostics := ValidateRoleOutput(roleOutput, frozen); len(diagnostics) > 0 {
		t.Fatalf("role output diagnostics = %#v", diagnostics)
	}
	batch, err := NewVerificationBatch(roleOutput, "batch-1", []string{"defect-1"})
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := ValidateVerificationBatch(batch, &roleOutput); len(diagnostics) > 0 {
		t.Fatalf("batch diagnostics = %#v", diagnostics)
	}
	return roleOutput, batch
}

func validCounterWitness() *CounterWitness {
	return &CounterWitness{
		Summary:  "The filed scenario does not reach the claimed branch.",
		Evidence: "The declared entry point exits before the branch is evaluated.",
	}
}

func validSurvivedVerdicts(batch VerificationBatchDocument) RelayWitnessVerdictsDocument {
	return RelayWitnessVerdictsDocument{
		SchemaVersion: RelayWitnessVerdictsV2,
		BatchID:       batch.BatchID,
		Verdicts: []WitnessVerdict{{
			FindingID:      batch.Findings[0].FindingID,
			WitnessDigest:  batch.Findings[0].WitnessDigest,
			Verdict:        VerdictSurvived,
			VerdictClass:   nil,
			CounterWitness: nil,
		}},
	}
}

func validVerificationManifest(t *testing.T, batch VerificationBatchDocument, verdicts RelayWitnessVerdictsDocument) VerificationManifest {
	t.Helper()
	batchDigest, err := VerificationBatchDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	verdictDigest, err := RelayWitnessVerdictsDigest(verdicts)
	if err != nil {
		t.Fatal(err)
	}
	portableExportDigest := testDigest("portable-export")
	portableExportRef := testArtifactRef("portable-export", "portable-export-1", portableExportDigest)
	return VerificationManifest{
		SchemaVersion:     VerificationManifestV6,
		PlanDigest:        testDigest("plan"),
		CharterHash:       batch.CharterHash,
		ArtifactDigest:    batch.ArtifactDigest,
		IntegrationBundle: testArtifactRef("integration-bundle", "bundle", testDigest("bundle")),
		Batches: []VerificationManifestBatch{{
			BatchID:               batch.BatchID,
			Status:                RecordStatusValid,
			BatchRef:              testArtifactRef("verification-batch", batch.BatchID, batchDigest),
			BatchDigest:           batchDigest,
			PortableExportRef:     &portableExportRef,
			PortableExportDigest:  portableExportDigest,
			CanonicalResultDigest: verdictDigest,
			RelayVerdicts:         &verdicts,
		}},
		ConsumerIdentity: map[string]any{"kind": "test", "id": "consumer"},
	}
}

func testArtifactRef(kind string, id string, value string) ArtifactRef {
	return ArtifactRef{Kind: kind, ID: id, Digest: value, DigestProfile: digest.Profile}
}

func testDigest(seed string) string {
	return digest.RawBytes([]byte(seed))
}

func validFrozenCharter(t *testing.T) *charter.FrozenCharter {
	t.Helper()
	frozen, err := charter.Freeze(charter.Charter{
		SchemaVersion: charter.SchemaVersion,
		Goals: []charter.Statement{{
			ID:        "goal-cli",
			Statement: "The CLI accepts declared valid inputs deterministically.",
		}},
		NonGoals: []charter.Statement{},
		OwnerEvents: []charter.OwnerEvent{{
			ID:      "event-1",
			Type:    "charter_initialized",
			Actor:   "owner",
			Summary: "Initial charter.",
		}},
		OperationalEnvelope: &charter.OperationalEnvelope{
			EntryPoints: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared entry points.",
				Entries:   []charter.Entry{{ID: "cli", Statement: "Command line interface."}},
			},
			InputSurface: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Caller supplied files.",
				Entries:   []charter.Entry{},
			},
			ValidStates: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared valid states.",
				Entries:   []charter.Entry{{ID: "normal", Statement: "Normal configured operation."}},
			},
			Environments: &charter.Dimension{
				State:     charter.StateNotApplicable,
				Statement: "No environment distinction.",
				Entries:   []charter.Entry{},
			},
			ScaleBounds: &charter.Dimension{
				State:     charter.StateUnspecified,
				Statement: "Scale is unspecified.",
				Entries:   []charter.Entry{},
			},
			CompatibilityPromises: &charter.Dimension{
				State:     charter.StateBounded,
				Statement: "Declared compatibility promises.",
				Entries:   []charter.Entry{{ID: "json-v1", Statement: "JSON response shape v1."}},
			},
			ThreatModel: &charter.Dimension{
				State:     charter.StateUnbounded,
				Statement: "Threat scenarios must be concrete.",
				Entries:   []charter.Entry{},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &frozen
}

func assertDiagnosticCode(t *testing.T, diagnostics []diag.Diagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want code %s", diagnostics, code)
}
