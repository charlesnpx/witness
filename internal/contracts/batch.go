package contracts

import (
	"encoding/json"
	"io"

	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

type VerificationBatchDocument struct {
	SchemaVersion          string                     `json:"schema_version"`
	TaskShape              string                     `json:"task_shape"`
	CharterHash            string                     `json:"charter_hash"`
	ArtifactDigest         string                     `json:"artifact_digest"`
	SourceRoleOutputRef    ArtifactRef                `json:"source_role_output_ref"`
	SourceRoleOutputDigest string                     `json:"source_role_output_digest"`
	BatchID                string                     `json:"batch_id"`
	Findings               []VerificationBatchFinding `json:"findings"`
}

type VerificationBatchFinding struct {
	FindingID     string  `json:"finding_id"`
	FiledFinding  Finding `json:"filed_finding"`
	WitnessDigest string  `json:"witness_digest"`

	filedFindingCanonicalJSON json.RawMessage
}

type verificationBatchFindingJSON struct {
	FindingID     string          `json:"finding_id"`
	FiledFinding  json.RawMessage `json:"filed_finding"`
	WitnessDigest string          `json:"witness_digest"`
}

func (finding VerificationBatchFinding) MarshalJSON() ([]byte, error) {
	filedFinding, err := canonicalBatchFiledFindingJSON(finding)
	if err != nil {
		return nil, err
	}
	return json.Marshal(verificationBatchFindingJSON{
		FindingID:     finding.FindingID,
		FiledFinding:  filedFinding,
		WitnessDigest: finding.WitnessDigest,
	})
}

func canonicalBatchFiledFindingJSON(finding VerificationBatchFinding) (json.RawMessage, error) {
	filedFinding, err := canonicalFindingJSON(finding.FiledFinding)
	if err != nil {
		return nil, err
	}
	if len(finding.filedFindingCanonicalJSON) > 0 {
		filedFinding, err = canonicalJSONWithVerifiedCache(finding.FiledFinding, finding.filedFindingCanonicalJSON, "filed finding")
		if err != nil {
			return nil, err
		}
	}
	return filedFinding, nil
}

func (finding *VerificationBatchFinding) UnmarshalJSON(data []byte) error {
	var decoded verificationBatchFindingJSON
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var filedFinding Finding
	var filedFindingCanonical json.RawMessage
	if len(decoded.FiledFinding) > 0 {
		if err := decodeStrictContractJSON(decoded.FiledFinding, &filedFinding); err != nil {
			return err
		}
		canonical, err := canonicalFindingRawMessage(decoded.FiledFinding, filedFinding)
		if err != nil {
			return err
		}
		filedFindingCanonical = canonical
	}
	*finding = VerificationBatchFinding{
		FindingID:                 decoded.FindingID,
		FiledFinding:              filedFinding,
		WitnessDigest:             decoded.WitnessDigest,
		filedFindingCanonicalJSON: filedFindingCanonical,
	}
	return nil
}

func ReadVerificationBatch(reader io.Reader) (VerificationBatchDocument, error) {
	return strictjson.Decode[VerificationBatchDocument](reader, strictjson.DefaultMaxBytes)
}

func ReadVerificationBatchBytes(data []byte) (VerificationBatchDocument, error) {
	return strictjson.DecodeBytes[VerificationBatchDocument](data, strictjson.DefaultMaxBytes)
}

func RequireValidVerificationBatch(document VerificationBatchDocument, roleOutput *RoleOutputDocument) error {
	return ErrorFromDiagnostics(ValidateVerificationBatch(document, roleOutput))
}

func ValidateVerificationBatch(document VerificationBatchDocument, roleOutput *RoleOutputDocument) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != VerificationBatchV2 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidVerificationBatch,
			"verification-batch document schema_version must be review-verification-batch-v2.",
			"/schema_version",
			map[string]any{"expected": VerificationBatchV2, "actual": document.SchemaVersion},
		))
	}
	requireEnum(&diagnostics, "/task_shape", "task_shape", document.TaskShape, stringSet(BatchTaskDefect, BatchTaskEconomy), CodeInvalidVerificationBatch)
	requireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	requireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	requireStableID(&diagnostics, "/batch_id", "batch ID", document.BatchID)
	requireDigest(&diagnostics, "/source_role_output_digest", "source role-output digest", document.SourceRoleOutputDigest)
	diagnostics = append(diagnostics, prefixDiagnostics("/source_role_output_ref", validateArtifactRef(document.SourceRoleOutputRef, ""))...)
	if document.SourceRoleOutputRef.Digest != "" {
		compareDigest(&diagnostics, "/source_role_output_ref/digest", "source role-output reference", document.SourceRoleOutputRef.Digest, document.SourceRoleOutputDigest)
	}
	if len(document.Findings) == 0 || len(document.Findings) > 8 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidVerificationBatch,
			"verification batches must contain one to eight findings.",
			"/findings",
			map[string]any{"count": len(document.Findings)},
		))
	}

	var roleFindings map[string]Finding
	if roleOutput != nil {
		roleDigest, err := RoleOutputDigest(*roleOutput)
		if err != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidVerificationBatch, "source role-output digest could not be recomputed.", "/source_role_output_digest", map[string]any{"error": err.Error()}))
		} else {
			compareDigest(&diagnostics, "/source_role_output_digest", "source role-output", document.SourceRoleOutputDigest, roleDigest)
		}
		compareDigest(&diagnostics, "/charter_hash", "charter", document.CharterHash, roleOutput.CharterHash)
		compareDigest(&diagnostics, "/artifact_digest", "artifact", document.ArtifactDigest, roleOutput.ArtifactDigest)
		expectedTask := taskShapeForRole(roleOutput.Role)
		if expectedTask != "" && document.TaskShape != expectedTask {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidVerificationBatch,
				"verification batch task_shape must match the source role output.",
				"/task_shape",
				map[string]any{"actual": document.TaskShape, "expected": expectedTask, "role": roleOutput.Role},
			))
		}
		roleFindings = make(map[string]Finding, len(roleOutput.Findings))
		for _, finding := range roleOutput.Findings {
			roleFindings[finding.ID] = finding
		}
	}

	seen := map[string]int{}
	for index, item := range document.Findings {
		path := "/findings/" + itoa(index)
		requireStableID(&diagnostics, path+"/finding_id", "finding ID", item.FindingID)
		if item.FindingID != item.FiledFinding.ID {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidVerificationBatch,
				"batch finding_id must match the filed finding object ID.",
				path+"/finding_id",
				map[string]any{"finding_id": item.FindingID, "filed_finding_id": item.FiledFinding.ID},
			))
		}
		if first, exists := seen[item.FindingID]; exists {
			diagnostics = append(diagnostics, diagnostic(
				CodeCoverageMismatch,
				"verification batch must not contain duplicate finding IDs.",
				path+"/finding_id",
				map[string]any{"finding_id": item.FindingID, "duplicate_of": "/findings/" + itoa(first) + "/finding_id"},
			))
		}
		seen[item.FindingID] = index
		if _, err := canonicalBatchFiledFindingJSON(item); err != nil {
			if !appendValidationErrorDiagnostics(&diagnostics, path+"/filed_finding", err) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidVerificationBatch, "filed finding canonical JSON could not be recomputed.", path+"/filed_finding", map[string]any{"error": err.Error()}))
			}
		}
		requireDigest(&diagnostics, path+"/witness_digest", "witness digest", item.WitnessDigest)
		witnessDigest, err := WitnessDigest(item.FiledFinding.Witness)
		if err != nil {
			if !appendValidationErrorDiagnostics(&diagnostics, path+"/filed_finding/witness", err) {
				diagnostics = append(diagnostics, diagnostic(CodeInvalidVerificationBatch, "filed witness digest could not be recomputed.", path+"/witness_digest", map[string]any{"error": err.Error()}))
			}
		} else {
			compareDigest(&diagnostics, path+"/witness_digest", "filed witness", item.WitnessDigest, witnessDigest)
		}
		if roleFindings != nil {
			sourceFinding, exists := roleFindings[item.FindingID]
			if !exists {
				diagnostics = append(diagnostics, diagnostic(
					CodeCoverageMismatch,
					"verification batch references a finding not present in the role-output document.",
					path+"/finding_id",
					map[string]any{"finding_id": item.FindingID},
				))
				continue
			}
			compareFindingValue(&diagnostics, path+"/filed_finding", "filed finding", item.FiledFinding, sourceFinding)
			sourceWitnessDigest, err := WitnessDigest(sourceFinding.Witness)
			if err != nil {
				if !appendValidationErrorDiagnostics(&diagnostics, path+"/witness_digest", err) {
					diagnostics = append(diagnostics, diagnostic(CodeInvalidVerificationBatch, "source witness digest could not be recomputed.", path+"/witness_digest", map[string]any{"error": err.Error()}))
				}
			} else {
				compareDigest(&diagnostics, path+"/witness_digest", "source witness", item.WitnessDigest, sourceWitnessDigest)
			}
		}
	}
	return diagnostics
}

func NewVerificationBatch(roleOutput RoleOutputDocument, batchID string, findingIDs []string) (VerificationBatchDocument, error) {
	roleDigest, err := RoleOutputDigest(roleOutput)
	if err != nil {
		return VerificationBatchDocument{}, err
	}
	byID := make(map[string]Finding, len(roleOutput.Findings))
	for _, finding := range roleOutput.Findings {
		byID[finding.ID] = finding
	}
	findings := make([]VerificationBatchFinding, 0, len(findingIDs))
	for _, id := range findingIDs {
		finding, exists := byID[id]
		if !exists {
			return VerificationBatchDocument{}, &ValidationError{Diagnostics: []diag.Diagnostic{diagnostic(
				CodeCoverageMismatch,
				"requested batch finding is not present in the role-output document.",
				"/findings",
				map[string]any{"finding_id": id},
			)}}
		}
		witnessDigest, err := WitnessDigest(finding.Witness)
		if err != nil {
			return VerificationBatchDocument{}, err
		}
		filedFinding, err := canonicalFindingJSON(finding)
		if err != nil {
			return VerificationBatchDocument{}, err
		}
		findings = append(findings, VerificationBatchFinding{
			FindingID:                 id,
			FiledFinding:              finding,
			WitnessDigest:             witnessDigest,
			filedFindingCanonicalJSON: filedFinding,
		})
	}
	return VerificationBatchDocument{
		SchemaVersion:          VerificationBatchV2,
		TaskShape:              taskShapeForRole(roleOutput.Role),
		CharterHash:            roleOutput.CharterHash,
		ArtifactDigest:         roleOutput.ArtifactDigest,
		SourceRoleOutputRef:    ArtifactRef{Kind: "role-output", ID: roleOutput.Role, Digest: roleDigest, DigestProfile: "relay-root-digests-v1"},
		SourceRoleOutputDigest: roleDigest,
		BatchID:                batchID,
		Findings:               findings,
	}, nil
}

func WitnessDigest(witness Witness) (string, error) {
	canonical, err := canonicalWitnessJSON(witness)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(canonical), nil
}

func FindingDigest(finding Finding) (string, error) {
	canonical, err := canonicalFindingJSON(finding)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(canonical), nil
}

func VerificationBatchDigest(document VerificationBatchDocument) (string, error) {
	return SemanticDigest(document)
}

func VerificationBatchCanonicalBytes(document VerificationBatchDocument) ([]byte, error) {
	return CanonicalBytes(document)
}

func taskShapeForRole(role string) string {
	switch role {
	case RoleDefect:
		return BatchTaskDefect
	case RoleEconomy:
		return BatchTaskEconomy
	default:
		return ""
	}
}

func compareSemanticValue(diagnostics *[]diag.Diagnostic, path string, label string, actual any, expected any) {
	actualDigest, actualErr := SemanticDigest(actual)
	expectedDigest, expectedErr := SemanticDigest(expected)
	if actualErr != nil {
		if appendValidationErrorDiagnostics(diagnostics, path, actualErr) {
			return
		}
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidVerificationBatch, label+" actual value could not be digested.", path, map[string]any{"error": actualErr.Error()}))
		return
	}
	if expectedErr != nil {
		if appendValidationErrorDiagnostics(diagnostics, path, expectedErr) {
			return
		}
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidVerificationBatch, label+" expected value could not be digested.", path, map[string]any{"error": expectedErr.Error()}))
		return
	}
	compareDigest(diagnostics, path, label, actualDigest, expectedDigest)
}

func compareFindingValue(diagnostics *[]diag.Diagnostic, path string, label string, actual Finding, expected Finding) {
	actualDigest, actualErr := FindingDigest(actual)
	expectedDigest, expectedErr := FindingDigest(expected)
	if actualErr != nil {
		if appendValidationErrorDiagnostics(diagnostics, path, actualErr) {
			return
		}
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidVerificationBatch, label+" actual value could not be digested.", path, map[string]any{"error": actualErr.Error()}))
		return
	}
	if expectedErr != nil {
		if appendValidationErrorDiagnostics(diagnostics, path, expectedErr) {
			return
		}
		*diagnostics = append(*diagnostics, diagnostic(CodeInvalidVerificationBatch, label+" expected value could not be digested.", path, map[string]any{"error": expectedErr.Error()}))
		return
	}
	compareDigest(diagnostics, path, label, actualDigest, expectedDigest)
}
