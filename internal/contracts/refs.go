package contracts

import (
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/review"
)

func validateArtifactRef(ref ArtifactRef, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	review.RequireString(&diagnostics, path+"/kind", "artifact reference kind", ref.Kind)
	review.RequireStableID(&diagnostics, path+"/id", "artifact reference ID", ref.ID)
	review.RequireDigest(&diagnostics, path+"/digest", "artifact reference digest", ref.Digest)
	if ref.DigestProfile != "" && ref.DigestProfile != "relay-root-digests-v1" {
		diagnostics = append(diagnostics, review.Diagnostic(
			CodeInvalidContract,
			"artifact reference digest_profile must be relay-root-digests-v1 when present.",
			path+"/digest_profile",
			map[string]any{"value": ref.DigestProfile},
		))
	}
	return diagnostics
}

func validateArtifactRefPointer(ref *ArtifactRef, path string, required bool) []diag.Diagnostic {
	if ref == nil {
		if required {
			return []diag.Diagnostic{review.Diagnostic(CodeInvalidContract, "artifact reference is required.", path, nil)}
		}
		return nil
	}
	return validateArtifactRef(*ref, path)
}

func validateExecutableSpec(spec ExecutableSpec, path string, transformationRequired bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if len(spec.Argv) == 0 {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidWitness, "executable specification requires structured argv.", path+"/argv", nil))
	}
	for index, item := range spec.Argv {
		if strings.TrimSpace(item) == "" {
			diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidWitness, "argv entries must be non-empty strings.", path+"/argv/"+itoa(index), nil))
		}
	}
	review.RequireString(&diagnostics, path+"/cwd", "executable cwd", spec.CWD)
	review.RequireString(&diagnostics, path+"/expected_observation", "expected observation", spec.ExpectedObservation)
	if transformationRequired && spec.TransformationRef == nil {
		diagnostics = append(diagnostics, review.Diagnostic(CodeInvalidWitness, "economy executable witnesses require a patch artifact or deterministic transformation reference.", path+"/transformation_ref", nil))
	}
	diagnostics = append(diagnostics, validateArtifactRefPointer(spec.TransformationRef, path+"/transformation_ref", false)...)
	return diagnostics
}
