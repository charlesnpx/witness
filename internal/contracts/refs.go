package contracts

import (
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
)

func validateArtifactRef(ref ArtifactRef, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireString(&diagnostics, path+"/kind", "artifact reference kind", ref.Kind)
	requireStableID(&diagnostics, path+"/id", "artifact reference ID", ref.ID)
	requireDigest(&diagnostics, path+"/digest", "artifact reference digest", ref.Digest)
	if ref.DigestProfile != "" && ref.DigestProfile != "relay-root-digests-v1" {
		diagnostics = append(diagnostics, diagnostic(
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
			return []diag.Diagnostic{diagnostic(CodeInvalidContract, "artifact reference is required.", path, nil)}
		}
		return nil
	}
	return validateArtifactRef(*ref, path)
}

func validateExecutableSpec(spec ExecutableSpec, path string, transformationRequired bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if len(spec.Argv) == 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "executable specification requires structured argv.", path+"/argv", nil))
	}
	for index, item := range spec.Argv {
		if strings.TrimSpace(item) == "" {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "argv entries must be non-empty strings.", path+"/argv/"+itoa(index), nil))
		}
	}
	requireString(&diagnostics, path+"/cwd", "executable cwd", spec.CWD)
	requireString(&diagnostics, path+"/expected_observation", "expected observation", spec.ExpectedObservation)
	if transformationRequired && spec.TransformationRef == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "economy executable witnesses require a patch artifact or deterministic transformation reference.", path+"/transformation_ref", nil))
	}
	diagnostics = append(diagnostics, validateArtifactRefPointer(spec.TransformationRef, path+"/transformation_ref", false)...)
	return diagnostics
}
