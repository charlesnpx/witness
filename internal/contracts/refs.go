package contracts

import "github.com/charlesnpx/witness/internal/diag"

type ArtifactRef struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Digest        string `json:"digest"`
	DigestProfile string `json:"digest_profile,omitempty"`
	MediaType     string `json:"media_type,omitempty"`
}

type SourceRef struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Digest        string `json:"digest"`
	DigestProfile string `json:"digest_profile,omitempty"`
}

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
