package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	Profile = "relay-root-digests-v1"
	Prefix  = "sha256:"

	ClassRawBytes        = "raw-bytes"
	ClassSemanticJSON    = "semantic-json"
	ClassStorageEnvelope = "storage-envelope"
)

var rootArtifactKinds = map[string]bool{
	"root_recipe_plan":               true,
	"integration_bundle":             true,
	"integration_contract":           true,
	"named_input_manifest":           true,
	"named_input_content":            true,
	"retained_input_materialization": true,
	"execution_workspace":            true,
	"root_checkpoint":                true,
	"reducer_attempt":                true,
	"raw_result":                     true,
	"result_validation":              true,
	"canonical_result":               true,
	"rendered_prompt":                true,
	"provider_invocation":            true,
	"provider_result":                true,
	"workspace_isolation_report":     true,
}

func RawBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return Prefix + hex.EncodeToString(sum[:])
}

func SemanticJSON(value any) (string, error) {
	canonical, err := canonjson.Marshal(value)
	if err != nil {
		return "", err
	}
	return RawBytes(canonical), nil
}

func SemanticJSONBytes(data []byte) (string, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return "", err
	}
	return SemanticJSON(value)
}

func StorageEnvelope(kind string, value any) (string, error) {
	if !rootArtifactKinds[kind] {
		return "", diag.New(
			diag.CodeUnsupportedRootKind,
			"relay-root-digests-v1 has no storage-envelope projection for this root artifact kind.",
			diag.WithDetail("kind", kind),
		)
	}
	materialized, err := canonjson.Materialize(value)
	if err != nil {
		return "", err
	}
	object, ok := materialized.(map[string]any)
	if !ok {
		return "", diag.New(
			diag.CodeInvalidDigestPayload,
			"storage-envelope digest payload must be a JSON object.",
			diag.WithDetail("kind", kind),
		)
	}
	if kind == "execution_workspace" {
		delete(object, "identity")
		deleteNested(object, "source", "git_root")
		deleteNested(object, "source", "launch_cwd")
		deleteNested(object, "source_after", "git_root")
		deleteNested(object, "source_after", "launch_cwd")
	}
	return SemanticJSON(object)
}

func ForClass(class string, kind string, value any, raw []byte) (string, error) {
	switch class {
	case ClassRawBytes:
		return RawBytes(raw), nil
	case ClassSemanticJSON:
		return SemanticJSON(value)
	case ClassStorageEnvelope:
		return StorageEnvelope(kind, value)
	default:
		return "", diag.New(
			diag.CodeUnsupportedDigest,
			"unsupported relay-root-digests-v1 digest class.",
			diag.WithDetail("class", class),
		)
	}
}

func deleteNested(object map[string]any, parent string, key string) {
	nested, ok := object[parent].(map[string]any)
	if !ok {
		return
	}
	delete(nested, key)
}

func Validate(expected string, actual string) error {
	if expected != actual {
		return fmt.Errorf("digest mismatch: got %s, want %s", actual, expected)
	}
	return nil
}
