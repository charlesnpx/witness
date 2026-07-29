package digest

import (
	"os"
	"path/filepath"
	"testing"

	"witness/internal/canonjson"
	"witness/internal/strictjson"
)

type relayDigestFixtures struct {
	SchemaVersion     string              `json:"schema_version"`
	Cases             []relayDigestCase   `json:"cases"`
	EquivalentNumbers equivalentNumberSet `json:"equivalent_numbers"`
}

type relayDigestCase struct {
	ID        string `json:"id"`
	Class     string `json:"class"`
	UTF8      string `json:"utf8,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Value     any    `json:"value,omitempty"`
	Canonical string `json:"canonical,omitempty"`
	Digest    string `json:"digest"`
}

type equivalentNumberSet struct {
	JSON      []string `json:"json"`
	Canonical string   `json:"canonical"`
	Digest    string   `json:"digest"`
}

func TestRelayRootDigestsV1Fixtures(t *testing.T) {
	fixture := loadRelayFixture(t)
	if fixture.SchemaVersion != "relay-root-digest-fixtures-v1" {
		t.Fatalf("schema_version = %q", fixture.SchemaVersion)
	}
	for _, item := range fixture.Cases {
		t.Run(item.ID, func(t *testing.T) {
			var (
				got string
				err error
			)
			switch item.Class {
			case ClassRawBytes:
				got = RawBytes([]byte(item.UTF8))
			case ClassSemanticJSON:
				var canonical []byte
				canonical, err = canonjson.Marshal(item.Value)
				if err == nil && string(canonical) != item.Canonical {
					t.Fatalf("canonical = %q, want %q", canonical, item.Canonical)
				}
				if err == nil {
					got, err = SemanticJSON(item.Value)
				}
			case ClassStorageEnvelope:
				var canonicalValue any
				canonicalValue, err = projectedStorageEnvelope(item.Kind, item.Value)
				if err == nil {
					var canonical []byte
					canonical, err = canonjson.Marshal(canonicalValue)
					if err == nil && string(canonical) != item.Canonical {
						t.Fatalf("canonical = %q, want %q", canonical, item.Canonical)
					}
				}
				if err == nil {
					got, err = StorageEnvelope(item.Kind, item.Value)
				}
			default:
				t.Fatalf("unknown fixture class %q", item.Class)
			}
			if err != nil {
				t.Fatalf("digest error: %v", err)
			}
			if got != item.Digest {
				t.Fatalf("digest = %s, want %s", got, item.Digest)
			}
		})
	}
}

func TestEquivalentNumberDigests(t *testing.T) {
	fixture := loadRelayFixture(t)
	for _, raw := range fixture.EquivalentNumbers.JSON {
		t.Run(raw, func(t *testing.T) {
			value, err := strictjson.DecodeAnyBytes([]byte(raw), strictjson.DefaultMaxBytes)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			canonical, err := canonjson.Marshal(value)
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			if string(canonical) != fixture.EquivalentNumbers.Canonical {
				t.Fatalf("canonical = %s, want %s", canonical, fixture.EquivalentNumbers.Canonical)
			}
			got, err := SemanticJSONBytes([]byte(raw))
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if got != fixture.EquivalentNumbers.Digest {
				t.Fatalf("digest = %s, want %s", got, fixture.EquivalentNumbers.Digest)
			}
		})
	}
}

func TestStorageEnvelopeUsesOnlyExactExecutionWorkspaceExclusions(t *testing.T) {
	workspace := map[string]any{
		"kind":           "execution_workspace",
		"schema_version": 2,
		"digest_profile": Profile,
		"identity":       map[string]any{"session_dir": "/one"},
		"base":           map[string]any{"head_commit": "abc"},
		"source":         map[string]any{"git_root": "/source", "launch_cwd": "/source/sub", "launch_subpath": "sub"},
	}
	first, err := StorageEnvelope("execution_workspace", workspace)
	if err != nil {
		t.Fatal(err)
	}
	workspace["identity"] = map[string]any{"session_dir": "/two"}
	workspace["source"].(map[string]any)["launch_cwd"] = "/different"
	second, err := StorageEnvelope("execution_workspace", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("runtime-only fields changed digest: %s != %s", first, second)
	}
	workspace["source"].(map[string]any)["launch_subpath"] = "other"
	third, err := StorageEnvelope("execution_workspace", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if second == third {
		t.Fatal("semantic field launch_subpath did not change digest")
	}
}

func loadRelayFixture(t *testing.T) relayDigestFixtures {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "relay", "relay-root-digests-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := strictjson.DecodeBytes[relayDigestFixtures](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func projectedStorageEnvelope(kind string, value any) (any, error) {
	materialized, err := canonjson.Materialize(value)
	if err != nil {
		return nil, err
	}
	object := materialized.(map[string]any)
	if kind == "execution_workspace" {
		delete(object, "identity")
		if source, ok := object["source"].(map[string]any); ok {
			delete(source, "git_root")
			delete(source, "launch_cwd")
		}
		if sourceAfter, ok := object["source_after"].(map[string]any); ok {
			delete(sourceAfter, "git_root")
			delete(sourceAfter, "launch_cwd")
		}
	}
	return object, nil
}
