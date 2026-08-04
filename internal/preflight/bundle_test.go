package preflight

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/strictjson"
)

func TestShippedRelayIntegrationBundleReferencedBySkill(t *testing.T) {
	skillBytes, err := os.ReadFile(filepath.Join("..", "..", "skill", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(skillBytes), "skill/bundle/relay-integration-bundle-v2.json") {
		t.Fatal("skill/SKILL.md does not reference the shipped relay integration bundle")
	}
	if _, err := os.Stat(shippedRelayIntegrationBundlePath()); err != nil {
		t.Fatalf("shipped relay integration bundle: %v", err)
	}
}

func TestShippedRelayIntegrationBundleUsesAuthoritativeReducerContract(t *testing.T) {
	bundle := readShippedRelayIntegrationBundle(t)
	if bundle["schema_version"] != "relay-integration-bundle-v2" {
		t.Fatalf("schema_version = %#v, want relay-integration-bundle-v2", bundle["schema_version"])
	}
	contractsValue, ok := bundle["contracts"].(map[string]any)
	if !ok {
		t.Fatalf("contracts = %T, want object", bundle["contracts"])
	}
	wantContracts := []string{
		"witnessed-review/economy-equivalence-v2",
		"witnessed-review/witness-falsification-v2",
	}
	if len(contractsValue) != len(wantContracts) {
		t.Fatalf("contracts = %#v, want exactly %v", mapKeys(contractsValue), wantContracts)
	}
	expectedSchema := decodeReducerSchemaConstant(t)
	for _, contractID := range wantContracts {
		rawContract, ok := contractsValue[contractID]
		if !ok {
			t.Fatalf("bundle missing contract %s", contractID)
		}
		contractObject, ok := rawContract.(map[string]any)
		if !ok {
			t.Fatalf("%s contract = %T, want object", contractID, rawContract)
		}
		assertNoJSONComment(t, contractObject, "/contracts/"+contractID)
		turns, ok := contractObject["turns"].([]any)
		if !ok || len(turns) != 4 {
			t.Fatalf("%s turns = %#v, want exactly four", contractID, contractObject["turns"])
		}
		reducer, ok := contractObject["reducer"].(map[string]any)
		if !ok || reducer["instructions"] != contracts.ReducerBriefText {
			t.Fatalf("%s reducer instructions do not match contracts.ReducerBriefText", contractID)
		}
		promptContext, ok := contractObject["prompt_context"].(map[string]any)
		if !ok || promptContext["participant_transcript"] != "complete" || promptContext["facilitator_ledger"] != "trace_only" {
			t.Fatalf("%s prompt_context = %#v", contractID, contractObject["prompt_context"])
		}
		result, ok := contractObject["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s result = %T, want object", contractID, contractObject["result"])
		}
		if result["transport"] != "json" {
			t.Fatalf("%s result transport = %#v, want json", contractID, result["transport"])
		}
		assertSemanticJSONEqual(t, result["schema"], expectedSchema)
	}
}

func shippedRelayIntegrationBundlePath() string {
	return filepath.Join("..", "..", "skill", "bundle", "relay-integration-bundle-v2.json")
}

func readShippedRelayIntegrationBundle(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(shippedRelayIntegrationBundlePath())
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*64)
	if err != nil {
		t.Fatal(err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("bundle = %T, want object", value)
	}
	return object
}

func decodeReducerSchemaConstant(t *testing.T) any {
	t.Helper()
	value, err := strictjson.DecodeAnyBytes([]byte(contracts.RelayWitnessVerdictsV2SchemaJSON), strictjson.DefaultMaxBytes*32)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertSemanticJSONEqual(t *testing.T, actual any, expected any) {
	t.Helper()
	actualBytes, err := canonjson.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes, err := canonjson.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Fatalf("semantic JSON mismatch\nactual:   %s\nexpected: %s", actualBytes, expectedBytes)
	}
}

func assertNoJSONComment(t *testing.T, value any, path string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$comment" {
				t.Fatalf("bundle schema contains unsupported $comment at %s", path)
			}
			assertNoJSONComment(t, child, path+"/"+key)
		}
	case []any:
		for _, child := range typed {
			assertNoJSONComment(t, child, path+"/*")
		}
	}
}

func mapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
