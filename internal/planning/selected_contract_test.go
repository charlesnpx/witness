package planning

import (
	"testing"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
)

func TestAuthenticatedSelectedContractsRejectsTamperedWitnessContractDigest(t *testing.T) {
	contractBody := map[string]any{
		"id":     "witnessed-review/test-contract-v1",
		"status": "retained",
	}
	payload := map[string]any{
		"contract_id":     "witnessed-review/test-contract-v1",
		"contract_digest": digest.RawBytes([]byte("wrong witness digest")),
		"contract":        contractBody,
	}

	_, err := AuthenticatedSelectedContractsFromBytes(canonjson.MustMarshal(payload))
	if err == nil {
		t.Fatal("AuthenticatedSelectedContractsFromBytes accepted a tampered Witness contract_digest")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeInvalidSelectedContract {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeInvalidSelectedContract)
	}
	if got := diagnostic.Details["contract_id"]; got != "witnessed-review/test-contract-v1" {
		t.Fatalf("contract_id detail = %v", got)
	}
	if got := diagnostic.Details["expected_digest"]; got != payload["contract_digest"] {
		t.Fatalf("expected_digest = %v, want %v", got, payload["contract_digest"])
	}
}

func TestAuthenticatedSelectedContractsRejectsDigestOnlyEvidence(t *testing.T) {
	payload := map[string]any{
		"contract_digests": map[string]any{
			"witnessed-review/test-contract-v1": digest.RawBytes([]byte("relay projection")),
		},
	}

	_, err := AuthenticatedSelectedContractsFromBytes(canonjson.MustMarshal(payload))
	if err == nil {
		t.Fatal("AuthenticatedSelectedContractsFromBytes accepted digest-only selected-contract evidence")
	}
	diagnostic := diag.FromError(err)
	if diagnostic.Code != CodeInvalidSelectedContract {
		t.Fatalf("diagnostic = %#v, want %s", diagnostic, CodeInvalidSelectedContract)
	}
}
