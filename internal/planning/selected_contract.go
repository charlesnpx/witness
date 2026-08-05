package planning

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/strictjson"
)

type SelectedContractEvidence struct {
	Ref        contracts.ArtifactRef `json:"ref"`
	ContractID string                `json:"contract_id"`
	Path       string                `json:"path,omitempty"`
	RawBytes   []byte                `json:"-"`
}

const CodeInvalidSelectedContract = "assemble_invalid_selected_contract"

type AuthenticatedSelectedContract struct {
	ContractID     string
	ContractDigest string
}

func AuthenticatedSelectedContractsFromBytes(data []byte) ([]AuthenticatedSelectedContract, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, diag.New(CodeInvalidSelectedContract, "selected-contract evidence must be a JSON object.")
	}
	contracts, err := authenticatedSelectedContractsFromObject(object)
	if err != nil {
		return nil, err
	}
	if len(contracts) == 0 {
		return nil, diag.New(CodeInvalidSelectedContract, "selected-contract evidence must retain contract bodies; digest-only selected-contract artifacts are not accepted.")
	}
	sort.Slice(contracts, func(i, j int) bool {
		return contracts[i].ContractID < contracts[j].ContractID
	})
	return contracts, nil
}

func authenticatedSelectedContractsFromObject(object map[string]any) ([]AuthenticatedSelectedContract, error) {
	if _, hasPayloadDigest := object["payload_digest"]; hasPayloadDigest {
		payload, hasPayload := object["payload"]
		if !hasPayload {
			return nil, diag.New(CodeInvalidSelectedContract, "selected-contract retained envelope payload_digest requires a retained payload.")
		}
		claimedPayloadDigest := strings.TrimSpace(selectedStringValue(object["payload_digest"]))
		payloadBytes, err := canonjson.Marshal(payload)
		if err != nil {
			return nil, err
		}
		actualPayloadDigest := digest.RawBytes(payloadBytes)
		if claimedPayloadDigest == "" || claimedPayloadDigest != actualPayloadDigest {
			return nil, diag.New(
				CodeInvalidSelectedContract,
				"selected-contract retained envelope payload_digest does not match the retained payload.",
				diag.WithDetail("actual_digest", actualPayloadDigest),
				diag.WithDetail("expected_digest", claimedPayloadDigest),
			)
		}
		payloadObject, ok := payload.(map[string]any)
		if !ok || payloadObject == nil {
			return nil, diag.New(CodeInvalidSelectedContract, "selected-contract retained envelope payload must be a JSON object.")
		}
		return authenticatedSelectedContractsFromObject(payloadObject)
	}

	found := map[string]AuthenticatedSelectedContract{}
	if contractBody, ok := object["contract"].(map[string]any); ok && contractBody != nil {
		contract, err := authenticateContractBody(object, contractBody, "")
		if err != nil {
			return nil, err
		}
		found[contract.ContractID] = contract
	}
	if rawContracts, ok := object["contracts"].(map[string]any); ok {
		for contractID, raw := range rawContracts {
			contract, err := authenticateContractEntry(contractID, raw)
			if err != nil {
				return nil, err
			}
			found[contract.ContractID] = contract
		}
	}
	if rawDigests, ok := object["contract_digests"].(map[string]any); ok {
		if len(found) == 0 {
			return nil, diag.New(CodeInvalidSelectedContract, "selected-contract evidence must include contract bodies; contract_digests alone are not authenticated evidence.")
		}
		for contractID, rawDigest := range rawDigests {
			if contractID == "" || contractID == "integration_bundle" {
				continue
			}
			claimedDigest := strings.TrimSpace(selectedStringValue(rawDigest))
			if claimedDigest == "" {
				continue
			}
			if contract, ok := found[contractID]; ok && contract.ContractDigest != claimedDigest {
				return nil, diag.New(
					CodeInvalidSelectedContract,
					"selected-contract claimed contract_digest does not match the retained contract body.",
					diag.WithDetail("contract_id", contractID),
					diag.WithDetail("actual_digest", contract.ContractDigest),
					diag.WithDetail("expected_digest", claimedDigest),
				)
			}
		}
	}
	contracts := make([]AuthenticatedSelectedContract, 0, len(found))
	for _, contract := range found {
		contracts = append(contracts, contract)
	}
	return contracts, nil
}

func authenticateContractEntry(contractID string, raw any) (AuthenticatedSelectedContract, error) {
	object, ok := raw.(map[string]any)
	if !ok || object == nil {
		return AuthenticatedSelectedContract{}, diag.New(
			CodeInvalidSelectedContract,
			"selected-contract contract entry must retain a JSON contract body.",
			diag.WithDetail("contract_id", contractID),
		)
	}
	if contractBody, ok := object["contract"].(map[string]any); ok && contractBody != nil {
		return authenticateContractBody(object, contractBody, contractID)
	}
	return authenticateContractBody(nil, object, contractID)
}

func authenticateContractBody(wrapper map[string]any, contractBody map[string]any, fallbackID string) (AuthenticatedSelectedContract, error) {
	wrapperID := ""
	claimedDigest := ""
	if wrapper != nil {
		wrapperID = firstNonEmptySelectedString(wrapper["contract_id"], wrapper["id"])
		claimedDigest = strings.TrimSpace(selectedStringValue(wrapper["contract_digest"]))
	}
	bodyID := strings.TrimSpace(selectedStringValue(contractBody["id"]))
	fallbackID = strings.TrimSpace(fallbackID)
	contractID := firstNonEmptyText(wrapperID, bodyID, fallbackID)
	if contractID == "" {
		return AuthenticatedSelectedContract{}, diag.New(CodeInvalidSelectedContract, "selected-contract body requires a contract id.")
	}
	if fallbackID != "" && contractID != fallbackID {
		return AuthenticatedSelectedContract{}, diag.New(CodeInvalidSelectedContract, "selected-contract body id does not match the contract map key.", diag.WithDetail("contract_id", contractID), diag.WithDetail("map_key", fallbackID))
	}
	if wrapperID != "" && wrapperID != contractID {
		return AuthenticatedSelectedContract{}, diag.New(CodeInvalidSelectedContract, "selected-contract wrapper contract_id does not match the selected contract.", diag.WithDetail("contract_id", contractID), diag.WithDetail("wrapper_id", wrapperID))
	}
	if bodyID != "" && bodyID != contractID {
		return AuthenticatedSelectedContract{}, diag.New(CodeInvalidSelectedContract, "selected-contract body id does not match the selected contract.", diag.WithDetail("contract_id", contractID), diag.WithDetail("body_id", bodyID))
	}
	contractDigest, err := digest.SemanticJSON(contractBody)
	if err != nil {
		return AuthenticatedSelectedContract{}, err
	}
	if claimedDigest != "" && claimedDigest != contractDigest {
		return AuthenticatedSelectedContract{}, diag.New(
			CodeInvalidSelectedContract,
			"selected-contract claimed contract_digest does not match the retained contract body.",
			diag.WithDetail("contract_id", contractID),
			diag.WithDetail("actual_digest", contractDigest),
			diag.WithDetail("expected_digest", claimedDigest),
		)
	}
	return AuthenticatedSelectedContract{
		ContractID:     contractID,
		ContractDigest: contractDigest,
	}, nil
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonEmptySelectedString(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(selectedStringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func selectedStringValue(value any) string {
	text, _ := value.(string)
	return text
}

func selectedContractEvidenceDigestPresent(evidence []SelectedContractEvidence, digestValue string) (bool, error) {
	if strings.TrimSpace(digestValue) == "" {
		return false, nil
	}
	if len(evidence) == 0 {
		return false, diag.New(CodeInvalidSelectedContract, "selected-contract evidence must include retained contract bytes; digest-only selected-contract references are not accepted.")
	}
	for _, item := range evidence {
		if len(item.RawBytes) == 0 {
			return false, diag.New(CodeInvalidSelectedContract, "selected-contract evidence is missing retained bytes.", diag.WithDetail("contract_id", item.ContractID), diag.WithDetail("ref_id", item.Ref.ID))
		}
		contracts, err := AuthenticatedSelectedContractsFromBytes(item.RawBytes)
		if err != nil {
			return false, err
		}
		for _, contract := range contracts {
			if item.ContractID != "" && contract.ContractID != item.ContractID {
				continue
			}
			if item.Ref.Digest != "" && item.Ref.Digest != contract.ContractDigest {
				return false, diag.New(
					CodeInvalidSelectedContract,
					"selected-contract manifest reference digest does not match the retained contract body.",
					diag.WithDetail("contract_id", contract.ContractID),
					diag.WithDetail("actual_digest", contract.ContractDigest),
					diag.WithDetail("witness_digest", contract.ContractDigest),
					diag.WithDetail("ref_digest", item.Ref.Digest),
					diag.WithDetail("relay_reported_digest", item.Ref.Digest),
				)
			}
			if contract.ContractDigest == digestValue {
				return true, nil
			}
		}
	}
	return false, nil
}

func selectedContractDigestClaimed(refs []contracts.ArtifactRef, digestValue string) bool {
	digestValue = strings.TrimSpace(digestValue)
	if digestValue == "" {
		return false
	}
	for _, ref := range refs {
		if ref.Digest == digestValue {
			return true
		}
	}
	return false
}

func selectedContractManifestDiagnostics(refs []contracts.ArtifactRef, evidence []SelectedContractEvidence) []diag.Diagnostic {
	diagnostics := selectedContractEvidenceDiagnostics(evidence)
	if len(diagnostics) > 0 {
		return diagnostics
	}
	authenticatedDigests := map[string]bool{}
	for _, item := range evidence {
		authenticated, err := AuthenticatedSelectedContractsFromBytes(item.RawBytes)
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
			continue
		}
		for _, contract := range authenticated {
			if item.ContractID != "" && contract.ContractID != item.ContractID {
				continue
			}
			authenticatedDigests[contract.ContractDigest] = true
		}
	}
	for _, ref := range refs {
		if strings.TrimSpace(ref.Digest) == "" {
			continue
		}
		if authenticatedDigests[ref.Digest] {
			continue
		}
		diagnostics = append(diagnostics, diag.FromError(diag.New(
			CodeInvalidSelectedContract,
			"selected-contract manifest reference digest does not match authenticated retained selected-contract evidence.",
			diag.WithDetail("ref_id", ref.ID),
			diag.WithDetail("ref_digest", ref.Digest),
		)))
	}
	return diagnostics
}

func SelectedContractManifestDiagnostics(refs []contracts.ArtifactRef, evidence []SelectedContractEvidence) []diag.Diagnostic {
	return selectedContractManifestDiagnostics(refs, evidence)
}

func selectedContractEvidenceDiagnostics(evidence []SelectedContractEvidence) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, item := range evidence {
		if len(item.RawBytes) == 0 {
			diagnostics = append(diagnostics, diag.FromError(diag.New(CodeInvalidSelectedContract, "selected-contract evidence is missing retained bytes.", diag.WithDetail("contract_id", item.ContractID), diag.WithDetail("ref_id", item.Ref.ID))))
			continue
		}
		contracts, err := AuthenticatedSelectedContractsFromBytes(item.RawBytes)
		if err != nil {
			diagnostics = append(diagnostics, diag.FromError(err))
			continue
		}
		matchedRef := false
		for _, contract := range contracts {
			if item.ContractID != "" && contract.ContractID != item.ContractID {
				continue
			}
			matchedRef = true
			if item.Ref.Digest != "" && item.Ref.Digest != contract.ContractDigest {
				diagnostics = append(diagnostics, diag.FromError(diag.New(
					CodeInvalidSelectedContract,
					"selected-contract manifest reference digest does not match the retained contract body.",
					diag.WithDetail("contract_id", contract.ContractID),
					diag.WithDetail("actual_digest", contract.ContractDigest),
					diag.WithDetail("witness_digest", contract.ContractDigest),
					diag.WithDetail("ref_digest", item.Ref.Digest),
					diag.WithDetail("relay_reported_digest", item.Ref.Digest),
				)))
			}
		}
		if !matchedRef {
			diagnostics = append(diagnostics, diag.FromError(diag.New(
				CodeInvalidSelectedContract,
				fmt.Sprintf("selected-contract evidence did not retain contract %q.", item.ContractID),
				diag.WithDetail("contract_id", item.ContractID),
				diag.WithDetail("ref_id", item.Ref.ID),
			)))
		}
	}
	return diagnostics
}
