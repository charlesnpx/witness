package contracts

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/strictjson"
)

type RelayWitnessVerdictsDocument struct {
	SchemaVersion string           `json:"schema_version"`
	BatchID       string           `json:"batch_id"`
	Verdicts      []WitnessVerdict `json:"verdicts"`
}

type WitnessVerdict struct {
	FindingID      string          `json:"finding_id"`
	WitnessDigest  string          `json:"witness_digest"`
	Verdict        string          `json:"verdict"`
	VerdictClass   *string         `json:"verdict_class"`
	CounterWitness *CounterWitness `json:"counter_witness"`
	Rationale      string          `json:"rationale,omitempty"`

	presence witnessVerdictPresence
}

type witnessVerdictPresence struct {
	decoded               bool
	verdictClassPresent   bool
	counterWitnessPresent bool
}

type CounterWitness struct {
	Summary      string        `json:"summary"`
	Evidence     string        `json:"evidence"`
	ArtifactRefs []ArtifactRef `json:"artifact_refs,omitempty"`
	ScopeAnchors []ScopeAnchor `json:"scope_anchors,omitempty"`
}

func (verdict *WitnessVerdict) UnmarshalJSON(data []byte) error {
	type witnessVerdictAlias WitnessVerdict
	var decoded witnessVerdictAlias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*verdict = WitnessVerdict(decoded)
	verdict.presence = witnessVerdictPresence{
		decoded:               true,
		verdictClassPresent:   fields["verdict_class"] != nil,
		counterWitnessPresent: fields["counter_witness"] != nil,
	}
	return nil
}

func ReadRelayWitnessVerdicts(reader io.Reader) (RelayWitnessVerdictsDocument, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return RelayWitnessVerdictsDocument{}, err
	}
	return ReadRelayWitnessVerdictsBytes(data)
}

func ReadRelayWitnessVerdictsBytes(data []byte) (RelayWitnessVerdictsDocument, error) {
	if err := rejectExecutionAttestationFields(data); err != nil {
		return RelayWitnessVerdictsDocument{}, err
	}
	return strictjson.DecodeBytes[RelayWitnessVerdictsDocument](data, strictjson.DefaultMaxBytes)
}

func RequireValidRelayWitnessVerdicts(document RelayWitnessVerdictsDocument, batch *VerificationBatchDocument) error {
	return ErrorFromDiagnostics(ValidateRelayWitnessVerdicts(document, batch))
}

func ValidateRelayWitnessVerdicts(document RelayWitnessVerdictsDocument, batch *VerificationBatchDocument) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != RelayWitnessVerdictsV2 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidRelayVerdicts,
			"relay witness verdicts schema_version must be relay-witness-verdicts-v2.",
			"/schema_version",
			map[string]any{"expected": RelayWitnessVerdictsV2, "actual": document.SchemaVersion},
		))
	}
	requireStableID(&diagnostics, "/batch_id", "batch ID", document.BatchID)
	if batch != nil && document.BatchID != batch.BatchID {
		diagnostics = append(diagnostics, diagnostic(
			CodeCoverageMismatch,
			"relay witness verdicts batch_id must match the verification batch.",
			"/batch_id",
			map[string]any{"actual": document.BatchID, "expected": batch.BatchID},
		))
	}

	expected := map[string]string{}
	if batch != nil {
		for _, finding := range batch.Findings {
			expected[finding.FindingID] = finding.WitnessDigest
		}
	}
	seen := map[string]int{}
	for index, verdict := range document.Verdicts {
		path := "/verdicts/" + itoa(index)
		diagnostics = append(diagnostics, validateWitnessVerdict(verdict, path)...)
		if first, exists := seen[verdict.FindingID]; exists {
			diagnostics = append(diagnostics, diagnostic(
				CodeCoverageMismatch,
				"relay witness verdicts must contain exactly one verdict per finding ID.",
				path+"/finding_id",
				map[string]any{"finding_id": verdict.FindingID, "duplicate_of": "/verdicts/" + itoa(first) + "/finding_id"},
			))
		}
		seen[verdict.FindingID] = index
		if batch != nil {
			expectedDigest, exists := expected[verdict.FindingID]
			if !exists {
				diagnostics = append(diagnostics, diagnostic(
					CodeCoverageMismatch,
					"relay witness verdicts contain an unexpected finding ID.",
					path+"/finding_id",
					map[string]any{"finding_id": verdict.FindingID},
				))
				continue
			}
			compareDigest(&diagnostics, path+"/witness_digest", "verdict witness", verdict.WitnessDigest, expectedDigest)
		}
	}
	if batch != nil {
		for _, id := range sortedStringKeys(expected) {
			if _, exists := seen[id]; !exists {
				diagnostics = append(diagnostics, diagnostic(
					CodeCoverageMismatch,
					"relay witness verdicts are missing a planned finding ID.",
					"/verdicts",
					map[string]any{"finding_id": id},
				))
			}
		}
	}
	return diagnostics
}

func validateWitnessVerdict(verdict WitnessVerdict, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/finding_id", "finding ID", verdict.FindingID)
	requireDigest(&diagnostics, path+"/witness_digest", "witness digest", verdict.WitnessDigest)
	requireEnum(&diagnostics, path+"/verdict", "verdict", verdict.Verdict, stringSet(VerdictSurvived, VerdictWeakened, VerdictBroken), CodeInvalidRelayVerdicts)
	if verdict.presence.decoded {
		if !verdict.presence.verdictClassPresent {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "verdict_class is required by the relay reducer schema.", path+"/verdict_class", nil))
		}
		if !verdict.presence.counterWitnessPresent {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "counter_witness is required by the relay reducer schema.", path+"/counter_witness", nil))
		}
	}
	if verdict.Verdict == VerdictSurvived {
		if verdict.VerdictClass != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "verdict_class must be null when verdict is survived.", path+"/verdict_class", map[string]any{"verdict": verdict.Verdict}))
		}
		if verdict.CounterWitness != nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "counter_witness must be null when verdict is survived.", path+"/counter_witness", map[string]any{"verdict": verdict.Verdict}))
		}
		return diagnostics
	}
	if verdict.Verdict == VerdictWeakened || verdict.Verdict == VerdictBroken {
		if verdict.VerdictClass == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "verdict_class is required for weakened and broken verdicts.", path+"/verdict_class", map[string]any{"verdict": verdict.Verdict}))
		} else {
			class := *verdict.VerdictClass
			requireEnum(&diagnostics, path+"/verdict_class", "verdict_class", class, stringSet(VerdictClassLogic, VerdictClassUnreachable, VerdictClassOutsideEnvelope, VerdictClassMissingPremise, VerdictClassOther), CodeInvalidRelayVerdicts)
			if (class == VerdictClassUnreachable || class == VerdictClassOutsideEnvelope) && verdict.Verdict != VerdictBroken {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidRelayVerdicts,
					"unreachable and outside_envelope verdict classes are valid only with broken verdicts.",
					path+"/verdict_class",
					map[string]any{"verdict": verdict.Verdict, "verdict_class": class},
				))
			}
		}
		if verdict.CounterWitness == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRelayVerdicts, "weakened and broken verdicts require a concrete counter-witness.", path+"/counter_witness", map[string]any{"verdict": verdict.Verdict}))
		} else {
			diagnostics = append(diagnostics, validateCounterWitness(*verdict.CounterWitness, path+"/counter_witness")...)
		}
	}
	return diagnostics
}

func validateCounterWitness(counter CounterWitness, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireString(&diagnostics, path+"/summary", "counter-witness summary", counter.Summary)
	requireString(&diagnostics, path+"/evidence", "counter-witness evidence", counter.Evidence)
	for index, ref := range counter.ArtifactRefs {
		diagnostics = append(diagnostics, prefixDiagnostics(path+"/artifact_refs/"+itoa(index), validateArtifactRef(ref, ""))...)
	}
	return diagnostics
}

func RelayWitnessVerdictsDigest(document RelayWitnessVerdictsDocument) (string, error) {
	return SemanticDigest(document)
}

func RelayWitnessVerdictsCanonicalBytes(document RelayWitnessVerdictsDocument) ([]byte, error) {
	return CanonicalBytes(document)
}

func rejectExecutionAttestationFields(data []byte) error {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return err
	}
	if diagnostic, ok := scanForbiddenExecutionFields(value, ""); ok {
		return diag.New(diagnostic.Code, diagnostic.Message, diag.WithPath(diagnostic.Path), diag.WithDetails(diagnostic.Details))
	}
	return nil
}

func scanForbiddenExecutionFields(value any, path string) (diag.Diagnostic, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range sortedAnyKeys(typed) {
			child := typed[key]
			childPath := appendPointer(path, key)
			if hasForbiddenExecutionFieldName(key) {
				return diagnostic(
					CodeForbiddenExecutionField,
					"relay witness verdicts must not contain execution attestation or execution contradiction fields.",
					childPath,
					map[string]any{"field": key},
				), true
			}
			if diagnostic, ok := scanForbiddenExecutionFields(child, childPath); ok {
				return diagnostic, true
			}
		}
	case []any:
		for index, child := range typed {
			if diagnostic, ok := scanForbiddenExecutionFields(child, path+"/"+itoa(index)); ok {
				return diagnostic, true
			}
		}
	}
	return diag.Diagnostic{}, false
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedAnyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
