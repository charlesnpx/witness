package contracts

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"witness/internal/charter"
	"witness/internal/diag"
	"witness/internal/strictjson"
)

type ScopeAnchor = charter.ScopeAnchor
type MissingGoalQuestion = charter.MissingGoalQuestion

type RoleOutputDocument struct {
	SchemaVersion        string                `json:"schema_version"`
	Role                 string                `json:"role"`
	CharterHash          string                `json:"charter_hash"`
	ArtifactDigest       string                `json:"artifact_digest"`
	SourceIdentity       map[string]any        `json:"source_identity"`
	ConsumerIdentity     map[string]any        `json:"consumer_identity"`
	Findings             []Finding             `json:"findings"`
	MissingGoalQuestions []MissingGoalQuestion `json:"missing_goal_questions,omitempty"`
}

type Finding struct {
	ID                       string                   `json:"id"`
	Kind                     string                   `json:"kind"`
	Title                    string                   `json:"title"`
	CharterGoalIDs           []string                 `json:"charter_goal_ids"`
	ClaimedSeverity          string                   `json:"claimed_severity"`
	ScopeAnchors             []ScopeAnchor            `json:"scope_anchors,omitempty"`
	Witness                  Witness                  `json:"witness"`
	EstimatedDelta           SplitDeltaEstimate       `json:"estimated_delta"`
	SmallestSufficientRemedy SmallestSufficientRemedy `json:"smallest_sufficient_remedy"`
	ProposedTests            []ProposedTest           `json:"proposed_tests,omitempty"`
	Recurrence               *RecurrenceRef           `json:"recurrence,omitempty"`

	canonicalJSON json.RawMessage
}

type Witness struct {
	Kind              string          `json:"kind"`
	Strength          string          `json:"strength"`
	Content           string          `json:"content"`
	ArtifactRefs      []ArtifactRef   `json:"artifact_refs,omitempty"`
	Executable        *ExecutableSpec `json:"executable,omitempty"`
	EntryPoint        *ScopeAnchor    `json:"entry_point,omitempty"`
	ReachabilityChain []ScopeAnchor   `json:"reachability_chain,omitempty"`

	canonicalJSON json.RawMessage
}

type ExecutableSpec struct {
	Argv                []string     `json:"argv"`
	CWD                 string       `json:"cwd"`
	ExpectedObservation string       `json:"expected_observation"`
	TransformationRef   *ArtifactRef `json:"transformation_ref,omitempty"`
}

type SplitDeltaEstimate struct {
	Production DeltaEstimate `json:"production"`
	Test       DeltaEstimate `json:"test"`
}

type DeltaEstimate struct {
	Status string `json:"status"`
	Lines  int    `json:"lines,omitempty"`
	Files  int    `json:"files,omitempty"`
}

func (finding *Finding) UnmarshalJSON(data []byte) error {
	type findingAlias Finding
	var decoded findingAlias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	canonical, err := canonicalFindingRawMessage(data, Finding(decoded))
	if err != nil {
		return err
	}
	*finding = Finding(decoded)
	finding.canonicalJSON = canonical
	return nil
}

func (witness *Witness) UnmarshalJSON(data []byte) error {
	type witnessAlias Witness
	var decoded witnessAlias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	canonical, err := canonicalRawMessage(data)
	if err != nil {
		return err
	}
	*witness = Witness(decoded)
	witness.canonicalJSON = canonical
	return nil
}

func (delta *DeltaEstimate) UnmarshalJSON(data []byte) error {
	type deltaEstimateAlias DeltaEstimate
	var decoded deltaEstimateAlias
	if err := decodeStrictContractJSON(data, &decoded); err != nil {
		return err
	}
	if decoded.Status != DeltaStatusKnown && decoded.Status != DeltaStatusUnknown {
		*delta = DeltaEstimate{Status: DeltaStatusUnknown}
		return nil
	}
	*delta = DeltaEstimate(decoded)
	return nil
}

type SmallestSufficientRemedy struct {
	Direction          string   `json:"direction"`
	Summary            string   `json:"summary"`
	MinimalityArgument string   `json:"minimality_argument"`
	TouchedProduction  []string `json:"touched_production,omitempty"`
	TouchedTests       []string `json:"touched_tests,omitempty"`
}

type ProposedTest struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	ReachablePartition string       `json:"reachable_partition"`
	CharterRefs        []CharterRef `json:"charter_refs"`
}

type CharterRef struct {
	GoalID string       `json:"goal_id,omitempty"`
	Anchor *ScopeAnchor `json:"anchor,omitempty"`
}

type RecurrenceRef struct {
	PriorFindingID string `json:"prior_finding_id"`
	FindingKey     string `json:"finding_key"`
	WitnessDigest  string `json:"witness_digest"`
	ArtifactDigest string `json:"artifact_digest"`
}

func ReadRoleOutput(reader io.Reader) (RoleOutputDocument, error) {
	return strictjson.Decode[RoleOutputDocument](reader, strictjson.DefaultMaxBytes)
}

func ReadRoleOutputBytes(data []byte) (RoleOutputDocument, error) {
	return strictjson.DecodeBytes[RoleOutputDocument](data, strictjson.DefaultMaxBytes)
}

func RequireValidRoleOutput(document RoleOutputDocument, frozen *charter.FrozenCharter) error {
	return ErrorFromDiagnostics(ValidateRoleOutput(document, frozen))
}

func ValidateRoleOutput(document RoleOutputDocument, frozen *charter.FrozenCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if document.SchemaVersion != RoleOutputV3 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidRoleOutput,
			"role-output document schema_version must be review-role-output-v3.",
			"/schema_version",
			map[string]any{"expected": RoleOutputV3, "actual": document.SchemaVersion},
		))
	}
	requireEnum(&diagnostics, "/role", "role", document.Role, stringSet(RoleDefect, RoleEconomy, RoleGoalFit), CodeInvalidRoleOutput)
	requireDigest(&diagnostics, "/charter_hash", "charter_hash", document.CharterHash)
	requireDigest(&diagnostics, "/artifact_digest", "artifact_digest", document.ArtifactDigest)
	if frozen != nil {
		compareDigest(&diagnostics, "/charter_hash", "charter", document.CharterHash, frozen.CharterHash)
	}
	if !identityPresent(document.SourceIdentity) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "source_identity is required.", "/source_identity", nil))
	}
	if !identityPresent(document.ConsumerIdentity) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "consumer_identity is required.", "/consumer_identity", nil))
	}
	if document.Role == RoleGoalFit && len(document.Findings) > 0 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidRoleOutput,
			"goal-fit role output must not contain findings.",
			"/findings",
			nil,
		))
	}
	if (document.Role == RoleDefect || document.Role == RoleEconomy) && document.Findings == nil {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidRoleOutput,
			"defect and economy role outputs require a findings array.",
			"/findings",
			nil,
		))
	}

	questions := map[string]MissingGoalQuestion{}
	questionPaths := map[string]string{}
	for index, question := range document.MissingGoalQuestions {
		path := "/missing_goal_questions/" + itoa(index)
		diagnostics = append(diagnostics, validateMissingGoalQuestion(question, path)...)
		if firstPath, exists := questionPaths[question.ID]; exists {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidRoleOutput,
				"missing-goal question IDs must be unique.",
				path+"/id",
				map[string]any{"id": question.ID, "duplicate_of": firstPath + "/id"},
			))
		}
		questions[question.ID] = question
		questionPaths[question.ID] = path
	}
	goalIDs := charterGoalIDs(frozen)
	seenFindings := map[string]int{}
	for index, finding := range document.Findings {
		path := "/findings/" + itoa(index)
		if first, exists := seenFindings[finding.ID]; exists {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidRoleOutput,
				"finding IDs must be unique.",
				path+"/id",
				map[string]any{"id": finding.ID, "duplicate_of": "/findings/" + itoa(first) + "/id"},
			))
		}
		seenFindings[finding.ID] = index
		diagnostics = append(diagnostics, validateFinding(document.Role, finding, path, frozen, goalIDs, questions, questionPaths)...)
	}
	return diagnostics
}

func RoleOutputDigest(document RoleOutputDocument) (string, error) {
	return SemanticDigest(document)
}

func RoleOutputCanonicalBytes(document RoleOutputDocument) ([]byte, error) {
	return CanonicalBytes(document)
}

func canonicalFindingJSON(finding Finding) (json.RawMessage, error) {
	return canonicalJSONWithVerifiedCache(finding, finding.canonicalJSON, "finding")
}

func canonicalWitnessJSON(witness Witness) (json.RawMessage, error) {
	return canonicalJSONWithVerifiedCache(witness, witness.canonicalJSON, "witness")
}

func canonicalFindingRawMessage(data []byte, finding Finding) (json.RawMessage, error) {
	canonical, err := canonicalRawMessage(data)
	if err != nil {
		return nil, err
	}
	return canonicalFindingCacheWithNormalizedDelta(canonical, finding)
}

func canonicalFindingCacheWithNormalizedDelta(cached json.RawMessage, finding Finding) (json.RawMessage, error) {
	cachedValue, err := decodeCanonicalJSONValue(cached)
	if err != nil {
		return nil, err
	}
	cachedObject, ok := cachedValue.(map[string]any)
	if !ok {
		return append(json.RawMessage(nil), cached...), nil
	}
	if !normalizeCachedSplitDelta(cachedObject["estimated_delta"], finding.EstimatedDelta) {
		return append(json.RawMessage(nil), cached...), nil
	}
	canonical, err := CanonicalBytes(cachedValue)
	if err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), canonical...), nil
}

func normalizeCachedSplitDelta(cached any, delta SplitDeltaEstimate) bool {
	cachedObject, ok := cached.(map[string]any)
	if !ok {
		return false
	}
	changed := normalizeCachedDeltaComponent(cachedObject, "production", delta.Production)
	return normalizeCachedDeltaComponent(cachedObject, "test", delta.Test) || changed
}

func normalizeCachedDeltaComponent(parent map[string]any, key string, delta DeltaEstimate) bool {
	component, ok := parent[key].(map[string]any)
	if !ok {
		return false
	}
	status, ok := component["status"].(string)
	if !ok || status == DeltaStatusKnown || status == DeltaStatusUnknown {
		return false
	}
	parent[key] = cachedDeltaEstimateValue(delta)
	return true
}

func cachedDeltaEstimateValue(delta DeltaEstimate) map[string]any {
	value := map[string]any{"status": delta.Status}
	if delta.Lines != 0 {
		value["lines"] = delta.Lines
	}
	if delta.Files != 0 {
		value["files"] = delta.Files
	}
	return value
}

func validateFinding(role string, finding Finding, path string, frozen *charter.FrozenCharter, goalIDs map[string]bool, questions map[string]MissingGoalQuestion, questionPaths map[string]string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/id", "finding ID", finding.ID)
	requireString(&diagnostics, path+"/title", "finding title", finding.Title)
	requireEnum(&diagnostics, path+"/claimed_severity", "claimed_severity", finding.ClaimedSeverity, stringSet(SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow), CodeInvalidRoleOutput)
	if len(finding.CharterGoalIDs) == 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "findings must name at least one Charter goal.", path+"/charter_goal_ids", nil))
	}
	for goalIndex, goalID := range finding.CharterGoalIDs {
		goalPath := path + "/charter_goal_ids/" + itoa(goalIndex)
		requireStableID(&diagnostics, goalPath, "Charter goal ID", goalID)
		if goalIDs != nil && !goalIDs[goalID] {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidRoleOutput,
				"finding references a Charter goal that is not declared.",
				goalPath,
				map[string]any{"goal_id": goalID},
			))
		}
	}
	switch role {
	case RoleDefect:
		if finding.Kind != FindingKindDefect {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "defect role findings must have kind defect.", path+"/kind", map[string]any{"kind": finding.Kind}))
		}
		if finding.Witness.Kind != WitnessKindDefect {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "defect findings require defect witnesses.", path+"/witness/kind", map[string]any{"kind": finding.Witness.Kind}))
		}
	case RoleEconomy:
		if finding.Kind != FindingKindEconomy {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "economy role findings must have kind economy.", path+"/kind", map[string]any{"kind": finding.Kind}))
		}
		if finding.Witness.Kind != WitnessKindEquivalence {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "economy findings require equivalence witnesses.", path+"/witness/kind", map[string]any{"kind": finding.Witness.Kind}))
		}
		if !hasNegativeDelta(finding.EstimatedDelta) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidDelta, "economy findings require a structured negative production or test delta.", path+"/estimated_delta", nil))
		}
	}
	diagnostics = append(diagnostics, validateWitness(finding.Kind, finding.Witness, path+"/witness", frozen)...)
	diagnostics = append(diagnostics, validateDelta(finding.EstimatedDelta, path+"/estimated_delta", role == RoleDefect)...)
	diagnostics = append(diagnostics, validateRemedy(role, finding.SmallestSufficientRemedy, finding.EstimatedDelta, path+"/smallest_sufficient_remedy")...)
	diagnostics = append(diagnostics, validateProposedTests(finding.ProposedTests, path+"/proposed_tests", frozen, goalIDs)...)
	if finding.Kind == FindingKindDefect && frozen != nil {
		scope := charter.ValidateFindingScope(frozen.Charter.OperationalEnvelope, charter.FindingScope{
			FindingID: finding.ID,
			Kind:      charter.FindingKindDefect,
			Anchors:   finding.ScopeAnchors,
		})
		diagnostics = append(diagnostics, prefixDiagnostics(path+"/scope_anchors", scope.Diagnostics)...)
		for _, expected := range scope.Questions {
			actual, exists := questions[expected.ID]
			if !exists {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidRoleOutput,
					"scope anchor on an unspecified Operational Envelope dimension requires a linked missing-goal question.",
					path+"/scope_anchors",
					map[string]any{"missing_goal_question_id": expected.ID},
				))
				continue
			}
			if actual != expected {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidRoleOutput,
					"linked missing-goal question must match the deterministic Charter-derived question.",
					questionPaths[expected.ID],
					map[string]any{"expected": expected, "actual": actual},
				))
			}
		}
	}
	if finding.Recurrence != nil {
		diagnostics = append(diagnostics, validateRecurrence(*finding.Recurrence, path+"/recurrence")...)
	}
	return diagnostics
}

func validateWitness(findingKind string, witness Witness, path string, frozen *charter.FrozenCharter) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireEnum(&diagnostics, path+"/kind", "witness kind", witness.Kind, stringSet(WitnessKindDefect, WitnessKindEquivalence), CodeInvalidWitness)
	requireEnum(&diagnostics, path+"/strength", "witness strength", witness.Strength, stringSet(WitnessStrengthExecutable, WitnessStrengthConstructed, WitnessStrengthArgued), CodeInvalidWitness)
	if strings.TrimSpace(witness.Content) == "" && len(witness.ArtifactRefs) == 0 && witness.Executable == nil {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "witness requires content, artifact references, or an executable specification.", path, nil))
	}
	for index, ref := range witness.ArtifactRefs {
		diagnostics = append(diagnostics, prefixDiagnostics(path+"/artifact_refs/"+itoa(index), validateArtifactRef(ref, ""))...)
	}
	if witness.Strength == WitnessStrengthExecutable {
		if witness.Executable == nil {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidWitness, "executable witness strength requires an executable specification.", path+"/executable", nil))
		} else {
			diagnostics = append(diagnostics, validateExecutableSpec(*witness.Executable, path+"/executable", findingKind == FindingKindEconomy)...)
		}
	}
	if frozen != nil {
		charterKind := charter.FindingKindEconomy
		if findingKind == FindingKindDefect {
			charterKind = charter.FindingKindDefect
		}
		result := charter.ValidateWitnessStructure(frozen.Charter.OperationalEnvelope, charterKind, charter.Witness{
			Kind:              witness.Kind,
			Strength:          witness.Strength,
			EntryPoint:        witness.EntryPoint,
			ReachabilityChain: witness.ReachabilityChain,
		})
		diagnostics = append(diagnostics, prefixDiagnostics(path, result.Diagnostics)...)
	}
	return diagnostics
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

func validateMissingGoalQuestion(question MissingGoalQuestion, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/id", "missing-goal question ID", question.ID)
	if strings.TrimSpace(question.FindingID) != "" {
		requireStableID(&diagnostics, path+"/finding_id", "missing-goal question finding ID", question.FindingID)
	}
	requireEnum(
		&diagnostics,
		path+"/dimension",
		"Operational Envelope dimension",
		question.Dimension,
		stringSet(
			charter.DimensionEntryPoints,
			charter.DimensionInputSurface,
			charter.DimensionValidStates,
			charter.DimensionEnvironments,
			charter.DimensionScaleBounds,
			charter.DimensionCompatibilityPromises,
			charter.DimensionThreatModel,
		),
		CodeInvalidRoleOutput,
	)
	if question.AnchorIndex < 0 {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidRoleOutput, "missing-goal question anchor_index must identify the originating anchor.", path+"/anchor_index", map[string]any{"anchor_index": question.AnchorIndex}))
	}
	requireString(&diagnostics, path+"/property", "missing-goal question unstated property", question.Property)
	requireString(&diagnostics, path+"/value", "missing-goal question unstated value", question.Value)
	requireString(&diagnostics, path+"/affected_decision", "missing-goal question affected decision", question.AffectedDecision)
	requireString(&diagnostics, path+"/statement", "missing-goal question statement", question.Statement)
	return diagnostics
}

func validateDelta(delta SplitDeltaEstimate, path string, malformedAsUnknown bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	diagnostics = append(diagnostics, validateDeltaComponent(delta.Production, path+"/production", malformedAsUnknown)...)
	diagnostics = append(diagnostics, validateDeltaComponent(delta.Test, path+"/test", malformedAsUnknown)...)
	return diagnostics
}

func validateDeltaComponent(delta DeltaEstimate, path string, malformedAsUnknown bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if delta.Status != DeltaStatusKnown && delta.Status != DeltaStatusUnknown {
		if malformedAsUnknown {
			return nil
		}
		diagnostics = append(diagnostics, diagnostic(CodeInvalidDelta, "delta status has an unsupported value.", path+"/status", map[string]any{"value": delta.Status}))
		return diagnostics
	}
	if delta.Status == DeltaStatusUnknown && (delta.Lines != 0 || delta.Files != 0) {
		diagnostics = append(diagnostics, diagnostic(CodeInvalidDelta, "unknown deltas must not carry line or file counts.", path, nil))
	}
	return diagnostics
}

func hasNegativeDelta(delta SplitDeltaEstimate) bool {
	return (delta.Production.Status == DeltaStatusKnown && (delta.Production.Lines < 0 || delta.Production.Files < 0)) ||
		(delta.Test.Status == DeltaStatusKnown && (delta.Test.Lines < 0 || delta.Test.Files < 0))
}

func validateRemedy(role string, remedy SmallestSufficientRemedy, delta SplitDeltaEstimate, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireEnum(&diagnostics, path+"/direction", "remedy direction", remedy.Direction, stringSet(RemedyDirectionAdd, RemedyDirectionChange, RemedyDirectionRemove), CodeInvalidRemedy)
	requireString(&diagnostics, path+"/summary", "remedy summary", remedy.Summary)
	requireString(&diagnostics, path+"/minimality_argument", "smallest sufficient remedy minimality argument", remedy.MinimalityArgument)
	if role == RoleEconomy {
		if remedy.Direction != RemedyDirectionRemove && remedy.Direction != RemedyDirectionChange {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRemedy, "economy remedies must remove code or make a size-reducing change.", path+"/direction", map[string]any{"direction": remedy.Direction}))
		}
		if remedy.Direction == RemedyDirectionChange && !hasNegativeDelta(delta) {
			diagnostics = append(diagnostics, diagnostic(CodeInvalidRemedy, "economy change remedies must carry a negative production or test delta estimate.", path, nil))
		}
	}
	return diagnostics
}

func validateProposedTests(tests []ProposedTest, path string, frozen *charter.FrozenCharter, goalIDs map[string]bool) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	partitions := map[string]int{}
	for index, test := range tests {
		testPath := path + "/" + itoa(index)
		requireStableID(&diagnostics, testPath+"/id", "proposed test ID", test.ID)
		requireString(&diagnostics, testPath+"/name", "proposed test name", test.Name)
		requireString(&diagnostics, testPath+"/reachable_partition", "reachable behavioral partition", test.ReachablePartition)
		if first, exists := partitions[test.ReachablePartition]; exists && test.ReachablePartition != "" {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidRoleOutput,
				"at most one proposed test may target a distinct reachable behavioral partition.",
				testPath+"/reachable_partition",
				map[string]any{"duplicate_of": path + "/" + itoa(first) + "/reachable_partition"},
			))
		}
		partitions[test.ReachablePartition] = index
		if len(test.CharterRefs) == 0 {
			diagnostics = append(diagnostics, diagnostic(CodeMissingCharterTrace, "proposed tests must reference a Charter goal or scope anchor.", testPath+"/charter_refs", nil))
			continue
		}
		for refIndex, ref := range test.CharterRefs {
			refPath := testPath + "/charter_refs/" + itoa(refIndex)
			if strings.TrimSpace(ref.GoalID) == "" && ref.Anchor == nil {
				diagnostics = append(diagnostics, diagnostic(CodeMissingCharterTrace, "Charter trace must include a goal_id or anchor.", refPath, nil))
			}
			if ref.GoalID != "" {
				requireStableID(&diagnostics, refPath+"/goal_id", "Charter goal ID", ref.GoalID)
				if goalIDs != nil && !goalIDs[ref.GoalID] {
					diagnostics = append(diagnostics, diagnostic(CodeMissingCharterTrace, "proposed test references a Charter goal that is not declared.", refPath+"/goal_id", map[string]any{"goal_id": ref.GoalID}))
				}
			}
			if ref.Anchor != nil && frozen != nil {
				scope := charter.ValidateFindingScope(frozen.Charter.OperationalEnvelope, charter.FindingScope{
					FindingID: test.ID,
					Kind:      charter.FindingKindDefect,
					Anchors:   []ScopeAnchor{*ref.Anchor},
				})
				diagnostics = append(diagnostics, prefixDiagnostics(refPath+"/anchor", scope.Diagnostics)...)
			}
		}
	}
	return diagnostics
}

func validateRecurrence(recurrence RecurrenceRef, path string) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	requireStableID(&diagnostics, path+"/prior_finding_id", "prior finding ID", recurrence.PriorFindingID)
	requireString(&diagnostics, path+"/finding_key", "finding key", recurrence.FindingKey)
	requireDigest(&diagnostics, path+"/witness_digest", "recurrence witness_digest", recurrence.WitnessDigest)
	requireDigest(&diagnostics, path+"/artifact_digest", "recurrence artifact_digest", recurrence.ArtifactDigest)
	return diagnostics
}

func charterGoalIDs(frozen *charter.FrozenCharter) map[string]bool {
	if frozen == nil {
		return nil
	}
	ids := make(map[string]bool, len(frozen.Charter.Goals))
	for _, goal := range frozen.Charter.Goals {
		ids[goal.ID] = true
	}
	return ids
}

func itoa(value int) string {
	return strconvAppend(value)
}

func strconvAppend(value int) string {
	var buf [20]byte
	return string(strconvAppendInt(buf[:0], value))
}

func strconvAppendInt(dst []byte, value int) []byte {
	if value == 0 {
		return append(dst, '0')
	}
	if value < 0 {
		dst = append(dst, '-')
		value = -value
	}
	var digits [20]byte
	i := len(digits)
	for value > 0 {
		i--
		digits[i] = byte('0' + value%10)
		value /= 10
	}
	return append(dst, digits[i:]...)
}

func DecodeAndValidateRoleOutput(data []byte, frozen *charter.FrozenCharter) (RoleOutputDocument, error) {
	document, err := ReadRoleOutputBytes(data)
	if err != nil {
		return RoleOutputDocument{}, err
	}
	if err := RequireValidRoleOutput(document, frozen); err != nil {
		return RoleOutputDocument{}, err
	}
	return document, nil
}

func DecodeRoleOutput(reader io.Reader, frozen *charter.FrozenCharter) (RoleOutputDocument, error) {
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(reader); err != nil {
		return RoleOutputDocument{}, err
	}
	return DecodeAndValidateRoleOutput(buffer.Bytes(), frozen)
}
