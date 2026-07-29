package charter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/strictjson"
)

const (
	SchemaVersion       = "review-charter-v2"
	FrozenSchemaVersion = "review-charter-freeze-v1"

	StandingNoGoalsID        = "standing-no-derived-goals"
	StandingNoGoalsStatement = "Existing code, tests, defenses, and review-introduced machinery create no goals."

	DimensionEntryPoints           = "entry_points"
	DimensionInputSurface          = "input_surface"
	DimensionValidStates           = "valid_states"
	DimensionEnvironments          = "environments"
	DimensionScaleBounds           = "scale_bounds"
	DimensionCompatibilityPromises = "compatibility_promises"
	DimensionThreatModel           = "threat_model"

	StateBounded       DimensionState = "bounded"
	StateUnbounded     DimensionState = "unbounded"
	StateNotApplicable DimensionState = "not_applicable"
	StateUnspecified   DimensionState = "unspecified"

	FindingKindDefect      = "defect"
	FindingKindEquivalence = "equivalence"
	FindingKindEconomy     = "economy"

	WitnessKindEquivalence = "equivalence"

	WitnessStrengthExecutable  = "executable"
	WitnessStrengthConstructed = "constructed"
	WitnessStrengthArgued      = "argued"

	CodeInvalidCharter                = "invalid_charter"
	CodeInvalidOwnerEvent             = "invalid_owner_event"
	CodeInvalidScopeAnchor            = "invalid_scope_anchor"
	CodeMissingScopeAnchor            = "missing_scope_anchor"
	CodeMissingGoalQuestion           = "missing_goal_question"
	CodeMissingEntryPoint             = "missing_entry_point"
	CodeMissingReachabilityChain      = "missing_reachability_chain"
	CodeDanglingReachabilityReference = "dangling_reachability_reference"
	CodeOutputPathConflict            = "output_path_conflict"
	CodeFileIO                        = "file_io"
)

var (
	requiredDimensions = []string{
		DimensionEntryPoints,
		DimensionInputSurface,
		DimensionValidStates,
		DimensionEnvironments,
		DimensionScaleBounds,
		DimensionCompatibilityPromises,
		DimensionThreatModel,
	}
	stableIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

type DimensionState string

type Charter struct {
	SchemaVersion       string               `json:"schema_version"`
	Goals               []Statement          `json:"goals"`
	NonGoals            []Statement          `json:"non_goals"`
	OwnerEvents         []OwnerEvent         `json:"owner_events"`
	OperationalEnvelope *OperationalEnvelope `json:"operational_envelope,omitempty"`
}

type NormalizedCharter struct {
	SchemaVersion       string               `json:"schema_version"`
	Goals               []Statement          `json:"goals"`
	NonGoals            []Statement          `json:"non_goals"`
	StandingNoGoals     []StandingStatement  `json:"standing_no_goals"`
	OwnerEvents         []OwnerEvent         `json:"owner_events"`
	OperationalEnvelope *OperationalEnvelope `json:"operational_envelope,omitempty"`
}

type FrozenCharter struct {
	SchemaVersion             string            `json:"schema_version"`
	DigestProfile             string            `json:"digest_profile"`
	CharterHash               string            `json:"charter_hash"`
	ReachabilityRulesActive   bool              `json:"reachability_rules_active"`
	AdditiveRemediesAutomatic bool              `json:"additive_remedies_automatic"`
	Charter                   NormalizedCharter `json:"charter"`
}

type Statement struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type StandingStatement struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type OwnerEvent struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Actor   string         `json:"actor"`
	Summary string         `json:"summary"`
	Details map[string]any `json:"details,omitempty"`
}

type OperationalEnvelope struct {
	EntryPoints           *Dimension `json:"entry_points"`
	InputSurface          *Dimension `json:"input_surface"`
	ValidStates           *Dimension `json:"valid_states"`
	Environments          *Dimension `json:"environments"`
	ScaleBounds           *Dimension `json:"scale_bounds"`
	CompatibilityPromises *Dimension `json:"compatibility_promises"`
	ThreatModel           *Dimension `json:"threat_model"`
}

type Dimension struct {
	State     DimensionState `json:"state"`
	Statement string         `json:"statement"`
	Entries   []Entry        `json:"entries"`

	presence dimensionPresence
}

type dimensionPresence struct {
	decoded          bool
	statePresent     bool
	stateNull        bool
	statementPresent bool
	statementNull    bool
	entriesPresent   bool
	entriesNull      bool
	entriesArray     bool
}

type Entry struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type ScopeAnchor struct {
	Dimension        string `json:"dimension"`
	EntryID          string `json:"entry_id,omitempty"`
	Property         string `json:"property,omitempty"`
	Value            string `json:"value,omitempty"`
	AffectedDecision string `json:"affected_decision,omitempty"`
	Excluded         bool   `json:"excluded,omitempty"`
}

type FindingScope struct {
	FindingID string        `json:"finding_id"`
	Kind      string        `json:"kind"`
	Anchors   []ScopeAnchor `json:"anchors"`
}

type ScopeResult struct {
	ReachabilityRulesActive   bool                  `json:"reachability_rules_active"`
	AdditiveRemediesAutomatic bool                  `json:"additive_remedies_automatic"`
	Obligating                bool                  `json:"obligating"`
	Advisory                  bool                  `json:"advisory"`
	Diagnostics               []diag.Diagnostic     `json:"diagnostics,omitempty"`
	Questions                 []MissingGoalQuestion `json:"questions,omitempty"`
}

type MissingGoalQuestion struct {
	ID               string `json:"id"`
	FindingID        string `json:"finding_id"`
	Dimension        string `json:"dimension"`
	AnchorIndex      int    `json:"anchor_index"`
	Property         string `json:"property"`
	Value            string `json:"value,omitempty"`
	AffectedDecision string `json:"affected_decision"`
	Statement        string `json:"statement"`
}

type Witness struct {
	Kind              string        `json:"kind,omitempty"`
	Strength          string        `json:"strength"`
	EntryPoint        *ScopeAnchor  `json:"entry_point,omitempty"`
	ReachabilityChain []ScopeAnchor `json:"reachability_chain,omitempty"`
}

type WitnessResult struct {
	ReachabilityRulesActive bool              `json:"reachability_rules_active"`
	Required                bool              `json:"required"`
	Valid                   bool              `json:"valid"`
	Diagnostics             []diag.Diagnostic `json:"diagnostics,omitempty"`
}

type EnvelopeProperties struct {
	ReachabilityRulesActive   bool `json:"reachability_rules_active"`
	AdditiveRemediesAutomatic bool `json:"additive_remedies_automatic"`
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "charter validation failed"
	}
	return fmt.Sprintf("%s: %s", err.Diagnostics[0].Code, err.Diagnostics[0].Message)
}

func InitSkeleton(actor string, eventID string, summary string) Charter {
	if actor == "" {
		actor = "owner"
	}
	if eventID == "" {
		eventID = "initial-charter"
	}
	if summary == "" {
		summary = "Initial owner-authorized charter skeleton."
	}
	return Charter{
		SchemaVersion: SchemaVersion,
		Goals:         []Statement{},
		NonGoals:      []Statement{},
		OwnerEvents: []OwnerEvent{{
			ID:      eventID,
			Type:    "charter_initialized",
			Actor:   actor,
			Summary: summary,
		}},
	}
}

func Read(reader io.Reader) (Charter, error) {
	return strictjson.Decode[Charter](reader, strictjson.DefaultMaxBytes)
}

func ReadBytes(data []byte) (Charter, error) {
	return strictjson.DecodeBytes[Charter](data, strictjson.DefaultMaxBytes)
}

func (dimension *Dimension) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for field := range raw {
		switch field {
		case "state", "statement", "entries":
		default:
			return fmt.Errorf("json: unknown field %q", field)
		}
	}

	decoded := Dimension{presence: dimensionPresence{decoded: true}}
	if rawState, ok := raw["state"]; ok {
		decoded.presence.statePresent = true
		if isJSONNull(rawState) {
			decoded.presence.stateNull = true
		} else if err := json.Unmarshal(rawState, &decoded.State); err != nil {
			return err
		}
	}
	if rawStatement, ok := raw["statement"]; ok {
		decoded.presence.statementPresent = true
		if isJSONNull(rawStatement) {
			decoded.presence.statementNull = true
		} else if err := json.Unmarshal(rawStatement, &decoded.Statement); err != nil {
			return err
		}
	}
	if rawEntries, ok := raw["entries"]; ok {
		decoded.presence.entriesPresent = true
		if isJSONNull(rawEntries) {
			decoded.presence.entriesNull = true
		} else if rawJSONKind(rawEntries) == '[' {
			decoded.presence.entriesArray = true
			if err := decodeStrictRaw(rawEntries, &decoded.Entries); err != nil {
				return err
			}
		}
	}

	*dimension = decoded
	return nil
}

func ReadFile(path string) (Charter, error) {
	file, err := os.Open(path)
	if err != nil {
		return Charter{}, fileError(err, path, "open charter file")
	}
	defer file.Close()
	return Read(file)
}

func ReadAmendments(reader io.Reader) ([]OwnerEvent, error) {
	return strictjson.DecodeJSONL[OwnerEvent](reader, strictjson.DefaultMaxBytes)
}

func ReadAmendmentsFile(path string) ([]OwnerEvent, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fileError(err, path, "open amendments file")
	}
	defer file.Close()
	return ReadAmendments(file)
}

func ReadOwnerEvent(reader io.Reader) (OwnerEvent, error) {
	return strictjson.Decode[OwnerEvent](reader, strictjson.DefaultMaxBytes)
}

func ReadOwnerEventFile(path string) (OwnerEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return OwnerEvent{}, fileError(err, path, "open owner event file")
	}
	defer file.Close()
	return ReadOwnerEvent(file)
}

func Validate(input Charter, amendments []OwnerEvent) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	if input.SchemaVersion != SchemaVersion {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidCharter,
			"charter schema_version must be review-charter-v2.",
			"/schema_version",
			map[string]any{"expected": SchemaVersion, "actual": input.SchemaVersion},
		))
	}
	diagnostics = append(diagnostics, validateStatements("/goals", input.Goals)...)
	diagnostics = append(diagnostics, validateStatements("/non_goals", input.NonGoals)...)
	diagnostics = append(diagnostics, validateOwnerEvents("/owner_events", input.OwnerEvents)...)
	if len(amendments) > 0 {
		diagnostics = append(diagnostics, validateOwnerEvents("/amendments", amendments)...)
	}
	diagnostics = append(diagnostics, validateOwnerEventUniqueness(input.OwnerEvents, amendments)...)
	if input.OperationalEnvelope != nil {
		diagnostics = append(diagnostics, validateEnvelope(input.OperationalEnvelope)...)
	}
	return diagnostics
}

func Normalize(input Charter, amendments []OwnerEvent) (NormalizedCharter, error) {
	if diagnostics := Validate(input, amendments); len(diagnostics) > 0 {
		return NormalizedCharter{}, &ValidationError{Diagnostics: diagnostics}
	}
	normalized := NormalizedCharter{
		SchemaVersion: SchemaVersion,
		Goals:         cloneStatements(input.Goals),
		NonGoals:      cloneStatements(input.NonGoals),
		StandingNoGoals: []StandingStatement{{
			ID:        StandingNoGoalsID,
			Statement: StandingNoGoalsStatement,
		}},
		OwnerEvents:         cloneOwnerEvents(append(cloneOwnerEvents(input.OwnerEvents), amendments...)),
		OperationalEnvelope: normalizeEnvelope(input.OperationalEnvelope),
	}
	return normalized, nil
}

func Hash(normalized NormalizedCharter) (string, error) {
	return digest.SemanticJSON(normalized)
}

func Freeze(input Charter, amendments []OwnerEvent) (FrozenCharter, error) {
	normalized, err := Normalize(input, amendments)
	if err != nil {
		return FrozenCharter{}, err
	}
	charterHash, err := Hash(normalized)
	if err != nil {
		return FrozenCharter{}, err
	}
	properties := Properties(normalized.OperationalEnvelope)
	return FrozenCharter{
		SchemaVersion:             FrozenSchemaVersion,
		DigestProfile:             digest.Profile,
		CharterHash:               charterHash,
		ReachabilityRulesActive:   properties.ReachabilityRulesActive,
		AdditiveRemediesAutomatic: properties.AdditiveRemediesAutomatic,
		Charter:                   normalized,
	}, nil
}

func AppendAmendment(path string, event OwnerEvent) error {
	existing, err := ReadAmendmentsFile(path)
	if err != nil {
		return err
	}
	diagnostics := validateOwnerEvents("/event", []OwnerEvent{event})
	for i, existingEvent := range existing {
		if existingEvent.ID == event.ID {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event IDs must be unique.",
				"/event/id",
				map[string]any{"duplicate_of": fmt.Sprintf("/%d/id", i+1), "id": event.ID},
			))
		}
	}
	if len(diagnostics) > 0 {
		return &ValidationError{Diagnostics: diagnostics}
	}
	encoded, err := canonjson.Marshal(event)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fileError(err, path, "append amendment")
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fileError(err, path, "write amendment")
	}
	return nil
}

func Properties(envelope *OperationalEnvelope) EnvelopeProperties {
	return EnvelopeProperties{
		ReachabilityRulesActive:   envelope != nil,
		AdditiveRemediesAutomatic: false,
	}
}

func ValidateFindingScope(envelope *OperationalEnvelope, finding FindingScope) ScopeResult {
	properties := Properties(envelope)
	result := ScopeResult{
		ReachabilityRulesActive:   properties.ReachabilityRulesActive,
		AdditiveRemediesAutomatic: properties.AdditiveRemediesAutomatic,
		Obligating:                true,
	}
	if envelope == nil {
		return result
	}
	if finding.Kind == FindingKindDefect && len(finding.Anchors) == 0 {
		result.Advisory = true
		result.Obligating = false
		result.Diagnostics = append(result.Diagnostics, diagnostic(
			CodeMissingScopeAnchor,
			"defect findings under an Operational Envelope must name at least one scope anchor.",
			"/anchors",
			map[string]any{"finding_id": finding.FindingID},
		))
		return result
	}
	for index, anchor := range finding.Anchors {
		resolution := resolveAnchor(envelope, anchor)
		path := fmt.Sprintf("/anchors/%d", index)
		switch resolution.status {
		case anchorValid:
			continue
		case anchorUnspecified:
			result.Advisory = true
			result.Obligating = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeMissingGoalQuestion,
				"scope anchor references an unspecified Operational Envelope dimension.",
				path,
				map[string]any{
					"affected_decision": anchor.AffectedDecision,
					"dimension":         anchor.Dimension,
					"finding_id":        finding.FindingID,
					"property":          anchor.Property,
					"value":             anchor.Value,
				},
			))
			result.Questions = append(result.Questions, MissingGoalQuestion{
				ID:               missingGoalQuestionID(finding.FindingID, anchor.Dimension, anchor.Property, anchor.Value, index),
				FindingID:        finding.FindingID,
				Dimension:        anchor.Dimension,
				AnchorIndex:      index,
				Property:         anchor.Property,
				Value:            anchor.Value,
				AffectedDecision: anchor.AffectedDecision,
				Statement:        missingGoalQuestionStatement(finding.FindingID, anchor.Dimension, anchor.Property, anchor.Value, anchor.AffectedDecision),
			})
		case anchorExcluded:
			result.Advisory = true
			result.Obligating = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeInvalidScopeAnchor,
				"scope anchor is explicitly excluded by the Operational Envelope.",
				path,
				map[string]any{"dimension": anchor.Dimension},
			))
		default:
			result.Advisory = true
			result.Obligating = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeInvalidScopeAnchor,
				resolution.message,
				path,
				resolution.details(anchor),
			))
		}
	}
	return result
}

func ValidateWitnessStructure(envelope *OperationalEnvelope, findingKind string, witness Witness) WitnessResult {
	properties := Properties(envelope)
	result := WitnessResult{
		ReachabilityRulesActive: properties.ReachabilityRulesActive,
		Valid:                   true,
	}
	if envelope == nil || !witnessRequiresReachability(findingKind, witness) {
		return result
	}
	result.Required = true
	if witness.EntryPoint == nil {
		result.Valid = false
		result.Diagnostics = append(result.Diagnostics, diagnostic(
			CodeMissingEntryPoint,
			"constructed and executable defect witnesses require an entry point.",
			"/entry_point",
			nil,
		))
	} else {
		entryPoint := *witness.EntryPoint
		if entryPoint.Dimension == "" {
			entryPoint.Dimension = DimensionEntryPoints
		}
		if entryPoint.Dimension != DimensionEntryPoints {
			result.Valid = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeDanglingReachabilityReference,
				"witness entry point must reference the entry_points dimension.",
				"/entry_point/dimension",
				map[string]any{"dimension": entryPoint.Dimension},
			))
		} else if resolution := resolveReachabilityAnchor(envelope, entryPoint); resolution.status != anchorValid {
			result.Valid = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeDanglingReachabilityReference,
				resolution.message,
				"/entry_point",
				resolution.details(entryPoint),
			))
		}
	}
	if len(witness.ReachabilityChain) == 0 {
		result.Valid = false
		result.Diagnostics = append(result.Diagnostics, diagnostic(
			CodeMissingReachabilityChain,
			"constructed and executable defect witnesses require a non-empty reachability chain.",
			"/reachability_chain",
			nil,
		))
		return result
	}
	for index, anchor := range witness.ReachabilityChain {
		resolution := resolveReachabilityAnchor(envelope, anchor)
		if resolution.status != anchorValid {
			result.Valid = false
			result.Diagnostics = append(result.Diagnostics, diagnostic(
				CodeDanglingReachabilityReference,
				resolution.message,
				fmt.Sprintf("/reachability_chain/%d", index),
				resolution.details(anchor),
			))
		}
	}
	return result
}

func DimensionNames() []string {
	return append([]string(nil), requiredDimensions...)
}

func (envelope *OperationalEnvelope) Dimension(name string) *Dimension {
	if envelope == nil {
		return nil
	}
	switch name {
	case DimensionEntryPoints:
		return envelope.EntryPoints
	case DimensionInputSurface:
		return envelope.InputSurface
	case DimensionValidStates:
		return envelope.ValidStates
	case DimensionEnvironments:
		return envelope.Environments
	case DimensionScaleBounds:
		return envelope.ScaleBounds
	case DimensionCompatibilityPromises:
		return envelope.CompatibilityPromises
	case DimensionThreatModel:
		return envelope.ThreatModel
	default:
		return nil
	}
}

func EntryIDs(dimension *Dimension) map[string]struct{} {
	ids := map[string]struct{}{}
	if dimension == nil {
		return ids
	}
	for _, entry := range dimension.Entries {
		ids[entry.ID] = struct{}{}
	}
	return ids
}

func validateEnvelope(envelope *OperationalEnvelope) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, name := range requiredDimensions {
		dimension := envelope.Dimension(name)
		path := "/operational_envelope/" + name
		if dimension == nil {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"Operational Envelope must include all seven required dimensions.",
				path,
				map[string]any{"dimension": name},
			))
			continue
		}
		diagnostics = append(diagnostics, validateDimension(path, *dimension)...)
	}
	return diagnostics
}

func validateDimension(path string, dimension Dimension) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	statePresent := true
	if dimension.presence.decoded && (!dimension.presence.statePresent || dimension.presence.stateNull) {
		statePresent = false
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidCharter,
			"Operational Envelope dimension state is required.",
			path+"/state",
			nil,
		))
	}
	if statePresent {
		switch dimension.State {
		case StateBounded, StateUnbounded, StateNotApplicable, StateUnspecified:
		default:
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"Operational Envelope dimension state is invalid.",
				path+"/state",
				map[string]any{"state": dimension.State},
			))
		}
	}
	statementPresent := true
	if dimension.presence.decoded && (!dimension.presence.statementPresent || dimension.presence.statementNull) {
		statementPresent = false
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidCharter,
			"Operational Envelope dimension statement is required.",
			path+"/statement",
			nil,
		))
	}
	if statementPresent && strings.TrimSpace(dimension.Statement) == "" {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidCharter,
			"Operational Envelope dimension statement is required.",
			path+"/statement",
			nil,
		))
	}
	if entriesDiagnostics := validateDimensionEntriesPresence(path, dimension); len(entriesDiagnostics) > 0 {
		diagnostics = append(diagnostics, entriesDiagnostics...)
		return diagnostics
	}
	if dimension.State == StateBounded {
		if len(dimension.Entries) == 0 {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"bounded Operational Envelope dimensions require at least one stable entry.",
				path+"/entries",
				nil,
			))
		}
		seen := map[string]int{}
		for index, entry := range dimension.Entries {
			entryPath := fmt.Sprintf("%s/entries/%d", path, index)
			if !stableIDPattern.MatchString(entry.ID) {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidCharter,
					"bounded Operational Envelope entries require stable IDs.",
					entryPath+"/id",
					map[string]any{"id": entry.ID},
				))
			}
			if first, ok := seen[entry.ID]; ok {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidCharter,
					"Operational Envelope entry IDs must be unique within a dimension.",
					entryPath+"/id",
					map[string]any{"id": entry.ID, "duplicate_of": fmt.Sprintf("%s/entries/%d/id", path, first)},
				))
			}
			seen[entry.ID] = index
			if strings.TrimSpace(entry.Statement) == "" {
				diagnostics = append(diagnostics, diagnostic(
					CodeInvalidCharter,
					"Operational Envelope entry statement is required.",
					entryPath+"/statement",
					nil,
				))
			}
		}
		return diagnostics
	}
	if len(dimension.Entries) > 0 {
		diagnostics = append(diagnostics, diagnostic(
			CodeInvalidCharter,
			"unbounded, not_applicable, and unspecified Operational Envelope dimensions require an empty entry list.",
			path+"/entries",
			map[string]any{"state": dimension.State},
		))
	}
	return diagnostics
}

func validateDimensionEntriesPresence(path string, dimension Dimension) []diag.Diagnostic {
	if dimension.presence.decoded {
		if !dimension.presence.entriesPresent {
			return []diag.Diagnostic{diagnostic(
				CodeInvalidCharter,
				"Operational Envelope dimension entries are required.",
				path+"/entries",
				nil,
			)}
		}
		if dimension.presence.entriesNull || !dimension.presence.entriesArray {
			return []diag.Diagnostic{diagnostic(
				CodeInvalidCharter,
				"Operational Envelope dimension entries must be a JSON array.",
				path+"/entries",
				nil,
			)}
		}
	}
	if dimension.Entries == nil {
		return []diag.Diagnostic{diagnostic(
			CodeInvalidCharter,
			"Operational Envelope dimension entries require an explicit array.",
			path+"/entries",
			nil,
		)}
	}
	return nil
}

func validateStatements(path string, statements []Statement) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	seen := map[string]int{}
	for index, statement := range statements {
		statementPath := fmt.Sprintf("%s/%d", path, index)
		if !stableIDPattern.MatchString(statement.ID) {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"statements require stable IDs.",
				statementPath+"/id",
				map[string]any{"id": statement.ID},
			))
		}
		if first, ok := seen[statement.ID]; ok {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"statement IDs must be unique within their list.",
				statementPath+"/id",
				map[string]any{"id": statement.ID, "duplicate_of": fmt.Sprintf("%s/%d/id", path, first)},
			))
		}
		seen[statement.ID] = index
		if strings.TrimSpace(statement.Statement) == "" {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidCharter,
				"statement text is required.",
				statementPath+"/statement",
				nil,
			))
		}
	}
	return diagnostics
}

func validateOwnerEvents(path string, events []OwnerEvent) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	seen := map[string]int{}
	for index, event := range events {
		eventPath := fmt.Sprintf("%s/%d", path, index)
		if !stableIDPattern.MatchString(event.ID) {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner events require stable IDs.",
				eventPath+"/id",
				map[string]any{"id": event.ID},
			))
		}
		if first, ok := seen[event.ID]; ok {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event IDs must be unique within their source.",
				eventPath+"/id",
				map[string]any{"id": event.ID, "duplicate_of": fmt.Sprintf("%s/%d/id", path, first)},
			))
		}
		seen[event.ID] = index
		if strings.TrimSpace(event.Type) == "" {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event type is required.",
				eventPath+"/type",
				nil,
			))
		}
		if strings.TrimSpace(event.Actor) == "" {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event actor is required.",
				eventPath+"/actor",
				nil,
			))
		}
		if strings.TrimSpace(event.Summary) == "" {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event summary is required.",
				eventPath+"/summary",
				nil,
			))
		}
	}
	return diagnostics
}

func validateOwnerEventUniqueness(base []OwnerEvent, amendments []OwnerEvent) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	seen := map[string]string{}
	for index, event := range base {
		seen[event.ID] = fmt.Sprintf("/owner_events/%d/id", index)
	}
	for index, event := range amendments {
		if first, ok := seen[event.ID]; ok {
			diagnostics = append(diagnostics, diagnostic(
				CodeInvalidOwnerEvent,
				"owner event IDs must be unique across the charter and amendments.",
				fmt.Sprintf("/amendments/%d/id", index),
				map[string]any{"id": event.ID, "duplicate_of": first},
			))
		}
		seen[event.ID] = fmt.Sprintf("/amendments/%d/id", index)
	}
	return diagnostics
}

func normalizeEnvelope(envelope *OperationalEnvelope) *OperationalEnvelope {
	if envelope == nil {
		return nil
	}
	return &OperationalEnvelope{
		EntryPoints:           normalizeDimension(envelope.EntryPoints),
		InputSurface:          normalizeDimension(envelope.InputSurface),
		ValidStates:           normalizeDimension(envelope.ValidStates),
		Environments:          normalizeDimension(envelope.Environments),
		ScaleBounds:           normalizeDimension(envelope.ScaleBounds),
		CompatibilityPromises: normalizeDimension(envelope.CompatibilityPromises),
		ThreatModel:           normalizeDimension(envelope.ThreatModel),
	}
}

func normalizeDimension(dimension *Dimension) *Dimension {
	if dimension == nil {
		return nil
	}
	normalized := &Dimension{
		State:     dimension.State,
		Statement: dimension.Statement,
		Entries:   cloneEntries(dimension.Entries),
	}
	if normalized.Entries == nil {
		normalized.Entries = []Entry{}
	}
	return normalized
}

func cloneStatements(input []Statement) []Statement {
	if input == nil {
		return []Statement{}
	}
	output := make([]Statement, len(input))
	copy(output, input)
	return output
}

func cloneEntries(input []Entry) []Entry {
	if input == nil {
		return []Entry{}
	}
	output := make([]Entry, len(input))
	copy(output, input)
	return output
}

func cloneOwnerEvents(input []OwnerEvent) []OwnerEvent {
	if input == nil {
		return []OwnerEvent{}
	}
	output := make([]OwnerEvent, len(input))
	for i, event := range input {
		output[i] = event
		if event.Details != nil {
			output[i].Details = cloneMap(event.Details)
		}
	}
	return output
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

type anchorStatus string

const (
	anchorValid       anchorStatus = "valid"
	anchorInvalid     anchorStatus = "invalid"
	anchorExcluded    anchorStatus = "excluded"
	anchorUnspecified anchorStatus = "unspecified"
)

type anchorResolution struct {
	status       anchorStatus
	message      string
	extraDetails map[string]any
}

func (resolution anchorResolution) details(anchor ScopeAnchor) map[string]any {
	details := map[string]any{"dimension": anchor.Dimension}
	if anchor.EntryID != "" {
		details["entry_id"] = anchor.EntryID
	}
	if anchor.Property != "" {
		details["property"] = anchor.Property
	}
	if anchor.Value != "" {
		details["value"] = anchor.Value
	}
	if anchor.AffectedDecision != "" {
		details["affected_decision"] = anchor.AffectedDecision
	}
	for key, value := range resolution.extraDetails {
		details[key] = value
	}
	return details
}

func resolveAnchor(envelope *OperationalEnvelope, anchor ScopeAnchor) anchorResolution {
	if envelope == nil {
		return anchorResolution{status: anchorValid}
	}
	if anchor.Excluded {
		return anchorResolution{status: anchorExcluded}
	}
	dimension := envelope.Dimension(anchor.Dimension)
	if dimension == nil {
		return anchorResolution{status: anchorInvalid, message: "scope anchor dimension is not declared in the Operational Envelope."}
	}
	switch dimension.State {
	case StateBounded:
		if anchor.EntryID == "" {
			return anchorResolution{status: anchorInvalid, message: "bounded scope anchors must reference a declared entry ID."}
		}
		if anchor.Value != "" {
			return anchorResolution{status: anchorInvalid, message: "bounded scope anchors must not use a concrete value."}
		}
		if _, ok := EntryIDs(dimension)[anchor.EntryID]; !ok {
			return anchorResolution{status: anchorInvalid, message: "bounded scope anchor references an undeclared entry ID."}
		}
		return anchorResolution{status: anchorValid}
	case StateUnbounded:
		if anchor.Value == "" {
			return anchorResolution{status: anchorInvalid, message: "unbounded scope anchors must state the concrete exercised value."}
		}
		if anchor.EntryID != "" {
			return anchorResolution{status: anchorInvalid, message: "unbounded scope anchors must not reference entry IDs."}
		}
		return anchorResolution{status: anchorValid}
	case StateUnspecified:
		missingFields := missingUnspecifiedAnchorFields(anchor)
		if len(missingFields) > 0 {
			return anchorResolution{
				status:  anchorInvalid,
				message: "unspecified scope anchors must state property, value, and affected_decision.",
				extraDetails: map[string]any{
					"missing_fields": missingFields,
				},
			}
		}
		return anchorResolution{status: anchorUnspecified}
	case StateNotApplicable:
		return anchorResolution{status: anchorExcluded}
	default:
		return anchorResolution{status: anchorInvalid, message: "scope anchor references an invalid Operational Envelope dimension state."}
	}
}

func resolveReachabilityAnchor(envelope *OperationalEnvelope, anchor ScopeAnchor) anchorResolution {
	resolution := resolveAnchor(envelope, anchor)
	if resolution.status == anchorUnspecified {
		return anchorResolution{status: anchorInvalid, message: "reachability reference cannot resolve against an unspecified Operational Envelope dimension."}
	}
	if resolution.status == anchorExcluded {
		return anchorResolution{status: anchorInvalid, message: "reachability reference cannot resolve against an excluded Operational Envelope dimension."}
	}
	return resolution
}

func witnessRequiresReachability(findingKind string, witness Witness) bool {
	if findingKind != FindingKindDefect {
		return false
	}
	if witness.Kind == WitnessKindEquivalence {
		return false
	}
	return witness.Strength == WitnessStrengthConstructed || witness.Strength == WitnessStrengthExecutable
}

func missingGoalQuestionID(findingID string, dimension string, property string, value string, index int) string {
	seed := fmt.Sprintf("%s:%s:%s:%s:%d", findingID, dimension, property, value, index)
	return "missing-goal:" + digest.RawBytes([]byte(seed))[len(digest.Prefix):]
}

func missingUnspecifiedAnchorFields(anchor ScopeAnchor) []string {
	var missing []string
	if strings.TrimSpace(anchor.Property) == "" {
		missing = append(missing, "property")
	}
	if strings.TrimSpace(anchor.Value) == "" {
		missing = append(missing, "value")
	}
	if strings.TrimSpace(anchor.AffectedDecision) == "" {
		missing = append(missing, "affected_decision")
	}
	return missing
}

func missingGoalQuestionStatement(findingID string, dimension string, property string, value string, affectedDecision string) string {
	propertyPhrase := fmt.Sprintf("%s=%q", property, value)
	return fmt.Sprintf("Finding %q depends on unstated property %s for decision %q in Operational Envelope dimension %q.", findingID, propertyPhrase, affectedDecision, dimension)
}

func decodeStrictRaw(data json.RawMessage, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func isJSONNull(data json.RawMessage) bool {
	return strings.TrimSpace(string(data)) == "null"
}

func rawJSONKind(data json.RawMessage) byte {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0
	}
	return trimmed[0]
}

func diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{
		Code:    code,
		Message: message,
		Path:    path,
		Details: details,
	}
}

func fileError(err error, path string, action string) error {
	return diag.Wrap(
		err,
		CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", action),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}

func CanonicalBytes(value any) ([]byte, error) {
	return canonjson.Marshal(value)
}
