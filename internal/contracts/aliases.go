package contracts

import (
	"encoding/json"

	"github.com/charlesnpx/witness/contract/canonjson"
	"github.com/charlesnpx/witness/contract/charter"
	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
	"github.com/charlesnpx/witness/contract/review"
)

type (
	ScopeAnchor              = review.ScopeAnchor
	MissingGoalQuestion      = review.MissingGoalQuestion
	RoleOutputDocument       = review.RoleOutputDocument
	RoleEvaluation           = review.RoleEvaluation
	Finding                  = review.Finding
	Witness                  = review.Witness
	ExecutableSpec           = review.ExecutableSpec
	SplitDeltaEstimate       = review.SplitDeltaEstimate
	DeltaEstimate            = review.DeltaEstimate
	SmallestSufficientRemedy = review.SmallestSufficientRemedy
	ProposedTest             = review.ProposedTest
	CharterRef               = review.CharterRef
	RecurrenceRef            = review.RecurrenceRef
	ArtifactRef              = review.ArtifactRef
	ValidationError          = review.ValidationError
)

const (
	RoleOutputV3                   = review.RoleOutputV3
	RoleOutputV4                   = review.RoleOutputV4
	RoleOutputV5                   = review.RoleOutputV5
	RoleDefect                     = review.RoleDefect
	RoleEconomy                    = review.RoleEconomy
	RoleGoalFit                    = review.RoleGoalFit
	FindingKindDefect              = review.FindingKindDefect
	FindingKindEconomy             = review.FindingKindEconomy
	WitnessKindDefect              = review.WitnessKindDefect
	WitnessKindEquivalence         = review.WitnessKindEquivalence
	WitnessStrengthExecutable      = review.WitnessStrengthExecutable
	WitnessStrengthConstructed     = review.WitnessStrengthConstructed
	WitnessStrengthArgued          = review.WitnessStrengthArgued
	SeverityCritical               = review.SeverityCritical
	SeverityHigh                   = review.SeverityHigh
	SeverityMedium                 = review.SeverityMedium
	SeverityLow                    = review.SeverityLow
	DeltaStatusKnown               = review.DeltaStatusKnown
	DeltaStatusUnknown             = review.DeltaStatusUnknown
	RemedyDirectionAdd             = review.RemedyDirectionAdd
	RemedyDirectionChange          = review.RemedyDirectionChange
	RemedyDirectionRemove          = review.RemedyDirectionRemove
	FindingAttributionIntroduced   = review.FindingAttributionIntroduced
	FindingAttributionWorsened     = review.FindingAttributionWorsened
	FindingAttributionPreExisting  = review.FindingAttributionPreExisting
	FindingAttributionUnattributed = review.FindingAttributionUnattributed
	CodeInvalidContract            = review.CodeInvalidContract
	CodeInvalidRoleOutput          = review.CodeInvalidRoleOutput
	CodeDigestMismatch             = review.CodeDigestMismatch
	CodeInvalidWitness             = review.CodeInvalidWitness
	CodeFiledValueMutated          = review.CodeFiledValueMutated
)

func ErrorFromDiagnostics(diagnostics []diag.Diagnostic) error {
	return review.ErrorFromDiagnostics(diagnostics)
}

func CanonicalBytes(value any) ([]byte, error) {
	return canonjson.Marshal(value)
}

func SemanticDigest(value any) (string, error) {
	return digest.SemanticJSON(value)
}

func ReadRoleOutputBytes(data []byte) (RoleOutputDocument, error) {
	return review.ReadRoleOutputBytes(data)
}

func RequireValidRoleOutput(document RoleOutputDocument, frozen *charter.FrozenCharter) error {
	return review.RequireValidRoleOutput(document, frozen)
}

func ValidateRoleEvaluation(evaluation RoleEvaluation) []diag.Diagnostic {
	return review.ValidateRoleEvaluation(evaluation)
}

func ValidateRoleOutput(document RoleOutputDocument, frozen *charter.FrozenCharter) []diag.Diagnostic {
	return review.ValidateRoleOutput(document, frozen)
}

func RoleOutputDigest(document RoleOutputDocument) (string, error) {
	return review.RoleOutputDigest(document)
}

func RoleOutputCanonicalBytes(document RoleOutputDocument) ([]byte, error) {
	return review.RoleOutputCanonicalBytes(document)
}

func FindingCanonicalJSON(finding Finding) (json.RawMessage, error) {
	return review.FindingCanonicalJSON(finding)
}

func WitnessCanonicalJSON(witness Witness) (json.RawMessage, error) {
	return review.WitnessCanonicalJSON(witness)
}

func WitnessDigest(witness Witness) (string, error) {
	return review.WitnessDigest(witness)
}

func FindingDigest(finding Finding) (string, error) {
	return review.FindingDigest(finding)
}
