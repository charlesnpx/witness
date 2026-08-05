package planning

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/witness/internal/changesurface"
	"github.com/charlesnpx/witness/internal/charter"
	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/diag"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	SchemaVersion                 = "witness-verification-plan-v2"
	ManifestSkeletonSchemaVersion = "witness-verification-manifest-skeleton-v1"
	MaxBatchFindings              = 8

	CodeMissingFrozenCharter       = "planning_missing_frozen_charter"
	CodeInvalidReviewRules         = "planning_invalid_review_rules"
	CodeInvalidReviewPolicy        = "planning_invalid_review_policy"
	CodeMixedCharter               = "planning_mixed_charter"
	CodeMixedArtifact              = "planning_mixed_artifact"
	CodeSnapshotArtifactMismatch   = "planning_snapshot_artifact_mismatch"
	CodeMissingChangeSurface       = "planning_missing_change_surface"
	CodeInvalidChangeSurface       = "planning_invalid_change_surface"
	CodeBaselineSurfaceConflict    = "planning_baseline_change_surface_conflict"
	CodeInvalidRoleOutput          = "planning_invalid_role_output"
	CodeScopeAdvisory              = "planning_scope_advisory"
	CodeInvalidReachability        = "planning_invalid_reachability"
	CodeSeverityExceedsCap         = "planning_severity_exceeds_strength_cap"
	CodeRecursiveRecurrence        = "planning_recursive_recurrence"
	CodeInvalidBatch               = "planning_invalid_batch"
	CodeOutputWriteFailed          = "planning_output_write_failed"
	CodeMissingRoleOutput          = "planning_missing_role_output"
	CodeUnsupportedRole            = "planning_unsupported_role"
	DispositionAdvisory            = "advisory"
	DispositionPendingVerification = "pending_verification"
)

type RoleOutputInput struct {
	Path     string
	RefID    string
	Document contracts.RoleOutputDocument
}

type Options struct {
	FrozenCharter    *charter.FrozenCharter
	CharterDigest    string
	RoleOutputs      []RoleOutputInput
	StateDir         string
	ConsumerIdentity map[string]any
	Rules            contracts.ReviewRules
	Policy           contracts.ReviewPolicy
	Preflight        PreflightBinding
	ChangeSurface    ChangeSurfaceInput
}

type Result struct {
	Plan             PlanDocument
	Batches          []BatchOutput
	ManifestSkeleton ManifestSkeleton
}

type ChangeSurfaceInput struct {
	BaseManifest *freeze.Manifest
	HeadManifest *freeze.Manifest
	BaselinePass bool
}

type ValidationError struct {
	Diagnostics []diag.Diagnostic
}

func (err *ValidationError) Error() string {
	if err == nil || len(err.Diagnostics) == 0 {
		return "planning validation failed"
	}
	first := err.Diagnostics[0]
	if first.Path != "" {
		return fmt.Sprintf("%s at %s: %s", first.Code, first.Path, first.Message)
	}
	return fmt.Sprintf("%s: %s", first.Code, first.Message)
}

type PlanDocument struct {
	SchemaVersion                    string                      `json:"schema_version"`
	DigestProfile                    string                      `json:"digest_profile"`
	PlanDigest                       string                      `json:"plan_digest"`
	CharterHash                      string                      `json:"charter_hash"`
	CharterDigest                    string                      `json:"charter_digest,omitempty"`
	ArtifactDigest                   string                      `json:"artifact_digest"`
	ScopePolicy                      string                      `json:"scope_policy,omitempty"`
	ChangeSurface                    *changesurface.Document     `json:"change_surface,omitempty"`
	ChangeSurfaceDigest              string                      `json:"change_surface_digest,omitempty"`
	BaselinePass                     *changesurface.BaselinePass `json:"baseline_pass,omitempty"`
	PreflightSnapshotDigest          string                      `json:"preflight_snapshot_digest,omitempty"`
	PreflightCompatibilityDigest     string                      `json:"preflight_compatibility_digest,omitempty"`
	PreflightRelayCapabilitiesDigest string                      `json:"preflight_relay_capabilities_digest,omitempty"`
	IntegrationBundleDigest          string                      `json:"integration_bundle_digest,omitempty"`
	BatchSizeMaximum                 strictjson.Int              `json:"batch_size_maximum"`
	Batches                          []BatchPlan                 `json:"batches"`
	ExcludedFindings                 []ExcludedFinding           `json:"excluded_findings,omitempty"`
	Diagnostics                      []diag.Diagnostic           `json:"diagnostics,omitempty"`
	ConsumerIdentity                 map[string]any              `json:"consumer_identity"`
}

type BatchPlan struct {
	BatchID                 string                `json:"batch_id"`
	Role                    string                `json:"role"`
	TaskShape               string                `json:"task_shape"`
	RecipeFamily            string                `json:"recipe_family"`
	CharterHash             string                `json:"charter_hash,omitempty"`
	CharterDigest           string                `json:"charter_digest,omitempty"`
	ArtifactDigest          string                `json:"artifact_digest,omitempty"`
	ArtifactDigestSet       []string              `json:"artifact_digest_set,omitempty"`
	PreflightSnapshotDigest string                `json:"preflight_snapshot_digest,omitempty"`
	IntegrationBundleDigest string                `json:"integration_bundle_digest,omitempty"`
	SourceRoleOutputRef     contracts.ArtifactRef `json:"source_role_output_ref"`
	SourceRoleOutputDigest  string                `json:"source_role_output_digest"`
	BatchRef                contracts.ArtifactRef `json:"batch_ref"`
	BatchDigest             string                `json:"batch_digest"`
	FindingIDs              []string              `json:"finding_ids"`
}

type PreflightBinding struct {
	SnapshotDigest          string
	CompatibilityDigest     string
	RelayCapabilitiesDigest string
	IntegrationBundleDigest string
}

type ExcludedFinding struct {
	Role                   string                `json:"role"`
	FindingID              string                `json:"finding_id,omitempty"`
	SourceRoleOutputRef    contracts.ArtifactRef `json:"source_role_output_ref"`
	SourceRoleOutputDigest string                `json:"source_role_output_digest"`
	Disposition            string                `json:"disposition"`
	ApplicationClass       string                `json:"application_class,omitempty"`
	Reason                 string                `json:"reason"`
	Diagnostics            []diag.Diagnostic     `json:"diagnostics,omitempty"`
}

type BatchOutput struct {
	Plan     BatchPlan
	Document contracts.VerificationBatchDocument
	Path     string
}

type ManifestSkeleton struct {
	SchemaVersion       string                      `json:"schema_version"`
	DigestProfile       string                      `json:"digest_profile"`
	PlanDigest          string                      `json:"plan_digest"`
	CharterHash         string                      `json:"charter_hash"`
	ArtifactDigest      string                      `json:"artifact_digest"`
	ScopePolicy         string                      `json:"scope_policy,omitempty"`
	ChangeSurface       *changesurface.Document     `json:"change_surface,omitempty"`
	ChangeSurfaceDigest string                      `json:"change_surface_digest,omitempty"`
	BaselinePass        *changesurface.BaselinePass `json:"baseline_pass,omitempty"`
	Batches             []ManifestSkeletonBatch     `json:"batches"`
	PendingVerification []ManifestPendingFinding    `json:"pending_verification,omitempty"`
	ExcludedFindings    []ExcludedFinding           `json:"excluded_findings,omitempty"`
	ConsumerIdentity    map[string]any              `json:"consumer_identity"`
}

type ManifestSkeletonBatch struct {
	BatchID     string                `json:"batch_id"`
	Status      string                `json:"status"`
	BatchRef    contracts.ArtifactRef `json:"batch_ref"`
	BatchDigest string                `json:"batch_digest"`
	FindingIDs  []string              `json:"finding_ids"`
}

type ManifestPendingFinding struct {
	FindingID string `json:"finding_id"`
	BatchID   string `json:"batch_id"`
}

type candidate struct {
	sourceIndex   int
	role          string
	taskShape     string
	claimed       string
	id            string
	witnessDigest string
}

func Run(options Options) (*Result, error) {
	if options.FrozenCharter == nil {
		return nil, diag.New(CodeMissingFrozenCharter, "planning requires a frozen Charter.")
	}
	if len(options.RoleOutputs) == 0 {
		return nil, diag.New(CodeMissingRoleOutput, "planning requires at least one role-output document.")
	}
	rules := options.Rules
	if rules.SchemaVersion == "" {
		rules = contracts.DefaultReviewRules()
	}
	if diagnostics := contracts.ValidateReviewRules(rules); len(diagnostics) > 0 {
		return nil, diag.New(CodeInvalidReviewRules, "planning review rules are invalid.", diag.WithDetails(firstDiagnosticDetails(diagnostics)))
	}
	policy := options.Policy
	if policy.SchemaVersion == "" {
		policy = contracts.DefaultReviewPolicy()
	}
	if diagnostics := contracts.ValidateReviewPolicy(policy, nil).Diagnostics; len(diagnostics) > 0 {
		return nil, diag.New(CodeInvalidReviewPolicy, "planning review policy is invalid.", diag.WithDetails(firstDiagnosticDetails(diagnostics)))
	}
	scopePolicy := contracts.EffectiveScopePolicy(policy)
	if scopePolicy == contracts.ScopePolicyDeltaObligating {
		if policy.SchemaVersion != contracts.ReviewPolicyV3 {
			return nil, diag.New(CodeInvalidReviewPolicy, "delta_obligating scope policy requires review-policy-v3.", diag.WithDetail("actual", policy.SchemaVersion), diag.WithDetail("expected", contracts.ReviewPolicyV3))
		}
		if rules.SchemaVersion != contracts.ReviewRulesV3 {
			return nil, diag.New(CodeInvalidReviewRules, "delta_obligating scope policy requires review-rules-v3.", diag.WithDetail("actual", rules.SchemaVersion), diag.WithDetail("expected", contracts.ReviewRulesV3))
		}
	}

	result := &Result{}
	preflightSnapshotDigest := strings.TrimSpace(options.Preflight.SnapshotDigest)
	changeSurface, changeSurfaceDigest, baselinePass, err := planChangeSurface(options.ChangeSurface, scopePolicy, preflightSnapshotDigest)
	if err != nil {
		return nil, err
	}
	consumer := cloneIdentity(options.ConsumerIdentity)
	if len(consumer) == 0 {
		consumer = firstConsumerIdentity(options.RoleOutputs, preflightSnapshotDigest)
	}
	if len(consumer) == 0 {
		consumer = map[string]any{"kind": "witness", "id": "verification-plan"}
	}

	plan := PlanDocument{
		SchemaVersion:                    SchemaVersion,
		DigestProfile:                    digest.Profile,
		CharterHash:                      options.FrozenCharter.CharterHash,
		CharterDigest:                    strings.TrimSpace(options.CharterDigest),
		ArtifactDigest:                   preflightSnapshotDigest,
		ScopePolicy:                      scopePolicy,
		ChangeSurface:                    changeSurface,
		ChangeSurfaceDigest:              changeSurfaceDigest,
		BaselinePass:                     baselinePass,
		PreflightSnapshotDigest:          preflightSnapshotDigest,
		PreflightCompatibilityDigest:     strings.TrimSpace(options.Preflight.CompatibilityDigest),
		PreflightRelayCapabilitiesDigest: strings.TrimSpace(options.Preflight.RelayCapabilitiesDigest),
		IntegrationBundleDigest:          strings.TrimSpace(options.Preflight.IntegrationBundleDigest),
		BatchSizeMaximum:                 MaxBatchFindings,
		ConsumerIdentity:                 consumer,
	}

	roleDigests := make([]string, len(options.RoleOutputs))
	var candidates []candidate
	for sourceIndex, input := range options.RoleOutputs {
		document := input.Document
		if document.CharterHash != "" && document.CharterHash != options.FrozenCharter.CharterHash {
			plan.Diagnostics = append(plan.Diagnostics, diag.FromError(diag.New(
				CodeMixedCharter,
				"role-output document charter_hash does not match the frozen Charter.",
				diag.WithDetail("role_output", inputLabel(input, sourceIndex)),
				diag.WithDetail("charter_hash", document.CharterHash),
				diag.WithDetail("expected", options.FrozenCharter.CharterHash),
			)))
		}
		if preflightSnapshotDigest != "" && document.ArtifactDigest != "" && document.ArtifactDigest != preflightSnapshotDigest {
			plan.Diagnostics = append(plan.Diagnostics, diag.FromError(diag.New(
				CodeSnapshotArtifactMismatch,
				"role-output artifact digest does not match the preflight frozen snapshot.",
				diag.WithDetail("role_output", inputLabel(input, sourceIndex)),
				diag.WithDetail("artifact_digest", document.ArtifactDigest),
				diag.WithDetail("expected", preflightSnapshotDigest),
			)))
			continue
		}
		if preflightSnapshotDigest == "" && plan.ArtifactDigest == "" {
			plan.ArtifactDigest = document.ArtifactDigest
		} else if preflightSnapshotDigest == "" && document.ArtifactDigest != "" && document.ArtifactDigest != plan.ArtifactDigest {
			plan.Diagnostics = append(plan.Diagnostics, diag.FromError(diag.New(
				CodeMixedArtifact,
				"all planned role-output documents must reference the same reviewed artifact digest.",
				diag.WithDetail("role_output", inputLabel(input, sourceIndex)),
				diag.WithDetail("artifact_digest", document.ArtifactDigest),
				diag.WithDetail("expected", plan.ArtifactDigest),
			)))
			continue
		}

		roleDigest, err := contracts.RoleOutputDigest(document)
		if err != nil {
			plan.Diagnostics = append(plan.Diagnostics, diag.FromError(diag.Wrap(
				err,
				CodeInvalidRoleOutput,
				"role-output digest could not be computed.",
				diag.WithDetail("role_output", inputLabel(input, sourceIndex)),
			)))
			continue
		}
		roleDigests[sourceIndex] = roleDigest
		roleOutputRef := sourceRoleOutputRef(input, sourceIndex, document, roleDigest)
		diagnostics := contracts.ValidateRoleOutput(document, options.FrozenCharter)
		findingDiagnostics, documentDiagnostics := splitFindingDiagnostics(diagnostics)
		plan.Diagnostics = append(plan.Diagnostics, prefixedRoleDiagnostics(input, sourceIndex, documentDiagnostics)...)
		documentInvalid := len(documentDiagnostics) > 0
		if document.Role == contracts.RoleGoalFit {
			if len(document.Findings) > 0 {
				plan.ExcludedFindings = append(plan.ExcludedFindings, excludeDocumentFindings(document, roleOutputRef, roleDigest, CodeUnsupportedRole, documentDiagnostics)...)
			}
			continue
		}
		if document.Role != contracts.RoleDefect && document.Role != contracts.RoleEconomy {
			plan.ExcludedFindings = append(plan.ExcludedFindings, excludeDocumentFindings(document, roleOutputRef, roleDigest, CodeUnsupportedRole, documentDiagnostics)...)
			continue
		}
		for findingIndex, finding := range document.Findings {
			if documentInvalid {
				plan.ExcludedFindings = append(plan.ExcludedFindings, ExcludedFinding{
					Role:                   document.Role,
					FindingID:              finding.ID,
					SourceRoleOutputRef:    roleOutputRef,
					SourceRoleOutputDigest: roleDigest,
					Disposition:            DispositionAdvisory,
					Reason:                 CodeInvalidRoleOutput,
					Diagnostics:            documentDiagnostics,
				})
				continue
			}
			if diagnostics := findingDiagnostics[findingIndex]; len(diagnostics) > 0 {
				plan.ExcludedFindings = append(plan.ExcludedFindings, ExcludedFinding{
					Role:                   document.Role,
					FindingID:              finding.ID,
					SourceRoleOutputRef:    roleOutputRef,
					SourceRoleOutputDigest: roleDigest,
					Disposition:            DispositionAdvisory,
					Reason:                 CodeInvalidRoleOutput,
					Diagnostics:            diagnostics,
				})
				continue
			}
			if scopePolicy == contracts.ScopePolicyDeltaObligating && changeSurface != nil && !contracts.FindingInChangeSurface(finding, *changeSurface) {
				plan.ExcludedFindings = append(plan.ExcludedFindings, ExcludedFinding{
					Role:                   document.Role,
					FindingID:              finding.ID,
					SourceRoleOutputRef:    roleOutputRef,
					SourceRoleOutputDigest: roleDigest,
					Disposition:            DispositionAdvisory,
					ApplicationClass:       contracts.ApplicationClassCallerDecision,
					Reason:                 contracts.ReasonOutOfDelta,
				})
				continue
			}
			preSpendDiagnostics, reason := preSpendDiagnostics(document, finding, options.FrozenCharter)
			if len(preSpendDiagnostics) > 0 {
				plan.ExcludedFindings = append(plan.ExcludedFindings, ExcludedFinding{
					Role:                   document.Role,
					FindingID:              finding.ID,
					SourceRoleOutputRef:    roleOutputRef,
					SourceRoleOutputDigest: roleDigest,
					Disposition:            DispositionAdvisory,
					Reason:                 reason,
					Diagnostics:            preSpendDiagnostics,
				})
				continue
			}
			witnessDigest, err := contracts.WitnessDigest(finding.Witness)
			if err != nil {
				plan.ExcludedFindings = append(plan.ExcludedFindings, ExcludedFinding{
					Role:                   document.Role,
					FindingID:              finding.ID,
					SourceRoleOutputRef:    roleOutputRef,
					SourceRoleOutputDigest: roleDigest,
					Disposition:            DispositionAdvisory,
					Reason:                 CodeInvalidRoleOutput,
					Diagnostics:            []diag.Diagnostic{diag.FromError(diag.Wrap(err, CodeInvalidRoleOutput, "witness digest could not be computed."))},
				})
				continue
			}
			candidates = append(candidates, candidate{
				sourceIndex:   sourceIndex,
				role:          document.Role,
				taskShape:     taskShapeForRole(document.Role),
				claimed:       finding.ClaimedSeverity,
				id:            finding.ID,
				witnessDigest: witnessDigest,
			})
		}
	}

	sortCandidates(candidates)
	batches, err := buildBatches(options.RoleOutputs, roleDigests, candidates, plan)
	if err != nil {
		return nil, err
	}
	for _, batch := range batches {
		plan.Batches = append(plan.Batches, batch.Plan)
	}
	if plan.ArtifactDigest == "" {
		plan.ArtifactDigest = digest.RawBytes(nil)
	}
	if err := stampPlanDigest(&plan); err != nil {
		return nil, err
	}
	result.Plan = plan
	result.Batches = batches
	result.ManifestSkeleton = manifestSkeleton(plan)
	if options.StateDir != "" {
		if err := WriteState(options.StateDir, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func WriteState(stateDir string, result *Result) error {
	if result == nil {
		return nil
	}
	for index := range result.Batches {
		relative := filepath.ToSlash(filepath.Join("verification", "batches", result.Batches[index].Plan.BatchID+".json"))
		path := filepath.Join(stateDir, filepath.FromSlash(relative))
		if err := writeCanonicalFile(path, result.Batches[index].Document); err != nil {
			return err
		}
		result.Batches[index].Path = path
	}
	if result.Plan.ChangeSurface != nil {
		if err := writeCanonicalFile(filepath.Join(stateDir, "verification", "change-surface.json"), result.Plan.ChangeSurface); err != nil {
			return err
		}
	}
	if err := writeCanonicalFile(filepath.Join(stateDir, "verification-plan.json"), result.Plan); err != nil {
		return err
	}
	return writeCanonicalFile(filepath.Join(stateDir, "verification", "index.skeleton.json"), result.ManifestSkeleton)
}

func planChangeSurface(input ChangeSurfaceInput, scopePolicy string, passArtifactDigest string) (*changesurface.Document, string, *changesurface.BaselinePass, error) {
	hasBase := input.BaseManifest != nil
	hasHead := input.HeadManifest != nil
	if hasBase != hasHead {
		return nil, "", nil, diag.New(
			CodeMissingChangeSurface,
			"change surface derivation requires both -base-manifest and -head-manifest.",
			diag.WithDetail("base_manifest", hasBase),
			diag.WithDetail("head_manifest", hasHead),
		)
	}
	if input.BaselinePass && hasBase {
		return nil, "", nil, diag.New(CodeBaselineSurfaceConflict, "baseline_pass cannot be combined with derived change surface manifests.")
	}
	if hasBase && hasHead {
		surface, surfaceDigest, err := changesurface.Derive(*input.BaseManifest, *input.HeadManifest, passArtifactDigest)
		if err != nil {
			return nil, "", nil, err
		}
		return &surface, surfaceDigest, nil, nil
	}
	if scopePolicy == contracts.ScopePolicyDeltaObligating {
		if input.BaselinePass {
			return nil, "", &changesurface.BaselinePass{
				Declared: true,
				Reason:   changesurface.BaselinePassReasonExplicit,
			}, nil
		}
		return nil, "", nil, diag.New(
			CodeMissingChangeSurface,
			"delta_obligating scope policy requires derived change surface manifests or an explicit baseline_pass marker.",
			diag.WithDetail("scope_policy", scopePolicy),
		)
	}
	if input.BaselinePass {
		return nil, "", &changesurface.BaselinePass{
			Declared: true,
			Reason:   changesurface.BaselinePassReasonExplicit,
		}, nil
	}
	return nil, "", nil, nil
}

func preSpendDiagnostics(document contracts.RoleOutputDocument, finding contracts.Finding, frozen *charter.FrozenCharter) ([]diag.Diagnostic, string) {
	if document.Role == contracts.RoleDefect && frozen != nil {
		scope := charter.ValidateFindingScope(frozen.Charter.OperationalEnvelope, charter.FindingScope{
			FindingID: finding.ID,
			Kind:      charter.FindingKindDefect,
			Anchors:   finding.ScopeAnchors,
		})
		if !scope.Obligating || len(scope.Diagnostics) > 0 {
			return prefixDiagnostics("/scope_anchors", scope.Diagnostics), CodeScopeAdvisory
		}
	}
	if frozen != nil {
		kind := charter.FindingKindEconomy
		if finding.Kind == contracts.FindingKindDefect {
			kind = charter.FindingKindDefect
		}
		witness := charter.ValidateWitnessStructure(frozen.Charter.OperationalEnvelope, kind, charter.Witness{
			Kind:              finding.Witness.Kind,
			Strength:          finding.Witness.Strength,
			EntryPoint:        finding.Witness.EntryPoint,
			ReachabilityChain: finding.Witness.ReachabilityChain,
		})
		if !witness.Valid || len(witness.Diagnostics) > 0 {
			return prefixDiagnostics("/witness", witness.Diagnostics), CodeInvalidReachability
		}
	}
	// Review-rules caps are adjudication semantics: planning sends over-cap
	// claims to verification, and adjudication caps admitted or pending results.
	if finding.Recurrence != nil && finding.Recurrence.PriorFindingID == finding.ID {
		return []diag.Diagnostic{diag.FromError(diag.New(
			CodeRecursiveRecurrence,
			"recurrence lineage must not point to the current finding ID.",
			diag.WithPath("/recurrence/prior_finding_id"),
			diag.WithDetail("finding_id", finding.ID),
		))}, CodeRecursiveRecurrence
	}
	return nil, ""
}

func buildBatches(inputs []RoleOutputInput, roleDigests []string, candidates []candidate, planDocument PlanDocument) ([]BatchOutput, error) {
	var batches []BatchOutput
	roleCounts := map[string]int{}
	var current []candidate
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		first := current[0]
		roleCounts[first.role]++
		batchID := fmt.Sprintf("%s-batch-%d", first.role, roleCounts[first.role])
		ids := make([]string, len(current))
		for i, item := range current {
			ids[i] = item.id
		}
		document, err := contracts.NewVerificationBatch(inputs[first.sourceIndex].Document, batchID, ids)
		if err != nil {
			return err
		}
		batchDigest, err := persistedVerificationBatchDigest(document)
		if err != nil {
			return err
		}
		roleOutputRef := document.SourceRoleOutputRef
		if roleOutputRef.Digest == "" && roleDigests[first.sourceIndex] != "" {
			roleOutputRef.Digest = roleDigests[first.sourceIndex]
		}
		plan := BatchPlan{
			BatchID:                 batchID,
			Role:                    first.role,
			TaskShape:               first.taskShape,
			RecipeFamily:            recipeFamilyForTask(first.taskShape),
			CharterHash:             planDocument.CharterHash,
			CharterDigest:           planDocument.CharterDigest,
			ArtifactDigest:          planDocument.ArtifactDigest,
			ArtifactDigestSet:       plannedArtifactDigests(document.ArtifactDigest),
			PreflightSnapshotDigest: planDocument.PreflightSnapshotDigest,
			IntegrationBundleDigest: planDocument.IntegrationBundleDigest,
			SourceRoleOutputRef:     roleOutputRef,
			SourceRoleOutputDigest:  document.SourceRoleOutputDigest,
			BatchRef: contracts.ArtifactRef{
				Kind:          "verification-batch",
				ID:            batchID,
				Digest:        batchDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			},
			BatchDigest: batchDigest,
			FindingIDs:  ids,
		}
		batches = append(batches, BatchOutput{Plan: plan, Document: document})
		current = nil
		return nil
	}
	for _, item := range candidates {
		if len(current) > 0 {
			first := current[0]
			if first.sourceIndex != item.sourceIndex || first.role != item.role || len(current) == MaxBatchFindings {
				if err := flush(); err != nil {
					return nil, err
				}
			}
		}
		current = append(current, item)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return batches, nil
}

func sortCandidates(candidates []candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if roleRank(left.role) != roleRank(right.role) {
			return roleRank(left.role) < roleRank(right.role)
		}
		if severityRank(left.claimed) != severityRank(right.claimed) {
			return severityRank(left.claimed) < severityRank(right.claimed)
		}
		if left.id != right.id {
			return left.id < right.id
		}
		return left.sourceIndex < right.sourceIndex
	})
}

func manifestSkeleton(plan PlanDocument) ManifestSkeleton {
	skeleton := ManifestSkeleton{
		SchemaVersion:       ManifestSkeletonSchemaVersion,
		DigestProfile:       digest.Profile,
		PlanDigest:          plan.PlanDigest,
		CharterHash:         plan.CharterHash,
		ArtifactDigest:      plan.ArtifactDigest,
		ScopePolicy:         plan.ScopePolicy,
		ChangeSurface:       plan.ChangeSurface,
		ChangeSurfaceDigest: plan.ChangeSurfaceDigest,
		BaselinePass:        plan.BaselinePass,
		ExcludedFindings:    append([]ExcludedFinding(nil), plan.ExcludedFindings...),
		ConsumerIdentity:    cloneIdentity(plan.ConsumerIdentity),
	}
	for _, batch := range plan.Batches {
		skeleton.Batches = append(skeleton.Batches, ManifestSkeletonBatch{
			BatchID:     batch.BatchID,
			Status:      DispositionPendingVerification,
			BatchRef:    batch.BatchRef,
			BatchDigest: batch.BatchDigest,
			FindingIDs:  append([]string(nil), batch.FindingIDs...),
		})
		for _, findingID := range batch.FindingIDs {
			skeleton.PendingVerification = append(skeleton.PendingVerification, ManifestPendingFinding{
				FindingID: findingID,
				BatchID:   batch.BatchID,
			})
		}
	}
	return skeleton
}

func stampPlanDigest(plan *PlanDocument) error {
	unstamped := *plan
	unstamped.PlanDigest = ""
	digestValue, err := contracts.SemanticDigest(unstamped)
	if err != nil {
		return err
	}
	plan.PlanDigest = digestValue
	return nil
}

func splitFindingDiagnostics(diagnostics []diag.Diagnostic) (map[int][]diag.Diagnostic, []diag.Diagnostic) {
	byFinding := map[int][]diag.Diagnostic{}
	var document []diag.Diagnostic
	for _, diagnostic := range diagnostics {
		index, ok := findingIndexFromPath(diagnostic.Path)
		if !ok {
			document = append(document, diagnostic)
			continue
		}
		byFinding[index] = append(byFinding[index], diagnostic)
	}
	return byFinding, document
}

func findingIndexFromPath(path string) (int, bool) {
	if !strings.HasPrefix(path, "/findings/") {
		return 0, false
	}
	rest := strings.TrimPrefix(path, "/findings/")
	segment, _, _ := strings.Cut(rest, "/")
	if segment == "" {
		return 0, false
	}
	var value int
	for _, r := range segment {
		if r < '0' || r > '9' {
			return 0, false
		}
		value = value*10 + int(r-'0')
	}
	return value, true
}

func prefixedRoleDiagnostics(input RoleOutputInput, index int, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for i, diagnostic := range diagnostics {
		result[i] = diagnostic
		if result[i].Details == nil {
			result[i].Details = map[string]any{}
		}
		result[i].Details["role_output"] = inputLabel(input, index)
	}
	return result
}

func excludeDocumentFindings(document contracts.RoleOutputDocument, sourceRef contracts.ArtifactRef, sourceDigest string, reason string, diagnostics []diag.Diagnostic) []ExcludedFinding {
	excluded := make([]ExcludedFinding, 0, len(document.Findings))
	for _, finding := range document.Findings {
		excluded = append(excluded, ExcludedFinding{
			Role:                   document.Role,
			FindingID:              finding.ID,
			SourceRoleOutputRef:    sourceRef,
			SourceRoleOutputDigest: sourceDigest,
			Disposition:            DispositionAdvisory,
			Reason:                 reason,
			Diagnostics:            diagnostics,
		})
	}
	return excluded
}

func sourceRoleOutputRef(input RoleOutputInput, index int, document contracts.RoleOutputDocument, roleDigest string) contracts.ArtifactRef {
	id := strings.TrimSpace(input.RefID)
	if id == "" {
		id = strings.TrimSpace(document.Role)
	}
	if id == "" {
		id = inputLabel(input, index)
	}
	return contracts.ArtifactRef{
		Kind:          "role-output",
		ID:            id,
		Digest:        roleDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
}

func exceedsSeverityCap(claimed string, strength string, rules contracts.ReviewRules) bool {
	capSeverity := rules.SeverityCaps[strength]
	if capSeverity == "" {
		return true
	}
	claimedRank := severityRank(claimed)
	capRank := severityRank(capSeverity)
	return claimedRank >= 0 && capRank >= 0 && claimedRank < capRank
}

func severityRank(severity string) int {
	switch severity {
	case contracts.SeverityCritical:
		return 0
	case contracts.SeverityHigh:
		return 1
	case contracts.SeverityMedium:
		return 2
	case contracts.SeverityLow:
		return 3
	default:
		return 100
	}
}

func roleRank(role string) int {
	switch role {
	case contracts.RoleDefect:
		return 0
	case contracts.RoleEconomy:
		return 1
	case contracts.RoleGoalFit:
		return 2
	default:
		return 100
	}
}

func taskShapeForRole(role string) string {
	switch role {
	case contracts.RoleDefect:
		return contracts.BatchTaskDefect
	case contracts.RoleEconomy:
		return contracts.BatchTaskEconomy
	default:
		return ""
	}
}

func recipeFamilyForTask(taskShape string) string {
	switch taskShape {
	case contracts.BatchTaskDefect:
		return "witness-falsify-v2"
	case contracts.BatchTaskEconomy:
		return "economy-equivalence-v2"
	default:
		return ""
	}
}

func firstConsumerIdentity(inputs []RoleOutputInput, preflightSnapshotDigest string) map[string]any {
	for _, input := range inputs {
		if preflightSnapshotDigest != "" && input.Document.ArtifactDigest != preflightSnapshotDigest {
			continue
		}
		if len(input.Document.ConsumerIdentity) > 0 {
			return cloneIdentity(input.Document.ConsumerIdentity)
		}
	}
	return nil
}

func cloneIdentity(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func firstDiagnosticDetails(diagnostics []diag.Diagnostic) map[string]any {
	if len(diagnostics) == 0 {
		return nil
	}
	details := map[string]any{
		"diagnostic_code": diagnostics[0].Code,
		"message":         diagnostics[0].Message,
	}
	if diagnostics[0].Path != "" {
		details["path"] = diagnostics[0].Path
	}
	return details
}

func inputLabel(input RoleOutputInput, index int) string {
	if input.Path != "" {
		return input.Path
	}
	if input.RefID != "" {
		return input.RefID
	}
	return fmt.Sprintf("role-output-%d", index+1)
}

func prefixDiagnostics(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]diag.Diagnostic, len(diagnostics))
	for i, diagnostic := range diagnostics {
		result[i] = diagnostic
		if diagnostic.Path != "" {
			result[i].Path = prefix + diagnostic.Path
		} else {
			result[i].Path = prefix
		}
	}
	return result
}

func writeCanonicalFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return diag.Wrap(err, CodeOutputWriteFailed, "planning output directory could not be created.", diag.WithDetail("path", filepath.Dir(path)))
	}
	data, err := contracts.CanonicalBytes(value)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return diag.Wrap(err, CodeOutputWriteFailed, "planning output could not be written.", diag.WithDetail("path", path))
	}
	return nil
}

func persistedVerificationBatchBytes(document contracts.VerificationBatchDocument) ([]byte, error) {
	data, err := contracts.VerificationBatchCanonicalBytes(document)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func persistedVerificationBatchDigest(document contracts.VerificationBatchDocument) (string, error) {
	data, err := persistedVerificationBatchBytes(document)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(data), nil
}
