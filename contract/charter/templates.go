package charter

import "sort"

const (
	TemplateMinimal        = "minimal"
	TemplateDeltaReview    = "delta-review"
	TemplateWholeTreeAudit = "whole-tree-audit"
)

func TemplateNames() []string {
	names := []string{TemplateMinimal, TemplateDeltaReview, TemplateWholeTreeAudit}
	sort.Strings(names)
	return names
}

func InitTemplate(name string, actor string, eventID string, summary string) (Charter, bool) {
	base := InitSkeleton(actor, eventID, summary)
	switch name {
	case "", TemplateMinimal:
		return base, true
	case TemplateDeltaReview:
		base.Goals = []Statement{{
			ID:        "preserve-reviewed-behavior",
			Statement: "Preserve the behavior intentionally covered by the reviewed change.",
		}}
		base.NonGoals = []Statement{{
			ID:        "unrelated-whole-tree-cleanup",
			Statement: "Do not expand the review into unrelated whole-tree cleanup.",
		}}
		base.OperationalEnvelope = templateEnvelope(
			boundedDimension("Only changed or directly affected entry points are in scope.", Entry{ID: "changed-entry-points", Statement: "Entry points touched by the reviewed delta or directly affected callers."}),
			boundedDimension("Inputs are limited to values accepted by the changed behavior.", Entry{ID: "changed-inputs", Statement: "Inputs introduced, removed, or reinterpreted by the reviewed delta."}),
			boundedDimension("Valid states are those reachable before and after the reviewed change.", Entry{ID: "reachable-state", Statement: "States reachable through supported workflows touched by the change."}),
			boundedDimension("Review assumes supported local and production-like environments.", Entry{ID: "supported-runtime", Statement: "The runtime, platform, and configuration the owner supports for this change."}),
			unboundedDimension("Scale bounds are inherited from the surrounding system unless the change states tighter limits."),
			boundedDimension("Compatibility promises are limited to declared callers and stored data contracts.", Entry{ID: "declared-compatibility", Statement: "Documented API, data, and workflow compatibility that the change claims to preserve."}),
			unboundedDimension("Threat model is limited to risks reachable through the changed behavior."),
		)
		return base, true
	case TemplateWholeTreeAudit:
		base.Goals = []Statement{{
			ID:        "preserve-product-behavior",
			Statement: "Preserve intended product behavior across the reviewed tree.",
		}, {
			ID:        "reduce-avoidable-complexity",
			Statement: "Identify simplifications that preserve the declared behavior.",
		}}
		base.NonGoals = []Statement{{
			ID:        "style-only-preferences",
			Statement: "Do not file style-only preferences without a behavioral, reliability, or maintainability consequence.",
		}}
		base.OperationalEnvelope = templateEnvelope(
			boundedDimension("All declared product entry points are in scope.", Entry{ID: "public-entry-points", Statement: "User, service, job, and command entry points intentionally exposed by the project."}),
			unboundedDimension("All supported inputs reachable through declared entry points are in scope."),
			unboundedDimension("All supported persisted, in-memory, and transitional states are in scope."),
			unboundedDimension("All owner-supported environments are in scope."),
			unboundedDimension("Owner-supported scale bounds are in scope."),
			unboundedDimension("Declared API, data, and workflow compatibility promises are in scope."),
			unboundedDimension("Threats reachable through supported entry points are in scope."),
		)
		return base, true
	default:
		return Charter{}, false
	}
}

func templateEnvelope(entryPoints Dimension, inputSurface Dimension, validStates Dimension, environments Dimension, scaleBounds Dimension, compatibilityPromises Dimension, threatModel Dimension) *OperationalEnvelope {
	return &OperationalEnvelope{
		EntryPoints:           &entryPoints,
		InputSurface:          &inputSurface,
		ValidStates:           &validStates,
		Environments:          &environments,
		ScaleBounds:           &scaleBounds,
		CompatibilityPromises: &compatibilityPromises,
		ThreatModel:           &threatModel,
	}
}

func boundedDimension(statement string, entries ...Entry) Dimension {
	if len(entries) == 0 {
		entries = []Entry{{ID: "declared", Statement: statement}}
	}
	return Dimension{
		State:     StateBounded,
		Statement: statement,
		Entries:   entries,
	}
}

func unboundedDimension(statement string) Dimension {
	return Dimension{
		State:     StateUnbounded,
		Statement: statement,
		Entries:   []Entry{},
	}
}
