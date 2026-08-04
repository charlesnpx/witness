package policy

import (
	"errors"
	"testing"

	"github.com/charlesnpx/witness/internal/contracts"
	"github.com/charlesnpx/witness/internal/digest"
)

func TestPolicyLoadAndApplicationBranches(t *testing.T) {
	rules := contracts.DefaultReviewRules()
	charterHash := pd("charter")
	validPolicy := autoPolicy(5, 5)
	validRelease := releaseFor(t, validPolicy, rules, charterHash)
	filesRelease := validRelease
	filesRelease.Unit = UnitFiles

	tests := []struct {
		name          string
		policy        contracts.ReviewPolicy
		releases      []contracts.CapReleaseRecord
		charterHash   string
		check         ApplicationCheck
		wantLoadError bool
		wantAllow     bool
		wantReason    string
		wantMismatch  bool
	}{
		{
			name:        "bootstrap state refuses",
			policy:      contracts.DefaultReviewPolicy(),
			charterHash: charterHash,
			check:       positiveCheck(1, 1, 1, 1),
			wantReason:  ReasonPolicyDisabled,
		},
		{
			name:        "bootstrap measured-zero positive remedy refuses",
			policy:      contracts.DefaultReviewPolicy(),
			charterHash: charterHash,
			check:       positiveCheck(0, 0, 0, 0),
			wantReason:  ReasonPolicyDisabled,
		},
		{
			name:          "enabled with missing cap rejects on load",
			policy:        contracts.ReviewPolicy{SchemaVersion: contracts.ReviewPolicyV3, PolicyID: "policy-1", ScopePolicy: contracts.ScopePolicyWholeTree, DefectAdditiveAutoApplyEnabled: true},
			charterHash:   charterHash,
			check:         positiveCheck(1, 1, 1, 1),
			wantLoadError: true,
		},
		{
			name:          "enabled with zero cap rejects on load",
			policy:        autoPolicy(0, 5),
			releases:      []contracts.CapReleaseRecord{validRelease},
			charterHash:   charterHash,
			check:         positiveCheck(1, 1, 1, 1),
			wantLoadError: true,
		},
		{
			name:        "valid release allows measured in cap",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       positiveCheck(1, 1, 1, 1),
			wantAllow:   true,
			wantReason:  ReasonAllowed,
		},
		{
			name:        "unknown delta routes to refusal",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       positiveCheckUnknownEstimate(1, 1),
			wantReason:  ReasonUnknownEstimatedDelta,
		},
		{
			name:        "over cap estimate disqualifies",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       positiveCheck(6, 1, 1, 1),
			wantReason:  ReasonEstimatedDeltaOverCap,
		},
		{
			name:        "missing Operational Envelope blocks additive automation",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       withoutEnvelope(positiveCheck(1, 1, 1, 1)),
			wantReason:  ReasonMissingOperationalEnvelope,
		},
		{
			name:        "measured delta over cap refuses",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       positiveCheck(1, 1, 6, 1),
			wantReason:  ReasonMeasuredDeltaOverCap,
		},
		{
			name:        "measured delta unit mismatch refuses",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{filesRelease},
			charterHash: charterHash,
			check:       withUnit(positiveCheck(1, 1, 1, 1), UnitLines),
			wantReason:  ReasonMeasuredDeltaUnitMismatch,
		},
		{
			name:        "nonpositive remedy consumes no positive allowance",
			policy:      validPolicy,
			releases:    []contracts.CapReleaseRecord{validRelease},
			charterHash: charterHash,
			check:       nonPositiveCheck(50, 50, 0, -1),
			wantAllow:   true,
			wantReason:  ReasonNonPositiveRemedy,
		},
		{
			name:         "charter mismatch warns without revocation",
			policy:       validPolicy,
			releases:     []contracts.CapReleaseRecord{validRelease},
			charterHash:  pd("new-charter"),
			check:        positiveCheck(1, 1, 1, 1),
			wantAllow:    true,
			wantReason:   ReasonAllowed,
			wantMismatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			effective, err := Load(LoadOptions{
				Policy:      test.policy,
				Rules:       rules,
				CharterHash: test.charterHash,
				CapReleases: test.releases,
			})
			if test.wantLoadError {
				if err == nil {
					t.Fatal("Load succeeded, want error")
				}
				var validation *ValidationError
				if !errors.As(err, &validation) {
					t.Fatalf("error = %T, want ValidationError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			decision, err := CheckApplication(effective, test.check)
			if err != nil {
				t.Fatalf("CheckApplication: %v", err)
			}
			if decision.Allow != test.wantAllow {
				t.Fatalf("allow = %v, want %v; decision=%#v", decision.Allow, test.wantAllow, decision)
			}
			if len(decision.Reasons) != 1 || decision.Reasons[0] != test.wantReason {
				t.Fatalf("reasons = %#v, want %q", decision.Reasons, test.wantReason)
			}
			if decision.CapReleaseCharterMismatch != test.wantMismatch {
				t.Fatalf("mismatch = %v, want %v", decision.CapReleaseCharterMismatch, test.wantMismatch)
			}
			if test.wantReason == ReasonNonPositiveRemedy && decision.PositiveCapAllowanceConsumed {
				t.Fatal("nonpositive remedy consumed positive cap allowance")
			}
		})
	}
}

func TestPolicyLoadMatchesReleaseUnitWhenSpecified(t *testing.T) {
	rules := contracts.DefaultReviewRules()
	charterHash := pd("charter")
	document := autoPolicy(5, 5)
	release := releaseFor(t, document, rules, charterHash)
	release.Unit = UnitFiles

	if _, err := Load(LoadOptions{
		Policy:      document,
		Rules:       rules,
		CharterHash: charterHash,
		Unit:        UnitLines,
		CapReleases: []contracts.CapReleaseRecord{release},
	}); err == nil {
		t.Fatal("Load accepted a cap release with the wrong unit")
	}

	effective, err := Load(LoadOptions{
		Policy:      document,
		Rules:       rules,
		CharterHash: charterHash,
		Unit:        UnitFiles,
		CapReleases: []contracts.CapReleaseRecord{release},
	})
	if err != nil {
		t.Fatalf("Load with matching unit: %v", err)
	}
	decision, err := CheckApplication(effective, withUnit(positiveCheck(1, 1, 1, 1), UnitLines))
	if err != nil {
		t.Fatalf("CheckApplication: %v", err)
	}
	if decision.Allow || len(decision.Reasons) != 1 || decision.Reasons[0] != ReasonMeasuredDeltaUnitMismatch {
		t.Fatalf("decision = %#v, want unit mismatch refusal", decision)
	}
}

func TestBuildCapReleaseValidatesDigestsAndPolicyMatch(t *testing.T) {
	rules := contracts.DefaultReviewRules()
	policy := autoPolicy(5, 5)
	_, err := BuildCapRelease(ReleaseInput{
		Policy:        policy,
		Rules:         rules,
		Unit:          "lines",
		ProductionCap: 5,
		TestCap:       5,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner judgment.",
		Actor:         "owner",
		PolicyDigest:  pd("wrong-policy"),
		CharterHash:   pd("charter"),
	})
	if err == nil {
		t.Fatal("BuildCapRelease accepted mismatched policy digest")
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want ValidationError", err)
	}
	if len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Code != CodeCapReleaseDigestMismatch {
		t.Fatalf("diagnostics = %#v", validation.Diagnostics)
	}
}

func releaseFor(t *testing.T, document contracts.ReviewPolicy, rules contracts.ReviewRules, charterHash string) contracts.CapReleaseRecord {
	t.Helper()
	release, err := BuildCapRelease(ReleaseInput{
		Policy:        document,
		Rules:         rules,
		Unit:          "lines",
		ProductionCap: *document.ProductionCap,
		TestCap:       *document.TestCap,
		Basis:         contracts.CapReleaseBasisOwnerJudgment,
		Rationale:     "Owner judgment.",
		Actor:         "owner",
		CharterHash:   charterHash,
	})
	if err != nil {
		t.Fatalf("BuildCapRelease: %v", err)
	}
	return release
}

func autoPolicy(productionCap int, testCap int) contracts.ReviewPolicy {
	return contracts.ReviewPolicy{
		SchemaVersion:                  contracts.ReviewPolicyV3,
		PolicyID:                       "policy-1",
		ScopePolicy:                    contracts.ScopePolicyWholeTree,
		DefectAdditiveAutoApplyEnabled: true,
		ProductionCap:                  &productionCap,
		TestCap:                        &testCap,
	}
}

func positiveCheck(estimatedProduction int, estimatedTest int, measuredProduction int, measuredTest int) ApplicationCheck {
	return ApplicationCheck{
		Role:                       contracts.RoleDefect,
		RemedyDirection:            contracts.RemedyDirectionAdd,
		RemedySign:                 RemedySignPositive,
		OperationalEnvelopePresent: true,
		EstimatedDelta: contracts.SplitDeltaEstimate{
			Production: contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: estimatedProduction},
			Test:       contracts.DeltaEstimate{Status: contracts.DeltaStatusKnown, Lines: estimatedTest},
		},
		MeasuredDelta: &contracts.MeasuredDelta{Production: measuredProduction, Test: measuredTest},
	}
}

func positiveCheckUnknownEstimate(measuredProduction int, measuredTest int) ApplicationCheck {
	check := positiveCheck(0, 0, measuredProduction, measuredTest)
	check.EstimatedDelta.Production = contracts.DeltaEstimate{Status: contracts.DeltaStatusUnknown}
	return check
}

func nonPositiveCheck(estimatedProduction int, estimatedTest int, measuredProduction int, measuredTest int) ApplicationCheck {
	check := positiveCheck(estimatedProduction, estimatedTest, measuredProduction, measuredTest)
	check.RemedySign = RemedySignNonPositive
	check.RemedyDirection = contracts.RemedyDirectionChange
	return check
}

func withoutEnvelope(check ApplicationCheck) ApplicationCheck {
	check.OperationalEnvelopePresent = false
	return check
}

func withUnit(check ApplicationCheck, unit string) ApplicationCheck {
	check.Unit = unit
	return check
}

func pd(value string) string {
	return digest.RawBytes([]byte(value))
}
