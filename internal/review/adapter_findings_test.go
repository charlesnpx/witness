package review

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	contractreview "github.com/charlesnpx/witness/contract/review"
)

func TestFindingsDetermineSimpleAdapterVerdict(t *testing.T) {
	finding := func(id, attribution string) contractreview.ReviewReportV2Finding {
		return contractreview.ReviewReportV2Finding{
			ID:              id,
			Kind:            contractreview.FindingKindDefect,
			Title:           "A reproducible defect",
			ClaimedSeverity: contractreview.SeverityLow,
			Attribution:     attribution,
			CharterGoalIDs:  []string{},
			Witness: contractreview.ReportWitness{
				Kind:     contractreview.WitnessKindDefect,
				Strength: contractreview.WitnessStrengthArgued,
				Content:  "The error path returns success, so a caller cannot detect the failure.",
			},
		}
	}
	introduced := finding("introduced-defect", contractreview.FindingAttributionIntroduced)
	worsened := finding("worsened-defect", contractreview.FindingAttributionWorsened)
	preExisting := finding("existing-defect", contractreview.FindingAttributionPreExisting)
	preExisting.ClaimedSeverity = contractreview.SeverityHigh
	preExisting.Witness.Strength = contractreview.WitnessStrengthConstructed
	unattributed := finding("unattributed-defect", contractreview.FindingAttributionUnattributed)

	for _, test := range []struct {
		name            string
		findings        map[string][]contractreview.ReviewReportV2Finding
		invalidReviewer string
		wantVerdict     string
		wantDiagnostics []string
	}{
		{
			name: "introduced",
			findings: map[string][]contractreview.ReviewReportV2Finding{
				contractreview.RoleDefect: {introduced},
			},
			wantVerdict:     contractreview.CompletionVerdictNotSatisfied,
			wantDiagnostics: []string{`reviewer "defect": blocking finding "introduced-defect" (introduced)`},
		},
		{
			name: "worsened",
			findings: map[string][]contractreview.ReviewReportV2Finding{
				contractreview.RoleEconomy: {worsened},
			},
			wantVerdict:     contractreview.CompletionVerdictNotSatisfied,
			wantDiagnostics: []string{`reviewer "economy": blocking finding "worsened-defect" (worsened)`},
		},
		{
			name: "nonblocking",
			findings: map[string][]contractreview.ReviewReportV2Finding{
				contractreview.RoleDefect:  {preExisting},
				contractreview.RoleEconomy: {unattributed},
			},
			wantVerdict: contractreview.CompletionVerdictSatisfied,
		},
		{
			name: "invalid_report_takes_precedence",
			findings: map[string][]contractreview.ReviewReportV2Finding{
				contractreview.RoleDefect: {introduced},
			},
			invalidReviewer: contractreview.RoleEconomy,
			wantVerdict:     contractreview.CompletionVerdictFailedToRun,
			wantDiagnostics: []string{`reviewer "defect": blocking finding "introduced-defect" (introduced)`},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, frozen, packets := testRunInputs(t)
			resultPaths := testReportsWithFindings(t, request, frozen, test.findings)
			if test.invalidReviewer != "" {
				if err := os.WriteFile(resultPaths[test.invalidReviewer], []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			delegate, agentbus := fakeReviewCommands(t, resultPaths, JobExitCompleted)
			result, err := NewSimpleAdapter(SimpleAdapterOptions{
				DelegateExecutable: delegate,
				AgentbusExecutable: agentbus,
				PollInterval:       -1,
				TranscriptPageSize: 2,
			}).Run(context.Background(), SimpleRunOptions{
				Request:          request,
				FrozenCharter:    frozen,
				Packets:          packets,
				WorkingDirectory: t.TempDir(),
			})
			if err != nil {
				t.Fatalf("adapter Run: %v", err)
			}
			if result.Completion.Verdict != test.wantVerdict {
				t.Fatalf("verdict = %q, want %q", result.Completion.Verdict, test.wantVerdict)
			}
			for _, job := range result.Jobs {
				wantStatus := contractreview.ExecutionReportValid
				if job.Reviewer == test.invalidReviewer {
					wantStatus = contractreview.ExecutionReportInvalid
				}
				if job.ReportStatus != wantStatus {
					t.Errorf("reviewer %q report status = %q, want %q", job.Reviewer, job.ReportStatus, wantStatus)
				}
			}
			var blockingDiagnostics []string
			for _, diagnostic := range result.Diagnostics {
				if strings.Contains(diagnostic, ": blocking finding ") {
					blockingDiagnostics = append(blockingDiagnostics, diagnostic)
				}
			}
			if !reflect.DeepEqual(blockingDiagnostics, test.wantDiagnostics) {
				t.Errorf("blocking diagnostics = %q, want %q", blockingDiagnostics, test.wantDiagnostics)
			}
		})
	}
}
