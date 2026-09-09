package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/review"
	internalreview "github.com/charlesnpx/witness/internal/review"
)

const (
	// ReviewRunExitNotSatisfied means the review completed with a negative
	// consumer verdict.
	ReviewRunExitNotSatisfied = 20
	// ReviewRunExitFailedToRun means the review did not produce a usable run.
	ReviewRunExitFailedToRun = 21
)

const reviewRunDescription = "Prepare and execute an independent defect plus economy review. Exit status: 0=satisfied, 20=not_satisfied, 21=failed_to_run; other command errors use 2."

type reviewRunExitError struct {
	verdict string
	code    int
}

func (err reviewRunExitError) Error() string {
	return fmt.Sprintf("review run verdict %q", err.verdict)
}

func (err reviewRunExitError) processExitCode() int {
	return err.code
}

func runReview(command string, args []string) error {
	switch command {
	case "run":
		return runReviewRun(args)
	case "configure":
		return runReviewConfigure(args)
	default:
		return notImplemented("review " + command)
	}
}

func runReviewConfigure(args []string) error {
	flags := newFlagSet("witness review configure", "Validate and write the active review configuration.")
	out := flags.String("out", "", "configuration output path; defaults to the active XDG configuration path")
	adapterID := flags.String("adapter", internalreview.DefaultAdapterID, "adapter identifier")
	adapterExecutable := flags.String("adapter-executable", "", "custom adapter executable; it must pass --validate")
	adapterSkill := flags.String("adapter-skill", "", "custom adapter skill identifier")
	recipeID := flags.String("recipe", internalreview.DefaultRecipeID, "recipe identifier")
	requireTranscript := flags.Bool("require-transcript", false, "require complete Agentbus transcript capture")
	if helpRequested, err := parseFlags(flags, args); helpRequested || err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	path := *out
	if path == "" {
		var err error
		path, err = internalreview.ConfigPath()
		if err != nil {
			return err
		}
	}
	config := internalreview.Config{
		Adapter: internalreview.AdapterDescriptor{
			ID:         *adapterID,
			Executable: *adapterExecutable,
			Skill:      *adapterSkill,
		},
		Recipe: *recipeID,
		Policy: internalreview.Policy{
			RequireTranscript: *requireTranscript,
		},
	}
	if err := internalreview.ValidateConfig(config); err != nil {
		return fmt.Errorf("validate configuration before selection: %w", err)
	}
	if err := internalreview.ValidateImplementation(context.Background(), config.Adapter); err != nil {
		return fmt.Errorf("validate adapter before selection: %w", err)
	}
	if err := internalreview.WriteConfig(path, config); err != nil {
		return fmt.Errorf("write review configuration: %w", err)
	}
	return diag.WriteCanonical(os.Stdout, map[string]any{
		"ok":     true,
		"path":   path,
		"config": config,
	})
}

func runReviewRun(args []string) error {
	flags := newFlagSet("witness review run", reviewRunDescription)
	configPath := flags.String("config", "", "explicit review configuration path")
	charterPath := flags.String("charter", "", "Charter or frozen Charter JSON path")
	charterFreezePath := flags.String("charter-freeze", "", "alias for a frozen Charter JSON path")
	amendmentsPath := flags.String("amendments", "", "optional owner amendments JSONL path")
	sourceDir := flags.String("source-dir", ".", "reviewed source directory")
	outDir := flags.String("out-dir", "", "directory for prepared packets and completion record")
	inputDigest := flags.String("input-digest", "", "precomputed review input digest")
	subjectHead := flags.String("subject-head", "", "source revision label; defaults to git HEAD")
	subjectTree := flags.String("subject-tree", "", "optional source tree label")
	subjectBranch := flags.String("subject-branch", "", "optional source branch label")
	consumerKind := flags.String("consumer-kind", internalreview.DefaultConsumerKind, "consumer identity kind")
	consumerID := flags.String("consumer-id", internalreview.DefaultConsumerID, "consumer identity id")
	delegateExecutable := flags.String("delegate", "", "Delegate executable")
	agentbusExecutable := flags.String("agentbus", "", "Agentbus executable")
	backend := flags.String("backend", "", "Delegate backend; defaults to codex")
	pollInterval := flags.Duration("poll-interval", internalreview.DefaultPollInterval, "interval between Agentbus status observations")
	transcriptPageSize := flags.Int("transcript-page-size", internalreview.DefaultTranscriptPageSize, "forward transcript page size")
	if helpRequested, err := parseFlags(flags, args); helpRequested || err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if *charterPath != "" && *charterFreezePath != "" {
		return diag.New(diag.CodeInvalidCommand, "witness review run accepts only one of -charter and -charter-freeze.")
	}
	if *outDir == "" {
		return diag.New(diag.CodeInvalidCommand, "witness review run requires -out-dir.")
	}
	absoluteOutDir, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("resolve review output directory: %w", err)
	}
	config, err := loadReviewConfig(*configPath)
	if err != nil {
		return err
	}
	selectedCharter := *charterPath
	if *charterFreezePath != "" {
		selectedCharter = *charterFreezePath
	}
	prepared, result, err := internalreview.Run(context.Background(), internalreview.PrepareOptions{
		Config:            config,
		CharterPath:       selectedCharter,
		AmendmentsPath:    *amendmentsPath,
		SourceDir:         *sourceDir,
		PacketDirectory:   filepath.Join(absoluteOutDir, "packets"),
		Subject:           review.RequestSubject{Head: *subjectHead, Tree: *subjectTree, Branch: *subjectBranch},
		ReviewInputDigest: *inputDigest,
		ConsumerIdentity:  review.Identity{Kind: *consumerKind, ID: *consumerID},
	}, internalreview.SimpleAdapterOptions{
		DelegateExecutable: *delegateExecutable,
		AgentbusExecutable: *agentbusExecutable,
		Backend:            *backend,
		PollInterval:       *pollInterval,
		TranscriptPageSize: *transcriptPageSize,
	})
	if err != nil {
		return err
	}
	requestPath := filepath.Join(absoluteOutDir, "review-request.json")
	charterOutputPath := filepath.Join(absoluteOutDir, "charter.freeze.json")
	completionPath := filepath.Join(absoluteOutDir, "review-completion.json")
	if err := writeCanonical(requestPath, prepared.Request); err != nil {
		return fmt.Errorf("write prepared review request: %w", err)
	}
	if err := writeCanonical(charterOutputPath, prepared.FrozenCharter); err != nil {
		return fmt.Errorf("write prepared frozen Charter: %w", err)
	}
	if err := internalreview.WriteCompletion(completionPath, result.Completion); err != nil {
		return err
	}
	jobSummaries := make([]map[string]any, 0, len(result.Jobs))
	for _, job := range result.Jobs {
		summary := map[string]any{
			"reviewer":                  job.Reviewer,
			"job_id":                    job.JobID,
			"state":                     job.State,
			"state_exit_code":           job.StateExitCode,
			"report_status":             job.ReportStatus,
			"result_artifact_available": job.ResultArtifactAvailable,
			"transcript_complete":       job.Transcript.Complete,
			"transcript_gap":            job.Transcript.Gap,
		}
		if job.ResultError != "" {
			summary["result_error"] = job.ResultError
		}
		jobSummaries = append(jobSummaries, summary)
	}
	output := map[string]any{
		"ok":                  result.Completion.Verdict == review.CompletionVerdictSatisfied,
		"verdict":             result.Completion.Verdict,
		"request_path":        requestPath,
		"charter_freeze_path": charterOutputPath,
		"completion_path":     completionPath,
		"jobs":                jobSummaries,
	}
	if len(result.Diagnostics) > 0 {
		output["diagnostics"] = result.Diagnostics
	}
	if err := diag.WriteCanonical(os.Stdout, output); err != nil {
		return err
	}
	switch result.Completion.Verdict {
	case review.CompletionVerdictSatisfied:
		return nil
	case review.CompletionVerdictNotSatisfied:
		return reviewRunExitError{verdict: result.Completion.Verdict, code: ReviewRunExitNotSatisfied}
	case review.CompletionVerdictFailedToRun:
		return reviewRunExitError{verdict: result.Completion.Verdict, code: ReviewRunExitFailedToRun}
	default:
		return fmt.Errorf("review run returned unsupported verdict %q", result.Completion.Verdict)
	}
}

func loadReviewConfig(path string) (internalreview.Config, error) {
	if strings.TrimSpace(path) == "" {
		config, err := internalreview.LoadConfig()
		if err != nil {
			return internalreview.Config{}, err
		}
		return config, nil
	}
	config, err := internalreview.LoadConfigAt(path)
	if err != nil {
		return internalreview.Config{}, err
	}
	return config, nil
}
