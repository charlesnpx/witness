package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charlesnpx/witness/contract/charter"
	contractreview "github.com/charlesnpx/witness/contract/review"
	"github.com/charlesnpx/witness/contract/strictjson"
)

const (
	// DefaultReviewBackend is the backend used by the bundled simple adapter
	// when the caller has not selected one for this process.
	DefaultReviewBackend = "codex"
	// DefaultTranscriptPageSize bounds each forward transcript request.
	DefaultTranscriptPageSize = 64
	// DefaultPollInterval keeps Agentbus as the source of job state while
	// avoiding a busy loop between status calls.
	DefaultPollInterval = 100 * time.Millisecond
)

// Job outcome exit codes are returned by Agentbus for selected jobs. They are
// outcomes, not ordinary process-command failures.
const (
	JobExitCompleted             = 0
	JobExitQueuedOrRunning       = 2
	JobExitCompletedNoncompliant = 3
	JobExitFailed                = 4
	JobExitTimeout               = 5
	JobExitInterrupted           = 6
	JobExitCanceled              = 7
	JobExitUnknown               = 14
	JobExitResultUnavailable     = 15
)

// SimpleAdapterOptions controls the external commands used by SimpleAdapter.
// These are process options, not configuration-file fields.
type SimpleAdapterOptions struct {
	DelegateExecutable string
	AgentbusExecutable string
	Backend            string
	PollInterval       time.Duration
	TranscriptPageSize int
}

// ReviewerPacket is the prepared prompt and output schema for one independent
// reviewer job.
type ReviewerPacket struct {
	Reviewer   string
	PromptPath string
	SchemaPath string
}

// SimpleRunOptions supplies the frozen request and prepared packets to the
// simple adapter.
type SimpleRunOptions struct {
	Request          contractreview.ReviewRequestV2Document
	FrozenCharter    charter.FrozenCharter
	Packets          []ReviewerPacket
	WorkingDirectory string
	// SourceDigest is the source-tree digest captured during preparation. A
	// direct adapter caller may leave it empty; the adapter then captures the
	// digest before submitting any jobs.
	SourceDigest string
}

// TranscriptItem is a parsed, forward-paged Agentbus transcript item.
// Items are used to advance the cursor but are not retained after paging.
type TranscriptItem struct {
	Ordinal int `json:"ordinal"`
}

// TranscriptObservation keeps transcript completeness separate from report
// validity. Gap is meaningful only after the selected job is terminal.
type TranscriptObservation struct {
	Complete bool   `json:"complete"`
	Gap      bool   `json:"gap"`
	Error    string `json:"error,omitempty"`
}

// JobObservation is the host's observation of one submitted reviewer job.
type JobObservation struct {
	Reviewer                string                                 `json:"reviewer"`
	JobID                   string                                 `json:"job_id"`
	State                   string                                 `json:"state"`
	StateExitCode           int                                    `json:"state_exit_code"`
	ResultArtifactAvailable bool                                   `json:"result_artifact_available"`
	ReportStatus            string                                 `json:"report_status"`
	Report                  *contractreview.ReviewReportV2Document `json:"-"`
	ReportDigest            string                                 `json:"report_digest,omitempty"`
	Transcript              TranscriptObservation                  `json:"transcript"`
	ResultPath              string                                 `json:"result_path,omitempty"`
	ResultError             string                                 `json:"result_error,omitempty"`
}

// SimpleRunResult contains host observations and in-process completion made
// by a SimpleAdapter run. Completion is not read back from disk to establish
// proof.
type SimpleRunResult struct {
	Jobs               []JobObservation                        `json:"jobs"`
	ReportDigests      map[string]string                       `json:"report_digests"`
	ObservedExecution  contractreview.ObservedReviewExecution  `json:"observed_execution"`
	Evidence           contractreview.HostExecutionEvidence    `json:"-"`
	TranscriptComplete bool                                    `json:"transcript_complete"`
	Diagnostics        []string                                `json:"diagnostics,omitempty"`
	Completion         contractreview.ReviewCompletionDocument `json:"-"`
}

// SimpleAdapter submits independent jobs through Delegate and observes each
// job through Agentbus. It owns no persistent job state.
type SimpleAdapter struct {
	options SimpleAdapterOptions
}

// NewSimpleAdapter returns the bundled process-boundary adapter.
func NewSimpleAdapter(options SimpleAdapterOptions) SimpleAdapter {
	if options.DelegateExecutable == "" {
		options.DelegateExecutable = "delegate"
	}
	if options.AgentbusExecutable == "" {
		options.AgentbusExecutable = "agentbus"
	}
	if options.Backend == "" {
		options.Backend = DefaultReviewBackend
	}
	if options.PollInterval <= 0 {
		options.PollInterval = DefaultPollInterval
	}
	if options.TranscriptPageSize <= 0 {
		options.TranscriptPageSize = DefaultTranscriptPageSize
	}
	return SimpleAdapter{options: options}
}

// Run submits all reviewer jobs before observing any of them, then constructs
// trusted execution evidence from the outcomes actually observed.
func (adapter SimpleAdapter) Run(ctx context.Context, options SimpleRunOptions) (SimpleRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contractreview.RequireValidReviewRequestV2(options.Request); err != nil {
		return SimpleRunResult{}, fmt.Errorf("validate review request before adapter run: %w", err)
	}
	if err := validateFrozenCharter(options.FrozenCharter); err != nil {
		return SimpleRunResult{}, fmt.Errorf("validate frozen review Charter before adapter run: %w", err)
	}
	requireTranscript, err := transcriptRequiredByRequest(options.Request)
	if err != nil {
		return SimpleRunResult{}, fmt.Errorf("read frozen review policy before adapter run: %w", err)
	}
	if strings.TrimSpace(options.WorkingDirectory) == "" {
		return SimpleRunResult{}, errors.New("simple adapter requires a working directory")
	}
	workingDirectory, err := resolveReviewPath(options.WorkingDirectory)
	if err != nil {
		return SimpleRunResult{}, fmt.Errorf("resolve simple adapter working directory %q: %w", options.WorkingDirectory, err)
	}
	if info, statErr := os.Stat(workingDirectory); statErr != nil || !info.IsDir() {
		if statErr != nil {
			return SimpleRunResult{}, fmt.Errorf("simple adapter working directory %q: %w", workingDirectory, statErr)
		}
		return SimpleRunResult{}, fmt.Errorf("simple adapter working directory %q is not a directory", workingDirectory)
	}
	if strings.ContainsAny(adapter.options.DelegateExecutable, `/\`) {
		resolvedExecutable, resolveErr := resolveReviewPath(adapter.options.DelegateExecutable)
		if resolveErr != nil {
			return SimpleRunResult{}, fmt.Errorf("resolve simple adapter Delegate executable %q: %w", adapter.options.DelegateExecutable, resolveErr)
		}
		adapter.options.DelegateExecutable = resolvedExecutable
	}
	if strings.ContainsAny(adapter.options.AgentbusExecutable, `/\`) {
		resolvedExecutable, resolveErr := resolveReviewPath(adapter.options.AgentbusExecutable)
		if resolveErr != nil {
			return SimpleRunResult{}, fmt.Errorf("resolve simple adapter Agentbus executable %q: %w", adapter.options.AgentbusExecutable, resolveErr)
		}
		adapter.options.AgentbusExecutable = resolvedExecutable
	}
	packets, err := packetsForRequest(options.Request, options.Packets)
	if err != nil {
		return SimpleRunResult{}, err
	}
	sourceDigest := options.SourceDigest
	if sourceDigest == "" {
		sourceDigest, err = sourceDigestResolved(workingDirectory)
		if err != nil {
			return SimpleRunResult{}, fmt.Errorf("capture review source digest before adapter run: %w", err)
		}
	}

	type submittedJob struct {
		reviewer string
		jobID    string
	}
	submitted := make([]submittedJob, 0, len(packets))
	for _, packet := range packets {
		jobID, err := adapter.submit(ctx, workingDirectory, packet)
		if err != nil {
			return SimpleRunResult{}, fmt.Errorf("submit reviewer %q: %w", packet.Reviewer, err)
		}
		submitted = append(submitted, submittedJob{reviewer: packet.Reviewer, jobID: jobID})
	}

	result := SimpleRunResult{
		Jobs:          make([]JobObservation, 0, len(submitted)),
		ReportDigests: make(map[string]string),
	}
	observed := contractreview.ObservedReviewExecution{
		Complete:                true,
		ResultArtifactAvailable: true,
		ReportOutcomes:          make(map[string]contractreview.ObservedReportOutcome, len(submitted)),
	}
	for _, job := range submitted {
		observation, err := adapter.observe(ctx, job.reviewer, job.jobID, options.Request, options.FrozenCharter)
		if err != nil {
			return SimpleRunResult{}, fmt.Errorf("observe reviewer %q job %q: %w", job.reviewer, job.jobID, err)
		}
		result.Jobs = append(result.Jobs, observation)
		if observation.ResultError != "" {
			result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("reviewer %q: %s", job.reviewer, observation.ResultError))
		}
		observed.ReportOutcomes[job.reviewer] = contractreview.ObservedReportOutcome{Status: observation.ReportStatus}
		if !isTerminalState(observation.State) {
			observed.Complete = false
		}
		if !observation.ResultArtifactAvailable {
			observed.ResultArtifactAvailable = false
		}
		if observation.Report != nil {
			result.ReportDigests[job.reviewer] = observation.ReportDigest
		}
	}
	currentSourceDigest, sourceDigestErr := sourceDigestResolved(workingDirectory)
	sourceStable := sourceDigestErr == nil && currentSourceDigest == sourceDigest
	if sourceDigestErr != nil {
		result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("review source could not be re-hashed after reviewer collection; digest before %q; after: %v", sourceDigest, sourceDigestErr))
	} else if currentSourceDigest != sourceDigest {
		result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("review source changed during reviewer collection; digest before %q, after %q", sourceDigest, currentSourceDigest))
	}
	result.ObservedExecution = observed
	result.Evidence, err = contractreview.NewHostExecutionEvidence(observed)
	if err != nil {
		return SimpleRunResult{}, fmt.Errorf("construct host execution evidence: %w", err)
	}
	result.TranscriptComplete = true
	for _, job := range result.Jobs {
		if job.Transcript.Gap || !job.Transcript.Complete {
			result.TranscriptComplete = false
			break
		}
	}
	verdict := contractreview.CompletionVerdictSatisfied
	allJobsCompleted := true
	for _, job := range result.Jobs {
		if !jobCompleted(job) {
			allJobsCompleted = false
			break
		}
	}
	if !observed.Complete || !allJobsCompleted || !observed.ResultArtifactAvailable || !allReportsValid(observed, options.Request.RequiredOutputs) || (requireTranscript && !result.TranscriptComplete) || !sourceStable {
		verdict = contractreview.CompletionVerdictFailedToRun
	}
	result.Completion, err = contractreview.NewReviewCompletionDocument(options.Request, result.Evidence, result.ReportDigests, verdict)
	if err != nil {
		return SimpleRunResult{}, fmt.Errorf("construct review completion: %w", err)
	}
	return result, nil
}

func jobCompleted(job JobObservation) bool {
	if job.State != "completed" && job.State != "completed_noncompliant" {
		return false
	}
	switch job.StateExitCode {
	case JobExitCompleted, JobExitCompletedNoncompliant, JobExitResultUnavailable:
		return true
	default:
		return false
	}
}

func transcriptRequiredByRequest(request contractreview.ReviewRequestV2Document) (bool, error) {
	recipe, err := contractreview.ReviewRequestV2Recipe(request)
	if err != nil {
		return false, err
	}
	value, present := recipe.Policy["require_transcript"]
	if !present {
		return false, nil
	}
	required, ok := value.(bool)
	if !ok {
		return false, errors.New(`frozen recipe policy field "require_transcript" must be boolean`)
	}
	return required, nil
}

func allReportsValid(observed contractreview.ObservedReviewExecution, required []string) bool {
	for _, reviewer := range required {
		outcome, ok := observed.ReportOutcomes[reviewer]
		if !ok || outcome.Status != contractreview.ExecutionReportValid {
			return false
		}
	}
	return true
}

func packetsForRequest(request contractreview.ReviewRequestV2Document, packets []ReviewerPacket) ([]ReviewerPacket, error) {
	byReviewer := make(map[string]ReviewerPacket, len(packets))
	for _, packet := range packets {
		if packet.Reviewer == "" {
			return nil, errors.New("reviewer packet has no reviewer identifier")
		}
		if _, exists := byReviewer[packet.Reviewer]; exists {
			return nil, fmt.Errorf("reviewer packets repeat reviewer %q", packet.Reviewer)
		}
		if packet.PromptPath == "" {
			return nil, fmt.Errorf("reviewer packet %q has no prompt path", packet.Reviewer)
		}
		promptPath, err := resolveReviewPath(packet.PromptPath)
		if err != nil {
			return nil, fmt.Errorf("resolve reviewer packet %q prompt path %q: %w", packet.Reviewer, packet.PromptPath, err)
		}
		packet.PromptPath = promptPath
		if packet.SchemaPath != "" {
			schemaPath, err := resolveReviewPath(packet.SchemaPath)
			if err != nil {
				return nil, fmt.Errorf("resolve reviewer packet %q schema path %q: %w", packet.Reviewer, packet.SchemaPath, err)
			}
			packet.SchemaPath = schemaPath
		}
		byReviewer[packet.Reviewer] = packet
	}
	ordered := make([]ReviewerPacket, 0, len(request.RequiredOutputs))
	for _, reviewer := range request.RequiredOutputs {
		packet, ok := byReviewer[reviewer]
		if !ok {
			return nil, fmt.Errorf("reviewer packet for required output %q is missing", reviewer)
		}
		ordered = append(ordered, packet)
	}
	if len(byReviewer) != len(ordered) {
		return nil, errors.New("reviewer packets contain an output not required by the request")
	}
	return ordered, nil
}

func (adapter SimpleAdapter) submit(ctx context.Context, workingDirectory string, packet ReviewerPacket) (string, error) {
	args := []string{
		"task",
		"--backend", adapter.options.Backend,
		"--cwd", workingDirectory,
		"--prompt-file", packet.PromptPath,
	}
	if packet.SchemaPath != "" {
		args = append(args, "--schema-file", packet.SchemaPath)
	}
	output, exitCode, err := runProcess(ctx, adapter.options.DelegateExecutable, args...)
	if err != nil {
		return "", commandError(adapter.options.DelegateExecutable, args, output, exitCode, err)
	}
	object, err := decodeJSONObject(output)
	if err != nil {
		return "", fmt.Errorf("delegate submission did not emit JSON receipt: %w", err)
	}
	jobID, ok, err := stringField(object, "jobId")
	if err != nil {
		return "", fmt.Errorf("delegate submission receipt jobId: %w", err)
	}
	if !ok || strings.TrimSpace(jobID) == "" {
		return "", errors.New("delegate submission receipt has no jobId")
	}
	return jobID, nil
}

func (adapter SimpleAdapter) observe(ctx context.Context, reviewer string, jobID string, request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter) (JobObservation, error) {
	observation := JobObservation{
		Reviewer:     reviewer,
		JobID:        jobID,
		ReportStatus: contractreview.ExecutionReportMissing,
	}
	cursor := 0
	for {
		record, exitCode, err := adapter.readJobRecord(ctx, "status", jobID)
		if err != nil {
			return observation, err
		}
		observation.State = record.State
		observation.StateExitCode = exitCode
		terminal := isTerminalState(record.State) || isTerminalJobOutcomeExitCode(exitCode)
		if err := adapter.pageTranscript(ctx, jobID, &cursor, &observation.Transcript, terminal); err != nil {
			// Transcript capture is a separate claim. Keep the gap visible and
			// allow a result-valid run when policy does not require a transcript.
			observation.Transcript.Error = err.Error()
			if terminal {
				observation.Transcript.Gap = true
			}
		}
		if terminal {
			observation.Transcript.Complete = !observation.Transcript.Gap
			resultRecord, resultExitCode, resultErr := adapter.readJobRecord(ctx, "result", jobID)
			if resultErr != nil {
				return observation, resultErr
			}
			if resultRecord.State != "" {
				observation.State = resultRecord.State
			}
			// A terminal status normally has the same outcome code as the
			// result lookup. Preserve the status observation, but retain a
			// result-only artifact-unavailable/noncompliant outcome when the
			// artifact became unusable between the two calls.
			if observation.StateExitCode == JobExitQueuedOrRunning || (resultExitCode != JobExitCompleted && isTerminalJobOutcomeExitCode(resultExitCode)) {
				observation.StateExitCode = resultExitCode
			}
			status, report, reportDigest, available, resultPath, resultErr := validateObservedReport(resultRecord, request, frozen, reviewer)
			outcomeCode := exitCode
			if resultExitCode != JobExitCompleted && resultExitCode != JobExitQueuedOrRunning && isJobOutcomeExitCode(resultExitCode) {
				outcomeCode = resultExitCode
			}
			switch outcomeCode {
			case JobExitCompletedNoncompliant:
				status = contractreview.ExecutionReportInvalid
				report = nil
				reportDigest = ""
				if resultErr == nil {
					resultErr = errors.New("Agentbus reported a completed noncompliant result")
				}
			case JobExitResultUnavailable:
				status = contractreview.ExecutionReportUnavailable
				report = nil
				reportDigest = ""
				available = false
				if resultErr == nil {
					resultErr = errors.New("Agentbus reported that the result artifact is unavailable")
				}
			case JobExitFailed, JobExitTimeout, JobExitInterrupted, JobExitCanceled, JobExitUnknown:
				status = contractreview.ExecutionReportMissing
				report = nil
				reportDigest = ""
				available = false
				if resultErr == nil {
					resultErr = fmt.Errorf("Agentbus reported terminal job outcome exit code %d", outcomeCode)
				}
			}
			observation.ReportStatus = status
			observation.Report = report
			observation.ReportDigest = reportDigest
			observation.ResultArtifactAvailable = available
			observation.ResultPath = resultPath
			if resultErr != nil {
				observation.ResultError = resultErr.Error()
			}
			return observation, nil
		}
		if err := waitContext(ctx, adapter.options.PollInterval); err != nil {
			return observation, fmt.Errorf("wait for Agentbus job %q: %w", jobID, err)
		}
	}
}

func (adapter SimpleAdapter) readJobRecord(ctx context.Context, operation string, jobID string) (jobRecord, int, error) {
	args := []string{operation, "--job", jobID, "--json"}
	output, exitCode, err := runProcess(ctx, adapter.options.AgentbusExecutable, args...)
	if err != nil && !isJobOutcomeExitCode(exitCode) {
		return jobRecord{}, exitCode, commandError(adapter.options.AgentbusExecutable, args, output, exitCode, err)
	}
	object, decodeErr := decodeJSONObject(output)
	if decodeErr != nil {
		if err != nil {
			return jobRecord{}, exitCode, commandError(adapter.options.AgentbusExecutable, args, output, exitCode, fmt.Errorf("decode job outcome JSON: %w", decodeErr))
		}
		return jobRecord{}, exitCode, fmt.Errorf("decode Agentbus %s response for job %q: %w", operation, jobID, decodeErr)
	}
	if operation == "status" {
		object, decodeErr = selectedStatusObject(object, jobID)
		if decodeErr != nil {
			return jobRecord{}, exitCode, fmt.Errorf("decode Agentbus status response for job %q: %w", jobID, decodeErr)
		}
	}
	record, parseErr := parseJobRecord(object, jobID)
	if parseErr != nil {
		return jobRecord{}, exitCode, fmt.Errorf("parse Agentbus %s response for job %q: %w", operation, jobID, parseErr)
	}
	if err != nil && !isJobOutcomeExitCode(exitCode) {
		return jobRecord{}, exitCode, commandError(adapter.options.AgentbusExecutable, args, output, exitCode, err)
	}
	return record, exitCode, nil
}

func selectedStatusObject(response map[string]any, jobID string) (map[string]any, error) {
	rawJobs, wrapped := response["jobs"]
	if !wrapped {
		return response, nil
	}
	jobs, ok := rawJobs.([]any)
	if !ok {
		return nil, errors.New("jobs must be an array")
	}
	if len(jobs) != 1 {
		return nil, fmt.Errorf("selected status must contain exactly one job, got %d", len(jobs))
	}
	selected, ok := jobs[0].(map[string]any)
	if !ok {
		return nil, errors.New("selected status job must be an object")
	}
	if selectedID, present, err := stringField(selected, "jobId"); err != nil {
		return nil, err
	} else if present && strings.TrimSpace(selectedID) != "" && selectedID != jobID {
		return nil, fmt.Errorf("selected status jobId %q does not match requested job %q", selectedID, jobID)
	}
	return selected, nil
}

func (adapter SimpleAdapter) pageTranscript(ctx context.Context, jobID string, cursor *int, capture *TranscriptObservation, terminal bool) error {
	for {
		args := []string{
			"transcript",
			"--job", jobID,
			"--kind", "message",
			"--since-ordinal", fmt.Sprintf("%d", *cursor),
			"--limit", fmt.Sprintf("%d", adapter.options.TranscriptPageSize),
			"--json",
		}
		output, exitCode, err := runProcess(ctx, adapter.options.AgentbusExecutable, args...)
		if err != nil && !isJobOutcomeExitCode(exitCode) {
			return commandError(adapter.options.AgentbusExecutable, args, output, exitCode, err)
		}
		object, decodeErr := decodeJSONObject(output)
		if decodeErr != nil {
			return fmt.Errorf("decode Agentbus transcript for job %q: %w", jobID, decodeErr)
		}
		page, parseErr := parseTranscript(object)
		if parseErr != nil {
			return fmt.Errorf("parse Agentbus transcript for job %q: %w", jobID, parseErr)
		}
		if terminal && page.Gap {
			capture.Gap = true
		}
		previousCursor := *cursor
		highest := *cursor
		for _, item := range page.Items {
			if item.Ordinal > highest {
				highest = item.Ordinal
			}
		}
		if highest > *cursor {
			*cursor = highest
		}
		if len(page.Items) == 0 || len(page.Items) < adapter.options.TranscriptPageSize {
			return nil
		}
		// A full page without a forward ordinal is a broken cursor response.
		if highest <= previousCursor {
			if terminal {
				capture.Gap = true
			}
			return nil
		}
	}
}

func validateObservedReport(record jobRecord, request contractreview.ReviewRequestV2Document, frozen charter.FrozenCharter, expectedReviewer string) (string, *contractreview.ReviewReportV2Document, string, bool, string, error) {
	if record.Result == nil || !record.Result.MetadataComplete || strings.TrimSpace(record.Result.ResultPath) == "" {
		return contractreview.ExecutionReportMissing, nil, "", false, "", errors.New("result artifact is missing")
	}
	result := record.Result
	resultPath, err := resolveReviewPath(result.ResultPath)
	if err != nil {
		return contractreview.ExecutionReportUnavailable, nil, "", false, result.ResultPath, fmt.Errorf("resolve result artifact %q: %w", result.ResultPath, err)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		return contractreview.ExecutionReportUnavailable, nil, "", false, resultPath, fmt.Errorf("read result artifact %q: %w", resultPath, err)
	}
	if result.Bytes < 0 || int64(len(data)) != result.Bytes {
		return contractreview.ExecutionReportUnavailable, nil, "", false, resultPath, fmt.Errorf("result artifact %q byte count is %d, recorded %d", resultPath, len(data), result.Bytes)
	}
	if !bareSHA256(result.SHA256) {
		return contractreview.ExecutionReportUnavailable, nil, "", false, resultPath, fmt.Errorf("result artifact %q has invalid recorded sha256", resultPath)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(result.SHA256) {
		return contractreview.ExecutionReportUnavailable, nil, "", false, resultPath, fmt.Errorf("result artifact %q does not match recorded sha256", resultPath)
	}
	if record.Contract == nil || !record.Contract.compliant() {
		return contractreview.ExecutionReportInvalid, nil, "", true, resultPath, errors.New("Agentbus output contract is not compliant")
	}
	report, err := contractreview.DecodeAndValidateReviewReportV2(data, request, frozen)
	if err != nil {
		return contractreview.ExecutionReportInvalid, nil, "", true, resultPath, fmt.Errorf("validate review report: %w", err)
	}
	if report.Reviewer != expectedReviewer {
		return contractreview.ExecutionReportMissing, nil, "", true, resultPath, fmt.Errorf("reviewer %q job produced report for reviewer %q; required output for reviewer %q is missing", expectedReviewer, report.Reviewer, expectedReviewer)
	}
	reportDigest, err := contractreview.ReviewReportV2Digest(report)
	if err != nil {
		return contractreview.ExecutionReportInvalid, nil, "", true, resultPath, fmt.Errorf("digest review report: %w", err)
	}
	return contractreview.ExecutionReportValid, &report, reportDigest, true, resultPath, nil
}

type jobRecord struct {
	JobID    string
	State    string
	Result   *jobResult
	Contract *jobContract
}

type jobResult struct {
	ResultPath       string
	SHA256           string
	Bytes            int64
	MetadataComplete bool
}

type jobContract struct {
	Status           string
	StatusPresent    bool
	Evaluated        bool
	EvaluatedPresent bool
	Compliant        bool
	CompliantPresent bool
}

func parseJobRecord(object map[string]any, fallbackJobID string) (jobRecord, error) {
	jobID, jobIDPresent, err := stringField(object, "jobId")
	if err != nil {
		return jobRecord{}, err
	}
	if !jobIDPresent || strings.TrimSpace(jobID) == "" {
		jobID = fallbackJobID
	} else if fallbackJobID != "" && jobID != fallbackJobID {
		return jobRecord{}, fmt.Errorf("jobId %q does not match requested job %q", jobID, fallbackJobID)
	}
	state, ok, err := stringField(object, "state")
	if err != nil {
		return jobRecord{}, err
	}
	if !ok || !validJobState(state) {
		return jobRecord{}, fmt.Errorf("state must be one of queued, starting, running, retrying, completed, completed_noncompliant, failed, timed_out, interrupted, canceled, unknown, orphaned, reaped, quarantined")
	}
	record := jobRecord{JobID: jobID, State: state}
	if raw, exists := object["result"]; exists && raw != nil {
		resultObject, ok := raw.(map[string]any)
		if !ok {
			return jobRecord{}, errors.New("result must be an object")
		}
		path, _, err := stringField(resultObject, "resultPath")
		if err != nil {
			return jobRecord{}, err
		}
		sha, _, err := stringField(resultObject, "sha256")
		if err != nil {
			return jobRecord{}, err
		}
		bytesValue, bytesPresent, err := int64Field(resultObject, "bytes")
		if err != nil {
			return jobRecord{}, err
		}
		pathPresent := strings.TrimSpace(path) != ""
		shaPresent := strings.TrimSpace(sha) != ""
		record.Result = &jobResult{
			ResultPath:       path,
			SHA256:           sha,
			Bytes:            bytesValue,
			MetadataComplete: pathPresent && shaPresent && bytesPresent,
		}
	}
	if raw, exists := object["contract"]; exists && raw != nil {
		contractObject, ok := raw.(map[string]any)
		if !ok {
			return jobRecord{}, errors.New("contract must be an object")
		}
		status, statusPresent, err := stringField(contractObject, "status")
		if err != nil {
			return jobRecord{}, err
		}
		evaluated, evaluatedPresent, err := boolField(contractObject, "evaluated")
		if err != nil {
			return jobRecord{}, err
		}
		compliant, compliantPresent, err := boolField(contractObject, "compliant")
		if err != nil {
			return jobRecord{}, err
		}
		record.Contract = &jobContract{
			Status:           status,
			StatusPresent:    statusPresent,
			Evaluated:        evaluated,
			EvaluatedPresent: evaluatedPresent,
			Compliant:        compliant,
			CompliantPresent: compliantPresent,
		}
	}
	return record, nil
}

func parseTranscript(object map[string]any) (struct {
	Items []TranscriptItem
	Gap   bool
}, error) {
	var result struct {
		Items []TranscriptItem
		Gap   bool
	}
	rawGap, ok := object["gap"]
	if !ok || rawGap == nil {
		return result, errors.New("gap is required")
	}
	gap, ok := rawGap.(bool)
	if !ok {
		return result, errors.New("gap must be boolean")
	}
	result.Gap = gap
	rawItems, ok := object["items"]
	if !ok || rawItems == nil {
		return result, errors.New("items is required")
	}
	items, ok := rawItems.([]any)
	if !ok {
		return result, errors.New("items must be an array")
	}
	result.Items = make([]TranscriptItem, 0, len(items))
	for index, rawItem := range items {
		itemObject, ok := rawItem.(map[string]any)
		if !ok {
			return result, fmt.Errorf("items[%d] must be an object", index)
		}
		ordinal, ok, err := intField(itemObject, "ordinal")
		if err != nil {
			return result, err
		}
		if !ok {
			return result, fmt.Errorf("items[%d].ordinal is required", index)
		}
		if ordinal < 0 {
			return result, fmt.Errorf("items[%d].ordinal must not be negative", index)
		}
		result.Items = append(result.Items, TranscriptItem{Ordinal: ordinal})
	}
	return result, nil
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON response must be an object")
	}
	return object, nil
}

func runProcess(ctx context.Context, executable string, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	if ctx != nil && ctx.Err() != nil {
		return stdout.Bytes(), -1, ctx.Err()
	}
	exitCode := -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode = exitError.ExitCode()
	}
	return stdout.Bytes(), exitCode, err
}

func commandError(executable string, args []string, output []byte, exitCode int, cause error) error {
	detail := strings.TrimSpace(string(output))
	if detail != "" {
		return fmt.Errorf("%s %s failed with exit code %d: %w: %s", executable, strings.Join(args, " "), exitCode, cause, detail)
	}
	return fmt.Errorf("%s %s failed with exit code %d: %w", executable, strings.Join(args, " "), exitCode, cause)
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isTerminalState(state string) bool {
	switch state {
	case "completed", "completed_noncompliant", "failed", "timed_out", "interrupted", "canceled", "unknown", "orphaned", "reaped", "quarantined":
		return true
	default:
		return false
	}
}

func validJobState(state string) bool {
	switch state {
	case "queued", "starting", "running", "retrying", "completed", "completed_noncompliant", "failed", "timed_out", "interrupted", "canceled", "unknown", "orphaned", "reaped", "quarantined":
		return true
	default:
		return false
	}
}

func contractCompliant(status string) bool {
	switch status {
	case "compliant", "retried":
		return true
	default:
		return false
	}
}

func (contract *jobContract) compliant() bool {
	if contract == nil {
		return false
	}
	if contract.StatusPresent {
		if !contractCompliant(contract.Status) {
			return false
		}
		if contract.EvaluatedPresent || contract.CompliantPresent {
			return contract.EvaluatedPresent && contract.CompliantPresent && contract.Evaluated && contract.Compliant
		}
		return true
	}
	return contract.EvaluatedPresent && contract.CompliantPresent && contract.Evaluated && contract.Compliant
}

func isJobOutcomeExitCode(code int) bool {
	switch code {
	case JobExitCompleted, JobExitQueuedOrRunning, JobExitCompletedNoncompliant, JobExitFailed, JobExitTimeout, JobExitInterrupted, JobExitCanceled, JobExitUnknown, JobExitResultUnavailable:
		return true
	default:
		return false
	}
}

func isTerminalJobOutcomeExitCode(code int) bool {
	return isJobOutcomeExitCode(code) && code != JobExitQueuedOrRunning
}

func bareSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func stringField(object map[string]any, key string) (string, bool, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", true, fmt.Errorf("%s must be a string", key)
	}
	return text, true, nil
}

func boolField(object map[string]any, key string) (bool, bool, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return false, false, nil
	}
	typed, ok := value.(bool)
	if !ok {
		return false, true, fmt.Errorf("%s must be boolean", key)
	}
	return typed, true, nil
}

func int64Field(object map[string]any, key string) (int64, bool, error) {
	value, ok := object[key]
	if !ok || value == nil {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, true, fmt.Errorf("%s must be an integer", key)
	}
	parsed, err := number.Int64()
	if err != nil {
		return 0, true, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, true, nil
}

func intField(object map[string]any, key string) (int, bool, error) {
	value, ok, err := int64Field(object, key)
	if err != nil || !ok {
		return int(value), ok, err
	}
	if int64(int(value)) != value {
		return 0, true, fmt.Errorf("%s is outside the local integer range", key)
	}
	return int(value), true, nil
}
