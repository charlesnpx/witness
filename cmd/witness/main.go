package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"witness/internal/canonjson"
	"witness/internal/charter"
	"witness/internal/contracts"
	"witness/internal/diag"
	"witness/internal/digest"
	"witness/internal/planning"
	"witness/internal/preflight"
	"witness/internal/relayclient"
	"witness/internal/relayrun"
	"witness/internal/strictjson"
)

var witnessCommands = map[string]map[string]bool{
	"charter": {
		"init":   true,
		"freeze": true,
		"amend":  true,
		"show":   true,
	},
	"verification": {
		"preflight": true,
		"plan":      true,
		"assemble":  true,
	},
	"ledger": {
		"show":              true,
		"promote":           true,
		"accept-unverified": true,
	},
	"policy": {
		"show":              true,
		"release-caps":      true,
		"check-application": true,
	},
}

var singleCommands = map[string]bool{
	"adjudicate": true,
	"metrics":    true,
}

var verificationAssembleRelayRunner relayclient.Runner

func main() {
	if err := route(os.Args[1:]); err != nil {
		if diagnostics := diagnosticsFromError(err); len(diagnostics) > 0 {
			_ = diag.WriteCanonical(os.Stderr, map[string]any{
				"ok":          false,
				"diagnostics": diagnostics,
			})
			os.Exit(2)
		}
		diagnostic := diag.FromError(err)
		_ = diag.WriteCanonical(os.Stderr, map[string]any{
			"ok":          false,
			"diagnostics": []diag.Diagnostic{diagnostic},
		})
		os.Exit(2)
	}
}

func route(args []string) error {
	if len(args) == 0 {
		return diag.New(diag.CodeInvalidCommand, "missing witness command.")
	}
	if singleCommands[args[0]] {
		return notImplemented(args[0])
	}
	if subcommands, ok := witnessCommands[args[0]]; ok {
		if len(args) < 2 {
			return diag.New(
				diag.CodeInvalidCommand,
				fmt.Sprintf("missing %s subcommand.", args[0]),
				diag.WithDetail("command", args[0]),
			)
		}
		if subcommands[args[1]] {
			if args[0] == "charter" {
				return runCharter(args[1], args[2:])
			}
			if args[0] == "verification" {
				return runVerification(args[1], args[2:])
			}
			return notImplemented(strings.Join(args[:2], " "))
		}
	}
	return diag.New(
		diag.CodeInvalidCommand,
		"unknown witness command.",
		diag.WithDetail("args", args),
	)
}

func runVerification(command string, args []string) error {
	switch command {
	case "preflight":
		return runVerificationPreflight(args)
	case "plan":
		return runVerificationPlan(args)
	case "assemble":
		return runVerificationAssemble(args)
	default:
		return notImplemented("verification " + command)
	}
}

func runVerificationPreflight(args []string) error {
	flags := newFlagSet("witness verification preflight")
	relayPath := flags.String("relay", "", "convo-relay executable path")
	integrationBundlePath := flags.String("integration-bundle", "", "relay integration bundle path")
	stateDir := flags.String("state-dir", "", "preflight state directory")
	sourceDir := flags.String("source-dir", "", "reviewed source directory")
	snapshotDir := flags.String("snapshot-dir", "", "frozen source snapshot directory")
	allowNonGitSource := flags.Bool("allow-non-git-source", false, "allow freezing a non-git source directory")
	out := flags.String("out", "", "preflight result output path")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	result, err := preflight.Run(context.Background(), preflight.Options{
		RelayPath:             *relayPath,
		IntegrationBundlePath: *integrationBundlePath,
		StateDir:              *stateDir,
		SourceDir:             *sourceDir,
		SnapshotDir:           *snapshotDir,
		AllowNonGitSource:     *allowNonGitSource,
	})
	if err != nil {
		return err
	}
	return writeCanonical(*out, result)
}

func runVerificationPlan(args []string) error {
	flags := newFlagSet("witness verification plan")
	frozenPath := flags.String("charter-freeze", "", "frozen Charter path")
	stateDir := flags.String("state-dir", "", "verification state directory")
	out := flags.String("out", "", "verification plan output path")
	var roleOutputPaths repeatedStrings
	flags.Var(&roleOutputPaths, "role-output", "role-output JSON path; may be repeated")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if *frozenPath == "" {
		return diag.New(diag.CodeInvalidCommand, "witness verification plan requires -charter-freeze.")
	}
	if *stateDir == "" {
		return diag.New("verification_plan_missing_state_dir", "witness verification plan requires -state-dir.")
	}
	if len(roleOutputPaths) == 0 {
		return diag.New(diag.CodeInvalidCommand, "witness verification plan requires at least one -role-output.")
	}
	frozen, err := readFrozenCharterFile(*frozenPath)
	if err != nil {
		return err
	}
	inputs := make([]planning.RoleOutputInput, 0, len(roleOutputPaths))
	for _, path := range roleOutputPaths {
		document, err := readRoleOutputFile(path)
		if err != nil {
			return err
		}
		inputs = append(inputs, planning.RoleOutputInput{
			Path:     path,
			RefID:    artifactIDFromPath(path),
			Document: document,
		})
	}
	result, err := planning.Run(planning.Options{
		FrozenCharter: &frozen,
		RoleOutputs:   inputs,
		StateDir:      *stateDir,
	})
	if err != nil {
		return err
	}
	if *out != "" {
		return writeCanonical(*out, result.Plan)
	}
	return diag.WriteCanonical(os.Stdout, result.Plan)
}

func runVerificationAssemble(args []string) error {
	flags := newFlagSet("witness verification assemble")
	planPath := flags.String("plan", "", "verification plan path")
	compatibilityPath := flags.String("compatibility-manifest", "", "retained compatibility manifest path")
	capabilitiesPath := flags.String("relay-capabilities", "", "retained relay capabilities path")
	integrationBundlePath := flags.String("integration-bundle", "", "retained integration bundle path")
	stateDir := flags.String("state-dir", "", "verification state directory")
	runRelay := flags.Bool("run-relay", false, "run planned relay verification batches before assembly")
	relayPath := flags.String("relay", "", "convo-relay executable path")
	backend := flags.String("backend", "", "relay backend suffix for verification recipes")
	charterPath := flags.String("charter-freeze", "", "frozen Charter path for relay verification runs")
	workspaceIsolation := flags.String("workspace-isolation", "", "relay workspace isolation mode")
	relayHome := flags.String("relay-home", "", "convo-relay home directory")
	launchCWD := flags.String("launch-cwd", "", "relay launch working directory")
	settingsPath := flags.String("settings", "", "convo-relay settings path")
	allowDirtySource := flags.Bool("allow-dirty-source", false, "allow dirty relay launch source")
	receiptOutputDir := flags.String("receipt-output-dir", "", "witness-harness output directory for receipt verification")
	receiptHMACKeyFile := flags.String("receipt-hmac-key-file", "", "HMAC key file for execution receipt verification")
	out := flags.String("out", "", "verification manifest output path")
	var batchPaths repeatedStrings
	var verdictPaths repeatedStrings
	var portableExports repeatedStrings
	var receiptPaths repeatedStrings
	var selectedContractPaths repeatedStrings
	var artifactPaths repeatedStrings
	flags.Var(&batchPaths, "batch", "verification-batch JSON path; may be repeated")
	flags.Var(&verdictPaths, "relay-verdict", "relay verdict JSON path or batch-id=path; may be repeated")
	flags.Var(&portableExports, "portable-export", "batch-id=portable export directory; may be repeated")
	flags.Var(&receiptPaths, "receipt", "execution receipt JSON path; may be repeated")
	flags.Var(&selectedContractPaths, "selected-contract", "selected relay contract artifact path; may be repeated")
	flags.Var(&artifactPaths, "artifact", "artifact input path for relay verification runs; may be repeated")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if *planPath == "" {
		return diag.New(diag.CodeInvalidCommand, "witness verification assemble requires -plan.")
	}
	if *runRelay && (len(verdictPaths) > 0 || len(portableExports) > 0) {
		return diag.New(diag.CodeInvalidCommand, "witness verification assemble -run-relay cannot be combined with pre-produced relay evidence flags.")
	}
	plan, err := readPlanFile(*planPath)
	if err != nil {
		return err
	}
	batches, err := readBatchEvidence(batchPaths)
	if err != nil {
		return err
	}
	relayEvidence, err := readRelayEvidence(verdictPaths, portableExports)
	if err != nil {
		return err
	}
	if *runRelay {
		runBatches, err := relayRunBatchInputs(plan, batches, *stateDir)
		if err != nil {
			return err
		}
		runResult, err := relayrun.RunBatches(context.Background(), runBatches, relayrun.Options{
			RelayPath:             *relayPath,
			IntegrationBundlePath: *integrationBundlePath,
			CharterPath:           *charterPath,
			ArtifactPaths:         append([]string(nil), artifactPaths...),
			OutputDir:             *stateDir,
			Backend:               *backend,
			WorkspaceIsolation:    *workspaceIsolation,
			RelayHome:             *relayHome,
			LaunchCWD:             *launchCWD,
			SettingsPath:          *settingsPath,
			AllowDirtySource:      *allowDirtySource,
			Runner:                verificationAssembleRelayRunner,
		})
		if err != nil {
			return err
		}
		relayEvidence = relayEvidenceFromRunResult(runResult)
		batches = batchEvidenceFromRunInputs(runBatches)
	}
	receipts, err := readReceipts(receiptPaths)
	if err != nil {
		return err
	}
	evidenceRefs, err := manifestEvidenceRefs(*compatibilityPath, *capabilitiesPath, *integrationBundlePath, selectedContractPaths, plan.ConsumerIdentity)
	if err != nil {
		return err
	}
	result, err := planning.Assemble(planning.AssembleOptions{
		Plan:         plan,
		Batches:      batches,
		RelayResults: relayEvidence,
		Receipts:     receipts,
		EvidenceRefs: evidenceRefs,

		ReceiptOutputDir:   *receiptOutputDir,
		ReceiptHMACKeyFile: *receiptHMACKeyFile,
	})
	if err != nil {
		if result != nil {
			if writeErr := writeCanonical(*out, result.Manifest); writeErr != nil {
				return writeErr
			}
		}
		return err
	}
	return writeCanonical(*out, verificationAssembleOutput(result))
}

func verificationAssembleOutput(result *planning.AssembleResult) any {
	if len(result.UnverifiedRelationships) > 0 {
		return result
	}
	return result.Manifest
}

type repeatedStrings []string

func (values *repeatedStrings) String() string {
	if values == nil {
		return ""
	}
	return strings.Join(*values, ",")
}

func (values *repeatedStrings) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func readFrozenCharterFile(path string) (charter.FrozenCharter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return charter.FrozenCharter{}, fileReadError(err, path, "open frozen Charter")
	}
	return strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
}

func readRoleOutputFile(path string) (contracts.RoleOutputDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.RoleOutputDocument{}, fileReadError(err, path, "open role-output")
	}
	return contracts.ReadRoleOutputBytes(data)
}

func readPlanFile(path string) (planning.PlanDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return planning.PlanDocument{}, fileReadError(err, path, "open verification plan")
	}
	return strictjson.DecodeBytes[planning.PlanDocument](data, strictjson.DefaultMaxBytes*4)
}

func readBatchEvidence(paths []string) ([]planning.BatchEvidence, error) {
	batches := make([]planning.BatchEvidence, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fileReadError(err, path, "open verification batch")
		}
		document, err := contracts.ReadVerificationBatchBytes(data)
		if err != nil {
			return nil, err
		}
		batches = append(batches, planning.BatchEvidence{
			BatchID:  document.BatchID,
			Document: document,
			Path:     path,
			RawBytes: append([]byte(nil), data...),
		})
	}
	return batches, nil
}

func relayRunBatchInputs(plan planning.PlanDocument, batches []planning.BatchEvidence, stateDir string) ([]relayrun.BatchInput, error) {
	if stateDir == "" {
		return nil, diag.New("verification_assemble_missing_state_dir", "witness verification assemble -run-relay requires -state-dir.")
	}
	byID := map[string]planning.BatchEvidence{}
	for _, batch := range batches {
		id := batch.BatchID
		if id == "" {
			id = batch.Document.BatchID
		}
		byID[id] = batch
	}
	inputs := make([]relayrun.BatchInput, 0, len(plan.Batches))
	for _, planned := range plan.Batches {
		batch := byID[planned.BatchID]
		if batch.Document.BatchID == "" {
			path := filepath.Join(stateDir, "verification", "batches", planned.BatchID+".json")
			loaded, err := readBatchEvidence([]string{path})
			if err != nil {
				return nil, err
			}
			batch = loaded[0]
		}
		inputs = append(inputs, relayrun.BatchInput{
			Plan:     planned,
			Document: batch.Document,
			Path:     batch.Path,
			RawBytes: append([]byte(nil), batch.RawBytes...),
		})
	}
	return inputs, nil
}

func batchEvidenceFromRunInputs(inputs []relayrun.BatchInput) []planning.BatchEvidence {
	batches := make([]planning.BatchEvidence, 0, len(inputs))
	for _, input := range inputs {
		batches = append(batches, planning.BatchEvidence{
			BatchID:  input.Plan.BatchID,
			Document: input.Document,
			Path:     input.Path,
			RawBytes: append([]byte(nil), input.RawBytes...),
		})
	}
	return batches
}

func relayEvidenceFromRunResult(result *relayrun.Result) []planning.RelayEvidence {
	if result == nil {
		return nil
	}
	evidence := make([]planning.RelayEvidence, 0, len(result.Runs))
	for _, run := range result.Runs {
		if run.PortableExportDir == "" {
			continue
		}
		record := planning.RelayEvidence{
			BatchID:           run.BatchID,
			PortableExportDir: run.PortableExportDir,
		}
		if run.PortableExportDigest != "" {
			record.PortableExportRef = &contracts.ArtifactRef{
				Kind:          "relay-root-portable-export",
				ID:            run.BatchID,
				Digest:        run.PortableExportDigest,
				DigestProfile: digest.Profile,
				MediaType:     "application/json",
			}
		}
		evidence = append(evidence, record)
	}
	return evidence
}

func readRelayEvidence(verdictSpecs []string, portableSpecs []string) ([]planning.RelayEvidence, error) {
	byBatch := map[string]planning.RelayEvidence{}
	for _, spec := range portableSpecs {
		batchID, path, ok := splitKeyValueSpec(spec)
		if !ok {
			return nil, diag.New(diag.CodeInvalidCommand, "portable export bindings must use batch-id=directory.", diag.WithDetail("value", spec))
		}
		record := byBatch[batchID]
		record.BatchID = batchID
		record.PortableExportDir = path
		byBatch[batchID] = record
	}
	for _, spec := range verdictSpecs {
		batchID, path, bound := splitKeyValueSpec(spec)
		if !bound {
			path = spec
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fileReadError(err, path, "open relay verdicts")
		}
		verdicts, err := contracts.ReadRelayWitnessVerdictsBytes(data)
		if err != nil {
			return nil, err
		}
		if batchID == "" {
			batchID = verdicts.BatchID
		}
		record := byBatch[batchID]
		record.BatchID = batchID
		record.Verdicts = &verdicts
		byBatch[batchID] = record
	}
	result := make([]planning.RelayEvidence, 0, len(byBatch))
	for _, record := range byBatch {
		result = append(result, record)
	}
	return result, nil
}

func readReceipts(paths []string) ([]contracts.ExecutionReceipt, error) {
	receipts := make([]contracts.ExecutionReceipt, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fileReadError(err, path, "open execution receipt")
		}
		receipt, err := contracts.ReadExecutionReceiptBytes(data)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func manifestEvidenceRefs(
	compatibilityPath string,
	capabilitiesPath string,
	integrationBundlePath string,
	selectedContractPaths []string,
	consumerIdentity map[string]any,
) (planning.ManifestEvidenceRefs, error) {
	refs := planning.ManifestEvidenceRefs{ConsumerIdentity: cloneMap(consumerIdentity)}
	var err error
	if compatibilityPath != "" {
		refs.CompatibilityManifest, err = artifactRefForFile("compatibility-manifest", compatibilityPath)
		if err != nil {
			return refs, err
		}
	}
	if capabilitiesPath != "" {
		refs.RelayCapabilities, err = artifactRefForFile("relay-capabilities", capabilitiesPath)
		if err != nil {
			return refs, err
		}
	}
	if integrationBundlePath != "" {
		refs.IntegrationBundle, err = artifactRefForFile("integration-bundle", integrationBundlePath)
		if err != nil {
			return refs, err
		}
	}
	for _, path := range selectedContractPaths {
		contractRefs, contractEvidence, err := selectedContractRefsAndEvidenceForFile(path)
		if err != nil {
			return refs, err
		}
		refs.SelectedContracts = append(refs.SelectedContracts, contractRefs...)
		refs.SelectedContractEvidence = append(refs.SelectedContractEvidence, contractEvidence...)
	}
	return refs, nil
}

func selectedContractRefsForFile(path string) ([]contracts.ArtifactRef, error) {
	refs, _, err := selectedContractRefsAndEvidenceForFile(path)
	return refs, err
}

func selectedContractRefsAndEvidenceForFile(path string) ([]contracts.ArtifactRef, []planning.SelectedContractEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fileReadError(err, path, "open artifact reference source")
	}
	authenticated, err := planning.AuthenticatedSelectedContractsFromBytes(data)
	if err != nil {
		return nil, nil, err
	}
	refs := make([]contracts.ArtifactRef, 0, len(authenticated))
	evidence := make([]planning.SelectedContractEvidence, 0, len(authenticated))
	baseID := artifactIDFromPath(path)
	for _, contract := range authenticated {
		id := baseID
		if len(authenticated) > 1 {
			id += ":" + artifactIDFromText(contract.ContractID)
		}
		ref := artifactRef("selected-contract", id, contract.ContractDigest)
		refs = append(refs, ref)
		evidence = append(evidence, planning.SelectedContractEvidence{
			Ref:        ref,
			ContractID: contract.ContractID,
			Path:       path,
			RawBytes:   append([]byte(nil), data...),
		})
	}
	return refs, evidence, nil
}

func artifactRefForFile(kind string, path string) (contracts.ArtifactRef, error) {
	if kind == "selected-contract" {
		refs, _, err := selectedContractRefsAndEvidenceForFile(path)
		if err != nil {
			return contracts.ArtifactRef{}, err
		}
		if len(refs) != 1 {
			return contracts.ArtifactRef{}, diag.New(diag.CodeInvalidCommand, "selected-contract artifact reference source retained multiple contracts; use selectedContractRefsForFile.", diag.WithDetail("path", path))
		}
		return refs[0], nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.ArtifactRef{}, fileReadError(err, path, "open artifact reference source")
	}
	refDigest := digest.RawBytes(data)
	if value, err := strictjson.DecodeAnyBytes(data, strictjson.DefaultMaxBytes*32); err == nil {
		if object, ok := value.(map[string]any); ok {
			if payloadDigest, ok := object["payload_digest"].(string); ok && strings.TrimSpace(payloadDigest) != "" {
				payload, hasPayload := object["payload"]
				if !hasPayload {
					return contracts.ArtifactRef{}, diag.New(diag.CodeInvalidCommand, "retained artifact payload_digest requires a retained payload.", diag.WithDetail("path", path))
				}
				payloadBytes, err := canonjson.Marshal(payload)
				if err != nil {
					return contracts.ArtifactRef{}, err
				}
				actualDigest := digest.RawBytes(payloadBytes)
				if actualDigest != strings.TrimSpace(payloadDigest) {
					return contracts.ArtifactRef{}, diag.New(
						diag.CodeInvalidCommand,
						"retained artifact payload_digest does not match the retained payload.",
						diag.WithDetail("path", path),
						diag.WithDetail("actual_digest", actualDigest),
						diag.WithDetail("expected_digest", strings.TrimSpace(payloadDigest)),
					)
				}
				refDigest = actualDigest
			}
		}
	}
	return artifactRef(kind, artifactIDFromPath(path), refDigest), nil
}

func artifactRef(kind string, id string, refDigest string) contracts.ArtifactRef {
	return contracts.ArtifactRef{
		Kind:          kind,
		ID:            id,
		Digest:        refDigest,
		DigestProfile: digest.Profile,
		MediaType:     "application/json",
	}
}

func splitKeyValueSpec(value string) (string, string, bool) {
	left, right, ok := strings.Cut(value, "=")
	if !ok {
		return "", value, false
	}
	return strings.TrimSpace(left), strings.TrimSpace(right), true
}

func artifactIDFromPath(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if base == "" {
		base = "artifact"
	}
	return artifactIDFromText(base)
}

func artifactIDFromText(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == ':':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	id := strings.Trim(builder.String(), ".-_")
	if id == "" {
		return "artifact"
	}
	return id
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func fileReadError(err error, path string, action string) error {
	return diag.Wrap(
		err,
		charter.CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", action),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}

func notImplemented(command string) error {
	return diag.New(
		diag.CodeNotImplemented,
		"witness command routing is present; implementation is assigned to a later unit.",
		diag.WithDetail("command", command),
	)
}

func runCharter(command string, args []string) error {
	switch command {
	case "init":
		return runCharterInit(args)
	case "freeze":
		return runCharterFreeze(args)
	case "amend":
		return runCharterAmend(args)
	case "show":
		return runCharterShow(args)
	default:
		return notImplemented("charter " + command)
	}
}

func runCharterInit(args []string) error {
	flags := newFlagSet("witness charter init")
	out := flags.String("out", "", "charter skeleton path")
	actor := flags.String("actor", "owner", "owner actor")
	eventID := flags.String("event-id", "initial-charter", "initial owner event ID")
	summary := flags.String("summary", "Initial owner-authorized charter skeleton.", "initial owner event summary")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if *out == "" {
		return diag.New(diag.CodeInvalidCommand, "witness charter init requires -out.")
	}
	skeleton := charter.InitSkeleton(*actor, *eventID, *summary)
	if _, err := charter.Normalize(skeleton, nil); err != nil {
		return err
	}
	return writeCanonical(*out, skeleton)
}

func runCharterFreeze(args []string) error {
	flags := newFlagSet("witness charter freeze")
	charterPath := flags.String("charter", "", "charter JSON path")
	amendmentsPath := flags.String("amendments", "", "amendments JSONL path")
	out := flags.String("out", "", "frozen charter output path")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if err := rejectOutputPathAliases(*out, protectedInput{role: "charter", path: *charterPath}, protectedInput{role: "amendments", path: *amendmentsPath}); err != nil {
		return err
	}
	input, amendments, err := loadCharterInputs(*charterPath, *amendmentsPath)
	if err != nil {
		return err
	}
	frozen, err := charter.Freeze(input, amendments)
	if err != nil {
		return err
	}
	return writeCanonical(*out, frozen)
}

func runCharterAmend(args []string) error {
	flags := newFlagSet("witness charter amend")
	charterPath := flags.String("charter", "", "charter JSON path")
	amendmentsPath := flags.String("amendments", "", "amendments JSONL path")
	eventPath := flags.String("event", "", "owner event JSON path")
	out := flags.String("out", "", "frozen charter output path")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if *eventPath == "" {
		return diag.New(diag.CodeInvalidCommand, "witness charter amend requires -event.")
	}
	if *amendmentsPath == "" {
		return diag.New(diag.CodeInvalidCommand, "witness charter amend requires -amendments.")
	}
	if err := rejectOutputPathAliases(*out, protectedInput{role: "charter", path: *charterPath}, protectedInput{role: "amendments", path: *amendmentsPath}); err != nil {
		return err
	}
	input, amendments, err := loadCharterInputs(*charterPath, *amendmentsPath)
	if err != nil {
		return err
	}
	event, err := charter.ReadOwnerEventFile(*eventPath)
	if err != nil {
		return err
	}
	frozen, err := charter.Freeze(input, append(append([]charter.OwnerEvent(nil), amendments...), event))
	if err != nil {
		return err
	}
	if err := charter.AppendAmendment(*amendmentsPath, event); err != nil {
		return err
	}
	return writeCanonical(*out, frozen)
}

func runCharterShow(args []string) error {
	flags := newFlagSet("witness charter show")
	charterPath := flags.String("charter", "", "charter JSON path")
	amendmentsPath := flags.String("amendments", "", "amendments JSONL path")
	out := flags.String("out", "", "normalized charter output path")
	if err := flags.Parse(args); err != nil {
		return invalidFlagError(err)
	}
	if flags.NArg() != 0 {
		return unexpectedArgs(flags.Args())
	}
	if err := rejectOutputPathAliases(*out, protectedInput{role: "charter", path: *charterPath}, protectedInput{role: "amendments", path: *amendmentsPath}); err != nil {
		return err
	}
	input, amendments, err := loadCharterInputs(*charterPath, *amendmentsPath)
	if err != nil {
		return err
	}
	normalized, err := charter.Normalize(input, amendments)
	if err != nil {
		return err
	}
	return writeCanonical(*out, normalized)
}

func loadCharterInputs(charterPath string, amendmentsPath string) (charter.Charter, []charter.OwnerEvent, error) {
	if charterPath == "" {
		return charter.Charter{}, nil, diag.New(diag.CodeInvalidCommand, "charter commands require -charter.")
	}
	input, err := charter.ReadFile(charterPath)
	if err != nil {
		return charter.Charter{}, nil, err
	}
	var amendments []charter.OwnerEvent
	if amendmentsPath != "" {
		amendments, err = charter.ReadAmendmentsFile(amendmentsPath)
		if err != nil {
			return charter.Charter{}, nil, err
		}
	}
	return input, amendments, nil
}

func writeCanonical(path string, value any) error {
	if path == "" {
		return diag.WriteCanonical(os.Stdout, value)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "write output"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	defer file.Close()
	return diag.WriteCanonical(file, value)
}

type protectedInput struct {
	role string
	path string
}

func rejectOutputPathAliases(outputPath string, protectedInputs ...protectedInput) error {
	if outputPath == "" {
		return nil
	}
	resolvedOutput, err := comparablePath(outputPath)
	if err != nil {
		return err
	}
	for _, input := range protectedInputs {
		if input.path == "" {
			continue
		}
		resolvedInput, err := comparablePath(input.path)
		if err != nil {
			return err
		}
		if resolvedOutput.conflictsWith(resolvedInput) {
			return diag.New(
				charter.CodeOutputPathConflict,
				"output path must not overwrite required charter inputs.",
				diag.WithDetail("input_path", input.path),
				diag.WithDetail("input_role", input.role),
				diag.WithDetail("output_path", outputPath),
				diag.WithDetail("resolved_path", resolvedOutput.canonical),
			)
		}
	}
	return nil
}

type comparablePathInfo struct {
	canonical string
	paths     []string
	info      os.FileInfo
}

func (left comparablePathInfo) conflictsWith(right comparablePathInfo) bool {
	if left.info != nil && right.info != nil && os.SameFile(left.info, right.info) {
		return true
	}
	for _, leftPath := range left.paths {
		for _, rightPath := range right.paths {
			if leftPath == rightPath {
				return true
			}
		}
	}
	return false
}

func comparablePath(path string) (comparablePathInfo, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return comparablePathInfo{}, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	info, err := os.Stat(absolute)
	if err != nil && !os.IsNotExist(err) {
		return comparablePathInfo{}, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	canonical, err := comparablePathString(absolute)
	if err != nil {
		return comparablePathInfo{}, err
	}
	comparable := comparablePathInfo{
		canonical: canonical,
		paths:     []string{canonical},
		info:      info,
	}
	if info == nil {
		target, ok, err := finalSymlinkTarget(absolute)
		if err != nil {
			return comparablePathInfo{}, err
		}
		if ok {
			comparable.paths = append(comparable.paths, target)
			resolvedTarget, err := comparablePathString(target)
			if err != nil {
				return comparablePathInfo{}, err
			}
			comparable.paths = append(comparable.paths, resolvedTarget)
		}
	}
	return comparable, nil
}

func comparablePathString(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if os.IsNotExist(err) {
		resolvedParent, parentErr := filepath.EvalSymlinks(filepath.Dir(absolute))
		if parentErr == nil {
			return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
		}
		if !os.IsNotExist(parentErr) {
			return "", diag.Wrap(
				parentErr,
				charter.CodeFileIO,
				"file operation failed.",
				diag.WithDetail("action", "resolve path"),
				diag.WithDetail("path", path),
				diag.WithDetail("error", parentErr.Error()),
			)
		}
		return absolute, nil
	}
	return "", diag.Wrap(
		err,
		charter.CodeFileIO,
		"file operation failed.",
		diag.WithDetail("action", "resolve path"),
		diag.WithDetail("path", path),
		diag.WithDetail("error", err.Error()),
	)
}

func finalSymlinkTarget(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", false, diag.Wrap(
			err,
			charter.CodeFileIO,
			"file operation failed.",
			diag.WithDetail("action", "resolve path"),
			diag.WithDetail("path", path),
			diag.WithDetail("error", err.Error()),
		)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target), true, nil
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func invalidFlagError(err error) error {
	return diag.Wrap(err, diag.CodeInvalidCommand, "invalid command flags.", diag.WithDetail("error", err.Error()))
}

func unexpectedArgs(args []string) error {
	return diag.New(
		diag.CodeInvalidCommand,
		"unexpected positional arguments.",
		diag.WithDetail("args", args),
	)
}

func diagnosticsFromError(err error) []diag.Diagnostic {
	var validation *charter.ValidationError
	if errors.As(err, &validation) {
		return validation.Diagnostics
	}
	var contractValidation *contracts.ValidationError
	if errors.As(err, &contractValidation) {
		return contractValidation.Diagnostics
	}
	var planningValidation *planning.ValidationError
	if errors.As(err, &planningValidation) {
		return planningValidation.Diagnostics
	}
	var preflightError *preflight.Error
	if errors.As(err, &preflightError) {
		return preflightError.Diagnostics
	}
	return nil
}
