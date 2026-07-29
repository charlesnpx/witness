package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"witness/internal/charter"
	"witness/internal/diag"
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
			return notImplemented(strings.Join(args[:2], " "))
		}
	}
	return diag.New(
		diag.CodeInvalidCommand,
		"unknown witness command.",
		diag.WithDetail("args", args),
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
	return nil
}
