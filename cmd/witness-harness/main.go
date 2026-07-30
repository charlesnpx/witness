package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"witness/internal/diag"
	"witness/internal/harness"
)

func main() {
	if err := route(os.Args[1:]); err != nil {
		var harnessErr *harness.Error
		if errors.As(err, &harnessErr) {
			_ = diag.WriteCanonical(os.Stderr, map[string]any{
				"ok":          false,
				"diagnostics": harnessErr.Diagnostics,
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
		return diag.New(diag.CodeInvalidCommand, "missing witness-harness command.")
	}
	if args[0] != "run" {
		return diag.New(
			diag.CodeInvalidCommand,
			"unknown witness-harness command.",
			diag.WithDetail("args", args),
		)
	}
	return runHarness(args[1:])
}

func runHarness(args []string) error {
	flags := newFlagSet("witness-harness run")
	requestPath := flags.String("request", "", "strict JSON harness request path")
	outputDir := flags.String("out-dir", "", "receipt output directory")
	if err := flags.Parse(args); err != nil {
		return diag.Wrap(err, diag.CodeInvalidCommand, "invalid witness-harness run flags.", diag.WithDetail("error", err.Error()))
	}
	if flags.NArg() != 0 {
		return diag.New(diag.CodeInvalidCommand, "unexpected witness-harness run arguments.", diag.WithDetail("args", flags.Args()))
	}
	result, err := harness.RunFile(context.Background(), *requestPath, *outputDir)
	if err != nil {
		return err
	}
	return diag.WriteCanonical(os.Stdout, result)
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}
