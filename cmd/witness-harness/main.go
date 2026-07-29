package main

import (
	"os"

	"witness/internal/diag"
)

func main() {
	if err := route(os.Args[1:]); err != nil {
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
	return diag.New(
		diag.CodeNotImplemented,
		"witness-harness command routing is present; implementation is assigned to a later unit.",
		diag.WithDetail("command", "run"),
	)
}
