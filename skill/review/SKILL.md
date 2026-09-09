---
name: review
description: Run a Witness review from a source directory and Charter using the recipe selected by review configuration.
---

# Witness review

Use `witness review run` for the ordinary recipe-bound workflow. Give it a
Charter (or frozen Charter), the reviewed source directory, and an output
directory outside that source tree:

```sh
witness review run \
  -charter /path/to/charter.json \
  -source-dir /path/to/repository \
  -out-dir /path/to/review-run
```

The command prepares the frozen request, reviewer prompts, output schemas, and
completion record. It submits independent defect and economy jobs through
Delegate and observes them through Agentbus. The absent configuration file is
valid: it selects the bundled `simple` adapter, `defect-and-economy` recipe,
recipe and default evidence policy without creating `$XDG_CONFIG_HOME/review/config.json` (or
`~/.config/review/config.json` when XDG_CONFIG_HOME is unset or empty).

Treat the completion verdict as an observation of this process. Execution
evidence is constructed by the host from observed job outcomes; a report that
claims it ran is not execution evidence. A missing, unreadable, digest-mismatched,
or contract-invalid result cannot make a run `satisfied`, while a valid empty
report can. A persisted completion file is an audit record, not re-validatable
proof; do not load it back and use its JSON as evidence that execution occurred.

Agentbus selected-job exit codes are job outcomes: 0 completed, 2 queued or
running, 3 completed-noncompliant, 4 failed, 5 timeout, 6 interrupted,
7 canceled, 14 unknown, and 15 result-artifact-unavailable. Codes 10, 11, and
13 are CLI or daemon failures. Transcript capture is a separate claim: follow
forward from ordinal zero with `--since-ordinal` and `--limit`, advancing to
the highest ordinal seen, and drain after termination. `--last` is a tail view,
not a cursor. A running `gap: true` does not prove loss; a terminal gap blocks
only when the selected policy requires transcript evidence.

The bundled adapter is read-only with respect to the reviewed source and owns
no job database or daemon. A custom adapter is named in configuration and
supplies its own skill or executable; invoke that implementation according to
its instructions rather than expecting the bundled Go runner to implement it.
It is not added as a Go adapter type.
