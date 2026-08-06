# Operator walkthrough

This is the complete operator path for a single Witness pass. Run it from a
new directory *outside* the repository being reviewed: the pass state must not
live inside the reviewed source tree. The reviewed source must be a real Git
checkout, and `BUNDLE` must name a valid relay integration bundle.

## 1. Create a run directory and Charter

Start in an empty directory and set the absolute paths for this run. Replace
the two placeholder paths before continuing.

```sh
mkdir witness-run
cd witness-run
RUN="$PWD"
STATE="$RUN/state"
REPO="/absolute/path/to/the/reviewed-git-repository"
BUNDLE="/absolute/path/to/relay-integration-bundle-v2.json"
RELAY="convo-relay"
mkdir -p "$STATE"
```

Create a minimal, owner-authored Charter:

```sh
witness charter init \
  -template minimal \
  -out "$RUN/charter.json"
```

Edit `$RUN/charter.json` in a JSON editor before freezing it. In particular,
replace the empty `goals` array with at least one owner-authorized goal. For
example:

```json
{
  "goals": [
    {
      "id": "preserve-reviewed-behavior",
      "statement": "Preserve the behavior intended for this reviewed change."
    }
  ],
  "non_goals": [],
  "owner_events": [
    {
      "id": "initial-charter",
      "type": "charter_initialized",
      "actor": "owner",
      "summary": "Initial owner-authorized charter skeleton."
    }
  ],
  "schema_version": "review-charter-v2"
}
```

Freeze the owner-visible Charter. The pass will make and retain its own freeze
too; this one is useful for the operator's pre-pass record.

```sh
witness charter freeze \
  -charter "$RUN/charter.json" \
  -out "$RUN/charter.owner.freeze.json"
```

These two owner input artifacts intentionally live beside, rather than inside,
the state directory: `$RUN/charter.json` and
`$RUN/charter.owner.freeze.json`. `pass begin` rejects a configured Charter
inside its driver-generated state directory.

## 2. Begin the pass and read its next action

Start a whole-tree baseline pass. This command uses `-allow-dirty-source` so
the walkthrough also works when the reviewed checkout has deliberate local
changes. Omit that flag for a clean-only workflow; without it Witness refuses
a dirty source snapshot.

```sh
witness pass begin \
  -state-dir "$STATE" \
  -charter "$RUN/charter.json" \
  -source-dir "$REPO" \
  -integration-bundle "$BUNDLE" \
  -relay "$RELAY" \
  -ledger "$RUN/ledger.jsonl" \
  -baseline-pass \
  -allow-dirty-source
```

The first invocation freezes source and returns JSON with
`stage_run: "freeze"` and a `next_action` command. It writes these
state-directory-relative artifacts:

- `pass-state.json`
- `charter.freeze.json`
- `source-snapshot/manifest.json`
- `source-snapshot/blobs/sha256/<content-digest>` for each captured file

Run the next action verbatim:

```sh
witness pass resume -state-dir "$STATE"
```

The preflight invocation returns `next_action.type: "caller_role_outputs"`.
Record these values from that JSON before preparing finder output:

- `next_action.charter_hash`
- `next_action.snapshot_digest`
- each `next_action.roles[].path`

It also writes `preflight.json` and retains the preflight evidence described
in the [artifact inventory](#artifact-inventory).

## 3. Initialize, complete, and validate finder output

The default pass requests the `defect` and `economy` finder roles. Create their
files at the exact paths requested by `next_action`:

```sh
mkdir -p "$STATE/role-outputs"

witness role-output init \
  -role defect \
  -out "$STATE/role-outputs/defect-output.json"

witness role-output init \
  -role economy \
  -out "$STATE/role-outputs/economy-output.json"
```

An initialized document is structurally valid but is only a template. For
example, validating either freshly initialized file succeeds while warning
about its placeholder identities:

```sh
witness role-output validate \
  -input "$STATE/role-outputs/defect-output.json"

witness role-output validate \
  -input "$STATE/role-outputs/economy-output.json"
```

The result has `"ok":true`, `"placeholders_present":true`, and this warning:

```text
document still carries role-output init placeholder identities; replace them before filing it in a pass.
```

Replace the placeholder `charter_hash`, `artifact_digest`, and both identities
in each file. In a real pass, these documents are produced by finder agents the
operator runs outside Witness (using any agent harness), one per role, each
examining the frozen source snapshot against the Charter goals. The manual
editing below is solely a stand-in used to demonstrate the required document
shape and the zero-findings flow. A hand-authored zero-findings document is the
vacuous case: Witness will record and adjudicate it, but its verdict carries no
evidentiary weight about the source; see [Zero findings does not prove absence
of defects](#zero-findings-does-not-prove-absence-of-defects). For a
zero-findings run, the complete defect document has this shape; use the
`charter_hash` and `snapshot_digest` reported by the pass rather than values
from another run:

```json
{
  "schema_version": "review-role-output-v3",
  "role": "defect",
  "charter_hash": "<next_action.charter_hash>",
  "artifact_digest": "<next_action.snapshot_digest>",
  "source_identity": {
    "kind": "witness-source-snapshot",
    "id": "<next_action.snapshot_digest>",
    "git_head": "<source.git_head from source-snapshot/manifest.json>"
  },
  "consumer_identity": {
    "kind": "finder",
    "id": "<identifier for this finder run>"
  },
  "findings": []
}
```

Use the same binding values and real identities for the economy document, with
`"role": "economy"`. The empty array is intentional: `findings` must be `[]`
for a zero-findings defect or economy role output. Do not leave the initializer's
`{"kind":"placeholder","id":"replace-before-use"}` identities in either
document. Angle-bracket values in the example are instructions to insert values
from this pass, not literal placeholder identities.

Validate the completed documents again:

```sh
witness role-output validate \
  -input "$STATE/role-outputs/defect-output.json"

witness role-output validate \
  -input "$STATE/role-outputs/economy-output.json"
```

Each result is an `ok: true` document with `schema_version` and a
`role_output_digest`; it has neither `placeholders_present` nor `warning`.
The two completed files are `role-outputs/defect-output.json` and
`role-outputs/economy-output.json` relative to `$STATE`.

## 4. Finish planning, assembly, adjudication, and metrics

Resume one stage at a time, checking `stage_run` after each command:

```sh
witness pass resume -state-dir "$STATE"
```

This runs the `plan` stage and writes `verification-plan.json`.

```sh
witness pass resume -state-dir "$STATE"
```

This runs the `assemble` stage and writes `verification/index.skeleton.json`
and `verification/index.json`. If assembly has supplementary unverified
relationships, it also writes `verification/assemble-result.json`.

```sh
witness pass resume -state-dir "$STATE"
```

This runs the `adjudicate` stage, writes `verdict.json`, and appends the
adjudication lineage to `$RUN/ledger.jsonl`.

```sh
witness pass resume -state-dir "$STATE"
```

This runs the `metrics` stage, writes `metrics.json`, and returns the terminal
next action:

```json
{
  "complete": true,
  "next_action": {
    "type": "complete",
    "summary": "pass complete"
  },
  "stage_run": "metrics"
}
```

Inspect the append-only ledger without creating another artifact:

```sh
witness ledger show -ledger "$RUN/ledger.jsonl"
```

For the zero-findings role-output example, the terminal `verdict.json` has a
zero-count summary, including `admitted: 0`, `advisory: 0`,
`pending_verification: 0`, and `fixpoint_eligible: true`. In the current CLI,
the terminal adjudication result serializes its zero-length `findings` field as
`null`; this is distinct from the required `findings: []` in each role-output
document:

```json
{
  "schema_version": "witness-adjudication-run-result-v2",
  "findings": null,
  "summary": {
    "admitted": 0,
    "advisory": 0,
    "pending_verification": 0,
    "fixpoint_eligible": true
  }
}
```

The ledger still receives an `adjudication_run` record whose `finding_count` is
`0`.

## Zero findings does not prove absence of defects

A zero-findings result is only as meaningful as the Charter goals and finder
effort behind it. Witness records that the submitted finder documents ran
against the frozen source snapshot and bound their claims to the frozen Charter;
it does not prove that the repository has no defects.
The identities in a role-output document assert the frozen source and who
produced the findings; inventing either defeats the provenance record Witness
keeps.

An empty Charter is rejected by the pass-driven path with
`charter_zero_goals`, because a zero-goal review is vacuous by construction.
`witness pass begin -allow-empty-charter` explicitly overrides that guard, but
does not make a resulting zero-findings pass meaningful. Likewise,
`-allow-dirty-source` records `source_dirty: true` and the dirty status in the
pass output and preflight result, so the result honestly identifies a review of
a dirty snapshot.

## Artifact inventory

The owner input files are `$RUN/charter.json` and
`$RUN/charter.owner.freeze.json`; the append-only ledger is
`$RUN/ledger.jsonl`. These configured inputs must remain outside `$STATE`.
All remaining paths below are relative to `$STATE`. The `retained_artifacts`
object in every pass result is the authoritative core inventory; do not infer
locations from a custom state-directory layout. A successful relay-absent
smoke run, for example, reports:

```json
{
  "charter_freeze": "charter.freeze.json",
  "compatibility_manifest": "compatibility-manifest.json",
  "integration_bundle": "integration-bundle.json",
  "pass_state": "pass-state.json",
  "preflight": "preflight.json",
  "relay_capabilities": "relay-capabilities.json",
  "source_manifest": "source-snapshot/manifest.json",
  "workspace_manifest": "source-snapshot/manifest.json"
}
```

The complete run layout is:

| Writer | State-directory-relative artifact |
| --- | --- |
| Pass freeze | `pass-state.json`, `charter.freeze.json`, `source-snapshot/manifest.json`, `source-snapshot/blobs/sha256/<content-digest>` |
| Preflight | `preflight.json`, `relay-capabilities.json`, `backend-status.json`, `recipes-list.json`, `integration-bundle.json`, `contract-digests.json`, `compatibility-manifest.json` |
| Preflight compilation | `compile-reports/witness-falsify-v2.json`, `compile-reports/witness-falsify-v2-codex.json`, `compile-reports/witness-falsify-v2-claude.json`, `compile-reports/economy-equivalence-v2.json`, `compile-reports/economy-equivalence-v2-codex.json`, `compile-reports/economy-equivalence-v2-claude.json`; a relay that emits plans also retains `recipe-plans/<recipe-id>.json` |
| Finders | `role-outputs/defect-output.json`, `role-outputs/economy-output.json` |
| Plan and assembly | `verification-plan.json`, `verification/index.skeleton.json`, `verification/index.json`, and, when applicable, `verification/assemble-result.json` |
| Adjudication and metrics | `verdict.json`, `metrics.json` (the ledger is `$RUN/ledger.jsonl`) |

## Intentional boundaries

`witness verification preflight` runs without Charter context. The
`charter_zero_goals` guard is enforced on the pass-driven path,
`witness pass begin`. Operators who invoke preflight directly are responsible
for supplying a frozen Charter with goals through the pass flow. This is an
intentional scoping boundary, not an oversight.

Dirty-source capture with `-allow-dirty-source` refuses sparse checkouts with
`freeze_source_sparse_checkout`: tracked files absent from the working tree
cannot be represented in a dirty snapshot. Use a full checkout before starting
the pass.
