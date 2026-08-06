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

A bare `RELAY` value (one without a path separator) is resolved through
`PATH`; Witness uses the resulting absolute executable path for the pass and
relay launch evidence. Supply a value containing a path separator when you
intend to use that path as written. If a bare name is not on `PATH`, preflight
records `relay_missing` and continues with the documented unavailable-relay
degradation.

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

`non_goals` is an array of structured statements, not an array of strings. Its
one-line shape is:

```json
{"non_goals":[{"id":"deferred-work","statement":"This pass does not add a deployment workflow."}]}
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

Confirm that `next_action.charter_hash` equals the `charter_hash` in
`$RUN/charter.owner.freeze.json`. The pass freezes whatever Charter file it was
given, so a mismatch means `charter.json` changed between the owner freeze and
`pass begin`; stop and re-freeze before continuing.

It also writes `preflight.json` and retains the preflight evidence described
in the [artifact inventory](#artifact-inventory).

## 3. Initialize, complete, and validate finder output

The default pass requests the `defect` and `economy` finder roles. Create their
files at the exact paths requested by `next_action`:

```sh
witness role-output init \
  -role defect \
  -out "$STATE/role-outputs/defect-output.json"

witness role-output init \
  -role economy \
  -out "$STATE/role-outputs/economy-output.json"
```

`role-output init` creates the parent directory of `-out`; no separate
directory-creation step is required.

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
examining the frozen source snapshot against the Charter goals. Point finders
at the snapshot retained under the state directory's `source-snapshot/` — the
manifest lists every captured file with its content digest and the blobs hold
the exact captured bytes — rather than at the live checkout, which can change
after the freeze. The manual
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

### Filing a non-empty finding

Finder output is strict JSON: every key below is a literal contract field name,
and unknown keys are rejected. The following is a structurally valid worked
defect example. It assumes that the real Charter declares the
`preserve-reviewed-behavior` goal and a bounded `entry_points` entry named
`cli`; replace the illustrative digests and identities with values from the
current pass before filing it.

```json
{
  "schema_version": "review-role-output-v3",
  "role": "defect",
  "charter_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "artifact_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "source_identity": {
    "kind": "witness-source-snapshot",
    "id": "snapshot-example"
  },
  "consumer_identity": {
    "kind": "finder",
    "id": "defect-finder-example"
  },
  "findings": [
    {
      "id": "illustrative-declared-input-rejection",
      "kind": "defect",
      "title": "Illustrative reachable input is rejected",
      "charter_goal_ids": ["preserve-reviewed-behavior"],
      "claimed_severity": "medium",
      "scope_anchors": [
        {
          "dimension": "entry_points",
          "entry_id": "cli"
        }
      ],
      "witness": {
        "kind": "defect",
        "strength": "argued",
        "content": "In this illustrative frozen artifact, the reachable CLI branch rejects a declared input.",
        "artifact_refs": [
          {
            "kind": "source-file",
            "id": "cmd-witness-main-go",
            "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "digest_profile": "relay-root-digests-v1",
            "media_type": "text/x-go"
          }
        ],
        "entry_point": {
          "dimension": "entry_points",
          "entry_id": "cli"
        },
        "reachability_chain": [
          {
            "dimension": "entry_points",
            "entry_id": "cli"
          }
        ]
      },
      "estimated_delta": {
        "production": {
          "status": "known",
          "lines": 1,
          "files": 1
        },
        "test": {
          "status": "known",
          "lines": 1,
          "files": 1
        }
      },
      "smallest_sufficient_remedy": {
        "direction": "change",
        "summary": "Change the rejecting branch for the declared input.",
        "minimality_argument": "Only the reachable rejection branch and its direct regression test need to change.",
        "touched_production": ["cmd/witness/main.go"],
        "touched_tests": ["cmd/witness/main_test.go"]
      },
      "proposed_tests": [
        {
          "id": "illustrative-declared-input-regression",
          "name": "accepts the declared CLI input",
          "reachable_partition": "declared CLI input",
          "charter_refs": [
            {
              "goal_id": "preserve-reviewed-behavior"
            },
            {
              "anchor": {
                "dimension": "entry_points",
                "entry_id": "cli"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

The root fields are `schema_version`, `role`, `charter_hash`,
`artifact_digest`, `source_identity`, `consumer_identity`, `findings`, and the
optional `missing_goal_questions`. `source_identity` and `consumer_identity`
must each be non-empty JSON objects; their internal identity fields are owned by
the producer. Defect and economy role outputs require `findings` to be an
array, including `[]` when there are no findings.

Each `findings` entry has `id`, `kind`, `title`, `charter_goal_ids`,
`claimed_severity`, `scope_anchors`, `witness`, `estimated_delta`,
`smallest_sufficient_remedy`, and optional `proposed_tests` and `recurrence`.
The `witness` fields are `kind`, `strength`, `content`, optional
`artifact_refs`, optional `executable`, optional `entry_point`, and optional
`reachability_chain`. An `artifact_refs` item, and an optional executable
`transformation_ref`, use `kind`, `id`, `digest`, optional `digest_profile`,
and optional `media_type`. When `strength` is `executable`, `executable` is
required and has `argv`, `cwd`, `expected_observation`, and optional
`transformation_ref`.

`estimated_delta` always has `production` and `test`; each has `status` and,
when known, `lines` and `files`. `smallest_sufficient_remedy` has `direction`,
`summary`, `minimality_argument`, optional `touched_production`, and optional
`touched_tests`. Every `proposed_tests` item has `id`, `name`,
`reachable_partition`, and `charter_refs`; each `charter_refs` item has an
optional `goal_id` and optional `anchor`, but must provide at least one of them.
If present, `recurrence` has `prior_finding_id`, `finding_key`,
`witness_digest`, and `artifact_digest`. If an unspecified envelope dimension
requires a question, each `missing_goal_questions` item has `id`, `finding_id`,
`dimension`, `anchor_index`, `property`, `value`, `affected_decision`, and
`statement`.

Use these enum values exactly:

- `role`: `defect`, `economy`, `goal_fit`
- finding `kind`: `defect`, `economy`; witness `kind`: `defect`, `equivalence`
- witness `strength`: `argued`, `constructed`, `executable`
- `claimed_severity`: `critical`, `high`, `medium`, `low`
- delta `status`: `known`, `unknown`
- remedy `direction`: `add`, `change`, `remove`

For a `known` delta, provide the measured `lines` and `files`; an `unknown`
delta must not provide either count. Economy findings use `kind: "economy"`,
an `equivalence` witness, and a size-reducing `remove` or `change` remedy.

Scope anchors are only meaningful against the Charter's
`operational_envelope`: every `dimension` must be declared there. For example,
the finding's `{"dimension":"entry_points","entry_id":"cli"}` anchor
requires a matching bounded Charter entry such as this fragment:

```json
"entry_points": {"state":"bounded","statement":"Supported entry points.","entries":[{"id":"cli","statement":"Witness CLI."}]}
```

A bounded dimension uses a declared `entry_id`; an unbounded dimension uses a
concrete `value`; an unspecified dimension also needs `property`, `value`, and
`affected_decision` plus its Charter-derived `missing_goal_questions` entry.
`excluded: true` marks an anchor as excluded. Constructed and executable defect
witnesses additionally need a reachable `entry_point` and a
`reachability_chain` that the operational envelope can resolve.

Save a real non-empty role output and validate it before filing it:

```sh
witness role-output validate \
  -input "$STATE/role-outputs/defect-output.json"
```

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

### Verifying a finding-bearing batch with relay

If planning returns `next_action.type: "caller_relay_batch"`, the pass has
planned a verification batch for a relay run to execute. The pass never
launches relay itself. Set `BATCH_PATH` to
`next_action.relay_batch.batch_path` and `BACKEND` to
`next_action.relay_batch.backend`, then launch the retained batch:

```sh
BATCH_PATH="<next_action.relay_batch.batch_path>"
BACKEND="<next_action.relay_batch.backend>"

witness verification assemble \
  -run-relay \
  -state-dir "$STATE" \
  -relay "$RELAY" \
  -backend "$BACKEND" \
  -charter-freeze "$STATE/charter.freeze.json" \
  -plan "$STATE/verification-plan.json" \
  -batch "$BATCH_PATH" \
  -artifact "$STATE/source-snapshot/manifest.json" \
  -integration-bundle "$STATE/integration-bundle.body.json" \
  -out "$STATE/verification/index.json"
```

The explicit inputs are the frozen Charter, plan, requested batch, and frozen
source manifest. A normal batch path is
`$STATE/verification/batches/<batch-id>.json`. The retained authored bundle at
`$STATE/integration-bundle.body.json` is the directly bindable
`-integration-bundle` input; `$STATE/integration-bundle.json` remains the
authenticated retention envelope. `-state-dir` also supplies the retained
compatibility, capability, and selected-contract evidence for assembly.

Every attempted launch retains a v2 run record at
`$STATE/verification/runs/<batch-id>.json`. Its launch evidence includes the
argv, exit code, bounded `stdout_b64` and `stderr_b64` bytes with their digests,
and the record also states `provider_invoked` and `consumes_batch`.
`status: "launch_failed"` means the relay process did not start:
`provider_invoked` is `false`, the record is non-consuming, and the pass keeps
returning `caller_relay_batch`; fix the launch and rerun it. A consuming
unavailable record is terminal for that batch instead. Return to the pass using
only `witness pass resume -state-dir "$STATE"` for each remaining stage: it
consumes that recorded run in its own assembly, adjudication, and metrics.
Findings assigned to the unavailable batch end as `pending_verification`, and
the metrics-stage response reports `complete: true`.

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
