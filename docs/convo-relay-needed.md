> **Historical.** This document is historical: the relay requirements it
> tracked are satisfied by `convo-relay` v1.4.0 and superseded by the corrected
> Witness spec's final contract. Do not implement from it.

# Convo-relay work still needed for witnessed review

> **Historical planning context.** This assessment was pinned to an executing
> pre-release plan. The active, release-pinned implementation plan is
> [`convo-relay-needed-v2.md`](convo-relay-needed-v2.md), based on
> `convo-relay` v1.1.0 at
> `72d3bf45874a5bd74e01d393bd0c0873e8f67da2`. Do not execute this file as the
> current plan.

This is the delta between the currently executing
`convo-relay-root-recipe-integration` plan and the generic relay capabilities
that Witnessed Adversarial Review needs. It is not a replacement plan and it
does not repeat work already accepted by that plan.

Assessment basis, captured 2026-07-21:

- plan id: `convo-relay-root-recipe-integration`;
- plan lock SHA-256:
  `b8957132643e7051ba49f6fd7ce2fced3912bf3a412d76f24ecf06d2e7dbfd3a`;
- 16 planned stories; and
- this document assumes every story completes exactly as written, including
  its tests and compatibility gates.

If the plan changes, this delta must be compared with the new lock before it
is treated as complete.

## Already covered by the active plan

The following are not additional work:

- strict JSON ingestion and typed diagnostics;
- versioned root artifacts and runtime snapshots;
- integration-bundle loading, selected-contract binding, inline JSON Schema,
  and generic assertions;
- backend installation and authentication readiness reporting;
- explicit `CompileTargetRoot` and `CompileTargetChild` behavior;
- integration-aware catalog and compile reporting;
- repeatable, binary-safe, digest-checked named inputs;
- Git source inventory, detached-worktree execution, source-integrity checks,
  retention, and cleanup;
- direct `run --recipe` dispatch and pure preflight;
- exact alternating participant turns and separate participant/facilitator
  contexts;
- a fresh reducer, raw result retention, schema/assertion validation, and a
  canonical result ref;
- recovery checkpoints and lifecycle guards;
- root-session inspection, output, health, and administrative integration;
  and
- the six structural witnessed-review recipe records and the generic
  acceptance suite.

The items below are required in addition to that baseline unless marked
conditional.

## CRN-00: Successor contract versions

The active plan intentionally defines strict v1 payloads and rejects unknown
fields. The additions in this document must not mutate those v1 schemas after
they land.

Before implementation, publish a version-transition matrix. At minimum it
must provide successor versions for:

- normalized recipes and root plans carrying `provider_retry`;
- integration bundles and selected contracts carrying `prompt_context`;
- root artifact envelopes carrying digest-profile and invocation refs;
- workspace records carrying isolation dimensions; and
- the machine-readable root-session result if its strict field set changes.

Provider-invocation and portable-export formats may begin at v1 because they
are new kinds. Existing recipe, root-plan, bundle, runtime, session, and
artifact v1 payloads remain readable and keep their original digest meaning.
New writers emit the successor versions whenever a post-plan field or digest
profile is used. Conversion is explicit; a reader never guesses a version
from field presence.

Acceptance requires old-reader/new-reader fixtures, explicit rejection of new
fields under v1 identifiers, deterministic migration where supported, and
capability output that advertises the exact version matrix.

## CRN-01: Named-input-aware `context_only`

The current prompt-policy API treats positional `--context` as the only
launch context. The active plan rejects positional context when a selected
contract declares named inputs. Consequently, the witnessed-review command
shape cannot currently combine its required named inputs with
`--investigation context_only`.

Required behavior:

- prompt-policy construction accepts an authoritative input-source set, not
  only a boolean indicating positional context;
- one or more successfully bound named inputs satisfy `context_only` for an
  integration-bound root run;
- prompts cite stable named-input labels and refs instead of requiring `ctxN`;
- positional context remains rejected when the contract declares named
  inputs;
- a run with neither positional nor named authoritative inputs still fails;
  and
- metadata records which input authority satisfied the policy.

`context_only` remains prompt guidance. It must not be described as an OS
sandbox or an execution receipt.

Acceptance requires CLI and prompt tests for named-only success, no-input
failure, mixed-input rejection, stable labels, and restored metadata.

## CRN-02: Disable runner-level provider retries

The existing provider lifecycle automatically retries classified transient
failures. Witnessed review is a single-pass protocol and says that the caller,
not the skill or relay, decides whether failed model work is retried.

Add a generic, compiled lifecycle field:

```toml
provider_retry = "allow" | "forbid"
```

It is written through the successor recipe and root-plan contracts from
CRN-00; the existing v1 payloads are not extended in place.

Required behavior:

- omission defaults to `allow` for ordinary-recipe compatibility;
- all six witnessed-review records set `forbid`;
- `forbid` permits one runner launch attempt for each declared participant,
  facilitator, or reducer invocation;
- a retryable provider error becomes that invocation's terminal failure with
  no backoff or replacement call;
- participant-turn counts still count completed protocol turns, while
  invocation records expose attempted launches separately;
- the field and its effective value participate in recipe and root-plan
  digests; and
- attempt count, failure classification, and terminal provider result are
  persisted and exported.

Provider-internal retries that are invisible to the runner are outside this
control and must not be represented as independently observed attempts.

Acceptance requires fake-provider tests proving one launch on every transient
failure path, including participant, facilitator, and reducer phases, plus
regression tests for the ordinary `allow` policy.

## CRN-03: Deterministic prompt-context projection

The active plan includes the ordinary facilitator ledger in later prompts
when available. For witnessed review, facilitator prose is neither a filed
witness nor an allowed defense premise. Merely asking later models to ignore
it leaves an avoidable protocol contamination path.

Extend selected integration contracts through the successor bundle and
selected-contract versions from CRN-00 with a generic normalized declaration:

```json
{
  "prompt_context": {
    "participant_transcript": "complete",
    "facilitator_ledger": "include"
  }
}
```

Initial prompt-context requirements:

- omission defaults to `complete` and `include` for compatibility;
- `participant_transcript` accepts only `complete`;
- `facilitator_ledger` accepts `include` or `trace_only`;
- `trace_only` persists facilitator output but excludes it from all later
  participant and reducer prompts;
- the declaration and defaults are schema-validated, normalized, digested,
  compiled, persisted, and exported; and
- the witnessed-review bundle sets `trace_only` for both of its contracts.

Acceptance requires fake-provider prompt capture proving lossless participant
history, no future-turn instruction leakage, and complete absence of a
trace-only ledger from participant and reducer prompts.

## CRN-04: Per-invocation provenance

The plan persists provider results but does not require a portable record of
the exact rendered prompt and attempt that produced each result. The consumer
needs to audit that the compiled actor instruction and context projection were
actually dispatched.

Add a versioned generic invocation artifact for every participant,
facilitator, and reducer call. It must bind:

- phase, actor, slot, and participant ordinal when applicable;
- exact rendered-prompt ref and byte digest;
- recipe, root-plan, and selected-contract refs;
- named-input manifest ref;
- resolved backend, requested model and effort, and provider session identity
  when available;
- workspace identity and mapped working directory without making an absolute
  path part of portable identity;
- runner attempt number and retry policy;
- start and completion timestamps; and
- terminal provider outcome and result ref.

These records prove what the relay runner dispatched and observed. They do
not prove that a model truthfully reported a tool action.

Acceptance requires a one-to-one check between declared calls and invocation
records, prompt tamper detection, fresh-reducer lineage, and preservation on
timeout, stall, cancellation, provider failure, and invalid structured output.

## CRN-05: Public, kind-aware digest profiles

The active plan requires digest-checked artifacts but does not define a
public compatibility contract from which an independent consumer can
recompute every digest. This cannot be left as an implementation detail.

There is also a dangerous distinction in the existing code: the legacy
storage-oriented contract digest recursively omits keys with names such as
`path`, `created_at`, and `storage_id`. Integration-bundle code already avoids
that behavior for opaque semantic maps, but canonical result and export
consumers need an explicit kind-safe rule as well.

Required behavior:

- define and publish a versioned digest profile used by root artifacts and
  portable exports;
- distinguish raw-byte, semantic-JSON, and storage-envelope digests;
- semantic digests bind every semantic member, regardless of its field name;
- any runtime-only exclusions are enumerated by artifact kind and exact field
  path rather than by recursive key name;
- define strict parsing, normalization, object-key ordering, string escaping,
  number representation, SHA-256 prefix/case, and newline behavior;
- persist the digest-profile id anywhere independently verifiable digests are
  exposed;
- reject unknown profiles at consumer boundaries; and
- preserve legacy artifact readability without silently applying the legacy
  profile to new semantic content.

Publish language-neutral golden fixtures for every root artifact kind,
including Unicode, escaped strings, equivalent and nonequivalent numbers,
arrays, and semantic fields named after legacy exclusions. At least one
implementation outside the Go package must reproduce all fixture digests.

## CRN-06: Complete portable root-session export

The active plan extends `show`, `export`, and `contracts` with root refs, but a
JSON envelope containing refs into relay-home storage is not durable review
evidence. Witnessed review must retain and validate a pass after the relay
session is cleaned or moved.

Add a versioned portable export consisting of a manifest and the closed set
of payloads required to validate a root run. It must include:

- CLI version, export schema version, and digest-profile id;
- normalized recipe and source provenance when applicable;
- root plan, runtime snapshot, bundle, and selected contract;
- ordered named-input manifests and exact content artifacts;
- workspace and source-integrity records;
- checkpoints, participant transcript, provider invocations, facilitator
  artifacts, and reducer invocation;
- raw candidate, result-validation report, and canonical result when present;
- terminal status, stop reason, and diagnostics; and
- a manifest digest binding the complete payload inventory.

The portable identity cannot require absolute source, session, relay-home, or
worktree paths. Export must resolve and verify the complete ref closure before
success, write atomically, and fail on a missing, ambiguous, or invalid ref.
The exported bundle must remain verifiable after `convo-relay clean` removes
the source session.

Acceptance requires success, every terminal failure class, interrupted or
incomplete rejection, missing-payload failure, digest tampering, relocation,
and post-clean verification. A public verification command is desirable, but
the format must also be independently implementable by `review-cli`.

## CRN-07: Truthful isolation capability reporting

The active plan records requested, effective, and achieved workspace policy.
A detached writable Git worktree provides source-copy separation; it does not
provide filesystem containment, network isolation, or a same-user security
boundary. Witnessed review must not accidentally treat `achieved = ephemeral`
as those stronger properties.

Persist and export generic isolation dimensions, including at least:

- workspace mechanism and base identity;
- source-copy separation;
- source write prevention versus post-run mutation detection;
- filesystem containment;
- network isolation;
- process containment; and
- unsupported or unknown dimensions.

The detached-worktree implementation reports its actual capabilities. A
source mutation detected after a run remains an operational failure and does
not retroactively turn the worktree into a trusted command sandbox.

Acceptance requires capability records for supported platforms and tests
showing that no stronger claim is emitted merely because a worktree was
created.

## CRN-08: Machine-readable compatibility advertisement

Witnessed review must fail before finder work if the installed relay cannot
produce the contracts it will later need. A bare semantic version and backend
readiness probe are not enough to establish that.

Provide a stable machine-readable capability record, either through a new
command or a versioned extension of an existing one, listing at least:

- root recipe plan and artifact versions;
- supported integration-bundle version and schema/assertion surface;
- prompt-context projection version;
- provider-retry policy version;
- invocation artifact version;
- portable-export version;
- digest-profile versions; and
- workspace mechanisms and isolation-report version.

The startup check compares this record with a reviewer-owned compatibility
manifest. Missing or unknown required capabilities are hard compatibility
failures before any model request.

## CRN-09: Frozen-source adapter, conditionally required

The active workspace story intentionally aborts for non-Git and unborn
repositories and creates its detached worktree from committed `HEAD`, not
from staged, unstaged, or untracked content.

No additional convo-relay workspace backend is required if the reviewer
always:

1. creates a deterministic clean Git staging snapshot from the exact frozen
   target;
2. launches relay from that staging snapshot; and
3. binds the reviewed bytes separately as digest-checked named inputs.

If direct relay launch against dirty Git state, unborn repositories, or
non-Git targets is a required product behavior, convo-relay additionally
needs a snapshot-backed ephemeral workspace that reproduces the complete
recorded source inventory rather than committed `HEAD`. That backend must be
implemented and pass parity tests before direct launch is enabled.

In both approaches, export and inspection must distinguish workspace-base
digest from reviewed named-input digests.

## Explicit non-requirements

The following are not prerequisites for witnessed review and should not be
added to this delta:

- migrating convo-relay provider execution to agentbus;
- running finder roles through delegate;
- using agentbus job hashes as command-execution receipts;
- review-specific prompts, schemas, severity rules, duplicate rules,
  adjudication, or rendering inside convo-relay;
- consumer-specific batching or backend-fallback policy in convo-relay; and
- claiming that `context_only`, a worktree, or a provider result is a trusted
  command sandbox.

The caller-trusted command harness, Charter authority, duplicate/fixpoint
rules, review ledger, and review-owned artifact retention remain reviewer
responsibilities.

## Pre-execution gate

Witnessed review may run on fake fixtures while these items are being built.
It must not run on a real target as an authoritative review until all of the
following are true:

1. all 16 active-plan stories pass their acceptance and compatibility gates;
2. CRN-00 through CRN-08 are implemented and tested;
3. CRN-09 is resolved by a mandatory reviewer staging adapter or by the new
   workspace backend;
4. the six recipes compile with `--target root` against the exact
   review-owned bundle and compatibility manifest;
5. a named-input-only `context_only` fake run completes four participant
   turns and a fresh reducer with no hidden retry or facilitator-ledger leak;
6. an independent verifier validates the portable export and every digest,
   then validates the same export after the relay session is cleaned; and
7. the reviewer-owned prerequisites in §16.5 of the integration specification
   pass their end-to-end failure and false-clean tests.

Agentbus and delegate readiness are intentionally absent from this gate.
