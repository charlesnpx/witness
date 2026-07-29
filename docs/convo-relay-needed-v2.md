> **Historical.** This document is historical: the relay requirements it
> tracked are satisfied by `convo-relay` v1.4.0 and superseded by the corrected
> Witness spec's final contract. Do not implement from it.

# Convo-Relay v2 work needed for witnessed review

Release-pinned implementation plan for the generic `convo-relay` capabilities
required by Witnessed Adversarial Review.

This document supersedes [`convo-relay-needed.md`](convo-relay-needed.md) as
the active implementation plan. The earlier file is retained as historical
planning context because it was written against an executing plan rather than
an inspected release.

## 1. Assessment basis

This plan is based on the released and locally verified baseline:

- repository: `charlesnpx/convo-relay`;
- release: `v1.1.0`;
- commit: `72d3bf45874a5bd74e01d393bd0c0873e8f67da2`;
- assessment date: 2026-07-27;
- source worktree: clean and aligned with `origin/main`;
- installed binary: built from the same commit with `vcs.modified=false`;
- `make test`: passed, including the build without optional default records;
  and
- fake-provider smoke matrix: all 16 backend and lifecycle cases passed.

The baseline is healthy. This is not a remediation plan for a broken merge.
It is the successor contract and evidence-portability plan required before
Witness may treat a relay verdict as authoritative review evidence.

If the implementation base changes, update the release, commit, capability
inventory, and three-dot diff before executing this plan.

## 2. Baseline accepted from v1.1.0

The following capabilities are present and are not reimplemented here:

- strict JSON ingestion and typed diagnostics;
- versioned v1 root artifacts and runtime snapshots;
- integration-bundle v1 loading, selected-contract binding, inline JSON
  Schema, and generic assertions;
- backend installation and authentication-readiness reporting;
- explicit root and child compile targets;
- integration-aware catalog and compile reporting;
- repeatable, binary-safe, digest-checked named inputs;
- Git inventory, detached-worktree execution, source-integrity checks,
  retention, and cleanup;
- direct `run --recipe` dispatch and pure preflight;
- exact alternating participant turns with separate participant and
  facilitator contexts;
- fresh reduction, raw result retention, schema/assertion validation, and a
  canonical result ref;
- recovery checkpoints and lifecycle guards;
- root-session inspection, output, health, and administration;
- the six structural witnessed-review recipe records; and
- the generic acceptance suite.

Every successor story must preserve those behaviors for v1 inputs and
ordinary non-Witness runs.

## 3. Required outcome

After this plan lands, a consumer can determine before any model request that
the installed relay supports the exact contract family it needs, execute a
named-input-only bounded protocol with at most one runner launch attempt per
declared invocation, and retain a complete result that an independent
implementation can validate after the relay session has been moved or
deleted.

The required Witness profile is:

```text
bundle schema:             relay-integration-bundle-v2
capability record:         relay-capabilities-v1
participant turns:         4
result source:             fresh reducer
investigation authority:   bound named inputs
prompt policy:             prompt-policy/v2
prompt projection policy:  relay-prompt-context-v1
provider retry policy:     relay-provider-retry-policy-v1
provider retry:            forbid
provider invocation:       relay-provider-invocation-v1
rendered prompt:           relay-rendered-prompt-v1
participant transcript:    complete
facilitator ledger:        trace_only
workspace minimum:         ephemeral
isolation report:          relay-workspace-isolation-v1
digest profile:            relay-root-digests-v1
portable export:           relay-root-portable-export-v1
```

The relay implementation remains domain-neutral. It must not branch on a
Witness recipe id, integration-contract id, input name, schema field, verdict
value, or consumer vocabulary.

## 4. Version-transition matrix

Strict v1 payloads keep their original field sets and digest meanings. No v2
field is added under a v1 identifier.

| Contract or format | Released reader/writer | Successor writer | Successor reader policy |
|---|---|---|---|
| normalized recipe | `kind=recipe`, numeric `schema_version=1` | numeric `schema_version=2` when `provider_retry` is represented | Read v1 and v2; reject v2 fields under v1. |
| root recipe plan | `kind=root_recipe_plan`, numeric `schema_version=1` | numeric `schema_version=2` with effective provider retry and selected prompt-context refs | Read v1 and v2; never infer version from fields. |
| integration bundle | `relay-integration-bundle-v1` | `relay-integration-bundle-v2` with `prompt_context` | Read both; v1 defaults to complete/include and rejects `prompt_context`. |
| selected integration contract artifact | numeric `schema_version=1` | numeric `schema_version=2` with normalized prompt projection and digest profile | Read both; selection preserves source bundle version. |
| root artifact payload | numeric `schema_version=1` | numeric `schema_version=2` when digest profile or invocation refs are exposed | Read both; v1 continues using its legacy digest meaning. |
| execution workspace artifact | numeric `schema_version=1` | numeric `schema_version=2` with isolation report | Read both; never translate `achieved=ephemeral` into stronger claims. |
| root-session machine result | current strict v1 projection | `kind=root_session_result`, numeric `schema_version=2` | Read both; new fields appear only in v2. |
| prompt policy | `prompt-policy/v1` with positional-context boolean | `prompt-policy/v2` with authoritative input-source records | Read both; recovery never infers authority from unrelated refs. |
| prompt-context projection policy | absent | `relay-prompt-context-v1` represented in selected-contract v2 | New policy identifier; unknown versions or values fail closed. |
| provider-retry policy | absent | `relay-provider-retry-policy-v1` represented in recipe and root-plan v2 | New policy identifier; legacy recipe omission retains the documented `allow` default. |
| provider invocation | absent | `relay-provider-invocation-v1` | New format; reject unknown versions. |
| rendered prompt | absent | `relay-rendered-prompt-v1` | New format; exact UTF-8 bytes are retained and raw-byte digested. |
| digest profile | implicit implementation detail | `relay-root-digests-v1` | Profile id is mandatory at independent-verification boundaries. |
| isolation report | absent | `relay-workspace-isolation-v1` | New format; unsupported and unknown are explicit values. |
| portable export | absent | `relay-root-portable-export-v1` | New closed-set format; reject unknown versions or incomplete closure. |
| capability advertisement | absent | `relay-capabilities-v1` | New stable command output; unknown required capabilities fail closed. |

### 4.1 Writer policy

- Existing stored v1 payloads remain byte- and digest-compatible.
- Child compilation remains v1 unless a separate successor requirement is
  introduced.
- New root runs using any successor execution policy or digest profile write
  v2 recipe, root-plan, root-artifact, workspace, and machine-result payloads.
- Omitted `provider_retry` reads as `allow` for legacy recipes. A v2 root plan
  always records the effective value.
- An integration-bundle v1 contract normalizes prompt context to
  `participant_transcript=complete` and `facilitator_ledger=include` without
  changing the v1 bundle bytes or digest.
- Conversion, where offered, is an explicit command or API operation. Readers
  never guess a schema version from field presence.

### 4.2 Compatibility fixtures

Each changed contract requires:

- old-reader rejection of successor fields under a v1 identifier;
- new-reader acceptance of valid v1 and v2 fixtures;
- explicit unknown-version rejection;
- deterministic migration fixtures where migration is supported;
- unchanged v1 digest fixtures; and
- capability output naming every exact supported version.

## 5. CRN-00: Successor contract registry and schema boundaries

Implement the version matrix before adding execution behavior.

Required work:

- create one central registry for public contract, artifact, digest, export,
  isolation, and capability versions;
- give every public decoder an explicit version dispatch;
- make every v1 decoder reject v2-only fields;
- add v2 recipe, root-plan, selected-contract, root-artifact, workspace, and
  root-session-result schemas;
- preserve v1 artifact-ref readability and digest semantics;
- expose the supported matrix through the capability record; and
- publish the matrix in repository documentation.

Acceptance:

- table-driven old/new reader fixtures cover every row in §4;
- no decoder chooses a version from field presence;
- v1 fixtures retain their existing canonical bytes and digests;
- unsupported versions return stable typed diagnostics; and
- generic operation without optional Witness records remains green.

## 6. CRN-01: Named-input-aware `context_only`

Replace the prompt-policy boolean that represents positional context with an
authoritative input-source set.

The normalized source set initially supports:

```json
{
  "schema_version": "prompt-policy/v2",
  "sources": [
    {
      "kind": "named_input",
      "label": "charter",
      "manifest_ref": {},
      "content_refs": []
    }
  ]
}
```

Required behavior:

- one or more successfully bound named inputs satisfy `context_only` for an
  integration-bound root run;
- prompt policy is finalized only after integration selection and named-input
  binding succeed;
- prompts cite stable input names and artifact refs;
- positional context remains rejected when the selected contract declares
  named inputs;
- a policy with neither positional context nor any successfully bound named
  authoritative input fails before session creation or provider launch;
- recovery reconstructs the same authoritative source set from persisted
  refs; and
- metadata records which source set satisfied the policy.

`context_only` remains provider guidance. It is not an OS sandbox, tool
receipt, filesystem restriction, or proof that a provider obeyed the prompt.

Acceptance:

- named-only CLI success;
- positional-only ordinary success;
- no-input failure;
- named-plus-positional rejection for a named-input contract;
- stable labels and refs in participant and reducer prompt captures;
- recovery and inspection preserve the authority record; and
- pure-preflight failures create no session and launch no provider.

## 7. CRN-02: Compiled provider-retry policy

Add to the successor recipe lifecycle:

```toml
provider_retry = "allow" | "forbid"
```

The public semantics of this field are identified by
`relay-provider-retry-policy-v1` and advertised independently from the numeric
recipe and root-plan schema versions.

Required behavior:

- omission defaults to `allow` for ordinary compatibility;
- the effective value is present in recipe v2, root-plan v2, runtime
  snapshot, root-session result v2, invocation records, inspection, and
  portable export;
- all six Witness default records set `forbid`;
- `forbid` permits at most one runner launch attempt per participant,
  facilitator, or reducer invocation;
- a classified transient failure becomes that invocation's terminal result
  with no runner backoff or replacement launch;
- participant-turn counts continue to count completed turns, while invocation
  records count attempted launches;
- cancellation, timeout, stall, provider failure, and invalid structured
  output preserve their original classifications; and
- provider-internal retries invisible to the runner are not invented as
  observed attempts.

Acceptance:

- fake-provider tests prove one launch for every transient failure path in
  participant, facilitator, and reducer phases;
- `allow` regression tests preserve the released retry behavior;
- digests change when the effective policy changes;
- recovery never replays a terminal forbidden attempt as an implicit retry;
  and
- inspection and export distinguish completed turns from attempted calls.

## 8. CRN-03: Integration-bundle v2 prompt projection

Add to every selected contract in `relay-integration-bundle-v2`:

```json
{
  "prompt_context": {
    "participant_transcript": "complete",
    "facilitator_ledger": "include"
  }
}
```

The public projection semantics are identified by `relay-prompt-context-v1`
and advertised independently from the bundle and selected-contract envelope
versions.

Initial values:

- `participant_transcript`: only `complete`;
- `facilitator_ledger`: `include` or `trace_only`.

Omission under bundle v2 defaults to complete/include. Bundle v1 has the same
effective compatibility default without gaining a new field.

Required behavior:

- validate, normalize, digest, compile, persist, inspect, and export the
  projection;
- `trace_only` retains facilitator outputs and ledger parsing in trace
  artifacts but excludes them from every later participant and reducer
  rendered prompt;
- participant transcript projection is lossless and ordered;
- future-turn actor instructions never appear before their declared turn;
- recovery uses the persisted selected-contract projection; and
- core code remains generic and does not inspect consumer ids.

Acceptance:

- strict v1 rejection of `prompt_context`;
- v2 default and explicit-value fixtures;
- unknown-value diagnostics;
- prompt captures prove complete participant history;
- prompt captures prove complete absence of trace-only facilitator content in
  participant and reducer prompts; and
- facilitator trace artifacts remain available for inspection and export.

## 9. CRN-04: Per-invocation provenance

Persist one invocation record for every declared participant, facilitator,
and reducer invocation, including attempts that fail during prompt
construction or before provider launch.

Proposed normalized shape:

```json
{
  "schema_version": "relay-provider-invocation-v1",
  "phase": "participant",
  "actor": "slot_0",
  "participant_ordinal": 1,
  "rendered_prompt_ref": {},
  "rendered_prompt_digest": "sha256:...",
  "recipe_ref": {},
  "root_recipe_plan_ref": {},
  "selected_contract_ref": {},
  "named_input_manifest_refs": [],
  "backend": "codex",
  "requested_model": "...",
  "requested_effort": "...",
  "provider_session_id": null,
  "workspace_ref": {},
  "mapped_working_directory": ".",
  "runner_attempt": 1,
  "provider_launch_attempted": true,
  "provider_retry": "forbid",
  "started_at": "...",
  "completed_at": "...",
  "outcome": "completed",
  "failure_stage": null,
  "provider_result_ref": {}
}
```

Required behavior:

- persist the exact rendered prompt as a separate byte artifact before the
  provider is launched whenever prompt construction succeeds;
- bind actor, phase, slot, participant ordinal, and reducer freshness;
- bind recipe, root plan, selected contract, the ordered named-input manifest
  refs, workspace, backend, requested model and effort, and provider session
  identity when available;
- use a relative mapped working directory in portable identity;
- preserve start and completion timestamps as trace fields without excluding
  semantically named fields from the invocation digest;
- record attempt number, retry policy, classification, terminal outcome, and
  whether provider launch occurred;
- represent stage-dependent unavailable refs as explicit nulls and record the
  failure stage rather than fabricating or ambiguously omitting provenance;
- record the provider result ref when one exists;
- persist records for construction failure, timeout, stall, cancellation,
  provider failure, invalid result, and success; and
- expose ordered invocation refs in root result v2 and portable export.

These records prove what the runner dispatched and observed. They do not
prove that a provider truthfully reported a tool action.

Acceptance:

- one-to-one declared-call versus invocation-record accounting;
- exact prompt-byte and prompt-ref tamper detection;
- fresh-reducer lineage independent of participant and facilitator sessions;
- records survive every terminal failure class;
- no more than one provider launch per invocation under `forbid`; and
- absolute source, relay-home, session, or worktree paths do not enter
  portable identity.

## 10. CRN-05: Public kind-aware digest profile

Publish `relay-root-digests-v1` as a language-neutral contract.

Digest classes:

- `raw-bytes`: SHA-256 over exact bytes;
- `semantic-json`: SHA-256 over the profile's canonical JSON bytes, binding
  every semantic member regardless of its key name; and
- `storage-envelope`: kind-specific projection with runtime-only exclusions
  enumerated by exact JSON Pointer.

The profile defines:

- strict input parsing and duplicate-key behavior;
- Unicode and string escaping;
- object-key ordering;
- array ordering;
- integer and non-integer number representation;
- negative zero and exponent handling;
- UTF-8 requirements;
- newline inclusion or exclusion;
- SHA-256 prefix and lowercase-hex requirements;
- artifact-kind digest class;
- exact runtime-only exclusions by artifact kind and JSON Pointer; and
- manifest-inventory digest construction.

The legacy recursive exclusion of names such as `path`, `created_at`, and
`storage_id` remains readable only for released v1 artifacts. It is not used
for new semantic JSON.

Required fixtures:

- every root artifact kind;
- recipe v1/v2 and root-plan v1/v2;
- bundle v1/v2 and selected contract v1/v2;
- raw named inputs and rendered prompts;
- provider invocation;
- workspace and isolation report;
- raw result, validation report, and canonical result;
- portable-export manifest;
- Unicode and escaped strings;
- equivalent and nonequivalent numeric forms;
- arrays and nested objects; and
- semantic members literally named `path`, `created_at`, and `storage_id`.

Acceptance:

- Go reproduces every fixture;
- at least one implementation outside the Go package reproduces every
  fixture;
- unknown profile ids fail at consumer boundaries;
- changing any semantic member changes the semantic digest; and
- released v1 fixtures keep their existing digests.

## 11. CRN-06: Complete portable root-session export

Add a closed-set directory export:

```text
convo-relay export <session> --portable -o <bundle-directory> --json
```

A built-in `convo-relay verify-export <bundle-directory> --json` command is
recommended for operator diagnostics, but it is not a Witness prerequisite
and cannot replace the independent review-owned verifier.

Proposed layout:

```text
<bundle-directory>/
├── manifest.json
└── payloads/
    └── <kind>/<portable-id>.<extension>
```

`manifest.json` uses `relay-root-portable-export-v1` and contains:

- CLI version;
- export schema version;
- digest-profile id;
- terminal status and stop reason;
- normalized recipe and source provenance;
- root plan and runtime snapshot;
- bundle and selected contract;
- ordered named-input manifests and exact content artifacts;
- workspace, source-integrity, and isolation reports;
- checkpoints and participant transcript;
- rendered prompts and provider invocations;
- facilitator artifacts and reducer invocation;
- raw candidate, validation report, and canonical result when present;
- diagnostics;
- a complete typed payload inventory; and
- a manifest digest binding the inventory.

Required behavior:

- resolve and validate the complete transitive ref closure before success;
- reject missing, ambiguous, duplicate, mismatched, or out-of-root refs;
- reject running or incomplete sessions as complete exports;
- support every terminal success and failure class with the payload closure
  appropriate to that class;
- exclude required absolute source, relay-home, session, and worktree paths
  from portable identity;
- write to a sibling temporary directory, fsync as supported, and atomically
  rename into place;
- never replace an existing non-empty target implicitly;
- verify successfully after relocation;
- verify successfully after `convo-relay clean` removes the source session;
  and
- expose stable typed diagnostics from the export command and, when the
  optional built-in verifier is implemented, from that command as well.

The ordinary `run --json -o` envelope and human transcript export remain
compatible. Neither is treated as the portable evidence bundle.

Acceptance:

- completed success;
- every terminal failure class;
- running and incomplete rejection;
- missing, ambiguous, duplicate, mismatched, and out-of-root refs;
- content, manifest, and digest-profile tampering;
- relocation;
- post-clean verification;
- interruption during export without a partial final target; and
- independent review-owned verification without importing the Go package.

## 12. CRN-07: Truthful isolation capability report

Publish `relay-workspace-isolation-v1` in execution-workspace v2 artifacts and
portable exports.

Minimum shape:

```json
{
  "schema_version": "relay-workspace-isolation-v1",
  "mechanism": "detached_writable_git_worktree",
  "base_identity": {
    "object_format": "sha1",
    "head_commit": "...",
    "head_tree": "..."
  },
  "source_copy_separation": "yes",
  "source_write_control": "post_run_detection",
  "filesystem_containment": "none",
  "network_isolation": "none",
  "process_containment": "none",
  "same_user_security_boundary": "none",
  "unknown_dimensions": []
}
```

Required behavior:

- report observed mechanism and base identity;
- distinguish write prevention from post-run mutation detection;
- use closed schema-defined enums for every dimension, with `yes`, `no`,
  `none`, `unknown`, or `unsupported` used where applicable and no inference
  from omission;
- never infer filesystem, network, process, or same-user containment from an
  `ephemeral` policy label;
- record supported-platform differences without claiming runtime
  certification for untested targets;
- preserve source mutation as an operational failure rather than rewriting
  the capability record; and
- expose the report through inspection, result v2, and portable export.

Acceptance:

- supported-platform golden records;
- inherited and detached-worktree fixtures;
- negative tests against stronger inferred claims;
- source-mutation failure retains the original truthful report; and
- portability tests for every supported build target.

## 13. CRN-08: Machine-readable capability advertisement

Add:

```text
convo-relay capabilities --json
```

The command performs no provider request and no authentication probe. Its
output is stable `relay-capabilities-v1` JSON containing at least:

```json
{
  "schema_version": "relay-capabilities-v1",
  "convo_relay_version": "...",
  "contracts": {
    "recipe": [1, 2],
    "root_recipe_plan": [1, 2],
    "integration_bundle": [
      "relay-integration-bundle-v1",
      "relay-integration-bundle-v2"
    ],
    "selected_integration_contract": [1, 2],
    "root_artifact": [1, 2],
    "execution_workspace": [1, 2],
    "root_session_result": [1, 2]
  },
  "prompt_policy": ["prompt-policy/v1", "prompt-policy/v2"],
  "prompt_context_projection": ["relay-prompt-context-v1"],
  "provider_retry_policy": ["relay-provider-retry-policy-v1"],
  "provider_invocation": ["relay-provider-invocation-v1"],
  "rendered_prompt": ["relay-rendered-prompt-v1"],
  "portable_export": ["relay-root-portable-export-v1"],
  "digest_profile": ["relay-root-digests-v1"],
  "workspace_mechanisms": ["inherited", "detached_writable_git_worktree"],
  "isolation_report": ["relay-workspace-isolation-v1"]
}
```

The top-level `schema_version` is the capability-advertisement version. A
consumer validates it before comparing the remaining inventory.

Required behavior:

- generate the record from the same central registry used by decoders and
  writers;
- deterministic key and array ordering;
- no environment-dependent backend-readiness data in this record;
- exact CLI version and build-supported platform data;
- stable diagnostics for unsupported output schema requests; and
- documentation separating compatibility advertisement from
  `backends status` runtime readiness.

Acceptance:

- golden output;
- registry-versus-capability completeness test;
- no provider executable is invoked;
- optional Witness default records do not alter generic capability claims;
  and
- a reviewer fixture fails closed on each removed or unknown required
  capability.

## 14. CRN-09: Frozen-source strategy decision

No new `convo-relay` workspace backend is required for this plan.

Witness selects the reviewer-owned staging strategy:

1. materialize the exact frozen reviewed bytes into a deterministic clean Git
   repository with a committed `HEAD`;
2. record its inventory, object format, commit, tree, and content digest;
3. launch relay from that staging snapshot; and
4. bind the reviewed bytes separately as digest-checked named inputs.

Relay responsibilities are limited to:

- accepting the supported clean Git staging snapshot;
- recording the workspace base independently from named-input digests;
- truthfully reporting the detached-worktree isolation dimensions; and
- retaining those records in the portable export.

Direct launch against dirty Git state, an unborn repository, or a non-Git
target is not an authoritative Witness path. If that product requirement is
introduced later, it needs a separately approved snapshot-workspace plan and
parity suite.

## 15. CLI and public-contract summary

Required new or extended surface:

```text
convo-relay capabilities --json

convo-relay recipes show <id> --integration-bundle <bundle> --json
convo-relay compile-recipe --recipe <id> --target root \
  --integration-bundle <bundle> --json

convo-relay run <task> --recipe <id> \
  --integration-bundle <bundle> \
  --input <name>=<path> \
  --investigation context_only \
  --workspace-isolation ephemeral \
  --json

convo-relay export <session> --portable -o <bundle-directory> --json

# optional operator diagnostic; not the independent Witness verifier
convo-relay verify-export <bundle-directory> --json
```

Existing commands retain their ordinary behavior. New flags fail explicitly
when used with an incompatible contract version or session kind.

## 16. Implementation order and dependency gates

Execute in this order:

1. **Contract registry and version matrix** — CRN-00.
2. **Recipe and prompt-policy inputs** — CRN-01 and CRN-02 may proceed after
   the v2 recipe/root-plan contracts exist.
3. **Bundle projection** — CRN-03 may proceed after bundle and selected
   contract v2 exist.
4. **Digest primitives and fixtures** — CRN-05 defines the identity contract
   required by new portable artifacts.
5. **Invocation provenance** — CRN-04 uses prompt raw-byte and semantic JSON
   digests from CRN-05.
6. **Isolation report** — CRN-07 completes execution-workspace v2.
7. **Portable export and verification contract** — CRN-06 consumes the
   completed artifact, invocation, digest, and isolation contracts. The
   built-in verification command remains optional; independent verification
   against the published format remains required.
8. **Capability advertisement** — CRN-08 is scaffolded from the registry in
   step 1 and finalized only after all supported versions exist.
9. **Generic acceptance and release gates** — run the complete matrix below.

Parallel implementation is allowed only where stories do not share public
schema or digest ownership. Schema identifiers, canonical bytes, and golden
fixtures are serialized decisions.

## 17. Generic acceptance matrix

Before release, the `convo-relay` repository proves:

1. all released v1 fixtures and compatibility tests still pass;
2. all v2 strict-reader and writer fixtures pass;
3. ordinary and child relay behavior remains compatible;
4. generic root execution works without optional Witness defaults;
5. all six structural Witness records compile for root against a generic v2
   fixture and set `provider_retry=forbid`;
6. named-input-only `context_only` completes four turns and a fresh reducer;
7. no positional context is required or accepted for that named-input
   contract;
8. one runner launch occurs per declared invocation under `forbid` for every
   success and transient-failure phase;
9. complete participant history reaches later prompts without future-turn
   instruction leakage;
10. a trace-only facilitator ledger never reaches a later participant or
    reducer prompt;
11. every provider call has exactly one invocation record per runner attempt;
12. invocation and rendered-prompt tampering is detected;
13. every new root artifact round-trips under `relay-root-digests-v1`;
14. the independent implementation reproduces every golden digest;
15. workspace reports make no unsupported containment claim;
16. complete portable exports validate for success and every terminal failure
    class;
17. incomplete sessions cannot produce a purportedly complete export;
18. missing, ambiguous, duplicate, mismatched, out-of-root, or tampered refs
    and payloads fail verification;
19. relocated exports validate;
20. exports validate after source-session cleanup;
21. the capability record exactly matches the implementation registry;
22. backend readiness remains separate and makes no model request by default;
23. race tests pass for runner, store, workspace, named inputs, export, and
    command packages;
24. production and test packages cross-compile for every supported target;
    and
25. documentation describes all trust boundaries without calling prompt
    policy, provider output, or a writable worktree a security boundary.

## 18. Witness-owned deliverables after relay implementation

These are required for the product gate but do not belong in `convo-relay`
core:

- `relay/witnessed-review-integration-v2.json`;
- a reviewer-owned compatibility manifest naming every required capability
  and version;
- a deterministic frozen-source staging adapter;
- an independent digest and portable-export verifier that does not import the
  `convo-relay` Go package;
- explicit owner-authorized Charter initialization and pass preflight that
  never creates goals implicitly;
- `review-execution-receipt-v2` issuance and verification with authenticated
  issuer/harness identity, policy and executable digests, pass/snapshot
  lineage, environment and resource policy, containment records,
  transformation digest, and before/after inventories;
- recurrence and explicit-resolution handling that cannot suppress an
  unresolved finding or forge `fixpoint_eligible`;
- compile reports for all six structural recipes against the exact bundle;
- fake-provider fixtures for both domain contracts and all three backend
  assignment variants;
- review-owned false-clean and failure-mapping tests; and
- pass-state retention of capabilities, bundle, compatibility manifest,
  compile reports, backend status, portable exports, and digests.

The domain contract ids remain:

```text
witnessed-review/witness-falsification-v1
witnessed-review/economy-equivalence-v1
```

They do not advance merely because the generic bundle envelope advances. A
domain id advances only when the witness-verdict semantics or schema meaning
changes.

## 19. Explicit non-requirements

This plan does not require:

- migrating provider execution to agentbus;
- running finder roles through delegate;
- treating agentbus hashes as command-execution receipts;
- review-specific prompts, schemas, severities, duplicate rules,
  adjudication, or rendering inside `convo-relay`;
- consumer-specific batching or backend-fallback policy in `convo-relay`;
- a new workspace backend while Witness uses its staging adapter;
- claiming provider-internal retries as runner-observed attempts; or
- claiming that `context_only`, a worktree, an invocation record, or a
  provider result is a trusted command sandbox or receipt.

## 20. Authoritative pre-execution gate

Fake fixtures may run while this plan is being implemented. A real target may
not produce authoritative automatic-change candidates or a clean-fixpoint
decision until all of the following are true:

1. the complete v1.1.0 regression suite and every acceptance item in §17
   pass;
2. CRN-00 through CRN-08 are implemented and advertised;
3. the reviewer-owned staging adapter resolves CRN-09;
4. the exact v2 review bundle and compatibility manifest validate;
5. all six structural recipes compile for root against those exact files;
6. a named-input-only fake run completes four participant turns and one fresh
   reducer with no hidden retry or facilitator-ledger leak;
7. invocation accounting and rendered-prompt digests validate one-to-one;
8. an independent verifier validates every digest and complete portable
   export before and after relay-session cleanup;
9. end-to-end failure injection maps every unavailable, timeout, isolation,
   provider, reducer, invalid-result, invocation, digest, export, and
   compatibility failure to pending verification rather than clean;
10. missing owner-authorized Charter, unauthenticated or incomplete execution
    receipts, and unresolved exact finding recurrence all fail closed; and
11. the review-owned false-clean tests pass.

Agentbus and delegate readiness are intentionally absent from this gate.

## 21. Definition of done

This plan is complete only when:

- the implementation, public schemas, documentation, golden fixtures, and
  capability record agree;
- no required behavior exists only in prose without an executable test;
- no released v1 digest or reader contract changed in place;
- a third-party consumer can implement digest and export verification from
  the published contracts alone;
- Witness can perform compatibility preflight before any model request; and
- the authoritative pre-execution gate in §20 passes without exceptions.
