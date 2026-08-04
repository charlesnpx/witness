# Witnessed Adversarial Review

Specification for Witness v1, a grounded single-pass review engine that
produces auditable findings from a frozen source state, a frozen Charter, and
independently verified defect witnesses.

Witness consists of:

- `witness`, the deterministic Go 1.23+ CLI;
- `witness-harness`, the trusted execution-receipt producer; and
- a repository-shipped Codex skill containing finder roles and orchestration
  guidance.

This revision targets `convo-relay` v1.4.0 and its six v2 Witness
recipes/contracts. No further relay changes are required. Witness never
mutates reviewed sources, applies findings, retries models, adds model roles,
or owns an iteration loop.

---

## 1. Problem

Automated review has a stable additive bias:

1. Findings are cheap to produce. A reviewer pays no implementation cost for
   a plausible suggestion and is rewarded for appearing thorough.
2. Subtraction is not a first-class verdict. Conventional review protocols
   create additions and changes more readily than deletions.
3. "Worthwhile" is not mechanically testable. A judgment-based gate tends to
   admit almost every locally reasonable proposal.
4. Reviewer temperament leaks into workflow length. A more expansive model
   produces a longer campaign rather than a demonstrably better artifact.
5. Finders grade their own evidence. The context that constructs a claim is
   predisposed to accept the demonstration supporting it.
6. Tool claims can be fictional. A model saying that it ran a command is not
   proof that the command ran against the frozen artifact.
7. Verification outages can forge a clean result when failure is silently
   treated as a weaker verified finding.

The result is defensive machinery for goals nobody stated and a human
manually performing the per-finding adjudication the system was intended to
make deterministic.

---

## 2. Goals

Witness produces reviews in which:

- every finding that can obligate a change names a valid Charter goal and
  carries a concrete witness;
- expensive findings are independently tested before becoming automatic
  change candidates;
- deletion and simplification are first-class findings;
- disposition and application class are functions of versioned rules, not
  model temperament;
- verification failure is visible as a pending state rather than a demotion;
- all findings, questions, owner decisions, and policy decisions remain
  recoverable in durable lineage;
- model output never self-certifies execution or verification;
- the reviewed source artifact is not modified during review or verification;
  and
- the human owner retains sole authority over goals, cap releases, and
  explicit overrides.

---

## 3. Architecture and Trust Boundaries

Anything that creates, discharges, or overrides an obligation must be
deterministic and auditable.

### 3.1 `witness`: Deterministic Core

`witness` performs no model calls. It owns:

- strict JSON and JSONL ingestion;
- canonical JSON and relay-root-digests-v1 verification implemented
  independently of relay;
- Charter initialization, freezing, hashing, showing, and append-only
  amendment records;
- frozen-source Git snapshot creation without modifying the caller's tree;
- role-output document validation;
- scope-anchor, reachability, witness-strength, severity-cap, and
  non-recursion rules;
- deterministic verification preflight, planning, batching, and assembly;
- relay capability, integration-bundle, contract, prompt-policy,
  provider-invocation, portable-export, and digest validation;
- execution-receipt validation;
- final finding dispositions and application classes;
- versioned rules and policy identifiers;
- append-only ledger writes;
- exact recurrence and resolution tracking through deterministic fingerprints
  and artifact lineage;
- verdict, advisory, question, and metric emission; and
- fail-closed policy loading.

The CLI surface is exactly:

```text
witness charter init|freeze|amend|show
witness verification preflight|plan|assemble
witness adjudicate
witness ledger show|promote|accept-unverified
witness policy show|release-caps|check-application
witness metrics
witness-harness run
```

`witness policy check-application` accepts caller-measured production and test
change deltas, returns a deterministic allow/refuse result, appends the policy
decision, and never applies patches.

### 3.2 Codex Skill

The repository-shipped skill contains finder and procedure guidance only. It
ships defect, economy, and optional goal-fit briefs, the review-owned relay
integration bundle, and orchestration instructions for a caller. It does not
add roles, judgment gates, disposition rules, or application authority.

Prompts may evolve as model behavior changes. They cannot change the
mechanical meaning of a finding, verification result, disposition, or
application class without a versioned contract or rules change.

### 3.3 Caller

The caller is the only component that:

- starts a pass;
- retries a failed pass or verification batch by launching a new recorded
  batch;
- applies a change;
- measures production and test deltas after applying a change;
- amends the Charter through an owner action;
- releases additive-automation caps; or
- decides whether its own external workflow should continue.

Witness itself emits decisions and durable records. It does not mutate the
reviewed artifact.

### 3.4 Trusted and Untrusted Data

Trusted for obligation purposes:

- normalized Charter data, including the Operational Envelope, and its hash;
- `witness` rules and policy versions;
- the review-owned integration bundle after deterministic validation and
  digesting;
- the consumer-owned compatibility manifest after deterministic validation and
  digesting;
- terminal, complete `convo-relay` portable exports validated under
  relay-root-digests-v1, including recipe, selected contract, root plan,
  named inputs, workspace records, provider invocations, provider results,
  validation records, and canonical result closure;
- execution receipts emitted by a caller-trusted `witness-harness`;
- artifact and file digests recomputed by Witness; and
- explicit owner override and cap-release records.

A validated relay result is trusted only as a bounded witness-survival verdict
for the filed witness. Relay survival never validates a remedy, proposed test,
or provider command execution.

Untrusted until validated:

- all reviewer prose;
- finding-claimed severity;
- model or backend claims that tools ran;
- model-authored verification fields;
- free-form relay transcript content;
- reducer output before generic relay validation and Witness-owned validation;
- relay-produced digest booleans; and
- semantic claims about duplicates.

---

## 4. Contracts and Public Interfaces

### 4.1 Contract Family

Witness implements only this contract family:

- `review-charter-v2`;
- `review-role-output-v3`;
- `review-verification-batch-v2`;
- `relay-witness-verdicts-v2`;
- `review-verification-manifest-v3`;
- `review-execution-receipt-v2`;
- `review-relay-compatibility-v3`;
- `review-rules-v2`; and
- `review-policy-v2`.

The JSON wrapper artifacts are named role-output document,
verification-batch document, and run-result document. The phrase Operational
Envelope is reserved exclusively for Charter scope.

### 4.2 Charter and Operational Envelope

`review-charter-v2` contains goals, non-goals, standing goals, owner events,
and an optional `operational_envelope`.

The Charter includes this standing statement:

> Existing code, tests, defenses, and review-introduced machinery create no
> goals.

The Operational Envelope, when present, has seven required dimensions:

- entry points;
- input surface;
- valid states;
- environments;
- scale bounds;
- compatibility promises; and
- threat model.

Every dimension has `state`, `statement`, and `entries`. `state` is one of
`bounded`, `unbounded`, `not_applicable`, or `unspecified`. A bounded
dimension requires stable entries with declared IDs. Every other state
requires an empty entry list. Omission of an Operational Envelope or of a
possible value never means exclusion.

No Operational Envelope leaves reachability rules inactive. In that mode,
additive defect remedies can never become automatic.

Under an Operational Envelope, every defect finding names at least one scope
anchor. Bounded anchors reference declared entry IDs. Unbounded anchors state
the concrete exercised value. Anchoring to an unspecified dimension
deterministically produces a linked missing-goal question and no obligating
finding. Invalid anchors and explicitly excluded anchors remain advisory.

Constructed and executable defect witnesses also provide an entry point and a
non-empty reachability chain. The CLI validates presence and references. The
falsifier judges truth. Argued defect witnesses and all equivalence witnesses
are exempt from the reachability-chain requirement.

### 4.3 Role-Output Document

`review-role-output-v3` is emitted by finder roles. It contains no verification
decisions and no relay results.

Required content includes:

- role, Charter hash, artifact digest, source identity, and consumer identity;
- findings for defect and economy roles;
- missing-goal questions for any role;
- scope anchors for defect findings when an Operational Envelope is present;
- entry point and reachability chain for constructed and executable defect
  witnesses that require them;
- witness kind, strength, content, digestable artifact references, and
  executable specification when applicable;
- split production and test estimated deltas;
- proposed tests that are traceable to Charter goals and reachable behavioral
  partitions; and
- `additionalProperties = false` semantics for the current schema version.

Role consistency rules:

- defect findings require defect witnesses;
- economy findings require equivalence witnesses;
- economy remedies must be `remove` or a size-reducing `change`;
- economy findings require valid structured negative production or test delta
  where relevant;
- defect findings with unknown or malformed estimated delta may still be
  admitted, but their delta status is `unknown`;
- executable strength requires structured argv, cwd, expected observation, and
  any transformation reference; and
- goal-fit output contains no findings, severities, remedies, or application
  recommendations.

The skill requires the smallest sufficient remedy and at most one proposed
test per distinct reachable behavioral partition. Proposed tests exclude
unreachable states, runtime guarantees, repeated internal layers, unsupported
Cartesian combinations, implementation-only details, and unbounded fuzz or
property work.

### 4.4 Verification-Batch Document

`review-verification-batch-v2` is produced by `witness verification plan`.
It contains the exact role-output digest and unchanged filed witnesses, with
no surrounding finder narrative.

Each batch contains:

- task shape `defect` or `economy`;
- Charter hash and artifact digest;
- source role-output ref and digest;
- batch ID;
- one to eight findings;
- exact filed finding objects;
- one witness digest per finding; and
- no model-authored verification fields.

The planner orders candidates by role, severity, and finding ID. Each batch is
run once. Oversized batches are split deterministically; validation is never
loosened to accommodate batch size.

### 4.5 Relay Verdicts

`relay-witness-verdicts-v2` is the reducer result schema for both Witness
relay contracts.

Allowed witness verdicts are:

- `survived`;
- `weakened`; and
- `broken`.

`verdict_class` is null for `survived` and required for `weakened` and
`broken`. Allowed classes are `logic`, `unreachable`, `outside_envelope`,
`missing_premise`, and `other`. `unreachable` and `outside_envelope` are valid
only with `broken`. A `weakened` result represents a partial logical failure
or premise failure.

A `weakened` or `broken` result requires a concrete counter-witness. A
`survived` result requires the counter-witness to be null. The result covers
the planned finding IDs exactly and preserves each witness digest exactly.

Relay output contains no trusted execution-attestation field. Receipt
contradictions are deterministic `witness verification assemble` outcomes,
not relay verdict classes.

The relay's JSON Schema subset rejects `$comment`. The broken-only rationale
for `unreachable` and `outside_envelope` is documented beside the bundle
schema source and in the reducer brief, without emitting unsupported schema
keywords.

### 4.6 Relay Integration Bundle

Witness ships the review-owned integration bundle for `convo-relay` v1.4.0.
The bundle uses `relay-integration-bundle-v2` and implements exactly:

```text
witnessed-review/witness-falsification-v2
witnessed-review/economy-equivalence-v2
```

The same bundle serves all six v2 structural recipe variants:

```text
witness-falsify-v2
witness-falsify-v2-codex
witness-falsify-v2-claude
economy-equivalence-v2
economy-equivalence-v2-codex
economy-equivalence-v2-claude
```

The selected recipes compile with `provider_retry = forbid`, exactly four
participant turns, a fresh reducer, complete participant transcript, and a
trace-only facilitator ledger. Backend assignment changes by variant; Witness
contract semantics do not.

### 4.7 Compatibility Manifest

`review-relay-compatibility-v3` is consumer-owned and exact. Preflight checks
capabilities directly and never infers support from a semantic-version range.
At minimum it requires:

- portable export v2;
- provider invocation v2;
- integration bundle v2;
- selected contract v2;
- prompt policy v2;
- relay-root-digests-v1;
- provider result references;
- original source-artifact IDs and digests in portable payloads and refs;
- valid one-to-one invocation/result lineage; and
- the remaining declared `convo-relay` v1.4 public contracts used by the six
  v2 Witness recipes.

Preflight compiles all six v2 recipes against the exact pass bundle and binds
them to the two v2 Witness contracts above. It retains capabilities, compile
reports, backend status, recipe plans, contract digests, and compatibility
manifest digests.

A missing executable, missing structural recipe, invalid integration bundle,
unknown digest profile, missing required capability, version mismatch, or
contract-ID mismatch is a hard compatibility failure before finder or
verification model work begins.

Backend status `installed_auth_unknown` is attemptable. A runtime
authentication failure, timeout, isolation failure, reducer failure, invalid
structured output, missing provider result, invalid export, or other launch
failure routes affected findings to `pending_verification`.

---

## 5. Strict Data and Digests

Witness uses one strict JSON reader for every JSON and JSONL input surface.
Before typed decoding, it:

- requires valid UTF-8;
- performs a token walk with `json.Decoder.Token()` and `UseNumber`;
- maintains a duplicate-key set for each object scope;
- rejects escaped-equivalent duplicate keys;
- rejects trailing values and trailing garbage;
- rejects malformed nesting; and
- enforces the configured size limit.

Typed decoding then uses `DisallowUnknownFields` and requires EOF again.
Diagnostics are deterministic and typed.

Witness implements canonical JSON and all relay-root-digests-v1 digest
classes independently, checked against relay's published fixtures. It never
trusts relay-produced digest booleans. Canonical output is deterministic.

---

## 6. Charter, Freeze, and Amendments

`witness charter init` creates an owner-authorized Charter event. A review pass
loads an existing Charter; it does not silently accept a template or invent
goals.

`witness charter freeze` normalizes and hashes the Charter, including the
Operational Envelope. Every role-output document is stamped with that hash.

`witness charter amend` appends owner events. Amendments never rewrite
history. A stale Charter hash never receives an inferred reinterpretation;
findings against a stale hash become advisory with reason `stale_charter`, and
a Charter amendment requires a new pass over the amended state.

The reviewed bytes are frozen into a deterministic clean Git snapshot without
modifying the caller's tree. Witness records source identity and frozen
workspace identity separately. Dirty, unborn, non-Git, or unsupported sources
never fall back silently to an unrelated committed `HEAD`.

---

## 7. Findings and Witnesses

A finding is a claimed defect or simplification opportunity. A witness is the
concrete, checkable basis for the claim relative to one or more Charter goals
and, when present, the Operational Envelope.

Witness kind and evidence strength are separate fields.

### 7.1 Witness Kinds

| Kind | Permitted role | Meaning |
|---|---|---|
| `defect` | defect reviewer | Demonstrates that the artifact violates a Charter goal. |
| `equivalence` | economy reviewer | Demonstrates that a proposed deletion or simplification preserves every relevant Charter goal. |

### 7.2 Witness Strengths

| Strength | Form |
|---|---|
| `executable` | Structured argv and deterministic expected observation. Economy executable witnesses include a patch artifact or deterministic transformation in an isolated workspace. |
| `constructed` | A fully specified input, state, sequence, or before/after scenario that can be walked without inventing missing premises. |
| `argued` | A specific load-bearing claim and the concrete decision or behavior it would make wrong. |

An economy witness may therefore be `kind = equivalence` and `strength =
executable`, `constructed`, or `argued`.

### 7.3 Severity Caps

The model supplies `claimed_severity`. Witness derives effective severity
after schema, scope, witness, receipt, and relay rules.

| Witness strength | Maximum severity |
|---|---|
| `executable` | `critical` |
| `constructed` | `high` |
| `argued` | `medium` |
| missing or invalid | no severity; advisory |

### 7.4 Missing-Goal Questions

A reviewer that believes an unstated property matters files a missing-goal
question, not a finding. The question names the unstated property, explains
the affected decision, links to any anchor or dimension that made the absence
visible, carries no severity, and obligates no change.

Anchoring to an unspecified Operational Envelope dimension always creates a
linked missing-goal question and no obligating finding.

---

## 8. Single-Pass Procedure

A pass proceeds as follows:

1. Load the owner-authorized Charter and freeze its normalized hash; fail
   before model work when no Charter exists.
2. Freeze the exact reviewed bytes into a deterministic clean Git snapshot and
   record source and workspace identities separately.
3. Query and persist relay capabilities, backend status, compatibility
   manifest, integration bundle, recipe plans, contract digests, and compile
   reports.
4. Run exact-capability preflight with no semantic-version inference.
5. Run defect, economy, and optional goal-fit roles in fresh, isolated model
   contexts.
6. Persist raw role-output documents without adding verification fields.
7. Run `witness verification plan` to validate enough structure to avoid
   wasting verification work, apply scope/reachability/witness/severity rules,
   and emit deterministic batches of at most eight findings.
8. Execute receipt-required witnesses through `witness-harness run` in
   ephemeral frozen workspaces.
9. Execute each required verification batch once through the appropriate
   `convo-relay` v2 recipe with `provider_retry = forbid`, four participant
   turns, a fresh reducer, complete participant transcript, trace-only
   facilitator ledger, and digest-checked named inputs.
10. Export each terminal relay session as `relay-root-portable-export-v2` and
    record `convo-relay verify-export --json` as a producer-side check.
11. Run `witness verification assemble` to independently revalidate the whole
    portable closure, including non-null `provider_result_ref`, original
    source-artifact IDs and digests, one-to-one invocation/result lineage, and
    validity after relocation and source-session cleanup.
12. Run `witness adjudicate` over the original role outputs and validated
    verification manifest.
13. Append the verdict, ledger delta, advisory rendering, pending results,
    policy decisions, measured deltas, and question delta.

The pass ends after adjudication. It does not apply findings or decide to run
again.

---

## 9. Adversarial Verification

Only finder roles originate findings. The relay receives the frozen Charter, a
verification-batch document containing filed finding objects, artifact
references required by those witnesses, and no surrounding finder narrative.

The presenter represents the filed witnesses. The falsifier attempts to break
them. The reducer emits a structured result over the original ID set.

The falsifier may confirm, weaken, or break a witness. It may not add a
finding. Extra observations remain transcript trace and are excluded from the
canonical result.

For the economy contract, the falsifier's burden is to identify a Charter goal
that fails after the proposed removal or simplification.

Participant turn requirements:

1. Presenter filing pass: enumerate every supplied ID and state each claim and
   witness exactly as filed.
2. Falsifier attack pass: attack every supplied ID and provide a concrete
   counter-witness for any claimed weakening or breakage.
3. Presenter defense pass: defend only with material already present in the
   filed witness, deterministic batch, Charter, bound artifact inputs, or
   immutable refs cited by those inputs.
4. Falsifier final pass: state the strongest remaining attack for every ID and
   identify presenter strengthening the reducer must ignore.

The fresh reducer classifies only supplied IDs, evaluates the witness as
filed, ignores uncited strengthening, emits exactly one JSON result, does not
use the ordinary relay ledger as the result, and does not claim provider tool
activity as trusted execution.

A valid relay method references an export whose portable closure verifies:

- execution kind is recipe;
- portable-export schema and digest-profile IDs match the compatibility
  manifest;
- manifest digest and complete payload inventory recompute;
- recipe ID and digest match the plan;
- root-plan version, digest, and effective `provider_retry = forbid` match;
- integration-bundle ID and digest match the pass copy;
- selected integration-contract ID and digest match the recipe and plan;
- prompt policy and prompt-context projection match complete participant
  transcript and trace-only facilitator ledger;
- runtime snapshot and root-plan refs match the compile report;
- Charter, findings, and artifact named-input digests match the plan;
- participant-turn count is four;
- every declared participant, facilitator, and reducer invocation has exactly
  one invocation record, one non-null provider result ref, and valid lineage;
- no trace-only facilitator ledger appears in a later participant or reducer
  rendered prompt;
- workspace isolation records make no unsupported containment claim and bind
  the expected frozen workspace base;
- result validation is valid;
- result schema version is `relay-witness-verdicts-v2`;
- result covers planned finding IDs exactly;
- each result witness digest matches the planned witness;
- result and referenced artifact digests recompute correctly; and
- the export remains valid after relocation and source-session cleanup.

Witness never scrapes the last participant response, treats the facilitator
ledger as a witness result, or asks relay to map output into review severity,
disposition, or application class.

---

## 10. Execution Receipts and Harness

A model statement such as "I ran the test" has no verification authority.
Executable strength is retained for threshold findings only through a valid
`review-execution-receipt-v2` receipt from `witness-harness run`.

`witness-harness run`:

- accepts structured argv only;
- runs in an ephemeral workspace based on the frozen source snapshot;
- reports filesystem, network, and process containment truthfully;
- never claims a stronger sandbox than the host can prove;
- records source and workspace inventories before and after execution;
- captures stdout, stderr, and produced artifacts by digest;
- binds transformation refs and resulting workspace digests when a witness
  requires a patch or deterministic transformation;
- records expected and observed outcomes; and
- authenticates the complete `review-execution-receipt-v2` record through a
  caller-verifiable mechanism.

Witness validates issuer authority and authenticity, recomputes every
referenced digest, checks pass and frozen-snapshot lineage, verifies the
harness executable or build identity and active policy, validates environment
and resource declarations, compares inventories, and evaluates expected
observations against captured outputs.

A missing or invalid receipt removes executable-strength credit but does not
prove failure. A valid receipt whose observation contradicts the filed
expectation deterministically breaks the witness during verification assembly.

---

## 11. Review-State Files

`review-verification-manifest-v3` is assembled by Witness from validated relay
exports and trusted receipts. Model output never authors it. The manifest
records the plan digest, Charter hash, artifact digest, compatibility
manifest, relay capabilities, integration bundle, selected contracts, each
batch ref and digest, each portable export ref and digest, each canonical
result digest, and every execution-receipt ref and digest.

Each manifest record has status `valid`, `failed`, `unavailable`, or
`not-required`. Relay verdicts are present only when relay verification is
valid. Execution status is `satisfied`, `contradicted`, `failed`,
`unavailable`, or `not-required`. Contradictory execution is valid evidence
that verification assembly uses to break the witness; failed or unavailable
execution only removes executable-strength credit.

Per review target:

```text
<review-root>/
├── charter.json
├── ledger.jsonl
├── pending-goal-questions.jsonl
├── advisory.md
└── passes/<n>/
    ├── artifact-manifest.json
    ├── charter.json
    ├── defect-output.json
    ├── economy-output.json
    ├── goal-fit-output.json                 # optional
    ├── verification-plan.json
    ├── verification/
    │   ├── compatibility-manifest.json
    │   ├── relay-capabilities.json
    │   ├── integration-bundle.json
    │   ├── backend-status.json
    │   ├── compile-reports/
    │   │   └── <recipe-id>.json
    │   ├── index.json                       # review-verification-manifest-v3
    │   ├── batches/
    │   │   └── <role>-batch-<n>.json        # verification-batch document
    │   ├── run-results/
    │   │   └── <role>-batch-<n>.json        # run-result document
    │   ├── sessions/
    │   │   └── <role>-batch-<n>/            # complete portable export
    │   │       ├── manifest.json
    │   │       └── payloads/
    │   ├── receipts/
    │   │   └── <finding-id>.json
    │   └── artifacts/
    │       ├── stdout/
    │       ├── stderr/
    │       ├── patches/
    │       └── inventory/
    ├── ledger-delta.jsonl
    └── verdict.json
```

`<review-root>` should be outside the source tree. If colocated, the state
directory is explicitly excluded from source-artifact digests.

`verdict.json` includes rules version, policy version, Charter hash, artifact
digest, compatibility-manifest digest, relay-capability digest,
integration-bundle digest, relay export schema version, relay digest profile,
admitted count, automatic-candidate count, caller-decision count, advisory
count, pending-verification count, unverified-high count,
pending-goal-question count, verification variant, verification batches,
backend authentication status at launch, cap-release mismatch flag, and
consumer identity.

---

## 12. Mechanical Adjudication

`review-rules-v2` defines the following order and reasons. A rules release may
lower caps or add advisory reasons only through a new rules version.

The adjudicator is a filter and classifier. It does not decide whether a
well-formed claim is intellectually persuasive; the witness, receipt, and
relay verifier supply bounded evidence.

Adjudication order is fixed:

1. Validate Charter, role, goal, scope, witness, and recurrence lineage.
2. For threshold executable witnesses, apply receipt rules: a satisfying
   receipt preserves executable strength; missing or invalid execution credit
   starts at constructed; a valid contradictory receipt breaks the witness.
3. Apply the strength-based severity cap.
4. If required relay verification is unavailable or invalid, preserve severity
   as `pending_verification`.
5. Apply relay results: `survived` retains current strength; `weakened`
   downgrades one step, reapplies the cap, and uses
   `witness_weakened_below_floor` if no strength remains; `broken` is
   advisory.
6. Assign application class independently from disposition.

Every finding ends in one disposition:

- `admitted`;
- `advisory`;
- `pending_verification`; or
- `owner_override`.

Every finding also receives one application class:

- `automatic_candidate`;
- `caller_decision`; or
- `none`.

Application class is derived from effective severity, verification state,
role, remedy direction, measured or estimated delta status, Operational
Envelope status, and policy. Pending findings are never automatic. Advisory
findings default to `none` unless an explicit owner override changes the
class.

Exact duplicate handling uses deterministic finding keys and witness digests.
A recurrence carries prior unresolved admitted, automatic-candidate,
caller-decision, or pending effect forward when Charter hash, artifact digest,
finding key, and witness digest match and no current-artifact resolution event
exists. A prior advisory state may carry forward only with its original reason
and lineage. Changed artifact bytes without a bound resolution record require
reconsideration.

---

## 13. Policy

`review-policy-v2` defines bootstrap policy, cap-release validation, and
application checks.

Default bootstrap policy:

- `defect_additive_auto_apply_enabled = false`;
- production and test caps are unset;
- unknown delta prevents additive defect automation;
- an over-cap estimate prevents additive defect automation;
- a missing Operational Envelope prevents additive defect automation;
- nonpositive remedies consume no positive cap allowance;
- estimated delta can only disqualify automation, never authorize application;
  and
- every automatic application still requires caller-measured production and
  test delta to pass `witness policy check-application`.

Policy loading fails closed when additive automation is enabled without both
positive caps and a matching append-only cap-release record.

A cap-release record includes:

- unit;
- production cap;
- test cap;
- basis, either `measured_history` or `explicit_owner_judgment`;
- evidence or rationale;
- actor;
- policy digest;
- rules digest; and
- `charter_hash`.

A later Charter-hash mismatch does not revoke released caps. `witness policy
show`, verdict metadata, and metrics flag `cap_release_charter_mismatch` until
the owner re-releases caps.

Owner overrides are explicit ledger events. `witness ledger promote` may
promote an advisory item. `witness ledger accept-unverified` may record that
an owner or authorized caller acting under explicit owner delegation accepts a
pending risk. Overrides do not rewrite history or claim that verification
occurred.

---

## 14. Ledger and Metrics

Witness appends every finding, question, pending result, owner override, cap
release, measured delta, and policy decision to durable lineage.

Ledger events include the normalized finding payload, finding key, witness
digest, Charter and artifact digests, scope anchors, reachability status,
preverification and effective severity, verification methods, validated
portable relay-export ref and digest profile, relay capability and
compatibility-manifest digests, integration-bundle and selected-contract
digests, root-plan and provider-invocation digests, provider-result refs,
workspace-base and isolation-report digests, execution-receipt ref,
disposition, reason, application class, rules version, policy version,
consumer identity, backend/model/CLI metadata, cap-release lineage, and owner
override lineage.

Metrics are stratified by consumer, role, recipe variant, integration-bundle
and contract digest, compatibility-manifest version, portable-export version,
digest-profile version, backend CLI version, backend authentication status at
launch, requested and reported model, effort, artifact type, rules version,
and policy version.

Metrics include:

- advisory-promotion rate by reason;
- net-size trend using measured deltas, with estimated deltas tracked
  separately;
- survived, weakened, broken, invalid-result, and contradiction rates by
  verdict class;
- paired variant accuracy on matched frozen witness sets;
- later execution confirmation or refutation of constructed and argued
  witnesses;
- pending-verification rate stratified by backend authentication status at
  launch;
- Operational Envelope question and promotion metrics;
- cap-release Charter mismatch counts;
- estimated-versus-measured production and test deltas; and
- batch-size reliability by invalid-result rate, omitted-ID attempts,
  latency, and token usage.

---

## 15. Usage

### 15.1 Standalone

Run one pass, inspect `verdict.json`, `advisory.md`, pending questions,
pending verification, and policy decisions, then apply or override findings
outside Witness.

### 15.2 External Automation

A caller that wants automation should:

1. apply only findings whose application class is `automatic_candidate` and
   whose policy check returned allow;
2. record measured production and test deltas;
3. rerun review against the new artifact state when desired;
4. treat pending required verification as non-clean unless an explicit owner
   policy accepts it; and
5. decide its own stopping condition outside Witness.

Medium and low admitted findings remain available as `caller_decision` items
under the default policy.

### 15.3 Blocking Entry Point

An explicit blocking procedure may pause to ask pending goal questions, offer
advisory promotion, or request acceptance of pending verification risk. The
CLI and file formats are unchanged. Blocking is a caller procedure, not a
hidden Witness state.

---

## 16. What Witness Never Does

- It never owns a surrounding workflow loop.
- It never schedules or silently retries model work.
- It never modifies the source artifact during review or verification.
- It never applies findings or patches.
- It never accepts a model-authored claim that a command ran.
- It never accepts a relay run-result document, live relay-home ref,
  incomplete export, unknown digest profile, or relay digest boolean as
  durable verification evidence.
- It never amends the Charter without an owner event.
- It never deletes a finding or question from history.
- It never treats verification failure as a weaker verified finding.
- It never lets a falsifier originate a finding.
- It never equates the ordinary relay ledger with the witness result.
- It never allows trace-only facilitator-ledger content into later witness
  participant or reducer prompts.
- It never treats `context_only`, an ephemeral worktree, or provider metadata
  as a command-execution receipt or security boundary.
- It never automatically applies admitted medium or low findings.
- It never treats additive defect remedies as automatic when the Operational
  Envelope is missing.
- It never claims deterministic semantic deduplication beyond documented
  fingerprint rules.
- It never relies on review-specific code, prompts, schemas, or validators in
  `convo-relay`.

---

## 17. Test and Acceptance Plan

Strict JSON fixtures, one fixture per equivalence class:

- valid nesting;
- root duplicate key;
- nested duplicate key;
- escaped-equivalent duplicate key;
- trailing value;
- trailing garbage;
- invalid UTF-8;
- unknown field; and
- size limit.

Charter tables:

- absent Operational Envelope;
- each dimension state;
- bounded reference validity;
- unbounded concrete-value anchoring;
- unspecified-to-question routing; and
- no Cartesian state matrix.

Reducer contract tests:

- exact ID and digest coverage;
- `verdict_class` null on survived;
- counter-witness requirements;
- broken-only `unreachable` and `outside_envelope` classes;
- weakening limited to partial logical or premise failure;
- rejection of execution-attestation fields; and
- no unsupported `$comment` keyword emitted in relay schemas.

Adjudication tables:

- one case per branch and reason;
- weakened with strength remaining;
- weakened below floor;
- threshold executable with satisfying receipt;
- threshold executable with missing receipt starting at constructed;
- threshold executable with valid contradictory receipt breaking the witness;
- required relay unavailable preserving `pending_verification`;
- survived retaining strength;
- broken routing to advisory; and
- executable to no receipt to constructed to relay weakened to argued to
  medium cap to `caller_decision`.

Policy tables:

- bootstrap state;
- enabled-with-missing-cap rejection;
- enabled-with-zero-cap rejection;
- valid cap release;
- unknown delta routing;
- over-cap routing;
- no-envelope additive block;
- measured-delta refusal; and
- Charter mismatch warning without revocation.

Portable verification:

- one tamper case per signed relationship;
- provider-result lineage tamper;
- source-artifact ID tamper;
- source-artifact digest tamper;
- successful relocation; and
- successful validation after source-session deletion.

End-to-end fake-provider passes cover mixed, Codex-only, and Claude-only
recipe families. Live model calls remain optional smoke tests, not CI
requirements.

Run:

```text
go test ./...
go vet ./...
```

Do not create recursive impossible-state tests or Cartesian combinations
without evidence of interaction.

---

## 18. Assumptions

- `convo-relay` v1.4.0 is the minimum supported relay generation.
- Witness uses only the six v2 Witness recipes supplied by that relay
  generation.
- There is no deployed Witness state requiring migration from older draft
  schemas.
- Reviewed sources and finding remedies are never mutated or applied by
  Witness.
- Existing hidden files, IDE state, `.DS_Store`, and unrelated dirty worktree
  changes remain untouched.

---

## 19. Delta Change-Surface Addendum

Witness change-surface review is a first-class pass input, not a Charter
amendment. A delta-scoped pass records a `witness-change-surface-v1` document
with `base_artifact_digest`, `head_artifact_digest`, and a sorted
`changed_paths` set. Each changed path carries one or more change kinds from
`added`, `modified`, `removed`, and `mode_changed`. Witness derives this
document only by comparing two `witness-source-snapshot-v1` freeze manifests;
caller-supplied changed-path lists are not valid input. The derived change
surface is canonical JSON under the normal digest profile and is stored in pass
state under its own digest.

`witness-verification-plan-v2` records the standing scope policy, the derived
change surface, its digest, or an explicit `baseline_pass` marker. Assembly
promotes those fields into `review-verification-manifest-v4`, so adjudication
uses the same pass input that planning used. The head freeze manifest digest
must equal the authoritative preflight snapshot digest for the pass; mismatch
fails closed before a plan is produced.

Standing scope policy lives in `review-policy-v3` as `scope_policy`, with
values `delta_obligating` and `whole_tree`. Omitted scope policy and
`whole_tree` preserve existing whole-tree behavior. `delta_obligating` requires
either a derived change surface or an explicit `baseline_pass` marker. The
marker records a whole-tree baseline pass on purpose and is visible in plan and
manifest outputs; there is no silent fallback from delta scope to whole-tree
scope.

`review-rules-v3` adds the `change_surface_scope` adjudication step and
declares `out_of_delta` as an advisory reason. A finding is in delta iff at
least one scope anchor or witness artifact reference resolves exactly to a
changed path; removed paths count as changed. Findings with global/component
loci or no overlap are routed, not erased: planning records them as advisory
excluded findings with `application_class: caller_decision`, and adjudication
emits them as advisory/caller-decision verdicts with reason `out_of_delta`.

---

## 20. Relay-Absent Degraded-Mode Addendum

Relay-absent degraded mode is triggered automatically only when the configured
relay executable cannot be launched and the relay client reports
`relay_missing`. No CLI flag enables degraded mode, and other relay command
failures remain normal blocking preflight diagnostics.

A relay-absent preflight remains manifest-shaped. It writes retained
capabilities, backend-status, recipes-list, compile-report, contract-digest,
integration-bundle, and compatibility artifacts. Required backend strata are
recorded as `relay_absent`, required capabilities are explicitly recorded as
unavailable, compile reports use status `relay_absent`, and no recipe-plan
digest is claimed. The integration bundle and selected contract digests remain
strictly bound; an invalid or missing bundle still fails preflight.

Assembly carries the degraded launch status into the verification manifest's
existing consumer identity fields, including per-batch relay metadata, and
records relay batches as `unavailable`. Adjudication still validates the
verification manifest unconditionally. Findings that require relay evidence in
a relay-absent pass use the existing `pending_verification` disposition and do
not introduce a new disposition kind.

Pending-verification metrics distinguish bootstrap relay absence from normal
backend authentication strata by reporting a `relay_absent` stratum when the
loaded preflight recorded relay absence.

Version impact: `witness-adjudication-run-result-v2` adds
`summary.fixpoint_eligible`. It is false whenever any finding remains admitted,
advisory, pending verification, automatic candidate, or caller decision.
Historical `witness-adjudication-run-result-v1` inputs remain accepted by the
metrics reader.

---

## 21. Pass Driver and Charter Bootstrap Addendum

`witness pass begin` and `witness pass resume` provide the deterministic pass
driver CLI surface. The driver sequences only deterministic Witness stages:
Charter/source freeze, preflight, planning after caller-produced role outputs,
assembly after caller-produced relay evidence when required, adjudication, and
metrics. It never calls models, never launches relay verification batches,
never applies findings, and owns no iteration or convergence loop.

The driver persists `witness-pass-state-v2` as canonical JSON under the pass
state directory. The state document records completed stages, exact input and
output artifact paths and digests, relay batch evidence locations when batches
exist, the next action, and a `state_digest` computed over the state document
with `state_digest` blank. Every resume verifies the state digest and all
recorded artifact digests before advancing; drift fails closed with a typed
diagnostic.

After each invocation the driver writes a canonical
`witness-pass-next-action-v2` JSON document to stdout and a concise human
summary to stderr. The next action is either the next `witness pass resume`
command, a caller instruction to produce role outputs for named roles at the
recorded snapshot digest into recorded paths, a caller instruction to run one
relay batch with the recorded recipe and portable-export directory, or
`complete`. Relay-absent degraded passes keep the existing degraded preflight,
manifest, adjudication, and metrics behavior; the driver reports the degraded
backend strata and skips relay-batch caller actions when relay evidence is not
required.

`witness charter init -template` adds embedded owner-editable template data:
`minimal`, `delta-review`, and `whole-tree-audit`. Templates emit ordinary
`review-charter-v2` documents and do not add freezing, hashing, or judgment
semantics.

Version impact: one new persisted surface,
`witness-pass-state-v2`, and one driver invocation output surface,
`witness-pass-next-action-v2`. Existing Charter, freeze, preflight, plan,
manifest, adjudication, metrics, receipt, pending, DELTA1, and DEGRADE1
surfaces are not bumped.

### Pass Next-Action v2 Addendum

`caller_role_outputs` actions in `witness-pass-next-action-v2` always carry
`scope_policy` as `delta_obligating` or `whole_tree`. For delta-obligating
passes with a derived change surface, the action also carries
`change_surface_path` and `change_surface_digest`; whole-tree and explicit
baseline-pass actions omit those two fields.

The early change-surface document is advisory transport for the caller. The
driver persists it as a preflight-stage output and revalidates it on resume by
rederiving from the configured base manifest and authoritative head snapshot,
but planning, assembly, and adjudication continue to derive from the
authoritative manifests and never read the early document as input.
