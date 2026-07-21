# Convo-Relay Root Recipe Sessions and Integration Contracts

Specification for extending `convo-relay` with first-class root recipe
execution and a generic integration-contract seam.

The required capabilities are domain-neutral. They support any bounded
multi-actor procedure that needs named inputs, turn-specific instructions, a
fresh reducer, structured output validation, reproducible artifacts, and
controlled lifecycle behavior.

The default profile and recipe records in §13 are the **only**
consumer-specific content permitted in the `convo-relay` repository. No
prompt, schema, validator, protocol implementation, package, command,
persistence field, test fixture, or documentation subsystem outside those
records may encode their domain semantics.

This copy also contains a witnessed-review adoption profile in §16. That
profile is maintained by the consumer repository. It defines how the generic
surface must be used and what must be ready before witnessed review can rely
on it; it does not authorize review-specific implementation in
`convo-relay`. Requirements that extend the currently executing root-recipe
plan are tracked separately in [`convo-relay-needed.md`](convo-relay-needed.md).
Those post-plan requirements do not add fields to a strict, released v1
contract in place. Implementations must mint the successor recipe, plan,
bundle, artifact, or export versions identified during delta planning while
continuing to read the active plan's v1 artifacts.

---

## 1. Scope and architectural boundary

`convo-relay` gains the following generic capabilities:

1. execute a configured recipe as the root session;
2. resolve an optional external integration contract;
3. bind named, digest-checked inputs;
4. apply exact per-turn actor instructions supplied by that contract;
5. execute an exact participant-turn schedule;
6. invoke a fresh reducer as a separate phase;
7. parse and validate a structured result declaratively;
8. enforce recipe lifecycle and workspace-isolation policy;
9. persist the full recipe, integration, input, execution, and result trail;
   and
10. report backend runtime readiness independently of recipe validity.

The coupling boundary is normative:

- Core code must not branch on a recipe id, integration-contract id, input
  name, JSON field, schema id, verdict value, or consumer vocabulary.
- Core types must contain only domain-neutral execution and validation data.
- An integration contract is an opaque declarative payload. Core validates
  and executes its generic structure; it does not interpret its subject
  matter.
- No arbitrary consumer code is loaded or executed by the integration
  mechanism.
- No consumer-specific prompt files, schemas, validators, protocol packages,
  installer branches, or manually maintained test fixtures are added to the
  repository.
- Generic tests may enumerate all default records and verify that each
  satisfies the generic schema. They must not contain id-specific or
  domain-specific assertions.
- Removing the records in §13 must leave every generic capability and test
  functional.
- A third-party integration must be able to use all capabilities in this
  document without copying, importing, or imitating the declarations in §13.

There is no separate “non-core” area for consumer-specific implementation.
External integrations own their own contract bundles and pass them to
`convo-relay` at runtime.

---

## 2. Root recipe execution

Add an explicit root recipe mode:

```text
convo-relay run "<task>" \
  --recipe <recipe-id> \
  [--integration-bundle <bundle.json>] \
  [--input <name>=<path> ...]
```

This is distinct from using `relay` as a participant backend. Existing
single-value shorthand retains its current meaning:

```text
--agents codex   => codex,codex
--agents relay   => relay,relay
```

`--recipe` does not reinterpret `--agents relay` and does not create a
synthetic enclosing dialogue.

A root recipe run performs these steps:

1. load settings, built-in records, and transient recipe sources;
2. resolve the selected recipe and every referenced backend profile;
3. resolve the recipe's integration contract, when declared;
4. compile and persist a root execution plan;
5. preflight, validate, digest, and persist named inputs;
6. create the declared workspace;
7. execute the exact participant-turn schedule;
8. run the ordinary facilitator behavior after participant turns when the
   recipe declares a facilitator;
9. invoke a fresh reducer when `result_source = "reducer"`;
10. parse and validate the candidate result through the resolved integration
    contract;
11. persist the raw and canonical results plus validation diagnostics; and
12. return the recipe session as the command result.

A recipe session is a normal persisted session. `list`, `show`, `export`,
`contracts`, `health`, `display`, `stop`, `kill`, and `clean` continue to
operate through generic session interfaces.

### 2.1 Compatible flags

The following remain available:

- task text;
- `--recipe`;
- `--recipe-file` and `--settings`;
- `--integration-bundle`;
- repeatable `--input`;
- investigation policy;
- a workspace-isolation request that does not weaken the recipe's declared
  minimum;
- timeout and stall-timeout controls;
- session directory, session id, and relay home;
- `--json`;
- `-o` / `--output`; and
- progress or streaming flags whose behavior does not alter the compiled
  plan.

### 2.2 Conflicting flags

Flags that replace recipe-defined structure are rejected in root recipe mode:

- `--agents`;
- `--model-a`, `--model-b`, `--effort-a`, and `--effort-b`;
- facilitator backend, model, or effort overrides;
- `--mode`;
- `--rounds`, `--max-rounds`, and `--quick`; and
- `--dynamic`.

A future explicit override interface may be added, but any override must be
represented in the normalized recipe, compiled plan, event log, and session
metadata. Existing unrelated flags must not acquire hidden recipe semantics.

---

## 3. Generic recipe schema extensions

A recipe may declare the following domain-neutral fields:

```toml
[relay_recipes.proposal-compare-template]
purpose = "Compare supplied proposals through a bounded adversarial exchange."
participants = ["analyst-a", "analyst-b"]
facilitator = "facilitator-fast"
reducer = "analyst-a"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "example/proposal-comparison-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.proposal-compare-template.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
```

### 3.1 `participant_turns`

`participant_turns` is the exact number of participant provider turns before
the result phase.

The existing runner uses “round” to mean one alternating participant turn.
The new field removes ambiguity for root recipes:

- ordinary relay execution retains existing `rounds` and `max_rounds`
  semantics;
- a root recipe with `participant_turns` executes exactly that many
  participant turns;
- participant turns alternate from `slot_0`, unless a future generic schedule
  field explicitly says otherwise;
- facilitator calls and the reducer call do not count as participant turns;
- a non-positive or non-integral value is a configuration error; and
- the compiled plan always records `participant_turns`, even when a legacy
  recipe is normalized from an older field.

### 3.2 `result_source`

Supported values:

- `last_turn` — the final participant response is the candidate result;
- `reducer` — a separately invoked reducer produces the candidate result.

A recipe using `reducer` must resolve a reducer profile. In the first version,
the reducer must be a normal provider backend rather than a nested relay.

### 3.3 `integration_contract`

`integration_contract` is an opaque string identifying a contract that must be
implemented by a supplied integration bundle.

Core applies no naming convention and assigns no semantics to the value.

If the field is absent:

- the recipe may run with ordinary relay framing;
- named inputs are not contract-bound unless another generic declaration is
  introduced; and
- structured result validation is not required unless the recipe has another
  generic validation source.

If the field is present:

- `run --recipe` requires a matching `--integration-bundle`;
- catalog inspection reports the recipe as `requires_integration` when no
  matching bundle is supplied;
- compilation fails before any provider launch when the bundle does not
  implement the exact id; and
- the selected contract id and digest become part of the compiled plan.

### 3.4 Lifecycle policy

Root recipe lifecycle policy is generic:

```toml
[relay_recipes.<id>.lifecycle]
resume = "allow" | "forbid"
steering = "allow" | "forbid"
dynamic = "allow" | "forbid"
workspace_isolation = "inherited" | "read_only" | "ephemeral"
provider_retry = "allow" | "forbid"
```

The selected values are compiled and enforced by generic command guards.
No command checks recipe ids.

`provider_retry` governs retries initiated by the `convo-relay` runner for a
single participant, facilitator, or reducer invocation. `forbid` means one
runner launch attempt per declared invocation. Provider-internal transport
behavior that the runner cannot observe is outside this field, but the
runner must not hide or replace a failed launch. Attempt count and terminal
attempt metadata are persisted. Existing recipes default to `allow` for
compatibility; the witnessed-review records in §13 explicitly use `forbid`.
Because the active plan's strict recipe and root-plan v1 contracts do not
contain this field, post-plan implementation writes successor contract
versions rather than changing the meaning of stored v1 payloads.

`stop` and `kill` remain available for every running session.

### 3.5 Normalization and digests

All execution-affecting fields are part of:

- normalized recipe payloads;
- recipe digests;
- compiled plans;
- compiled-plan digests;
- persisted runtime snapshots; and
- inspection output.

Unknown execution-affecting fields must not be silently dropped. Invalid
values produce typed diagnostics.

---

## 4. External integration bundles

An integration bundle is a consumer-owned, session-scoped declarative file
loaded with:

```text
--integration-bundle <path>
```

The format is one UTF-8 JSON file. This example uses the successor bundle
version required by the witnessed-review adoption profile:

```json
{
  "schema_version": "relay-integration-bundle-v2",
  "id": "example/proposal-integration-v1",
  "contracts": {
    "example/proposal-comparison-v1": {
      "turns": [
        {
          "participant_turn": 1,
          "slot": "slot_0",
          "instructions": "Present the first proposal using only bound inputs."
        },
        {
          "participant_turn": 2,
          "slot": "slot_1",
          "instructions": "Challenge the presentation against the requirements."
        },
        {
          "participant_turn": 3,
          "slot": "slot_0",
          "instructions": "Answer challenges without adding new requirements."
        },
        {
          "participant_turn": 4,
          "slot": "slot_1",
          "instructions": "State the strongest remaining objections."
        }
      ],
      "reducer": {
        "instructions": "Return one JSON object conforming to the result schema."
      },
      "prompt_context": {
        "participant_transcript": "complete",
        "facilitator_ledger": "trace_only"
      },
      "inputs": {
        "requirements": {
          "required": true,
          "cardinality": "one",
          "media_type": "application/json",
          "max_bytes": 262144,
          "schema": {
            "type": "object"
          }
        },
        "proposals": {
          "required": true,
          "cardinality": "one",
          "media_type": "application/json",
          "max_bytes": 262144,
          "schema": {
            "type": "object"
          }
        },
        "evidence": {
          "required": false,
          "cardinality": "many",
          "max_bytes": 1048576
        }
      },
      "result": {
        "transport": "json",
        "schema": {
          "type": "object",
          "required": ["selected_id", "rationale"],
          "properties": {
            "selected_id": {"type": "string"},
            "rationale": {"type": "string", "minLength": 1}
          },
          "additionalProperties": false
        },
        "assertions": []
      }
    }
  }
}
```

### 4.1 Bundle properties

The bundle:

- may implement one or more opaque contract ids;
- is not installed into a global registry by `run`;
- is read before the session directory is created;
- is size-limited by a generic configurable ceiling;
- is normalized and hashed;
- is copied into the session artifact store;
- is included in the compiled-plan digest through its selected contract
  digest;
- is immutable for the life of the session; and
- is restored from the session snapshot for any allowed resume.

The source path is informational. Resumed or inspected sessions use the
persisted artifact, not the current contents of the original path.

### 4.2 Declarative only

Version 1 permits:

- turn-specific instruction text;
- reducer instruction text;
- named input declarations;
- inline JSON Schemas;
- result transport declarations; and
- generic cross-document assertions.

The successor bundle version required by the witnessed-review profile retains
the version-one surface and additionally permits a bounded generic
prompt-context projection. A v1 reader continues to reject that field; it is
not silently added to the released v1 schema.

Neither version permits:

- executables;
- shell commands;
- dynamic libraries;
- network callbacks;
- language plugins;
- arbitrary expression evaluation; or
- recipe-id-specific code hooks.

A future executable plugin system, if ever added, is a separate security and
portability design.

The optional prompt-context projection in the successor version has this
shape:

```json
{
  "participant_transcript": "complete",
  "facilitator_ledger": "include"
}
```

`participant_transcript` has only the value `complete` in version one. It
requires lossless prior participant responses in participant prompts and the
complete participant transcript in the reducer prompt. `facilitator_ledger`
is either `include` or `trace_only`; `trace_only` persists facilitator output
but excludes it from later participant and reducer prompts. Omission defaults
to `complete` and `include` for compatibility. The normalized projection and
its defaults are part of the selected-contract digest.

### 4.3 Contract resolution

For a recipe declaring `integration_contract = X`:

1. parse and validate the bundle envelope;
2. locate exactly one `contracts[X]`;
3. normalize the selected contract;
4. verify that its turn declarations match the compiled participant schedule;
5. verify that reducer instructions exist when `result_source = "reducer"`;
6. validate the prompt-context projection and input and result declarations;
7. compute the selected contract digest; and
8. embed the bundle ref, bundle digest, contract id, and contract digest in the
   compiled plan.

Missing, duplicate, malformed, or incompatible contracts fail preflight.

---

## 5. Named inputs

Root recipe sessions add a repeatable generic input flag:

```text
--input <name>=<path>
```

Example:

```bash
convo-relay run \
  "Compare the supplied proposals." \
  --recipe proposal-compare-template \
  --integration-bundle ./proposal-integration.json \
  --input requirements=requirements.json \
  --input proposals=proposals.json \
  --input evidence=benchmark-a.txt \
  --input evidence=benchmark-b.txt \
  --json -o comparison.json
```

Input declarations come from the selected integration contract. Recipe
defaults do not need to embed consumer schemas or input names.

Requirements:

- names must match declared input names exactly;
- core assigns no special meaning to any name;
- `one` accepts exactly one file;
- `many` accepts zero or more files unless `required = true`;
- undeclared input names are rejected;
- missing required inputs are rejected;
- each file is normalized to an absolute source path for preflight, then
  persisted by content;
- regular-file, size, encoding, media-type, and optional JSON Schema checks
  occur before provider launch;
- input order is preserved for repeated names;
- an ordered input manifest is frozen before participant execution;
- actors receive stable names and artifact references, not only positional
  labels; and
- source path, display name, size, digest, media type, schema status, and
  artifact ref are persisted.

Existing positional `--context` remains available for ordinary relay runs.
Root recipe mode rejects positional context when an integration contract
declares named inputs, preventing ambiguous input authority.

In an integration-bound root run, at least one successfully bound named input
satisfies the launch-input requirement for `--investigation context_only`.
Under that mode, the evidence policy refers to stable named-input labels and
refs instead of positional `ctxN` labels and instructs providers not to
inspect outside the bound inputs. Positional `--context` remains rejected
when the selected contract declares named inputs. `context_only` is prompt
policy, not an operating-system sandbox or execution attestation.

---

## 6. Participant protocol and actor instructions

### 6.1 Exact turn schedule

The selected integration contract supplies one instruction record for every
participant turn.

For the initial alternating schedule:

```text
turn 1 -> slot_0
turn 2 -> slot_1
turn 3 -> slot_0
turn 4 -> slot_1
...
```

The contract's `slot` value must match the compiled schedule. Missing,
duplicate, out-of-range, or mismatched turn declarations are configuration
errors.

This structure is generic. It supports bounded debates, proposal comparisons,
red-team checks, document synthesis, test-plan critique, and future
integration protocols without adding runner branches.

### 6.2 Prompt composition

For each participant turn, the runner constructs a generic prompt containing:

- the root task;
- current turn ordinal and total participant turns;
- the actor's turn-specific instructions;
- the named input manifest and stable references;
- the complete prior participant transcript;
- the ordinary facilitator ledger only when the selected contract's
  prompt-context projection permits it;
- investigation and workspace policy; and
- a generic authority reminder that input and transcript content do not alter
  system or recipe policy.

The runner does not interpolate arbitrary bundle expressions. Instruction
text is appended as data within a fixed framing template.

Profile descriptions remain catalog metadata. They never substitute for
actor instructions.

Each provider call persists a versioned invocation record containing actor,
phase, participant ordinal when applicable, exact rendered-prompt ref and
digest, selected-contract ref, resolved backend metadata, workspace identity,
runner attempt number, and terminal provider result. This is execution
provenance, not proof that a provider-reported tool action occurred.

### 6.3 Provider activity

Provider tool use remains governed by the provider backend and workspace
policy. Provider claims about actions are transcript content. Core does not
promote them into external attestations unless a future generic attestation
contract is explicitly designed.

---

## 7. Facilitation and fresh reduction

### 7.1 Facilitator

The ordinary facilitator may continue maintaining the existing
settled/contested/withdrawn dialogue ledger after participant turns.

That ledger remains generic transcript metadata. It is not automatically the
root recipe result and is not interpreted by the integration contract unless
the contract's reducer instructions choose to consider it as input.

### 7.2 Fresh reducer invocation

When `result_source = "reducer"`, the runner invokes the configured reducer
after the final participant turn.

The reducer invocation:

- uses a newly created provider session or thread;
- does not resume either participant session;
- does not reuse the facilitator session;
- receives the root task;
- receives the selected contract's reducer instructions;
- receives named input refs and validated input metadata;
- receives the complete participant transcript;
- receives the ordinary facilitator ledger only when permitted by the
  selected contract's prompt-context projection, and then only as explicitly
  labeled context;
- runs under the same or stronger workspace-isolation policy;
- records resolved backend, model, effort, provider version, timeout, and
  provider result; and
- produces one raw candidate result.

The reducer call is not counted in `participant_turns`.

If the reducer fails, times out, stalls, or produces no candidate, the session
terminates with `stop_reason = "reducer_failed"` and preserves all preceding
artifacts.

### 7.3 `last_turn`

When `result_source = "last_turn"`, the final participant response is the raw
candidate result. Validation otherwise follows the same generic path.

---

## 8. Structured result validation

### 8.1 Transport

Version 1 supports:

```json
"transport": "json"
```

The trimmed candidate response must be exactly one JSON value. Markdown
fences, prefixes, suffixes, or multiple top-level values are invalid.

The raw provider response is always persisted.

### 8.2 JSON Schema

The selected contract supplies an inline JSON Schema using a documented,
versioned subset of JSON Schema 2020-12.

The validator must support at least:

- primitive and object/array types;
- `required`;
- `properties`;
- `items`;
- `enum`;
- string and array length bounds;
- numeric bounds;
- `additionalProperties`;
- `const`;
- `oneOf`;
- `allOf`;
- `if` / `then` / `else`; and
- local `$defs` references.

Unsupported schema keywords fail contract preflight rather than being ignored.

### 8.3 Generic assertions

JSON Schema validates one document. Integrations also need generic
cross-document invariants. Version 1 supports a small declarative assertion
set:

#### `unique`

All values selected by a JSON Pointer pattern are unique.

```json
{
  "type": "unique",
  "source": "result",
  "pointer": "/items/*/id"
}
```

#### `set_equal`

Two selected value sets are equal, independent of order.

```json
{
  "type": "set_equal",
  "left": {"source": "input:proposals", "pointer": "/proposals/*/id"},
  "right": {"source": "result", "pointer": "/results/*/proposal_id"}
}
```

#### `field_equal_by_key`

For matching keys, one field has equal values across two documents.

```json
{
  "type": "field_equal_by_key",
  "left": {
    "source": "input:proposals",
    "items_pointer": "/proposals",
    "key_pointer": "/id",
    "value_pointer": "/digest"
  },
  "right": {
    "source": "result",
    "items_pointer": "/results",
    "key_pointer": "/proposal_id",
    "value_pointer": "/proposal_digest"
  }
}
```

#### `value_equal`

Two single selected values are equal.

```json
{
  "type": "value_equal",
  "left": {"source": "input:requirements", "pointer": "/version"},
  "right": {"source": "result", "pointer": "/requirements_version"}
}
```

Unknown assertion types, unresolved sources, invalid pointers, non-JSON input
sources, or ambiguous single-value selections fail validation.

The assertion engine is domain-neutral. It reports source names, pointers, and
mismatches; it does not name or interpret consumer concepts.

### 8.4 Canonical result

A valid result is canonicalized with deterministic JSON encoding and persisted
as a contract artifact.

On validation failure:

- no canonical result is produced;
- the raw candidate remains persisted;
- diagnostics include parse, schema, and assertion failures;
- session status becomes `invalid_result`;
- stop reason is `result_validation_failed`;
- the command exits nonzero; and
- inspection and export remain available.

Validation failure never discards the transcript or reducer response.

### 8.5 Digest interoperability

Every digest exposed to an independent consumer declares a stable digest
profile. Before witnessed review may consume root results, `convo-relay` must
publish a versioned profile and cross-language fixtures for recipe, root plan,
bundle, selected contract, named-input content and manifest, invocation, raw
result, validation, canonical result, and portable-export digests.

A semantic-content digest hashes every semantic field. It must not reuse a
legacy storage digest that recursively drops members merely because their
names resemble runtime metadata such as `path`, `created_at`, or
`storage_id`. Runtime-only exclusions, where unavoidable, are defined by
artifact kind and exact field path. Raw-file digests are SHA-256 over exact
bytes. JSON digest fixtures define normalization, key ordering, string
escaping, number handling, prefix, and newline behavior sufficiently for an
independent implementation to reproduce them byte-for-byte.

The digest-profile id is persisted in every root artifact and export that
contains independently verifiable digests. Unknown profiles are compatibility
failures, not warnings.

---

## 9. Lifecycle and workspace isolation

### 9.1 Lifecycle enforcement

Generic guards enforce the compiled policy:

- `resume = "forbid"` rejects `resume`;
- `steering = "forbid"` rejects `steer`;
- `dynamic = "forbid"` prevents proposal creation, approval, or automatic
  expansion;
- `allow` preserves the corresponding generic behavior.

A rejected command returns a typed policy error and does not mutate the
session.

### 9.2 Workspace isolation

Supported policy levels:

- `inherited` — use ordinary backend working-directory behavior;
- `read_only` — expose the source state read-only where supported;
- `ephemeral` — operate on an isolated copy, worktree, or sandbox.

A CLI request may strengthen but not weaken the recipe's declared minimum.

For `ephemeral`:

- workspace creation finishes before provider launch;
- the base source digest is recorded;
- participant, facilitator, and reducer processes use the isolated workspace;
- the original source tree is checked after execution;
- mutation of the original source tree is an operational failure;
- workspace identity and base digest are persisted; and
- cleanup or retention follows a generic policy.

The isolation implementation may vary by platform, but the reported policy
must describe what was actually achieved. Failure to establish the required
level aborts preflight or execution; it must not silently downgrade.

`ephemeral` describes separation of the session working copy from the caller's
source. It does not, by itself, claim an operating-system filesystem boundary,
network isolation, process containment, or trusted command execution. Those
dimensions are reported separately as capabilities. Witnessed review treats
provider tool claims as untrusted even when workspace isolation is
`ephemeral`; executable witness credit comes only from the separate
caller-trusted harness described by the consumer specification.

The workspace base and the reviewed artifact are separate identities. A
detached Git worktree may establish a safe provider CWD, while the exact
reviewed bytes are the digest-checked named inputs. A consumer reviewing dirty
Git state, an unborn repository, or a non-Git artifact must first materialize
an exact frozen staging snapshot that the workspace implementation supports,
or use a future snapshot-capable workspace backend. It must never silently
substitute committed `HEAD` for the artifact named in the review manifest.

---

## 10. Persistence, contracts, and inspection

A root recipe session persists at least:

```json
{
  "execution_kind": "recipe",
  "convo_relay_version": "...",
  "digest_profile": "relay-root-digests-v1",
  "recipe_id": "proposal-compare-template",
  "recipe_ref": {},
  "recipe_digest": "sha256:...",
  "compiled_plan_ref": {},
  "compiled_plan_digest": "sha256:...",
  "integration_bundle_ref": {},
  "integration_bundle_digest": "sha256:...",
  "integration_contract_id": "example/proposal-comparison-v1",
  "integration_contract_digest": "sha256:...",
  "named_input_refs": [],
  "participant_turns": 4,
  "actual_participant_turns": 4,
  "provider_retry": "forbid",
  "provider_invocation_refs": [],
  "result_source": "reducer",
  "reducer_invocation_ref": {},
  "raw_result_ref": {},
  "canonical_result_ref": {},
  "result_validation": {
    "status": "valid",
    "errors": []
  },
  "workspace": {
    "requested": "ephemeral",
    "achieved": "ephemeral",
    "base_digest": "sha256:..."
  }
}
```

Fields whose values do not apply are omitted or null under a versioned
contract.

### 10.1 Artifact trail

The artifact index includes:

- normalized recipe;
- compiled plan;
- runtime configuration snapshot;
- integration bundle;
- selected integration contract;
- named input manifests and content artifacts;
- exact participant, facilitator, and reducer invocation records, including
  rendered-prompt refs and runner attempt metadata;
- participant transcript;
- facilitator outputs already retained by the ordinary runner;
- reducer invocation and raw provider result;
- raw candidate result;
- canonical result, when valid;
- result-validation report;
- workspace metadata; and
- provider metadata.

All public refs use the existing digest-checked artifact-ref model.

### 10.2 Inspection commands

`show --json`, `export --json`, and `contracts --json` expose the generic
fields above.

Machine consumers additionally require a versioned portable root-session
export. It contains a manifest plus every payload needed to verify the recipe,
root plan, bundle, selected contract, named inputs, provider invocations,
workspace, reducer, raw result, validation report, and canonical result after
the original relay session is cleaned. It contains no required absolute local
paths and does not require knowledge of the relay-home storage layout. The
manifest names its schema version and digest profile and binds every included
payload by digest. Export fails rather than producing a purportedly complete
bundle when a required ref is missing or invalid.

The ordinary `run --json -o` session-result envelope may point to this
portable export, but it is not itself assumed to contain all referenced
payloads. A consumer must finish and validate portable export before cleaning
the relay session.

Human output should state:

- recipe id;
- integration contract id;
- participant-turn count;
- result source;
- validation status;
- workspace isolation;
- resolved providers; and
- artifact refs.

`display` may render the reducer and canonical result as separate labeled
sections. It does not need consumer-specific formatting.

### 10.3 Resume snapshots

When resume is allowed, the persisted recipe, bundle, selected contract, and
runtime configuration are authoritative. Changes to original source files,
settings, or the external bundle path do not alter the resumed session.

---

## 11. Recipe catalog and backend readiness

### 11.1 Recipe catalog status

Catalog status distinguishes structural validity from integration binding.

A recipe may report:

- `usable` — structurally valid and fully bound;
- `requires_integration` — structurally valid but declares an unresolved
  integration contract;
- `unavailable` — fully bound but one or more resolved backends are not
  installed or otherwise unavailable under the selected readiness policy;
- `invalid` — malformed or internally inconsistent; or
- `skipped` — parseable input was intentionally excluded by normalization.

The following commands accept `--integration-bundle`:

```text
convo-relay recipes list
convo-relay recipes show <id>
convo-relay recipes doctor
convo-relay compile-recipe --recipe <id>
```

Without a bundle, `requires_integration` is not an error for catalog listing.
For `run --recipe`, it is a preflight error.

### 11.2 Backend readiness

Add:

```text
convo-relay backends status --json
convo-relay backends status --probe-auth --json
```

Per backend, report at least:

```json
{
  "backend": "codex",
  "executable": {
    "status": "installed",
    "path": "/absolute/path",
    "version": "..."
  },
  "authentication": {
    "status": "unknown"
  },
  "overall": "installed_auth_unknown"
}
```

Generic status values include:

- `not_installed`;
- `installed_auth_unknown`;
- `ready`;
- `auth_failed`;
- `probe_failed`; and
- `unsupported_probe`.

Default status inspection must not launch a model request. `--probe-auth` may
perform the cheapest backend-supported check and must record exactly what was
probed.

Recipe selection and fallback remain caller responsibilities.

---

## 12. Generic acceptance tests

The core suite uses neutral fixtures and fake providers.

It covers:

1. existing `--agents` semantics remain unchanged;
2. a neutral root recipe executes without a synthetic parent;
3. a recipe without an integration contract retains ordinary behavior;
4. a recipe with an integration contract reports `requires_integration`
   without a bundle;
5. a matching bundle resolves and becomes part of the compiled-plan digest;
6. a mismatched or missing contract fails before provider launch;
7. named input cardinality, size, media type, encoding, and JSON Schema are
   enforced;
8. undeclared and missing inputs fail preflight;
9. exact participant-turn scheduling is honored;
10. turn instructions are delivered only to their declared turn and slot;
11. the reducer uses a fresh provider session;
12. the reducer call is excluded from participant-turn counts;
13. valid JSON results produce canonical result artifacts;
14. prose, fences, multiple values, schema failures, and assertion failures
    produce `invalid_result`;
15. generic `unique`, `set_equal`, `field_equal_by_key`, and `value_equal`
    assertions work on neutral documents;
16. lifecycle policies are enforced without recipe-id branches;
17. required workspace isolation cannot silently downgrade;
18. session contracts and artifact refs digest-validate;
19. resume, where allowed, uses persisted bundle and recipe snapshots;
20. backend readiness is separate from recipe structural status;
21. removing all optional default records leaves the generic suite passing;
    and
22. a data-driven registry test validates every default record without
    hard-coded consumer ids or domain assertions;
23. integration-bound `context_only` runs accept named inputs without
    positional context and reject runs with no authoritative input;
24. `provider_retry = "forbid"` performs one runner launch attempt and
    persists the failed attempt without hidden replacement;
25. prompt-context projection supplies complete participant history and keeps
    a trace-only facilitator ledger out of participant and reducer prompts;
26. every provider call produces a digest-checked invocation record tied to
    the exact rendered prompt;
27. a portable export remains independently verifiable after the source
    session has been cleaned; and
28. an independent digest implementation passes published fixtures,
    including semantic objects containing fields named `path`, `created_at`,
    and `storage_id`.

---

## 13. Default recipe declarations

The records below are added to the existing default recipe registry. This
code block is the only consumer-specific material required in the repository
by this specification.

The currently executing plan lands the baseline records from the imported
specification. The blocks below show the consumer-ready successor records;
their `provider_retry` member is post-plan work under CRN-00 and CRN-02 and
must not be retrofitted into a strict v1 recipe artifact.

```toml
[relay_recipes.witness-falsify]
purpose = "Adversarially test filed defect witnesses against a frozen Charter."
participants = ["claude-code", "codex-deep"]
facilitator = "codex-fast"
reducer = "codex-deep"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/witness-falsification-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.witness-falsify.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"


[relay_recipes.witness-falsify-codex]
purpose = "Adversarially test filed defect witnesses against a frozen Charter."
participants = ["codex-deep", "codex-deep"]
facilitator = "codex-fast"
reducer = "codex-deep"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/witness-falsification-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.witness-falsify-codex.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"


[relay_recipes.witness-falsify-claude]
purpose = "Adversarially test filed defect witnesses against a frozen Charter."
participants = ["claude-code", "claude-code"]
facilitator = "claude-code"
reducer = "claude-code"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/witness-falsification-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.witness-falsify-claude.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"


[relay_recipes.economy-equivalence]
purpose = "Adversarially test filed deletion and simplification equivalence witnesses."
participants = ["claude-code", "codex-deep"]
facilitator = "codex-fast"
reducer = "codex-deep"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/economy-equivalence-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.economy-equivalence.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"


[relay_recipes.economy-equivalence-codex]
purpose = "Adversarially test filed deletion and simplification equivalence witnesses."
participants = ["codex-deep", "codex-deep"]
facilitator = "codex-fast"
reducer = "codex-deep"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/economy-equivalence-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.economy-equivalence-codex.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"


[relay_recipes.economy-equivalence-claude]
purpose = "Adversarially test filed deletion and simplification equivalence witnesses."
participants = ["claude-code", "claude-code"]
facilitator = "claude-code"
reducer = "claude-code"
mode = "adversarial"
participant_turns = 4
result_source = "reducer"
integration_contract = "witnessed-review/economy-equivalence-v1"
max_depth = 1
auto_approval = "never"

[relay_recipes.economy-equivalence-claude.lifecycle]
resume = "forbid"
steering = "forbid"
dynamic = "forbid"
workspace_isolation = "ephemeral"
provider_retry = "forbid"
```

No other file, package, prompt, schema, validator, fixture, command, output
field, installer rule, profile record, or manual test case is added for these
declarations. They are ordinary data consumed by the same generic loaders and
data-driven checks as every other default recipe record.

---

## 14. Non-goals

This specification does not add:

- a general workflow engine or arbitrary DAG executor;
- automatic integration discovery;
- automatic batching or fan-out;
- consumer-specific retry or fallback policy;
- external execution attestations;
- arbitrary plugin execution;
- domain-specific result interpretation;
- recipe-id-specific rendering;
- consumer-specific persistence fields; or
- any change to ordinary two-agent relay behavior beyond shared generic
  internals required by root recipe sessions.

---

## 15. Summary of required repository changes

1. Add explicit `run --recipe` root sessions.
2. Add exact `participant_turns` semantics.
3. Add opaque `integration_contract` references on recipes.
4. Add session-scoped declarative integration bundles.
5. Add repeatable named inputs bound by the selected contract.
6. Add exact per-turn instruction delivery.
7. Execute configured reducers in fresh provider contexts.
8. Add generic JSON Schema and cross-document assertion validation.
9. Add generic lifecycle and workspace-isolation enforcement.
10. Persist recipe, bundle, contract, input, reducer, result, and validation
    artifacts.
11. Add integration-aware recipe catalog and compile commands.
12. Add backend runtime-readiness inspection.
13. Add the default recipe records in §13.
14. Keep all consumer-specific implementation outside the repository.
15. Make `context_only` operate on bound named inputs in root recipe mode.
16. Add generic runner-level provider retry policy and attempt provenance.
17. Add declarative prompt-context projection and exact invocation artifacts.
18. Publish kind-aware digest profiles and cross-language fixtures.
19. Add a complete, digest-checked portable root-session export.

---

## 16. Witnessed adversarial review adoption profile

This section is normative for the `reviewer` consumer. It does not change the
rule that `convo-relay` remains domain-neutral.

### 16.1 Responsibility boundary

For witnessed review, `convo-relay` is the agent-dialogue executor and the
producer of a bounded, structured witness-survival verdict. Its existing
provider harness may execute participant, facilitator, and reducer calls.

It is not the caller-trusted command harness. A relay transcript, provider
result, invocation record, or agent statement that a command ran never earns
executable-witness credit. The review-owned command harness separately runs
structured commands, captures exact outputs, and issues authenticated
receipts against the frozen artifact.

Neither an `agentbus` migration nor `delegate` adoption is a prerequisite for
this profile. They may later replace or supplement execution internals while
the root recipe, portable export, and digest contracts remain stable.

### 16.2 Required witness execution semantics

The review-owned integration bundle must:

- use the successor integration-bundle version that declares
  `prompt_context` without redefining `relay-integration-bundle-v1`;
- implement `witnessed-review/witness-falsification-v1` and
  `witnessed-review/economy-equivalence-v1`;
- declare exactly four alternating participant turns and a fresh reducer;
- set `prompt_context.participant_transcript = "complete"`;
- set `prompt_context.facilitator_ledger = "trace_only"` so facilitator prose
  cannot introduce a premise into a presenter, falsifier, or reducer prompt;
- bind `charter`, `findings`, and zero or more `artifact` inputs;
- forbid result fields that claim trusted command execution; and
- validate exact finding-id and witness-digest coverage with the generic
  schema and assertion surface.

All six structural recipes in §13 must compile with
`provider_retry = "forbid"`, `resume = "forbid"`, `steering = "forbid"`,
`dynamic = "forbid"`, and an effective workspace policy of at least
`ephemeral`. Exactly four completed participant turns are required. A failed
provider invocation, facilitator call, reducer call, validation phase, or
export remains a failed or pending verification; the runner does not replace
it with a hidden retry.

Witness runs use `--investigation context_only`. For these integration-bound
runs, the named inputs are the authoritative launch context. The provider
prompt may refer to their materialized paths and stable refs but must not
require positional `--context`.

### 16.3 Compatibility preflight

Before any reviewer model work begins, the caller must:

1. record the `convo-relay` CLI version and verify support for every contract,
   artifact, export, and digest-profile version it will consume;
2. validate and digest the exact review-owned integration bundle;
3. run `convo-relay compile-recipe --recipe <id> --target root
   --integration-bundle <bundle>` for each of the six structural recipes;
4. compare each normalized recipe and compiled root plan with a
   reviewer-owned compatibility manifest covering participant and provider
   assignment, facilitator, reducer, exact turn count, result source,
   integration-contract id, lifecycle, and isolation minimum;
5. inspect backend readiness and select one recipe variant without treating
   runtime failure as a clean result; and
6. preserve the exact bundle, compatibility manifest, compile reports,
   backend snapshot, and their digests in the review pass.

Omitting `--target root` is not valid preflight: the compatibility default for
`compile-recipe` is the child target, and integration-bound recipes are
root-only.

The relay workspace base is not accepted as the reviewed-artifact identity.
The caller binds the exact reviewed bytes as named inputs and compares those
digests with its artifact manifest. For dirty, unborn, or non-Git targets, the
caller first creates a deterministic frozen staging snapshot supported by the
workspace backend; committed `HEAD` must not silently replace the reviewed
state.

### 16.4 Relay result import

The reviewer accepts a relay verdict only from a terminal portable export
whose manifest and required payloads validate under a known digest profile.
It independently checks at least:

- CLI and export schema versions;
- recipe payload, source provenance when applicable, and recipe digest;
- root plan payload and digest;
- integration-bundle and selected-contract payloads and digests;
- ordered named-input manifests, raw content digests, and artifact refs;
- exact four-turn schedule and actual participant count;
- prompt-context projection and one invocation record for every declared
  participant, facilitator, and reducer call;
- fresh reducer identity and result source;
- raw result, validation report, canonical result, and all referenced
  digests; and
- terminal status, checkpoints, source-integrity result, and absence of
  unresolved export diagnostics.

The reviewer copies the complete portable export into review-owned state
before `convo-relay clean`. A run-result envelope containing refs into a live
relay home is insufficient durable evidence by itself.

### 16.5 Reviewer-owned prerequisites

Completion of the relay plan and the extensions above is necessary but not
sufficient. Witnessed review must not execute on a real target until the
consumer repository also has:

- an owner-authorized, frozen Charter; first-run automation may request or
  record one but may not invent goals under an implicit auto-create rule;
- the final review integration bundle, schemas, assertions, compatibility
  manifest, and fake-provider conformance fixtures;
- a deterministic planner, relay-export importer, adjudicator, append-only
  ledger, and final-state gate;
- duplicate handling that carries forward the unresolved effect of an exact
  prior finding instead of turning its reappearance into evidence for a clean
  fixpoint;
- a command harness whose receipt binds harness identity and version, policy
  digest, exact source snapshot, command array, working directory, environment
  policy, timeout, filesystem and network capabilities, transformation,
  stdout, stderr, exit status, and post-run source-integrity result;
- an exact snapshot/materialization rule for Git-dirty, unborn, non-Git, and
  ordinary-file targets;
- retention rules that keep pass inputs, relay exports, command outputs,
  receipts, and ledger lineage independently verifiable; and
- end-to-end tests showing that missing, invalid, unavailable, or
  contradictory verification cannot produce a clean pass.

### 16.6 Corrections required in the witnessed-review specification

The consumer specification must be amended before implementation is treated
as authoritative:

- **Charter initialization:** the single-pass procedure loads an already
  owner-authorized Charter. `charter init` is a separate explicit owner or
  authorized-caller action; a pass never invents standing goals by silently
  creating a Charter.
- **Duplicate recurrence:** an exact fingerprint and witness match may avoid
  duplicate model work, but it must not erase the prior finding's unresolved
  effect. On the same artifact, the latest unresolved admitted, automatic, or
  pending state carries forward. On a changed artifact, recurrence is either
  reconsidered or linked to an explicit resolution record. It cannot be
  routed to advisory in a way that makes `fixpoint_eligible` true merely
  because the same defect was reported again.
- **Compile target:** every startup compile for a structural review recipe
  supplies `--target root`; relying on the child-compatible default is an
  error.
- **Investigation input:** `context_only` is satisfied by bound named inputs,
  not by a contradictory requirement to also pass positional `--context`.
- **Retry ownership:** no runner-level retry is permitted for a witnessed
  invocation. A caller-initiated replacement batch is a new recorded session,
  not a hidden continuation of the original one.
- **Prompt authority:** facilitator output is retained only as trace and is
  absent from presenter, falsifier, and reducer prompt authority.
- **Contract versions:** the review bundle, startup checks, and accepted relay
  artifacts use the declared successor versions for post-plan fields; they do
  not treat a v1 identifier as if its schema had changed in place.
- **Frozen artifact:** the artifact manifest identifies exact content, while
  the relay workspace record identifies only its execution base. Dirty or
  non-Git review state is materialized exactly; committed `HEAD` is never used
  as an implicit substitute.
- **Relay evidence retention:** the reviewed pass retains a complete portable
  export and recomputes its declared digest profile before the relay session
  may be cleaned.
- **Execution-receipt provenance:** a receipt adds issuer/harness identity and
  version, executable or build digest, policy digest, pass and snapshot
  lineage, environment allowlist, timeout/resource policy, filesystem,
  network and process-containment capabilities, transformation digest, and a
  caller-verifiable authenticity mechanism. A boolean
  `source_tree_unchanged` without the before/after inventory and comparison
  result is insufficient.

Until those corrections and their tests land, the specification may guide
fixture work but must not issue authoritative automatic-change candidates or
clean-fixpoint decisions.

The detailed relay-only delta beyond the active implementation plan is in
[`convo-relay-needed.md`](convo-relay-needed.md).
