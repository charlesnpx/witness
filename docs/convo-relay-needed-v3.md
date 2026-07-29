> **Historical.** This document is historical: the relay requirements it
> tracked are satisfied by `convo-relay` v1.4.0 and superseded by the corrected
> Witness spec's final contract. Do not implement from it.

# Convo-Relay v1.2 follow-up: provider results and portable source identity

Release-pinned implementation specification for the two remaining generic
lineage gaps in `convo-relay`.

This document is a narrow delta from
[`convo-relay-needed-v2.md`](convo-relay-needed-v2.md). The v2 plan has landed;
do not reimplement it. This follow-up makes provider results directly
referenced and makes a portable export retain the complete identity of every
source artifact from which it was projected.

## 1. Assessment basis

Implement against this verified release baseline:

- repository: `charlesnpx/convo-relay`;
- release: `v1.2.0`;
- commit: `bc261b4c12c7c5ec8c6d1d7cb7b6f6a88dd0731a`;
- assessment date: 2026-07-27; and
- existing v1.2.0 tests and public fixtures are the compatibility floor.

The two observed limitations are:

1. `internal/runner/root_invocation.go` writes
   `provider_result_ref: null` for every provider invocation record.
2. `internal/portable/export.go` retains only `source_artifact_id` in the
   portable inventory and rewrites an artifact edge to only a
   `portable_id`. The original source artifact digest is therefore absent
   from the exported graph.

A consumer can currently compensate by correlating deterministic invocation
identities and retaining pre-run capability, compile, and artifact records.
That is sufficient when those records remain available. The changes below
are required when the portable directory itself must contain the complete
invocation-to-result relationship and the original source-artifact
identities.

In this document, **self-contained** means self-contained for those two
relationships. It does not mean that an unsigned directory authenticates its
author, proves that a provider obeyed a prompt, or proves trusted command
execution.

## 2. Compatibility and domain-neutrality rules

Do not change a released contract in place. Add successor contracts and keep
all existing readers, writers, fixtures, and digest meanings:

| Surface | Released contract | New contract |
|---|---|---|
| Provider invocation | `relay-provider-invocation-v1` | `relay-provider-invocation-v2` |
| Provider result | absent | `relay-provider-result-v1` |
| Portable export | `relay-root-portable-export-v1` | `relay-root-portable-export-v2` |
| Rewritten portable edge | unversioned v1 shape | `relay-portable-payload-ref-v2` |

Required compatibility policy:

- Continue reading historic invocation-v1 records whose
  `provider_result_ref` is null.
- Do not add source digests or new allowed fields to portable-export v1.
- Continue producing and verifying byte-compatible portable-v1 fixtures.
- Dispatch readers by the declared version, never by field presence.
- Reject unknown versions and successor fields under a v1 identifier.
- Do not backfill a result or source digest that was not durably recorded.
- Advertise both old and new versions through `relay-capabilities-v1`.
- Keep the existing inline provider-result projections for compatible
  inspection and display, but make the new artifact ref authoritative for
  v2 lineage.

All implementation and fixtures in `convo-relay` must remain domain-neutral.
Core code must not inspect or branch on a Witness recipe id, integration id,
input label, schema field, verdict value, finding status, or other
consumer-owned vocabulary.

## 3. CRN-10: Durable provider-result artifacts

### 3.1 Required contract

Add a root artifact kind named `provider_result`. Its root-artifact envelope
uses the existing successor digest profile and contains a record identified
by `relay-provider-result-v1`.

The normalized record should have this closed shape:

```json
{
  "schema_version": "relay-provider-result-v1",
  "invocation_id": "participant:000001",
  "phase": "participant",
  "actor": "slot_0",
  "slot": "slot_0",
  "participant_ordinal": 1,
  "reducer_fresh": false,
  "runner_attempt": 1,
  "backend": "codex",
  "provider_session_id": "provider-session-or-null",
  "content": {
    "media_type": "application/octet-stream",
    "encoding": "base64",
    "bytes_base64": "ZXhhY3QgcHJvdmlkZXIgb3V0cHV0",
    "size_bytes": 21,
    "raw_digest": "sha256:..."
  },
  "observation": {
    "return_code": 0,
    "timed_out": false,
    "stalled": false,
    "recovered": false,
    "recovery_source": null,
    "warnings": [],
    "retryable_error": null
  },
  "failure": null,
  "completed_at": "..."
}
```

Field semantics:

- The correlation key is `(invocation_id, runner_attempt)`. It is unique
  within a root session.
- Preserve the released v1.2 logical invocation-id grammar in invocation v2:
  `participant:%06d`, `facilitator:%06d`, and `reducer:%06d`, using the
  applicable participant or reducer ordinal. A retry keeps the same logical
  invocation id and advances `runner_attempt`. Do not insert slot ids or
  publish a new id grammar as an incidental part of this work.
- `phase`, `actor`, `slot`, `participant_ordinal`, `reducer_fresh`, backend,
  and provider session identity have the same meanings as the matching
  invocation record.
- `content.bytes_base64` is the exact byte sequence in the `TurnResult.Content`
  value returned by the backend adapter. Do not trim it, normalize newlines,
  parse and reserialize it, or replace it with a diagnostic excerpt.
- Empty returned content is represented by the base64 encoding and digest of
  zero bytes. It is not represented by omission or null.
- `size_bytes` and `raw_digest` are computed over the decoded content bytes.
- `observation` is the normalized, sanitized provider observation already
  represented by `ProviderResult`: return code when known, timeout, stall,
  recovery, recovery source, warnings, and retryable error.
- An unknown return code is null, not zero.
- `failure` is null on a non-error return. Otherwise it contains only stable,
  sanitized fields such as category, retryability, remediation code, and
  sanitized detail. It must not contain credentials, raw settings, absolute
  paths, an unsanitized stderr stream, or arbitrary error object serialization.
- Exact provider content and sanitized failure detail are different data.
  Sanitization of the failure must not silently mutate the retained content.
- The artifact records what the backend adapter returned to the runner. It
  does not claim to be raw process stdout unless that adapter defines its
  returned content that way.

The public validator must enforce the closed field set, exact version,
required/nullability rules, strict base64 decoding, decoded size, raw digest,
portable identity fields, and normalized observation types.

### 3.2 Invocation-v2 binding

Add `relay-provider-invocation-v2` with the released invocation-v1 fields and
the following stronger invariant:

```text
provider_launch_attempted = true  <=>  provider_result_ref is a valid ref
provider_launch_attempted = false <=>  provider_result_ref is null
```

`provider_launch_attempted` means the runner entered the backend `RunTurn`
operation. It does not assert that a remote service accepted or completed a
request.

For every launched participant, facilitator, and reducer runner attempt:

1. persist exactly one provider-result artifact;
2. validate and durably save it before saving the matching invocation-v2
   record;
3. set `provider_result_ref` to its complete artifact ref; and
4. validate equality of all shared identity fields.

For prompt construction, backend construction, retained-input pre-launch
integrity, or another failure before `RunTurn` is entered:

- persist the invocation-v2 record;
- set `provider_launch_attempted=false`;
- set `provider_result_ref=null`; and
- retain the existing precise `failure_stage` classification.

The invocation/result cross-check must compare at least:

- invocation id and runner attempt;
- phase, actor, slot, and participant ordinal;
- reducer freshness;
- backend and provider session id; and
- terminal timestamps in their documented ordering.

A missing result, an extra result, a ref resolving to the wrong kind, a
digest mismatch, or any shared-identity mismatch is a persisted-integrity
failure. It must never be downgraded to a warning.

### 3.3 Propagation through the session graph

The authoritative result ref must be available at every artifact that
represents the same attempt:

- a participant transcript entry carries `provider_result_ref`;
- a facilitator attempt carries `provider_result_ref`;
- the corresponding participant transcript entry may also carry
  `facilitator_provider_result_ref`;
- a reducer attempt carries `provider_result_ref`;
- root metadata and the successor machine result expose the ordered
  `provider_result_refs`; and
- events may retain the compatible inline observation, but any v2 lineage
  edge uses the same complete result ref.

Do not remove the existing inline `provider_result` values. Treat them as
compatibility/display projections. When both an inline projection and a
result ref are present, their common normalized observation fields must
agree; disagreement is an integrity error.

### 3.4 Persistence and recovery

Result persistence must be idempotent under the correlation key. Repeating
recovery may reuse an existing result only when its complete artifact ref and
record content validate exactly. It must not create a second result or a
second invocation for the same `(invocation_id, runner_attempt)`.

Add a durable internal attempt marker before entering `RunTurn`, or an
equivalent journal that lets recovery distinguish these states:

1. no provider launch was attempted;
2. a launch may have occurred but no result became durable;
3. the result is durable but its invocation is not;
4. both result and invocation are durable; and
5. downstream transcript or attempt propagation remains incomplete.

Recovery behavior must be fail-closed:

- In state 3, validate and reuse the result, then finish the one matching
  invocation and downstream refs without another provider launch.
- In states 4 and 5, validate and finish propagation without duplicating
  artifacts.
- In ambiguous state 2, do not invent output or silently launch a replacement
  under `provider_retry=forbid`. Recover the exact backend attempt when that
  is supported; otherwise leave the session attention-required or
  recovery-pending with a typed diagnostic.
- A session with an unresolved launched attempt is not eligible for a
  complete portable-v2 export.
- Under `provider_retry=allow`, every actual runner retry has its own attempt
  number, result artifact, and invocation record. An ambiguous earlier
  attempt is not erased by a later attempt.

The implementation may choose the journal representation, but it must not
expose absolute runtime paths or weaken the existing retry-forbid guarantee.

## 4. CRN-11: Portable export with original source identities

### 4.1 Inventory-v2 shape

Add `relay-root-portable-export-v2`. Every payload inventory entry contains a
`source_artifact_ref` member. For a payload projected from a stored source
artifact, the value is the complete original ref:

```json
{
  "kind": "provider_result",
  "portable_id": "artifact-000001",
  "path": "payloads/provider_result/artifact-000001.json",
  "media_type": "application/json",
  "size_bytes": 1234,
  "digest_class": "raw-bytes",
  "digest": "sha256:...",
  "source_artifact_ref": {
    "kind": "artifact_ref",
    "schema_version": 1,
    "id": "provider_result:000001",
    "digest": "sha256:..."
  }
}
```

For the synthetic `root_session`, `participant_transcript`, and `diagnostics`
payloads, use the explicit value:

```json
"source_artifact_ref": null
```

Remove `source_artifact_id` from the v2 entry rather than retaining two
partially overlapping source-identity fields. Its v1 meaning remains
unchanged.

The two digests in a source-originated inventory entry serve different
purposes:

- `digest` authenticates the exact projected portable payload bytes; and
- `source_artifact_ref.digest` retains the identity of the validated source
  artifact before portable projection and ref rewriting.

### 4.2 Rewritten edge-v2 shape

When an original source payload contains an artifact ref, rewrite it to:

```json
{
  "kind": "portable_payload_ref",
  "schema_version": "relay-portable-payload-ref-v2",
  "portable_id": "artifact-000001",
  "source_artifact_ref": {
    "kind": "artifact_ref",
    "schema_version": 1,
    "id": "provider_result:000001",
    "digest": "sha256:..."
  }
}
```

The nested source ref is identity evidence, not a live path back into the
deleted relay session. Portable-v2 ref discovery must distinguish this
nested attestation from an unreplaced source-session edge.

For each rewritten edge:

- `portable_id` resolves to exactly one inventory entry;
- the target inventory entry has a non-null `source_artifact_ref`;
- the edge's source ref exactly equals the target entry's source ref; and
- id-only, digest-only, or inferred source identities are invalid.

### 4.3 Exporter requirements

Before projecting any source artifact, the exporter must:

1. validate the complete artifact-ref shape;
2. resolve it within the source session;
3. validate the source payload using the declared artifact digest profile;
4. reject an id whose stored payload does not match the ref digest; and
5. retain that exact validated ref in both inventory and rewritten edges.

The exporter must then:

- build a one-to-one map from complete source artifact refs to portable ids;
- reject duplicate inventory entries for the same complete source ref;
- reject the same source artifact id paired with different digests;
- reject ambiguous, missing, out-of-root, or wrong-kind mappings;
- include the full `source_artifact_ref` objects in `inventory_digest` and
  therefore in `manifest_digest`;
- preserve complete provider-result and invocation-v2 closure;
- keep all portable ids and paths deterministic for the same validated
  source graph;
- omit original filesystem paths and all fields already excluded from
  portable identity; and
- retain atomic publication and closed-directory behavior.

A portable-v2 writer must reject an old or incomplete session that lacks
complete invocation-v2/provider-result lineage. Such a session remains
eligible for portable v1 when it satisfies the released v1 rules. Do not
fabricate result refs or source digests during export.

### 4.4 Verifier requirements

The v1.2 checkout provides portable verification internally through
`portable.VerifyDirectory` and its tests, but does not expose an obvious
user-facing `verify-export` subcommand. Extend that internal verifier and add
the public command specified in §5; do not assume the command already exists.

The internal verifier and new CLI must dispatch by manifest version. For
portable v2 they must validate all released byte, size, digest,
closed-file-set, and relocation rules plus:

- the exact closed inventory-v2 field set;
- every source artifact ref with the public artifact-ref validator;
- null source refs only for explicitly synthetic payload classes;
- uniqueness by portable id, path, complete source ref, and source artifact
  id;
- equality between every edge source ref and its target inventory source
  ref;
- the absence of unrewritten live `artifact_ref` edges outside the explicit
  `source_artifact_ref` attestation position;
- provider invocation/result one-to-one accounting and shared-identity
  equality; and
- recomputed inventory and manifest digests over the complete v2 shapes.

Verification must still succeed after relocating the directory and after the
source relay session has been deleted. A verifier must be able to report the
original id and digest of every source-originated payload using the portable
directory alone.

### 4.5 Trust boundary

Portable v2 preserves the source identity that the exporter validated at
export time. The portable payload is a projection: runtime-only fields are
removed and refs are rewritten, so its bytes are not expected to reproduce
the original source-artifact digest.

An attacker who can rewrite the whole directory can also recompute its
internal manifest digest. Cryptographic authenticity therefore still
requires an externally retained manifest digest, a signature, or a signed
execution receipt. This is generic evidence handling and does not belong in
a consumer-specific branch in `convo-relay`.

## 5. Registry, capability, and CLI behavior

Add the following exact entries to the implementation-owned public registry
and capability advertisement:

```json
{
  "provider_invocation": [
    "relay-provider-invocation-v1",
    "relay-provider-invocation-v2"
  ],
  "provider_result": ["relay-provider-result-v1"],
  "portable_export": [
    "relay-root-portable-export-v1",
    "relay-root-portable-export-v2"
  ],
  "portable_payload_ref": ["relay-portable-payload-ref-v2"]
}
```

Document all four contracts and publish language-neutral golden fixtures.

Preserve the current `export --portable` behavior for callers that do not
select a successor contract. Add an explicit portable contract selector,
using this public shape unless an existing repository convention requires an
equivalent spelling:

```text
convo-relay export <session> --portable \
  --portable-version relay-root-portable-export-v2 \
  -o <bundle-directory> --json
```

Add this new public command over the internal directory verifier:

```text
convo-relay verify-export <bundle-directory> --json
```

`verify-export` reads the declared manifest version and requires no version
flag. It verifies both supported generations, returns a stable machine result
and exit status, and performs no provider or network operation. Unknown
versions fail with the existing stable unsupported-contract diagnostic
family.

## 6. Implementation order

Implement in this order so no writer gets ahead of its validator:

1. Add registry identifiers, explicit reader dispatch, schemas, and golden
   compatibility fixtures.
2. Add provider-result validation and the new root artifact kind.
3. Add invocation-v2 creation, cross-artifact validation, and capability
   advertisement.
4. Add idempotent result-before-invocation persistence and recovery
   reconciliation.
5. Propagate the authoritative result ref into transcript, facilitator,
   reducer, metadata, inspection, and machine-result projections.
6. Add portable inventory-v2 and portable-payload-ref-v2 projection.
7. Add portable-v2 verification, CLI selection, and documentation.
8. Run the complete v1 regression suite and the acceptance matrix below.

## 7. Required generic acceptance matrix

The release is not complete until automated tests prove all of the following:

1. Successful participant, facilitator, and reducer launches each create one
   invocation-v2 record and one matching provider-result artifact.
2. Provider failure, timeout, stall, launched cancellation, recovered output,
   warnings, retryable error, and known/unknown return-code cases are covered
   independently in all three phases where applicable.
3. Prompt construction, provider construction, and pre-launch integrity
   failures create invocation-v2 records with a null result ref and create no
   provider-result artifact.
4. Empty content, trailing newlines, Unicode, and arbitrary byte values that
   can be returned through `TurnResult.Content` retain exact base64 bytes,
   size, and raw digest.
5. Credential-shaped failure fields and absolute paths are sanitized without
   changing the exact returned content field.
6. Tampering with result content, content size, raw digest, artifact ref,
   invocation identity, runner attempt, backend, provider session id, or
   inline observation is detected.
7. Failpoints before result persistence, after result persistence, after
   invocation persistence, and during downstream ref propagation prove
   idempotent recovery, no duplicate records, and fail-closed handling of an
   ambiguous launched attempt.
8. `provider_retry=forbid` never turns recovery ambiguity into an undeclared
   second launch. Under `allow`, each actual retry has distinct matched
   result and invocation records.
9. Portable-v2 inventory entries retain exact full source refs; synthetic
   entries carry explicit null source refs.
10. Tampering with an inventory source id or digest, an edge source id or
    digest, or an edge portable id fails verification.
11. Duplicate complete source refs and one source id paired with distinct
    digests are rejected as ambiguous.
12. Missing, wrong-kind, out-of-root, and unrewritten source refs fail export
    or verification with typed diagnostics.
13. Inventory and manifest digests change when any retained source id or
    digest changes.
14. Portable-v2 verifies after relocation and after source-session cleanup,
    and exposes every original source id/digest without external records.
15. No absolute source, relay-home, session, worktree, settings, or retained-
    input path enters portable identity.
16. Explicit portable-v2 export of a historic invocation-v1 session fails
    rather than inventing lineage; portable-v1 behavior remains available.
17. Invocation v2 preserves the released logical ids, including
    `participant:000001`, `facilitator:000001`, and `reducer:000001`; retries
    advance only `runner_attempt`.
18. Capability output exactly matches the public registry and names both
    generations.
19. The new `verify-export <directory> --json` command exercises the internal
    verifier for valid and invalid v1/v2 bundles and returns stable JSON and
    exit statuses without provider or network activity.
20. All released invocation-v1, portable-export-v1, digest, CLI, and ordinary
    non-root fixtures remain unchanged and green.

Include one neutral end-to-end fixture with:

- named authoritative inputs;
- `provider_retry=forbid`;
- four alternating participant turns;
- a trace-only facilitator projection;
- one fresh reducer;
- exactly nine launched provider attempts: four participant, four
  facilitator, and one reducer;
- exactly nine invocation-v2 records;
- exactly nine provider-result artifacts;
- every invocation and downstream attempt carrying the correct result ref;
  and
- successful independent portable-v2 verification after the source session
  is removed.

The fixture must use neutral names and a generic output schema. It must not
contain Witness ids, verdict semantics, severities, finding rules, or review-
specific branching.

## 8. Explicit non-requirements

This follow-up does not require:

- any Witness package, schema, recipe, identifier, or conditional behavior in
  `convo-relay`;
- changing provider execution backends or adopting another orchestration
  service;
- claiming provider-internal retries as runner-observed attempts;
- retaining raw credentials, settings, stderr, or absolute runtime paths;
- making prompt policy, a provider result, or a writable worktree a trusted
  execution receipt;
- signing the bundle inside relay core;
- migrating or fabricating complete lineage for historic sessions; or
- embedding consumer-owned pre-run capability or compile receipts.

After these changes, consumers may still retain capability and compile
records for policy audit. They are no longer needed to compensate for a null
provider-result edge or a missing original source-artifact digest.

## 9. Definition of done

This delta is complete only when:

- every launched successor-root provider attempt has one directly referenced
  durable result;
- every source-originated portable-v2 payload and edge retains the complete
  original source artifact ref;
- recovery cannot duplicate or silently invent either relationship;
- an implementation using only the published contracts can verify the
  portable graph after source cleanup;
- released v1 readers, writers, digests, fixtures, and CLI behavior remain
  compatible; and
- the implementation contains no consumer-specific coupling.
