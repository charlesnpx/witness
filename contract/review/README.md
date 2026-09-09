# Review boundary documents

`review-request-v1` binds a consumer, source revision (`head`, with optional
`tree` and `branch`), frozen charter, and the exact reviewer-input bytes.
Its request digest is the canonical digest of that document.

The review input packet is caller-supplied verbatim bytes. This contract performs
no content screening, including for secrets; screening is the caller's
responsibility.

`review-report-v1` is the defect-only reviewer response. It echoes the frozen
`charter_hash` and `review_input_digest`; a finding may be bound to charter
goals or be unbound with an empty `charter_goal_ids` array. Annotation
`path`/`line` metadata is presentation-only and carries zero epistemic weight;
the witness is the evidence.

Its required `evaluation` object records the reviewer's self-attestation of
coverage through `evaluated_paths` and `evaluated_goal_ids`. The validator checks
the goal IDs against the frozen Charter but does not verify evaluated paths
against the review input.

The default-reviewer schema caps a report at 128 findings; consumers may enforce their own bounds.

`review-request-v2` adds the recipe boundary. It stores the strict JSON recipe
bytes, their semantic canonical-JSON digest, the adapter identifier, and the
open reviewer identifiers required by both the request and recipe. A recipe's
instructions, required outputs, and policy are validated for shape without an
enum or registry of recipe or reviewer names.

`review-report-v2` binds each report to the v2 request digest, recipe digest,
and required reviewer identifier. It retains the v1 report surfaces and adds
finding kind/attribution plus economy equivalence evidence: the behavior
preserved by a removal and the declared Charter goals it serves.

`review-completion-v1` is host-facing. Its `HostExecutionEvidence` has private
state and can only be initialized from `ObservedReviewExecution` through
`NewHostExecutionEvidence`; JSON decoding deliberately leaves that state
untrusted. Therefore a model-written report or completion JSON cannot supply
evidence that permits the `satisfied` verdict.

The `review-role-output-v3` through `review-role-output-v5` family consists of
Witness-internal compatibility structures retained for the Witness engine. It is
not part of the `review-request-v1`/`review-report-v1` adapter contract, and this
boundary does not accept those documents.
