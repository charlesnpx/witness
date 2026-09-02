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

The `review-role-output-v3` through `review-role-output-v5` family consists of
Witness-internal compatibility structures retained for the Witness engine. It is
not part of the `review-request-v1`/`review-report-v1` adapter contract, and this
boundary does not accept those documents.
