# Review boundary documents

`review-request-v1` binds a consumer, source revision (`head`, with optional
`tree` and `branch`), frozen charter, and the exact reviewer-input bytes.
Its request digest is the canonical digest of that document.

`review-report-v1` is the defect-only reviewer response. It echoes the frozen
`charter_hash` and `review_input_digest`; a finding may be bound to charter
goals or be unbound with an empty `charter_goal_ids` array. Annotation
`path`/`line` metadata is presentation-only and carries zero epistemic weight;
the witness is the evidence.

This boundary does not accept `review-role-output-v3`, `review-role-output-v4`,
or `review-role-output-v5` documents.
