// Package review defines the public review boundary documents.
//
// review-request-v1 binds a consumer to a source revision: subject.head and
// optional subject.tree/subject.branch identify that revision, charter_hash
// identifies frozen intent, and review_input_digest identifies the exact bytes
// shown to the reviewer. Its request digest is the canonical digest of the
// request document itself. review-report-v1 returns defect findings bound to
// the same frozen charter and exact reviewer input digest.
//
// A finding annotation is presentation-only file:line metadata and has zero
// epistemic weight. Witness content remains the evidence. This phase is
// defect-only: review-role-output-v3, review-role-output-v4, and
// review-role-output-v5 documents are not accepted at this boundary.
package review
