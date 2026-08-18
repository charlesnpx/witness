---
name: witness
description: Run deterministic single-pass Witness reviews from a frozen source state and Charter. Use when Codex or Claude should orchestrate Witness review, verification planning, adjudication, or ledger review without mutating reviewed sources.
---

# Witness Single-Pass Review

Use this skill to run Witness review from a frozen source state and frozen Charter. Witness is a deterministic CLI workflow: it does not mutate reviewed sources, apply findings, retry models, add model roles, add judgment gates, or own an iteration loop.

Finder roles are exactly: defect, economy, and optional goal-fit.

Use the shipped relay integration bundle at `bundle/relay-integration-bundle-v2.json`, relative to this `SKILL.md`, for all Witness v2 relay verification recipes. In the repository source, it is `skill/bundle/relay-integration-bundle-v2.json`.

## Finder Guidance

All new finder output is a `review-role-output-v5` role-output document. Findings must name Charter goals; existing code, tests, defenses, and review machinery create no goals.

When a defect or economy finder finds no findings, it must emit `"findings": []` and an `evaluation` object with non-empty, duplicate-free `evaluated_paths` and `evaluated_charter_goal_ids` arrays. List the actual frozen Charter goal IDs evaluated. When the caller supplies a derived `delta_obligating` change surface, list every changed path in that surface and no other path. In a whole-tree pass with no derived change surface, list the non-empty set of paths actually evaluated. A v5 document with findings may also include `evaluation`, which is checked the same way when present.

This attestation is a finder self-report, not proof that review happened. Witness can reject an invented path, omitted delta path, or unknown Charter goal, but a determined lazy finder can still make a false shape-correct claim.

Every finding must carry base/head attribution: `introduced` when the stack created it, `worsened` when the stack made it worse, `pre-existing` when it was already present at base, or `unattributed` when the finder could not establish it. Only introduced and worsened findings can score the stack; pre-existing and unattributed findings remain visible as advisory findings.

Defect finders file defect findings with defect witnesses. When an Operational Envelope is present, include scope anchors. Constructed and executable defect witnesses must include an entry point and a non-empty reachability chain; argued defect witnesses are exempt from the chain.

Economy finders file economy findings with equivalence witnesses. Economy remedies must remove code or make a size-reducing change and include structured negative production or test delta where relevant.

Optional goal-fit output contains missing-goal questions only. It contains no findings, severities, remedies, or application recommendations.

Every finding must state the smallest sufficient remedy. Propose at most one test per distinct reachable behavioral partition. Exclude tests of unreachable states, runtime guarantees, repeated internal layers, unsupported Cartesian combinations, implementation-only details, and unbounded fuzz/property work.

## Orchestration Procedure

1. Before starting a large, multi-branch, or moving-stack pass, write a short human-readable review plan. It records the frozen branch names and SHAs, included branches, branch-movement policy and response to drift, relay source-reduction approach, and stack-attribution boundary. This is a manual operator step; use it whenever the scope or relay input reduction needs deliberate judgment.
2. Freeze the Charter with `witness charter freeze`.
3. Run verification preflight with `witness verification preflight`.
4. Produce role-output documents for the applicable finder roles.
5. Create verification-batch documents with `witness verification plan`.
6. Run each required relay verification batch once with the selected Witness recipe. Preserve the run-result document, portable export, provider/result refs, transcript, and retained artifacts.
7. Assemble verification with `witness verification assemble`.
8. Adjudicate with `witness adjudicate`.
9. Inspect the run-result document, ledger records, pending verification, and Operational Envelope questions. Use `witness ledger promote` or `witness ledger accept-unverified` only for explicit owner decisions.

The pass ends after adjudication. Any decision to apply, override, accept risk, promote a question, derive statistics, or run another pass belongs to the caller or owner outside Witness.

After the pass, the orchestrating agent must manually produce a human-readable
review report with these required finding sections: `Witness ledger findings`,
`Manual post-freeze findings`, and `Pre-existing defects excluded from stack
attribution`. Each finding belongs in exactly one section; state an empty
section as empty. Ledger findings retain their Witness provenance and truthful
verification state, including `pending verification` when relay produced no
verdict. Manual post-freeze findings carry no Witness provenance, and a defect
that reproduces at the review base is excluded from stack attribution. Witness
does not generate this report.
