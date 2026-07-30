# Witness Single-Pass Review

Use this skill to run Witness review from a frozen source state and frozen Charter. Witness is a deterministic CLI workflow: it does not mutate reviewed sources, apply findings, retry models, add model roles, add judgment gates, or own an iteration loop.

Finder roles are exactly: defect, economy, and optional goal-fit.

Use the shipped relay integration bundle at `skill/bundle/relay-integration-bundle-v2.json` for all Witness v2 relay verification recipes.

## Finder Guidance

All finder output is a `review-role-output-v3` role-output document. Findings must name Charter goals; existing code, tests, defenses, and review machinery create no goals.

Defect finders file defect findings with defect witnesses. When an Operational Envelope is present, include scope anchors. Constructed and executable defect witnesses must include an entry point and a non-empty reachability chain; argued defect witnesses are exempt from the chain.

Economy finders file economy findings with equivalence witnesses. Economy remedies must remove code or make a size-reducing change and include structured negative production or test delta where relevant.

Optional goal-fit output contains missing-goal questions only. It contains no findings, severities, remedies, or application recommendations.

Every finding must state the smallest sufficient remedy. Propose at most one test per distinct reachable behavioral partition. Exclude tests of unreachable states, runtime guarantees, repeated internal layers, unsupported Cartesian combinations, implementation-only details, and unbounded fuzz/property work.

## Orchestration Procedure

1. Freeze the Charter with `witness charter freeze`.
2. Run verification preflight with `witness verification preflight`.
3. Produce role-output documents for the applicable finder roles.
4. Create verification-batch documents with `witness verification plan`.
5. Run each required relay verification batch once with the selected Witness recipe. Preserve the run-result document, portable export, provider/result refs, transcript, and retained artifacts.
6. Assemble verification with `witness verification assemble`.
7. Adjudicate with `witness adjudicate`.
8. Inspect the run-result document, ledger records, policy decisions, pending verification, and Operational Envelope questions. Use `witness ledger promote` or `witness ledger accept-unverified` only for explicit owner decisions.
9. Run policy checks for caller-measured deltas with `witness policy check-application` before any external automation applies an automatic candidate.
10. Emit metrics with `witness metrics`.

The pass ends after adjudication and metrics emission. Any decision to apply, override, accept risk, promote a question, or run another pass belongs to the caller or owner outside Witness.
