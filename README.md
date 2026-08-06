# Witness

Witness is a deterministic Go CLI for evidence-backed, single-pass software
review. It freezes the reviewed source and an owner-authored Charter, validates
finder output, plans independent verification, assembles retained evidence,
adjudicates findings, and emits an append-only ledger and metrics.

Witness deliberately does not edit reviewed source, apply findings, retry
models, add review roles, or own an iteration loop. Those decisions remain
with the caller or repository owner.

The project is early-stage `v0.x` software. Its JSON contracts are strict and
versioned; compatibility changes are made explicitly rather than inferred.

## Requirements

- Go 1.23 or newer, using a currently supported security patch release.
- Git for freezing repository snapshots.
- [convo-relay](https://github.com/charlesnpx/convo-relay) for relay-backed
  verification. Witness can record an explicit degraded, relay-absent pass
  when convo-relay is unavailable.

## Install

Build the two commands directly:

```sh
go install github.com/charlesnpx/witness/cmd/witness@main
go install github.com/charlesnpx/witness/cmd/witness-harness@main
```

The existing `v0.1.0` and `v0.2.0` tags predate the canonical GitHub module
path. Use `@main` until a newer versioned release is published.

Alternatively, clone the repository and use the delegated installer:

```sh
git clone https://github.com/charlesnpx/witness.git
cd witness
./install-skill.sh --plan --target all --json
./install-skill.sh --install --target all --json
```

The `all` target installs binaries beneath `~/.local/bin` and the shipped skill
and relay bundle beneath the Codex and Claude skill directories. Use
`--install-root` to stage the installation somewhere else, or select only
`tools`, `codex`, or `claude` with `--target`.

## Quick start

Create an owner-authorized Charter and begin an explicit whole-tree baseline
pass:

```sh
witness charter init \
  -template minimal \
  -out charter.json

witness pass begin \
  -state-dir witness-state \
  -charter charter.json \
  -source-dir . \
  -baseline-pass
```

`pass begin` and `pass resume` emit a machine-readable next-action document.
The caller supplies the requested finder or relay artifacts, then resumes the
same state directory:

```sh
witness pass resume -state-dir witness-state
```

The lower-level workflow remains available for callers that need direct
control:

1. `witness charter freeze`
2. `witness verification preflight`
3. Produce defect, economy, and optional goal-fit role-output documents.
4. `witness verification plan`
5. Run the required relay verification batches and retain their exports.
6. `witness verification assemble`
7. `witness adjudicate`
8. Inspect the ledger, policy decisions, pending verification, and metrics.

See [skill/SKILL.md](skill/SKILL.md) for the complete orchestration procedure
and [docs/witnessed-adversarial-review-spec-corrected.md](docs/witnessed-adversarial-review-spec-corrected.md)
for the architecture and contract model.

## Operator walkthrough

For the copy-pasteable pass flow—from an owner-authored Charter through finder
output, adjudication, ledger, and a zero-findings result—see
[docs/operator-walkthrough.md](docs/operator-walkthrough.md).

## Security and trust model

`witness-harness` is an evidence producer, not a security sandbox. It launches
caller-selected structured argument vectors with the current user's authority.
It does not provide network isolation, container isolation, or a boundary
against another process running as the same user. Run only commands and input
documents you trust.

Harness receipts contain the supplied environment map and captured artifacts.
Do not place credentials or other secrets in that map. On shared systems, use
a private state/output directory and a restrictive umask such as `umask 077`.
Protect the HMAC key used for execution receipts separately from the receipts
it authenticates.

Read [SECURITY.md](SECURITY.md) before using Witness with sensitive source or
on a multi-user machine.

## Development

The repository has no third-party Go module dependencies. Run the local gate
before submitting a change:

```sh
gofmt -w cmd internal testdata/e2e
go build ./...
go vet ./...
go test ./... -count=1
```

Additional contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Witness is licensed under the [MIT License](LICENSE).
