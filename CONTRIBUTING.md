# Contributing

Contributions are welcome through focused issues and pull requests.

## Development setup

Witness requires Go 1.23 or newer and Git. The repository intentionally has no
third-party Go module dependencies.

Before submitting a change, run:

```sh
gofmt -w cmd internal testdata/e2e
go build ./...
go vet ./...
go test ./... -count=1
```

Tests should be deterministic, local, and bounded. Add coverage for meaningful
behavioral partitions and trust boundaries; avoid duplicating the same guard
at every internal layer.

## Design constraints

Changes should preserve the project's core boundaries:

- Witness remains deterministic and model-free.
- It does not modify reviewed source or apply findings.
- Owner decisions remain explicit ledger events.
- Versioned JSON inputs are decoded strictly and fail closed.
- Digests and retained evidence are rederived from authoritative inputs.
- The harness reports its actual containment and never claims to be a stronger
  sandbox than the host provides.

When changing a wire contract, document the version impact and add compatibility
tests where an older contract remains supported.

## Security reports

Do not file suspected vulnerabilities as public issues. Follow
[SECURITY.md](SECURITY.md) instead.
