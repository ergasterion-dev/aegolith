# Contributing to Aegolith

Thanks for helping. Aegolith is pre-alpha, so the design is still moving. For anything bigger than a small fix, open an issue first so we can agree on the approach before you write code.

## Ground rules

- **Security issues go through [private reporting](https://github.com/ergasterion-dev/aegolith/security/advisories/new)**, never public issues or PRs. See [SECURITY.md](SECURITY.md).
- **A false positive is worse than a missed probe the backend would 404 anyway.** A change that blocks a legitimate request is a bug; a change that adds recall at the cost of one needs a very good reason.
- **Stay inside the budget.** Aegolith aims for tens of microseconds per typical request. A feature that costs more is off by default or out.
- **No CRS clone.** Generic rules only where the field is free text. Typed fields are validated, not scanned for everything.
- **Never commit real customer data**, secrets or content from a real incident. That includes tests, the corpus and commit messages. Use made-up values with the same shape.
- **Never copy code from GPL or AGPL projects.** Ideas only. Patterns adapted from the OWASP Core Rule Set (Apache-2.0) keep attribution in [NOTICE](NOTICE).

## Dependencies

The core module depends on the standard library and `github.com/corazawaf/libinjection-go` only. Fiber lives in `adapters/fiberv2`, its own module, so the core never pulls Fiber or fasthttp. Adding any other dependency to the core needs a written justification in [docs/architecture.md](docs/architecture.md) in the same PR.

## Development

Requirements: Go (see `go.mod`) and `make`.

```sh
make test         # go test -race, then the plain run, in both modules
make test-quick   # go test ./... in both modules, no -race
make vet          # go vet in both modules
make fmt          # gofmt -w on tracked and untracked Go files
make corpus       # the attack and legitimate corpus, with the per-category table
make bench        # benchmarks with allocations, both modules
make perf         # latency budget (p99 < 50 µs); wall-clock, never under -race
make fuzz-quick   # every fuzz target for FUZZTIME (default 10s) each
make ci           # fmt-check, vet, test, corpus: what must pass before you push
```

Install the pre-commit hook once (it runs `make fmt-check vet test-quick`):

```sh
ln -sf ../../scripts/pre-commit .git/hooks/pre-commit
```

Do not bypass it. Timing checks are strict only with `AEGOLITH_PERF=1` and are skipped under `go test -short`, so a busy machine does not fail the normal run.

There are no GitHub Actions workflows in this project and none will be accepted. CI is `make ci` plus the hook.

## Code style

- `gofmt` clean; `go vet` clean.
- Wrap errors with context: `fmt.Errorf("policy: route %d: %w", i, err)`. Never swallow them.
- Table-driven tests in every package.
- No global mutable state; the `Firewall` is immutable and safe for concurrent use.
- Never log full request values. Use `model.Redact` for snippets and `model.SafeName` for field names.
- No panics out of the middleware. Detectors are pure, linear-time functions of one value.

## Commits and pull requests

- Use [conventional commits](https://www.conventionalcommits.org): `fix(detect): narrow CmdI prose guard`.
- Keep PRs focused and include tests. For a change to a detector, include the corpus gates (`make corpus`) before and after.
- Every PR needs a maintainer review.

## Add a detector or fix a false positive

The full recipe, including how the prefilter and the corpus fit in, is in [docs/architecture.md](docs/architecture.md#how-to-add-a-detector-and-a-corpus-case). The short version: write the failing test first, with the false-positive shapes beside the true positives; add the detector as a linear pure function; add corpus cases; run `make ci`.

## Add a corpus case

The corpus is how Aegolith is measured, and a new case is the most useful small contribution. You don't need to know the engine.

- A **legitimate** request that Aegolith wrongly flags: add a line to `testdata/corpus/legit.extra.jsonl`.
- An **attack** Aegolith misses: add it to `testdata/corpus/source/attacks.sh` in the existing style, with its category.

Then regenerate and run:

```sh
sh testdata/corpus/gen.sh     # needs python3
make corpus
```

The line format and the current known misses are in [testdata/corpus/README.md](testdata/corpus/README.md). A case that Aegolith gets wrong today is welcome, and often more useful than one it gets right. Say so in the pull request.

Rules for cases:

- **Never use real customer data or real incident content.** Make up values that keep the characters that matter.
- Add legitimate cases before you narrow a rule, so the fix is provably tested.
- The gates are in `corpus_test.go`. If your case changes a total, update the constants there in the same PR.

## Reporting a false positive

Use the **False positive** issue template. It asks for the rule ID, a made-up request that still triggers it, and your configuration. If an exclusion (`rule` x `route` x `field`) or a stricter field type fixed it for you, say so.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
