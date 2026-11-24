## What and why

<!-- One or two sentences. Link the issue: Fixes #123 -->

## Checklist

- [ ] Tests added or updated (table-driven), `make ci` passes
- [ ] Detector changes include true positives and the false-positive shapes the rule must not touch
- [ ] Corpus cases added for a new rule or a fixed false positive; the gates did not regress (`make corpus`)
- [ ] `make bench` before and after for changes on a hot path
- [ ] No new dependencies in the core module, or the justification is added to `docs/architecture.md`
- [ ] No real customer data or secrets anywhere (code, tests, corpus, commit messages)
- [ ] Conventional commit messages
