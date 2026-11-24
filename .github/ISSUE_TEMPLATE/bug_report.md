---
name: Bug report
about: Something in Aegolith behaves incorrectly (not a false positive; use the other template for that)
labels: bug
---

**Security problem?** Stop here and [report it privately](https://github.com/ergasterion-dev/aegolith/security/advisories/new).

## What happened

What you did, what you expected, and what you got instead.

## Steps to reproduce

A minimal `Config` (or JSON file), the request, and the decision you got. A Go test is ideal.

## Where

- [ ] core (`Inspect`, config)
- [ ] a detector or rule (give the rule ID)
- [ ] route policies / typed fields
- [ ] `net/http` middleware
- [ ] Fiber v2 middleware
- [ ] not sure

## Version

Commit SHA or tag:

## Environment

OS, Go version, server (net/http or Fiber/fasthttp), mode (monitor or enforce).

## Logs

Relevant output from your decision hook. Aegolith snippets are redacted; remove anything else that is private before pasting.
