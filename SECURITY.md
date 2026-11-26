# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/ergasterion-dev/aegolith/security/advisories/new>).

Do not open a public issue, pull request, or discussion for security problems.

Include the affected version or commit, steps to reproduce, and the impact you expect.
You should get an acknowledgement within 7 days.

We follow coordinated disclosure. We aim to ship a fix or a documented
mitigation within 90 days of the report, and we agree the disclosure date with
you; we ask that you keep the details private until then. If a fix lands
sooner, we publish the advisory with the fix and credit you unless you prefer
otherwise.

## What counts

A vulnerability in Aegolith itself: a panic or crash, unbounded CPU or memory use on a crafted request, a way to make the firewall allow a request it documents that it blocks (a bypass of a rule that is meant to hold), a leak of full request values into a decision, snippet or log, or a flaw in an adapter.

Not a vulnerability, but welcome as a normal issue: a false positive (use the false-positive template), or an attack shape Aegolith does not detect that is not already listed in the [threat model](docs/threat-model.md).

## Supported versions

Aegolith is alpha. Only the latest commit on `main` receives fixes.
