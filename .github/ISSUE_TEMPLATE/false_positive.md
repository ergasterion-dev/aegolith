---
name: False positive
about: Aegolith blocked or flagged a legitimate request
labels: false-positive
---

A false positive is the most serious kind of bug here. Thank you for reporting it.

**Do not paste real customer data.** Replace names, numbers and addresses with made-up ones that keep the same shape (the characters that triggered the rule are what matter).

## Rule

The rule ID from the decision (for example `AEG-CMDI-001`):

## The request

Method, path, and the field that was flagged, with a made-up value that still triggers it:

```text
POST /api/v1/orders
note: "..."
```

## Your configuration

Mode, whether the field is declared in a route policy and as which type, and any exclusions or `rule_actions` you already use.

## What you expected

Why this value is legitimate for your API.

## Workaround

Did an exclusion (`rule`, `route`, `field`) or declaring the field with a stricter type fix it for you?

## Version

Commit SHA or tag:
