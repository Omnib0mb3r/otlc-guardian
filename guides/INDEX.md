# Field Guides — INDEX

> Reference material for the bug classes AI coding assistants generate most often.
> Each guide follows the same shape: what it looks like, why AI tools generate it,
> why it is dangerous, how to check your own app, the fix, a checklist, and a prompt
> you can hand to an assistant.
>
> Source: [The Lazy Developer](https://www.thelazydeveloper.org/resources) · retrieved 2026-07-20.
> Stored verbatim. Do not edit the bodies; re-pull from the source instead.

---

## Guides

| Guide | Covers | Audit rules |
|---|---|---|
| [securing-endpoints.md](securing-endpoints.md) | Endpoints with no auth check, identity trusted from the request body, internal endpoints assumed private, email header injection | `AUTHZ-001` `AUTHZ-002` `AUTHZ-004` `VAL-002` |
| [authorization-idor.md](authorization-idor.md) | Authenticated-but-not-authorized handlers, object-level access control, cache keys that skip authorization | `AUTHZ-003` `AUTHZ-005` |
| [form-validation.md](form-validation.md) | Zod schemas, XSS sanitization, server-side re-validation, structured error responses | `VAL-001` |

## How these connect to the audit

Every rule below was written against a specific section of a guide, so a finding
always has somewhere to send you.

| Rule | Severity | Kind | What it means |
|---|---|---|---|
| `AUTHZ-001` | CRITICAL | analyzer | Handler performs a side effect with no authentication check anywhere in its body |
| `AUTHZ-002` | CRITICAL | pattern | Identity (`userId`, `email`, `role`) read from the request instead of a verified session |
| `AUTHZ-003` | CRITICAL | analyzer | IDOR — authenticated handler acts on a caller-supplied object ID with no ownership check |
| `AUTHZ-004` | HIGH | pattern | Secret compared with `===` instead of `crypto.timingSafeEqual` |
| `AUTHZ-005` | HIGH | pattern | Cache key not scoped to the requesting user, so a cache hit bypasses authorization |
| `VAL-001` | HIGH | analyzer | Request body reaches a side effect without a schema parse |
| `VAL-002` | CRITICAL | pattern | Raw email header built by interpolation — CRLF injection makes it an open relay |

`analyzer` rules use the per-file route-handler analyzer in
[`../security/03-audit.js`](../security/03-audit.js) rather than a regex, because
they describe the *absence* of a check inside a block. A regular expression cannot
express "this is missing from within these braces".

## Adding a guide

1. Drop the markdown in this directory with the provenance header the others carry.
2. Add a row to the Guides table above.
3. If any part of it is mechanically checkable, add the rule to `security/03-audit.js`
   with a comment pointing back at the guide, plus a firing test **and** a silent test
   in `tests/audit.test.js`.
4. Add the finding-to-guide mapping to `skill/SKILL.md`.

A guide with no rule is still worth keeping. A rule with no test is not.
