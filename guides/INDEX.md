# Field Guides - INDEX

> Reference material for the bug classes AI coding assistants generate most often.
> Each guide follows the same shape: what it looks like, why AI tools generate it,
> why it is dangerous, how to check your own app, the fix, a checklist, and a prompt
> you can hand to an assistant.
>
> Source: [The Lazy Developer](https://www.thelazydeveloper.org/resources) · retrieved 2026-07-20.
> Stored verbatim from the source, with one change: em and en dashes are replaced by hyphens (house rule, 2026-11-10). Do not edit the bodies otherwise; when re-pulling from the source, apply the same replacement.

---

## Guides

| Guide | Covers | Audit rules |
|---|---|---|
| [securing-endpoints.md](securing-endpoints.md) | Endpoints with no auth check, identity trusted from the request body, internal endpoints assumed private, email header injection | `AUTHZ-001` `AUTHZ-002` `AUTHZ-004` `VAL-002` |
| [authorization-idor.md](authorization-idor.md) | Authenticated-but-not-authorized handlers, object-level access control, cache keys that skip authorization | `AUTHZ-003` `AUTHZ-005` |
| [tenant-isolation-tests.md](tenant-isolation-tests.md) | Cross-customer reads and writes, customer uploads replacing staff records, account shapes that escape tenant scoping, sign-in limits that reset. Test templates, because no scanner sees these. Original to this repo | `AUTHZ-011` `AUTHZ-013` |
| [form-validation.md](form-validation.md) | Zod schemas, XSS sanitization, server-side re-validation, structured error responses | `VAL-001` |

## How these connect to the audit

Every rule below was written against a specific section of a guide, so a finding
always has somewhere to send you.

| Rule | Severity | Kind | What it means |
|---|---|---|---|
| `AUTHZ-001` | CRITICAL | analyzer | Handler performs a side effect with no authentication check anywhere in its body |
| `AUTHZ-002` | CRITICAL | pattern | Identity (`userId`, `email`, `role`) read from the request instead of a verified session |
| `AUTHZ-003` | CRITICAL | analyzer | IDOR - authenticated handler acts on a caller-supplied object ID with no ownership check |
| `AUTHZ-004` | HIGH | pattern | Secret compared with `===` instead of `crypto.timingSafeEqual` |
| `AUTHZ-005` | HIGH | pattern | Cache key not scoped to the requesting user, so a cache hit bypasses authorization |
| `AUTHZ-011` | HIGH | analyzer | Python (FastAPI/Flask) handler performs a side effect with no authentication check |
| `AUTHZ-013` | HIGH | analyzer | Python handler acts on a caller-supplied ID with no owner or tenant check |
| `WEB-001` | HIGH | pattern | Auth token written to `localStorage` / `sessionStorage` |
| `WEB-002` | MEDIUM | project | nginx server block with no Content-Security-Policy anywhere in the project |
| `VAL-001` | HIGH | analyzer | Request body reaches a side effect without a schema parse |
| `VAL-002` | CRITICAL | pattern | Raw email header built by interpolation - CRLF injection makes it an open relay |
| `INJ-003` | HIGH | pattern | `dangerouslySetInnerHTML` - sanitize the HTML first (see [form-validation.md](form-validation.md), section 2, XSS Sanitization) |

### INJ-003 and the shadcn chart component

The stock shadcn `components/ui/chart.jsx` reports INJ-003, correctly: its `ChartStyle`
writes the `id` prop and the `ChartConfig` colours into a `<style>` element unescaped,
and under server rendering a value holding `</style>` breaks out of the style tag. If
your chart config and ids are developer constants, never user input, record that with a
per-rule allowlist line so every other rule still runs on the file:

```
src/components/ui/chart.jsx  [INJ-003]  # reason: stock shadcn ChartStyle; ChartConfig and id are developer constants, never user input
```

Manual chapter 06 ("shadcn chart.jsx and INJ-003") has the full reasoning.

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
