# Security Policy

## Reporting a vulnerability

If you find a security issue in OTLC Guardian, **please do not open a public GitHub issue**. Public disclosure before a fix is available puts every Guardian user at risk.

Instead, report it privately:

1. **Preferred:** [Create a GitHub security advisory](https://github.com/Omnib0mb3r/otlc-guardian/security/advisories/new) (drafts are private until you publish them).
2. **Alternative:** Email `security@onthelevelconcepts.com` with the subject line `OTLC GUARDIAN SECURITY` and a description of the issue.

In your report, please include:

- A clear description of the issue
- The Guardian version (`package.json` → `version`) and commit SHA
- Reproduction steps — the smaller the test case, the faster the fix
- The impact you observed (what an attacker can do)
- Any suggested mitigation, if you have one

We aim to respond within **3 business days** and to ship a patched release within **14 days** for HIGH/CRITICAL issues. We will credit you in the CHANGELOG if you'd like.

---

## What counts as a Guardian security issue

| Yes | No |
|---|---|
| A way to bypass `guardInput()` with a payload that should have been blocked | A pattern in your application that Guardian doesn't catch (open a feature request instead) |
| A way to make `guardOutput()` leak a secret it should have blocked | An issue in your own application's auth, ORM, or input validation |
| A way to abuse `guardian init` to overwrite a user's file | A bug in `npm install` itself |
| A way to silently disable the audit (a marker bypass that isn't visible in the exempt summary) | An issue in a dependency we don't ship with |
| Code execution via `guardian audit` on a hostile codebase | An issue in Claude Code itself |
| An injection pattern that fires on legitimate text 100% of the time | An injection pattern that fires on legitimate text in *some* edge cases (open a feature request) |

---

## Threat model summary

OTLC Guardian is **defense in depth, not a single line of defense**. The runtime guard, the audit script, the hook, and the standards files work together. Each layer can be bypassed individually; the value comes from the combination plus the visibility of every detection.

Specifically:

- **The runtime guard** (`guardInput`/`guardOutput`) is the strongest layer. It runs at request time on every input/output, scans against 28 injection patterns and 9 secret patterns with NFKC normalization plus invisible-Unicode stripping plus URL/base64 decoding to defeat encoded bypasses. The output guard catches secrets the AI may inadvertently include in its response.
- **The Claude Code hooks** (`injection-guard-hook.mjs` + `web-content-guard.mjs`) are advisory only. They never block tool execution. They surface warnings into Claude's context so the model can choose to disregard hostile instructions in fetched web content or planning artifacts. By design they fail open — a broken hook never blocks legitimate work.
- **The audit script** (`guardian audit`) is a static-analysis pass meant for code review and CI. It is not a runtime defense.
- **The standards files** (`CLAUDE.md`, `STANDARDS.md`) shape Claude's behavior at session start. They are not a runtime defense.

A pattern-based scanner cannot achieve 100% detection. Guardian is a strong default that catches the publicly-known attack catalog plus the most common bypass tricks. For applications handling regulated data, engage a professional security firm in addition.

---

## The audit-exempt mechanism — is it a vulnerability?

Short answer: **no, but it's a controlled trust mechanism worth being explicit about.**

Two ways to exempt a file from `guardian audit` scanning:

1. **Per-file marker** (`otlc-guardian:audit-exempt`) — drop a comment in any file.
2. **Central allowlist** (`security/.audit-allowlist`) — one file, one line per exemption, **required reason field**.

For an attacker to abuse either mechanism, they need write access to your repository. If they have that, they can already do strictly worse things — modify the audit script itself, modify the patterns, add backdoors, change the CI workflow.

Defenses we ship to make abuse visible:

- **Allowlist takes precedence.** A file in both ends up reported as `[allowlist]`, which is the more reviewable mechanism.
- **Required reason field.** Allowlist entries without `# reason: ...` are loudly rejected at scan time.
- **Exemption summary printed every run.** `guardian audit` prints the count and full list of exempted files before any findings, so unexpected growth is impossible to miss.
- **CI step summary.** GitHub Actions writes the exemption count to the workflow summary so reviewers see it from the Actions tab.
- **CODEOWNERS suggested.** Repos that need stronger guarantees can require security-team review of any change to `security/.audit-allowlist` and `.claude/hooks/`.

If you find a way to add an exemption that does **not** show up in the summary or the allowlist — that **is** a Guardian security issue. Please report it.

---

## Out of scope

The following are not Guardian security issues:

- Bugs in user-supplied code that Guardian failed to catch (Guardian is not a substitute for security review)
- DoS attacks against the audit script via maliciously-large input files (the audit is a developer tool, not a public endpoint)
- Issues in third-party dependencies of *your* project that Guardian doesn't scan
- Issues in tools Guardian wraps (Gitleaks, npm audit, pip-audit) — please report those upstream

---

*OTLC Guardian · [onthelevelconcepts.com](https://onthelevelconcepts.com)*
