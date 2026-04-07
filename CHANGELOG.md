# Changelog

All notable changes to OTLC Guardian. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Centralized audit allowlist** at `security/.audit-allowlist` with required reason field. Per-file `otlc-guardian:audit-exempt` marker still supported as an end-user opt-in. Allowlist is checked first so it takes precedence.
- **Audit exemption visibility** — every `guardian audit` run prints the count and full list of exempted files. CI now writes the exemption count to the GitHub Actions step summary.
- **52 new automated tests** across `tests/init.test.js` (26 — covers all merge functions, idempotency, JSON safety, matcher set comparison, inline-comment dedupe) and `tests/hook.test.js` (26 — both Claude Code hooks tested as subprocesses with full watch list and web content guard coverage). Total: 90/90 passing.
- **`guardian list-watched`** — debug command that prints the effective hook watch list for the current project, including custom paths and ignores from `.claude/settings.json`.
- **`guardian update`** — alias for `guardian init`. Both are merge-safe and idempotent; `update` is the natural verb after pulling a new Guardian release.
- **`web-content-guard.mjs`** — PostToolUse hook on `WebFetch`/`WebSearch` that scans fetched content before Claude reasons about it. Catches indirect prompt injection at the entry point.
- **Configurable hook watch list** via `otlcGuardian.watchPaths` / `ignorePaths` / `extendDefaults` block in `.claude/settings.json`.
- **Doc-exempt marker** (`otlc-guardian:doc`) for security spec files that legitimately discuss injection patterns.
- **Python parity**: `SECRET_PATTERNS` (9 entries), v1.0.1 normalizer (NFKC + invisible-strip + URL/base64 decode), and `guard_output()` added to `security/injection_guard.py`.
- **`GuardianConfigError`** — new error class thrown by `validateEnv()` when required env vars are missing.
- **CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, CODEOWNERS, .github/ISSUE_TEMPLATE, PULL_REQUEST_TEMPLATE.md, .editorconfig, .gitattributes**.

### Changed
- **Restructured** all source files from a flat root layout into the `bin/`, `security/`, `tests/`, `.claude/hooks/`, `.github/workflows/` directories that the code, docs, and `package.json` were already referencing. Without this, `npm install -g .` and every `guardian` subcommand failed to resolve their source files.
- **Default hook watch list dramatically broader** — now covers `.planning/`, `.gsd/`, `.plans/`, `.claude/`, `.cursor/`, `.continue/`, `.aider/`, `.windsurf/`, every `*/memory/` directory, plus `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.aider.conf.yml`, `copilot-instructions.md`, `MEMORY.md`, and `.env*`. Previously only watched `.planning/`, `.claude/`, `CLAUDE.md`, and `.env`.
- **Hook patterns sourced from main module** — `.claude/hooks/injection-guard-hook.mjs` (renamed from `.js`) now imports `INJECTION_PATTERNS` directly from `security/01-injection-guard.js` instead of inlining a stale 17-pattern subset. Drift is now impossible.
- **`mergeClaudeSettings` no longer overwrites invalid JSON** — aborts with a clear error and points the user to the reference copy. Previously a stray trailing comma during a mid-edit save would silently replace the user's file with Guardian defaults.
- **`mergeClaudeSettings` matcher comparison is set-based** — `Edit|Write` and `Write|Edit` are recognized as the same block. Guardian no longer creates a parallel `Write|Edit` block alongside a user's existing `Edit|Write`.
- **`mergeClaudeSettings` handles multiple events** — registers PreToolUse and PostToolUse hooks in one pass.
- **`mergeGitignore` strips inline comments** before deduping — a user line like `.env # local secrets` correctly suppresses Guardian's own `.env` entry instead of producing a duplicate.
- **`validateEnv` throws instead of `process.exit(1)`** — library code never terminates the process. Callers catch `GuardianConfigError` and decide how to fail.
- **Rate limiter Redis swap point documented** in `security/02-code-security.js`.
- **`guardian check` now smoke-tests the hook** — pipes a known-bad payload through and asserts it fires. Also detects Python projects and conditionally requires `security/injection_guard.py`.

### Fixed
- **Audit `--json` mode contaminated stdout** — `runAudit()` called `console.info` for the status header (`SAFETY AUDIT STARTING`, target, file count, exempt list) before writing the JSON. `console.info` writes to stdout, so the captured file in CI was `[status text] + [JSON object]` and `JSON.parse` choked on the leading emoji. Fixed by routing status to stderr in JSON mode (standard Unix convention — diagnostic stream vs result stream). The CI `Audit exemption visibility` step now produces clean parseable JSON.
- **`make_fastapi_guard` in `injection_guard.py`** had a bug where the inner dependency function's `request` parameter had no type hint, so FastAPI's dependency injection could not provide it. Adding the Request type hint resolves the issue.
- **Audit script self-detection false positives** — the audit's own pattern definitions matched themselves (`/eval\s*\(/`, `dangerouslySetInnerHTML`, `console.log` in CLI/logger). Resolved via the new exemption mechanisms.
- **CI workflow had no test step** — only the audit ran. Now runs `injection-guard.test.js`, `init.test.js`, `hook.test.js`, and `guardian check` before the audit.

### Removed
- **`devneural.jsonc`** from the public repo (project-owner metadata for an unrelated tool). Kept locally via `.git/info/exclude`.

### Security
- The audit-exempt mechanism is now reviewable by design. See `security/.audit-allowlist` (required reason field, one-line diffs in PR review) and the new audit summary (counts and full list printed every run). The per-file marker remains as an end-user convenience.

---

## [1.1.0] — initial public release

First public release. Core capabilities:

- Prompt injection guard (28 patterns + Unicode/encoding bypass defenses)
- Code security utilities (secure headers, rate limiter, structured logger, request ID, error handler, health check)
- Safety audit CLI (`guardian audit`)
- Claude Code behavior rules (`CLAUDE.md`) and approved stack standards (`STANDARDS.md`)
- `guardian init` merge-safe installer
- Python parity module
- GitHub Actions CI workflow
