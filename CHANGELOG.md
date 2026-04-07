# Changelog

All notable changes to OTLC Guardian. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-04-07

Two new features land in this minor release — an OWASP-aligned SQL injection
defense helper and a surgical `guardian uninstall` command that closes the
merge-safety loop left open in 1.1.1. Both are net-new surface area with their
own test suites; no behavior changes to the 1.1.1 code.

### Added

- **`security/04-sql-guard.js`** — a zero-dep `sql\`\`` tagged template literal
  that makes parameterized queries the path of least resistance. Auto-expands
  `${}` interpolations into placeholders and returns a `{ text, values, driver }`
  object compatible with `pg`, `mysql2`, and `better-sqlite3`. Both dialects
  are first-class: the default `sql` export is postgres-bound with
  `.toMysql()` / `.toSqlite()` / `.toPostgres()` conversion methods, and
  `createSqlHelper({ driver })` returns a natively-bound tag for projects
  that prefer the factory pattern. Nested `sql\`\`` composition is supported
  end-to-end — interpolating one query into another inlines its compiled
  parts and renumbers placeholders automatically. Dynamic table/column
  interpolation goes through `sql.identifier(name, allowList)` with three
  layers of validation: the allow-list must be a non-empty array, the
  identifier must match a strict safe-shape regex (letters/digits/underscore,
  optional single-dot schema prefix), and it must be a member of the allow-
  list. The regex check runs even when the name is on the allow-list, so a
  caller who accidentally adds a malicious string to the list still has the
  query aborted (defense in depth). No runtime blocklist scanner, no keyword
  detection, no input filtering — OWASP's SQL Injection Prevention Cheat
  Sheet explicitly warns that input filtering is not a primary defense
  against SQL injection, and Guardian's static audit rules
  (`INJ-004` / `INJ-005` / `INJ-006` in `security/03-audit.js`) already catch
  the bad concatenation pattern statically. Wired into
  `package.json` exports as `./sql` and mentioned in `STANDARDS.md` as the
  zero-dep fallback for projects that cannot adopt Prisma. Coverage lives
  in `tests/sql-guard.test.js` — 40 tests across seven security properties
  (parameterization, literal-text preservation, injection-payload
  pass-through, identifier escape hatch, nested composition, zero-scanning,
  dialect-conversion purity).

- **`guardian uninstall` command** — the surgical inverse of `guardian init`
  that closes the merge-safety loop on the uninstall side. The symmetry
  contract is `init && uninstall == no-op` on a well-formed project: a
  project with custom content in every managed file (`CLAUDE.md`, `AGENTS.md`,
  `GEMINI.md`, `STANDARDS.md`, `.gitignore`, `.env.example`, and
  `.claude/settings.json` with a pre-existing non-Guardian hook) must be
  byte-for-byte equal to its original state after running
  `guardian init && guardian uninstall`. The command marker-strips merged
  files (removing only the content between the `<!-- OTLC-GUARDIAN-START -->`
  and `<!-- OTLC-GUARDIAN-END -->` markers, preserving every line the user
  wrote), surgically removes Guardian's hook entries from
  `.claude/settings.json` (using the same set-based matcher comparison
  that `mergeClaudeSettings` uses on the init side), and byte-compares
  pure-Guardian copied files in `security/`, `.claude/hooks/`, and `.github/`
  against the source-of-truth at `ROOT` — deleting only files that are
  byte-identical to the shipped template, and keeping user-modified copies
  with a "customized" note. Never deletes a file whose marker is absent
  (provenance can no longer be verified), never touches a file Guardian
  did not create (e.g. a user's own `security/my-custom-rules.js` is
  preserved), and refuses to modify a malformed `.claude/settings.json`
  with the same "refuse to touch what we cannot reason about" contract
  used by `mergeClaudeSettings`. A `--dry-run` flag previews the actions
  without touching disk. Wired into `bin/guardian.js` as the `case "uninstall":`
  router branch with a try/catch that converts the invalid-JSON throw into
  a clean non-zero exit. Coverage lives in `tests/uninstall.test.js` —
  11 tests covering the full contract: symmetry, idempotency, partial
  state (manual marker removal), pre-existing AGENTS.md (Codex user
  survival), custom hooks alongside Guardian's, invalid JSON refusal,
  custom security files, customized Guardian files, dry-run, CLI wiring,
  and the empty-project no-op. This fixes the known data-loss foot-gun
  shipped in 1.1.1 where `SETUP.md` told users to
  `rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md` — an instruction that
  would destroy any content the user wrote above Guardian's marker block.
  PR #4 already shipped the merge-safe manual documentation in
  `SETUP.md § Uninstalling`; 1.2.0 ships the automated command the docs
  have been pointing at.

### Changed

- **README.md** — "The Six Commands" → "The Seven Commands" with a full
  block for `guardian uninstall` including the `--dry-run` flag, the
  marker-strip / byte-compare strategy, and the symmetry contract
  reference. One-line mention of the SQL helper added to the
  "What You Get" audit CLI section.
- **`SETUP.md § Uninstalling`** — replaces the "command is on the roadmap"
  line with "run `guardian uninstall` — it does every step below
  automatically." The manual marker-based procedure is preserved as a
  fallback for users who want to see exactly what the command does.
- **`STANDARDS.md § Database (SQL)`** — adds a one-paragraph mention of
  the `sql\`\`` helper as the zero-dep fallback for projects that cannot
  adopt Prisma.
- **`FAQ.md`** — adds "How do I uninstall Guardian from a project?" under
  Installation, updates the "three security files" answer to "four"
  with `04-sql-guard.js` in the list, and adds a new "Why doesn't
  Guardian include a SQL injection runtime scanner?" Q explaining the
  OWASP-aligned design decision.
- **`package.json`** — `"./sql": "./security/04-sql-guard.js"` added to
  `exports`. `npm test` script extended to include `tests/sql-guard.test.js`
  and `tests/uninstall.test.js`. New `test:sql` and `test:uninstall`
  shortcuts for running each suite in isolation.

### Fixed

- **Stale version string in `bin/guardian.js:121`** — the `showHelp()`
  footer was still printing `Version 1.1.0` after the 1.1.1 bump.
  Bumped to 1.2.0 as part of this release.

---

## [1.1.1] — 2026-04-06

Pre-ship security and correctness pass. Every item below was surfaced by an
adversarial review of the 1.1.0 code and docs on 2026-04-06, verified with live
proofs-of-concept in an isolated sandbox, and fixed with tests that lock in the
regression so it cannot slip back.

### Security

- **Shell-injection fix in `guardian audit`** — `bin/guardian.js:128` (pre-1.1.1)
  spliced `args.slice(1).join(" ")` into an `execSync` template literal. Any
  argument containing `;`, `&&`, `|`, backticks, or `$()` was executed by the
  shell. Live PoC: `guardian audit ". && echo INJECTED > pwned.txt"` created
  the file. **Replaced** with `spawnSync("node", [auditScript, ...args.slice(1)], { shell: false })`
  so the shell never parses arguments at all. The same fix was applied to
  `smokeTestHook()`, which used the same anti-pattern.
- **Outdated OpenAI / Anthropic key regex across all three modules** — the
  pre-1.1.1 SEC-001 pattern was `/sk-[a-zA-Z0-9]{20,}/`, which silently missed
  both current-format OpenAI project keys (`sk-proj-...`) and Anthropic Claude
  keys (`sk-ant-api03-...`) because the hyphen after the provider tag is
  outside `[a-zA-Z0-9]`. A leaked current-generation key would sail through
  `guardOutput()` with zero findings and through `guardian audit` with zero
  findings. **Replaced** with provider-specific rules (`SEC-001` for
  `sk-proj-`, `SEC-010` for `sk-ant-api`, `SEC-001b` as a negative-lookahead
  legacy fallback). Mirrored across `security/01-injection-guard.js`,
  `security/03-audit.js`, and `security/injection_guard.py`. Regression tests
  live in `tests/injection-guard.test.js` and `tests/audit.test.js`.
- **Missing raw SQL detection rule** — README claimed "raw SQL" detection in
  two places but `security/03-audit.js` had no SQL rule at all. **Added**
  `INJ-004` (string-concat SQL), `INJ-005` (template-literal SQL with `${}`
  interpolation), and `INJ-006` (Python f-string and `%` formatting SQL).
  Scanner extended with a `wholeFile: true` flag because multi-line SQL
  queries don't fit the line-by-line scanner. Tests in `tests/audit.test.js`.
- **`ERR-001` silent-catch false negatives** — the pre-1.1.1 regex required
  literal empty braces, so `catch (e) { /* silent */ }` and multi-line
  comment-only catch bodies passed the audit clean. **Rewritten** to accept
  any sequence of whitespace, `//` line comments, and `/* ... */` block
  comments inside the catch body, running in `wholeFile` mode so multi-line
  cases match.
- **`SEC-011` — new rule for connection strings with embedded credentials**
  — `postgres://user:pass@host`, `mongodb+srv://...`, `redis://:pw@...`,
  `amqp://...`. The pre-1.1.1 audit ignored these even though they are
  hardcoded secrets in every meaningful sense. Mirrored across all three
  modules. User part is `*` so the redis "password-only, no user" variant
  matches.
- **ReDoS hardening on `INJ-027` / `INJ-028`** — the pre-1.1.1 patterns
  (`<!--.*(?:ignore|override|system).*-->` and the block-comment equivalent)
  used greedy `.*` before and after the alternation — the classic
  catastrophic-backtracking shape. Long inputs without a closing delimiter
  could burn seconds of CPU. **Rewritten** with `[\s\S]*?` (lazy, line-
  spanning) so the engine fails fast. Regression test asserts a 20 KB
  pathological payload completes in under 1 second.
- **`scan()` input length cap** — `guardInput()` has always enforced its own
  `maxLength` (default 4000), but `scan()` is exported and used directly by
  the audit CLI, the hooks, and third-party callers. Without a cap, a huge
  string passed to any direct caller could burn CPU inside the normalizer
  (which appends URL-decoded and base64-decoded copies onto the original).
  **Added** `MAX_SCAN_LENGTH = 100_000` to both the JS and Python `scan()`
  functions with a visible truncation warning. Tests cover the
  mega-input-doesn't-hang and injection-still-detected-in-first-100KB cases.

### Fixed

- **`guardian scan` crashed on Windows with `ERR_UNSUPPORTED_ESM_URL_SCHEME`**
  — `bin/guardian.js:148` passed a raw Windows path (`C:\...`) to dynamic
  `import()`, which requires a `file://` URL on Windows. Ironically
  `pathToFileURL` was already imported at the top of the file but never used
  here. **Fixed** by wrapping the path with `pathToFileURL(...).href`. This
  was a 100% reproducible crash on every `guardian scan` invocation on
  Windows — the single most customer-visible bug of the 1.1.0 release.
- **`guardian init` shipped Guardian's internal files into user projects** —
  prior releases copied `security/__pycache__/injection_guard.cpython-*.pyc`
  (Python bytecode cache, version-mismatched against any interpreter other
  than the one used to build the cache) and the entire Guardian-internal
  `tests/` directory (four test files that exercise Guardian internals and
  are useless to end users). **Fixed** by (a) adding a `COPY_IGNORE` set in
  `copyDirSafe()` for `__pycache__`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `.DS_Store`, `Thumbs.db`, and `node_modules`, and (b)
  removing the `runInit()` call that copied `tests/` at all.
- **`STANDARDS.md` advertised the wrong version** — the file header claimed
  `Version: 1.2.0` while every other file in the repo agreed on `1.1.0`. The
  JSON health-check example at line 778 also used `1.2.0`. **Fixed** by
  updating the header to `1.1.1` and replacing the JSON example version with
  a generic `1.0.0` placeholder plus a note clarifying the field is the
  reader's application version, not Guardian's.
- **Windows path normalization bug in PreToolUse hook** — the hook normalized
  `\` to `/` at the top of `isWatchedPath()` and then checked
  `normP.endsWith("\\")` a few lines later — dead code that could never be
  true after normalization. On Windows, a user who set
  `watchPaths: [".myplanning\\"]` in `.claude/settings.json` would have the
  trailing slash silently stripped and fall into the file-basename branch
  instead of the directory-prefix branch. **Fixed** by detecting the user's
  intent from the raw (pre-normalization) string and always stripping
  trailing separators consistently.
- **`GEMINI.md` was watched but never provisioned** — the hook watch list
  (and the old `list-watched` command) included `GEMINI.md`, but
  `guardian init` never created one. The template defended an ecosystem it
  did not seed. **Fixed** by adding `GEMINI.md` to the repo root, wiring it
  into `runInit()` as a `mergeMd` call (same idempotent marker-sealed merge
  pattern as `CLAUDE.md` and `AGENTS.md`), and reporting it in the
  `editorCoverage` table and `guardian check` output.
- **README underplayed `STANDARDS.md`** — the approved technology stack file
  is 80% of Guardian's day-to-day value but was mentioned only in passing.
  **Rewrote** README to give `STANDARDS.md` a dedicated section with a
  one-screen preview of the stack table (Node/TS + Python, frontend + auth
  + testing + observability), and expanded the "What Guardian Actually Is"
  section to cover every file in the package — the four behavior files and
  the four runtime-security files — not just the audit CLI.

### Added

- **`tests/audit.test.js`** — 16 new subprocess-based tests for the audit
  rule set. Verifies every new rule fires on the fixtures it should fire on,
  does not fire on legitimate code, and that the end-to-end regression
  fixture from the 1.1.1 pre-ship review (hardcoded key + connection string
  + SQL concat + silent catch + console.log) now produces five findings
  instead of the one it produced before the fixes.
- **Scanner `wholeFile: true` flag** — extends `scanFile()` in
  `03-audit.js` to run a rule against the entire file content as one string
  rather than line-by-line. Required for any pattern that legitimately spans
  multiple lines (the new silent-catch rule, the new SQL rules). Match line
  numbers are computed from the match offset so reports still point at a
  specific line.
- **Uninstall documentation** in `SETUP.md` and `README.md` — previously
  nothing in the docs told users how to remove Guardian from a project.
- **Privacy statement** in `README.md` — explicit confirmation that Guardian
  does not collect data, does not phone home, and has zero runtime
  dependencies. Users can verify by grepping the source tree.
- **Defense-in-depth disclaimer** at the top of `README.md` — honest framing
  of what Guardian is (a strong baseline) and what it is not (a comprehensive
  security solution). Points at `SECURITY.md` for the full threat model.

### Changed

- **Version bump** from `1.1.0` to `1.1.1` across `package.json`, `README.md`
  badge, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `STANDARDS.md`, `FAQ.md`,
  `SETUP.md`, `security/01-injection-guard.js`, `security/03-audit.js`, and
  `security/injection_guard.py`. This is a security patch release.
- **`editorCoverage()` reports Gemini CLI** — the table now has a row for
  Gemini CLI keyed off the presence of `GEMINI.md`, mirroring the
  `AGENTS.md`-keyed rows for the other non-Claude agents.
- **`copyDirSafe()` skip list** — see "Fixed" above for the `COPY_IGNORE` set.

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
- **Centralized audit allowlist** at `security/.audit-allowlist` with required reason field. Per-file `otlc-guardian:audit-exempt` marker still supported as an end-user opt-in. Allowlist is checked first so it takes precedence.
- **Audit exemption visibility** — every `guardian audit` run prints the count and full list of exempted files. CI writes the exemption count to the GitHub Actions step summary.
- **`guardian list-watched`** — debug command that prints the effective hook watch list for the current project, including custom paths and ignores from `.claude/settings.json`.
- **`guardian update`** — alias for `guardian init`. Both are merge-safe and idempotent; `update` is the natural verb after pulling a new Guardian release.
- **`web-content-guard.mjs`** — PostToolUse hook on `WebFetch`/`WebSearch` that scans fetched content before Claude reasons about it. Catches indirect prompt injection at the entry point.
- **Configurable hook watch list** via `otlcGuardian.watchPaths` / `ignorePaths` / `extendDefaults` block in `.claude/settings.json`.
- **Doc-exempt marker** (`otlc-guardian:doc`) for security spec files that legitimately discuss injection patterns.
- **Python parity**: `SECRET_PATTERNS` (9 entries), v1.0.1 normalizer (NFKC + invisible-strip + URL/base64 decode), and `guard_output()` added to `security/injection_guard.py`.
- **`GuardianConfigError`** — error class thrown by `validateEnv()` when required env vars are missing.
- **Restructured source tree** from a flat root layout into `bin/`, `security/`, `tests/`, `.claude/hooks/`, `.github/workflows/`.
- **Hook patterns sourced from main module** — `.claude/hooks/injection-guard-hook.mjs` imports `INJECTION_PATTERNS` directly from `security/01-injection-guard.js` instead of inlining a stale subset. Drift is now impossible.
- **`mergeClaudeSettings` no longer overwrites invalid JSON** — aborts with a clear error and points the user to the reference copy.
- **`mergeClaudeSettings` matcher comparison is set-based** — `Edit|Write` and `Write|Edit` are recognized as the same block.
- **`mergeClaudeSettings` handles multiple events** — registers PreToolUse and PostToolUse hooks in one pass.
- **`mergeGitignore` strips inline comments** before deduping — a user line like `.env # local secrets` correctly suppresses Guardian's own `.env` entry.
- **`validateEnv` throws instead of `process.exit(1)`** — library code never terminates the process. Callers catch `GuardianConfigError` and decide how to fail.
- **`guardian check` smoke-tests the hook** — pipes a known-bad payload through and asserts it fires. Detects Python projects and conditionally requires `security/injection_guard.py`.
- **Audit `--json` mode no longer contaminates stdout** — status lines go to stderr in `--json` mode (standard Unix convention). CI now produces clean parseable JSON.
- **`make_fastapi_guard` in `injection_guard.py`** — fixed a bug where the dependency's `request` parameter had no type hint so FastAPI couldn't provide it.
- **Audit script self-detection false positives** — the audit's own pattern definitions matched themselves. Resolved via the exemption mechanisms.
- **CI workflow runs the full test suite** before the audit.
- **CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, CODEOWNERS, .github/ISSUE_TEMPLATE, PULL_REQUEST_TEMPLATE.md, .editorconfig, .gitattributes** added.
