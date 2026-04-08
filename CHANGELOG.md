# Changelog

All notable changes to OTLC Guardian. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] — 2026-04-08

Audit blind-spot fixes plus release-readiness improvements. Two new
audit tests cover bypass patterns the pre-1.3.0 ruleset silently
missed; one new audit rule (`INJ-005b`) catches the variable-indirection
form of template-literal SQL; the existing `INJ-006` Python rule was
rewritten so it actually fires on real-world SQL containing inner
quoted literals (the most common case). Plus npm publish hygiene and
a GitHub Actions Node 20 deprecation fix.

Minor version bump (`1.2.4` → `1.3.0`) because rule additions and
behavior changes are not patches under semver — adding a new rule
that fires on previously-clean code is a feature, not a bugfix.

### Added

- **`INJ-005b`** — new CRITICAL rule that catches template-literal
  SQL with `${}` interpolation **regardless of how the variable is
  used**. The pre-1.3.0 `INJ-005` rule required the backtick template
  to be the first argument of `query|execute|exec|raw|prepare`, so a
  trivial two-line refactor bypassed it:
    ```js
    const sql = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(sql);   // INJ-005 misses this — no backtick at the call site
    ```
  Writing the dangerous template literal anywhere in source is
  independently a bug, whether the variable is then passed directly
  to `db.query(sql)` or through ten more levels of indirection.
  `INJ-005b` catches the **declaration site** instead of the call
  site. Both rules are kept; they're complementary. A direct call
  fires both — slightly redundant but harmless.

- **`package.json` `files` field** — explicit allowlist of what
  `npm publish` actually ships. Pre-1.3.0 the package fell back to
  `.gitignore` (which is the wrong tool for the job — `.gitignore`
  excludes things from git, not from npm). The new field ships:
  `bin/`, `security/`, `.claude/`, `.github/`, all the markdown
  docs, the LICENSE, the `.env.example`, and `.gitleaks.toml`.
  Tarball size: 148.3 kB unpacked, 39 files. Tests are still
  shipped because `guardian init` copies them into target projects
  as part of the setup.

### Fixed

- **`INJ-006` (Python f-string SQL) regex rewritten to handle inner
  quoted literals.** The pre-1.3.0 character class `[^"']*` excluded
  BOTH quote styles, so an f-string containing a literal like
  `WHERE name = 'admin'` — which is most real-world SQL — broke
  the match and the rule silently did nothing. Real-world Python
  code is full of these patterns and the audit was missing every
  one of them. New regex splits into quote-specific alternation
  branches: `f"..."` allows `'` inside, `f'...'` allows `"` inside.
  Same fix applied to the legacy `% formatting` branch.

- **GitHub Actions Node 20 deprecation warnings.** Bumped
  `actions/checkout@v4` → `@v6` (released Nov 2025) and
  `actions/setup-node@v4` → `@v6` (released Dec 2025). Both v6
  releases run on Node.js 24, removing the deprecation warning
  GitHub started emitting in late 2025. `gitleaks/gitleaks-action`
  pinned to `@v2.3.9` (the latest v2.x as of 2026-04-08) for
  reproducibility. GitHub's force-migration deadlines are
  2026-06-02 (force Node 24) and 2026-09-16 (Node 20 removed).

- **CI workflow now runs the full `npm test` script** instead of
  invoking each test file individually. Pre-1.3.0 the workflow had
  hardcoded `node tests/injection-guard.test.js` plus a few `if
  -f` guards for the others, which silently skipped any test file
  the workflow author forgot to add. The 1.2.4 release accidentally
  left `tests/audit.test.js` and `tests/sql-guard.test.js` out of
  the CI invocation list — both were running locally and via `npm
  test`, but CI was only running 4 of the 6 test files. Switching
  to `npm test` makes the CI invocation match what every developer
  runs locally, eliminating an entire class of "I forgot to add
  this test to CI" bugs.

### Changed

- **Audit allowlist (`security/.audit-allowlist`) gained two
  entries:** `security/04-sql-guard.js` and `tests/sql-guard.test.js`.
  The new `INJ-005b` rule correctly fires on the SQL helper's own
  JSDoc examples and test fixtures (38 findings on the helper alone)
  because they all demonstrate the unsafe `\`SELECT ... ${id}\`` form
  the helper exists to replace. Allowlist entries include the full
  reason field per the `.audit-allowlist` format contract — silent
  exemptions are forbidden.

### Verification

- `npm test` — all 6 test files green: injection-guard, init, hook,
  agents-md, **audit 48/48 (was 40/40 in 1.2.4)**, sql-guard 40/40
- `node security/03-audit.js .` — `No issues found` on the Guardian
  repo. **24 rules** (up from 23 in 1.2.4 — INJ-005b added).
  **7 allowlisted files** (up from 5).
- `node bin/guardian.js check` — 15 passed, 0 warnings, 0 missing
- 12-project real-world re-audit (DevNeural, NLT, omnibomber, autolisp,
  blkbom, Claude-Setup, conveyor-designer, conveyornum, devneural-projects,
  dev-template, Landmark40, skill-connections) shows **zero false
  positives from INJ-005b or the rewritten INJ-006**. The new rules
  are correctly scoped — they catch the dangerous patterns without
  flooding real codebases. Same finding totals as 1.2.4 across all
  12 projects.

### Not changed

- The `--json` output shape. Field names, severities, and finding
  structure are identical to 1.2.4. New rule IDs (`INJ-005b`) appear
  in the findings array; no field renames or removals.
- The runtime injection guard (`security/01-injection-guard.js`).
  This release is audit-only and CI-config-only.
- The runtime SQL helper (`security/04-sql-guard.js`). The helper
  itself is unchanged; only its allowlist entry changed because the
  new INJ-005b rule would otherwise flag the helper's own JSDoc
  examples as dangerous.
- The Python equivalent of `04-sql-guard.js`. Still deferred — Python
  has no tagged template literals so the design needs to be different
  (context manager or parameterized wrapper). On the roadmap for a
  future release.

### Upgrade notes

If you're upgrading from 1.2.x and you have a project that legitimately
uses template-literal SQL (e.g. you're maintaining an ORM internals
file or a SQL builder library), the new `INJ-005b` rule will fire on
your declaration sites. Two options:

1. **The right fix:** rewrite to the parameterized form. Use the
   bundled `security/04-sql-guard.js` `sql` tagged template:
   ```js
   import { sql } from 'otlc-guardian/sql';
   const query = sql`SELECT * FROM users WHERE id = ${userId}`;
   await db.query(query.text, query.values);
   ```
2. **The escape hatch:** add the per-file marker
   `// otlc-guardian:audit-exempt` to a file that legitimately needs
   to construct raw SQL strings, OR add the file to a project-local
   `security/.audit-allowlist` with a reason. Both mechanisms are
   reviewable in PR diffs.

---

## [1.2.4] — 2026-04-08

`DEP-001` false-positive fix. The pre-1.2.4 `DEP-001 — No health check
endpoint found` rule fired on every project that didn't contain the
substring `health` in any file. It was designed for HTTP services but
had no project-shape detection, so every CLI tool, static site, library,
npm package, code-generation skill, desktop app, and notebook produced
a spurious `MEDIUM` finding telling the user to add a `/health`
endpoint to a project that should never have one.

Real-world audit testing across 12 projects on a developer machine
showed 9 of them hitting exactly this false positive — they are not
servers, so they do not have health endpoints, and that is correct.
The 9 projects involved were CLIs, static sites, AutoLISP skill
modules, and code-generation tools. None of them needed a health
endpoint. The audit was telling them to add one anyway.

This release adds a `looksLikeHttpServer(rootDir, files)` gate that
runs in two stages:

1. **Manifest check (fast path).** Inspects `package.json`,
   `requirements.txt`, `pyproject.toml`, and `Pipfile` in the project
   root for any known HTTP server framework dependency. The Node list
   covers `express`, `fastify`, `koa`, `@hapi/hapi`, `restify`,
   `@nestjs/core`, `polka`, `tinyhttp`, `connect`, `h3`, `hono`,
   `@feathersjs/feathers`, `micro`, `sails`, `loopback`, and
   `@adonisjs/core`. The Python list covers `fastapi`, `flask`,
   `django`, `starlette`, `tornado`, `aiohttp`, `bottle`, `sanic`,
   `quart`, `falcon`, `pyramid`, `cherrypy`, `masonite`, and
   `litestar`. Both `dependencies` and `devDependencies` are checked,
   so a project that uses express only in its dev tooling still
   counts as a server shape.

2. **Source-pattern fallback.** Only runs when the manifest check
   comes back empty. Scans up to 150 source files (sorted shallow-
   first so the project bootstrap is examined first) for known
   listen-style call patterns: `app.listen(`, `server.listen(`,
   `http.createServer(`, `fastify(`, `uvicorn.run(`, etc. Catches
   single-file servers run via `tsx` / `bun` / `deno` that have no
   manifest but are clearly listening on a port.

DEP-001 only fires when both conditions hold: the project looks like
an HTTP server AND no `health` substring is found in any source file.
Non-server projects are left alone.

The gate mirrors the design of `isPythonProject()` in
`bin/guardian.js`, which only requires `injection_guard.py` when the
project actually looks Python-shaped. Same principle: don't pester
users about features their project type doesn't need.

### Changed

- **`security/03-audit.js`** — added `looksLikeHttpServer(rootDir, files)`
  helper as a hoisted function declaration above `AUDIT_RULES`. Updated
  `DEP-001`'s `checkFn` to gate on it. Updated the function-rule
  invocation loop in `runAudit` to pass `rootDir` as the second
  argument so future project-shape rules can use the same hook.

- **`tests/audit.test.js`** — added 6 TDD tests for the new behavior:
  positive (express + no health → fires), positive (fastapi + no
  health → fires), negative (CLI project → does NOT fire), negative
  (static site → does NOT fire), control (server WITH /health → does
  NOT fire), positive edge (no manifest but `app.listen()` in source
  → fires). Test count: 34 → 40, all green.

### Real-world impact

Re-audit of the same 12 projects from the 1.2.2 / 1.2.3 testing run:

```
Project                  pre-1.2.4      post-1.2.4    DEP-001 dropped
DevNeural                14 findings    14 findings   (was already 0 — has /health)
New-Letter-and-TikToks    1 finding      0 findings   yes
omnibomber-site           1 finding      0 findings   yes
autolisp-skill            1 finding      0 findings   yes
blkbom                    1 finding      0 findings   yes
Claude-Setup              1 finding      0 findings   yes
conveyor-designer         1 finding      0 findings   yes
conveyornum               1 finding      0 findings   yes
devneural-projects        1 finding      0 findings   yes
dev-template              1 finding      0 findings   yes
Landmark40                1 finding      0 findings   yes
skill-connections         1 finding      0 findings   yes
```

11 of 12 projects dropped from `MEDIUM: 1` to `MEDIUM: 0` — the exact
predicted outcome. The 12th (DevNeural) was already at 0 because it
has both a real server (`02-api-server/src/server.ts`) AND a real
`/health` endpoint at `02-api-server/src/routes/graph.ts:9`, which is
the correct happy path. The audit detector confirmed the monorepo
shape via the source-pattern fallback (DevNeural has no root
`package.json`) and then correctly suppressed the finding because the
health endpoint exists.

Guardian's own self-audit also benefits: pre-1.2.4 the audit would
have correctly suppressed DEP-001 on the Guardian repo because some
of its source files mention "health" in comments, but post-1.2.4 it's
properly suppressed for the right reason (Guardian is a CLI, not an
HTTP server, so the rule doesn't apply at all).

### Not changed

- The `--json` output shape. Field names, severities, and finding
  structure are identical to 1.2.3. Tooling consuming the JSON output
  needs no changes.
- Any other rule. Only `DEP-001`'s gating changed; the underlying
  "look for `health` substring" check is the same.
- The two known auditor gaps deferred since 1.2.2 — `INJ-005` template
  literal SQL with variable indirection, and `INJ-006` Python f-string
  SQL with inner quoted literals. Still on the deferred list. See the
  1.2.2 / 1.2.3 testing notes for the isolated test fixtures at
  `c:/tmp/guardian-audit-fixture/sql-edges.{js,py}`.

### Fixed

- **Stale `Version 1.2.3` strings across the repo** — bumped to 1.2.4
  in `package.json`, `bin/guardian.js` help footer, `README.md` badge,
  `AGENTS.md`, `CLAUDE.md`, `STANDARDS.md`, `SETUP.md`, `FAQ.md`, and
  `GEMINI.md`. This is the same lockstep-version-bump checklist used
  in every prior 1.2.x patch release.

---

## [1.2.3] — 2026-04-07

Audit reporter readability rewrite. The pre-1.2.3 human-readable
output of `guardian audit` repeated the rule header and full absolute
path for every finding, even when the same rule fired on 14 different
lines. Real-world DevNeural audit (56 findings before the 1.2.2
noise-reduction fixes) was 200+ lines of console output that all
looked the same. After 1.2.2 the same audit dropped to 14 findings,
but the report still had 14 standalone blocks because the reporter
hadn't been updated.

This release rewrites the human reporter only — no rule changes, no
detection changes, no JSON shape changes. The `--json` output that
tooling and `tests/audit.test.js` consume is byte-identical to 1.2.2.
Only the human-readable terminal output changed.

### Changed

- **Audit findings now group by rule, then by file.** Each severity
  bucket lists each rule **once** with an occurrence count, then
  underneath the rule lists each file **once** with all its line
  numbers comma-separated. Snippets show once per file (the first
  occurrence's content) instead of repeating for every line. Same
  data, ~70% fewer lines on a non-trivial audit.

- **File paths in the human report are now relative to the audit
  target.** `c:\dev\Projects\DevNeural\06-notebooklm-integration\src\config.ts:13`
  becomes `06-notebooklm-integration/src/config.ts:13`. Forward
  slashes used regardless of OS, so a Windows audit copy-pastes
  cleanly into a markdown PR comment.

- **Trailing four-line `Summary:` block replaced with a one-line
  status header at the top.** The pre-1.2.3 reporter ended every
  multi-finding audit with:
    ```
       Summary:
       CRITICAL : 0
       HIGH     : 36
       MEDIUM   : 11
       LOW      : 9
    ```
  That information was already implied by the per-section headers
  earlier in the report. Replaced with a single line directly under
  the AUDIT COMPLETE banner:
    ```
    ⚠️  [OTLC GUARDIAN] AUDIT COMPLETE — 56 issue(s) found
        0 CRITICAL · 36 HIGH · 11 MEDIUM · 9 LOW
    ```

### Real impact (DevNeural, 14 findings post-1.2.2)

  Pre-1.2.3 reporter   : 14 standalone blocks, ~50 lines of output
  Post-1.2.3 reporter  : 4 rule headers, ~25 lines of output

The 4 rule headers correspond exactly to the 4 distinct rules that
fired (`CFG-001`, `INJ-002`, `ERR-003`, `TS-001`). The reader sees
"three categories of finding: a hardcoded URL, two innerHTML uses,
seven console.log calls in CLI/server code, four `any` types in
browser code" — at a glance, instead of having to mentally
deduplicate 14 nearly-identical blocks.

### Not changed

- The `--json` output (used by `tests/audit.test.js` and CI). Same
  structure, same field names, same severities. The 34 audit tests
  pass byte-for-byte against the new build with no changes.
- The detection rules. No rule was added, removed, or modified. The
  same fixtures produce the same findings as 1.2.2.
- The `[OTLC GUARDIAN] SAFETY AUDIT STARTING` header block (Target,
  Rules, Files scanned, Exempt). Untouched.

### Fixed

- **Stale `Version 1.2.2` in `bin/guardian.js:121`** — bumped to
  `1.2.3` alongside all the other version strings.

---

## [1.2.2] — 2026-04-07

Audit signal-to-noise improvements. Three real-world rule fixes that
came out of running `guardian audit` against 12 projects on a developer
machine and finding that ~95% of the HIGH/MEDIUM findings on three of
those projects were false positives caused by scope and heuristic
gaps in the audit rules — not bugs in the user's code.

Concrete impact, measured by re-auditing the same three projects
before and after this release:

  DevNeural               56 → 14 findings  (-42, 75% drop)
  New-Letter-and-TikToks  10 →  1 findings  (-9,  90% drop)
  omnibomber-site         11 →  1 findings  (-10, 91% drop)
  ----------------------------------------------------------
  Total                   77 → 16 findings  (-61, 79% drop)

Signal-to-noise on the DevNeural project went from 3 real findings out
of 56 (5%) to 3 real findings out of 14 (21%) — a ~4x improvement.
The 3 real findings are the same in both runs, which is what makes
this a noise-reduction release: every fix below is a correctness
improvement to the rule, not a way to silence real warnings.

### Changed

- **`SKIP_DIRS` expanded to include all major dependency and build
  directories.** Pre-1.2.2 the audit walked `vendor/` (PHP composer),
  `target/` (Rust / Maven build outputs), `bower_components/` (legacy
  JS), and various Python cache directories — producing dozens of
  false positives on minified jQuery, Popper, D3, and PHPUnit's own
  bundled JS that real users had inside their own projects. The
  audit's job is to scan **your** code for **your** bugs; dependency
  scanning is a separate tool's job (`npm audit`, `pip-audit`,
  `composer audit`) and is **already** in Guardian's CI workflow as
  separate steps. Added: `vendor`, `bower_components`, `target`,
  `out`, `site-packages`, `dist-packages`, `.pytest_cache`,
  `.mypy_cache`, `.ruff_cache`, `.turbo`. The existing `node_modules`,
  `dist`, `build`, `.next`, `__pycache__`, `.venv`, `venv`, `.git`,
  `coverage`, `.cache` entries are kept. `env` is **deliberately
  not** on the list because too many real projects have a legitimate
  `env/` source directory. Documented inline.

- **Test-file detection broadened to recognize 7 conventions across
  ecosystems.** The pre-1.2.2 `excludePatterns` for `ERR-003`
  console.log only knew about `*.test.*`, `*.spec.*`, and the
  substring `test/` (which doesn't even match Windows backslash
  paths). It missed pytest's `test_*.py`, the alt-pytest `*_test.py`
  convention, custom test runners like `test-site.js`, the standard
  `tests/` directory on Windows, Rails-style `spec/` directories, and
  several others. The new module-level `TEST_FILE_EXCLUDES` constant
  recognizes:
    - `*.test.{js,ts,...}` (Jest, Vitest)
    - `*.spec.{js,ts,...}` (Mocha, Jasmine, Karma)
    - `__tests__/*` (Jest folder convention)
    - `test/*` and `tests/*` (most other frameworks, both slash forms)
    - `spec/*` (Rails / RSpec)
    - `test_*.{py,js}` and `test-*.{py,js}` (pytest + custom runners)
    - `*_test.{py,js}` and `*-test.{py,js}` (alt pytest convention)
  The character class `[\/\\]` in the directory matchers is what
  makes them work on both Windows and Unix path forms. The constant
  is now applied to **every** rule whose intent is "production code
  only": `ERR-003`, `CFG-001`, `CFG-002`, `CFG-003`, `INJ-002`,
  `TS-001`, and `SEC-006`. The previous narrow list was attached to
  `ERR-003` only, leaving the other rules to false-positive on test
  fixtures.

- **`CFG-003` distinguishes binding-to-localhost from URL-pointing-
  at-localhost.** The pre-1.2.2 rule pattern was a bare
  `/["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/` that fired on any
  quoted IP address. That conflated two opposite things:
    1. **URL pointing at a hardcoded IP** — real bug. Production
       config leak. `fetch('http://192.168.1.10:8080/api')`.
    2. **Server binding to `127.0.0.1`** — security best practice.
       The server refuses connections from any IP other than
       loopback. `fastify.listen({ host: '127.0.0.1' })`,
       `server.listen(0, '127.0.0.1', cb)`, `socket.bind('127.0.0.1', port)`.
  The pre-1.2.2 rule fired on the safe form and called it a config
  leak, which is actively wrong security advice. The fix introduces a
  new `excludeLinePatterns` rule field — a list of regexes that
  suppresses a finding when its surrounding line matches one of the
  "this is the safe form" patterns. `CFG-003` now skips findings
  where the IP appears immediately after `host:`, inside a `.listen(`
  positional call, or inside a `bind(` call. The bind-context
  patterns are anchored on the syntactic shape of the listen / bind
  call so they cannot match a URL string in the same line. Bare IP
  config assignments (`const dbHost = "192.168.1.10"`) and IP-in-URL
  forms still fire, which is what `CFG-003` was always meant to
  catch.

### Added

- **`excludeLinePatterns` rule field.** A general-purpose mechanism
  for any future rule that needs to distinguish a "safe form" from a
  "bug form" by line-context. Patterns are tested against the same
  line that matched the main rule pattern; if any match, the finding
  is suppressed. Currently only `CFG-003` uses it.

### Tests

- **`tests/audit.test.js`** — 14 new tests across three describe
  blocks (`v1.2.2 — dependency directories`, `v1.2.2 — test-file
  detection`, `v1.2.2 — CFG-003 bind vs URL`). Each fix has positive
  tests (the rule must NOT fire on the new safe forms) AND control
  tests (the rule must STILL fire in legitimate contexts so we
  haven't accidentally turned the rule off entirely). Total audit
  test count went from 20 → 34. Every test was watched fail before
  the implementation landed.

### Why these are best-practice fixes, not workarounds

Each of the three changes corrects an **actual flaw in the rule**, not
the visibility of a real warning:

  1. **Dependency dirs.** Every serious security scanner — Semgrep,
     SonarQube, ESLint, Ruff, Bandit, Snyk — skips dependency
     directories by default. The audit already skipped `node_modules/`
     for exactly this reason. Adding the equivalents for other
     ecosystems is closing a parity gap.

  2. **Test-file detection.** The principle "don't apply production
     rules to test code" was already in the audit (`ERR-003` had
     `excludePatterns`). The implementation just didn't recognize 6+
     conventions used in the wild. The intent of the rule didn't
     change — only the recognition heuristic was completed.

  3. **CFG-003 bind vs URL.** The pre-1.2.2 rule was actively wrong:
     it called a security best practice (binding to loopback) a
     security bug. The fix doesn't silence a warning — it makes the
     rule **correct**. Guardian's whole pitch is "production-grade
     security," and the previous rule contradicted the pitch.

A workaround would be: "add per-file `// otlc-guardian:audit-exempt`
markers to all the noisy files in DevNeural." That hides real
warnings behind a per-project carve-out. These three fixes are the
opposite: they make the rules correctly distinguish bugs from
non-bugs **for everybody**, so the auditor's signal-to-noise improves
on every project that uses it.

### Out of scope for 1.2.2

- **`DEP-001` "no /health endpoint" false positive on non-server
  projects.** This rule fires on every project that doesn't have a
  `/health` endpoint, which includes every CLI tool, every static
  site, every library, every code-generation skill, etc. After the
  three fixes above, `DEP-001` is the lone remaining `MEDIUM` on
  most non-server projects. The fix is to detect whether the project
  looks like a server (Express, Fastify, Koa, FastAPI, Flask, etc.)
  before firing the rule, similar to how the Python module check in
  `guardian check` only fires on Python-shaped projects. Deferred to
  a future release because the heuristic for "looks like a server"
  needs more thought.

- **`SEC-006` test-fixture downgrade.** Was on the original shortlist
  but skipped because it's closer to a noise filter than a
  correctness fix. The other three changes already cover the
  test-file noise this would have addressed (test files are now
  excluded from `SEC-006` via `TEST_FILE_EXCLUDES`).

### Fixed

- **Stale `Version 1.2.1` in `bin/guardian.js:121`** — bumped to
  `1.2.2` alongside all the other version strings.

---

## [1.2.1] — 2026-04-07

Hotfix that reverts one of the two features shipped in 1.2.0. The SQL
injection defense helper (`security/04-sql-guard.js`) stays — it does
not touch user files. The automated `guardian uninstall` command is
removed — it does.

### Removed

- **`guardian uninstall` command** — reverted in full. Removed
  `runUninstall()` and its helpers (`unmergeMarkerFile`,
  `unmergeClaudeSettings`, `deleteCopiedTree`, `HTML_MARKER_RE`,
  `HASH_MARKER_RE`) from `bin/guardian.js`, dropped the
  `case "uninstall":` router branch, removed the help text block,
  removed the mention from the file-header comment block, and dropped
  the `rmSync` import that was only needed by the uninstall code.
  Deleted `tests/uninstall.test.js` entirely and removed it from the
  `npm test` script in `package.json`. README reverted from "Seven
  Commands" back to "Six Commands" with a note explaining that
  uninstalling is deliberately manual. SETUP.md uninstall section
  restored to manual-only with the "no automated command by design"
  rationale. FAQ.md uninstall answer rewritten to point at
  `SETUP.md § Uninstalling`.

### Why the revert

The 1.2.0 uninstall command passed a full 11-test suite covering
symmetry (byte-identical `init && uninstall`), idempotency, invalid
JSON refusal, customized-file skip, dry-run, and the refuse-to-modify
contract for `.claude/settings.json`. The implementation was careful:
marker-strip for merged files with user content above the markers,
set-based matcher comparison for `.claude/settings.json` hook removal,
byte-compare-then-delete for pure-Guardian copied files, and never
touching a file Guardian did not create.

None of that changes the risk profile. An automated command that
mutates user files has a blast radius that is proportional to the
install base, not to the size of its test suite. A single bug in a
marker regex, a single Windows line-ending edge case, a single
interaction with a user-configured matcher block that is equivalent
but not textually identical to the canonical form — any one of these
could silently destroy a user's `CLAUDE.md` or `STANDARDS.md` after
they have poured hours of project-specific rules into it. The tests
prove the happy paths; they cannot prove the absence of corner cases.

For a security-forward template whose tagline includes "safe on
existing projects", the correct posture is: **do not automate the
teardown of files that contain user content.** The manual
marker-based procedure in `SETUP.md § Uninstalling` puts the user in
full control of every delete and every edit. It is slower, and that
is the point. The PR #4 documentation fix (2026-04-06) that replaced
the original `rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md`
instructions with the marker-based procedure remains the
authoritative uninstall path.

### What is kept from 1.2.0

- **`security/04-sql-guard.js`** — stays. The OWASP-aligned tagged
  template helper does not touch user files; it returns a
  `{ text, values }` object for the caller to pass to a database
  driver. The 40-test suite remains, the `./sql` subpath export in
  `package.json` remains, the STANDARDS.md and README.md mentions
  remain, and the FAQ answers about the helper remain.

### Fixed

- **Stale `Version 1.2.0` in `bin/guardian.js:121`** — bumped to
  1.2.1 alongside all the other version strings (package.json badge,
  doc headers/footers for README, CLAUDE.md, STANDARDS.md, AGENTS.md,
  GEMINI.md, FAQ.md, SETUP.md).

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
