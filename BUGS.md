# BUGS — OTLC Guardian

Persistent bug log. Survives across sessions so a fresh-context agent knows what is
already known-broken before it starts troubleshooting.

**Read the Index first.** Only open a detail block when you need that specific bug.

Statuses: `OPEN` (confirmed, not fixed) → `SMOKE-TESTING` (fix applied, verifying) →
`RESOLVED` (fixed and verified). `DEFERRED` = real bug, intentionally parked.

<!-- INDEX START -->

| ID | Status | Summary |
|---|---|---|
| BUG-001 | RESOLVED | `INJ-005b` fires CRITICAL on any template literal containing a SQL-looking word, including `window.confirm` and JSX labels |
| BUG-002 | OPEN | Audit has zero rules covering what AI agents can write to, despite the README claiming AI-attack coverage |
| BUG-003 | OPEN | `INJ-003` fires HIGH on stock shadcn `chart.jsx` boilerplate that every shadcn user inherits |
| BUG-004 | RESOLVED | Planned rule id `DEP-001` for npm version drift collides with the existing `DEP-001` health-check rule |
| BUG-005 | DEFERRED | No detection of `setTimeout`-before-query race conditions (planned `RACE-001`) |
| BUG-006 | DEFERRED | No detection of inconsistent `npm:` import versions across Deno-style project files (now `DEP-003`) |
| BUG-007 | DEFERRED | No file-size/decomposition rule (planned `QUAL-001`); changes Guardian's identity toward style-linter |
| BUG-008 | RESOLVED | `SEC-001` missed current-format OpenAI (`sk-proj-`) and Anthropic (`sk-ant-api03-`) keys |
| BUG-009 | RESOLVED | `ERR-001` missed comment-only catch bodies, the most common silent-failure form |
| BUG-010 | RESOLVED | README claimed raw SQL detection but no rule implemented it |
| BUG-011 | RESOLVED | Nothing flagged connection strings with embedded credentials |
| BUG-012 | RESOLVED | `--json` mode contaminated stdout with status text, breaking CI parsing |
| BUG-013 | RESOLVED | README uninstall instructions caused data loss by blanket-deleting user rule files |
| BUG-014 | RESOLVED | `CFG-003` flagged safe localhost bind as a config leak, inverting correct security advice |
| BUG-015 | RESOLVED | `DEP-001` fired on CLI tools, libraries, and static sites that should never have `/health` |
| BUG-016 | RESOLVED | `INJ-006` silently failed on any Python f-string SQL containing an inner quote |
| BUG-017 | RESOLVED | `INJ-005` bypassed by assigning the SQL template to a variable first |
| BUG-018 | RESOLVED | Subdirectory audits ignored the project-root manifest and central allowlist |
| BUG-019 | RESOLVED | Claude Code hooks bypassed the runtime guard's normalization and decode passes |
| BUG-020 | RESOLVED | Python FastAPI dependency returned unsanitized input to the caller |
| BUG-021 | SMOKE-TESTING | Hook: a payload carrying `otlc-guardian:doc` exempted itself from scanning |
| BUG-022 | SMOKE-TESTING | Hook: advisory only and silent on its own failure; could not stop a poisoned write |
| BUG-023 | SMOKE-TESTING | `INJ-027`/`INJ-028` cubic backtracking stalled both hooks on a comment flood (ReDoS) |
| BUG-024 | SMOKE-TESTING | Scanner bypassed by tag characters, U+2060, lookalike letters, stray `%`, embedded base64, entities, markdown, filler padding |
| BUG-025 | SMOKE-TESTING | `guardian update` never overwrote anything, so fixes never reached existing installs |
| BUG-026 | SMOKE-TESTING | Secret rules missed OpenSSH/EC keys, `github_pat_`, `ghs_`, Slack, Stripe live, Anthropic OAuth |
| BUG-027 | OPEN | Hook files and scanner are writable by the agent they guard (only settings.json is protected) |
| BUG-028 | OPEN | Hook command path is cwd-relative; `$CLAUDE_PROJECT_DIR` form untested on Windows |
| BUG-029 | OPEN | Scanner bypasses: base64 candidate cap can be spent, chained encodings pass, confusables gaps |
| BUG-030 | OPEN | `AUTHZ-013` misses a textbook IDOR: a 404 and a `user_id` path parameter count as ownership checks |
| BUG-031 | OPEN | `AUTHZ-011` blind spots: router-level `Depends(get_db)`, substring public-route list, bare `api_key` mention |
| BUG-032 | OPEN | `AUTHZ-011` flags reads: `GET` plus `db.execute(select(...))` reports HIGH |
| BUG-033 | OPEN | `WEB-001` misses token constants and JSON-wrapped tokens; flags `refreshCount` |
| BUG-034 | OPEN | Bash in the PreToolUse matcher makes BUG-028 worse: hook error on every Bash call after a `cd` |
| BUG-035 | OPEN | "ask" stalls unattended workers in default and acceptEdits modes |
| BUG-036 | OPEN | Web guard MCP tool names (`mcp__firecrawl__crawl`, `mcp__exa__search`) are probably wrong |
| BUG-037 | OPEN | `guardian update` hook migration overrides a custom wider matcher and duplicates the `$CLAUDE_PROJECT_DIR` form |
| BUG-038 | OPEN | Small hook and audit defects: deny message loses the file name, NGINX check cost, CSP comment suppresses WEB-002 |
| BUG-039 | OPEN | `DEP-002` can never fire: the walker never collects a bare `.env` file |
| BUG-040 | OPEN | Audit `INJ-001` (eval) fires on any call whose name ends in `eval`, e.g. `retrieval(` |
| BUG-041 | RESOLVED | Partial scans: project checks judge the scanned subtree as the whole project (false `DEP-001`), and a single-file target scans nothing |

<!-- INDEX END -->

<!-- DETAILS START -->

---

### BUG-001 — `INJ-005b` fires CRITICAL on non-SQL template literals

**Status:** RESOLVED
**Found:** 2026-07-20 (originally observed 2026-04-27 against Guardian 1.3.1)
**Fixed:** 2026-07-20 (1.4.1)
**Area:** `security/03-audit.js` — `INJ-005b`

`INJ-005b` matches any template literal containing `${}` and one or more SQL-looking
words, with no awareness of the call site. Because `DELETE`, `UPDATE`, `SELECT`, and
`DROP` are ordinary English words, ordinary UI strings match.

Confirmed still reproducible on 1.4.0:

```jsx
if (!window.confirm(`Delete asset ${asset.name}?`)) return;   // INJ-005b CRITICAL
return <button>{`Delete ${asset.name}`}</button>;              // INJ-005b CRITICAL
```

Real-world impact: a `guardian audit` run against a Base44-generated CMMS project
returned 6 CRITICAL findings, **all six false positives from this one rule**. In any
codebase using an ORM with no direct SQL (Base44, Supabase, Prisma), every match is a
false positive. This burns first-run trust, which is the worst possible failure mode
for a security tool.

The rule was added in 1.3.0 for a genuine reason (BUG-017, variable-indirection
bypass), so it could not simply be deleted.

**Fix (1.4.1).** The handoff proposed inverting the rule to a call-site match (only
flag templates passed to `.query(`/`.execute(`/`.raw(`). That would have been wrong:
a call-site match is exactly what `INJ-005` already does, so `INJ-005b` would have
become a duplicate and the variable-indirection bypass it exists to close would have
reopened. Declaration-site detection is the whole point of the rule.

Fixed instead by raising the evidence bar for what counts as SQL. Real SQL has clause
structure; English prose does not. Each verb now has to appear with its mandatory
companion keyword:

| Verb | Required companion |
|---|---|
| `SELECT` | `FROM` |
| `INSERT` | `INTO` |
| `UPDATE` | `SET` |
| `DELETE` | `FROM` |
| `DROP` / `ALTER` / `TRUNCATE` | `TABLE` / `DATABASE` / `INDEX` / `VIEW` / `SCHEMA` |

"Delete asset" has no `FROM`. "Failed to update record" has no `SET`. Valid SQL
essentially always carries the companion clause, so precision rose with no real
coverage loss.

Two further points the fix had to get right:

- The interpolation check is a lookahead asserting `${` appears *anywhere* in the
  template, not after the clause pair. Requiring it after `FROM` would have missed
  `` `SELECT ${columns} FROM users` ``, a genuinely unparameterized query.
- A `(?<!\bsql)` lookbehind clears the sql-guard tagged template. That tag is the
  auto-parameterizing remediation for this bug class, and flagging the fix is how you
  teach people to stop applying it. The exclusion is narrow enough that `mysql\`` and
  an untagged sibling on the next line both still fire.

No secondary lower-severity hint was added. The handoff suggested one, but a MEDIUM
noise channel reinstates the exact problem the fix removes, and the clause-pair test
is orthogonal to the call site — a custom DB wrapper is still caught as long as the
SQL it builds is really SQL.

13 tests in `tests/audit.test.js`, including a BUG-017 guard that fails if anyone ever
converts this rule to a call-site match.

Original proposal in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 1.

---

### BUG-002 — No audit coverage of AI agent write permissions

**Status:** OPEN
**Found:** 2026-07-20 (originally observed 2026-04-27)
**Area:** `security/03-audit.js` — missing rule, planned as `AGT-001`

Guardian's runtime layer defends against prompt injection and output leakage. The
audit has no rules about *what AI agents are allowed to write to*.

The Zion CMMS project shipped an AI agent configured with `create`/`update`/`delete`
on `QuoteLineItem` and `update` on `Inventory`, where the only approval gate was a
politely worded sentence in the system prompt. The audit walked straight past it.

This is squarely inside the threat surface the README claims to cover, which makes it
a coverage gap with a marketing claim attached, not merely a missing feature.

Proposed rule shape and file globs in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 2.

---

### BUG-003 — `INJ-003` fires on stock shadcn boilerplate

**Status:** OPEN
**Found:** 2026-07-20 (originally observed 2026-04-27)
**Area:** `security/03-audit.js` — `INJ-003`

`INJ-003` correctly flags `dangerouslySetInnerHTML`, but shadcn's generated
`chart.jsx` uses it to inject static CSS variables from a constant. Every shadcn user
inherits one HIGH finding they must triage and then ignore.

The finding is technically correct and practically noise. Needs a built-in allowlist
for the exact shadcn pattern, narrow enough that a modified version of the component
still fires.

Proposal in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 5.

---

### BUG-004 — Planned `DEP-001` rule id collides with the existing one

**Status:** RESOLVED
**Found:** 2026-07-20
**Fixed:** 2026-07-20
**Area:** `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 4

The handoff document proposes `DEP-001 — inconsistent npm: import versions`. That id
is already in use by `DEP-001 — No health check endpoint found`, shipped since at
least 1.2.4 and covered by tests in `tests/audit.test.js`.

Implementing the handoff as written would either silently overwrite an existing rule
or produce two rules reporting under one id, which breaks per-id filtering in JSON
consumers and CI.

**Fix.** All six `DEP-001` references in the handoff rewritten to `DEP-003`, with a
correction note at the top of Item 4 recording what changed and why. `DEP-002` remains
the committed-`.env` rule.

Unblocks BUG-006.

---

### BUG-005 — No `setTimeout`-before-query race detection

**Status:** DEFERRED
**Found:** 2026-07-20 (originally observed 2026-04-27)
**Area:** `security/03-audit.js` — missing rule, planned as `RACE-001`

`setTimeout(r, 1000)` followed by an entity lookup is a classic race: the code sleeps
a guessed interval and hopes the write has landed. Observed at
`base44/functions/inviteUser/entry.ts:29` in the Zion CMMS.

Deferred, not dismissed. The handoff explicitly allows items 3 through 6 to split
into a follow-up release. Correctness rule, not security.

Proposal in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 3.

---

### BUG-006 — No `npm:` import version drift detection

**Status:** DEFERRED
**Found:** 2026-07-20 (originally observed 2026-04-27)
**Area:** `security/03-audit.js` — missing rule

In Deno-based projects (Base44, Supabase Edge Functions, Deno Deploy), `npm:` imports
pin a version inline, so the same package can drift across entry files. The Zion CMMS
had `@base44/sdk` at `0.8.23` and `0.8.25` across three functions.

Unblocked: BUG-004 reassigned this rule to `DEP-003`.

Proposal in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 4.

---

### BUG-007 — No file-size / decomposition rule

**Status:** DEFERRED
**Found:** 2026-07-20 (originally observed 2026-04-27)
**Area:** `security/03-audit.js` — missing rule, planned as `QUAL-001`

`STANDARDS.md` implies decomposition; the audit does not enforce it. The Zion CMMS
shipped a 708-line page component.

Deliberately parked. The handoff itself flags this as lowest priority and notes it
shifts Guardian's identity from security tool toward style linter. If implemented it
must be default-disabled behind `--enable-quality`. That is a positioning decision,
not an engineering one, and it deserves its own explicit call.

Proposal in `HANDOFF-AUDIT-IMPROVEMENTS.md` § Item 6.

---

### BUG-008 — `SEC-001` missed current-format API keys

**Status:** RESOLVED · **Found:** pre-1.1.1 · **Fixed:** 1.1.1

The pattern was `/sk-[a-zA-Z0-9]{20,}/`. The hyphen after the provider tag falls
outside `[a-zA-Z0-9]`, so matching stopped at 4 characters — far below the `{20,}`
threshold — and both `sk-proj-...` (OpenAI project keys) and `sk-ant-api03-...`
(Anthropic) were reported as clean. A leaked current-format key passed the audit with
no finding.

Split into provider-labelled rules (`SEC-001`, `SEC-010`, `SEC-001b`) so the report
names the provider that just leaked. Regression tests in `tests/audit.test.js`.

---

### BUG-009 — `ERR-001` missed comment-only catch bodies

**Status:** RESOLVED · **Found:** pre-1.1.1 · **Fixed:** 1.1.1

The pattern required literal empty braces, so the most common lazy form
(`catch (e) { /* silent failure */ }`) was missed. A comment makes the body non-empty
to a character counter and identically harmful to error handling.

Pattern now accepts any sequence of whitespace, line comments, and block comments as
a silent body. Runs `wholeFile` so multi-line catch bodies are caught.

---

### BUG-010 — Raw SQL detection claimed but never implemented

**Status:** RESOLVED · **Found:** pre-1.1.1 · **Fixed:** 1.1.1

The README advertised raw SQL detection. No rule implemented it. A planted fixture
containing `db.raw("SELECT * FROM users WHERE id = " + id)` received zero findings.

Fixed by `INJ-004` (concatenation form) and `INJ-005` (template-literal form).
See BUG-017 for the follow-on bypass.

---

### BUG-011 — Connection strings with embedded credentials unflagged

**Status:** RESOLVED · **Found:** pre-1.1.1 · **Fixed:** 1.1.1

`postgresql://admin:hunter2@db.internal:5432/prod` produced no finding despite being
a hardcoded secret by every definition in `CLAUDE.md`. Added as `SEC-011`, covering
postgres, mysql, mongodb (including `+srv`), redis/rediss, and amqp/amqps.

---

### BUG-012 — `--json` mode contaminated stdout

**Status:** RESOLVED · **Found:** pre-1.1.1 · **Fixed:** 1.1.1 (commit `90f9665`)

Status lines such as `🔍 SAFETY AUDIT STARTING` were written to stdout in `--json`
mode, so `guardian audit . --json > out.json` produced a file that would not parse.

Status now routes to stderr in JSON mode and stdout in human mode — the standard Unix
diagnostic-vs-result split.

---

### BUG-013 — README uninstall instructions caused data loss

**Status:** RESOLVED · **Found:** 1.3.0 · **Fixed:** 1.3.1

README line 380 told users to `rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md`,
destroying any project-specific rules written before `guardian init` ran. The same bug
had already been fixed in `SETUP.md` in PR #4 but was never propagated to the README.

Replaced with a marker-based manual procedure linking to the full SETUP instructions.

---

### BUG-014 — `CFG-003` flagged safe localhost binds

**Status:** RESOLVED · **Found:** pre-1.2.2 · **Fixed:** 1.2.2

The rule conflated two opposite things: binding a server to `127.0.0.1` (a security
best practice — refuses external connections) and a URL pointing at a hardcoded IP (a
real config leak). Flagging the safe form is actively misleading security advice.

Added `excludeLinePatterns` anchored on the syntactic shape of `listen`/`bind`/`host`
calls so they cannot match a URL string on the same line.

---

### BUG-015 — `DEP-001` fired on projects with no HTTP server

**Status:** RESOLVED · **Found:** pre-1.2.4 · **Fixed:** 1.2.4

The rule fired on every project lacking a "health" substring, producing spurious
findings on CLI tools, static sites, libraries, notebooks, and desktop apps — none of
which should have a `/health` endpoint.

Now gated on `looksLikeHttpServer()`, which checks the manifest for a server framework
before falling back to a capped source scan for `.listen(`/`createServer(`.

---

### BUG-016 — `INJ-006` broke on Python f-strings containing inner quotes

**Status:** RESOLVED · **Found:** pre-1.3.0 · **Fixed:** 1.3.0

The inner character class was `[^"']*`, excluding *both* quote styles. Any real-world
f-string containing a literal such as `WHERE name = 'admin'` broke the match, so the
rule silently did nothing on most production-shaped SQL.

Split into quote-specific alternation branches so each outer quote style permits the
opposite inner style.

---

### BUG-017 — `INJ-005` bypassed by variable indirection

**Status:** RESOLVED · **Found:** pre-1.3.0 · **Fixed:** 1.3.0

`INJ-005` required the backtick template to be the first argument of the query call. A
two-line refactor defeated it entirely:

```js
const sql = `SELECT * FROM users WHERE id = ${userId}`;
db.query(sql);
```

Added `INJ-005b`, which matches the declaration site rather than the call site. Both
rules are kept so a project using either form is caught.

**Caused BUG-001.** The declaration-site match has no call-site context, which is why
it over-fired on English prose until the 1.4.1 precision rewrite. The regression guard
in BUG-001's test block exists to keep this bypass closed if anyone tries to fix the
precision problem by reverting to a call-site match.

---

### BUG-018 — Subdirectory audits ignored project-root config

**Status:** RESOLVED · **Found:** pre-1.3.1 · **Fixed:** 1.3.1

The auditor conflated the scan target with the project root. Running
`guardian audit ./src` made manifest lookups hit `./src/package.json` (nonexistent)
and silently ignored the central allowlist at `<root>/security/.audit-allowlist`.

Split into `scanRoot` (what the user asked to scan) and `projectRoot` (found by
walking upward for `.git`, the allowlist, or a manifest, capped at 8 levels).

---

### BUG-019 — Hooks bypassed the runtime guard's decode passes

**Status:** RESOLVED · **Found:** 1.3.0 · **Fixed:** 1.3.1

Both Claude Code hooks walked the raw `INJECTION_PATTERNS` array directly, bypassing
the runtime guard's NFKC normalization, invisible-Unicode stripping, URL-decode, and
base64-decode passes. A fullwidth-Unicode or percent-encoded injection payload slipped
past the hooks even though a direct `scan()` call caught it.

Both hooks now import and call the public `scan()`. Hook coverage is byte-for-byte
identical to runtime coverage.

---

### BUG-020 — FastAPI dependency returned unsanitized input

**Status:** RESOLVED · **Found:** 1.3.0 · **Fixed:** 1.3.1

The Python FastAPI dependency scanned input but returned the original value rather
than the sanitized one, so callers received unsanitized text while believing it had
been through the guard. Soft-breaking change for FastAPI users; see the 1.3.1
CHANGELOG entry.

---

### BUG-021 to BUG-026 — 2026-11-10 review (fixed in 1.5.0, awaiting live verification)

**Status:** SMOKE-TESTING · **Found:** 2026-11-10 · **Fix applied:** 2026-11-10 (1.5.0, commit da927d8; BUG-021 and BUG-022 reopened by the independent review `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`, findings 1 to 5, and fixed again in e8481d8, d8346da, 17d049c, 3d18992, a55d884)

Found in one review pass and reproduced against 1.4.1 before any change. Full write-up
per item in the `CHANGELOG.md` 1.5.0 entry. Regression tests: `tests/hook.test.js`
(1.5.0 blocks), `tests/injection-guard.test.js` (1.5.0 blocks), `tests/init.test.js`
(migration and refresh).

Still to verify outside the test suite before marking RESOLVED:

- In a live Claude Code session on Windows: a CRITICAL write to `CLAUDE.md` is denied,
  a Bash append to it prompts, and an edit that removes the hook from
  `.claude/settings.json` prompts.
- `guardian update` run in one real project, diff reviewed, then the rest.
- For the review fixes, in the same live session: a full rewrite of a CLAUDE.md that
  carries Guardian's section is allowed, `grep` over CLAUDE.md quoting a pattern is not
  blocked, and a `{"disableAllHooks":true}` write to `settings.local.json` prompts.

### BUG-027 — Hook files and scanner are not write-protected

**Status:** OPEN · **Found:** 2026-11-10

`.claude/settings.json` edits that weaken Guardian now ask for confirmation. The hook
files (`.claude/hooks/*.mjs`) and `security/01-injection-guard.js` do not. An agent that
is already compromised can rewrite them, or write any file through a script. Belongs with
the hard-no hook in the Self-Growing Gate spec (Lane 5), and with the DevNeural write
guard boundary noted in `TODO.md`.

### BUG-028 — Hook command path is cwd-relative

**Status:** OPEN · **Found:** 2026-11-10

`.claude/settings.json` registers `node .claude/hooks/injection-guard-hook.mjs`. Claude
Code's documented form is `"$CLAUDE_PROJECT_DIR"/.claude/hooks/...`. Not changed in 1.5.0
because the expansion was not tested on Windows. The hook itself now resolves the project
root from `CLAUDE_PROJECT_DIR`, so only the launch path is affected.

### BUG-029: Scanner bypasses: base64 candidate cap can be spent, chained encodings pass, confusables gaps

**Status:** OPEN · **Found:** 2026-11-10

Review finding 6 (MEDIUM). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- The 64-candidate cap on embedded base64 runs (`MAX_BASE64_CANDIDATES`, `security/01-injection-guard.js`) can be spent on harmless tokens: 65 git SHAs, then a base64 payload. `scanChange()` applies the same cap per changed window, so a large edit can still exhaust it.
- Decoders run one at a time, so chained encodings pass: `ign&#1086;re` (entity that decodes to a Cyrillic lookalike), `%2569gnore` (double percent-encoding).
- The confusables table misses U+0261 (Latin script g) and Armenian `ո`.

### BUG-030: `AUTHZ-013` misses a textbook IDOR: a 404 and a `user_id` path parameter count as ownership checks

**Status:** OPEN · **Found:** 2026-11-10

Review finding 7 (HIGH). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- A handler that returns 404 when the row is missing is treated as checking ownership (`security/03-audit.js` around line 690), though a 404 says nothing about whose row it is.
- A `user_id:` path parameter also counts as an ownership check (around line 662), though it is caller-supplied.

### BUG-031: `AUTHZ-011` blind spots: router-level `Depends(get_db)`, substring public-route list, bare `api_key` mention

**Status:** OPEN · **Found:** 2026-11-10

Review finding 8 (HIGH). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- A router-level `Depends(get_db)` silences the whole file, though a database dependency is not auth.
- The public-route list matches substrings, so `/api/tokens/{id}` is treated as public.
- Any mention of `api_key` counts as auth.

### BUG-032: `AUTHZ-011` flags reads: `GET` plus `db.execute(select(...))` reports HIGH

**Status:** OPEN · **Found:** 2026-11-10

Review finding 9 (MEDIUM). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- A read-only `GET` handler that runs `db.execute(select(...))` is reported as an unauthenticated side effect at HIGH.

### BUG-033: `WEB-001` misses token constants and JSON-wrapped tokens; flags `refreshCount`

**Status:** OPEN · **Found:** 2026-11-10

Review finding 10 (MEDIUM). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- Missed: `setItem(TOKEN_KEY, accessToken)` and `setItem("auth", JSON.stringify({accessToken}))`.
- Falsely flagged: `setItem("refreshCount", "1")`.

### BUG-034: Bash in the PreToolUse matcher makes BUG-028 worse: hook error on every Bash call after a `cd`

**Status:** OPEN · **Found:** 2026-11-10

Review finding 11 (MEDIUM). Related: BUG-028. Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- The hook command path is cwd-relative (`node .claude/hooks/injection-guard-hook.mjs`). With Bash in the matcher, every Bash call made after the session changes directory fails to launch the hook and shows a hook error, so the hook does not run for those calls.

### BUG-035: "ask" stalls unattended workers in default and acceptEdits modes

**Status:** OPEN · **Found:** 2026-11-10

Review finding 12 (MEDIUM). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- Only `bypassPermissions` mode turns the hook's "ask" into "deny". An unattended worker running in default or acceptEdits mode waits on a prompt nobody will answer. Needs a way to tell an attended session from an unattended one, or a policy setting. Relates to the hard-no hook design in `TODO.md` ("must not disturb unattended workers").

### BUG-036: Web guard MCP tool names (`mcp__firecrawl__crawl`, `mcp__exa__search`) are probably wrong

**Status:** OPEN · **Found:** 2026-11-10

Review finding 13 (LOW). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- The PostToolUse matcher (`bin/guardian.js`, `.claude/settings.json`) names `mcp__firecrawl__crawl` and `mcp__exa__search`, which probably do not match the servers' real tool names, so the hook would not fire on them. Fix: match on the `mcp__firecrawl__` and `mcp__exa__` prefixes. Docs describe the matcher as registered today (finding 15 commit).

### BUG-037: `guardian update` hook migration overrides a custom wider matcher and duplicates the `$CLAUDE_PROJECT_DIR` form

**Status:** OPEN · **Found:** 2026-11-10

Review finding 14 (LOW). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- The migration replaces a matcher the user had widened on purpose.
- An entry written in the `"$CLAUDE_PROJECT_DIR"/.claude/hooks/...` form is not recognized as Guardian's, so a second entry is added.

### BUG-038: Small hook and audit defects: deny message loses the file name, NGINX check cost, CSP comment suppresses WEB-002

**Status:** OPEN · **Found:** 2026-11-10

Review finding 16 (LOW). Source: `C:/dev/data/skill-connections/brainstorms/16f2e0e3-349e-466f-af79-5ad72f28770d/plans/2026-11-10-guardian-1.5.0-review.md`. Logged when 1.5.0 landed; not fixed in it.

- The hook's deny message truncates a long path from the end (`safeEcho`), so the file name is cut off. Truncate from the start instead.
- The `NGINX_SERVER_BLOCK` check's cost grows with the file size.
- A comment that mentions ContentSecurityPolicy suppresses `WEB-002`.

### BUG-039: `DEP-002` can never fire: the walker never collects a bare `.env` file

**Status:** OPEN · **Found:** 2026-11-10

Found by the first fixture for DEP-002 (gate plan step 0, `tests/audit.test.js`, "Rules with no prior test").

- `collectFiles()` in `security/03-audit.js` keeps a file only when `path.extname()` is in the rule extension list. `path.extname(".env")` is `""`, so a bare `.env` is never collected, and DEP-002's `checkFn` (`path.basename(f) === ".env"`) never sees one.
- Same root cause: the `.env` entry in `SECRET_FILE_EXTS` matches only names like `prod.env`, so the secret rules never read `.env`, `.env.local` or `.env.production` either. Whether they should (a `.env` is where secrets belong) is a separate decision; DEP-002's presence check clearly should see the file.
- The fixture is kept as a known-bug test (`knownBug("BUG-039", ...)`); it fails the suite once DEP-002 starts firing, so the fix must move it to `test()`.

### BUG-040: Audit `INJ-001` (eval) fires on any call whose name ends in `eval`, e.g. `retrieval(`

**Status:** OPEN · **Found:** 2026-11-10

Found by the fixtures for the audit's INJ-001 (gate plan step 0).

- The pattern is `/eval\s*\(/` with no word boundary, so `retrieval(query)` is reported CRITICAL as "Direct user input passed to eval()".
- The description also overstates what is checked: any `eval(` fires, with or without user input. The likely fix is `\beval\s*\(` (and `new Function(`, which the rule does not cover), with the description matched to what it detects.
- The fixture is kept as a known-bug test (`knownBug("BUG-040", ...)`).

### BUG-041: Partial scans: project checks judge the scanned subtree as the whole project (false `DEP-001`), and a single-file target scans nothing

**Status:** RESOLVED · **Found:** 2026-11-10 · **Fixed:** 2026-11-10

Reported by DevNeural, reproduced by DevNeural's Lex: `node security/03-audit.js 07-daemon/src/capture/hooks`, run from DevNeural, reports DEP-001 although DevNeural serves `GET /health` in `07-daemon/src/dashboard/routes.ts`. Reproduced again here on a scratch project.

- Project checks (`checkFn`) received `files`, collected from the scan root, while `projectRoot` (already found for manifests and the allowlist) was used only for manifests. A check that proves an absence across the project then answers from part of it: DEP-001 (no health route) and WEB-002 (no CSP anywhere; its nginx search already used the project root, its CSP search did not) both report falsely on a subfolder scan. DEP-002 (`.env` present) is a presence check, so a hit in the scanned subtree is true.
- A file given as the target: `collectFiles()` called `readdirSync` on it, failed, and returned no files, so the audit scanned nothing and reported only project checks. Same trigger (a partial scan), found while reproducing this bug.

Fix: project checks declare `evidence: "project"` when they prove an absence (DEP-001, WEB-002) and then read the project root's files on a partial scan; `collectFiles()` accepts a file target. Tests: `tests/audit.test.js`, "BUG-041" block. Verified live: the pre-fix engine reports DEP-001 on DevNeural's `07-daemon/src/capture/hooks`, the fixed engine does not.

<!-- DETAILS END -->
