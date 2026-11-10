# Changelog

All notable changes to OTLC Guardian. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.5.0] - Unreleased

Hook and scanner hardening from a full review on 2026-11-10. Working tree
only: not committed, not published, and not yet rolled out to any other
project (each project picks it up when `guardian update` is run there).

### Security

- **The PreToolUse hook can now block (BUG-022).** It was advisory only.
  A CRITICAL injection pattern that a write adds to a watched path is
  denied. A Bash command that carries one and writes to a watched path asks
  for confirmation. HIGH and MEDIUM findings stay advisory.
- **Bash is judged by what it writes (review finding 2).** The first deny
  build asked (and in bypass mode denied) any Bash command that carried a
  pattern and named a watched path, so `grep -rn "<pattern>" CLAUDE.md`
  and `git commit -m` were blocked. The hook now reads the paths a command
  writes: redirections, `tee`, `sed -i`/`perl -i`, `cp`/`mv`/`install`/`ln`
  destinations, `dd of=`, `curl -o`/`wget -O`, deletes, and the same
  inside `sh -c`, `eval`, `$( )`, backticks and `find -exec`, following
  `cd`. Quoted text and heredoc bodies are data. Inline interpreter code
  (`node -e`, `python -c`) cannot be parsed, so every path-like word in it
  counts as written. A command that only names a watched path gets an
  advisory.
- **A write is judged by what it adds (review finding 1).** The first deny
  build scanned the whole new content, so a rewrite of any file that
  already quoted a pattern was denied, including every CLAUDE.md that
  `init` had merged Guardian's rules into. The hook now compares the write
  with the file on disk through the new `scanChange()` export: a finding
  counts only when the change adds a matched string that was not there
  before, view by view (plain, decoded, folded). A second copy of an
  already-quoted pattern is still new.
- **PowerShell is covered (verification P6).** The PowerShell tool was not
  in the matcher and the hook ignored it, so `Add-Content CLAUDE.md ...` and
  `Set-Content .claude/settings.local.json ...` were allowed. It is now in
  the PreToolUse matcher (`guardian update` migrates) and judged like Bash
  with a PowerShell reader: `Set-Content`, `Add-Content`, `Out-File`,
  `Tee-Object`, `New-Item`, `Copy-Item`, `Move-Item`, `Remove-Item`,
  `Rename-Item` and their aliases, by named or positional parameter,
  `[IO.File]::Write*` calls, and `Get-Content` piped into a writer. Bash
  `powershell "..."` was only read when `-Command` was given; any script
  argument is now read. An `-EncodedCommand` script is decoded and read
  for write targets; its text is not scanned for patterns, so a payload
  inside it passes (BUG-067). `-File` scripts are not read. Parameter
  prefixes such as `-LiteralP` are not recognized (BUG-067), and a
  PowerShell tool command is not read for `git`, `bash -c` or `node -e`
  writes (BUG-048).
- **A shell copy is judged by what it copies (verification P1).** Writing a
  payload to an unwatched file and then `cp notes/x.md CLAUDE.md`,
  `cat x > CLAUDE.md` or `git apply p.diff` was allowed: the command text
  carried nothing to scan. The hook now reads the files whose content a
  command puts in a watched file (`cp`/`mv`/`install` sources, the
  operands of `cat`/`sort`/`head`-style commands under a redirect, `<`
  input, content piped into `tee`, `dd if=`, and the added lines of a
  patch for the files it names) and denies a CRITICAL finding the same way
  a Write would. A replace is compared as the new file, an append as the
  old file plus the new text.
- **Bash can no longer undo the settings protection by removing the
  folder (verification P2).** `rm -rf .claude`, `mv .claude .claude-old`
  and `git checkout HEAD~3 -- .claude/settings.json` were allowed, because
  only an exact settings-file target counted. A Bash target now counts
  when it is a settings file or a directory that holds one (so `rm -rf .`
  too); `mv` sources count as written; and `git checkout`, `restore`, `rm`
  and `mv` paths are read. Targets the command does not spell out (a
  variable, a glob, `node -e` code) are not seen by this hook.
- **The hook files and the scanner are protected (verification P3,
  BUG-027 in-hook half).** An agent could switch Guardian off without
  touching settings: `echo 'process.exit(0)' > .claude/hooks/injection-guard-hook.mjs`,
  or a Write of `security/01-injection-guard.js` that returns no
  violations, was allowed. Both hook scripts and the scanner now join the
  protected set on the same rule as the settings: a Write, Edit, MultiEdit
  or NotebookEdit of one, or a Bash or PowerShell target that is one or a
  directory holding one (`rm -rf security`, `mv .claude/hooks x`), asks,
  and is denied in bypass mode. The project's copies and the files the
  running hook loads are both covered. Any change asks, because the
  content is code the scanner cannot judge. Changing Guardian's own code
  in a bypass-mode session now needs a person.
- **Path spelling no longer dodges the watch list (verification P4, P5).**
  Matching was case-sensitive, so `.PLANNING/STATE.md` and
  `.Claude/agents/a.md` were not watched on Windows, where they are the
  same files; and an NTFS stream suffix (`CLAUDE.md::$DATA`) slipped past
  the end-anchored file patterns. Paths are now canonicalized (slashes,
  `..`, stream suffix) and matched without case. `ignorePaths` matches
  without case only on Windows and macOS, so an exemption never covers a
  different file on a case-sensitive file system.
- **An Edit is judged as the file it leaves (review finding 5).** Only
  `new_string` was scanned, so a payload split between the file and the
  edit, or between two edits, or joined by deleting the text between its
  halves, passed. Edit and MultiEdit are now applied to the file on disk
  (line endings normalized) and the result goes through `scanChange()`.
  An edit the hook cannot place is judged as appended text.
- **INJ-019 / INJ-020 match template delimiters, not headings (review
  finding 1).** `### System Overview`, `### Instructions` and
  `### Prompt Injection Defense` scanned CRITICAL, and so did YAML front
  matter that began with a `system` key. INJ-019 now needs the colon form
  (`### Instruction:`, `### System Prompt:`) and INJ-020 needs a delimited
  `--- SYSTEM ---`, `--- SYSTEM:` or `--- SYSTEM` alone on its line.
- **A payload can no longer exempt itself (BUG-021).** The
  `otlc-guardian:doc` marker inside the content being written used to skip
  the scan, and the warning text told the model about the marker. The
  hook no longer reads the marker at all. The first 1.5.0 build still
  honored a marker already on disk, which the review (finding 3) showed
  could be bypassed in two steps: write a marker-only file, then the
  payload. The only exemption is now `otlcGuardian.ignorePaths`, which
  the settings self-protection guards. The audit's own markers are
  unchanged.
- **INJ-027 / INJ-028 were cubic (BUG-023).** 44 KB of `<!--ignore `
  took 16 s and 99 KB ran past a minute, which stalled both hooks. Both
  rules now use a linear comment walker. SEC-011 had a quadratic case and
  is now length-bounded.
- **Scanner bypasses closed (BUG-024).** Each of these returned zero
  findings before: Unicode tag characters (ASCII smuggling), word joiner
  U+2060, Cyrillic/Greek lookalike letters, a percent-encoded payload next
  to any stray `%`, base64 embedded in prose, HTML entities, markdown
  emphasis inside the phrase, and a payload placed after 100 KB of filler
  (64 KB in the web hook). Content past the scan cap (now 1 MB) raises
  `INJ-OVERSIZE` instead of passing as clean.
- **Coverage gaps closed.** The hook now scans MultiEdit, NotebookEdit and
  Bash. The MCP web tools named in the web hook are now in the matcher, so
  they actually fire.
- **Self-protection for `.claude/settings.json`.** A change that removes a
  Guardian hook, sets `disableAllHooks`, turns `extendDefaults` off, adds
  to `ignorePaths`, or removes from `watchPaths` asks for confirmation.
  After the review (finding 4) it judges `settings.json` and
  `settings.local.json` together, as Claude Code merges them. Guardian's
  coverage is each (event, matcher token, exact command) its hooks run
  under, so narrowing a matcher (`Nothing`), altering the command (`node`
  to `echo`), or lowering the timeout is caught; widening a matcher or
  moving the hook between the two files is not a weakening. A Bash command
  that writes or deletes any `.claude/settings*.json` asks, because the
  hook cannot see the result. `disableAllHooks` asks in any settings file,
  including the user-level one.
- **Hook failures are loud.** A missing scanner, bad input or an internal
  error used to exit 0 with no output. The hooks still do not block on
  their own failure, but they say on stderr that the call was not scanned
  and exit 1.
- **Secrets that were missed (BUG-026):** OpenSSH, EC and encrypted
  private key headers (SEC-007), GitHub fine-grained and server tokens
  (SEC-012, SEC-013), Slack tokens (SEC-014), Stripe live keys (SEC-015),
  Anthropic OAuth and admin keys (SEC-010).
- Matched text echoed into the model's context is cut to 40 printable
  characters with markup characters removed.
- Python module (`security/injection_guard.py`) carries the same scanner
  changes.

### Added

- **`AUTHZ-011`, `AUTHZ-013`: authorization rules for Python.** `AUTHZ-001`
  and `AUTHZ-003` only read JS/TS, so FastAPI and Flask backends had no
  authorization coverage. A new indentation-aware analyzer finds route
  handlers under `@router.get/post/...` and `@app.route`, and reports a
  side effect with no auth, and a write by caller-supplied ID with no owner
  or tenant check. HIGH, not CRITICAL: auth wired up in another file
  (`include_router(dependencies=...)`, middleware) is invisible to a
  per-file analyzer. Tested on fixtures only; not yet run on a real
  Python project.
- **`WEB-001`: auth token in `localStorage` / `sessionStorage`.** CLAUDE.md
  has always banned this; nothing enforced it.
- **`WEB-002`: nginx server block with no Content-Security-Policy** in
  nginx, application code, or a meta tag.
- **`guides/tenant-isolation-tests.md`.** Test templates for the bugs a
  scanner cannot see: cross-customer reads and writes, a customer upload
  replacing a staff record, account shapes that escape tenant scoping, and
  sign-in limits that reset.
- In `bypassPermissions` mode the hook's two "ask" decisions become "deny",
  because prompts are off there and nobody would be asked.

### Fixed

- **AUTHZ-003 needs an ownership check tied to the caller (BUG-069).**
  The JavaScript IDOR rule took any `userId:` or bare `teamId` mention as
  an ownership check, so `where: { id: req.params.docId, userId:
  req.params.userId }` passed. Like AUTHZ-013 (BUG-030), the owner column
  must now be compared with or bound to the verified caller (`req.user`,
  `session.user`, `auth()` and similar) or a name taken from it first.
  AUTHZ-013 gains the same bound-name form (`uid = current_user.id`).

- **WEB-001 matches credential words, not substrings (BUG-033).** It
  missed `setItem(TOKEN_KEY, accessToken)` and
  `setItem("auth", JSON.stringify({ accessToken }))`, and flagged
  `setItem("refreshCount", "1")`. Keys may now be literals or
  identifiers, a value that names a token counts, and words are split
  at camelCase and non-letters, so `refreshCount`, `themeTokens` and
  `tokenizer` no longer count.

- **AUTHZ-011 no longer reports reads (BUG-032).** Every database
  `execute` counted as a side effect, so a `GET` running
  `db.execute(select(...))` was reported HIGH as an unauthenticated write.
  An execute is now a write unless the handler builds a select and no
  write (`insert(`, `update(`, `delete(`, or an INSERT, UPDATE, DELETE or
  DDL string); an execute of a statement built elsewhere still counts.
  AUTHZ-013 keeps counting reads, since a read by a caller-supplied id
  leaks the row.

- **AUTHZ-011 blind spots closed (BUG-031).** A router-level
  `Depends(get_db)` (or any `dependencies=[Depends(` in the file, a route
  decorator's included) silenced every Python handler in the file; now
  only a router built in the file whose dependency list is auth counts,
  and only for that router's handlers. Public routes are judged per path
  segment, so `/api/tokens/{token_id}` is no longer public. A bare
  `api_key` mention no longer counts as auth; `APIKeyHeader` and
  `Depends(get_api_key)` do.

- **AUTHZ-013 catches the textbook IDOR (BUG-030).** A 404 for a missing
  row and a caller-supplied `user_id` or `org_id` (path or signature
  parameter) counted as ownership checks, so a handler that deletes any
  document by id passed. Python ownership evidence must now tie the
  object to the authenticated caller (`Document.owner_id == user.id`,
  `filter_by(owner_id=current_user.id)`, `user.id != doc.owner_id`), or be
  an authorization helper, a permission or tenancy signal, or a 403.

- **INJ-001 matches `eval(` as a word, and `new Function(` (BUG-040).**
  The pattern had no boundary, so `retrieval(query)` was reported
  CRITICAL, and the description claimed a user-input check the rule does
  not make. It now skips names ending in `eval` and Puppeteer's
  `page.$eval(`, also catches `new Function(`, and is described as
  "eval() or new Function() runs a string as code".

- **DEP-002 can fire (BUG-039).** A bare `.env` has no extension, so the
  walker never collected it and the committed-`.env` check never ran.
  `collectFiles()` now keeps a `.env` by name, for DEP-002 only (the
  secret rules still do not read it). DEP-002 asks git: a tracked `.env`
  is reported even if `.gitignore` lists it, an ignored untracked one is
  not, and with no git or no repository the file is reported. DEP-001 no
  longer counts a `HEALTH...` variable in `.env` as a health route.

- **`guardian scan` exits non-zero on a finding (BUG-068).** It printed
  the findings and exited 0, so `cat untrusted.txt | guardian scan &&
  send-to-model` sent poisoned text on. Exit codes are now 0 clean, 1 at
  least one pattern, 2 nothing scanned (no text, which used to be 1, or a
  scanner that failed to load, which used to be an uncaught exit 1).

- **A project under a folder named `test`, `tests` or `spec` keeps its
  rules (BUG-052).** The test-file exclusions ran on the absolute path,
  so every file of such a project counted as test code and lost the 17
  test-excluded rules. `excludedByRule()` now tests the path inside the
  project root.

- **What an audit exemption means for the project checks is defined
  (BUG-059).** An exemption silences findings about a file and never
  hides the file as evidence. The absence checks DEP-001 and WEB-002
  keep reading exempt files (a health route or CSP header there still
  counts); the presence check DEP-002 now leaves exempt files out, so an
  allowlisted `.env` is not reported. Tested and documented in manual
  chapter 06.

- **Only a marker comment exempts a file (BUG-057).** Any occurrence of
  `otlc-guardian:audit-exempt` in a file's first 4 KB used to exempt it,
  including a string, a regex or a sentence about the marker. The marker
  now counts only on its own comment line (`//`, `#`, `/*`, `*`, `<!--`,
  `--`), as a whole word. A file that relied on a bare mention is audited
  again; give it a real marker line or an allowlist entry.

- **An allowlist entry with an empty reason is rejected (BUG-056).**
  `src/a.js  # reason:` with nothing after the prefix used to exempt the
  file, though SECURITY.md says entries without a reason are rejected.
  `loadAllowlist()` now ignores the line and warns
  `.audit-allowlist:N - reason is empty, line ignored`.

- **Audit secret rules now cover every runtime secret format (BUG-054).**
  The 1.5.0 runtime widening (BUG-026) had not reached the audit, so a
  committed fine-grained GitHub token or an OpenSSH key passed
  `guardian audit`. SEC-003 now matches every GitHub token form (`ghp_`,
  `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), SEC-004 any PEM private
  key header, and SEC-010 Anthropic OAuth and admin keys; SEC-011 is
  length-bounded like the runtime rule. New rules: SEC-012 (Google API
  key), SEC-013 (Slack token), SEC-014 (Stripe live key). The audit now
  has 45 rules (37 pattern, 5 analyzer, 3 project). A test maps every
  runtime `GUARD-SEC` id to its audit rule and fails when one is missing.

- **An unreadable file no longer crashes the audit (BUG-055).** DEP-001's
  check read every file with a bare `readFileSync`, so a file that
  vanished or lost its read permission mid-scan threw out of `runAudit`.
  It now reads through `readForCheck()`, which names the file and the
  reason on stderr (stdout stays clean for `--json`) and counts the file
  as having no text.

- **Importing the audit module no longer runs an audit (BUG-053).** The
  CLI block at the bottom of `security/03-audit.js` ran on every load, so
  `import { runAudit } from "otlc-guardian/audit"` audited the importer's
  directory and could exit its process. It now runs only when the file is
  the program Node started, compared by real path so npm's bin symlink still
  works.
- **`init` installs a project's files, not Guardian's repo files
  (BUG-060).** It copied Guardian's whole `.github/` folder, including a
  `CODEOWNERS` that made Guardian's maintainer the owner of everything, and
  Guardian's issue and PR templates; and it copied Guardian's own audit
  allowlist, whose `bin/` and `tests/` entries exempted whatever a project
  kept at those paths. `init` now adds only the audit workflow and
  `secret_scanning.yml`, and writes a project allowlist with entries for the
  `security/` modules it installs. An existing allowlist is never rewritten.
  Projects set up earlier keep the copied files; SETUP.md lists them.
- **An invalid settings file stops `init` and `update` before they write
  (BUG-061).** Invalid JSON in `.claude/settings.json` was found only at step
  6, after the behavior files, `.gitignore`, `.env.example` and `security/`
  were written, and the run ended in a stack trace. A preflight now refuses
  invalid JSON and valid JSON that is not an object before any write, and a
  later failure prints the reason and what to do instead of a stack trace.
- **A bad audit argument no longer passes (BUG-051).** A path that did not
  exist scanned 0 files and exited 0, even with `--fail-on-error`, and an
  unknown flag was ignored, so a CI typo turned the gate into a pass. An
  unknown flag, a second path or a missing path is now a usage error (exit
  2, message on stderr, nothing scanned). `--help` prints usage. `guardian
  audit` passes the code through and treats a child killed by a signal as a
  failure.
- **`guardian check` fails on a broken or unregistered hook (BUG-062).** A
  failed hook smoke test was a warning and `check` still printed "correctly
  installed" and exited 0, and nothing read `.claude/settings.json`, so the
  CI gate could not fail on a hook that protects nothing. A failed smoke test
  (including the hook's own fail-open exit) is now a failure, and a new
  registration check requires both hooks in `settings.json` or
  `settings.local.json` on matchers that cover `Write` and `WebFetch`.
  Invalid JSON and `disableAllHooks` fail too.
- **The hook no longer fails open in CommonJS projects (BUG-063, first half).**
  The scanner is an ES module with a `.js` extension, so in a project whose
  `package.json` says `"type": "commonjs"` (npm 11's `npm init -y` default)
  the hook could not load it and let every write through unscanned. A new
  `security/package.json` with `"type": "module"` pins the folder; `init`
  installs it, `update` restores it, `check` requires it, and `init` warns
  when an existing one says otherwise. The hook does not protect that file
  yet.
- **Partial scans gave wrong project-level answers (BUG-041).** Reported by
  DevNeural: auditing `07-daemon/src/capture/hooks` reported DEP-001 though
  the project serves a health route in another folder. Project checks
  answered from the scanned subtree only. Checks that prove an absence
  across the project (DEP-001, WEB-002) now read the project root's files
  on a partial scan, and their finding names the project root; DEP-002, a
  presence check, still reads the scanned files. A single file given as
  the target used to scan nothing at all; it is now audited.
- **Docs that disagreed with the code (review finding 15).** The audit
  rule breakdown is now the audit's own header (34 pattern, 5 analyzer,
  3 project; 42 in all) in README.md and the skill, which still said 33.
  SECURITY.md said 9 secret patterns; there are 16. SETUP.md listed the
  PreToolUse hook as Write/Edit only, and README.md and SETUP.md gave the
  web hook's matcher without the MCP tool names it registers.
- **`guardian update` did nothing for an existing install (BUG-025).** It
  was an alias for `init`, which never overwrites a file, so no fix ever
  reached a project that already had Guardian. `update` now replaces
  Guardian-owned files (`security/*`, `.claude/hooks/*`) and the marker
  sections of the behavior files, and moves Guardian's hook registration
  to the current matcher. `security/.audit-allowlist`, `.github/` and
  everything outside the markers are left alone.
- The Edit branch scanned `old_string`, so removing a bad line was flagged.
  Only added content is scanned now.
- Project root comes from `CLAUDE_PROJECT_DIR`, then the payload `cwd`,
  then `process.cwd()`.
- An empty string in `ignorePaths` matched every path and turned the hook
  off. Empty entries are skipped.
- The in-memory rate limiter never evicted keys. Expired windows are swept
  once the map passes `RATE_LIMIT_SWEEP_THRESHOLD` (default 10000).
- `security/.audit-allowlist` claimed CI fails when the allowlist grows.
  CI only prints the count; the comment now says so.

### Changed (behavior you will notice)

- A write that used to produce a warning can now be refused.
- A documentation file that gains new injection examples must be listed in
  `ignorePaths`; the `otlc-guardian:doc` marker no longer exempts anything
  from the hook.
- Hook matchers changed. Existing projects are migrated by `guardian update`.
- `guardian update` overwrites local edits to Guardian-owned files.
- **Runtime scanner rule ids gained the engine prefix `GUARD-`.** The
  scanner (`01-injection-guard.js`, `injection_guard.py`, both hooks) and
  the audit (`03-audit.js`) numbered their `INJ-*` and `SEC-*` rules
  separately, so one id meant two rules: `INJ-001` was "ignore previous
  instructions" in the scanner and `eval()` in the audit, and `SEC-002`
  was a Google key in one and an AWS key in the other. Audit ids are
  unchanged, since they are what projects cite in bug logs, CI output
  and the guides, and the allowlist names paths, not ids. Each scanner
  violation also carries its old id as `legacyId` (Python: `legacy_id`)
  for this release; it is removed in 1.6.0. Entries above this one, and
  older releases, use the old scanner ids.

  | Old scanner id | New id |
  |---|---|
  | `INJ-001` to `INJ-028` | `GUARD-INJ-001` to `GUARD-INJ-028` |
  | `INJ-UNICODE`, `INJ-OVERSIZE` | `GUARD-INJ-UNICODE`, `GUARD-INJ-OVERSIZE` |
  | `SEC-001`, `SEC-001b`, `SEC-002` to `SEC-015` | `GUARD-SEC-001`, `GUARD-SEC-001b`, `GUARD-SEC-002` to `GUARD-SEC-015` |

### Known limits (not fixed here)

- Detection is pattern-based. A reworded instruction with no known
  pattern still passes.
- The content hook judges what a command spells out. It does not see a
  target held in a variable, computed by inline code (`node -e` with
  `path.join`) or matched by a glob; a script file or a PowerShell `-File`
  script that writes the target; content assembled or encoded in the
  shell (`printf` octal, `rev`, `tr` rot13, `base64 -d`, variable
  concatenation, quote-split words); or git branch switches, `reset`,
  `stash` and `merge`, which replace files without naming them. These are
  inputs for the planned hard-no hook that DevNeural hosts, not for this
  hook.
- The hook command in `.claude/settings.json` is still a relative path.
  Whether to switch it to `$CLAUDE_PROJECT_DIR` needs a test on Windows.

---

## [1.4.1] - 2026-07-20

`INJ-005b` precision. The rule was reporting ordinary UI strings as CRITICAL
SQL injection, which is the worst failure mode a security tool has: the fix
users reach for is switching it off.

### Fixed

- **`INJ-005b` no longer fires on English prose (BUG-001).** The 1.3.0
  pattern required only a lone SQL verb plus an interpolation. `SELECT`,
  `INSERT`, `UPDATE`, `DELETE`, `DROP`, and `ALTER` are also ordinary
  English words, so ordinary UI strings matched:

  ```js
  window.confirm(`Delete asset ${asset.name}?`)          // was CRITICAL
  console.error(`Failed to update record ${record.id}:`) // was CRITICAL
  ```

  A real audit of a Base44-generated project returned 6 CRITICAL findings,
  **all six false positives from this single rule**. In any codebase on an
  ORM with no direct SQL, every match was noise.

  Each SQL verb must now appear with its mandatory companion keyword:
  `SELECT`..`FROM`, `INSERT INTO`, `UPDATE`..`SET`, `DELETE FROM`, and
  `DROP`/`ALTER`/`TRUNCATE` with `TABLE`/`DATABASE`/`INDEX`/`VIEW`/`SCHEMA`.
  Real SQL has clause structure; prose does not. "Delete asset" has no
  `FROM`; "failed to update record" has no `SET`. Valid SQL essentially
  always carries the companion clause, so precision rose with no meaningful
  coverage loss.

  The internal handoff had proposed inverting the rule to a call-site match
  instead. That was rejected: a call-site match is exactly what `INJ-005`
  already does, so `INJ-005b` would have become a duplicate and the
  variable-indirection bypass it exists to close (see 1.3.0) would have
  reopened. Declaration-site detection is the point of the rule. A
  regression test now fails if anyone makes that change.

  Two details the fix had to get right. The interpolation check is a
  lookahead asserting `${` appears anywhere in the template rather than
  after the clause pair, because `` `SELECT ${columns} FROM users` `` is a
  genuinely unparameterized query whose only interpolation sits between the
  verb and its clause. And a `(?<!\bsql)` lookbehind clears the sql-guard
  tagged template from `security/04-sql-guard.js` - that tag is the
  auto-parameterizing remediation for this bug class, and flagging the fix
  is how you teach people to stop applying it. The exclusion is narrow
  enough that `mysql\`` and an untagged sibling on the next line both still
  fire.

  No secondary lower-severity hint was added for near-misses. A MEDIUM
  noise channel would reinstate the exact problem this fix removes, and the
  clause-pair test is orthogonal to the call site - a custom DB wrapper is
  still caught as long as the SQL it builds is really SQL.

- **Rule id collision in the audit-improvements plan (BUG-004).** The
  internal handoff specified `DEP-001` for a planned npm-version-drift rule.
  That id already belongs to `DEP-001 - No health check endpoint found`,
  shipped since 1.2.4 and covered by tests. Implementing as written would
  have put two rules under one id and broken per-id filtering for JSON
  consumers and CI gates. Reassigned to `DEP-003` with a correction note in
  the document. No shipped behavior changed; this is a planning defect
  caught before it reached code.

### Added

- **`BUGS.md`** - persistent bug tracker, seeded with a consolidated sweep
  of 20 known bugs (4 OPEN, 3 DEFERRED, 13 RESOLVED) drawn from the git
  log, CHANGELOG, code comments, and the audit-improvements handoff.

### Testing

13 new tests for `INJ-005b` (83 in `audit.test.js`, 246 across the suite).
Positive fixtures cover all five verb/clause pairs plus the
interpolation-before-clause case; negative fixtures are the exact shapes
that misfired in the real-world run. Includes a BUG-017 regression guard
that keeps the variable-indirection bypass closed.

---

## [1.4.0] - 2026-07-20

Authorization and validation coverage. Guardian could already find a
leaked key, a silent catch, and a concatenated SQL string. It could not
find the two bugs AI coding assistants generate most: an endpoint with no
authentication, and an endpoint that authenticates but never checks
whether the caller may touch the object they named.

Neither is expressible as a regular expression. Both are *absence*
conditions scoped to a block - "nowhere inside these braces is there an
auth check" - and negative matching across an arbitrarily nested block is
not something a regular language can do. So the audit engine gained a
third rule kind rather than shipping a regex approximation that would fire
on unrelated files.

### Added

- **Per-file analyzer rule kind.** Rules may now supply
  `fileCheckFn(content, filePath) -> [{ line, content }]` alongside the
  existing `pattern` (regex) and `checkFn` (project-level predicate)
  kinds. The analyzer extracts route-handler bodies by string- and
  comment-aware brace matching, then tests for the presence or absence of
  authentication, side effects, caller-supplied object IDs, ownership
  checks, and schema parsing. Handler signatures are recognised across
  Express/Fastify route registration, Next.js App Router route handlers,
  Next.js Pages Router / Vercel serverless default exports, and arrow-form
  exports. Exemptions (`otlc-guardian:audit-exempt` marker and the central
  `security/.audit-allowlist`) apply to analyzer rules identically to
  pattern rules. An analyzer that throws on a malformed file warns and
  continues rather than aborting the run.

- **Seven rules across two new categories.**

  | Rule | Severity | Kind | Detects |
  |---|---|---|---|
  | `AUTHZ-001` | CRITICAL | analyzer | Handler performs a side effect with no authentication check |
  | `AUTHZ-002` | CRITICAL | pattern | Identity read from request body/query instead of a verified session |
  | `AUTHZ-003` | CRITICAL | analyzer | IDOR - authenticated handler acts on a caller-supplied object ID with no ownership check |
  | `AUTHZ-004` | HIGH | pattern | Secret compared with `===` rather than `crypto.timingSafeEqual` |
  | `AUTHZ-005` | HIGH | pattern | Cache key not scoped to the requesting user, so a cache hit bypasses authorization |
  | `VAL-001` | HIGH | analyzer | Request body reaches a side effect without a schema parse |
  | `VAL-002` | CRITICAL | pattern | Raw email header built by interpolation - CRLF injection makes it an open relay |

  Detection is deliberately conservative. `AUTHZ-001` only fires when the
  handler contains a real side effect, so a read-only or computational
  route is never flagged. `AUTHZ-003` only fires when the handler *does*
  authenticate, so an unauthenticated route is reported once by
  `AUTHZ-001` rather than twice under two rule IDs.

- **`guides/` - three field guides, stored verbatim.**
  `securing-endpoints.md`, `authorization-idor.md`, and
  `form-validation.md`, sourced from
  [The Lazy Developer](https://www.thelazydeveloper.org/resources).
  Every new rule carries a comment pointing back at the guide section it
  was written against, and `guides/INDEX.md` maps each finding to the
  guide that explains the fix.

- **`skill/SKILL.md` - Guardian as an invocable skill.** Any project can
  now reach the standards without installing the package, via a junction
  at `~/.claude/skills/OTLC-Guardian`. The skill runs the audit, maps
  findings to guides, and enforces the self-audit checklist.

- **Audit status line reports all three rule kinds**, e.g.
  `Rules : 28 pattern · 3 analyzer · 2 project`.

### Testing

24 new tests in `tests/audit.test.js` (70 total, up from 46). Every new
rule has both a firing fixture and a silent fixture - a security rule that
cannot be quieted by writing correct code is a rule people switch off.
Additional coverage for brace-matching inside string literals (a `}` in a
string must not truncate a handler body) and for exemption handling on
analyzer rules. Verified against a synthetic well-written Next.js API
surface (zero findings) and its vulnerable twin (all seven rules firing on
the correct lines).

---

## [1.3.1] - 2026-04-08

Comprehensive pre-release adversarial review pass. Codex CLI was tasked
with a hostile audit of the entire 1.3.0 release covering README clarity,
CLI UX, hidden assumptions, audit-rule edge cases, hook/runtime parity,
documentation consistency, and npm publish readiness. This release ships
fixes for **every actionable finding** Codex returned that was safe to
apply without changing the project's product positioning.

The most important fix is the README uninstall data-loss bug - the
README at line 380 was telling users to `rm -f CLAUDE.md AGENTS.md
GEMINI.md STANDARDS.md`, which would destroy any project-specific rules
the user wrote before running `guardian init`. This was the same bug
already fixed in `SETUP.md` back in PR #4 but never propagated to the
README. It is now removed and replaced with a marker-based manual
procedure that links to the full SETUP instructions.

This is a patch release. No breaking API changes for the runtime guard,
the audit CLI, or the SQL helper. **One soft-breaking change** for
Python FastAPI users - see SECURITY FIX #2 below.

### Security fixes

1. **Hook/runtime scanner parity (Codex HIGH #1).** Both Claude Code
   hooks (`.claude/hooks/injection-guard-hook.mjs` and
   `.claude/hooks/web-content-guard.mjs`) used to walk the raw
   `INJECTION_PATTERNS` array directly, bypassing the runtime guard's
   NFKC normalization, invisible-Unicode stripping, URL-decode, and
   base64-decode passes. That meant a fullwidth-Unicode or `%`-encoded
   prompt-injection payload would slip past the hooks even though
   `guardInput()` (or any direct `scan()` call from the user's app)
   would catch it. Both hooks now import the public `scan()` function
   from `security/01-injection-guard.js` and call it directly. Hook
   coverage is now byte-for-byte identical to runtime coverage; no
   bypass class can defeat the hook without also defeating the runtime
   guard. The pattern array is no longer duplicated across the hook
   files at all.

2. **FastAPI dependency now returns sanitized input (Codex HIGH #2).**
   `make_fastapi_guard()` in `security/injection_guard.py` used to call
   `guard_input()` and discard the sanitized return value. The Node
   middleware (`injectionMiddleware()` in `01-injection-guard.js`)
   correctly writes the sanitized value back into `req.body[field]`,
   but the Python helper just relied on the side effect of raising on
   critical violations. That meant non-blocking but sanitizable input
   (for example a string with a zero-width-space bypass) would reach
   the endpoint UNCHANGED in Python while being correctly sanitized in
   Node. Fixed by capturing the `guard_input()` return value and
   returning it from the dependency, so the endpoint receives the
   sanitized version through `Depends()`.

   **SOFT-BREAKING for Python FastAPI users:** if you were using the
   helper as `_=Depends(guard)` to discard the return value, switch to
   `clean_message: str = Depends(guard)` to receive the sanitized
   string. The old form still works (the dependency still raises
   `HTTPException` on critical violations) but it now silently
   discards the sanitized output, leaving the unsanitized raw input
   reachable via `body["message"]` if your endpoint reads it directly.
   The new form is documented in the helper's docstring and in
   `FAQ.md`.

3. **Audit subdirectory scoping (Codex HIGH #3).** `guardian audit
   ./src` was treating the scan target as the project root for both
   the file walker AND the project-shape lookups. That meant manifest
   checks (`looksLikeHttpServer()`) and the central `.audit-allowlist`
   load both looked at `./src/package.json` and
   `./src/security/.audit-allowlist`, neither of which exist. Result:
   subdirectory audits silently disabled DEP-001 gating AND ignored
   project-level exemptions, producing different findings than the
   same audit run from the project root.

   Fixed by adding a `findProjectRoot(scanDir)` helper that walks
   upward from the scan target looking for project markers (`.git/`,
   `package.json`, `requirements.txt`, `pyproject.toml`, `Pipfile`,
   `security/.audit-allowlist`), capped at 8 levels deep. The audit
   now distinguishes `scanRoot` (where the walker walks) from
   `projectRoot` (where manifests, allowlists, and project-shape
   lookups are read). The walker still walks the user's chosen scan
   target; everything else consults the upward-walked project root.
   Reported in the audit header as `Project : <path>` whenever the
   two diverge.

   Three new tests in `tests/audit.test.js` cover the contract: DEP-001
   fires correctly when scanning a subdirectory of an express project,
   does NOT fire when scanning a subdirectory of a CLI project, and
   the project-root allowlist is honored when scanning a subdirectory.

### Audit rule fixes

4. **`INJ-005b`, `SEC-*`, `CFG-*`, `ERR-*`, `INJ-*`, `API-001`, `TS-001`
   now scan modern JS module extensions (Codex HIGH #5).** Pre-1.3.1
   most rules hardcoded `[".js", ".ts", ".jsx", ".tsx"]` and silently
   missed `.mjs/.cjs/.mts/.cts` files. Modern Node projects (post-2020)
   commonly use these extensions for explicit ESM/CommonJS module
   declarations, and any rule that didn't include them was a silent
   coverage gap. The 1.3.0 release fixed this for `INJ-005b` only;
   1.3.1 applies the same fix to every JS/TS rule.

   Fixed by introducing four centralized extension constants at the
   top of `security/03-audit.js`:

   - `JS_TS_EXTS` - every JS/TS module extension we scan (`.js`,
     `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`)
   - `JS_TS_PY_EXTS` - same plus `.py`
   - `SECRET_FILE_EXTS` - JS/TS/Python plus the data-format extensions
     where credentials commonly leak (`.env`, `.json`, `.yaml`, `.yml`)
   - `TS_EXTS` - TypeScript-only (`.ts`, `.tsx`, `.mts`, `.cts`) for
     `TS-001` (`any` type detection)

   Every rule's `fileTypes` array now references one of these
   constants instead of hardcoding its own list. New file-extension
   support flows through the whole rule set automatically.

### Documentation fixes

5. **README uninstall instructions no longer destroy user data
   (Codex CRITICAL #1).** The README at line 380 told users to
   `rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md` and
   `rm -rf security/`. Both contradict Guardian's merge-safety
   contract - `guardian init` appends Guardian content below
   `<!-- OTLC-GUARDIAN-START -->` markers inside those files, and a
   blanket `rm -f` would destroy every line the user wrote above the
   marker. The same bug was already fixed in `SETUP.md` back in PR #4
   but never propagated to the README until now.

   Fixed by removing the dangerous block entirely and replacing it
   with a marker-based manual procedure that links to the full
   `SETUP.md § Uninstalling` walkthrough. README now calls the bug
   out explicitly so users with old README copies in their cache
   don't get caught by the obsolete instructions.

6. **CI dependency-scan honesty (Codex HIGH #4).** `npm audit` and
   `pip-audit` in `.github/workflows/security-audit.yml` run with
   `continue-on-error: true`, meaning they report vulnerable
   dependencies in the run log but do NOT fail the workflow. The
   pre-1.3.1 README sold this as "Dependency vulnerability checks"
   without the asterisk, which contradicted the STANDARDS.md OWASP
   checklist (which says HIGH/CRITICAL findings should block release).
   Fixed by:
   - Adding inline workflow comments explaining the
     advisory-only stance and the rationale (`npm audit` can flag a
     fresh CVE before any fixed version exists, and a hard-fail gate
     would brick PRs in that window).
   - Updating README's "What you get" list to label each CI step as
     either **blocking** or **advisory**.
   - Adding a footnote to `STANDARDS.md § CI/CD` that says: the
     standard is "block on HIGH/CRITICAL," but Guardian's own template
     ships with "advisory only" as the default because it serves a
     wide variety of project types - projects that want hard-fail
     should remove `continue-on-error: true` from their fork.

7. **Python parity overstated (Codex HIGH #7).** README was claiming
   "Two languages (Node and Python) at parity" but only the injection
   guard has a Python implementation; `02-code-security.js` (server
   utilities), `03-audit.js` (the audit CLI), and `04-sql-guard.js`
   (the SQL helper) are all Node-only. FAQ also pointed users at the
   wrong path (`python/injection_guard.py` instead of
   `security/injection_guard.py`) and instructed them to install
   `structlog` even though the Python module uses stdlib `logging`.

   Fixed by rewriting the "Layer 2 - The Runtime Security Layer"
   section in README to label each component's language support
   honestly:
   - `01-injection-guard.js` / `injection_guard.py` - both Node and
     Python at parity
   - `02-code-security.js` - Node only
   - `03-audit.js` - Node script that scans both Node AND Python
     source
   - `04-sql-guard.js` - Node only (Python equivalent on the roadmap)

   The FAQ entry was rewritten to use the correct path
   (`security/injection_guard.py`), explicitly say "do NOT install
   structlog," and show the full FastAPI usage pattern with the new
   `clean_message: str = Depends(guard)` form.

8. **`SETUP.md` uninstall section updated for 1.1.1+ AGENTS.md/GEMINI.md
   reality (Codex MEDIUM #1).** SETUP step 5 still listed `AGENTS.md`
   and `GEMINI.md` under "files Guardian never creates" with a
   "future release" note. That was true pre-1.1.1; both files have
   been Guardian-managed since 1.1.1. Updated:
   - Step 1 (un-merge) now lists `AGENTS.md` and `GEMINI.md` alongside
     `CLAUDE.md` and `STANDARDS.md`.
   - Step 5 (do not touch) now only lists files Guardian truly never
     creates: `.cursorrules`, `.windsurfrules`, `.aider.conf.yml`,
     `copilot-instructions.md`. The "future release" note is replaced
     with an "updated 1.3.1" note flagging the move for users reading
     older versions of the doc.

9. **Stale rule counts in README (Codex MEDIUM #2).** README said
   "23 rules in 1.1.1" in two places. The current count is 24
   (INJ-005b was added in 1.3.0). Updated both references and added
   a hint pointing users at `node bin/guardian.js help` for the
   current count so future bumps don't strand the README.

10. **`CONTRIBUTING.md` test count fix (Codex LOW #3).** Said `npm
    test` runs "all 90 tests." Updated to "the full test suite (6
    test files, 100+ assertions)." Stopped hardcoding numbers because
    they always go stale.

### CLI fixes

11. **Web hook overclaim hardened (Codex MEDIUM #3).**
    `web-content-guard.mjs` claimed to handle "any other web content
    tool registered against this hook" but the code hardcoded four
    tool names (`WebFetch`, `WebSearch`, `mcp__firecrawl__crawl`,
    `mcp__exa__search`). The misleading comment is gone; the watched
    set is now declared as a top-level `WATCHED_TOOLS` constant with
    a clear comment explaining that adding a new tool requires
    fork-and-edit. Configurability via `.claude/settings.json` is on
    the roadmap but explicitly not in this release - the surface
    needs careful thought to avoid users accidentally disabling the
    security default.

12. **`editorCoverage()` no longer reports false coverage for Gemini
    CLI (Codex MEDIUM #4).** Pre-1.3.1, `runCheck()` reported Gemini
    CLI as `BEHAVIOR-ONLY` whenever `GEMINI.md` existed, even if
    `AGENTS.md` was missing. Since `GEMINI.md` is a pointer file
    (it tells Gemini "read AGENTS.md and CLAUDE.md"), a missing
    `AGENTS.md` means the pointer dangles and Gemini loads no
    Guardian rules even though `GEMINI.md` exists. Now reports
    `PARTIAL` with the message "GEMINI.md present but AGENTS.md
    missing - pointer dangles, no rules loaded" in that case.

13. **CLI color/emoji output is TTY-gated (Codex MEDIUM #5).** Pre-1.3.1
    every `guardian` command emitted unconditional ANSI escape
    sequences and emoji glyphs (✅, ⚠️, ❌). That polluted redirected
    output (`guardian audit > findings.txt` would have raw escape
    codes inside the file) and broke some non-ANSI Windows terminals.
    Now:
    - ANSI sequences are silenced when `process.stdout.isTTY` (or
      `process.stderr.isTTY` for warn/err) is false
    - The `NO_COLOR=1` environment variable is honored (per the
      no-color.org convention)
    - A new `--no-color` flag forces plain output regardless of TTY
      state, useful in CI logs and pipes
    - Emoji glyphs are replaced with ASCII tags (`[ok]`, `[warn]`,
      `[err]`) when colors are off, so a UTF-8-impaired Windows
      console doesn't render mojibake
    - The `--no-color` flag is stripped from `process.argv` before
      the per-command parsers see it, so it doesn't accidentally
      become a positional argument

14. **`guardian scan` accepts piped stdin (Codex LOW #1).** Pre-1.3.1
    `guardian scan` only accepted positional argv text, which made
    it useless in pipelines. Now supports all of:
    ```bash
    guardian scan "ignore all previous instructions"   # positional
    echo "untrusted text" | guardian scan              # piped stdin
    guardian scan < input.txt                          # stdin redirect
    ```
    Stdin reads are gated on `!process.stdin.isTTY` so an interactive
    `guardian scan` with no args still shows usage instead of hanging
    on a blank stdin. A 5-second timeout protects against pathological
    pipe stalls.

### Package metadata

15. **`package.json` description and keywords no longer Claude-centric
    (Codex LOW #2).** Updated description to "Production-grade AI
    security guardrails for any AI coding agent (Claude Code, Codex,
    Cursor, Aider, Continue, Windsurf, Gemini)..." and expanded
    keywords from 9 to 22 entries - added agent names (`claude-code`,
    `codex`, `cursor`, `aider`, `continue`, `windsurf`, `gemini`,
    `agents-md`) and feature names (`audit`, `audit-cli`,
    `sql-injection`, `parameterized-queries`, `secrets-detection`).
    Better discoverability via `npm search` and Google.

16. **Internal version headers aligned to 1.3.1 (Codex LOW #4).**
    Pre-1.3.1, internal file version headers ranged from `1.0.0` to
    `2.0.0` (the PreToolUse hook claimed 2.0.0 for some reason)
    while the package was at 1.3.0. They're now all at 1.3.1, in
    lockstep with `package.json`. The test files keep their per-test
    version headers because those legitimately document "what
    version added this test."

### Verification

- `npm test` - all 6 test files green: injection-guard, init, hook,
  agents-md, **audit 52/52** (up from 48/48 in 1.3.0 - added 4 new
  tests for the projectRoot/scanRoot fix), sql-guard 40/40
- `node security/03-audit.js .` - `No issues found` on the Guardian
  repo. **24 rules** (unchanged - no new rules in 1.3.1, only fixes
  to existing rules' file-type coverage).
- `node bin/guardian.js check` - 15 passed, 0 warnings, 0 missing
- `node bin/guardian.js help` - footer shows `Version 1.3.1`
- `guardian audit` and `guardian scan` exercised in TTY, piped, and
  `--no-color` modes; output adapts correctly in all three.
- 12-project real-world re-audit - no false positives from any of the
  rule changes. Same finding totals as 1.3.0.

### Things explicitly NOT changed in this release

These were findings or considerations in the Codex review that the
assistant deliberately did not act on without user input. Each is on
the roadmap but requires a product decision the user has not made yet.

- **CI dependency scans switching from advisory to blocking
  (Codex HIGH #4 second half).** Codex flagged this as "the right
  default for a security-forward template, but it will break some
  user repos immediately." This is a positioning call that needs the
  user's go-ahead. The honesty fix (item 6 above) IS in this release;
  the behavior change is not.
- **Primary install path becoming `npm install -g otlc-guardian`
  instead of `git clone && npm install -g .` (Codex HIGH #6).** Codex
  said this is the right move for an npm-bound release but called it
  "a product/positioning call." The README still documents the
  source-clone path as primary because the package isn't on npm yet.
  When the user actually runs `npm publish`, the install instructions
  in README and SETUP should flip - that's a separate commit.
- **Hook configurability via `.claude/settings.json`.** Codex
  flagged the four hardcoded web tools as a place to add user
  configurability. The honesty fix (item 11 above) is in this release;
  the configurability surface needs careful design and is deferred.
- **Whether the npm package should ship `.github/` and `.claude/`.**
  Codex asked whether these directories belong in the public package
  surface. They currently do, because `guardian init` copies them
  into target projects. Changing that would require redesigning the
  init flow.
- **Python equivalent of `04-sql-guard.js`.** Still deferred - Python
  has no tagged template literals, so the design needs to be a
  context manager or `?` placeholder wrapper. ~4-8 hours of work and
  a separate Python test suite.

---

## [1.3.0] - 2026-04-08

Audit blind-spot fixes plus release-readiness improvements. Two new
audit tests cover bypass patterns the pre-1.3.0 ruleset silently
missed; one new audit rule (`INJ-005b`) catches the variable-indirection
form of template-literal SQL; the existing `INJ-006` Python rule was
rewritten so it actually fires on real-world SQL containing inner
quoted literals (the most common case). Plus npm publish hygiene and
a GitHub Actions Node 20 deprecation fix.

Minor version bump (`1.2.4` → `1.3.0`) because rule additions and
behavior changes are not patches under semver - adding a new rule
that fires on previously-clean code is a feature, not a bugfix.

### Added

- **`INJ-005b`** - new CRITICAL rule that catches template-literal
  SQL with `${}` interpolation **regardless of how the variable is
  used**. The pre-1.3.0 `INJ-005` rule required the backtick template
  to be the first argument of `query|execute|exec|raw|prepare`, so a
  trivial two-line refactor bypassed it:
    ```js
    const sql = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(sql);   // INJ-005 misses this - no backtick at the call site
    ```
  Writing the dangerous template literal anywhere in source is
  independently a bug, whether the variable is then passed directly
  to `db.query(sql)` or through ten more levels of indirection.
  `INJ-005b` catches the **declaration site** instead of the call
  site. Both rules are kept; they're complementary. A direct call
  fires both - slightly redundant but harmless.

- **`package.json` `files` field** - explicit allowlist of what
  `npm publish` actually ships. Pre-1.3.0 the package fell back to
  `.gitignore` (which is the wrong tool for the job - `.gitignore`
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
  `WHERE name = 'admin'` - which is most real-world SQL - broke
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
  the CI invocation list - both were running locally and via `npm
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
  reason field per the `.audit-allowlist` format contract - silent
  exemptions are forbidden.

### Verification

- `npm test` - all 6 test files green: injection-guard, init, hook,
  agents-md, **audit 48/48 (was 40/40 in 1.2.4)**, sql-guard 40/40
- `node security/03-audit.js .` - `No issues found` on the Guardian
  repo. **24 rules** (up from 23 in 1.2.4 - INJ-005b added).
  **7 allowlisted files** (up from 5).
- `node bin/guardian.js check` - 15 passed, 0 warnings, 0 missing
- 12-project real-world re-audit (DevNeural, NLT, omnibomber, autolisp,
  blkbom, Claude-Setup, conveyor-designer, conveyornum, devneural-projects,
  dev-template, Landmark40, skill-connections) shows **zero false
  positives from INJ-005b or the rewritten INJ-006**. The new rules
  are correctly scoped - they catch the dangerous patterns without
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
- The Python equivalent of `04-sql-guard.js`. Still deferred - Python
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

## [1.2.4] - 2026-04-08

`DEP-001` false-positive fix. The pre-1.2.4 `DEP-001 - No health check
endpoint found` rule fired on every project that didn't contain the
substring `health` in any file. It was designed for HTTP services but
had no project-shape detection, so every CLI tool, static site, library,
npm package, code-generation skill, desktop app, and notebook produced
a spurious `MEDIUM` finding telling the user to add a `/health`
endpoint to a project that should never have one.

Real-world audit testing across 12 projects on a developer machine
showed 9 of them hitting exactly this false positive - they are not
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

- **`security/03-audit.js`** - added `looksLikeHttpServer(rootDir, files)`
  helper as a hoisted function declaration above `AUDIT_RULES`. Updated
  `DEP-001`'s `checkFn` to gate on it. Updated the function-rule
  invocation loop in `runAudit` to pass `rootDir` as the second
  argument so future project-shape rules can use the same hook.

- **`tests/audit.test.js`** - added 6 TDD tests for the new behavior:
  positive (express + no health → fires), positive (fastapi + no
  health → fires), negative (CLI project → does NOT fire), negative
  (static site → does NOT fire), control (server WITH /health → does
  NOT fire), positive edge (no manifest but `app.listen()` in source
  → fires). Test count: 34 → 40, all green.

### Real-world impact

Re-audit of the same 12 projects from the 1.2.2 / 1.2.3 testing run:

```
Project                  pre-1.2.4      post-1.2.4    DEP-001 dropped
DevNeural                14 findings    14 findings   (was already 0 - has /health)
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

11 of 12 projects dropped from `MEDIUM: 1` to `MEDIUM: 0` - the exact
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
- The two known auditor gaps deferred since 1.2.2 - `INJ-005` template
  literal SQL with variable indirection, and `INJ-006` Python f-string
  SQL with inner quoted literals. Still on the deferred list. See the
  1.2.2 / 1.2.3 testing notes for the isolated test fixtures at
  `c:/tmp/guardian-audit-fixture/sql-edges.{js,py}`.

### Fixed

- **Stale `Version 1.2.3` strings across the repo** - bumped to 1.2.4
  in `package.json`, `bin/guardian.js` help footer, `README.md` badge,
  `AGENTS.md`, `CLAUDE.md`, `STANDARDS.md`, `SETUP.md`, `FAQ.md`, and
  `GEMINI.md`. This is the same lockstep-version-bump checklist used
  in every prior 1.2.x patch release.

---

## [1.2.3] - 2026-04-07

Audit reporter readability rewrite. The pre-1.2.3 human-readable
output of `guardian audit` repeated the rule header and full absolute
path for every finding, even when the same rule fired on 14 different
lines. Real-world DevNeural audit (56 findings before the 1.2.2
noise-reduction fixes) was 200+ lines of console output that all
looked the same. After 1.2.2 the same audit dropped to 14 findings,
but the report still had 14 standalone blocks because the reporter
hadn't been updated.

This release rewrites the human reporter only - no rule changes, no
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
    ⚠️  [OTLC GUARDIAN] AUDIT COMPLETE - 56 issue(s) found
        0 CRITICAL · 36 HIGH · 11 MEDIUM · 9 LOW
    ```

### Real impact (DevNeural, 14 findings post-1.2.2)

  Pre-1.2.3 reporter   : 14 standalone blocks, ~50 lines of output
  Post-1.2.3 reporter  : 4 rule headers, ~25 lines of output

The 4 rule headers correspond exactly to the 4 distinct rules that
fired (`CFG-001`, `INJ-002`, `ERR-003`, `TS-001`). The reader sees
"three categories of finding: a hardcoded URL, two innerHTML uses,
seven console.log calls in CLI/server code, four `any` types in
browser code" - at a glance, instead of having to mentally
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

- **Stale `Version 1.2.2` in `bin/guardian.js:121`** - bumped to
  `1.2.3` alongside all the other version strings.

---

## [1.2.2] - 2026-04-07

Audit signal-to-noise improvements. Three real-world rule fixes that
came out of running `guardian audit` against 12 projects on a developer
machine and finding that ~95% of the HIGH/MEDIUM findings on three of
those projects were false positives caused by scope and heuristic
gaps in the audit rules - not bugs in the user's code.

Concrete impact, measured by re-auditing the same three projects
before and after this release:

  DevNeural               56 → 14 findings  (-42, 75% drop)
  New-Letter-and-TikToks  10 →  1 findings  (-9,  90% drop)
  omnibomber-site         11 →  1 findings  (-10, 91% drop)
  ----------------------------------------------------------
  Total                   77 → 16 findings  (-61, 79% drop)

Signal-to-noise on the DevNeural project went from 3 real findings out
of 56 (5%) to 3 real findings out of 14 (21%) - a ~4x improvement.
The 3 real findings are the same in both runs, which is what makes
this a noise-reduction release: every fix below is a correctness
improvement to the rule, not a way to silence real warnings.

### Changed

- **`SKIP_DIRS` expanded to include all major dependency and build
  directories.** Pre-1.2.2 the audit walked `vendor/` (PHP composer),
  `target/` (Rust / Maven build outputs), `bower_components/` (legacy
  JS), and various Python cache directories - producing dozens of
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
    1. **URL pointing at a hardcoded IP** - real bug. Production
       config leak. `fetch('http://192.168.1.10:8080/api')`.
    2. **Server binding to `127.0.0.1`** - security best practice.
       The server refuses connections from any IP other than
       loopback. `fastify.listen({ host: '127.0.0.1' })`,
       `server.listen(0, '127.0.0.1', cb)`, `socket.bind('127.0.0.1', port)`.
  The pre-1.2.2 rule fired on the safe form and called it a config
  leak, which is actively wrong security advice. The fix introduces a
  new `excludeLinePatterns` rule field - a list of regexes that
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

- **`tests/audit.test.js`** - 14 new tests across three describe
  blocks (`v1.2.2 - dependency directories`, `v1.2.2 - test-file
  detection`, `v1.2.2 - CFG-003 bind vs URL`). Each fix has positive
  tests (the rule must NOT fire on the new safe forms) AND control
  tests (the rule must STILL fire in legitimate contexts so we
  haven't accidentally turned the rule off entirely). Total audit
  test count went from 20 → 34. Every test was watched fail before
  the implementation landed.

### Why these are best-practice fixes, not workarounds

Each of the three changes corrects an **actual flaw in the rule**, not
the visibility of a real warning:

  1. **Dependency dirs.** Every serious security scanner - Semgrep,
     SonarQube, ESLint, Ruff, Bandit, Snyk - skips dependency
     directories by default. The audit already skipped `node_modules/`
     for exactly this reason. Adding the equivalents for other
     ecosystems is closing a parity gap.

  2. **Test-file detection.** The principle "don't apply production
     rules to test code" was already in the audit (`ERR-003` had
     `excludePatterns`). The implementation just didn't recognize 6+
     conventions used in the wild. The intent of the rule didn't
     change - only the recognition heuristic was completed.

  3. **CFG-003 bind vs URL.** The pre-1.2.2 rule was actively wrong:
     it called a security best practice (binding to loopback) a
     security bug. The fix doesn't silence a warning - it makes the
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

- **Stale `Version 1.2.1` in `bin/guardian.js:121`** - bumped to
  `1.2.2` alongside all the other version strings.

---

## [1.2.1] - 2026-04-07

Hotfix that reverts one of the two features shipped in 1.2.0. The SQL
injection defense helper (`security/04-sql-guard.js`) stays - it does
not touch user files. The automated `guardian uninstall` command is
removed - it does.

### Removed

- **`guardian uninstall` command** - reverted in full. Removed
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
but not textually identical to the canonical form - any one of these
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

- **`security/04-sql-guard.js`** - stays. The OWASP-aligned tagged
  template helper does not touch user files; it returns a
  `{ text, values }` object for the caller to pass to a database
  driver. The 40-test suite remains, the `./sql` subpath export in
  `package.json` remains, the STANDARDS.md and README.md mentions
  remain, and the FAQ answers about the helper remain.

### Fixed

- **Stale `Version 1.2.0` in `bin/guardian.js:121`** - bumped to
  1.2.1 alongside all the other version strings (package.json badge,
  doc headers/footers for README, CLAUDE.md, STANDARDS.md, AGENTS.md,
  GEMINI.md, FAQ.md, SETUP.md).

---

## [1.2.0] - 2026-04-07

Two new features land in this minor release - an OWASP-aligned SQL injection
defense helper and a surgical `guardian uninstall` command that closes the
merge-safety loop left open in 1.1.1. Both are net-new surface area with their
own test suites; no behavior changes to the 1.1.1 code.

### Added

- **`security/04-sql-guard.js`** - a zero-dep `sql\`\`` tagged template literal
  that makes parameterized queries the path of least resistance. Auto-expands
  `${}` interpolations into placeholders and returns a `{ text, values, driver }`
  object compatible with `pg`, `mysql2`, and `better-sqlite3`. Both dialects
  are first-class: the default `sql` export is postgres-bound with
  `.toMysql()` / `.toSqlite()` / `.toPostgres()` conversion methods, and
  `createSqlHelper({ driver })` returns a natively-bound tag for projects
  that prefer the factory pattern. Nested `sql\`\`` composition is supported
  end-to-end - interpolating one query into another inlines its compiled
  parts and renumbers placeholders automatically. Dynamic table/column
  interpolation goes through `sql.identifier(name, allowList)` with three
  layers of validation: the allow-list must be a non-empty array, the
  identifier must match a strict safe-shape regex (letters/digits/underscore,
  optional single-dot schema prefix), and it must be a member of the allow-
  list. The regex check runs even when the name is on the allow-list, so a
  caller who accidentally adds a malicious string to the list still has the
  query aborted (defense in depth). No runtime blocklist scanner, no keyword
  detection, no input filtering - OWASP's SQL Injection Prevention Cheat
  Sheet explicitly warns that input filtering is not a primary defense
  against SQL injection, and Guardian's static audit rules
  (`INJ-004` / `INJ-005` / `INJ-006` in `security/03-audit.js`) already catch
  the bad concatenation pattern statically. Wired into
  `package.json` exports as `./sql` and mentioned in `STANDARDS.md` as the
  zero-dep fallback for projects that cannot adopt Prisma. Coverage lives
  in `tests/sql-guard.test.js` - 40 tests across seven security properties
  (parameterization, literal-text preservation, injection-payload
  pass-through, identifier escape hatch, nested composition, zero-scanning,
  dialect-conversion purity).

- **`guardian uninstall` command** - the surgical inverse of `guardian init`
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
  against the source-of-truth at `ROOT` - deleting only files that are
  byte-identical to the shipped template, and keeping user-modified copies
  with a "customized" note. Never deletes a file whose marker is absent
  (provenance can no longer be verified), never touches a file Guardian
  did not create (e.g. a user's own `security/my-custom-rules.js` is
  preserved), and refuses to modify a malformed `.claude/settings.json`
  with the same "refuse to touch what we cannot reason about" contract
  used by `mergeClaudeSettings`. A `--dry-run` flag previews the actions
  without touching disk. Wired into `bin/guardian.js` as the `case "uninstall":`
  router branch with a try/catch that converts the invalid-JSON throw into
  a clean non-zero exit. Coverage lives in `tests/uninstall.test.js` - 
  11 tests covering the full contract: symmetry, idempotency, partial
  state (manual marker removal), pre-existing AGENTS.md (Codex user
  survival), custom hooks alongside Guardian's, invalid JSON refusal,
  custom security files, customized Guardian files, dry-run, CLI wiring,
  and the empty-project no-op. This fixes the known data-loss foot-gun
  shipped in 1.1.1 where `SETUP.md` told users to
  `rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md` - an instruction that
  would destroy any content the user wrote above Guardian's marker block.
  PR #4 already shipped the merge-safe manual documentation in
  `SETUP.md § Uninstalling`; 1.2.0 ships the automated command the docs
  have been pointing at.

### Changed

- **README.md** - "The Six Commands" → "The Seven Commands" with a full
  block for `guardian uninstall` including the `--dry-run` flag, the
  marker-strip / byte-compare strategy, and the symmetry contract
  reference. One-line mention of the SQL helper added to the
  "What You Get" audit CLI section.
- **`SETUP.md § Uninstalling`** - replaces the "command is on the roadmap"
  line with "run `guardian uninstall` - it does every step below
  automatically." The manual marker-based procedure is preserved as a
  fallback for users who want to see exactly what the command does.
- **`STANDARDS.md § Database (SQL)`** - adds a one-paragraph mention of
  the `sql\`\`` helper as the zero-dep fallback for projects that cannot
  adopt Prisma.
- **`FAQ.md`** - adds "How do I uninstall Guardian from a project?" under
  Installation, updates the "three security files" answer to "four"
  with `04-sql-guard.js` in the list, and adds a new "Why doesn't
  Guardian include a SQL injection runtime scanner?" Q explaining the
  OWASP-aligned design decision.
- **`package.json`** - `"./sql": "./security/04-sql-guard.js"` added to
  `exports`. `npm test` script extended to include `tests/sql-guard.test.js`
  and `tests/uninstall.test.js`. New `test:sql` and `test:uninstall`
  shortcuts for running each suite in isolation.

### Fixed

- **Stale version string in `bin/guardian.js:121`** - the `showHelp()`
  footer was still printing `Version 1.1.0` after the 1.1.1 bump.
  Bumped to 1.2.0 as part of this release.

---

## [1.1.1] - 2026-04-06

Pre-ship security and correctness pass. Every item below was surfaced by an
adversarial review of the 1.1.0 code and docs on 2026-04-06, verified with live
proofs-of-concept in an isolated sandbox, and fixed with tests that lock in the
regression so it cannot slip back.

### Security

- **Shell-injection fix in `guardian audit`** - `bin/guardian.js:128` (pre-1.1.1)
  spliced `args.slice(1).join(" ")` into an `execSync` template literal. Any
  argument containing `;`, `&&`, `|`, backticks, or `$()` was executed by the
  shell. Live PoC: `guardian audit ". && echo INJECTED > pwned.txt"` created
  the file. **Replaced** with `spawnSync("node", [auditScript, ...args.slice(1)], { shell: false })`
  so the shell never parses arguments at all. The same fix was applied to
  `smokeTestHook()`, which used the same anti-pattern.
- **Outdated OpenAI / Anthropic key regex across all three modules** - the
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
- **Missing raw SQL detection rule** - README claimed "raw SQL" detection in
  two places but `security/03-audit.js` had no SQL rule at all. **Added**
  `INJ-004` (string-concat SQL), `INJ-005` (template-literal SQL with `${}`
  interpolation), and `INJ-006` (Python f-string and `%` formatting SQL).
  Scanner extended with a `wholeFile: true` flag because multi-line SQL
  queries don't fit the line-by-line scanner. Tests in `tests/audit.test.js`.
- **`ERR-001` silent-catch false negatives** - the pre-1.1.1 regex required
  literal empty braces, so `catch (e) { /* silent */ }` and multi-line
  comment-only catch bodies passed the audit clean. **Rewritten** to accept
  any sequence of whitespace, `//` line comments, and `/* ... */` block
  comments inside the catch body, running in `wholeFile` mode so multi-line
  cases match.
- **`SEC-011` - new rule for connection strings with embedded credentials**
  (`postgres://user:pass@host`, `mongodb+srv://...`, `redis://:pw@...`,
  `amqp://...`). The pre-1.1.1 audit ignored these even though they are
  hardcoded secrets in every meaningful sense. Mirrored across all three
  modules. User part is `*` so the redis "password-only, no user" variant
  matches.
- **ReDoS hardening on `INJ-027` / `INJ-028`** - the pre-1.1.1 patterns
  (`<!--.*(?:ignore|override|system).*-->` and the block-comment equivalent)
  used greedy `.*` before and after the alternation - the classic
  catastrophic-backtracking shape. Long inputs without a closing delimiter
  could burn seconds of CPU. **Rewritten** with `[\s\S]*?` (lazy, line-
  spanning) so the engine fails fast. Regression test asserts a 20 KB
  pathological payload completes in under 1 second.
- **`scan()` input length cap** - `guardInput()` has always enforced its own
  `maxLength` (default 4000), but `scan()` is exported and used directly by
  the audit CLI, the hooks, and third-party callers. Without a cap, a huge
  string passed to any direct caller could burn CPU inside the normalizer
  (which appends URL-decoded and base64-decoded copies onto the original).
  **Added** `MAX_SCAN_LENGTH = 100_000` to both the JS and Python `scan()`
  functions with a visible truncation warning. Tests cover the
  mega-input-doesn't-hang and injection-still-detected-in-first-100KB cases.

### Fixed

- **`guardian scan` crashed on Windows with `ERR_UNSUPPORTED_ESM_URL_SCHEME`**
  because `bin/guardian.js:148` passed a raw Windows path (`C:\...`) to dynamic
  `import()`, which requires a `file://` URL on Windows. Ironically
  `pathToFileURL` was already imported at the top of the file but never used
  here. **Fixed** by wrapping the path with `pathToFileURL(...).href`. This
  was a 100% reproducible crash on every `guardian scan` invocation on
  Windows - the single most customer-visible bug of the 1.1.0 release.
- **`guardian init` shipped Guardian's internal files into user projects** - 
  prior releases copied `security/__pycache__/injection_guard.cpython-*.pyc`
  (Python bytecode cache, version-mismatched against any interpreter other
  than the one used to build the cache) and the entire Guardian-internal
  `tests/` directory (four test files that exercise Guardian internals and
  are useless to end users). **Fixed** by (a) adding a `COPY_IGNORE` set in
  `copyDirSafe()` for `__pycache__`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `.DS_Store`, `Thumbs.db`, and `node_modules`, and (b)
  removing the `runInit()` call that copied `tests/` at all.
- **`STANDARDS.md` advertised the wrong version** - the file header claimed
  `Version: 1.2.0` while every other file in the repo agreed on `1.1.0`. The
  JSON health-check example at line 778 also used `1.2.0`. **Fixed** by
  updating the header to `1.1.1` and replacing the JSON example version with
  a generic `1.0.0` placeholder plus a note clarifying the field is the
  reader's application version, not Guardian's.
- **Windows path normalization bug in PreToolUse hook** - the hook normalized
  `\` to `/` at the top of `isWatchedPath()` and then checked
  `normP.endsWith("\\")` a few lines later - dead code that could never be
  true after normalization. On Windows, a user who set
  `watchPaths: [".myplanning\\"]` in `.claude/settings.json` would have the
  trailing slash silently stripped and fall into the file-basename branch
  instead of the directory-prefix branch. **Fixed** by detecting the user's
  intent from the raw (pre-normalization) string and always stripping
  trailing separators consistently.
- **`GEMINI.md` was watched but never provisioned** - the hook watch list
  (and the old `list-watched` command) included `GEMINI.md`, but
  `guardian init` never created one. The template defended an ecosystem it
  did not seed. **Fixed** by adding `GEMINI.md` to the repo root, wiring it
  into `runInit()` as a `mergeMd` call (same idempotent marker-sealed merge
  pattern as `CLAUDE.md` and `AGENTS.md`), and reporting it in the
  `editorCoverage` table and `guardian check` output.
- **README underplayed `STANDARDS.md`** - the approved technology stack file
  is 80% of Guardian's day-to-day value but was mentioned only in passing.
  **Rewrote** README to give `STANDARDS.md` a dedicated section with a
  one-screen preview of the stack table (Node/TS + Python, frontend + auth
  + testing + observability), and expanded the "What Guardian Actually Is"
  section to cover every file in the package - the four behavior files and
  the four runtime-security files - not just the audit CLI.

### Added

- **`tests/audit.test.js`** - 16 new subprocess-based tests for the audit
  rule set. Verifies every new rule fires on the fixtures it should fire on,
  does not fire on legitimate code, and that the end-to-end regression
  fixture from the 1.1.1 pre-ship review (hardcoded key + connection string
  + SQL concat + silent catch + console.log) now produces five findings
  instead of the one it produced before the fixes.
- **Scanner `wholeFile: true` flag** - extends `scanFile()` in
  `03-audit.js` to run a rule against the entire file content as one string
  rather than line-by-line. Required for any pattern that legitimately spans
  multiple lines (the new silent-catch rule, the new SQL rules). Match line
  numbers are computed from the match offset so reports still point at a
  specific line.
- **Uninstall documentation** in `SETUP.md` and `README.md` - previously
  nothing in the docs told users how to remove Guardian from a project.
- **Privacy statement** in `README.md` - explicit confirmation that Guardian
  does not collect data, does not phone home, and has zero runtime
  dependencies. Users can verify by grepping the source tree.
- **Defense-in-depth disclaimer** at the top of `README.md` - honest framing
  of what Guardian is (a strong baseline) and what it is not (a comprehensive
  security solution). Points at `SECURITY.md` for the full threat model.

### Changed

- **Version bump** from `1.1.0` to `1.1.1` across `package.json`, `README.md`
  badge, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `STANDARDS.md`, `FAQ.md`,
  `SETUP.md`, `security/01-injection-guard.js`, `security/03-audit.js`, and
  `security/injection_guard.py`. This is a security patch release.
- **`editorCoverage()` reports Gemini CLI** - the table now has a row for
  Gemini CLI keyed off the presence of `GEMINI.md`, mirroring the
  `AGENTS.md`-keyed rows for the other non-Claude agents.
- **`copyDirSafe()` skip list** - see "Fixed" above for the `COPY_IGNORE` set.

---

## [1.1.0] - initial public release

First public release. Core capabilities:

- Prompt injection guard (28 patterns + Unicode/encoding bypass defenses)
- Code security utilities (secure headers, rate limiter, structured logger, request ID, error handler, health check)
- Safety audit CLI (`guardian audit`)
- Claude Code behavior rules (`CLAUDE.md`) and approved stack standards (`STANDARDS.md`)
- `guardian init` merge-safe installer
- Python parity module
- GitHub Actions CI workflow
- **Centralized audit allowlist** at `security/.audit-allowlist` with required reason field. Per-file `otlc-guardian:audit-exempt` marker still supported as an end-user opt-in. Allowlist is checked first so it takes precedence.
- **Audit exemption visibility** - every `guardian audit` run prints the count and full list of exempted files. CI writes the exemption count to the GitHub Actions step summary.
- **`guardian list-watched`** - debug command that prints the effective hook watch list for the current project, including custom paths and ignores from `.claude/settings.json`.
- **`guardian update`** - alias for `guardian init`. Both are merge-safe and idempotent; `update` is the natural verb after pulling a new Guardian release.
- **`web-content-guard.mjs`** - PostToolUse hook on `WebFetch`/`WebSearch` that scans fetched content before Claude reasons about it. Catches indirect prompt injection at the entry point.
- **Configurable hook watch list** via `otlcGuardian.watchPaths` / `ignorePaths` / `extendDefaults` block in `.claude/settings.json`.
- **Doc-exempt marker** (`otlc-guardian:doc`) for security spec files that legitimately discuss injection patterns.
- **Python parity**: `SECRET_PATTERNS` (9 entries), v1.0.1 normalizer (NFKC + invisible-strip + URL/base64 decode), and `guard_output()` added to `security/injection_guard.py`.
- **`GuardianConfigError`** - error class thrown by `validateEnv()` when required env vars are missing.
- **Restructured source tree** from a flat root layout into `bin/`, `security/`, `tests/`, `.claude/hooks/`, `.github/workflows/`.
- **Hook patterns sourced from main module** - `.claude/hooks/injection-guard-hook.mjs` imports `INJECTION_PATTERNS` directly from `security/01-injection-guard.js` instead of inlining a stale subset. Drift is now impossible.
- **`mergeClaudeSettings` no longer overwrites invalid JSON** - aborts with a clear error and points the user to the reference copy.
- **`mergeClaudeSettings` matcher comparison is set-based** - `Edit|Write` and `Write|Edit` are recognized as the same block.
- **`mergeClaudeSettings` handles multiple events** - registers PreToolUse and PostToolUse hooks in one pass.
- **`mergeGitignore` strips inline comments** before deduping - a user line like `.env # local secrets` correctly suppresses Guardian's own `.env` entry.
- **`validateEnv` throws instead of `process.exit(1)`** - library code never terminates the process. Callers catch `GuardianConfigError` and decide how to fail.
- **`guardian check` smoke-tests the hook** - pipes a known-bad payload through and asserts it fires. Detects Python projects and conditionally requires `security/injection_guard.py`.
- **Audit `--json` mode no longer contaminates stdout** - status lines go to stderr in `--json` mode (standard Unix convention). CI now produces clean parseable JSON.
- **`make_fastapi_guard` in `injection_guard.py`** - fixed a bug where the dependency's `request` parameter had no type hint so FastAPI couldn't provide it.
- **Audit script self-detection false positives** - the audit's own pattern definitions matched themselves. Resolved via the exemption mechanisms.
- **CI workflow runs the full test suite** before the audit.
- **CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, CODEOWNERS, .github/ISSUE_TEMPLATE, PULL_REQUEST_TEMPLATE.md, .editorconfig, .gitattributes** added.
