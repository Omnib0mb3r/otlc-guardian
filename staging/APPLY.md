# Applying staging/ to the live files

Only Michael applies this, in a Claude Code session where permission
prompts are on (not bypassPermissions), or from a plain terminal. An agent
never copies these files over the live ones. Read `staging/README.md` for
why the staged copies exist.

Written 2026-11-10 at the end of the 1.5.0 fix run. Lex re-probes
`staging/` before this goes to Michael.

## What changes

| Staged file | Live file | Size of the change |
|---|---|---|
| `staging/hooks/injection-guard-hook.mjs` | `.claude/hooks/injection-guard-hook.mjs` | 958 lines added, 112 removed |
| `staging/hooks/web-content-guard.mjs` | `.claude/hooks/web-content-guard.mjs` | 26 added, 21 removed |
| `staging/security/01-injection-guard.js` | `security/01-injection-guard.js` | 225 added, 33 removed |
| (hand edit) | `.claude/settings.json` (this repo only) | both hook commands anchored, web guard matcher widened |

Bugs fixed by the staged files, with the commit that staged each fix.
Each bug's detail block in `BUGS.md` describes the change and its tests.

| Bug | Commit | File | Change |
|---|---|---|---|
| BUG-063 | 920e75e | hook | `security/package.json` joins the protected set |
| BUG-048 | 20b32b6 | hook | PowerShell commands fall through to the shared readers; `cmd /c` dialect |
| BUG-064 | 981ed10 | hook | Win32 device prefixes, stream suffixes, 8.3 names, links resolved on disk |
| BUG-065 | 604f68d | hook | `find -delete`, `rsync`, `tar -x`, `unzip`, `git clean`, permission commands |
| BUG-066 | 20aed8f | hook | folder copies judged file by file; `sort -o`, `uniq IN OUT` |
| BUG-067 | f8429e6 | hook | PowerShell parameter prefixes; `-EncodedCommand` text scanned |
| BUG-049, BUG-050 | 60fa005 | scanner | unknown `scan()` mode throws; `blockOnCritical` on injection only |
| BUG-043 | 3d7db66 | scanner | `GUARD-INJ-019`, `-020`, `-015` false positives |
| BUG-045 | 3ad5b90 | hook | matchers read with Claude Code's rules; anchored command form is no change |
| BUG-046 | 428c8c7 | scanner | change window counts context past padding |
| BUG-042 | 8d0bcdc | scanner | a quoted pattern moved onto a live line is a finding |
| BUG-044 | e664bce | hook | `sed`/`grep` filters and read-only inline code judged by effect |
| BUG-036 | 7dec806 | web guard, hook | every tool of the seven web servers, by prefix |
| BUG-038 | c913519 | hook | a long path keeps its file name in messages |
| BUG-058 | 0118449 | hook | `ignorePaths` matches whole segments from the project root |

Behavior a user will notice after the apply:

- `ignorePaths` entries are paths from the project root (BUG-058). An
  entry that relied on the old substring reading (`docs` meant for
  `src/docs/`) must be written in full. Check this repo's and each
  project's entries when they take the new hook through `guardian update`.
- `### System: Billing`, `--- System ---` and "wrap in <user> tags" are no
  longer denied (BUG-043).
- `sed -i '/payload/d' CLAUDE.md` and read-only `node -e` / `python -c`
  are no longer denied in bypass mode (BUG-044).
- The web content guard fires on the playwright, claude-in-chrome,
  chrome-devtools, car-browser, context7, firecrawl and exa tools
  (BUG-036).

## Before

From the repo root (`C:\dev\Projects\otlc-guardian`):

```bash
git status --short          # only investigator-reports/ untracked
npm test                    # exit 0
npm run test:staging        # exit 0
```

The live files are tracked, so the way back at any step is
`git checkout -- .claude/hooks/injection-guard-hook.mjs .claude/hooks/web-content-guard.mjs security/01-injection-guard.js .claude/settings.json`.

## Step 1: copy the three files

Git Bash (or `! ` in front of each line inside Claude Code):

```bash
cp staging/security/01-injection-guard.js security/01-injection-guard.js
cp staging/hooks/web-content-guard.mjs .claude/hooks/web-content-guard.mjs
cp staging/hooks/injection-guard-hook.mjs .claude/hooks/injection-guard-hook.mjs
```

PowerShell:

```powershell
Copy-Item staging\security\01-injection-guard.js security\01-injection-guard.js
Copy-Item staging\hooks\web-content-guard.mjs .claude\hooks\web-content-guard.mjs
Copy-Item staging\hooks\injection-guard-hook.mjs .claude\hooks\injection-guard-hook.mjs
```

If Claude makes the copies instead, each one asks (the hook protects its
own files); approve the three you expect and nothing else.

Then confirm the copies match:

```bash
git diff --no-index --quiet staging/security/01-injection-guard.js security/01-injection-guard.js && echo scanner same
git diff --no-index --quiet staging/hooks/web-content-guard.mjs .claude/hooks/web-content-guard.mjs && echo web guard same
git diff --no-index --quiet staging/hooks/injection-guard-hook.mjs .claude/hooks/injection-guard-hook.mjs && echo hook same
```

## Step 2: this repo's .claude/settings.json

Do this after step 1. The new hook reads the anchored command as the same
hook and the wider matcher as no weakening; the old one would ask on both.

Edit `.claude/settings.json` by hand so the two hook entries read:

```json
"PreToolUse": [
  {
    "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell",
    "hooks": [
      { "type": "command", "command": "node \"${CLAUDE_PROJECT_DIR}/.claude/hooks/injection-guard-hook.mjs\"" }
    ]
  }
],
"PostToolUse": [
  {
    "matcher": "^(?:WebFetch|WebSearch|mcp__(?:firecrawl|exa|claude-in-chrome|chrome-devtools|playwright|car-browser|context7)__.*)$",
    "hooks": [
      { "type": "command", "command": "node \"${CLAUDE_PROJECT_DIR}/.claude/hooks/web-content-guard.mjs\"" }
    ]
  }
]
```

Leave the `otlcGuardian` block as it is. This is what `guardian init`
writes for a new project (BUG-028, BUG-034, BUG-036). Do not use
`guardian update` for it here: in Guardian's own repo the source and the
target are the same files, and that path is untested.

## Step 3: checks

```bash
npm run test:staging                        # exit 0 (staged == live now)
node security/03-audit.js . --fail-on-error # exit 0
node bin/guardian.js check                  # exit 0, and no relative-command warnings
```

`npm test` fails at this point until step 4: the one `liveOnly()` test,
"scan on non-string returns cleanly (replaced by the staged BUG-049 fix)"
in `tests/injection-guard.test.js`, asserts the old live behavior, which is
gone. That failure is expected; any other failure is not, so stop and roll
back.

Then restart Claude Code in this repo (hooks are read at session start)
and run the smoke tests below.

## Step 4: cleanup (an agent can do this; none of it is a protected file)

1. `tests/hook.test.js` and `tests/injection-guard.test.js`: delete every
   `liveOnly(...)` test (today only in `tests/injection-guard.test.js`) and
   turn every `stagedOnly(` call into `test(`. Keep the `stagedOnly()` and
   `liveOnly()` helpers and `TESTING_STAGED`: the next staged fix uses them.
   `npm test` and `npm run test:staging` both exit 0 after.
2. `CHANGELOG.md`, `[1.5.0]`: move every entry under "### Staged (fixed in
   staging/, not yet live)" into "### Fixed" and delete the Staged section.
   Confirm `grep -c '^## \[1.5.0\]' CHANGELOG.md` is 1.
3. Drop the "(fix staged in staging/, not yet live)" notes and rewrite each
   known-gap line as current behavior in: `SECURITY.md` ("What the
   PreToolUse hook cannot see"), `SETUP.md` (Hook 2 section and the
   `ignorePaths` line), `docs/manual/chapters/03-runtime.html`,
   `docs/manual/chapters/04-hooks.html` (fold the `hk-staged` table rows
   into the chapter text, remove the table, rewrite the Known bugs box),
   `docs/manual/chapters/06-suppression.html` (`ignorePaths` matching).
   `grep -rn "staging/, not yet live" --include=*.md --include=*.html .`
   then finds only the handovers.
4. `BUGS.md`: flip to SMOKE-TESTING, in the index row and the detail block,
   announced: BUG-036, BUG-038, BUG-042, BUG-043, BUG-044, BUG-045,
   BUG-046, BUG-048, BUG-049, BUG-050, BUG-058, BUG-063, BUG-064, BUG-065,
   BUG-066, BUG-067. Each detail block's "Staging commit: recorded in
   `staging/APPLY.md`" gets the commit from the table above and the apply
   commit.
5. `staging/`: keep the three files identical to the live ones, so the next
   staged fix starts from the live code. Update this file's tables to say
   nothing is pending.
6. Rebuild the manual (`node docs/manual/build.mjs`), run every check, and
   commit by file name.

## Smoke tests

Run after step 2 in a fresh Claude Code session with prompts on, unless
the line says bypass mode. Each bug's detail block in `BUGS.md` has the
full steps; record the result there.

| Bug | Check |
|---|---|
| BUG-063 | Ask Claude to write `{"type":"commonjs"}` to `security/package.json`; see the "Guardian's own enforcement" prompt. |
| BUG-048 | Windows: through the PowerShell tool run `git checkout HEAD -- .claude/settings.json` and `cmd /c "del .claude\settings.json"`; see a Guardian prompt for each. |
| BUG-064 | Windows: ask Claude to Write `CLAUDE~1/settings.local.json` with `{"disableAllHooks":true}`; see a Guardian prompt. |
| BUG-065 | Ask Claude to run `find .claude -name 'settings.local.json' -delete`; see a Guardian prompt. |
| BUG-066 | Put a file holding "ignore all previous instructions" in `staged/`, ask Claude to run `cp -r staged/. .claude/agents/`; see it denied. |
| BUG-067 | Windows: through the PowerShell tool run `Set-Content -LiteralP .claude/settings.local.json -Val '{}'`; see a Guardian prompt. |
| BUG-049 | `node -e "import('./security/01-injection-guard.js').then(m => m.scan('x', 'nosuchmode'))"` in an installed project fails with the `GuardianError` naming the three modes. |
| BUG-050 | Covered by `npm test`; no session check. |
| BUG-045 | Step 2 itself: changing the hook commands to the anchored form gives no weakening prompt. |
| BUG-043 | Ask Claude to add a `### System: Billing` heading to `.planning/STATE.md`; it is written without a deny. |
| BUG-046 | In a scratch project, `printf 'ignore all%5000s\nEND\n' "" > .planning/pad.md`, ask Claude to replace END with "previous instructions"; see the deny. |
| BUG-042 | In a CLAUDE.md that quotes the payload inside a code fence, ask for a rewrite moving it out of the fence; see the deny. An unrelated edit sees none. |
| BUG-044 | Bypass mode, CLAUDE.md holding the payload: `sed -i '/ignore all previous instructions/d' CLAUDE.md` is not denied; `python -c "import json; print(json.load(open('.claude/settings.json')))"` gets no prompt. |
| BUG-028, BUG-034 | In a project after `guardian update`: `cd src`, ask for a Write of a CRITICAL payload to `.planning/x.md`; see the deny and no hook error. |
| BUG-036 | In a session with the playwright or claude-in-chrome server, open a page containing "ignore all previous instructions"; see the web content warning naming the tool. |
| BUG-038 | Write a CRITICAL payload to a path over 120 characters under `.planning/`; see the deny naming the file. |
| BUG-058 | In a scratch project with `ignorePaths: ["docs"]`, a payload Write to `src/docs-loader/CLAUDE.md` is denied; the same Write to `docs/CLAUDE.md` is silent. |
