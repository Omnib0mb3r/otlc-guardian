# staging/: candidate next versions of Guardian's protected files

The files here are the next versions of the three files the live PreToolUse hook protects:

| Staged file | Live file it replaces |
|---|---|
| `staging/hooks/injection-guard-hook.mjs` | `.claude/hooks/injection-guard-hook.mjs` |
| `staging/hooks/web-content-guard.mjs` | `.claude/hooks/web-content-guard.mjs` |
| `staging/security/01-injection-guard.js` | `security/01-injection-guard.js` |

They started as exact copies of the live files at commit e2200bf. Hook and scanner fixes land here first, with their tests, so the live files stay untouched until Michael applies them.

**Only Michael applies them, in a session where permission prompts are on**, so the hook's own "a person confirms" check on its enforcement files does its job. An agent never copies these over the live files. `staging/APPLY.md` lists the copy commands and the checks to run afterwards.

## Why the folder is flat

The live hook watches every path containing `.claude/`, so `staging/.claude/hooks/` would put the staged hooks under its content scan. `hooks/` and `security/` here sit outside every watched and protected path. `npm run test:staging` (`tests/staging.mjs`) copies them into a temporary folder laid out like an install (`.claude/hooks/`, `security/`) and runs the hook and scanner suites there.

## Tests

- `npm test` tests the live files, as before.
- `npm run test:staging` runs `tests/injection-guard.test.js` and `tests/hook.test.js` against the staged files, through the `GUARDIAN_ENFORCEMENT_ROOT` environment variable.

A test for a fix that exists only in staging fails under `npm test` until the fix is applied live, so such tests are marked with `stagedOnly()` and skipped against the live files; see `tests/hook.test.js`.

staging/ is not in the npm package (`files` in package.json does not list it).
