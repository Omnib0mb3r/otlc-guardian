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

- **The runtime guard** (`guardInput`/`guardOutput`) is the strongest layer. It runs at request time on every input/output, scans against 28 injection patterns and 16 secret patterns with NFKC normalization plus invisible-Unicode stripping plus URL/base64 decoding to defeat encoded bypasses. The output guard catches secrets the AI may inadvertently include in its response.
- **The Claude Code hooks** (`injection-guard-hook.mjs` + `web-content-guard.mjs`) are a detection layer, not a sandbox. Since 1.5.0 the PreToolUse hook denies a write that adds a CRITICAL injection pattern to a watched file, asks on a Bash or PowerShell command that carries one and writes a watched file, denies a shell copy whose source carries one, asks before `.claude/settings.json` or `settings.local.json` is weakened, and asks before any change to the hook scripts or `security/01-injection-guard.js`. In bypassPermissions mode every "ask" is a deny. Everything else is a warning in Claude's context. When a hook itself fails it does not block the tool call, and it reports the failure on stderr as a hook error.
- **What the PreToolUse hook cannot see.** It reads the paths a shell command spells out and the text it carries. It does not see:
  - targets the command does not spell out: a variable (`f=CLAUDE.md; echo x > $f`), a computed path (`node -e` with `path.join`), or a glob (`.claude/settings.loc*.json`);
  - inline interpreter code beyond its literal path words (`node -e`, `python -c`), a script file that writes the target, and PowerShell `-File` scripts;
  - encoded or assembled content: `printf` octal escapes, `rev`, `tr` rot13, `base64 -d`, variable concatenation, words split by quotes;
  - git operations that replace files without naming them: branch switches, `reset`, `stash`, `merge`.

  Known gaps in what it does read, logged and not yet fixed in 1.5.0 (each is a hook change, and the hook is a protected file):
  - Windows path aliases: a directory stream suffix on a folder (`.claude::$INDEX_ALLOCATION/settings.local.json`) and 8.3 short names (`CLAUDE~1/settings.local.json`, `PLANNI~1/STATE.md`) reach watched and protected files unmatched (BUG-064);
  - deletes and replaces it does not parse: `find -delete`, `rsync --delete`, `tar -x` members (BUG-065);
  - `cmd /c` and `cmd.exe /c` are read by neither shell reader, so `rd`, `del`, `copy` and redirects through them pass (BUG-048, BUG-065, BUG-066);
  - a PowerShell tool command is read only for redirections and Guardian's list of cmdlets, so `git`, `bash -c`, `node -e` and `curl -o` typed into the PowerShell tool are not read (BUG-048);
  - PowerShell parameter prefixes (`-LiteralP`, `-Pat`, `-Val`) are not recognized as the parameters they abbreviate (BUG-067);
  - the script inside `powershell -EncodedCommand` is decoded and read for write targets, but its text is not scanned for patterns (BUG-067);
  - copies whose content is not read: a directory source (`cp -r staged/. .claude/agents/`), `sort -o`, `cmd /c copy` (BUG-066);
  - `security/package.json`, which keeps the scanner loadable in a CommonJS project, is not in the protected set, so a write that changes its `type` switches the scanner off (BUG-063).

  Detection is also pattern-based, so a reworded instruction with no known pattern passes. An agent that is already compromised can use any of these routes. They belong to the planned hard-no hook, which DevNeural hosts and which judges a command by its effect instead of its text (see `TODO.md`, "Self-Growing Gate spec").
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
