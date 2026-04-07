# OTLC Guardian

**Makes your AI coding agent build like a senior developer. Protects your app from AI security attacks.**

Free and open source · MIT License · Built by [onthelevelconcepts.com](https://onthelevelconcepts.com)

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Node: 22+](https://img.shields.io/badge/Node-22%2B-green.svg)](https://nodejs.org)
[![Version: 1.1.0](https://img.shields.io/badge/version-1.1.0-blue.svg)](package.json)

---

## What It Does

Without Guardian, your coding agent takes shortcuts — silent error handling, hardcoded secrets, raw SQL, no tests. It builds fast, not right.

With Guardian, it behaves like a 30-year senior developer. Production standards, no cut corners, the right tools reached for automatically.

It also protects your running app. Every message a user sends gets scanned for prompt injection attacks before it reaches your AI. Every AI response gets scanned before it reaches your user.

---

## Agent compatibility

Guardian is split cleanly between **portable features** that work for every agent and **Claude Code integrations** that only work inside Claude Code. Know which tier you're in before you install:

| Agent                                       | Behavior rules | Runtime guard | Audit CLI | PreToolUse / PostToolUse hooks |
|---------------------------------------------|:-------------:|:-------------:|:---------:|:------------------------------:|
| **Claude Code**                             | ✅ `CLAUDE.md` | ✅            | ✅        | ✅                              |
| **Codex CLI**                               | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Cursor**                                  | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Aider**                                   | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Continue**                                | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Windsurf**                                | ✅ `AGENTS.md` | ✅            | ✅        | —                              |

**Why the split:** the runtime guard, the audit CLI, and behavior files (`CLAUDE.md` / `AGENTS.md` / `STANDARDS.md`) are portable — they work anywhere Node or Python runs. The two Claude Code hooks live inside Claude's PreToolUse / PostToolUse tool-call lifecycle, which has no direct equivalent in other agents. When you run `guardian check` it reports which tier you're in and what's active.

---

## Install Once. Use Everywhere.

Guardian has two parts:

| Part | What it is | When you do it |
|------|-----------|----------------|
| **The CLI** | The `guardian` command | Once per machine |
| **The project files** | `CLAUDE.md`, `STANDARDS.md`, `security/` etc. | Once per project |

**Step 1 — Install the CLI on your machine (do this once)**

```bash
git clone https://github.com/Omnib0mb3r/otlc-guardian.git
cd otlc-guardian
npm install -g .
```

**Step 2 — Add Guardian to a project (do this for each project)**

```bash
cd /your/project
guardian init
```

**Step 3 — Start (or restart) your coding agent.** Behavior files are re-read at session start:

- **Claude Code** reads `CLAUDE.md` and `STANDARDS.md` automatically.
- **Codex CLI, Cursor, Aider, Continue, Windsurf** read `AGENTS.md` (which points at `STANDARDS.md` and `CLAUDE.md` for the full rules).

Then run `guardian check` to confirm the install and see which coverage tier you're in.

> Setting up a new machine later? Just repeat Step 1. Your projects keep their files.

---

## The Six Commands

Once installed, you have six commands:

**`guardian init`** — Run once inside each project you want Guardian in.
```bash
cd /your/project
guardian init
```

**`guardian update`** — Re-merge the latest Guardian files into an existing project. Same as `init` (merge-safe, idempotent), but the natural verb after pulling a new release.
```bash
guardian update
```

**`guardian audit`** — Scan your project for security and quality problems. Run regularly.
```bash
guardian audit
```

**`guardian scan`** — Test a specific string for prompt injection. Useful during development.
```bash
guardian scan "some text you want to check"
```

**`guardian check`** — Verify Guardian is correctly installed. Includes a hook smoke test.
```bash
guardian check
```

**`guardian list-watched`** — Print the effective hook watch list for the current project. Useful for debugging when the hook doesn't fire (or fires unexpectedly).
```bash
guardian list-watched
```

---

## What You Get

Two clearly-scoped tiers. Tier 1 works for every agent. Tier 2 only activates inside Claude Code.

### Tier 1 — Works in any project, with any agent

**Senior-dev behavior rules, loaded from `AGENTS.md` / `CLAUDE.md` / `STANDARDS.md`:**
- No silent `catch {}` blocks
- No hardcoded secrets, URLs, or config values
- Structured logging with request IDs on every entry
- Versioned APIs with consistent response shapes
- Self-audit checklist before marking any task complete
- Flags when the agent is about to reach for a junior-level library and switches to the right one

How the agent picks up the rules:
- **Claude Code** reads `CLAUDE.md` and `STANDARDS.md` natively
- **Codex CLI / Cursor / Aider / Continue / Windsurf** read `AGENTS.md`, which points at `STANDARDS.md` and `CLAUDE.md` for the full rule text
- All three files ship with `guardian init` and merge safely with whatever you already have

**Runtime protection for your running app:**
- Prompt injection scanner — 28 patterns including Unicode bypass attacks (NFKC normalization, invisible-character stripping, base64/URL decoding)
- Output scanner — catches secrets leaking in AI responses
- Rate limiter, secure headers, structured logger, health check endpoint
- Works identically in Node (`security/01-injection-guard.js`) and Python (`security/injection_guard.py`)

**Audit CLI — scan any codebase:**
- `guardian audit` scans for hardcoded secrets, silent errors, console.log in prod paths, missing `/health`, raw SQL, and a dozen other junior patterns
- JSON output mode for CI integration
- Works on any project — Python, TypeScript, JavaScript, mixed

**GitHub Actions workflow (if you push to GitHub):**
- Secret scanning (Gitleaks)
- Dependency vulnerability checks (`npm audit`, `pip-audit`)
- Full codebase audit on every PR
- All Guardian unit tests run before the audit
- Audit exemption count posted to the workflow summary for visibility

### Tier 2 — Claude Code integrations (Claude Code only)

These features piggy-back on Claude Code's `PreToolUse` / `PostToolUse` tool-call lifecycle, which no other agent exposes today. They're installed automatically by `guardian init` and do nothing if you're not running inside Claude Code.

**Two advisory hooks (never block — only surface warnings):**
- **PreToolUse** scans every Write/Edit on a wide default watch list — `.planning/`, `.gsd/`, `.cursor/`, `.continue/`, `.aider/`, `.windsurf/`, every `*/memory/` directory, plus `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `MEMORY.md`, `copilot-instructions.md`, and `.env*`. Patterns are imported from the runtime guard so they cannot drift.
- **PostToolUse** scans every `WebFetch` and `WebSearch` response **before** Claude reasons about the content — catches indirect prompt injection at the entry point, the highest-leverage place to defend.
- Configurable per project via `otlcGuardian.watchPaths` / `ignorePaths` in `.claude/settings.json`. Doc-exempt marker (`otlc-guardian:doc`) silences scanning for security spec files.

**Hook smoke test in `guardian check`:**
- Pipes a known-injection payload through the `PreToolUse` hook and confirms it fires
- Catches broken hook installs (wrong shebang, missing import, etc.) before you discover them the hard way in a real session

> **For non-Claude users:** Tier 2 is not blocking or even visible in your workflow. You get the full Tier 1 stack, which is the majority of Guardian's value. An equivalent lifecycle-hook integration for Codex / Cursor / Aider would require per-agent tool-call interception which those tools don't currently expose — we're tracking it, but we're not pretending it exists today.

---

## Safe on Existing Projects

`guardian init` never overwrites your files. It merges:

- **CLAUDE.md** — your rules stay at the top, Guardian's are appended below (Claude Code behavior file)
- **AGENTS.md** — same merge pattern (universal agent behavior file for Codex / Cursor / Aider / Continue / Windsurf)
- **STANDARDS.md** — same merge pattern
- **.gitignore** — only adds entries you don't already have
- **.env.example** — only adds variables you don't already have
- **.claude/settings.json** — adds Guardian's Claude-only hooks alongside your existing hooks
- **Everything else** — only copies files that don't already exist

Run it twice — nothing changes the second time. It detects what's already there and skips it.

---

## Full Documentation

| File | What's in it |
|------|-------------|
| `SETUP.md` | Complete step-by-step guide with troubleshooting |
| `CLAUDE.md` | Full Claude behavior rules |
| `STANDARDS.md` | Full approved technology stack |
| `FAQ.md` | Common questions answered |

---

## Requirements

- **Node.js 22+** — required (the CLI, audit, and runtime guard are ESM Node)
- **Python 3.11+** — required only if you use the Python runtime guard module
- **A coding agent that reads behavior files** — see the [Agent compatibility](#agent-compatibility) table above for the supported list
- **GitHub** — required only if you want the included CI workflow

---

## Forking

MIT licensed. Fork it, brand it, make it yours.

```bash
# Keep your fork in sync with upstream
git remote add upstream https://github.com/Omnib0mb3r/otlc-guardian.git
git fetch upstream && git merge upstream/main
```

### Minimal fork (rebrand only)

If you're keeping Guardian's multi-agent posture and just want to rebrand:

- Update `package.json` — `name`, `homepage`, `repository`, `bugs`
- Replace `onthelevelconcepts.com` in `CLAUDE.md`, `AGENTS.md`, and `STANDARDS.md`
- Replace `Omnib0mb3r/otlc-guardian` in `README.md` and `SETUP.md` install commands
- Keep `security/` intact — don't modify the runtime guard unless you're adding patterns
- Keep the `otlc-guardian:doc` and `otlc-guardian:audit-exempt` marker names intact, or your fork's markers won't match any downstream docs that reference them

### Single-agent fork (e.g. Codex-only, Cursor-only)

If you want a fork that's scoped to a single agent — say, a Codex-first template for your team — the work is bigger than a rebrand. Be honest with yourself about the effort before you start:

- **Delete the Claude-specific tier.** Remove `CLAUDE.md`, `.claude/`, the `mergeClaudeSettings` call path in `bin/guardian.js`, the smoke test in `runCheck`, and the Claude Code row from the compatibility table. Update `runInit`'s "what was merged" output. Update tests in `tests/init.test.js` and `tests/hook.test.js` that assert Claude-specific behavior.
- **Replace the hook layer with something your agent actually supports** — or drop it entirely and ship a behavior-only product. Guardian's PreToolUse / PostToolUse hooks rely on Claude Code's tool-call lifecycle; Codex, Cursor, Aider, Continue, and Windsurf don't expose an equivalent as of early 2026. A real replacement is a 1–2 day research-and-build effort at minimum, and it may not be possible at all depending on the agent. A behavior-only fork is the realistic path.
- **Rewrite the value sections in README, SETUP, and FAQ.** Everything in "Tier 2 — Claude Code integrations" has to go. The compatibility table collapses to one row. The `guardian check` editor-coverage output needs to be simplified.
- **Decide whether to rename files.** `CLAUDE.md` is meaningless in a Codex-only fork. You can delete it, or keep it as an alias that points at `AGENTS.md`. Test your choice against `bin/guardian.js` and the test suite.

If the above feels like a lot, that's the honest signal: a single-agent fork is real engineering work, not a 10-minute rebrand. The multi-agent default is the path of least resistance for almost every use case.

---

*OTLC Guardian · [onthelevelconcepts.com](https://onthelevelconcepts.com) · Built to the standard of a $100k engagement.*
