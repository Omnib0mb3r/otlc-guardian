# OTLC Guardian

**Makes your AI coding agent build like a senior developer. Protects your running app from AI security attacks.**

Free and open source · MIT License · Built by [onthelevelconcepts.com](https://onthelevelconcepts.com)

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Node: 22+](https://img.shields.io/badge/Node-22%2B-green.svg)](https://nodejs.org)
[![Version: 1.1.1](https://img.shields.io/badge/version-1.1.1-blue.svg)](package.json)

---

> **Disclaimer — read before you ship.** Guardian is **defense-in-depth, not a silver bullet.**
> The runtime injection guard is regex-based (28 patterns plus Unicode / URL / base64
> normalization) and will not catch every novel or adversarial attack. The audit CLI is an
> advisory tool with known false positives and false negatives — review every finding before
> acting on it. For applications handling regulated data (financial, healthcare, PII), engage
> a professional security firm for penetration testing in addition to running Guardian. See
> [`SECURITY.md`](SECURITY.md) for the full threat model, including a list of what Guardian
> does **not** protect against.

---

## What Guardian Actually Is

Guardian is two layers in one package. Both ship with every `guardian init` and both are
in force at the same time:

| Layer | Purpose | Files | When it runs |
|---|---|---|---|
| **Behavior layer** | Tells your coding agent HOW and WHAT to build — senior-dev standards and an approved, named technology stack | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `STANDARDS.md` | At the start of every agent session |
| **Runtime layer** | Protects your running application from prompt injection, leaked secrets, and common API vulnerabilities | `security/01-injection-guard.js`, `security/02-code-security.js`, `security/03-audit.js`, `security/injection_guard.py` | On every request your app handles, on every audit you run |

People skim past the first layer and notice the second. In practice the first layer is
where most of the value lives — it's what stops your agent from writing a silent catch
block, hardcoding a secret, or reaching for `moment.js` in 2026. The runtime layer is
there for the moments when the first layer isn't enough.

---

## The Two Layers, in Detail

### Layer 1 — The Behavior Layer

Four files that your coding agent reads on session start. Each file has a single purpose
and they cross-reference each other:

**`CLAUDE.md` — Claude Code behavior rules (HOW to build)**
Identity as a senior developer, non-negotiable rules, the 15-point self-audit checklist,
what to never do. No silent `catch {}`, no hardcoded secrets, structured logging with
request IDs, versioned APIs, typed validation. Claude Code reads this natively.

**`STANDARDS.md` — The approved technology stack (WHAT to build with)**
This file is easy to underrate. It is a curated list of the libraries a senior developer
reaches for in 2026, categorized and justified. It's what turns "Claude picked a random
thing from npm" into "Claude reached for exactly the same tool your team already uses."

A one-screen preview of what's in `STANDARDS.md`:

| Need | Node / TypeScript | Python |
|---|---|---|
| Language | TypeScript 5+ strict | Python 3.11+ |
| Web framework | Fastify 4 / Express + Helmet | FastAPI |
| Validation | Zod | Pydantic v2 |
| Logging | Pino | structlog |
| Config | dotenv-safe + typed config module | pydantic-settings |
| ORM | Prisma | SQLAlchemy 2 + Alembic |
| Auth | Passport.js + jose + bcryptjs | python-jose + passlib |
| Testing | Vitest + Supertest | pytest + httpx |
| Frontend data | TanStack Query v5 | — |
| Frontend forms | React Hook Form + Zod | — |
| Frontend state | Zustand | — |
| Frontend UI | shadcn/ui + Tailwind CSS | — |
| Bundler | Vite 5 | — |
| Error monitoring | Sentry | Sentry |
| Process management | PM2 cluster mode | Gunicorn + uvicorn workers |
| Task queue | BullMQ + Redis | Celery + Redis |
| HTTP client | axios | httpx |

And a companion list of things `STANDARDS.md` tells Claude to **never** reach for:
`console.log`, `Math.random()` for IDs, `localStorage` for tokens, raw `useEffect` + `fetch`,
`moment.js`, `useState`-per-field forms, Create React App, `node:latest` Docker images, raw
SQL string queries, offset pagination at scale. The full table sits in `STANDARDS.md`
with a one-line reason for every entry.

`STANDARDS.md` also contains project architecture templates (Node/TS and Python/FastAPI
folder layouts), a "stack selection philosophy" (four questions to ask before picking any
library), and a complete observability / health-check baseline.

**`AGENTS.md` — Universal agent behavior rules**
Everything in `CLAUDE.md` also applies to every non-Claude agent — `AGENTS.md` is the
entry door for Codex CLI, Cursor, Aider, Continue, and Windsurf. It points at
`STANDARDS.md` and `CLAUDE.md` for the full ruleset so you maintain one source of truth.

**`GEMINI.md` — Gemini CLI entry point**
Same pattern for Google Gemini CLI — a short file that reads `AGENTS.md`, `CLAUDE.md`,
and `STANDARDS.md` for the full rule set. Added in 1.1.1 so the template now matches
the ecosystem the hooks were already defending.

### Layer 2 — The Runtime Security Layer

Four files under `security/`. All zero-dependency, all drop-in, all work on Windows,
Linux, and macOS. Two languages (Node and Python) at parity.

**`01-injection-guard.js` / `injection_guard.py` — Input + output scanner**
Wraps every call into your AI API. Scans user input before it reaches the model (blocks
critical injections, sanitizes delimiters, normalizes Unicode) and scans AI output
before it reaches your user (blocks leaked API keys, catches reflected injection).

- **28 injection patterns** — classic override, role hijack, prompt extraction, delimiter
  injection, jailbreak classics, HTML/block-comment context poisoning
- **Secret leak detection** — OpenAI (`sk-proj-` and legacy), Anthropic (`sk-ant-api03-`),
  Google, GitHub, AWS, private keys, inline passwords, database connection strings with
  embedded credentials. **All key format regexes were updated in 1.1.1** — prior releases
  silently missed current-generation OpenAI and Anthropic keys. If you were relying on
  the output scanner, please upgrade.
- **Unicode / encoding bypass defense** — NFKC normalization (fullwidth attacks),
  invisible-character stripping (zero-width space attacks), URL-decode, base64-decode —
  before the pattern scan runs
- **Input length cap** (1.1.1) — `scan()` hard-caps input at 100 KB to prevent CPU burn
  from crafted mega-payloads
- **Express middleware** (Node) and **FastAPI dependency** (Python) both included

**`02-code-security.js` — Server utilities**
Secure headers, rate limiter, structured logger with request ID threading, consistent
success/error response shapes, health check helper, environment variable validation,
Windows environment setup helper. Drop in, wire up, done.

**`03-audit.js` — Standalone audit CLI**
Run `guardian audit` from anywhere inside a project. Scans for hardcoded secrets,
silent catches, raw SQL string concatenation, `console.log` in production paths,
missing health endpoints, `any`-typed TypeScript, and a dozen other junior patterns.
Exit code signals CI failure when --fail-on-error is set. JSON output mode for
machine parsing.

**Injection guard — Python parity**
`security/injection_guard.py` is a full parity implementation of the Node module —
same patterns, same normalizer, same `guardInput` / `guardOutput` shape. Import and
use in FastAPI, Flask, Django, or plain Python. No additional dependencies.

---

## Agent Compatibility

Guardian is split cleanly between **portable features** that work for every agent and
**Claude Code integrations** that only work inside Claude Code. Know which tier you're in
before you install:

| Agent                                       | Behavior rules | Runtime guard | Audit CLI | PreToolUse / PostToolUse hooks |
|---------------------------------------------|:-------------:|:-------------:|:---------:|:------------------------------:|
| **Claude Code**                             | ✅ `CLAUDE.md` | ✅            | ✅        | ✅                              |
| **Codex CLI**                               | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Cursor**                                  | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Aider**                                   | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Continue**                                | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Windsurf**                                | ✅ `AGENTS.md` | ✅            | ✅        | —                              |
| **Gemini CLI**                              | ✅ `GEMINI.md` | ✅            | ✅        | —                              |

**Why the split:** the runtime guard, the audit CLI, and the behavior files are portable
— they work anywhere Node or Python runs. The two Claude Code hooks live inside
Claude's PreToolUse / PostToolUse tool-call lifecycle, which has no direct equivalent in
other agents. When you run `guardian check` it reports which tier you're in and what's
active per agent.

**Last updated:** April 2026. If your agent reads a behavior file at session start and
is not listed above, treat it as equivalent to Codex CLI (Tier 1 features only).

---

## Install Once. Use Everywhere.

Guardian has two parts:

| Part | What it is | When you do it |
|------|-----------|----------------|
| **The CLI** | The `guardian` command | Once per machine |
| **The project files** | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `STANDARDS.md`, `security/`, etc. | Once per project |

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

**Step 3 — Start (or restart) your coding agent.** Behavior files are re-read at session
start:

- **Claude Code** reads `CLAUDE.md` and `STANDARDS.md` automatically.
- **Codex CLI, Cursor, Aider, Continue, Windsurf** read `AGENTS.md` (which points at
  `STANDARDS.md` and `CLAUDE.md`).
- **Gemini CLI** reads `GEMINI.md` (which points at the same shared rule set).

Then run `guardian check` to confirm the install and see which coverage tier you're in.

> Setting up a new machine later? Just repeat Step 1. Your projects keep their files.

---

## The Six Commands

Once installed, you have six commands:

**`guardian init`** — Run once inside each project you want Guardian in. Merge-safe and
idempotent.
```bash
cd /your/project
guardian init
```

**`guardian update`** — Re-merge the latest Guardian files into an existing project.
Same behavior as `init` (safe to re-run any time). Use this after pulling a new release.
```bash
guardian update
```

**`guardian audit`** — Scan your project for security and quality problems. 23 rules in
1.1.1. Run regularly.
```bash
guardian audit
guardian audit ./src              # scope to a subdirectory
guardian audit . --fail-on-error  # exit 1 if any CRITICAL/HIGH findings
guardian audit . --json           # machine-readable output for CI
```

**`guardian scan`** — Test a specific string for prompt injection. Useful during
development.
```bash
guardian scan "some text you want to check"
```

**`guardian check`** — Verify Guardian is correctly installed. Includes a hook smoke
test that pipes a known-bad payload through the PreToolUse hook and confirms it fires.
Also prints the editor coverage table.
```bash
guardian check
```

**`guardian list-watched`** — Print the effective hook watch list for the current
project. Useful when debugging why a file is (or isn't) being scanned by the hook.
```bash
guardian list-watched
```

---

## What You Get on Every Init

Two clearly-scoped tiers. Tier 1 works for every agent. Tier 2 only activates inside
Claude Code.

### Tier 1 — Works in any project, with any agent

**Senior-dev behavior rules, loaded from `AGENTS.md` / `CLAUDE.md` / `GEMINI.md` / `STANDARDS.md`:**
- No silent `catch {}` blocks (and from 1.1.1, no `catch { /* comment */ }` either)
- No hardcoded secrets, URLs, or config values
- Structured logging with request IDs on every entry
- Versioned APIs with consistent response shapes
- Zod / Pydantic validation — never hand-rolled
- Self-audit checklist before marking any task complete
- Stack deviation warnings when the agent is about to reach for a junior-level library

**Runtime protection for your running app:**
- Prompt injection scanner — 28 patterns including Unicode bypass attacks (NFKC
  normalization, invisible-character stripping, base64/URL decoding)
- Output scanner — catches leaked API keys (OpenAI `sk-proj-`, Anthropic `sk-ant-api03-`,
  legacy `sk-`, Google, GitHub, AWS, private keys, and connection strings with embedded
  credentials)
- Rate limiter, secure headers, structured logger, health check endpoint
- Works identically in Node (`security/01-injection-guard.js`) and Python
  (`security/injection_guard.py`)

**Audit CLI — scan any codebase:**
- `guardian audit` scans for hardcoded secrets, silent errors, raw SQL, console.log in
  prod paths, missing `/health`, and more (23 rules in 1.1.1 — every finding should be
  reviewed; the tool is advisory)
- JSON output mode for CI integration
- Works on any project — Python, TypeScript, JavaScript, mixed

**GitHub Actions workflow (if you push to GitHub):**
- Secret scanning (Gitleaks)
- Dependency vulnerability checks (`npm audit`, `pip-audit`)
- Full codebase audit on every PR
- All Guardian unit tests run before the audit
- Audit exemption count posted to the workflow summary for visibility

### Tier 2 — Claude Code integrations (Claude Code only)

These features piggy-back on Claude Code's `PreToolUse` / `PostToolUse` tool-call
lifecycle, which no other agent exposes today. They're installed automatically by
`guardian init` and do nothing if you're not running inside Claude Code.

**Two advisory hooks (never block — only surface warnings):**
- **PreToolUse** scans every Write/Edit on a wide default watch list — `.planning/`,
  `.gsd/`, `.plans/`, `.cursor/`, `.continue/`, `.aider/`, `.windsurf/`, every `*/memory/`
  directory, plus `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
  `MEMORY.md`, `copilot-instructions.md`, and `.env*`. Patterns are imported from the
  runtime guard so they cannot drift.
- **PostToolUse** scans every `WebFetch` and `WebSearch` response **before** Claude
  reasons about the content — catches indirect prompt injection at the entry point, the
  highest-leverage place to defend.
- Configurable per project via `otlcGuardian.watchPaths` / `ignorePaths` in
  `.claude/settings.json`. Doc-exempt marker (`otlc-guardian:doc`) silences scanning for
  security spec files.

**Hook smoke test in `guardian check`:**
- Pipes a known-injection payload through the `PreToolUse` hook and confirms it fires
- Catches broken hook installs (wrong shebang, missing import, etc.) before you discover
  them the hard way in a real session

> **For non-Claude users:** Tier 2 is not blocking or even visible in your workflow. You
> get the full Tier 1 stack, which is the majority of Guardian's value. An equivalent
> lifecycle-hook integration for Codex / Cursor / Aider would require per-agent
> tool-call interception which those tools don't currently expose — we're tracking it,
> but we're not pretending it exists today.

---

## Safe on Existing Projects

`guardian init` never overwrites your files. It merges:

- **CLAUDE.md** — your rules stay at the top, Guardian's are appended below (Claude Code
  behavior file)
- **AGENTS.md** — same merge pattern (universal agent behavior file)
- **GEMINI.md** — same merge pattern (Gemini CLI entry point)
- **STANDARDS.md** — same merge pattern (approved technology stack)
- **.gitignore** — only adds entries you don't already have
- **.env.example** — only adds variables you don't already have
- **.claude/settings.json** — adds Guardian's Claude-only hooks alongside your existing
  hooks (aborts if the file has invalid JSON rather than clobbering it)
- **Everything else** — only copies files that don't already exist

Run it twice — nothing changes the second time. It detects what's already there and
skips it. Guardian's own internal test files and Python bytecode caches are never
copied into your project (1.1.1 fix — prior releases shipped `tests/` and `__pycache__/`
into every user project).

---

## Privacy

OTLC Guardian does not collect data, does not phone home, and does not require a
network connection. All Guardian operations (injection scanning, auditing, hook
execution) run entirely on your machine. There are no API calls to
`onthelevelconcepts.com` or any external service. The package has **zero runtime
dependencies** (`"dependencies": {}` in `package.json`) — every import is a Node
builtin, which you can verify by grepping the source tree.

---

## Uninstalling

To remove Guardian from a project while keeping your own code intact:

**1. Remove the Guardian-added files:**
```bash
rm -f CLAUDE.md AGENTS.md GEMINI.md STANDARDS.md
rm -rf security/
rm -rf .claude/hooks/
```

**2. Revert `.gitignore` and `.env.example` if you want them back to pre-Guardian state:**
```bash
git checkout .gitignore .env.example
```

**3. Clean `.claude/settings.json`** — open the file and remove only the Guardian-added
entries (PreToolUse `Write|Edit` running `injection-guard-hook.mjs`, and PostToolUse
`WebFetch|WebSearch` running `web-content-guard.mjs`). Leave any other hooks alone.

**4. Uninstall the global CLI if you want it off the machine entirely:**
```bash
npm uninstall -g otlc-guardian
```

You do **not** need to uninstall the global CLI to stop using Guardian in a project.
Deleting the project files is enough — the CLI does nothing on its own.

---

## Maintenance & Support

OTLC Guardian is actively maintained. For security issues, see [`SECURITY.md`](SECURITY.md)
— there is a private disclosure process with a 3-business-day target response. For bug
reports and feature requests, open a
[GitHub issue](https://github.com/Omnib0mb3r/otlc-guardian/issues). For general questions,
start a [discussion](https://github.com/Omnib0mb3r/otlc-guardian/discussions).

---

## Full Documentation

| File | What's in it |
|------|-------------|
| `SETUP.md` | Complete step-by-step guide with troubleshooting |
| `CLAUDE.md` | Full Claude behavior rules (HOW to build) |
| `STANDARDS.md` | Full approved technology stack (WHAT to build with) |
| `AGENTS.md` | Universal agent entry point (non-Claude agents) |
| `GEMINI.md` | Gemini CLI entry point |
| `SECURITY.md` | Threat model, reporting process, and what Guardian does not protect against |
| `FAQ.md` | Common questions answered |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | How to contribute patterns, rules, or fixes |

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
- Replace `onthelevelconcepts.com` in `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, and `STANDARDS.md`
- Replace `Omnib0mb3r/otlc-guardian` in `README.md` and `SETUP.md` install commands
- Keep `security/` intact — don't modify the runtime guard unless you're adding patterns
- Keep the `otlc-guardian:doc` and `otlc-guardian:audit-exempt` marker names intact, or your fork's markers won't match any downstream docs that reference them

### Single-agent fork (e.g. Codex-only, Cursor-only)

If you want a fork that's scoped to a single agent — say, a Codex-first template for
your team — the work is bigger than a rebrand. Be honest with yourself about the effort
before you start:

- **Delete the Claude-specific tier.** Remove `CLAUDE.md`, `.claude/`, the
  `mergeClaudeSettings` call path in `bin/guardian.js`, the smoke test in `runCheck`,
  and the Claude Code row from the compatibility table. Update `runInit`'s "what was
  merged" output. Update tests in `tests/init.test.js` and `tests/hook.test.js` that
  assert Claude-specific behavior.
- **Replace the hook layer with something your agent actually supports** — or drop it
  entirely and ship a behavior-only product. Guardian's PreToolUse / PostToolUse hooks
  rely on Claude Code's tool-call lifecycle; Codex, Cursor, Aider, Continue, and
  Windsurf don't expose an equivalent as of early 2026. A real replacement is a 1–2 day
  research-and-build effort at minimum, and it may not be possible at all depending on
  the agent. A behavior-only fork is the realistic path.
- **Rewrite the value sections in README, SETUP, and FAQ.** Everything in "Tier 2 —
  Claude Code integrations" has to go. The compatibility table collapses to one row.
  The `guardian check` editor-coverage output needs to be simplified.
- **Decide whether to rename files.** `CLAUDE.md` is meaningless in a Codex-only fork.
  You can delete it, or keep it as an alias that points at `AGENTS.md`. Test your choice
  against `bin/guardian.js` and the test suite.

If the above feels like a lot, that's the honest signal: a single-agent fork is real
engineering work, not a 10-minute rebrand. The multi-agent default is the path of
least resistance for almost every use case.

---

*OTLC Guardian · [onthelevelconcepts.com](https://onthelevelconcepts.com) · Built to the standard of a $100k engagement, with the honesty about its limits that a real $100k engagement also ships.*
