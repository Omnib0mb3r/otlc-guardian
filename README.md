# OTLC Guardian

**Makes Claude Code build like a senior developer. Protects your app from AI security attacks.**

Free and open source · MIT License · Built by [onthelevelconcepts.com](https://onthelevelconcepts.com)

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Node: 18+](https://img.shields.io/badge/Node-18%2B-green.svg)](https://nodejs.org)
[![Version: 1.1.0](https://img.shields.io/badge/version-1.1.0-blue.svg)](package.json)

---

## What It Does

Without Guardian, Claude takes shortcuts — silent error handling, hardcoded secrets, raw SQL, no tests. It builds fast, not right.

With Guardian, Claude behaves like a 30-year senior developer. It enforces production standards, refuses to cut corners, and reaches for the right tools automatically.

It also protects your running app. Every message a user sends gets scanned for prompt injection attacks before it reaches your AI. Every AI response gets scanned before it reaches your user.

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

That's it. Open Claude Code in your project — it reads the Guardian files automatically and enforces senior developer standards from that point on.

> Setting up a new machine later? Just repeat Step 1. Your projects keep their files.

---

## The Four Commands

Once installed, you have four commands. Here's when to use each one:

**`guardian init`** — Run this once inside each project you want Guardian in.
```bash
cd /your/project
guardian init
```

**`guardian audit`** — Run this to scan your project for security and quality problems. Use it regularly.
```bash
guardian audit
```

**`guardian scan`** — Run this to test a specific string for prompt injection. Useful during development.
```bash
guardian scan "some text you want to check"
```

**`guardian check`** — Run this if something isn't working. Tells you exactly what's missing.
```bash
guardian check
```

---

## What You Get

**Claude Code enforces these rules automatically:**
- No silent `catch {}` blocks
- No hardcoded secrets, URLs, or config values
- Structured logging with request IDs on every entry
- Versioned APIs with consistent response shapes
- 15-point self-audit before marking any task complete
- Flags when it's about to use a junior-level library and switches to the right one

**Your app gets runtime protection:**
- Prompt injection scanner — 28 patterns including Unicode bypass attacks
- Output scanner — catches secrets leaking in AI responses
- Rate limiter, secure headers, structured logger, health check endpoint
- Safety audit CLI — scan any codebase for hardcoded secrets, silent errors, bad patterns

**GitHub gets automatic scanning on every push:**
- Secret scanning
- Dependency vulnerability checks
- Full codebase audit on every PR

---

## Safe on Existing Projects

`guardian init` never overwrites your files. It merges:

- **CLAUDE.md** — your rules stay at the top, Guardian's are appended below
- **STANDARDS.md** — same
- **.gitignore** — only adds entries you don't already have
- **.env.example** — only adds variables you don't already have
- **.claude/settings.json** — adds Guardian's hook alongside your existing hooks
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

- Node.js 18+
- Python 3.11+ (Python module only)
- Claude Code (for behavior enforcement)
- GitHub (for CI/CD workflows)

---

## Forking

MIT licensed. Fork it, brand it, make it yours.

```bash
# Keep your fork in sync with upstream
git remote add upstream https://github.com/Omnib0mb3r/otlc-guardian.git
git fetch upstream && git merge upstream/main
```

When forking: update `package.json`, replace `onthelevelconcepts.com` in `CLAUDE.md` and `STANDARDS.md`, keep `security/` intact.

---

*OTLC Guardian · [onthelevelconcepts.com](https://onthelevelconcepts.com) · Built to the standard of a $100k engagement.*
