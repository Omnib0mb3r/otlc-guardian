# OTLC Guardian — Setup Guide
<!-- onthelevelconcepts.com · Version 1.1.0 -->

Step-by-step setup from zero to a fully protected, standards-enforced project.  
Estimated time: **10 minutes** for a new project, **5 minutes** for an existing one.

---

## Prerequisites

Confirm these are installed before starting:

| Tool | Minimum Version | How to Check |
|------|----------------|--------------|
| Node.js | 22 LTS or higher | `node --version` |
| Git | Any recent version | `git --version` |
| Claude Code | Latest | `claude --version` |
| Python | 3.11+ (Python projects only) | `python --version` |

---

## Understanding Global vs Project Level

Before you start, it helps to understand the two distinct parts of Guardian:

**The CLI — global, installed once**

```bash
npm install -g .
```

This installs the `guardian` command on your machine so it works from any folder, any project, forever. You only do this once per machine.

**The project files — per project**

```bash
guardian init
```

This copies `CLAUDE.md`, `STANDARDS.md`, `security/`, and the supporting files into a specific project. Each project you work on gets its own copy of these files. Claude Code reads them automatically because they live in that project's root.

**This repo is both things at once** — it's the source you clone to get the CLI, and it's the template that `guardian init` copies from.

---

## Step 1 — Clone Guardian

```bash
git clone https://github.com/Omnib0mb3r/otlc-guardian.git
cd otlc-guardian
```

---

## Step 2 — Install the CLI

```bash
npm install -g .
```

This makes the `guardian` command available everywhere on your machine.  
Verify it worked:

```bash
guardian help
```

You should see the list of available commands. If you see a "command not found" error, see the troubleshooting section at the bottom of this guide.

---

## Step 3 — Add Guardian to Your Project

### New project (starting fresh)

If you cloned Guardian as your project root, you are already done. Skip to Step 4.

### Existing project (recommended approach)

Navigate to your project and run:

```bash
cd /path/to/your-project
guardian init
```

`guardian init` is **fully merge-safe**. It never overwrites anything you already have:

| File / Folder | What happens |
|---------------|-------------|
| `CLAUDE.md` | Guardian rules **appended** below your existing content |
| `STANDARDS.md` | Guardian stack **appended** below your existing content |
| `.gitignore` | Guardian entries **appended** — only ones you don't already have |
| `.env.example` | Guardian variables **appended** — only ones you don't already have |
| `.claude/settings.json` | Guardian hook **merged** into your existing hooks config |
| `security/` files | **Copied only if not already present** |
| `.claude/hooks/` files | **Copied only if not already present** |
| `.github/` files | **Copied only if not already present** |

Running `guardian init` a second time is safe — it detects everything already in place and skips it. No duplicates, no broken config.

### Verify the result

```bash
guardian check
```

You should see all green checkmarks. Any missing files will be flagged with instructions.

---

## Step 4 — Set Up Environment Variables

Guardian enforces that secrets never live in code. All sensitive values must be in environment variables.

### Create your local .env file

```bash
cd your-project
cp .env.example .env
```

Open `.env` and fill in your actual values. This file is already in `.gitignore` — it will never be committed to git.

### Register variables permanently (so they survive restarts)

**Windows — PowerShell (permanent):**
```powershell
[System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-your-key", "User")
[System.Environment]::SetEnvironmentVariable("DATABASE_URL",   "postgresql://user:pass@host:5432/db", "User")
[System.Environment]::SetEnvironmentVariable("JWT_SECRET",     "your-secret-minimum-32-chars", "User")
```

**Windows — GUI (no PowerShell needed):**
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Click **Advanced** tab
3. Click **Environment Variables**
4. Under **User variables**, click **New**
5. Add each key and value

**Windows — current session only (lost on restart):**
```powershell
$env:OPENAI_API_KEY = "sk-your-key"
$env:DATABASE_URL   = "postgresql://..."
```

**Mac / Linux:**
```bash
export OPENAI_API_KEY=sk-your-key
export DATABASE_URL=postgresql://...
# Add these lines to ~/.zshrc or ~/.bashrc to persist
```

### Set GitHub Secrets for CI/CD

For every variable in `.env.example`:
1. Go to your GitHub repo
2. Settings → Secrets and variables → Actions
3. Click **New repository secret**
4. Add the variable name and value

Reference them in workflows as `${{ secrets.VARIABLE_NAME }}`.

---

## Step 5 — Wire Up the Runtime Guard

This is the code that protects your live app. Add it to any route that passes user input to an AI model.

### Minimum integration — one line

```javascript
import { guardInput } from './security/01-injection-guard.js';

const clean = guardInput(userMessage);
const reply = await yourAI(clean);
```

That is the minimum. Everything else is additive.

### Full Node.js / Express setup

```javascript
import express from 'express';
import { guardInput, guardOutput, GuardianError } from './security/01-injection-guard.js';
import {
  validateEnv,
  requestIdMiddleware,
  applySecureHeaders,
  rateLimitMiddleware,
  errorHandler,
  healthCheck,
} from './security/02-code-security.js';

// Fail fast at startup — never start with missing secrets
validateEnv(['OPENAI_API_KEY', 'DATABASE_URL', 'JWT_SECRET']);

const app = express();
app.use(express.json());
app.use(requestIdMiddleware);   // assigns UUID to every request
app.use(applySecureHeaders);    // HSTS, CSP, X-Frame-Options, etc.

app.get('/health', healthCheck);

app.post('/api/v1/chat',
  rateLimitMiddleware({ limit: 20, windowMs: 60_000 }),
  async (req, res, next) => {
    try {
      const clean = guardInput(req.body.message, { context: 'POST /api/v1/chat' });
      const reply = await callYourAI(clean);
      const safe  = guardOutput(reply, { context: 'AI response' });
      res.json({ success: true, data: { reply: safe }, requestId: req.requestId });
    } catch (err) {
      if (err instanceof GuardianError) {
        return res.status(400).json({
          success: false,
          error: { code: 'ERR_REJECTED', message: 'Input rejected.' },
          requestId: req.requestId,
        });
      }
      next(err);
    }
  }
);

app.use(errorHandler); // always register last
```

### Full Python / FastAPI setup

```python
from security.injection_guard import guard_input, guard_output, GuardianError
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI()

class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)

@app.get('/health')
async def health():
    return {'status': 'ok'}

@app.post('/api/v1/chat')
async def chat(body: ChatRequest, request: Request):
    try:
        clean = guard_input(body.message, context=f'{request.method} {request.url.path}')
        reply = await call_your_ai(clean)
        safe  = guard_output(reply)
        return {'success': True, 'data': {'reply': safe}}
    except GuardianError:
        raise HTTPException(status_code=400, detail={
            'success': False,
            'error': {'code': 'ERR_REJECTED', 'message': 'Input rejected.'}
        })
```

---

## Step 6 — Understand the Two Hooks

Guardian installs two Claude Code hooks. They are advisory only — they
**never block** a tool call, only surface a warning. Both are wired up
automatically by `guardian init` and registered in `.claude/settings.json`.

### Hook 1 — `injection-guard-hook.mjs` (PreToolUse on Write/Edit)

Fires every time Claude writes or edits a file in a watched location and
scans the content for the same 28 injection patterns the runtime guard
uses (single source of truth — the hook imports them directly from
`security/01-injection-guard.js`, so they cannot drift).

**Default watched paths** — anything that ends up loaded into a future
Claude session as instructions, memory, or research:

- `.planning/`, `.gsd/`, `.plans/` — phase plans, research, roadmaps
- `.claude/`, `.cursor/`, `.continue/`, `.aider/`, `.windsurf/` — coding-agent state
- Any `*/memory/` directory — auto-memory and persistent context stores
- `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` — cross-agent instruction files
- `.cursorrules`, `.windsurfrules`, `.aider.conf.yml`, `copilot-instructions.md`
- `MEMORY.md` — auto-memory index
- `.env*` — environment files (sometimes contain embedded payloads)

### Hook 2 — `web-content-guard.mjs` (PostToolUse on WebFetch/WebSearch)

Fires every time Claude fetches a URL or runs a web search, and scans the
returned content **before Claude reasons about it**. This is the entry
point for indirect prompt injection — hostile instructions hidden in a
web page or search result. Catching it here is dramatically higher
leverage than waiting until Claude has laundered the content into a plan
file.

The warning includes the source URL so you can decide whether to trust
the fetched content.

### Customizing the watch list

Both hooks honor an `otlcGuardian` config block in `.claude/settings.json`:

```json
{
  "otlcGuardian": {
    "extendDefaults": true,
    "watchPaths":  ["src/prompts/", ".myplanning/"],
    "ignorePaths": ["docs/security-spec.md"]
  }
}
```

- `watchPaths` — extra paths to scan (added to defaults)
- `ignorePaths` — paths to exclude from scanning
- `extendDefaults: false` — replace the default list entirely with your own

### Exempting a doc file

If you keep prompt-injection documentation in a watched directory (e.g.
a security spec in `.planning/specs/injection-defense.md`), add the
marker `otlc-guardian:doc` anywhere in the file and the hook will skip
it. No more false-positive warnings on your own security docs.

```markdown
<!-- otlc-guardian:doc -->
# Injection Defense Spec

This document discusses "ignore all previous instructions" as a
known attack vector...
```

### Verifying the hooks work

```bash
guardian check
```

This runs a smoke test that pipes a known-bad payload through the
PreToolUse hook and confirms it fires. If the hook is broken (wrong
shebang, missing import, etc.) you'll see it here instead of discovering
it during a real Claude session.

---

## Step 7 — Run Your First Audit

Scan your project for existing security and quality issues:

```bash
guardian audit
```

Or using the direct script:
```bash
node security/03-audit.js
node security/03-audit.js ./src              # scan a specific folder
node security/03-audit.js . --fail-on-error  # exit code 1 on HIGH/CRITICAL — use in CI
node security/03-audit.js . --json           # machine-readable output
```

**What it checks:**
- Hardcoded API keys and secrets (OpenAI, AWS, GitHub, private keys)
- Hardcoded passwords and inline credentials
- Hardcoded `localhost` URLs and IP addresses
- Silent `catch {}` blocks
- `console.log()` in non-test code
- `eval()` usage
- `innerHTML` and `dangerouslySetInnerHTML` (XSS risk)
- Committed `.env` files
- Missing health check endpoints
- Unversioned API routes

Fix all **CRITICAL** and **HIGH** findings before pushing to production.

---

## Step 8 — Verify Claude Code is Reading the Standards

Open a Claude Code session in your project directory:

```bash
claude
```

Ask Claude:
```
What standards are you following for this project?
```

Claude should describe the rules from `CLAUDE.md` and the stack from `STANDARDS.md`. If it doesn't reference either file, verify both files are in the **project root** — not in a subdirectory.

**Test behavioral enforcement:**

```
Show me how to fetch data in a React component.
```
→ Claude should reach for TanStack Query, not raw `useEffect` + `fetch`.

```
Add a catch block to this function.
```
→ Claude should write a structured, logged error handler — not `catch (e) {}`.

```
I need to store the user's auth token.
```
→ Claude should reach for `httpOnly` cookies, not `localStorage`.

---

## Step 9 — Confirm CI/CD is Active

The workflow at `.github/workflows/security-audit.yml` activates automatically when you push to GitHub. No configuration needed.

To verify it's working:
1. Push a commit to your repo
2. Go to your repo on GitHub
3. Click the **Actions** tab
4. You should see the **OTLC Guardian — Security Audit** workflow running

What it runs on every push and PR:
1. OTLC Guardian safety audit (`--fail-on-error`)
2. Gitleaks secret scanning
3. `npm audit` (if `package.json` exists)
4. `pip-audit` (if `requirements.txt` exists)

---

## Pre-Production Checklist

Run through this before your first production deployment:

**Setup:**
- [ ] `CLAUDE.md` exists in project root
- [ ] `STANDARDS.md` exists in project root
- [ ] `.env` created from `.env.example` with real values filled in
- [ ] `.env` is listed in `.gitignore` and has NOT been committed
- [ ] `security/` folder is in your project
- [ ] `guardian check` shows all green

**Runtime guard:**
- [ ] `guardInput()` called before every AI API call
- [ ] `guardOutput()` called on every AI response before sending to the user
- [ ] `validateEnv()` called at app startup with all required key names
- [ ] `/health` endpoint exists and returns 200

**CI/CD:**
- [ ] `.github/workflows/security-audit.yml` is present
- [ ] GitHub Secrets configured for all production environment variables
- [ ] CI passes on the current branch

**Claude Code behavior:**
- [ ] Claude references `CLAUDE.md` rules when asked about project standards
- [ ] Claude reaches for approved stack tools (Zod, Pino, TanStack Query, Prisma)
- [ ] Claude flags any stack deviations visibly before proceeding

---

## Troubleshooting

**`guardian: command not found` after `npm install -g .`**

On Windows, the npm global bin directory may not be in your PATH.  
Find your npm global bin path:
```powershell
npm config get prefix
```
Add `<that path>\bin` to your User environment variables PATH.  
Or run Guardian directly:
```powershell
node C:\path\to\otlc-guardian\bin\guardian.js help
```

**`Cannot find module './security/01-injection-guard.js'`**

Your `package.json` needs `"type": "module"` for ESM imports.  
Add it, or use `require()` with `.cjs` file extensions for CommonJS.

**`Missing required environment variables` at startup**

Open `.env` and confirm every variable listed in `.env.example` has a value.  
On Windows, also confirm the variables are set in System Environment Variables if you're running outside a terminal that loaded `.env`.

**Claude Code hook not activating**

Confirm `.claude/settings.json` is in the **project root** (not a subdirectory).  
The command `node .claude/hooks/injection-guard-hook.js` must resolve from the project root.  
Run `guardian check` to verify the hook is registered correctly.

**GitHub Actions failing on Gitleaks scan**

If Gitleaks flags test fixtures, example values, or documentation code:  
Add the path to `.github/secret_scanning.yml` under `paths-ignore`.

**`guardian init` merged CLAUDE.md but Claude doesn't seem to follow the rules**

Close and reopen your Claude Code session. Claude reads `CLAUDE.md` at session start, so changes take effect on the next session.

**`guardInput is not a function`**

You are likely mixing CommonJS `require()` with ESM files.  
Add `"type": "module"` to your `package.json` to use ESM imports throughout.

---

*OTLC Guardian · [onthelevelconcepts.com](https://onthelevelconcepts.com) · Version 1.1.0*
