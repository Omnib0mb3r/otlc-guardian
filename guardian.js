#!/usr/bin/env node
// ============================================================
// OTLC Guardian — CLI
// // onthelevelconcepts.com
// ============================================================
//
// Usage:
//   guardian audit           Scan current project for issues
//   guardian audit ./src     Scan a specific folder
//   guardian scan "text"     Scan a string for injection
//   guardian check           Verify Guardian is set up correctly
//   guardian init            Copy Guardian files into current project
//   guardian help            Show this help
//
// ============================================================

import { execSync } from "child_process";
import { existsSync, mkdirSync, copyFileSync, readdirSync, statSync,
         readFileSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT      = path.join(__dirname, "..");
const CWD       = process.cwd();
const args      = process.argv.slice(2);
const command   = args[0];

// ---------------------------------------------------------------------------
// COLORS — no dependencies
// ---------------------------------------------------------------------------
const c = {
  reset:  "\x1b[0m",
  cyan:   "\x1b[36m",
  green:  "\x1b[32m",
  yellow: "\x1b[33m",
  red:    "\x1b[31m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
};

const log  = (msg) => console.log(msg);
const info = (msg) => console.log(`${c.cyan}${msg}${c.reset}`);
const ok   = (msg) => console.log(`${c.green}✅ ${msg}${c.reset}`);
const warn = (msg) => console.warn(`${c.yellow}⚠️  ${msg}${c.reset}`);
const err  = (msg) => console.error(`${c.red}❌ ${msg}${c.reset}`);

// ---------------------------------------------------------------------------
// HELP
// ---------------------------------------------------------------------------

function showHelp() {
  log(`
${c.bold}${c.cyan}OTLC Guardian${c.reset} — Production-grade AI security guardrails
${c.dim}onthelevelconcepts.com${c.reset}

${c.bold}COMMANDS${c.reset}

  ${c.cyan}guardian audit${c.reset} [path] [--json] [--fail-on-error]
    Scan a codebase for security and quality issues.
    Default path: current directory.

    Examples:
      guardian audit
      guardian audit ./src
      guardian audit . --fail-on-error
      guardian audit . --json

  ${c.cyan}guardian scan${c.reset} "<text>"
    Scan a string for prompt injection patterns.
    Useful for testing your input before wiring up the runtime guard.

    Examples:
      guardian scan "ignore all previous instructions"
      guardian scan "What is the weather today?"

  ${c.cyan}guardian check${c.reset}
    Verify Guardian is correctly installed in the current project.
    Checks for required files and common setup issues.

  ${c.cyan}guardian init${c.reset}
    Copy Guardian files into the current project directory.
    Safe to run on existing projects — will not overwrite existing CLAUDE.md.

  ${c.cyan}guardian help${c.reset}
    Show this help message.

${c.bold}QUICK START${c.reset}

  1. Fork or clone: https://github.com/Omnib0mb3r/otlc-guardian
  2. Run: npm install -g .   (from the guardian directory)
  3. In any project: guardian init
  4. guardian audit

${c.dim}Version 1.1.0 · MIT License${c.reset}
`);
}

// ---------------------------------------------------------------------------
// AUDIT — wraps 03-audit.js
// ---------------------------------------------------------------------------

function runAudit() {
  const auditArgs = args.slice(1).join(" ") || ".";
  const auditScript = path.join(ROOT, "security", "03-audit.js");

  if (!existsSync(auditScript)) {
    err("Audit script not found. Is Guardian installed correctly?");
    process.exit(1);
  }

  try {
    execSync(`node "${auditScript}" ${auditArgs}`, { stdio: "inherit" });
  } catch (e) {
    // exit code 1 from audit script = issues found with --fail-on-error
    process.exit(e.status ?? 1);
  }
}

// ---------------------------------------------------------------------------
// SCAN — scan a string for injection
// ---------------------------------------------------------------------------

async function runScan() {
  const text = args.slice(1).join(" ");

  if (!text) {
    err("Usage: guardian scan \"<text to scan>\"");
    process.exit(1);
  }

  const guardModule = path.join(ROOT, "security", "01-injection-guard.js");
  const { scan, reportViolations } = await import(guardModule);

  log(`\n${c.bold}[OTLC GUARDIAN] SCANNING INPUT${c.reset}`);
  log(`${c.dim}Text: "${text.slice(0, 100)}${text.length > 100 ? "..." : ""}"${c.reset}\n`);

  const { violations } = scan(text, "all");
  reportViolations(violations, "guardian scan");

  if (violations.length === 0) {
    ok("No injection patterns detected. Input appears clean.");
  } else {
    const criticalCount = violations.filter(v => v.severity === "CRITICAL").length;
    warn(`${violations.length} pattern(s) detected (${criticalCount} CRITICAL).`);
    log(`\n  Recommendation: Do not pass this input to an AI API without sanitization.`);
  }
  log("");
}

// ---------------------------------------------------------------------------
// CHECK — verify Guardian is set up in the current project
// ---------------------------------------------------------------------------

function runCheck() {
  log(`\n${c.bold}[OTLC GUARDIAN] SETUP CHECK${c.reset}`);
  log(`${c.dim}Checking: ${CWD}${c.reset}\n`);

  const checks = [
    {
      label: "CLAUDE.md in project root",
      path: path.join(CWD, "CLAUDE.md"),
      required: true,
    },
    {
      label: "STANDARDS.md in project root",
      path: path.join(CWD, "STANDARDS.md"),
      required: true,
    },
    {
      label: "security/01-injection-guard.js",
      path: path.join(CWD, "security", "01-injection-guard.js"),
      required: true,
    },
    {
      label: "security/02-code-security.js",
      path: path.join(CWD, "security", "02-code-security.js"),
      required: true,
    },
    {
      label: "security/03-audit.js",
      path: path.join(CWD, "security", "03-audit.js"),
      required: true,
    },
    {
      label: ".claude/settings.json (Claude Code hook)",
      path: path.join(CWD, ".claude", "settings.json"),
      required: false,
    },
    {
      label: ".claude/hooks/injection-guard-hook.js",
      path: path.join(CWD, ".claude", "hooks", "injection-guard-hook.js"),
      required: false,
    },
    {
      label: ".env.example",
      path: path.join(CWD, ".env.example"),
      required: false,
    },
    {
      label: ".github/workflows/security-audit.yml",
      path: path.join(CWD, ".github", "workflows", "security-audit.yml"),
      required: false,
    },
    {
      label: ".env NOT committed (good)",
      path: path.join(CWD, ".env"),
      required: false,
      invert: true, // this one should NOT exist in git — warn if found
    },
  ];

  let passed = 0;
  let failed = 0;
  let warnings = 0;

  for (const check of checks) {
    const exists = existsSync(check.path);

    if (check.invert) {
      if (exists) {
        warn(`${check.label} — .env found. Make sure it is in .gitignore!`);
        warnings++;
      } else {
        ok(`No .env file found in root (secrets managed via environment)`);
        passed++;
      }
      continue;
    }

    if (exists) {
      ok(check.label);
      passed++;
    } else if (check.required) {
      err(`MISSING (required): ${check.label}`);
      failed++;
    } else {
      warn(`Missing (optional): ${check.label}`);
      warnings++;
    }
  }

  log(`\n${c.bold}Results:${c.reset} ${passed} passed · ${warnings} warnings · ${failed} missing required`);

  if (failed > 0) {
    log(`\n  Run ${c.cyan}guardian init${c.reset} to copy missing files into this project.\n`);
    process.exit(1);
  } else {
    log(`\n  ${c.green}Guardian is correctly installed in this project.${c.reset}\n`);
  }
}

// ---------------------------------------------------------------------------
// INIT HELPERS
// ---------------------------------------------------------------------------

/** Read a file as string, return '' if missing */
function readFile(p) {
  try { return readFileSync(p, "utf8"); } catch { return ""; }
}

/** Write a file, creating parent dirs as needed */
function writeFile(p, content) {
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, content, "utf8");
}

/**
 * Merge two Markdown files.
 * Guardian content is appended under a clearly labelled section header
 * so the user's existing content is 100% preserved above it.
 * Idempotent — won't append again if the Guardian section already exists.
 */
function mergeMd(existingPath, guardianSrcPath, label) {
  const existing = readFile(existingPath);
  const incoming = readFile(guardianSrcPath);
  const marker   = `<!-- OTLC-GUARDIAN-START -->`;

  if (existing.includes(marker)) {
    warn(`${label} — Guardian section already present, skipping`);
    return;
  }

  const merged =
    existing.trimEnd() +
    `\n\n${marker}\n` +
    `---\n\n` +
    `<!-- The section below was added by OTLC Guardian (guardian init)     -->\n` +
    `<!-- Do not edit between the OTLC-GUARDIAN-START and END markers.      -->\n` +
    `<!-- To update, run: guardian init  (safe to re-run at any time)       -->\n\n` +
    incoming.trim() +
    `\n\n<!-- OTLC-GUARDIAN-END -->\n`;

  writeFile(existingPath, merged);
  ok(`${label} — merged Guardian content into existing file`);
}

/**
 * Merge Guardian's Claude Code hook into an existing .claude/settings.json.
 * Reads the existing JSON, finds (or creates) the PreToolUse hook array,
 * and adds the Guardian hook entry only if it isn't already there.
 * Never removes or modifies existing hooks.
 */
function mergeClaudeSettings(existingPath, guardianSrcPath) {
  const guardianHook = {
    type:    "command",
    command: "node .claude/hooks/injection-guard-hook.js",
  };

  let existing = {};
  try {
    existing = JSON.parse(readFile(existingPath) || "{}");
  } catch {
    warn(".claude/settings.json exists but is invalid JSON — writing fresh copy");
    copyFileSync(guardianSrcPath, existingPath);
    ok(".claude/settings.json — replaced (was invalid JSON)");
    return;
  }

  // Navigate / create the hook path
  existing.hooks                  = existing.hooks ?? {};
  existing.hooks.PreToolUse       = existing.hooks.PreToolUse ?? [];

  // Find or create the Write|Edit matcher block
  let matcherBlock = existing.hooks.PreToolUse.find(
    (b) => b.matcher === "Write|Edit"
  );

  if (!matcherBlock) {
    matcherBlock = { matcher: "Write|Edit", hooks: [] };
    existing.hooks.PreToolUse.push(matcherBlock);
  }

  matcherBlock.hooks = matcherBlock.hooks ?? [];

  // Check if Guardian hook already registered
  const alreadyAdded = matcherBlock.hooks.some(
    (h) => h.command === guardianHook.command
  );

  if (alreadyAdded) {
    ok(".claude/settings.json — Guardian hook already registered");
    return;
  }

  matcherBlock.hooks.push(guardianHook);
  writeFile(existingPath, JSON.stringify(existing, null, 2) + "\n");
  ok(".claude/settings.json — Guardian hook merged into existing config");
}

/**
 * Merge a .gitignore — appends Guardian's entries under a labelled block.
 * Idempotent. Never removes existing entries.
 */
function mergeGitignore(existingPath, guardianSrcPath) {
  const existing = readFile(existingPath);
  const incoming = readFile(guardianSrcPath);
  const marker   = "# OTLC-GUARDIAN-START";

  if (existing.includes(marker)) {
    ok(".gitignore — Guardian entries already present");
    return;
  }

  // Extract only the lines from Guardian's gitignore that aren't already present
  const existingLines = new Set(existing.split("\n").map(l => l.trim()));
  const newLines = incoming
    .split("\n")
    .filter(l => l.trim() && !l.startsWith("#") && !existingLines.has(l.trim()));

  if (newLines.length === 0) {
    ok(".gitignore — all Guardian entries already covered");
    return;
  }

  const block =
    `\n# OTLC-GUARDIAN-START\n` +
    `# Added by OTLC Guardian (guardian init) — safe to keep\n` +
    newLines.join("\n") +
    `\n# OTLC-GUARDIAN-END\n`;

  writeFile(existingPath, existing.trimEnd() + block);
  ok(`.gitignore — ${newLines.length} Guardian entries merged`);
}

/**
 * Merge a .env.example — appends Guardian's variables under a labelled block.
 * Idempotent. Never removes existing variables.
 */
function mergeEnvExample(existingPath, guardianSrcPath) {
  const existing = readFile(existingPath);
  const incoming = readFile(guardianSrcPath);
  const marker   = "# OTLC-GUARDIAN-START";

  if (existing.includes(marker)) {
    ok(".env.example — Guardian variables already present");
    return;
  }

  // Only add keys not already in existing file
  const existingKeys = new Set(
    existing.split("\n")
      .map(l => l.split("=")[0].trim())
      .filter(Boolean)
  );

  const newLines = incoming
    .split("\n")
    .filter(l => {
      const key = l.split("=")[0].trim();
      return key && !key.startsWith("#") && !existingKeys.has(key);
    });

  if (newLines.length === 0) {
    ok(".env.example — all Guardian variables already present");
    return;
  }

  const block =
    `\n# OTLC-GUARDIAN-START\n` +
    `# Added by OTLC Guardian (guardian init)\n` +
    newLines.join("\n") +
    `\n# OTLC-GUARDIAN-END\n`;

  writeFile(existingPath, existing.trimEnd() + block);
  ok(`.env.example — ${newLines.length} Guardian variables merged`);
}

/**
 * Copy a single file — only if destination does not exist.
 * Never overwrites.
 */
function copyIfNew(srcPath, destPath, label) {
  if (existsSync(destPath)) {
    ok(`${label} — already exists, skipped`);
    return;
  }
  mkdirSync(path.dirname(destPath), { recursive: true });
  copyFileSync(srcPath, destPath);
  ok(`${label} — copied`);
}

/**
 * Copy a directory of files — each file handled individually.
 * Never blindly overwrites an entire directory.
 */
function copyDirSafe(srcDir, destDir, label) {
  if (!existsSync(srcDir)) return;
  mkdirSync(destDir, { recursive: true });

  for (const entry of readdirSync(srcDir)) {
    const srcPath  = path.join(srcDir, entry);
    const destPath = path.join(destDir, entry);

    if (statSync(srcPath).isDirectory()) {
      copyDirSafe(srcPath, destPath, `${label}/${entry}`);
    } else if (!existsSync(destPath)) {
      copyFileSync(srcPath, destPath);
      ok(`${label}/${entry} — copied`);
    } else {
      ok(`${label}/${entry} — already exists, skipped`);
    }
  }
}

// ---------------------------------------------------------------------------
// INIT — merge Guardian into current project without breaking anything
// ---------------------------------------------------------------------------

function runInit() {
  log(`\n${c.bold}[OTLC GUARDIAN] INITIALIZING PROJECT${c.reset}`);
  log(`${c.dim}Target: ${CWD}${c.reset}`);
  log(`${c.dim}Guardian source: ${ROOT}${c.reset}\n`);

  // ── 1. CLAUDE.md ─────────────────────────────────────────────────────────
  log(`${c.bold}── CLAUDE.md${c.reset}`);
  const claudeDest = path.join(CWD, "CLAUDE.md");
  const claudeSrc  = path.join(ROOT, "CLAUDE.md");
  if (existsSync(claudeDest)) {
    mergeMd(claudeDest, claudeSrc, "CLAUDE.md");
  } else {
    copyFileSync(claudeSrc, claudeDest);
    ok("CLAUDE.md — copied (new file)");
  }

  // ── 2. STANDARDS.md ──────────────────────────────────────────────────────
  log(`\n${c.bold}── STANDARDS.md${c.reset}`);
  const standardsDest = path.join(CWD, "STANDARDS.md");
  const standardsSrc  = path.join(ROOT, "STANDARDS.md");
  if (existsSync(standardsDest)) {
    mergeMd(standardsDest, standardsSrc, "STANDARDS.md");
  } else {
    copyFileSync(standardsSrc, standardsDest);
    ok("STANDARDS.md — copied (new file)");
  }

  // ── 3. .gitignore ─────────────────────────────────────────────────────────
  log(`\n${c.bold}── .gitignore${c.reset}`);
  const gitignoreDest = path.join(CWD, ".gitignore");
  const gitignoreSrc  = path.join(ROOT, ".gitignore");
  if (existsSync(gitignoreDest)) {
    mergeGitignore(gitignoreDest, gitignoreSrc);
  } else {
    copyFileSync(gitignoreSrc, gitignoreDest);
    ok(".gitignore — copied (new file)");
  }

  // ── 4. .env.example ───────────────────────────────────────────────────────
  log(`\n${c.bold}── .env.example${c.reset}`);
  const envDest = path.join(CWD, ".env.example");
  const envSrc  = path.join(ROOT, ".env.example");
  if (existsSync(envDest)) {
    mergeEnvExample(envDest, envSrc);
  } else {
    copyFileSync(envSrc, envDest);
    ok(".env.example — copied (new file)");
  }

  // ── 5. security/ ──────────────────────────────────────────────────────────
  log(`\n${c.bold}── security/${c.reset}`);
  copyDirSafe(
    path.join(ROOT, "security"),
    path.join(CWD, "security"),
    "security"
  );

  // ── 6. python/ ────────────────────────────────────────────────────────────
  log(`\n${c.bold}── python/${c.reset}`);
  copyDirSafe(
    path.join(ROOT, "python"),
    path.join(CWD, "python"),
    "python"
  );

  // ── 7. tests/ ─────────────────────────────────────────────────────────────
  log(`\n${c.bold}── tests/${c.reset}`);
  copyDirSafe(
    path.join(ROOT, "tests"),
    path.join(CWD, "tests"),
    "tests"
  );

  // ── 8. .claude/settings.json — smart JSON merge ───────────────────────────
  log(`\n${c.bold}── .claude/settings.json${c.reset}`);
  const claudeSettingsDest = path.join(CWD, ".claude", "settings.json");
  const claudeSettingsSrc  = path.join(ROOT, ".claude", "settings.json");
  mkdirSync(path.join(CWD, ".claude", "hooks"), { recursive: true });

  if (existsSync(claudeSettingsDest)) {
    mergeClaudeSettings(claudeSettingsDest, claudeSettingsSrc);
  } else {
    copyFileSync(claudeSettingsSrc, claudeSettingsDest);
    ok(".claude/settings.json — copied (new file)");
  }

  // ── 9. .claude/hooks/ — copy only, never overwrite ────────────────────────
  log(`\n${c.bold}── .claude/hooks/${c.reset}`);
  copyDirSafe(
    path.join(ROOT, ".claude", "hooks"),
    path.join(CWD, ".claude", "hooks"),
    ".claude/hooks"
  );

  // ── 10. .github/ — copy only, never overwrite ─────────────────────────────
  log(`\n${c.bold}── .github/${c.reset}`);
  copyDirSafe(
    path.join(ROOT, ".github"),
    path.join(CWD, ".github"),
    ".github"
  );

  // ── DONE ──────────────────────────────────────────────────────────────────
  log(`
${c.green}${c.bold}✅ Guardian initialized successfully.${c.reset}

${c.bold}What was merged / added:${c.reset}
  • CLAUDE.md        — Guardian rules appended (your content preserved above)
  • STANDARDS.md     — Guardian stack appended (your content preserved above)
  • .gitignore       — Guardian entries appended (your entries untouched)
  • .env.example     — Guardian variables appended (yours untouched)
  • security/        — Files copied (existing files skipped)
  • .claude/         — Hook merged into settings.json (your hooks untouched)
  • .github/         — Workflow files added (existing files skipped)

${c.bold}Next steps:${c.reset}

  1. ${c.cyan}cp .env.example .env${c.reset}  then fill in your secrets
     Never commit .env — it is in .gitignore

  2. Wrap every AI call with the input guard:
     ${c.cyan}import { guardInput } from './security/01-injection-guard.js';${c.reset}
     ${c.cyan}const clean = guardInput(userMessage);${c.reset}

  3. ${c.cyan}guardian audit${c.reset}  — scan your project for existing issues

  4. Start a Claude Code session — CLAUDE.md and STANDARDS.md
     activate automatically on the next session

${c.dim}Run guardian check at any time to verify your setup.${c.reset}
`);
}

// ---------------------------------------------------------------------------
// ROUTER
// ---------------------------------------------------------------------------

switch (command) {
  case "audit":
    runAudit();
    break;

  case "scan":
    runScan();
    break;

  case "check":
    runCheck();
    break;

  case "init":
    runInit();
    break;

  case "help":
  case "--help":
  case "-h":
  case undefined:
    showHelp();
    break;

  default:
    err(`Unknown command: "${command}"`);
    log(`Run ${c.cyan}guardian help${c.reset} to see available commands.`);
    process.exit(1);
}
