#!/usr/bin/env node
// ============================================================
// OTLC GUARDIAN — Claude Code PreToolUse Hook (ESM)
// // security · onthelevelconcepts.com
// Version: 1.3.1
// ============================================================
//
// Scans the content of Write and Edit tool calls before they touch
// files that will later be re-read into Claude's context. Defense in
// depth against indirect prompt injection and steganographic attacks
// that have been laundered through web research, memory, or planning
// artifacts.
//
// Triggered on: Write and Edit (registered in .claude/settings.json)
// Action:       Advisory only — never blocks (prevents tool deadlocks)
// Pattern source: imports directly from security/01-injection-guard.js
//                 so the hook can never drift from the main module.
//
// Configuration:
//   The watch list and ignore list are read from the project's
//   .claude/settings.json under the key "otlcGuardian":
//
//     {
//       "otlcGuardian": {
//         "watchPaths": ["src/prompts/", ".myplanning/"],
//         "ignorePaths": ["docs/security-spec.md"],
//         "extendDefaults": true
//       }
//     }
//
//   When `extendDefaults` is true (default), the user's watchPaths are
//   added to Guardian's default list. Set to false to fully replace it.
//
//   Files containing the marker `otlc-guardian:doc` (anywhere in the
//   first 4 KB) are treated as documentation about injection attacks
//   and exempted from scanning. Use this in security specs and tests.
// ============================================================

import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// SCANNER IMPORT — single source of truth (1.3.1)
// ---------------------------------------------------------------------------
//
// The hook lives at <project>/.claude/hooks/injection-guard-hook.mjs and
// the scanner lives at <project>/security/01-injection-guard.js. Resolve
// the path relative to this file so the import works no matter what cwd
// Claude Code launched the hook from.
//
// We import dynamically + defensively: if the security module is missing
// (e.g. during a partial install), we exit cleanly instead of blocking
// the user's tool call.
//
// Pre-1.3.1 the hook only imported the raw INJECTION_PATTERNS array and
// ran each regex against the input directly. That bypassed the runtime
// guard's NFKC normalization, URL-decode, and base64-decode steps —
// meaning a fullwidth-Unicode or %-encoded payload would slip past the
// hook even though `guardInput()` (or any direct `scan()` call from the
// user's app) would have caught it. Hook/runtime parity is now enforced
// by importing the public `scan()` function and calling it directly.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const guardModulePath = path.resolve(__dirname, "..", "..", "security", "01-injection-guard.js");

let scan = null;

try {
  if (existsSync(guardModulePath)) {
    const mod = await import(pathToFileURL(guardModulePath).href);
    scan = typeof mod.scan === "function" ? mod.scan : null;
  }
} catch {
  // Hook never blocks on its own failures.
  process.exit(0);
}

// If the main module is missing or `scan` isn't exported (older Guardian
// install), exit silently — the runtime guards in security/* are the
// primary defense; the hook is advisory.
if (!scan) process.exit(0);

// ---------------------------------------------------------------------------
// DEFAULT WATCH LIST
// ---------------------------------------------------------------------------
//
// Anything that ends up loaded into a future Claude session as
// instructions, memory, or research deserves a scan. The defaults below
// cover the major coding-agent ecosystems and the common planning/memory
// conventions. Users add their own paths via settings.json.

const DEFAULT_WATCH_DIR_PATTERNS = [
  // Planning & GSD
  ".planning/",
  ".gsd/",
  ".plans/",
  // Coding-agent state
  ".claude/",
  ".cursor/",
  ".continue/",
  ".aider/",
  ".windsurf/",
  // Memory directories — auto-memory and other persistent context stores
  "/memory/",
];

const DEFAULT_WATCH_FILE_PATTERNS = [
  // Cross-agent instruction files
  /(?:^|\/)CLAUDE\.md$/i,
  /(?:^|\/)AGENTS\.md$/i,
  /(?:^|\/)GEMINI\.md$/i,
  /(?:^|\/)\.cursorrules$/i,
  /(?:^|\/)\.windsurfrules$/i,
  /(?:^|\/)\.aider\.conf\.ya?ml$/i,
  /(?:^|\/)copilot-instructions\.md$/i,
  // Environment / secrets — always worth scanning for embedded payloads
  /(?:^|\/)\.env(?:\..+)?$/i,
  // Memory index used by the auto-memory system
  /(?:^|\/)MEMORY\.md$/i,
];

// ---------------------------------------------------------------------------
// SETTINGS LOADER — reads .claude/settings.json otlcGuardian config block
// ---------------------------------------------------------------------------

function loadSettings(projectRoot) {
  const settingsPath = path.join(projectRoot, ".claude", "settings.json");
  if (!existsSync(settingsPath)) return {};
  try {
    const raw = readFileSync(settingsPath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed.otlcGuardian ?? {};
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// PATH MATCHING
// ---------------------------------------------------------------------------

function isWatchedPath(filePath, settings) {
  const normalized = filePath.replace(/\\/g, "/");

  // Custom watchPaths (always checked).
  //
  // Both `normalized` and `normP` have already had Windows backslashes
  // converted to forward slashes, so testing `normP.endsWith("\\")`
  // after normalization can never be true and was dead code in prior
  // releases. On Windows this meant a user who set
  //   watchPaths: [".myplanning\\"]
  // would have their trailing slash stripped to `.myplanning` and fall
  // into the "file basename" branch below instead of the "directory
  // prefix" branch — so the custom directory was silently not watched.
  // Fixed in 1.1.1: strip any trailing separator before classification
  // and key off whether the user wrote a slash/backslash at all.
  const customDirs = Array.isArray(settings.watchPaths) ? settings.watchPaths : [];
  for (const raw of customDirs) {
    const trimmed = raw.replace(/[\\/]+$/, "");
    const isDirStyle = /[\\/]/.test(raw); // user intended a directory if they wrote any separator
    const normP = trimmed.replace(/\\/g, "/");
    if (isDirStyle) {
      // Directory match: watch anything containing this path segment.
      if (normalized.includes(`${normP}/`) || normalized.endsWith(normP)) return true;
    } else if (normalized.endsWith(normP) || normalized.includes(`/${normP}/`) || normalized.includes(`/${normP}`)) {
      // File-basename match.
      return true;
    }
  }

  // If extendDefaults is explicitly false, only honor custom paths
  if (settings.extendDefaults === false) return false;

  // Default directory patterns
  for (const dir of DEFAULT_WATCH_DIR_PATTERNS) {
    if (normalized.includes(dir)) return true;
  }
  // Default file patterns
  for (const re of DEFAULT_WATCH_FILE_PATTERNS) {
    if (re.test(normalized)) return true;
  }
  return false;
}

function isIgnoredPath(filePath, settings) {
  const normalized = filePath.replace(/\\/g, "/");
  const ignored = Array.isArray(settings.ignorePaths) ? settings.ignorePaths : [];
  for (const p of ignored) {
    const normP = p.replace(/\\/g, "/");
    if (normalized.includes(normP)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// SCAN EXEMPT MARKER
// ---------------------------------------------------------------------------
//
// Files that document injection patterns (security specs, tests, this
// hook itself) need a way to opt out of scanning without weakening the
// patterns. The marker is checked in:
//   1. The new content being written (so the user can mark a file as
//      doc-only on first write)
//   2. The first 4 KB of the existing file on disk, if any (so previously
//      marked files stay exempt across edits)

const SCAN_EXEMPT_MARKER = "otlc-guardian:doc";

function isExempt(filePath, newContent) {
  if (newContent && newContent.includes(SCAN_EXEMPT_MARKER)) return true;
  if (existsSync(filePath)) {
    try {
      const head = readFileSync(filePath, "utf8").slice(0, 4096);
      if (head.includes(SCAN_EXEMPT_MARKER)) return true;
    } catch { /* unreadable — fall through and scan */ }
  }
  return false;
}

// ---------------------------------------------------------------------------
// SCANNER WRAPPER
// ---------------------------------------------------------------------------
//
// Delegates to the imported `scan()` function so the hook gets the
// runtime guard's full bypass-defense stack: NFKC normalization,
// invisible-Unicode stripping, URL-decode, base64-decode, and the
// MAX_SCAN_LENGTH cap. Returns the violations in the simpler shape
// the hook's downstream warning formatter expects.

function scanContent(text) {
  const { violations } = scan(text, "injection");
  return violations.map((v) => ({
    id:       v.id,
    severity: v.severity,
    matched:  v.matched,
  }));
}

// ---------------------------------------------------------------------------
// STDIN READER + MAIN
// ---------------------------------------------------------------------------

let input = "";
const stdinTimeout = setTimeout(() => process.exit(0), 5000);

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  clearTimeout(stdinTimeout);

  try {
    const data     = JSON.parse(input);
    const toolName = data.tool_name;

    if (toolName !== "Write" && toolName !== "Edit") process.exit(0);

    const filePath = data.tool_input?.file_path ?? "";
    if (!filePath) process.exit(0);

    // Project root: derived from cwd, which Claude Code sets to the
    // workspace root before invoking hooks.
    const projectRoot = process.cwd();
    const settings = loadSettings(projectRoot);

    if (isIgnoredPath(filePath, settings)) process.exit(0);
    if (!isWatchedPath(filePath, settings)) process.exit(0);

    const newContent = data.tool_input?.content ?? data.tool_input?.new_string ?? "";
    const oldContent = data.tool_input?.old_string ?? "";

    if (isExempt(filePath, newContent)) process.exit(0);

    const combined = `${newContent}\n${oldContent}`;
    if (!combined.trim()) process.exit(0);

    const findings = scanContent(combined);
    if (findings.length === 0) process.exit(0);

    // ---------------------------------------------------------------------
    // ADVISORY WARNING — never blocks
    // ---------------------------------------------------------------------

    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount     = findings.filter((f) => f.severity === "HIGH").length;
    const detailLines   = findings
      .map((f) => `[${f.severity}] ${f.id} — matched: "${String(f.matched).slice(0, 60)}"`)
      .join(" | ");

    const output = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext:
          `⚠️  [OTLC GUARDIAN] PROMPT INJECTION WARNING\n` +
          `    File     : ${filePath}\n` +
          `    Patterns : ${findings.length} matched (${criticalCount} CRITICAL, ${highCount} HIGH)\n` +
          `    Details  : ${detailLines}\n` +
          `    Action   : Advisory only — operation will proceed.\n` +
          `    Note     : If this content is legitimate documentation about\n` +
          `               prompt injection, add the marker '${SCAN_EXEMPT_MARKER}'\n` +
          `               anywhere in the file to silence this warning.`,
      },
    };

    process.stdout.write(JSON.stringify(output));
  } catch {
    // Never block tool execution on guard error.
    process.exit(0);
  }
});
