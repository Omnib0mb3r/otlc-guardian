#!/usr/bin/env node
// ============================================================
// OTLC GUARDIAN — Claude Code PreToolUse Hook
// // security · onthelevelconcepts.com
// Version: 1.0.0
// ============================================================
//
// Scans file content being written to agent context files for
// prompt injection patterns. Defense-in-depth for Claude Code.
//
// Triggers on: Write and Edit tool calls targeting:
//   .planning/, .claude/, CLAUDE.md, any .md in project root
//
// Action: Advisory warning — never blocks (prevents deadlocks)
//
// Install: Reference this file in .claude/settings.json hooks
// ============================================================

const fs   = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// INJECTION PATTERNS — inlined for hook self-containment
// (mirrors security/01-injection-guard.js — keep in sync)
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i,           severity: "CRITICAL", id: "INJ-001" },
  { pattern: /ignore\s+(all\s+)?above\s+instructions/i,              severity: "CRITICAL", id: "INJ-002" },
  { pattern: /disregard\s+(all\s+)?previous/i,                       severity: "CRITICAL", id: "INJ-003" },
  { pattern: /forget\s+(all\s+)?(your\s+)?instructions/i,            severity: "CRITICAL", id: "INJ-004" },
  { pattern: /override\s+(system|previous)\s+(prompt|instructions)/i, severity: "CRITICAL", id: "INJ-005" },
  { pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i,                   severity: "HIGH",     id: "INJ-006" },
  { pattern: /pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)/i,         severity: "HIGH",     id: "INJ-007" },
  { pattern: /from\s+now\s+on,?\s+you\s+(?:are|will|should|must)/i,  severity: "HIGH",     id: "INJ-008" },
  { pattern: /(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i, severity: "HIGH", id: "INJ-009" },
  { pattern: /<\/?(?:system|assistant|human)>/i,                      severity: "CRITICAL", id: "INJ-010" },
  { pattern: /\[SYSTEM\]/i,                                           severity: "CRITICAL", id: "INJ-011" },
  { pattern: /\[INST\]/i,                                             severity: "CRITICAL", id: "INJ-012" },
  { pattern: /<<\s*SYS\s*>>/i,                                        severity: "CRITICAL", id: "INJ-013" },
  { pattern: /###\s*(?:System|Instruction|Prompt)/i,                  severity: "CRITICAL", id: "INJ-014" },
  { pattern: /do\s+anything\s+now/i,                                  severity: "HIGH",     id: "INJ-015" },
  { pattern: /jailbreak/i,                                            severity: "HIGH",     id: "INJ-016" },
  { pattern: /bypass\s+(?:your\s+)?(?:safety|filter|guideline)/i,    severity: "HIGH",     id: "INJ-017" },
];

const INVISIBLE_UNICODE = /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/;

// ---------------------------------------------------------------------------
// WATCHED PATHS — project-relative patterns (portable, no hardcoded paths)
// ---------------------------------------------------------------------------

function isWatchedPath(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return (
    normalized.includes(".planning/")  ||
    normalized.includes(".claude/")    ||
    /(?:^|\/)CLAUDE\.md$/i.test(normalized) ||
    /(?:^|\/)\.env$/i.test(normalized)
  );
}

// ---------------------------------------------------------------------------
// STDIN READER + MAIN LOGIC
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

    // Only scan write operations
    if (toolName !== "Write" && toolName !== "Edit") {
      process.exit(0);
    }

    const filePath = data.tool_input?.file_path ?? "";

    // Only scan watched paths
    if (!isWatchedPath(filePath)) {
      process.exit(0);
    }

    // Get content being written (Write uses content, Edit uses new_string)
    const newContent = data.tool_input?.content ?? data.tool_input?.new_string ?? "";
    const oldContent = data.tool_input?.old_string ?? ""; // also scan replacement targets

    const combined = `${newContent}\n${oldContent}`;
    if (!combined.trim()) process.exit(0);

    // Scan for injection patterns
    const findings = [];

    for (const { pattern, severity, id } of INJECTION_PATTERNS) {
      if (pattern.test(combined)) {
        findings.push({ id, severity, matched: (combined.match(pattern) ?? [""])[0] });
      }
    }

    if (INVISIBLE_UNICODE.test(combined)) {
      findings.push({ id: "INJ-UNICODE", severity: "HIGH", matched: "invisible unicode characters" });
    }

    // Clean exit if nothing found
    if (findings.length === 0) process.exit(0);

    // ---------------------------------------------------------------------------
    // ADVISORY WARNING — does not block the operation
    // ---------------------------------------------------------------------------

    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount     = findings.filter((f) => f.severity === "HIGH").length;
    const fileName      = filePath; // use full path, not basename — avoids ambiguity

    const detailLines = findings
      .map((f) => `[${f.severity}] ${f.id} — matched: "${f.matched.slice(0, 60)}"`)
      .join(" | ");

    const output = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext:
          `⚠️  [OTLC GUARDIAN] PROMPT INJECTION WARNING\n` +
          `    File     : ${fileName}\n` +
          `    Patterns : ${findings.length} matched (${criticalCount} CRITICAL, ${highCount} HIGH)\n` +
          `    Details  : ${detailLines}\n` +
          `    Action   : Advisory only — operation will proceed.\n` +
          `    Note     : If this content is legitimate documentation about injection attacks,\n` +
          `               you may proceed. Otherwise review the content before continuing.`,
      },
    };

    process.stdout.write(JSON.stringify(output));
  } catch {
    // Silent fail — never block tool execution on guard error
    process.exit(0);
  }
});
