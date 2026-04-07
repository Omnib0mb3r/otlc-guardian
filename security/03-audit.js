#!/usr/bin/env node
/**
 * ============================================================
 * OTLC GUARDIAN — Safety Audit Tool
 * // security · onthelevelconcepts.com
 * Version: 1.1.0
 * ============================================================
 *
 * Scans an existing codebase for security and quality violations.
 * Run against any project before go-live or during code review.
 *
 * Usage:
 *   node security/03-audit.js                  # audit current directory
 *   node security/03-audit.js ./src            # audit specific path
 *   node security/03-audit.js --json           # output as JSON
 *   node security/03-audit.js --fail-on-error  # exit code 1 if issues found
 *
 * Note: this file is exempted from auditing via the central allowlist
 * at security/.audit-allowlist because its pattern definitions
 * (e.g. /eval\s*\(/) would otherwise match themselves when the audit
 * is run against the Guardian repo. End-user projects can use either
 * the allowlist or the per-file `otlc-guardian:audit-exempt` marker.
 *
 * ============================================================
 */

import fs   from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// AUDIT RULES
// Each rule: { id, category, severity, description, pattern, fileTypes }
// ---------------------------------------------------------------------------

const AUDIT_RULES = [
  // --- SECRETS ---
  {
    id: "SEC-001", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded OpenAI API key",
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    fileTypes: [".js", ".ts", ".py", ".env", ".json", ".yaml", ".yml"],
  },
  {
    id: "SEC-002", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/,
    fileTypes: [".js", ".ts", ".py", ".env", ".json", ".yaml", ".yml"],
  },
  {
    id: "SEC-003", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded GitHub token",
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    fileTypes: [".js", ".ts", ".py", ".env", ".json"],
  },
  {
    id: "SEC-004", category: "Secrets", severity: "CRITICAL",
    description: "Private key embedded in code",
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    fileTypes: [".js", ".ts", ".py", ".json", ".env"],
  },
  {
    id: "SEC-005", category: "Secrets", severity: "HIGH",
    description: "Inline password assignment",
    pattern: /password\s*[:=]\s*["'][^"']{6,}["']/i,
    fileTypes: [".js", ".ts", ".py", ".json", ".yaml", ".yml"],
  },
  {
    id: "SEC-006", category: "Secrets", severity: "HIGH",
    description: "Hardcoded API key assignment",
    pattern: /api[_-]?key\s*[:=]\s*["'][^"']{8,}["']/i,
    fileTypes: [".js", ".ts", ".py", ".json", ".yaml", ".yml"],
  },

  // --- HARDCODED CONFIG ---
  {
    id: "CFG-001", category: "Configuration", severity: "HIGH",
    description: "Hardcoded localhost URL",
    pattern: /["'`]https?:\/\/localhost:\d+/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx", ".py"],
  },
  {
    id: "CFG-002", category: "Configuration", severity: "HIGH",
    description: "Hardcoded 127.0.0.1 address",
    pattern: /["'`]https?:\/\/127\.0\.0\.1/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx", ".py"],
  },
  {
    id: "CFG-003", category: "Configuration", severity: "MEDIUM",
    description: "Hardcoded IP address (potential config leak)",
    pattern: /["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx", ".py"],
  },

  // --- ERROR HANDLING ---
  {
    id: "ERR-001", category: "Error Handling", severity: "HIGH",
    description: "Silent catch block — swallows errors with no handling",
    pattern: /catch\s*\([^)]*\)\s*\{\s*\}/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
  },
  {
    id: "ERR-002", category: "Error Handling", severity: "HIGH",
    description: "catch block with only console.log — not structured logging",
    pattern: /catch\s*\([^)]*\)\s*\{\s*console\.log/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
  },
  {
    id: "ERR-003", category: "Error Handling", severity: "MEDIUM",
    description: "console.log() in non-test code — use structured logger",
    pattern: /console\.log\(/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
    excludePatterns: [/\.test\./, /\.spec\./, /test\//, /spec\//],
  },

  // --- API DESIGN ---
  {
    id: "API-001", category: "API Design", severity: "MEDIUM",
    description: "API route without version prefix (/api/v1/...)",
    pattern: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`]\/api\/(?!v\d)/,
    fileTypes: [".js", ".ts"],
  },

  // --- SECURITY PATTERNS ---
  {
    id: "INJ-001", category: "Injection Risk", severity: "CRITICAL",
    description: "Direct user input passed to eval()",
    pattern: /eval\s*\(/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
  },
  {
    id: "INJ-002", category: "Injection Risk", severity: "HIGH",
    description: "innerHTML assignment — potential XSS",
    pattern: /\.innerHTML\s*=/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
  },
  {
    id: "INJ-003", category: "Injection Risk", severity: "HIGH",
    description: "dangerouslySetInnerHTML — potential XSS (ensure sanitized)",
    pattern: /dangerouslySetInnerHTML/,
    fileTypes: [".js", ".ts", ".jsx", ".tsx"],
  },

  // --- DEPLOYMENT ---
  {
    id: "DEP-001", category: "Deployment", severity: "MEDIUM",
    description: "No health check endpoint found",
    pattern: null, // checked separately
    fileTypes: [],
    checkFn: (files) => !files.some((f) => /health/.test(fs.readFileSync(f, "utf8").toLowerCase())),
  },
  {
    id: "DEP-002", category: "Deployment", severity: "LOW",
    description: ".env file present — should not be committed",
    pattern: null,
    fileTypes: [],
    checkFn: (files) => files.some((f) => path.basename(f) === ".env"),
  },

  // --- TYPESCRIPT ---
  {
    id: "TS-001", category: "TypeScript", severity: "LOW",
    description: "Use of 'any' type — reduces type safety",
    pattern: /:\s*any(?:\s|;|,|\)|\[)/,
    fileTypes: [".ts", ".tsx"],
  },
];

// ---------------------------------------------------------------------------
// FILE SCANNER
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "__pycache__",
  ".venv", "venv", "coverage", ".cache",
]);

function collectFiles(rootDir, extensions) {
  const results = [];

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.length === 0 || extensions.includes(ext)) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(rootDir);
  return results;
}

// ---------------------------------------------------------------------------
// EXEMPTION MECHANISMS
// ---------------------------------------------------------------------------
//
// Two ways to exempt a file from audit scanning, both visible to reviewers:
//
//   1. PER-FILE MARKER (otlc-guardian:audit-exempt)
//      A file containing this string in its first 4 KB is skipped. Easy
//      for end users — drop the marker into a file header comment and
//      you're done. Greppable in any code review.
//
//   2. CENTRAL ALLOWLIST (security/.audit-allowlist)
//      A single file listing each exempted path with a required reason.
//      Used by the Guardian repo itself. Every addition is a one-line
//      diff in PR review, and the reason field forces the contributor
//      to justify the exemption. CODEOWNERS can require security-team
//      approval for any change to the allowlist file.
//
// Both mechanisms are tracked separately in the audit summary so you
// always know how many files were skipped and via which mechanism.
// Visibility is the strongest defense against the exemption being abused.

const AUDIT_EXEMPT_MARKER = "otlc-guardian:audit-exempt";

/**
 * Load the central allowlist from security/.audit-allowlist if present.
 * Returns a Map of normalized-path -> reason. Lines without a reason are
 * rejected loudly so silent additions cannot slip past CI.
 */
function loadAllowlist(rootDir) {
  const allowlistPath = path.join(rootDir, "security", ".audit-allowlist");
  const allowlist = new Map();

  if (!fs.existsSync(allowlistPath)) return allowlist;

  let content;
  try { content = fs.readFileSync(allowlistPath, "utf8"); }
  catch { return allowlist; }

  const lines = content.split("\n");
  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;

    // Format:  <path>  # reason: <text>
    const hashIdx = line.indexOf("#");
    if (hashIdx === -1) {
      console.warn(`⚠️  [OTLC GUARDIAN] .audit-allowlist:${idx + 1} — missing reason, line ignored`);
      return;
    }

    const filePart   = line.slice(0, hashIdx).trim();
    const reasonPart = line.slice(hashIdx + 1).trim();

    if (!filePart) return;
    if (!/^reason:/i.test(reasonPart)) {
      console.warn(`⚠️  [OTLC GUARDIAN] .audit-allowlist:${idx + 1} — reason must start with "reason:", line ignored`);
      return;
    }

    // Normalize path separators so Windows backslashes match Unix forward slashes
    const normalized = filePart.replace(/\\/g, "/");
    allowlist.set(normalized, reasonPart.replace(/^reason:\s*/i, ""));
  });

  return allowlist;
}

/**
 * Check whether a file is exempted by either mechanism. Returns the
 * mechanism name ("marker" | "allowlist") or null. We expose this so
 * the audit summary can report counts and the list of skipped files.
 *
 * Allowlist is checked FIRST so a file that appears in both
 * security/.audit-allowlist and contains the marker string in its
 * source (e.g. documentation about how the marker works) is reported
 * via the more-reviewable mechanism.
 */
function exemptionMechanism(filePath, content, allowlist, rootDir) {
  // Allowlist check first — more reviewable, takes precedence
  const rel = path.relative(rootDir, filePath).replace(/\\/g, "/");
  if (allowlist.has(rel)) return "allowlist";

  // Marker fallback — for end-user projects that prefer per-file headers
  if (content.slice(0, 4096).includes(AUDIT_EXEMPT_MARKER)) return "marker";

  return null;
}

function scanFile(filePath, rule, exemptionState) {
  if (!rule.pattern) return [];

  let content;
  try { content = fs.readFileSync(filePath, "utf8"); }
  catch { return []; }

  // Whole-file exemption — handled outside per-rule logic so the same
  // file isn't checked once per rule. State is precomputed in runAudit.
  if (exemptionState?.exemptPaths?.has(filePath)) return [];

  // Per-rule exclude patterns (e.g. ERR-003 already excludes *.test.*)
  if (rule.excludePatterns?.some((ep) => ep.test(filePath))) return [];

  const findings = [];
  const lines    = content.split("\n");

  lines.forEach((line, index) => {
    if (rule.pattern.test(line)) {
      findings.push({
        file:    filePath,
        line:    index + 1,
        content: line.trim().slice(0, 120), // truncate long lines
        rule,
      });
    }
  });

  return findings;
}

// ---------------------------------------------------------------------------
// MAIN AUDIT RUNNER
// ---------------------------------------------------------------------------

function runAudit(targetDir, options = {}) {
  const { outputJson = false, failOnError = false } = options;
  const rootDir = path.resolve(targetDir);

  // Status output routing: in JSON mode, status lines go to stderr so
  // the consumer of stdout (e.g. `node ... --json > out.json` in CI)
  // gets clean parseable JSON. In human mode, status lines go to stdout
  // alongside the human-readable report. This is the standard Unix
  // convention — diagnostic stream vs result stream — and it fixes the
  // CI bug where the JSON file was getting "🔍 SAFETY AUDIT STARTING"
  // text prepended to the actual JSON object.
  const status = outputJson
    ? (msg) => process.stderr.write(msg + "\n")
    : (msg) => process.stdout.write(msg + "\n");

  status(`\n🔍 [OTLC GUARDIAN] SAFETY AUDIT STARTING`);
  status(`    Target  : ${rootDir}`);
  status(`    Rules   : ${AUDIT_RULES.filter((r) => r.pattern).length} pattern rules`);

  // ── Load exemption state once, up front ──────────────────────────────
  const allowlist = loadAllowlist(rootDir);

  // Collect all relevant files
  const allExtensions = [...new Set(AUDIT_RULES.flatMap((r) => r.fileTypes))];
  const files         = collectFiles(rootDir, allExtensions);

  // Precompute which files are exempt and via which mechanism. We do
  // this once here instead of inside scanFile so the same file isn't
  // re-checked once per rule, and so the audit summary can report
  // exemption counts up front.
  const exemptPaths     = new Set();
  const exemptByMarker  = [];
  const exemptByList    = [];

  for (const file of files) {
    let head;
    try { head = fs.readFileSync(file, "utf8"); }
    catch { continue; }
    const mech = exemptionMechanism(file, head, allowlist, rootDir);
    if (mech === "marker") {
      exemptPaths.add(file);
      exemptByMarker.push(path.relative(rootDir, file).replace(/\\/g, "/"));
    } else if (mech === "allowlist") {
      exemptPaths.add(file);
      exemptByList.push(path.relative(rootDir, file).replace(/\\/g, "/"));
    }
  }

  const exemptionState = { exemptPaths };

  status(`    Files   : ${files.length} scanned`);
  status(`    Exempt  : ${exemptPaths.size} (${exemptByMarker.length} marker, ${exemptByList.length} allowlist)`);

  // Visibility: print the exempt list every run, not just on issues.
  // If this list grows unexpectedly, you see it immediately.
  if (exemptPaths.size > 0) {
    if (exemptByMarker.length > 0) {
      status(`    [marker] ${exemptByMarker.join(", ")}`);
    }
    if (exemptByList.length > 0) {
      status(`    [allowlist] ${exemptByList.join(", ")}`);
    }
  }
  status("");

  const allFindings = [];

  // Pattern-based rules
  for (const rule of AUDIT_RULES) {
    if (!rule.pattern) continue;

    const relevantFiles = files.filter((f) =>
      rule.fileTypes.length === 0 || rule.fileTypes.includes(path.extname(f).toLowerCase())
    );

    for (const file of relevantFiles) {
      const findings = scanFile(file, rule, exemptionState);
      allFindings.push(...findings);
    }
  }

  // Function-based rules
  for (const rule of AUDIT_RULES) {
    if (!rule.checkFn) continue;
    const triggered = rule.checkFn(files);
    if (triggered) {
      allFindings.push({ file: targetDir, line: null, content: null, rule });
    }
  }

  // ---------------------------------------------------------------------------
  // REPORT OUTPUT
  // ---------------------------------------------------------------------------

  if (outputJson) {
    console.log(JSON.stringify({
      findings: allFindings,
      total:    allFindings.length,
      exempt:   {
        total:     exemptPaths.size,
        marker:    exemptByMarker,
        allowlist: exemptByList,
      },
    }, null, 2));
  } else {
    const bySeverity = {
      CRITICAL: allFindings.filter((f) => f.rule.severity === "CRITICAL"),
      HIGH:     allFindings.filter((f) => f.rule.severity === "HIGH"),
      MEDIUM:   allFindings.filter((f) => f.rule.severity === "MEDIUM"),
      LOW:      allFindings.filter((f) => f.rule.severity === "LOW"),
    };

    if (allFindings.length === 0) {
      console.info(`✅ [OTLC GUARDIAN] AUDIT COMPLETE — No issues found.\n`);
    } else {
      console.warn(`⚠️  [OTLC GUARDIAN] AUDIT COMPLETE — ${allFindings.length} issue(s) found\n`);

      for (const [severity, findings] of Object.entries(bySeverity)) {
        if (findings.length === 0) continue;
        const icon = severity === "CRITICAL" ? "🚨" : severity === "HIGH" ? "⚠️ " : severity === "MEDIUM" ? "🔶" : "🔵";
        console.warn(`${icon} ${severity} (${findings.length})`);
        findings.forEach((f) => {
          const loc = f.line ? `${f.file}:${f.line}` : f.file;
          console.warn(`   [${f.rule.id}] ${f.rule.description}`);
          console.warn(`   → ${loc}`);
          if (f.content) console.warn(`   → ${f.content}\n`);
        });
      }

      console.warn(`\n   Summary:`);
      console.warn(`   CRITICAL : ${bySeverity.CRITICAL.length}`);
      console.warn(`   HIGH     : ${bySeverity.HIGH.length}`);
      console.warn(`   MEDIUM   : ${bySeverity.MEDIUM.length}`);
      console.warn(`   LOW      : ${bySeverity.LOW.length}\n`);
    }
  }

  if (failOnError && allFindings.some((f) => ["CRITICAL", "HIGH"].includes(f.rule.severity))) {
    process.exit(1);
  }

  return allFindings;
}

// ---------------------------------------------------------------------------
// CLI ENTRY POINT
// ---------------------------------------------------------------------------

const args        = process.argv.slice(2);
const targetDir   = args.find((a) => !a.startsWith("--")) ?? ".";
const outputJson  = args.includes("--json");
const failOnError = args.includes("--fail-on-error");

runAudit(targetDir, { outputJson, failOnError });

export { runAudit, AUDIT_RULES };
