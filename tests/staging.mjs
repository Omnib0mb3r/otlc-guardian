/**
 * ============================================================
 * OTLC GUARDIAN - Staged enforcement test runner
 * // tests · onthelevelconcepts.com
 * Version: 1.5.0
 * ============================================================
 *
 * Runs the hook and scanner suites against the candidate next versions
 * of Guardian's protected files in staging/ instead of the live ones.
 * staging/ holds them flat (hooks/, security/) so no staged file sits on
 * a path the live hook watches; this runner lays them out like an
 * install in a temporary folder, because the hook loads the scanner from
 * ../../security relative to itself, and points GUARDIAN_ENFORCEMENT_ROOT
 * at it.
 *
 * Exit code: 0 when every suite passes, 1 when any fails or staging/ is
 * incomplete.
 *
 * Run: npm run test:staging
 * ============================================================
 */

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT    = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STAGING = path.join(ROOT, "staging");

// staged file -> its place in an install
const LAYOUT = [
  ["hooks/injection-guard-hook.mjs", ".claude/hooks/injection-guard-hook.mjs"],
  ["hooks/web-content-guard.mjs",    ".claude/hooks/web-content-guard.mjs"],
  ["security/01-injection-guard.js", "security/01-injection-guard.js"],
];
const SUITES = ["tests/injection-guard.test.js", "tests/hook.test.js"];

const missing = LAYOUT.map(([from]) => from).filter((f) => !existsSync(path.join(STAGING, f)));
if (missing.length > 0) {
  process.stderr.write(`[OTLC GUARDIAN] staging/ is incomplete, missing: ${missing.join(", ")}\n`);
  process.exit(1);
}

const install = mkdtempSync(path.join(os.tmpdir(), "guardian-staging-"));
let failedSuites = 0;
try {
  for (const [from, to] of LAYOUT) {
    mkdirSync(path.dirname(path.join(install, to)), { recursive: true });
    copyFileSync(path.join(STAGING, from), path.join(install, to));
  }
  // Not a protected file, so it is not staged: the live copy pins the
  // staged scanner to ES modules the way an install does (BUG-063).
  copyFileSync(path.join(ROOT, "security", "package.json"), path.join(install, "security", "package.json"));

  process.stdout.write(`[OTLC GUARDIAN] testing the STAGED enforcement files from ${STAGING} (not the live ones)\n`);
  for (const suite of SUITES) {
    const result = spawnSync(process.execPath, [path.join(ROOT, suite)], {
      cwd:   ROOT,
      stdio: "inherit",
      env:   { ...process.env, GUARDIAN_ENFORCEMENT_ROOT: install },
    });
    if (result.status !== 0) {
      failedSuites++;
      process.stderr.write(`[OTLC GUARDIAN] staged run of ${suite} failed (exit ${result.status ?? result.signal})\n`);
    }
  }
} finally {
  rmSync(install, { recursive: true, force: true });
}
process.stdout.write(`[OTLC GUARDIAN] staged suites: ${SUITES.length - failedSuites} passed, ${failedSuites} failed\n`);
process.exit(failedSuites > 0 ? 1 : 0);
