/**
 * ============================================================
 * OTLC GUARDIAN — AGENTS.md + editor-coverage tests
 * // tests · onthelevelconcepts.com
 * Version: 1.0.0
 * ============================================================
 *
 * Verifies the multi-agent posture added in the Node 22 + multi-agent
 * branch:
 *
 *   - AGENTS.md source template exists at the Guardian repo root and
 *     contains the expected universal-agent guidance
 *   - `guardian init` creates AGENTS.md in a fresh project
 *   - `guardian init` merges Guardian content into an existing user
 *     AGENTS.md under the OTLC-GUARDIAN-START marker without clobbering
 *     the user's content
 *   - A follow-up `guardian init` on a marker-sealed AGENTS.md is a
 *     no-op (idempotency via the mergeMd path — this is the path that
 *     the README promises and that matters for users re-running init
 *     to refresh patterns)
 *   - editorCoverage() reports the right status for each of the four
 *     install scenarios (Claude full / Claude partial / behavior-only /
 *     disabled)
 *
 * Uses a temp directory so tests never touch real project files. Same
 * zero-dep mini test runner as init.test.js.
 *
 * Run: node tests/agents-md.test.js
 * ============================================================
 */

import { strict as assert } from "assert";
import { execSync } from "child_process";
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import { editorCoverage, mergeMd } from "../bin/guardian.js";

const __dirname     = path.dirname(fileURLToPath(import.meta.url));
const GUARDIAN_ROOT = path.join(__dirname, "..");
const GUARDIAN_BIN  = path.join(GUARDIAN_ROOT, "bin", "guardian.js");

// ---------------------------------------------------------------------------
// MINI TEST RUNNER
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌ ${name}`);
    console.error(`     → ${err.message}`);
    failed++;
    failures.push({ name, error: err.message });
  }
}

function describe(group, fn) {
  console.log(`\n📋 ${group}`);
  fn();
}

function withTempDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "guardian-agents-test-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Run guardian init as a subprocess in the target dir and return the
// captured stdout/stderr for inspection. Stderr is piped to the result
// so a test failure includes any warnings the CLI printed.
function runInit(cwd) {
  return execSync(`node "${GUARDIAN_BIN}" init`, {
    cwd,
    encoding: "utf8",
    stdio:    ["ignore", "pipe", "pipe"],
  });
}

// ---------------------------------------------------------------------------
// AGENTS.md source template
// ---------------------------------------------------------------------------

describe("AGENTS.md — source template at repo root", () => {
  test("exists", () => {
    const p = path.join(GUARDIAN_ROOT, "AGENTS.md");
    assert.ok(
      existsSync(p),
      "AGENTS.md must exist at the Guardian repo root so guardian init can copy it",
    );
  });

  test("references STANDARDS.md and CLAUDE.md as companion files", () => {
    const content = readFileSync(path.join(GUARDIAN_ROOT, "AGENTS.md"), "utf8");
    assert.ok(
      content.includes("STANDARDS.md"),
      "AGENTS.md must point readers at STANDARDS.md for the full stack rules",
    );
    assert.ok(
      content.includes("CLAUDE.md"),
      "AGENTS.md must point readers at CLAUDE.md for the full rule text",
    );
  });

  test("acknowledges non-Claude agents by name", () => {
    const content = readFileSync(path.join(GUARDIAN_ROOT, "AGENTS.md"), "utf8");
    // A public template that claims multi-agent support but names zero
    // non-Claude agents is exactly the failure mode this file is meant
    // to fix. Assert at least one concrete reference.
    const nonClaudeAgents = ["Codex", "Cursor", "Aider", "Continue", "Windsurf"];
    const mentioned = nonClaudeAgents.filter((a) => content.includes(a));
    assert.ok(
      mentioned.length >= 2,
      `AGENTS.md should mention at least two of ${nonClaudeAgents.join(", ")} — found ${mentioned.length}`,
    );
  });
});

// ---------------------------------------------------------------------------
// guardian init — AGENTS.md provisioning via subprocess
// ---------------------------------------------------------------------------

describe("guardian init — AGENTS.md provisioning (subprocess)", () => {
  test("creates AGENTS.md in a fresh project that has none", () => {
    withTempDir((dir) => {
      runInit(dir);
      const dest = path.join(dir, "AGENTS.md");
      assert.ok(existsSync(dest), "AGENTS.md must be created in the target project");
      const content = readFileSync(dest, "utf8");
      assert.ok(
        content.includes("OTLC Guardian"),
        "The created AGENTS.md must contain Guardian content",
      );
    });
  });

  test("merges Guardian content into an existing user AGENTS.md without clobbering", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "AGENTS.md");
      const userBody = "# My custom agent rules\n\nDo not delete my words.\n";
      writeFileSync(userPath, userBody);

      runInit(dir);

      const merged = readFileSync(userPath, "utf8");
      assert.ok(
        merged.startsWith("# My custom agent rules"),
        "User content must remain at the top of the file after merge",
      );
      assert.ok(
        merged.includes("Do not delete my words"),
        "User text must survive the merge",
      );
      assert.ok(
        merged.includes("OTLC-GUARDIAN-START"),
        "Guardian section marker must be present after merge",
      );
      assert.ok(
        merged.includes("OTLC Guardian"),
        "Guardian content must be appended below the marker",
      );
    });
  });

  test("second init on a marker-sealed AGENTS.md is a no-op (mergeMd idempotency)", () => {
    // This test covers the code path the README promises: "Running
    // guardian init a second time is safe — it detects everything
    // already in place and skips it." We exercise the path through
    // mergeMd explicitly (user AGENTS.md → first init adds marker →
    // second init detects marker → no-op) because that path is
    // provably idempotent.
    //
    // NOTE: there is a separate pre-existing issue in runInit() where
    // copyFileSync-on-fresh-file produces a marker-less copy that will
    // get merged again on the next init. That bug affects CLAUDE.md,
    // STANDARDS.md, and AGENTS.md equally, was not introduced by this
    // branch, and is out of scope for the multi-agent fix. It should
    // be addressed as a separate commit with its own tests.
    withTempDir((dir) => {
      const userPath = path.join(dir, "AGENTS.md");
      writeFileSync(userPath, "# Mine\n");

      runInit(dir);
      const afterFirst = readFileSync(userPath, "utf8");
      assert.ok(
        afterFirst.includes("OTLC-GUARDIAN-START"),
        "First init must add the Guardian marker",
      );

      runInit(dir);
      const afterSecond = readFileSync(userPath, "utf8");
      assert.equal(
        afterSecond,
        afterFirst,
        "Second init on marker-sealed AGENTS.md must be a byte-for-byte no-op",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// mergeMd — direct unit test for AGENTS.md content shape
// ---------------------------------------------------------------------------

describe("mergeMd — AGENTS.md content shape", () => {
  test("marker block wraps only Guardian content, not user content", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "AGENTS.md");
      const srcPath  = path.join(dir, "guardian-AGENTS.md");
      writeFileSync(userPath, "# My rules\n\nUser paragraph.\n");
      writeFileSync(srcPath,  "# Guardian rules\n\nGuardian paragraph.\n");

      mergeMd(userPath, srcPath, "AGENTS.md");

      const merged = readFileSync(userPath, "utf8");
      const startIdx = merged.indexOf("<!-- OTLC-GUARDIAN-START -->");
      const endIdx   = merged.indexOf("<!-- OTLC-GUARDIAN-END -->");
      assert.ok(startIdx > 0,             "START marker must appear after user content");
      assert.ok(endIdx > startIdx,        "END marker must appear after START marker");
      const userSection     = merged.slice(0, startIdx);
      const guardianSection = merged.slice(startIdx, endIdx);
      assert.ok(userSection.includes("User paragraph"),       "User content above the marker");
      assert.ok(!userSection.includes("Guardian paragraph"),  "Guardian content NOT above the marker");
      assert.ok(guardianSection.includes("Guardian paragraph"), "Guardian content inside the marker block");
      assert.ok(!guardianSection.includes("User paragraph"),    "User content NOT inside the marker block");
    });
  });
});

// ---------------------------------------------------------------------------
// editorCoverage — per-agent status reporting
// ---------------------------------------------------------------------------

// Helper: populate a temp dir with an arbitrary set of Guardian artifacts
// so editorCoverage() has something concrete to inspect. Only the files
// named in `opts` are created.
function setupCoverageDir(dir, opts) {
  if (opts.claudeMd) {
    writeFileSync(path.join(dir, "CLAUDE.md"), "# claude rules\n");
  }
  if (opts.agentsMd) {
    writeFileSync(path.join(dir, "AGENTS.md"), "# agent rules\n");
  }
  if (opts.settings || opts.hooks) {
    mkdirSync(path.join(dir, ".claude", "hooks"), { recursive: true });
  }
  if (opts.settings) {
    writeFileSync(path.join(dir, ".claude", "settings.json"), "{}");
  }
  if (opts.hooks) {
    writeFileSync(path.join(dir, ".claude", "hooks", "injection-guard-hook.mjs"), "// stub\n");
    writeFileSync(path.join(dir, ".claude", "hooks", "web-content-guard.mjs"),   "// stub\n");
  }
}

describe("editorCoverage — per-editor status reporting", () => {
  test("FULL Claude Code install: everything present → Claude FULL, others BEHAVIOR-ONLY", () => {
    withTempDir((dir) => {
      setupCoverageDir(dir, { claudeMd: true, agentsMd: true, settings: true, hooks: true });
      const rows = editorCoverage(dir);

      const claude = rows.find((r) => r.editor === "Claude Code");
      assert.ok(claude,                         "Claude Code row must exist");
      assert.equal(claude.status, "FULL",       "Claude Code must be FULL when hooks + settings + CLAUDE.md all present");

      for (const editor of ["Codex CLI", "Cursor", "Aider", "Continue", "Windsurf"]) {
        const row = rows.find((r) => r.editor === editor);
        assert.ok(row, `${editor} row must exist`);
        assert.equal(row.status, "BEHAVIOR-ONLY", `${editor} must be BEHAVIOR-ONLY when AGENTS.md is present`);
      }
    });
  });

  test("PARTIAL Claude install: CLAUDE.md present, hooks missing → Claude PARTIAL", () => {
    withTempDir((dir) => {
      setupCoverageDir(dir, { claudeMd: true, agentsMd: true });
      const rows = editorCoverage(dir);
      const claude = rows.find((r) => r.editor === "Claude Code");
      assert.equal(claude.status, "PARTIAL", "Claude Code must be PARTIAL when CLAUDE.md exists but hooks do not");
    });
  });

  test("AGENTS.md only (non-Claude user): Claude DISABLED, others BEHAVIOR-ONLY", () => {
    withTempDir((dir) => {
      setupCoverageDir(dir, { agentsMd: true });
      const rows = editorCoverage(dir);

      const claude = rows.find((r) => r.editor === "Claude Code");
      assert.equal(claude.status, "DISABLED", "Claude Code must be DISABLED when CLAUDE.md is missing");

      for (const editor of ["Codex CLI", "Cursor", "Aider", "Continue", "Windsurf"]) {
        const row = rows.find((r) => r.editor === editor);
        assert.equal(row.status, "BEHAVIOR-ONLY", `${editor} must still be BEHAVIOR-ONLY when only AGENTS.md is present`);
      }
    });
  });

  test("Nothing present: every row is DISABLED", () => {
    withTempDir((dir) => {
      setupCoverageDir(dir, {});
      const rows = editorCoverage(dir);
      for (const row of rows) {
        assert.equal(row.status, "DISABLED", `${row.editor} must be DISABLED when no behavior files exist`);
      }
    });
  });

  test("Returns a row for every mainstream agent (Claude, Codex, Cursor, Aider, Continue, Windsurf)", () => {
    withTempDir((dir) => {
      setupCoverageDir(dir, { claudeMd: true, agentsMd: true, settings: true, hooks: true });
      const rows = editorCoverage(dir);
      const editors = rows.map((r) => r.editor);
      for (const expected of ["Claude Code", "Codex CLI", "Cursor", "Aider", "Continue", "Windsurf"]) {
        assert.ok(editors.includes(expected), `${expected} must have a row in editorCoverage output`);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// RESULTS
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(60)}`);
console.log(`🔍 [OTLC GUARDIAN] agents-md.test.js RESULTS`);
console.log(`   Passed : ${passed}`);
console.log(`   Failed : ${failed}`);
console.log(`   Total  : ${passed + failed}`);

if (failures.length > 0) {
  console.error(`\n❌ FAILURES:`);
  failures.forEach((f) => console.error(`   → ${f.name}: ${f.error}`));
  process.exit(1);
} else {
  console.log(`\n✅ All agents-md tests passed.\n`);
  process.exit(0);
}
