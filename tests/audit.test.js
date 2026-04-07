/**
 * ============================================================
 * OTLC GUARDIAN — Audit Rule Tests
 * // tests · onthelevelconcepts.com
 * Version: 1.1.1
 * ============================================================
 *
 * Tests the rule set in security/03-audit.js against fixture files
 * in a temp directory. The audit is run as a subprocess in JSON mode
 * (`--json`) so the output is machine-parseable and we can assert on
 * specific rule IDs rather than string-matching the human report.
 *
 * This file exists because the pre-1.1.1 audit had silent false
 * negatives:
 *   - SEC-001 missed current-format OpenAI (sk-proj-) and Anthropic
 *     (sk-ant-api03-) keys because the hyphen after the provider tag
 *     is outside [a-zA-Z0-9]
 *   - ERR-001 missed `catch (e) { /* silent *\/ }` because the pattern
 *     required literal empty braces
 *   - README claimed "raw SQL" detection but no rule implemented it
 *   - Nothing flagged connection strings with embedded credentials
 *
 * Each fix here gets a test so those regressions cannot slip back in.
 *
 * Run: node tests/audit.test.js
 * This file is exempted from `guardian audit` via the central allowlist
 * at security/.audit-allowlist — the fixtures below deliberately
 * contain patterns that would trip the scanner.
 * ============================================================
 */

import { strict as assert } from "assert";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";

const __dirname   = path.dirname(fileURLToPath(import.meta.url));
const AUDIT_SCRIPT = path.resolve(__dirname, "..", "security", "03-audit.js");

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

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

/**
 * Run `node 03-audit.js <tmpDir> --json` as a subprocess and return
 * the parsed findings array. Uses spawnSync (array form, shell: false)
 * — never passes tmpDir through a shell — so paths with spaces work
 * and there is no injection surface even for test fixtures.
 */
function runAuditOn(tmpDir) {
  const result = spawnSync("node", [AUDIT_SCRIPT, tmpDir, "--json"], {
    encoding: "utf8",
    shell: false,
  });
  if (result.error) {
    throw new Error(`audit subprocess failed: ${result.error.message}`);
  }
  // --json routes status to stderr and JSON to stdout. Parse stdout only.
  try {
    return JSON.parse(result.stdout);
  } catch (e) {
    throw new Error(
      `audit did not emit valid JSON.\n` +
      `stdout: ${result.stdout.slice(0, 400)}\n` +
      `stderr: ${result.stderr.slice(0, 400)}`
    );
  }
}

function hasFinding(report, ruleId) {
  return report.findings.some((f) => f.rule?.id === ruleId);
}

/**
 * Create a temp directory containing one fixture file with the given
 * content. Returns the directory path; caller is responsible for
 * cleaning it up with rmSync in the test body.
 */
function makeFixture(name, content) {
  const dir  = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
  const file = path.join(dir, name);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content, "utf8");
  return dir;
}

// ---------------------------------------------------------------------------
// SECRET PATTERN TESTS — v1.1.1 regression coverage
// ---------------------------------------------------------------------------

describe("Secret rules — OpenAI + Anthropic key formats (v1.1.1)", () => {
  test("SEC-001 catches sk-proj- OpenAI project key", () => {
    const dir = makeFixture(
      "bad.js",
      `const key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890AbCdEfGhIjKl";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "SEC-001"), "SEC-001 should fire on sk-proj- key");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("SEC-010 catches sk-ant-api03- Anthropic key", () => {
    const dir = makeFixture(
      "bad.js",
      `const key = "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "SEC-010"), "SEC-010 should fire on sk-ant-api03- key");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("SEC-001b catches legacy sk- format", () => {
    const dir = makeFixture(
      "bad.js",
      `const key = "sk-aBcDeFgHiJkLmNoPqRsT1234567890AbCd";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "SEC-001b"),
        "SEC-001b should fire on legacy sk- key"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("SEC-011 catches postgres URL with embedded password", () => {
    const dir = makeFixture(
      "config.js",
      `const DB = "postgresql://admin:hunter2@db.internal:5432/prod";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "SEC-011"), "SEC-011 should fire on postgres creds");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("SEC-011 catches mongodb+srv URL with credentials", () => {
    const dir = makeFixture(
      "config.js",
      `const MONGO = "mongodb+srv://app:secret123@cluster0.mongodb.net/prod";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "SEC-011"), "SEC-011 should fire on mongodb+srv creds");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("SEC-011 does NOT fire on credential-less URL", () => {
    const dir = makeFixture(
      "config.js",
      `const DB = "postgresql://read-replica.internal:5432/analytics";\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "SEC-011"),
        "SEC-011 must not fire when no embedded credentials are present"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// ERROR HANDLING TESTS — ERR-001 silent-catch with comment body
// ---------------------------------------------------------------------------

describe("ERR-001 — silent catch (v1.1.1 false-negative fix)", () => {
  test("ERR-001 catches literal empty catch", () => {
    const dir = makeFixture(
      "bad.js",
      `function f() {\n  try { doThing(); } catch (e) {}\n}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "ERR-001"), "ERR-001 should fire on empty catch");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("ERR-001 catches single-line catch with // comment", () => {
    const dir = makeFixture(
      "bad.js",
      `function f() {\n  try { doThing(); } catch (e) { /* silent */ }\n}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "ERR-001"),
        "ERR-001 should fire on catch with only block comment"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("ERR-001 catches multi-line catch with comment body", () => {
    const dir = makeFixture(
      "bad.js",
      `async function getUser(id) {\n` +
      `  try {\n` +
      `    return await db.get(id);\n` +
      `  } catch (e) {\n` +
      `    // silent failure — production will never know\n` +
      `  }\n` +
      `}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "ERR-001"),
        "ERR-001 should fire on multi-line catch with comment body"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("ERR-001 does NOT fire on catch with real handling", () => {
    const dir = makeFixture(
      "ok.js",
      `function f() {\n` +
      `  try {\n` +
      `    doThing();\n` +
      `  } catch (e) {\n` +
      `    logger.error({ err: e }, "doThing failed");\n` +
      `    throw new AppError("failed", { cause: e });\n` +
      `  }\n` +
      `}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "ERR-001"),
        "ERR-001 must not fire on a catch with real error handling"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// SQL INJECTION TESTS — INJ-004, INJ-005, INJ-006 (v1.1.1)
// ---------------------------------------------------------------------------
//
// The README has long claimed "raw SQL" detection but the pre-1.1.1
// audit had no rule for it. A planted file with string-concat SQL
// produced zero findings. These tests lock in the new rules.

describe("INJ-004 / INJ-005 / INJ-006 — raw SQL detection (v1.1.1)", () => {
  test("INJ-004 catches JS string-concat SQL", () => {
    const dir = makeFixture(
      "bad.js",
      `async function getUser(id) {\n` +
      `  return db.query("SELECT * FROM users WHERE id = " + id);\n` +
      `}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "INJ-004"), "INJ-004 should fire on string-concat SQL");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-004 catches SQL built with db.raw and concat", () => {
    const dir = makeFixture(
      "bad.js",
      `const row = await db.raw("DELETE FROM sessions WHERE id = '" + sid + "'");\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "INJ-004"), "INJ-004 should fire on raw() with concat");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-005 catches template literal with ${} interpolation", () => {
    const dir = makeFixture(
      "bad.js",
      "const row = await db.query(`SELECT * FROM users WHERE id = ${userId}`);\n"
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-005"),
        "INJ-005 should fire on template literal SQL with interpolation"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-006 catches Python f-string SQL", () => {
    const dir = makeFixture(
      "bad.py",
      `def get_user(user_id):\n` +
      `    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "INJ-006"), "INJ-006 should fire on Python f-string SQL");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-004/005 do NOT fire on parameterized queries", () => {
    const dir = makeFixture(
      "ok.js",
      "const row = await db.query('SELECT * FROM users WHERE id = ?', [id]);\n" +
      "const row2 = await db.query(`SELECT * FROM users WHERE id = $1`, [id]);\n"
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "INJ-004"),
        "INJ-004 must not fire on parameterized string query"
      );
      assert.ok(
        !hasFinding(report, "INJ-005"),
        "INJ-005 must not fire on template literal without interpolation"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// END-TO-END: the original regression fixture from the 1.1.1 review
// ---------------------------------------------------------------------------
//
// The pre-ship review handed the audit a file with FIVE obvious bugs
// and the audit caught only one (console.log). This test reproduces
// that exact fixture and asserts every finding the audit now catches.

describe("End-to-end regression — five bugs, five findings", () => {
  test("1.1.1 fixture: sk-proj, conn string, SQL concat, silent catch, console.log", () => {
    const dir = makeFixture(
      "bad-code.js",
      `// Planted regression fixture for the 1.1.1 pre-ship review.\n` +
      `const OPENAI_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890AbCdEfGhIjKl";\n` +
      `const DB_URL = "postgresql://admin:hunter2@localhost:5432/prod";\n` +
      `\n` +
      `async function getUser(id) {\n` +
      `  try {\n` +
      `    const user = await db.raw("SELECT * FROM users WHERE id = " + id);\n` +
      `    return user;\n` +
      `  } catch (e) {\n` +
      `    // silent failure\n` +
      `  }\n` +
      `}\n` +
      `\n` +
      `console.log("debug: user fetched");\n`
    );
    try {
      const report = runAuditOn(dir);

      // Five findings the audit must now catch:
      assert.ok(hasFinding(report, "SEC-001"),  "sk-proj- hardcoded key must be caught");
      assert.ok(hasFinding(report, "SEC-011"),  "postgres URL with creds must be caught");
      assert.ok(hasFinding(report, "INJ-004"),  "SQL string concatenation must be caught");
      assert.ok(hasFinding(report, "ERR-001"),  "silent catch with comment body must be caught");
      assert.ok(hasFinding(report, "ERR-003"),  "console.log in non-test code must be caught");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// RESULTS
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(60)}`);
console.log(`🔍 [OTLC GUARDIAN] audit.test.js RESULTS`);
console.log(`   Passed : ${passed}`);
console.log(`   Failed : ${failed}`);
console.log(`   Total  : ${passed + failed}`);

if (failures.length > 0) {
  console.error(`\n❌ FAILURES:`);
  failures.forEach((f) => console.error(`   → ${f.name}: ${f.error}`));
  process.exit(1);
} else {
  console.log(`\n✅ All audit tests passed.\n`);
  process.exit(0);
}
