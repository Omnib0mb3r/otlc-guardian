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
// v1.2.2 — DEPENDENCY DIRECTORY SKIP LIST
// ---------------------------------------------------------------------------
//
// The pre-1.2.2 audit walked vendor/, target/, bower_components/, and
// the various Python cache dirs. Real-world test on three projects
// produced 9+ false-positive findings inside vendored composer packages
// alone (jquery.min.js, popper.min.js, d3.min.js). Dependency code is
// not the user's code; security scanning of dependencies is a separate
// tool's job (npm audit, pip-audit, composer audit) and is already in
// Guardian's CI workflow. The fix is to add the missing dependency
// directories to SKIP_DIRS in lockstep with what the auditor already
// does for node_modules/.

describe("v1.2.2 — dependency directories are skipped", () => {
  test("vendor/ (composer) — findings inside are NOT reported", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "vendor", "phpunit"), { recursive: true });
      writeFileSync(
        path.join(dir, "vendor", "phpunit", "min.js"),
        `try{x()}catch(e){}`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "ERR-001"),
        "ERR-001 must not fire on a file inside vendor/"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("target/ (rust/maven build output) — findings inside are NOT reported", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "target", "debug"), { recursive: true });
      writeFileSync(
        path.join(dir, "target", "debug", "bundle.js"),
        `const k = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHi";`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "SEC-001"),
        "SEC-001 must not fire on a file inside target/"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("bower_components/ — findings inside are NOT reported", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "bower_components", "jquery"), { recursive: true });
      writeFileSync(
        path.join(dir, "bower_components", "jquery", "j.js"),
        `try{x()}catch(t){}`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "ERR-001"),
        "ERR-001 must not fire on a file inside bower_components/"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("control: same finding outside any skip dir IS still reported", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "lib.js"),
        `try{x()}catch(e){}`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "ERR-001"),
        "ERR-001 must still fire on a file in src/"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// v1.2.2 — BROADENED TEST-FILE DETECTION
// ---------------------------------------------------------------------------
//
// The pre-1.2.2 ERR-003 rule already had an excludePatterns list, but
// it only knew about *.test.* and *.spec.* and the substring "test/".
// Real-world test on three projects produced 28+ false-positive
// findings on legitimate test code that uses other naming conventions:
// pytest's test_*.py, custom test runners like test-site.js, files
// inside a `tests/` directory on Windows where the path separator is
// backslash, etc. The fix introduces a TEST_FILE_EXCLUDES constant
// that recognizes the full set of conventional test-file patterns and
// applies it to every rule whose intent is "production code only":
// ERR-003, CFG-001, CFG-002, CFG-003, INJ-002, TS-001, SEC-006.

describe("v1.2.2 — test-file detection recognizes more conventions", () => {
  test("foo.spec.ts with localhost URL — CFG-001 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "foo.spec.ts"),
        `const url = "http://localhost:3000/api";`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-001"),
        "CFG-001 must not fire in *.spec.ts files"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("test_foo.py with localhost URL — CFG-001 must NOT fire (pytest convention)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "test_api.py"),
        `URL = "http://localhost:8000/api"`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-001"),
        "CFG-001 must not fire in test_*.py files"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("foo_test.py with localhost URL — CFG-001 must NOT fire (alt pytest)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "api_test.py"),
        `URL = "http://localhost:8000/api"`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-001"),
        "CFG-001 must not fire in *_test.py files"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("test-site.js with console.log — ERR-003 must NOT fire (custom test runner)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "test-site.js"),
        `console.log("running tests");`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "ERR-003"),
        "ERR-003 must not fire in test-*.js files (custom test runners)"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("nested tests/ directory on any OS — CFG-002 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "pkg-a", "tests"), { recursive: true });
      writeFileSync(
        path.join(dir, "pkg-a", "tests", "integration.ts"),
        `const url = "http://127.0.0.1:8080/api";`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-002"),
        "CFG-002 must not fire in any file inside a tests/ directory"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("__tests__ folder with innerHTML — INJ-002 must NOT fire (JSDOM cleanup)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "__tests__"), { recursive: true });
      writeFileSync(
        path.join(dir, "__tests__", "ui.test.ts"),
        `document.body.innerHTML = '';`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "INJ-002"),
        "INJ-002 must not fire in __tests__/ files (JSDOM teardown is standard)"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("tests/ file with `any` type — TS-001 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "tests"), { recursive: true });
      writeFileSync(
        path.join(dir, "tests", "mock.test.ts"),
        `const cb = (e: any) => null;`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "TS-001"),
        "TS-001 must not fire in tests/ files (mocking external APIs needs any)"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("test fixture API key assignment — SEC-006 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "tests"), { recursive: true });
      writeFileSync(
        path.join(dir, "tests", "setup.test.ts"),
        `process.env.ANTHROPIC_API_KEY = 'test-key-for-vitest';`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "SEC-006"),
        "SEC-006 must not fire in test files setting up env vars"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("control: src/ file with localhost URL still triggers CFG-001", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "config.ts"),
        `export const apiUrl = "http://localhost:3000/api";`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "CFG-001"),
        "CFG-001 must still fire in src/ production code"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("control: src/ file with console.log still triggers ERR-003", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "service.ts"),
        `console.log("debug: user fetched");`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "ERR-003"),
        "ERR-003 must still fire in src/ production code"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// v1.2.2 — CFG-003 BIND-vs-URL DISTINCTION
// ---------------------------------------------------------------------------
//
// The pre-1.2.2 CFG-003 rule fired on ANY quoted IP address. That
// conflated two opposite things:
//   - URL pointing at a hardcoded IP (real bug — production config leak)
//   - Server BINDING to 127.0.0.1 (security best practice — refuses
//     connections from any other IP)
// DevNeural's audit had 4 false-positive CFG-003 findings on legitimate
// `fastify.listen({ host: '127.0.0.1' })` and `server.listen(0,
// '127.0.0.1', ...)` calls. The fix introduces an excludeLinePatterns
// mechanism that lets a rule suppress findings whose surrounding line
// matches one of a list of "this is the safe form" patterns.

describe("v1.2.2 — CFG-003 distinguishes binding from URL", () => {
  test("fastify.listen({ host: '127.0.0.1' }) — CFG-003 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.ts"),
        `await fastify.listen({ port: 3000, host: '127.0.0.1' });`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-003"),
        "CFG-003 must not fire on a fastify-style bind to 127.0.0.1"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("server.listen(0, '127.0.0.1', cb) — CFG-003 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.ts"),
        `server.listen(0, '127.0.0.1', () => console.log('up'));`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-003"),
        "CFG-003 must not fire on a positional listen(port, host, cb) bind"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("bind('127.0.0.1', port) — CFG-003 must NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "socket.ts"),
        `socket.bind('127.0.0.1', 8080);`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "CFG-003"),
        "CFG-003 must not fire on a bind() call"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("control: bare hardcoded IP assignment IS still flagged", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "config.ts"),
        `export const dbHost = "192.168.1.10";`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "CFG-003"),
        "CFG-003 must still fire on a bare IP config assignment (real config leak)"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// v1.2.4 — DEP-001 GATED ON "LOOKS LIKE AN HTTP SERVER"
// ---------------------------------------------------------------------------
//
// The pre-1.2.4 DEP-001 rule fired on any project that didn't contain the
// substring "health" in any file. It was designed for HTTP services but had
// no project-shape detection, so every CLI tool, static site, library, npm
// package, code-generation skill, desktop app, and notebook produced a
// spurious "No health check endpoint found" finding. Audit testing across
// 12 real projects on the user's machine showed 9 of them hitting exactly
// this false positive — they are not servers, so they do not have health
// endpoints, and that is correct.
//
// The fix adds a `looksLikeHttpServer(rootDir, files)` gate that checks
// package.json / requirements.txt / pyproject.toml for known HTTP server
// frameworks AND scans source files for listen-pattern calls. DEP-001
// only fires when both conditions hold: the project looks like an HTTP
// server AND no health endpoint is found. Non-server projects are left
// alone.

describe("v1.2.4 — DEP-001 gated on HTTP server shape", () => {
  // POSITIVE: a Node project with express in package.json and no /health
  // endpoint must still trip DEP-001. This is the original use case of the
  // rule and must not regress.
  test("express in package.json, no /health — DEP-001 FIRES", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({
          name: "my-api",
          dependencies: { express: "^4.18.0" },
        }),
        "utf8"
      );
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.js"),
        `import express from 'express';\n` +
        `const app = express();\n` +
        `app.get('/users', (req, res) => res.json([]));\n` +
        `app.listen(3000);\n`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "DEP-001"),
        "DEP-001 must still fire on an express app that has no /health"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // POSITIVE: a Python project with fastapi in requirements.txt and no
  // /health endpoint must trip DEP-001. Mirrors the Node case.
  test("fastapi in requirements.txt, no /health — DEP-001 FIRES", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "requirements.txt"),
        `fastapi==0.104.0\nuvicorn==0.24.0\n`,
        "utf8"
      );
      mkdirSync(path.join(dir, "app"), { recursive: true });
      writeFileSync(
        path.join(dir, "app", "main.py"),
        `from fastapi import FastAPI\n` +
        `app = FastAPI()\n` +
        `@app.get('/items')\n` +
        `def list_items(): return []\n`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "DEP-001"),
        "DEP-001 must fire on a FastAPI app that has no /health"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // NEGATIVE: a pure CLI project with no server framework must NOT trip
  // DEP-001. This is the 9-of-12 false-positive case the fix exists for.
  test("CLI project, no server framework — DEP-001 does NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({
          name: "my-cli",
          bin: { "my-cli": "./bin/cli.js" },
          dependencies: { chalk: "^5.0.0" },
        }),
        "utf8"
      );
      mkdirSync(path.join(dir, "bin"), { recursive: true });
      writeFileSync(
        path.join(dir, "bin", "cli.js"),
        `#!/usr/bin/env node\nimport chalk from 'chalk';\nconsole.log(chalk.green('hi'));\n`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "DEP-001"),
        "DEP-001 must not fire on a CLI project that has no server framework"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // NEGATIVE: a project with no package.json, no requirements.txt, and no
  // server-looking source files (e.g. a static site or a data/notebook dir)
  // must NOT trip DEP-001.
  test("static site — no manifest, no server code — DEP-001 does NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "index.html"),
        `<!doctype html><html><body><h1>hi</h1></body></html>`,
        "utf8"
      );
      writeFileSync(
        path.join(dir, "styles.css"),
        `body { font-family: sans-serif; }`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "DEP-001"),
        "DEP-001 must not fire on a static site with no server framework"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // CONTROL: a project that IS a server AND HAS a /health endpoint must
  // NOT trip DEP-001. This is the existing happy path and must not regress.
  test("express app WITH /health endpoint — DEP-001 does NOT fire", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({
          name: "my-api",
          dependencies: { express: "^4.18.0" },
        }),
        "utf8"
      );
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.js"),
        `import express from 'express';\n` +
        `const app = express();\n` +
        `app.get('/health', (req, res) => res.json({ status: 'ok' }));\n` +
        `app.listen(3000);\n`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "DEP-001"),
        "DEP-001 must not fire on a server that has a /health endpoint"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // POSITIVE edge: no manifest at all, but source files contain
  // app.listen(...) / server.listen(...) / createServer(...) — still
  // counts as a server. This catches projects that bundle via tsx or
  // run from source without a package.json (rare but real).
  test("source contains app.listen() but no manifest — DEP-001 FIRES", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.js"),
        `import http from 'http';\n` +
        `const server = http.createServer((req, res) => res.end('hi'));\n` +
        `server.listen(3000);\n`,
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "DEP-001"),
        "DEP-001 must fire when source code clearly calls .listen() even without a manifest"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// v1.3.0 — INJ-005b: template literal SQL with ${} interpolation,
// regardless of how the variable is used (variable indirection fix)
// ---------------------------------------------------------------------------
//
// The pre-1.3.0 INJ-005 rule required the backtick template to be the
// FIRST ARGUMENT of `query|execute|exec|raw|prepare`. A simple two-line
// refactor evaded the rule:
//
//   const sql = `SELECT * FROM users WHERE id = ${userId}`;
//   db.query(sql);
//
// The SQL is still unparameterized, the user input is still being
// spliced into the query text, the injection surface is identical —
// but the regex sees `db.query(sql)` (no backtick as the first arg)
// and doesn't fire. A single level of variable indirection bypassed
// the entire rule.
//
// Fix: add a companion rule INJ-005b that catches template-literal
// SQL with `${}` interpolation ANYWHERE in the file, regardless of
// how (or whether) the variable is subsequently used. Writing
// `const sql = \`SELECT ... ${x}\`` is independently dangerous — if
// that line exists in your code, it's a bug, whether it's then
// passed directly to `db.query(sql)` or through 5 more levels of
// indirection. The original INJ-005 is kept as-is; projects can get
// the direct-call match from INJ-005 and the declaration-site match
// from INJ-005b, making the two rules complementary.

describe("v1.3.0 — INJ-005b: variable-indirection template literal SQL", () => {
  test("INJ-005b catches const X = `SELECT ... ${x}` ... db.query(X)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "bad.js"),
        "async function getUser(userId) {\n" +
        "  const sql = `SELECT * FROM users WHERE id = ${userId}`;\n" +
        "  return await db.query(sql);\n" +
        "}\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-005b"),
        "INJ-005b should fire on template-literal SQL stored in a variable"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-005b catches let X = `INSERT INTO ... ${x}` (bare declaration)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "bad.ts"),
        "let sql: string;\n" +
        "sql = `INSERT INTO audit_log (actor) VALUES ('${actor}')`;\n" +
        "await db.execute(sql);\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-005b"),
        "INJ-005b should fire on a template-literal SQL assignment with an interpolation"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-005b does NOT fire on template literal without interpolation", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "ok.js"),
        "const sql = `SELECT id, name FROM users WHERE active = true`;\n" +
        "const rows = await db.query(sql);\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "INJ-005b"),
        "INJ-005b must not fire on a template-literal SQL with no interpolation"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-005b does NOT fire on a template literal that isn't SQL", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "ok.js"),
        "const greeting = `Hello, ${name}! You have ${count} messages.`;\n" +
        "console.log(greeting);\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "INJ-005b"),
        "INJ-005b must not fire on a non-SQL template literal with interpolation"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// v1.3.0 — INJ-006: Python f-string SQL with inner quoted literals
// ---------------------------------------------------------------------------
//
// The pre-1.3.0 INJ-006 regex used `[^"']*` between the f-string's
// opening and closing quotes. That character class excludes BOTH quote
// types, so any f-string containing a literal like `WHERE name = 'admin'`
// — which is most real-world SQL — broke the match and the rule silently
// did nothing.
//
// Fix: split into two alternation branches, one for each outer quote
// style. When the f-string is `f"..."` the inner character class
// excludes only `"`, so single quotes are allowed. When the f-string
// is `f'...'` the inner character class excludes only `'`, so double
// quotes are allowed. Real-world SQL almost always contains string
// equality literals like `'admin'` or `'active'`, and the pre-1.3.0
// regex couldn't see any of them.

describe("v1.3.0 — INJ-006 inner-quote regex fix", () => {
  test("INJ-006 catches f\"...'{x}'...\" — double-quoted outer, single-quoted inner", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "app"), { recursive: true });
      writeFileSync(
        path.join(dir, "app", "bad.py"),
        "def get_user_by_email(email):\n" +
        "    cur.execute(f\"SELECT * FROM users WHERE email = '{email}'\")\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-006"),
        "INJ-006 should fire on an f\"...\" SQL that contains a single-quoted literal inside"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-006 catches f'...\"{x}\"...' — single-quoted outer, double-quoted inner", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "app"), { recursive: true });
      writeFileSync(
        path.join(dir, "app", "bad.py"),
        "def find_items(keyword):\n" +
        "    cur.execute(f'SELECT * FROM items WHERE title LIKE \"%{keyword}%\"')\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-006"),
        "INJ-006 should fire on an f'...' SQL that contains a double-quoted literal inside"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-006 still catches the simple no-inner-quotes form (regression guard)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "app"), { recursive: true });
      writeFileSync(
        path.join(dir, "app", "bad.py"),
        "def get_user(user_id):\n" +
        "    cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        hasFinding(report, "INJ-006"),
        "INJ-006 must still fire on the original simple form with no inner quoted literal"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("INJ-006 does NOT fire on parameterized Python query", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      mkdirSync(path.join(dir, "app"), { recursive: true });
      writeFileSync(
        path.join(dir, "app", "ok.py"),
        "def get_user(user_id):\n" +
        "    cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n",
        "utf8"
      );
      const report = runAuditOn(dir);
      assert.ok(
        !hasFinding(report, "INJ-006"),
        "INJ-006 must not fire on a parameterized %s query passed as separate arg"
      );
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
