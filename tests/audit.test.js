/**
 * ============================================================
 * OTLC GUARDIAN - Audit Rule Tests
 * // tests · onthelevelconcepts.com
 * Version: 1.5.0
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
 * at security/.audit-allowlist - the fixtures below deliberately
 * contain patterns that would trip the scanner.
 * ============================================================
 */

import { strict as assert } from "assert";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath, pathToFileURL } from "url";

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

/**
 * A test that reproduces an open bug. It must keep failing until the bug
 * is fixed: while it fails it is reported as known, and the moment it
 * passes the suite fails, so the fix also moves the test to test() and
 * the bug in BUGS.md. The assertion itself is never weakened.
 */
let knownBugs = 0;
function knownBug(bugId, name, fn) {
  try {
    fn();
  } catch (err) {
    console.log(`  ⚠️  ${name} (known: ${bugId})`);
    knownBugs++;
    return;
  }
  console.error(`  ❌ ${name}`);
  console.error(`     → passes now: ${bugId} looks fixed. Move this to test() and update BUGS.md.`);
  failed++;
  failures.push({ name, error: `${bugId} passes now` });
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

/**
 * Run `node 03-audit.js <tmpDir> --json` as a subprocess and return
 * the parsed findings array. Uses spawnSync (array form, shell: false)
 * - never passes tmpDir through a shell - so paths with spaces work
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
// SECRET PATTERN TESTS - v1.1.1 regression coverage
// ---------------------------------------------------------------------------

describe("Secret rules - OpenAI + Anthropic key formats (v1.1.1)", () => {
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
// ERROR HANDLING TESTS - ERR-001 silent-catch with comment body
// ---------------------------------------------------------------------------

describe("ERR-001 - silent catch (v1.1.1 false-negative fix)", () => {
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
      `    // silent failure - production will never know\n` +
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
// SQL INJECTION TESTS - INJ-004, INJ-005, INJ-006 (v1.1.1)
// ---------------------------------------------------------------------------
//
// The README has long claimed "raw SQL" detection but the pre-1.1.1
// audit had no rule for it. A planted file with string-concat SQL
// produced zero findings. These tests lock in the new rules.

describe("INJ-004 / INJ-005 / INJ-006 - raw SQL detection (v1.1.1)", () => {
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

describe("End-to-end regression - five bugs, five findings", () => {
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
// v1.2.2 - DEPENDENCY DIRECTORY SKIP LIST
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

describe("v1.2.2 - dependency directories are skipped", () => {
  test("vendor/ (composer) - findings inside are NOT reported", () => {
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

  test("target/ (rust/maven build output) - findings inside are NOT reported", () => {
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

  test("bower_components/ - findings inside are NOT reported", () => {
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
// v1.2.2 - BROADENED TEST-FILE DETECTION
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

describe("v1.2.2 - test-file detection recognizes more conventions", () => {
  test("foo.spec.ts with localhost URL - CFG-001 must NOT fire", () => {
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

  test("test_foo.py with localhost URL - CFG-001 must NOT fire (pytest convention)", () => {
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

  test("foo_test.py with localhost URL - CFG-001 must NOT fire (alt pytest)", () => {
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

  test("test-site.js with console.log - ERR-003 must NOT fire (custom test runner)", () => {
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

  test("nested tests/ directory on any OS - CFG-002 must NOT fire", () => {
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

  test("__tests__ folder with innerHTML - INJ-002 must NOT fire (JSDOM cleanup)", () => {
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

  test("tests/ file with `any` type - TS-001 must NOT fire", () => {
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

  test("test fixture API key assignment - SEC-006 must NOT fire", () => {
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
// v1.2.2 - CFG-003 BIND-vs-URL DISTINCTION
// ---------------------------------------------------------------------------
//
// The pre-1.2.2 CFG-003 rule fired on ANY quoted IP address. That
// conflated two opposite things:
//   - URL pointing at a hardcoded IP (real bug - production config leak)
//   - Server BINDING to 127.0.0.1 (security best practice - refuses
//     connections from any other IP)
// DevNeural's audit had 4 false-positive CFG-003 findings on legitimate
// `fastify.listen({ host: '127.0.0.1' })` and `server.listen(0,
// '127.0.0.1', ...)` calls. The fix introduces an excludeLinePatterns
// mechanism that lets a rule suppress findings whose surrounding line
// matches one of a list of "this is the safe form" patterns.

describe("v1.2.2 - CFG-003 distinguishes binding from URL", () => {
  test("fastify.listen({ host: '127.0.0.1' }) - CFG-003 must NOT fire", () => {
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

  test("server.listen(0, '127.0.0.1', cb) - CFG-003 must NOT fire", () => {
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

  test("bind('127.0.0.1', port) - CFG-003 must NOT fire", () => {
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
// v1.2.4 - DEP-001 GATED ON "LOOKS LIKE AN HTTP SERVER"
// ---------------------------------------------------------------------------
//
// The pre-1.2.4 DEP-001 rule fired on any project that didn't contain the
// substring "health" in any file. It was designed for HTTP services but had
// no project-shape detection, so every CLI tool, static site, library, npm
// package, code-generation skill, desktop app, and notebook produced a
// spurious "No health check endpoint found" finding. Audit testing across
// 12 real projects on the user's machine showed 9 of them hitting exactly
// this false positive - they are not servers, so they do not have health
// endpoints, and that is correct.
//
// The fix adds a `looksLikeHttpServer(rootDir, files)` gate that checks
// package.json / requirements.txt / pyproject.toml for known HTTP server
// frameworks AND scans source files for listen-pattern calls. DEP-001
// only fires when both conditions hold: the project looks like an HTTP
// server AND no health endpoint is found. Non-server projects are left
// alone.

describe("v1.2.4 - DEP-001 gated on HTTP server shape", () => {
  // POSITIVE: a Node project with express in package.json and no /health
  // endpoint must still trip DEP-001. This is the original use case of the
  // rule and must not regress.
  test("express in package.json, no /health - DEP-001 FIRES", () => {
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
  test("fastapi in requirements.txt, no /health - DEP-001 FIRES", () => {
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
  test("CLI project, no server framework - DEP-001 does NOT fire", () => {
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
  test("static site - no manifest, no server code - DEP-001 does NOT fire", () => {
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
  test("express app WITH /health endpoint - DEP-001 does NOT fire", () => {
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
  // app.listen(...) / server.listen(...) / createServer(...) - still
  // counts as a server. This catches projects that bundle via tsx or
  // run from source without a package.json (rare but real).
  test("source contains app.listen() but no manifest - DEP-001 FIRES", () => {
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
// v1.3.0 - INJ-005b: template literal SQL with ${} interpolation,
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
// spliced into the query text, the injection surface is identical - 
// but the regex sees `db.query(sql)` (no backtick as the first arg)
// and doesn't fire. A single level of variable indirection bypassed
// the entire rule.
//
// Fix: add a companion rule INJ-005b that catches template-literal
// SQL with `${}` interpolation ANYWHERE in the file, regardless of
// how (or whether) the variable is subsequently used. Writing
// `const sql = \`SELECT ... ${x}\`` is independently dangerous - if
// that line exists in your code, it's a bug, whether it's then
// passed directly to `db.query(sql)` or through 5 more levels of
// indirection. The original INJ-005 is kept as-is; projects can get
// the direct-call match from INJ-005 and the declaration-site match
// from INJ-005b, making the two rules complementary.

describe("v1.3.0 - INJ-005b: variable-indirection template literal SQL", () => {
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
// v1.3.0 - INJ-006: Python f-string SQL with inner quoted literals
// ---------------------------------------------------------------------------
//
// The pre-1.3.0 INJ-006 regex used `[^"']*` between the f-string's
// opening and closing quotes. That character class excludes BOTH quote
// types, so any f-string containing a literal like `WHERE name = 'admin'`
// - which is most real-world SQL - broke the match and the rule silently
// did nothing.
//
// Fix: split into two alternation branches, one for each outer quote
// style. When the f-string is `f"..."` the inner character class
// excludes only `"`, so single quotes are allowed. When the f-string
// is `f'...'` the inner character class excludes only `'`, so double
// quotes are allowed. Real-world SQL almost always contains string
// equality literals like `'admin'` or `'active'`, and the pre-1.3.0
// regex couldn't see any of them.

describe("v1.3.0 - INJ-006 inner-quote regex fix", () => {
  test("INJ-006 catches f\"...'{x}'...\" - double-quoted outer, single-quoted inner", () => {
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

  test("INJ-006 catches f'...\"{x}\"...' - single-quoted outer, double-quoted inner", () => {
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
// v1.3.1 - projectRoot vs scanRoot (audit subdirectory scoping)
// ---------------------------------------------------------------------------
//
// The pre-1.3.1 audit treated the scan target as the project root for
// BOTH the file walker AND the project-shape lookups (manifest checks,
// .audit-allowlist load). That was wrong when the user ran
// `guardian audit ./src` - the manifest is at the project root, not
// inside src/, so DEP-001 gating saw "no package.json" and silently
// disabled itself, AND the central .audit-allowlist was ignored
// because it lives at <project-root>/security/.audit-allowlist.
//
// Fix: separate `projectRoot` from `scanRoot`. The walker still walks
// `scanRoot`, but manifest lookups, .audit-allowlist, and any other
// project-level concept consult the upward-walked project root.

describe("v1.3.1 - projectRoot vs scanRoot (subdirectory audit scoping)", () => {
  test("DEP-001 fires when scanning a subdirectory of an express project", () => {
    // Build a project structure:
    //   tmp/
    //     package.json (express)
    //     src/
    //       server.js  (no /health)
    // Then audit the src/ subdirectory. DEP-001 should still fire
    // because looksLikeHttpServer should walk UP to find package.json.
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({ name: "my-api", dependencies: { express: "^4.18.0" } }),
        "utf8"
      );
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "server.js"),
        "import express from 'express';\nconst app = express();\napp.listen(3000);\n",
        "utf8"
      );
      const report = runAuditOn(path.join(dir, "src"));
      assert.ok(
        hasFinding(report, "DEP-001"),
        "DEP-001 must fire when scanning ./src of a project whose package.json (with express) lives one level up"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("DEP-001 does NOT fire when scanning a subdirectory of a non-server project", () => {
    // Same as above but the parent project has no server framework.
    // DEP-001 must stay silent because the project as a whole is not
    // a server, even though the scanned subdirectory has source files.
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({ name: "my-cli", bin: { "my-cli": "./bin/cli.js" } }),
        "utf8"
      );
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "lib.js"),
        "export function add(a, b) { return a + b; }\n",
        "utf8"
      );
      const report = runAuditOn(path.join(dir, "src"));
      assert.ok(
        !hasFinding(report, "DEP-001"),
        "DEP-001 must NOT fire when scanning ./src of a CLI project whose parent has no server framework"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test(".audit-allowlist at project root is honored when scanning a subdirectory", () => {
    // Build a project with a centralized allowlist that exempts a file
    // inside src/. Audit ./src and verify the allowlist is consulted.
    // Pre-1.3.1 the allowlist load would look at ./src/security/.audit-allowlist
    // which doesn't exist, and the file would not be exempted - false
    // positive. Post-1.3.1 the allowlist is loaded from the project
    // root and the file is correctly exempted.
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      // Project marker at the top
      writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify({ name: "my-app" }),
        "utf8"
      );
      // Centralized allowlist at <project-root>/security/.audit-allowlist
      mkdirSync(path.join(dir, "security"), { recursive: true });
      writeFileSync(
        path.join(dir, "security", ".audit-allowlist"),
        "src/legacy.js  # reason: legacy code, scheduled for rewrite in Q3\n",
        "utf8"
      );
      // The file that should be exempted - contains a SEC-001 trigger
      mkdirSync(path.join(dir, "src"), { recursive: true });
      writeFileSync(
        path.join(dir, "src", "legacy.js"),
        'const KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890AbCdEfGhIjKl";\n',
        "utf8"
      );
      // Audit the src/ subdirectory
      const report = runAuditOn(path.join(dir, "src"));
      assert.ok(
        !hasFinding(report, "SEC-001"),
        "SEC-001 must NOT fire on src/legacy.js when the project-root .audit-allowlist exempts it (subdirectory scan must consult the project-root allowlist)"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("Project-root walker stops at filesystem boundary if no markers found", () => {
    // Edge case: scanning a directory that has no project markers
    // anywhere up the tree (e.g. /tmp/orphaned-source/). The detector
    // must NOT walk past the original scan target - it should fall
    // back to the scan target as its own project root.
    const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
    try {
      // No package.json, no .git, no requirements.txt - no markers
      writeFileSync(
        path.join(dir, "main.js"),
        "console.log('hello');\n",
        "utf8"
      );
      // Audit should still run cleanly without crashing on the missing
      // upward markers; behavior should match scanning the dir directly.
      const report = runAuditOn(dir);
      assert.ok(Array.isArray(report.findings), "audit should still produce a valid report on a marker-less directory");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// INJ-005b PRECISION - v1.4.1 (BUG-001)
// ---------------------------------------------------------------------------
//
// The 1.3.0 rule required only a lone SQL verb plus an interpolation, so
// ordinary UI strings ("Delete asset ${name}?") were reported as CRITICAL
// SQL injection. A real audit returned 6 CRITICALs, all six false
// positives from this rule alone.
//
// The negative fixtures below are the exact shapes that misfired. They are
// the point of the rule now: a security rule that cannot be quieted by
// writing correct code is a rule people switch off.

describe("INJ-005b - still catches real SQL (regression guard)", () => {
  test("fires on SELECT ... FROM with interpolation", () => {
    const dir = makeFixture(
      "db.js",
      "const id = req.params.id;\n" +
      "const q = `SELECT * FROM users WHERE id = ${id}`;\n" +
      "await db.query(q);\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "INJ-005b"), "INJ-005b must still catch SELECT..FROM");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fires on UPDATE ... SET with interpolation", () => {
    const dir = makeFixture(
      "db.js",
      "const sqlText = `UPDATE accounts SET balance = ${amount} WHERE id = ${userId}`;\n" +
      "await pool.execute(sqlText);\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "INJ-005b"), "INJ-005b must still catch UPDATE..SET");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fires on DELETE FROM and INSERT INTO", () => {
    const dir = makeFixture(
      "db.js",
      "const a = `DELETE FROM sessions WHERE token = ${token}`;\n" +
      "const b = `INSERT INTO audit (actor) VALUES ('${actor}')`;\n"
    );
    try {
      const report = runAuditOn(dir);
      const hits = report.findings.filter((f) => f.rule?.id === "INJ-005b");
      assert.equal(hits.length, 2, `expected both DELETE FROM and INSERT INTO to fire, got ${hits.length}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fires when the only interpolation sits before the companion clause", () => {
    // `SELECT ${columns} FROM users` - a pattern that required `${` to
    // appear AFTER the clause pair would miss this genuinely
    // unparameterized query.
    const dir = makeFixture(
      "db.js",
      "const q = `SELECT ${columns} FROM users`;\nawait db.query(q);\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "INJ-005b"), "interpolation before the clause pair must still fire");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("variable-indirection bypass stays closed (BUG-017 guard)", () => {
    // The entire reason INJ-005b exists. If a precision fix ever turns
    // this rule into a call-site match, this test fails.
    const dir = makeFixture(
      "db.js",
      "const sqlText = `SELECT * FROM users WHERE id = ${userId}`;\n" +
      "db.query(sqlText);\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "INJ-005b"), "declaration-site detection must survive the precision fix");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("INJ-005b - no longer fires on English prose (BUG-001)", () => {
  const CLEAN = {
    "window.confirm with the word Delete": "if (!window.confirm(`Delete ${count} items? This cannot be undone.`)) return;\n",
    "console.error with the word update": "console.error(`Failed to update record ${record.id}:`, err);\n",
    "JSX label with the word Delete": "const label = `Delete ${asset.name}`;\n",
    "thrown Error with the word Select": "throw new Error(`Select a quote ${quoteId} before continuing`);\n",
    "alert with the word Drop": "window.alert(`Drop ${file.name} here to upload`);\n",
    "plain greeting": "const greeting = `Hello ${name}`;\n",
  };

  for (const [name, source] of Object.entries(CLEAN)) {
    test(`stays silent: ${name}`, () => {
      const dir = makeFixture("ui.jsx", source);
      try {
        assert.ok(!hasFinding(runAuditOn(dir), "INJ-005b"), `INJ-005b must not fire on ${name}`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  test("stays silent on the sql-guard tagged template", () => {
    // security/04-sql-guard.js's `sql` tag auto-parameterizes. It is the
    // remediation for this bug class, not an instance of it - flagging
    // the fix teaches people to stop applying it.
    const dir = makeFixture(
      "db.js",
      "import { sql } from './security/04-sql-guard.js';\n" +
      "const query = sql`SELECT * FROM users WHERE id = ${userId}`;\n"
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "INJ-005b"), "the sql-guard safe tag must not be flagged");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("an untagged template still fires even next to a sql-tagged one", () => {
    // Guard against the sql-tag exclusion being over-broad.
    const dir = makeFixture(
      "db.js",
      "const safe = sql`SELECT * FROM a WHERE id = ${id}`;\n" +
      "const unsafe = `SELECT * FROM b WHERE id = ${id}`;\n"
    );
    try {
      const hits = runAuditOn(dir).findings.filter((f) => f.rule?.id === "INJ-005b");
      assert.equal(hits.length, 1, `only the untagged template should fire, got ${hits.length}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// AUTHORIZATION + VALIDATION RULES - v1.4.0
// ---------------------------------------------------------------------------
//
// AUTHZ-001/003 and VAL-001 run through the per-file analyzer, not a
// regex, so each rule needs BOTH a positive fixture (the bug fires) and a
// negative fixture (the correct code stays silent). A security rule that
// cannot be silenced by writing correct code is a rule people disable.

describe("AUTHZ-001 - unauthenticated side-effecting handler", () => {
  test("fires on a send-email handler with no auth check", () => {
    const dir = makeFixture(
      "api/send-welcome-email.ts",
      `export default async function handler(req, res) {\n` +
      `  const { customerEmail, customerName } = req.body;\n` +
      `  await sendEmail({ to: customerEmail, subject: "Welcome" });\n` +
      `  return res.status(200).json({ sent: true });\n` +
      `}\n`
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "AUTHZ-001"), "AUTHZ-001 should fire on an unauthenticated email endpoint");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when the handler verifies an internal secret", () => {
    const dir = makeFixture(
      "api/send-welcome-email.ts",
      `export default async function handler(req, res) {\n` +
      `  if (!verifyInternalSecret(req)) return res.status(401).json({ error: "Unauthorized" });\n` +
      `  const parsed = welcomeSchema.safeParse(req.body);\n` +
      `  if (!parsed.success) return res.status(400).json({ error: "Invalid" });\n` +
      `  await sendEmail({ to: parsed.data.customerEmail, subject: "Welcome" });\n` +
      `  return res.status(200).json({ sent: true });\n` +
      `}\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-001"), "AUTHZ-001 must not fire when auth is present");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent on a read-only handler with no side effect", () => {
    const dir = makeFixture(
      "api/version.ts",
      `export async function GET() {\n` +
      `  return Response.json({ version: "1.0.0" });\n` +
      `}\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-001"), "AUTHZ-001 must not fire on a public read-only route");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("AUTHZ-002 - identity trusted from the request", () => {
  test("fires on req.body.userId used for a write", () => {
    const dir = makeFixture(
      "api/profile.ts",
      `const { userId } = req.body;\n` +
      `await db.profiles.update({ where: { id: req.body.userId }, data: { marketing: true } });\n`
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "AUTHZ-002"), "AUTHZ-002 should fire on body-supplied userId");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when identity comes from the verified session", () => {
    const dir = makeFixture(
      "api/profile.ts",
      `const user = await getUser(req);\n` +
      `await db.profiles.update({ where: { id: user.id }, data: { marketing: true } });\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-002"), "AUTHZ-002 must not fire on session-derived identity");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("AUTHZ-003 - IDOR, authenticated but not authorized", () => {
  test("fires on a DELETE that only checks authentication", () => {
    const dir = makeFixture(
      "api/documents/route.ts",
      `export async function DELETE(req, { params }) {\n` +
      `  const user = await getUser(req);\n` +
      `  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n` +
      `  await db.documents.delete({ where: { id: params.id } });\n` +
      `  return Response.json({ success: true });\n` +
      `}\n`
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "AUTHZ-003"), "AUTHZ-003 should fire on an ownership-free delete");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when an object-level access check is present", () => {
    const dir = makeFixture(
      "api/documents/route.ts",
      `export async function DELETE(req, { params }) {\n` +
      `  const user = await getUser(req);\n` +
      `  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n` +
      `  await assertObjectAccess(user.id, user.role, params.id, "delete");\n` +
      `  await db.documents.delete({ where: { id: params.id } });\n` +
      `  return Response.json({ success: true });\n` +
      `}\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-003"), "AUTHZ-003 must not fire when access control runs");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("does not double-report an unauthenticated handler as IDOR", () => {
    // A handler with no auth at all is AUTHZ-001's finding. Reporting it
    // as AUTHZ-003 too would inflate counts and split one fix across two
    // rule IDs.
    const dir = makeFixture(
      "api/documents/route.ts",
      `export async function DELETE(req, { params }) {\n` +
      `  await db.documents.delete({ where: { id: params.id } });\n` +
      `  return Response.json({ success: true });\n` +
      `}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(hasFinding(report, "AUTHZ-001"), "AUTHZ-001 should own the no-auth case");
      assert.ok(!hasFinding(report, "AUTHZ-003"), "AUTHZ-003 must not also fire on the no-auth case");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("AUTHZ-004 - non-constant-time secret comparison", () => {
  test("fires on === against an env secret", () => {
    const dir = makeFixture(
      "api/auth.ts",
      `if (req.headers["x-internal-secret"] === process.env.INTERNAL_API_SECRET) { return true; }\n`
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "AUTHZ-004"), "AUTHZ-004 should fire on === secret compare");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when timingSafeEqual is used", () => {
    const dir = makeFixture(
      "api/auth.ts",
      `return timingSafeEqual(Buffer.from(provided), Buffer.from(process.env.INTERNAL_API_SECRET));\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-004"), "AUTHZ-004 must not fire on timingSafeEqual");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("AUTHZ-005 - cache key not scoped to the user", () => {
  test("fires on a cache key built only from an object ID", () => {
    const dir = makeFixture(
      "lib/thumbnails.ts",
      "const cached = await redis.get(`thumbnail:${videoId}`);\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "AUTHZ-005"), "AUTHZ-005 should fire on an unscoped cache key");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when the key is scoped to userId", () => {
    const dir = makeFixture(
      "lib/thumbnails.ts",
      "const cached = await redis.get(`thumbnail:${userId}:${videoId}`);\n"
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-005"), "AUTHZ-005 must not fire on a user-scoped key");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("VAL-001 - request body without schema validation", () => {
  test("fires when req.body reaches a write unvalidated", () => {
    const dir = makeFixture(
      "api/contact.ts",
      `export default async function handler(req, res) {\n` +
      `  const user = await getUser(req);\n` +
      `  await db.messages.create({ data: req.body });\n` +
      `  return res.status(201).json({ ok: true });\n` +
      `}\n`
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "VAL-001"), "VAL-001 should fire on an unvalidated body write");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent when the body goes through safeParse", () => {
    const dir = makeFixture(
      "api/contact.ts",
      `export default async function handler(req, res) {\n` +
      `  const user = await getUser(req);\n` +
      `  const parsed = contactSchema.safeParse(req.body);\n` +
      `  if (!parsed.success) return res.status(400).json({ error: "Invalid" });\n` +
      `  await db.messages.create({ data: parsed.data });\n` +
      `  return res.status(201).json({ ok: true });\n` +
      `}\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "VAL-001"), "VAL-001 must not fire on a Zod-validated body");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("VAL-002 - email header injection", () => {
  test("fires on a raw header built by interpolation", () => {
    const dir = makeFixture(
      "lib/mail.ts",
      "const message = `From: \"${name}\" <noreply@example.com>\\r\\nSubject: ${subject}`;\n"
    );
    try {
      assert.ok(hasFinding(runAuditOn(dir), "VAL-002"), "VAL-002 should fire on interpolated email headers");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("stays silent on a structured send call with no raw headers", () => {
    const dir = makeFixture(
      "lib/mail.ts",
      `await sendEmail({ to: parsed.data.email, subject: sanitizeHeaderValue(parsed.data.subject) });\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "VAL-002"), "VAL-002 must not fire on a structured send");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("Analyzer robustness", () => {
  test("a brace inside a string literal does not truncate the handler body", () => {
    // If brace matching were naive, the `}` inside the string would close
    // the block early, the auth check below it would fall outside the
    // extracted body, and AUTHZ-001 would false-positive.
    const dir = makeFixture(
      "api/webhook.ts",
      `export default async function handler(req, res) {\n` +
      `  const template = "payload: { id }";\n` +
      `  const user = await getUser(req);\n` +
      `  if (!user) return res.status(401).end();\n` +
      `  await db.events.create({ data: { template } });\n` +
      `  return res.status(200).end();\n` +
      `}\n`
    );
    try {
      assert.ok(!hasFinding(runAuditOn(dir), "AUTHZ-001"), "brace-in-string must not truncate the handler body");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("audit-exempt marker suppresses analyzer rules too", () => {
    const dir = makeFixture(
      "api/legacy.ts",
      `// otlc-guardian:audit-exempt - legacy route, tracked in BUGS.md\n` +
      `export default async function handler(req, res) {\n` +
      `  await sendEmail({ to: req.body.to });\n` +
      `  return res.status(200).end();\n` +
      `}\n`
    );
    try {
      const report = runAuditOn(dir);
      assert.ok(!hasFinding(report, "AUTHZ-001"), "exemption must apply to analyzer rules, not only regex rules");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 1.5.0 - Python authorization analyzer, WEB-001, WEB-002
// ---------------------------------------------------------------------------

/** Like makeFixture, for a project with several files. */
function makeProject(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "guardian-audit-test-"));
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(dir, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content, "utf8");
  }
  return dir;
}

function auditFires(files, ruleId) {
  const dir = makeProject(files);
  try {
    return hasFinding(runAuditOn(dir), ruleId);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("AUTHZ-011 - Python handler with a side effect and no auth (1.5.0)", () => {
  test("fires on a FastAPI handler that writes with no auth anywhere", () => {
    assert.ok(auditFires({ "portal/documents.py": [
      `from fastapi import APIRouter`,
      `router = APIRouter()`,
      ``,
      `@router.post("/documents")`,
      `async def create_document(payload: dict, db = Depends(get_db)):`,
      `    db.add(Document(**payload))`,
      `    db.commit()`,
      `    return {"ok": True}`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("silent when auth is a Depends in the signature", () => {
    assert.ok(!auditFires({ "portal/documents.py": [
      `@router.post("/documents")`,
      `async def create_document(`,
      `    payload: dict,`,
      `    db = Depends(get_db),`,
      `    user = Depends(get_current_user),`,
      `):`,
      `    db.add(Document(owner_id=user.id, **payload))`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("silent when auth is a decorator (Flask)", () => {
    assert.ok(!auditFires({ "app.py": [
      `@app.route("/notes", methods=["POST"])`,
      `@login_required`,
      `def add_note():`,
      `    db.session.add(Note(text=request.form["text"]))`,
      `    db.session.commit()`,
      `    return "ok"`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("silent when the router declares auth for every route in the file", () => {
    assert.ok(!auditFires({ "api.py": [
      `router = APIRouter(dependencies=[Depends(require_staff)])`,
      ``,
      `@router.delete("/things/{thing_id}")`,
      `def remove(thing_id: int, db = Depends(get_db)):`,
      `    db.delete(db.get(Thing, thing_id))`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("silent on a login route (public on purpose)", () => {
    assert.ok(!auditFires({ "auth.py": [
      `@router.post("/login")`,
      `def login(body: LoginBody, db = Depends(get_db)):`,
      `    db.add(LoginAttempt(email=body.email))`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("a comment mentioning auth does not count as auth", () => {
    assert.ok(auditFires({ "api.py": [
      `@router.post("/items")`,
      `def add_item(payload: dict, db = Depends(get_db)):`,
      `    # TODO: require current_user here`,
      `    db.add(Item(**payload))`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });

  test("silent on a read-only handler", () => {
    assert.ok(!auditFires({ "api.py": [
      `@router.get("/status")`,
      `def status():`,
      `    return {"up": True}`,
      ``,
    ].join("\n") }, "AUTHZ-011"));
  });
});

describe("AUTHZ-013 - Python handler acts on an ID with no owner or tenant check (1.5.0)", () => {
  const unsafe = [
    `@router.put("/documents/{doc_id}")`,
    `async def replace(doc_id: int, body: DocBody, db = Depends(get_db), user = Depends(get_current_user)):`,
    `    doc = db.get(Document, doc_id)`,
    `    doc.content = body.content`,
    `    db.commit()`,
    `    return doc`,
    ``,
  ].join("\n");

  test("fires when an authenticated handler mutates by ID with no ownership", () => {
    assert.ok(auditFires({ "portal/documents.py": unsafe }, "AUTHZ-013"));
  });

  test("does not double-report the same handler as AUTHZ-011", () => {
    assert.ok(!auditFires({ "portal/documents.py": unsafe }, "AUTHZ-011"));
  });

  test("silent when the query is scoped to the caller's customer", () => {
    assert.ok(!auditFires({ "portal/documents.py": [
      `@router.put("/documents/{doc_id}")`,
      `async def replace(doc_id: int, body: DocBody, db = Depends(get_db), user = Depends(get_current_user)):`,
      `    doc = db.query(Document).filter(Document.id == doc_id, Document.customer_id == user.customer_id).first()`,
      `    if doc is None:`,
      `        raise HTTPException(status_code=404)`,
      `    doc.content = body.content`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-013"));
  });

  test("fires on a Flask path parameter too", () => {
    assert.ok(auditFires({ "app.py": [
      `@app.route("/tickets/<int:ticket_id>", methods=["DELETE"])`,
      `@login_required`,
      `def delete_ticket(ticket_id):`,
      `    db.session.delete(Ticket.query.get(ticket_id))`,
      `    db.session.commit()`,
      `    return "", 204`,
      ``,
    ].join("\n") }, "AUTHZ-013"));
  });

  test("silent when the handler takes no object ID", () => {
    assert.ok(!auditFires({ "app.py": [
      `@router.post("/profile")`,
      `def update_profile(body: ProfileBody, db = Depends(get_db), user = Depends(get_current_user)):`,
      `    user.name = body.name`,
      `    db.commit()`,
      ``,
    ].join("\n") }, "AUTHZ-013"));
  });
});

describe("WEB-001 - auth token in browser storage (1.5.0)", () => {
  const fires = {
    "setItem with a token key":     `localStorage.setItem("customer_token", data.token);\n`,
    "property assignment":          `localStorage.authToken = res.token;\n`,
    "bracket assignment":           `sessionStorage["jwt"] = res.jwt;\n`,
    "refresh token via setItem":    `window.localStorage.setItem('refresh', r);\n`,
  };
  for (const [name, code] of Object.entries(fires)) {
    test(`fires: ${name}`, () => assert.ok(auditFires({ "src/auth.js": code }, "WEB-001")));
  }

  const silent = {
    "a UI preference":              `localStorage.setItem("theme", "dark");\n`,
    "reading, not writing":         `const t = localStorage.getItem("token");\n`,
    "comparison, not assignment":   `if (localStorage.token === undefined) redirect();\n`,
    "removing the token":           `localStorage.removeItem("token");\n`,
  };
  for (const [name, code] of Object.entries(silent)) {
    test(`silent: ${name}`, () => assert.ok(!auditFires({ "src/ui.js": code }, "WEB-001")));
  }
});

describe("WEB-002 - nginx server block with no CSP (1.5.0)", () => {
  const nginx = (extra = "") => [
    `server {`,
    `    listen 443 ssl;`,
    `    server_name portal.example.com;`,
    `    add_header X-Frame-Options DENY;`,
    extra,
    `    location / { proxy_pass http://app:8000; }`,
    `}`,
    ``,
  ].join("\n");

  test("fires when nginx serves the app and nothing sets a CSP", () => {
    assert.ok(auditFires({ "deploy/nginx.conf": nginx(), "app/main.py": `app = FastAPI()\n` }, "WEB-002"));
  });

  test("silent when nginx sets the header", () => {
    assert.ok(!auditFires({
      "deploy/nginx.conf": nginx(`    add_header Content-Security-Policy "default-src 'self'" always;`),
      "app/main.py": `app = FastAPI()\n`,
    }, "WEB-002"));
  });

  test("silent when the application sets it", () => {
    assert.ok(!auditFires({
      "deploy/nginx.conf": nginx(),
      "app/main.py": `response.headers["Content-Security-Policy"] = "default-src 'self'"\n`,
    }, "WEB-002"));
  });

  test("silent when the project has no nginx config", () => {
    assert.ok(!auditFires({ "app/main.py": `app = FastAPI()\n` }, "WEB-002"));
  });

  test("silent on a .conf file that is not an nginx server block", () => {
    assert.ok(!auditFires({ "tool.conf": `[section]\nkey = value\n`, "app/main.py": `x = 1\n` }, "WEB-002"));
  });
});

// ---------------------------------------------------------------------------
// BUG-041: partial scans (a subfolder or one file of a project)
// ---------------------------------------------------------------------------

describe("BUG-041 - project checks on a partial scan see the whole project", () => {
  // DevNeural's shape: the health route lives in one folder, the audit is
  // pointed at another.
  const server = (withHealth) => ({
    "package.json":           JSON.stringify({ dependencies: { express: "4.21.0" } }),
    "src/dashboard/routes.ts": withHealth ? `router.get("/health", (_req, res) => res.json({ ok: true }));\n` : `router.get("/stats", stats);\n`,
    "src/capture/hooks/session.ts": `export function onSession(e: unknown) { return e; }\n`,
  });
  const auditAt = (files, rel) => {
    const dir = makeProject(files);
    try {
      const report = spawnSync("node", [AUDIT_SCRIPT, path.join(dir, rel), "--json"], { encoding: "utf8" });
      return JSON.parse(report.stdout);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  test("auditing a subfolder of a project with a health route does not report DEP-001 (DevNeural's case)", () => {
    assert.ok(!hasFinding(auditAt(server(true), "src/capture/hooks"), "DEP-001"));
  });

  test("auditing one file of a project with a health route does not report DEP-001", () => {
    assert.ok(!hasFinding(auditAt(server(true), "src/capture/hooks/session.ts"), "DEP-001"));
  });

  test("a project that really has no health route still reports DEP-001 on a subfolder scan", () => {
    assert.ok(hasFinding(auditAt(server(false), "src/capture/hooks"), "DEP-001"));
  });

  test("WEB-002 on a subfolder sees CSP middleware elsewhere in the project", () => {
    const files = {
      "requirements.txt":   "fastapi==0.115.0\n",
      "deploy/nginx.conf":  "server {\n  listen 80;\n  server_name app.example.com;\n}\n",
      "app/security.py":    "app.add_middleware(CSPMiddleware)  # sets Content-Security-Policy\n",
      "app/routes/items.py": "def list_items():\n    return []\n",
    };
    assert.ok(!hasFinding(auditAt(files, "app/routes"), "WEB-002"));
  });

  test("a single file given as the target is scanned", () => {
    const report = auditAt({ "package.json": "{}", "src/calc.js": "const r = eval(input);\n" }, "src/calc.js");
    assert.ok(hasFinding(report, "INJ-001"), "the target file itself must be audited");
  });
});

// ---------------------------------------------------------------------------
// Rules that had no test before 2026-11-10 (gate plan, step 0).
// One sample each rule must flag and one it must not. A rule that fails
// its own fixture is logged in BUGS.md; the fixture is not loosened.
// Secret-shaped values are assembled at runtime so this file carries none.
// ---------------------------------------------------------------------------

describe("Rules with no prior test: bad sample fires, good sample is silent", () => {
  const big = (n) => "x".repeat(n);
  const cases = [
    { id: "SEC-002", bad: { "src/aws.js": `const key = "${"AKIA" + "IOSFODNN7EXAMPLE"}";\n` },
                     good: { "src/aws.js": `const key = process.env.AWS_ACCESS_KEY_ID;\n` } },
    { id: "SEC-003", bad: { "src/gh.js": `const token = "${"ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}";\n` },
                     good: { "src/gh.js": `const token = process.env.GITHUB_TOKEN; // ghp_ prefix expected\n` } },
    { id: "SEC-004", bad: { "src/key.js": `const pem = \`${"-----BEGIN RSA " + "PRIVATE KEY-----"}\nMIIE...\`;\n` },
                     good: { "src/key.js": `const pem = \`-----BEGIN PUBLIC KEY-----\nMIIB...\`;\n` } },
    { id: "SEC-005", bad: { "src/db.js": `const config = { password: "${"hunter" + "2secret"}" };\n` },
                     good: { "src/db.js": `const config = { password: process.env.DB_PASSWORD };\n` } },
    { id: "ERR-002", bad: { "src/job.js": `try { run(); } catch (err) { console.log(err); }\n` },
                     good: { "src/job.js": `try { run(); } catch (err) { logger.error({ err }, "run failed"); throw err; }\n` } },
    { id: "API-001", bad: { "src/routes.js": `router.get("/api/users", listUsers);\n` },
                     good: { "src/routes.js": `router.get("/api/v1/users", listUsers);\n` } },
    { id: "INJ-001", bad: { "src/calc.js": `const result = eval(req.query.expr);\n` },
                     good: { "src/calc.js": `const result = JSON.parse(req.query.expr);\n` } },
    { id: "INJ-003", bad: { "src/Post.jsx": `export const Post = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n` },
                     good: { "src/Post.jsx": `export const Post = ({ text }) => <div>{text}</div>;\n` } },
    { id: "DEP-002", bad: { ".env": `API_URL=https://api.example.com\n`, "src/index.js": `export {};\n` },
                     good: { ".env.example": `API_URL=\n`, "src/index.js": `export {};\n` } },
    { id: "REP-001", bad: { "index.html": `<html><body><script>var a = "${big(21000)}";</script></body></html>\n` },
                     good: { "index.html": `<html><body><script src="app.3f9a.js"></script><script>init();</script></body></html>\n` } },
    { id: "REP-002", bad: { "public/data.js": `window.DATA = "${big(25000)}";\n` },
                     good: { "public/data.js": `window.DATA = [\n${Array.from({ length: 50 }, () => `  "${big(500)}",`).join("\n")}\n];\n` } },
    { id: "REP-003", bad: { "index.html": `<button onclick="buy()">Buy</button>\n` },
                     good: { "index.html": `<button id="buy">Buy</button>\n` } },
    { id: "REP-004", bad: { "index.html": `<a href="javascript:void(0)">Menu</a>\n` },
                     good: { "index.html": `<a href="/menu">Menu</a>\n` } },
    { id: "REP-005", bad: { "src/logo.js": `export const logo = "data:image/png;base64,${"QUFB".repeat(1100)}";\n` },
                     good: { "src/logo.js": `export const logo = "data:image/png;base64,${"QUFB".repeat(20)}";\n` } },
  ];

  // BUG-039: a bare .env has no extension, so the walker never collects it.
  const openBugs = { "DEP-002 bad": "BUG-039" };

  for (const { id, bad, good } of cases) {
    const badName = `${id} flags its bad sample`;
    const badFn = () => assert.ok(auditFires(bad, id), `${id} did not fire on ${Object.keys(bad).join(", ")}`);
    if (openBugs[`${id} bad`]) knownBug(openBugs[`${id} bad`], badName, badFn);
    else test(badName, badFn);
    test(`${id} is silent on its good sample`, () => assert.ok(!auditFires(good, id), `${id} fired on its good sample`));
  }

  knownBug("BUG-040", "INJ-001 (eval) is silent on a function whose name ends in 'eval'", () => {
    assert.ok(!auditFires({ "src/search.js": `const docs = retrieval(query);\n` }, "INJ-001"));
  });
});

// ---------------------------------------------------------------------------
// BUG-051: a target that does not exist, or a mistyped flag, is an error
// ---------------------------------------------------------------------------
//
// A path that did not exist scanned 0 files and exited 0 with "No issues
// found", even with --fail-on-error, so a CI typo turned the gate into a
// pass. An unknown flag was ignored the same way (--fail-on-eror ran a
// non-failing audit). Both now exit 2, the usage-error code, with a
// message on stderr and nothing on stdout.

function runAuditArgs(...args) {
  return spawnSync("node", [AUDIT_SCRIPT, ...args], { encoding: "utf8", shell: false });
}

function withTempProject(files, fn) {
  const dir = makeProject(files);
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("BUG-051: bad audit arguments exit 2 instead of passing", () => {
  test("a target that does not exist exits 2, even with --fail-on-error", () => {
    withTempProject({}, (dir) => {
      const r = runAuditArgs(path.join(dir, "does-not-exist"), "--fail-on-error");
      assert.equal(r.status, 2, `exit ${r.status}: ${r.stdout.slice(0, 200)}`);
      assert.ok(/does not exist/.test(r.stderr), r.stderr.slice(0, 200));
      assert.ok(!/No issues found/.test(r.stdout + r.stderr));
    });
  });

  test("a missing target in --json mode exits 2 and writes no JSON to stdout", () => {
    withTempProject({}, (dir) => {
      const r = runAuditArgs(path.join(dir, "nope"), "--json");
      assert.equal(r.status, 2);
      assert.equal(r.stdout.trim(), "");
    });
  });

  test("a mistyped flag exits 2 and names the flag", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const r = runAuditArgs(dir, "--fail-on-eror");
      assert.equal(r.status, 2);
      assert.ok(/--fail-on-eror/.test(r.stderr));
    });
  });

  test("two targets exit 2 instead of silently scanning the first", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const r = runAuditArgs(dir, path.join(dir, "src"));
      assert.equal(r.status, 2);
    });
  });

  test("--help prints usage and exits 0 without scanning", () => {
    const r = runAuditArgs("--help");
    assert.equal(r.status, 0);
    assert.ok(/Usage/i.test(r.stdout));
    assert.ok(!/SAFETY AUDIT STARTING/.test(r.stdout + r.stderr));
  });

  test("an existing target with known flags still runs", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const r = runAuditArgs(dir, "--json", "--fail-on-error");
      assert.equal(r.status, 0, r.stderr.slice(-300));
      JSON.parse(r.stdout);
    });
  });
});

// ---------------------------------------------------------------------------
// BUG-053: importing the audit module must not run an audit
// ---------------------------------------------------------------------------
//
// package.json exports the engine as "./audit", but the CLI block at the
// bottom ran on every load, so `import { runAudit } from "otlc-guardian/audit"`
// audited the importer's cwd, printed a report and could exit the process.

function importAuditIn(dir) {
  const code = `const m = await import(${JSON.stringify(pathToFileURL(AUDIT_SCRIPT).href)});\n` +
               `process.stdout.write("IMPORTED " + typeof m.runAudit + " " + Array.isArray(m.AUDIT_RULES));\n`;
  return spawnSync("node", ["--input-type=module", "-e", code], { cwd: dir, encoding: "utf8", shell: false });
}

describe("BUG-053: importing security/03-audit.js does not run an audit", () => {
  test("an import prints nothing but the importer's own output and exits 0", () => {
    withTempProject({ "src/a.js": "try { run(); } catch (e) {}\n" }, (dir) => {
      const r = importAuditIn(dir);
      assert.equal(r.status, 0, r.stderr.slice(0, 300));
      assert.equal(r.stdout, "IMPORTED function true");
      assert.ok(!/SAFETY AUDIT/.test(r.stdout + r.stderr), (r.stdout + r.stderr).slice(0, 300));
    });
  });

  test("runAudit() is still callable after an import", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const code = `const { runAudit } = await import(${JSON.stringify(pathToFileURL(AUDIT_SCRIPT).href)});\n` +
                   `const findings = runAudit(${JSON.stringify(dir)}, { outputJson: true });\n` +
                   `process.stderr.write("RETURNED " + Array.isArray(findings));\n`;
      const r = spawnSync("node", ["--input-type=module", "-e", code], { encoding: "utf8", shell: false });
      assert.equal(r.status, 0, r.stderr.slice(-300));
      assert.ok(/RETURNED true/.test(r.stderr));
    });
  });

  test("running the file directly still runs the CLI", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const r = spawnSync("node", [AUDIT_SCRIPT, dir, "--json"], { encoding: "utf8", shell: false });
      assert.equal(r.status, 0);
      assert.ok(Array.isArray(JSON.parse(r.stdout).findings));
    });
  });

  test("running it through a symlink (npm's bin link on Unix) still runs the CLI", () => {
    withTempProject({ "src/a.js": "export const a = 1;\n" }, (dir) => {
      const link = path.join(dir, "guardian-audit.mjs");
      try {
        symlinkSync(AUDIT_SCRIPT, link);
      } catch (e) {
        if (e.code === "EPERM") return; // Windows without symlink rights: npm uses .cmd shims there instead
        throw e;
      }
      const r = spawnSync("node", [link, dir, "--json"], { encoding: "utf8", shell: false });
      assert.equal(r.status, 0, r.stderr.slice(-300));
      assert.ok(Array.isArray(JSON.parse(r.stdout).findings), "the CLI did not run through the link");
    });
  });
});

// ---------------------------------------------------------------------------
// BUG-055: DEP-001 must survive a file it cannot read
// ---------------------------------------------------------------------------
//
// A file can vanish or lose its read permission between collectFiles()
// and DEP-001's check. The check is called directly with a path that no
// longer exists, which is the same failure without a race in the test.

const { AUDIT_RULES } = await import(pathToFileURL(AUDIT_SCRIPT).href);

describe("BUG-055: DEP-001 does not crash on an unreadable file", () => {
  const dep001 = AUDIT_RULES.find((r) => r.id === "DEP-001");

  test("a vanished file is skipped with a warning, and a readable health route still counts", () => {
    withTempProject({
      "package.json": JSON.stringify({ dependencies: { express: "4.21.2" } }),
      "src/server.js": "app.get('/health', (req, res) => res.send('ok'));\n",
    }, (dir) => {
      const gone = path.join(dir, "src", "gone.js");
      const warnings = [];
      const origWarn = console.warn;
      console.warn = (msg) => { warnings.push(String(msg)); };
      let fired;
      try {
        fired = dep001.checkFn([gone, path.join(dir, "src", "server.js")], dir);
      } finally {
        console.warn = origWarn;
      }
      assert.equal(fired, false, "the health route in server.js was not seen");
      assert.ok(warnings.some((w) => /DEP-001/.test(w) && /gone\.js/.test(w)), `no warning naming the file: ${warnings.join(" | ")}`);
    });
  });

  test("with no readable health route the rule still fires", () => {
    withTempProject({
      "package.json": JSON.stringify({ dependencies: { express: "4.21.2" } }),
      "src/server.js": "app.listen(3000);\n",
    }, (dir) => {
      const origWarn = console.warn;
      console.warn = () => {};
      let fired;
      try {
        fired = dep001.checkFn([path.join(dir, "src", "gone.js"), path.join(dir, "src", "server.js")], dir);
      } finally {
        console.warn = origWarn;
      }
      assert.equal(fired, true);
    });
  });
});

// ---------------------------------------------------------------------------
// RESULTS
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(60)}`);
console.log(`🔍 [OTLC GUARDIAN] audit.test.js RESULTS`);
console.log(`   Passed : ${passed}`);
console.log(`   Failed : ${failed}`);
console.log(`   Known  : ${knownBugs} (open bugs reproduced, see BUGS.md)`);
console.log(`   Total  : ${passed + failed + knownBugs}`);

if (failures.length > 0) {
  console.error(`\n❌ FAILURES:`);
  failures.forEach((f) => console.error(`   → ${f.name}: ${f.error}`));
  process.exit(1);
} else {
  console.log(`\n✅ All audit tests passed.\n`);
  process.exit(0);
}
