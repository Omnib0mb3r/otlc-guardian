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
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "fs";
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

  for (const { id, bad, good } of cases) {
    test(`${id} flags its bad sample`, () => assert.ok(auditFires(bad, id), `${id} did not fire on ${Object.keys(bad).join(", ")}`));
    test(`${id} is silent on its good sample`, () => assert.ok(!auditFires(good, id), `${id} fired on its good sample`));
  }

  // BUG-040: the pattern had no word boundary, so `retrieval(` fired.
  test("INJ-001 (eval) is silent on a function whose name ends in 'eval'", () => {
    assert.ok(!auditFires({ "src/search.js": `const docs = retrieval(query);\n` }, "INJ-001"));
  });

  for (const [label, line] of [
    ["window.eval(", "window.eval(code);"],
    ["eval with a space before the parenthesis", "eval (code);"],
    ["new Function(", `const fn = new Function("a", body);`],
  ]) {
    test(`INJ-001 fires on ${label}`, () => {
      assert.ok(auditFires({ "src/run.js": line + "\n" }, "INJ-001"));
    });
  }

  for (const [label, line] of [
    ["Puppeteer's page.$eval(", "const t = await page.$eval('h1', (el) => el.textContent);"],
    ["evaluate(", "const v = evaluate(expr);"],
    ["a Function type reference", "const handlers: Function[] = [];"],
  ]) {
    test(`INJ-001 is silent on ${label}`, () => {
      assert.ok(!auditFires({ "src/run.ts": line + "\n" }, "INJ-001"));
    });
  }
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
// BUG-054: audit secret rules cover every runtime secret pattern
// ---------------------------------------------------------------------------
//
// The audit and the runtime guard keep separate tables (the audit is one
// self-contained file). This block is what keeps them in step: every
// GUARD-SEC id in security/01-injection-guard.js must be listed in
// SECRET_PARITY with the audit rule that catches the same secret, or
// carry a reason it is not mirrored. A runtime pattern added without an
// audit counterpart fails the first test.

const GUARD_SCRIPT = path.resolve(__dirname, "..", "security", "01-injection-guard.js");
const { scan: guardScan } = await import(pathToFileURL(GUARD_SCRIPT).href);

const SECRET_PARITY = {
  "GUARD-SEC-001":  { audit: "SEC-001",  sample: "sk-proj-" + "a1B2c3D4e5".repeat(3) },
  "GUARD-SEC-010":  { audit: "SEC-010",  sample: "sk-ant-oat01-" + "a".repeat(40) },
  "GUARD-SEC-001b": { audit: "SEC-001b", sample: "sk-" + "a1B2c3D4e5".repeat(3) },
  "GUARD-SEC-002":  { audit: "SEC-012",  sample: "AIza" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R" },
  "GUARD-SEC-003":  { audit: "SEC-003",  sample: "ghp_" + "a".repeat(36) },
  "GUARD-SEC-004":  { audit: "SEC-003",  sample: "gho_" + "a".repeat(36) },
  "GUARD-SEC-005":  { audit: "SEC-002",  sample: "AKIA" + "ABCDEFGHIJKLMNOP" },
  "GUARD-SEC-006":  { audit: null, reason: "keyword plus 40 base64 characters is too loose for source code; SEC-005 and SEC-006 cover quoted password and api key literals" },
  "GUARD-SEC-007":  { audit: "SEC-004",  sample: "-----BEGIN OPENSSH PRIVATE KEY-----" },
  "GUARD-SEC-008":  { audit: "SEC-005",  sample: "hunter2hunter2", line: (s) => `const password = "${s}";` },
  "GUARD-SEC-009":  { audit: "SEC-006",  sample: "abcd1234efgh", line: (s) => `const api_key = "${s}";` },
  "GUARD-SEC-011":  { audit: "SEC-011",  sample: "postgresql://admin:hunter2@db.internal:5432/prod" },
  "GUARD-SEC-012":  { audit: "SEC-003",  sample: "github_pat_" + "A1b2C3d4E5".repeat(6) },
  "GUARD-SEC-013":  { audit: "SEC-003",  sample: "ghs_" + "a".repeat(36) },
  "GUARD-SEC-014":  { audit: "SEC-013",  sample: "xoxb-123456789012-abcdefghijkl" },
  "GUARD-SEC-015":  { audit: "SEC-014",  sample: "sk_live_" + "a".repeat(24) },
};

describe("BUG-054: audit secret rules cover the runtime secret patterns", () => {
  test("every runtime GUARD-SEC id is listed in SECRET_PARITY", () => {
    const source = readFileSync(GUARD_SCRIPT, "utf8");
    const runtimeIds = [...source.matchAll(/id:\s*"(GUARD-SEC-[0-9]+b?)"/g)].map((m) => m[1]);
    assert.ok(runtimeIds.length > 10, `found only ${runtimeIds.length} runtime secret ids`);
    assert.deepEqual([...new Set(runtimeIds)].sort(), Object.keys(SECRET_PARITY).sort());
  });

  const mirrored = Object.entries(SECRET_PARITY).filter(([, p]) => p.audit);
  const files = {};
  for (const [guardId, p] of mirrored) {
    files[`src/${guardId}.js`] = (p.line ? p.line(p.sample) : `const value = "${p.sample}";`) + "\n";
  }
  const dir = makeProject(files);
  let report;
  try {
    report = runAuditOn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  for (const [guardId, p] of mirrored) {
    test(`${guardId} sample is caught by the runtime and by audit ${p.audit}`, () => {
      const runtime = guardScan(p.line ? p.line(p.sample) : p.sample, "secrets").violations.map((v) => v.id);
      assert.ok(runtime.includes(guardId), `runtime gave ${runtime}`);
      const audit = report.findings
        .filter((f) => path.basename(f.file) === `${guardId}.js`)
        .map((f) => f.rule.id);
      assert.ok(audit.includes(p.audit), `audit gave ${audit.join(", ") || "nothing"}`);
    });
  }

  for (const header of ["EC", "ENCRYPTED", "RSA", "DSA"]) {
    test(`SEC-004 catches the ${header} private key header`, () => {
      assert.ok(auditFires({ "src/k.js": `const k = "-----BEGIN ${header} PRIVATE KEY-----";\n` }, "SEC-004"));
    });
  }

  test("SEC-004 does not fire on a public key header", () => {
    assert.ok(!auditFires({ "src/k.js": `const k = "-----BEGIN PUBLIC KEY-----";\n` }, "SEC-004"));
  });
});

// ---------------------------------------------------------------------------
// BUG-056: an allowlist entry with an empty reason is rejected
// ---------------------------------------------------------------------------

describe("BUG-056: allowlist entries need a non-empty reason", () => {
  const secretFile = `const k = "${"AKIA" + "ABCDEFGHIJKLMNOP"}";\n`;

  for (const [label, line] of [
    ["an empty reason", "src/a.js  # reason:"],
    ["a reason of only spaces", "src/a.js  # reason:   "],
  ]) {
    test(`${label} is ignored with a visible warning`, () => {
      withTempProject({ "src/a.js": secretFile, "security/.audit-allowlist": line + "\n" }, (dir) => {
        const r = runAuditArgs(dir, "--json");
        assert.equal(r.status, 0, r.stderr.slice(0, 300));
        assert.ok(hasFinding(JSON.parse(r.stdout), "SEC-002"), "the file was exempted by an entry with no reason");
        assert.ok(/\.audit-allowlist:1 - reason is empty, line ignored/.test(r.stderr), r.stderr.slice(0, 300));
      });
    });
  }

  test("an entry with a reason still exempts the file", () => {
    withTempProject({ "src/a.js": secretFile, "security/.audit-allowlist": "src/a.js  # reason: fixture key\n" }, (dir) => {
      const r = runAuditArgs(dir, "--json");
      assert.ok(!hasFinding(JSON.parse(r.stdout), "SEC-002"));
      assert.ok(!/reason is empty/.test(r.stderr));
    });
  });
});

// ---------------------------------------------------------------------------
// BUG-057: only a standalone marker comment exempts a file
// ---------------------------------------------------------------------------

describe("BUG-057: the audit-exempt marker must be its own comment line", () => {
  const M = "otlc-guardian:" + "audit-exempt";
  const body = `const k = "${"AKIA" + "ABCDEFGHIJKLMNOP"}";\n`;
  const exempt = (name, head) => {
    const report = withTempProject({ [name]: head + "\n" + body }, (dir) => runAuditOn(dir));
    return report.exempt.marker.length === 1 && !hasFinding(report, "SEC-002");
  };

  for (const [label, name, head] of [
    ["a // line comment", "src/a.js", `// ${M} - legacy fixture, tracked in BUGS.md`],
    ["an indented // comment", "src/a.js", `  //${M}`],
    ["a # comment in Python", "src/a.py", `# ${M}  fixture`],
    ["a block comment", "src/a.js", `/* ${M} */`],
    ["a JSDoc continuation line", "src/a.js", `/**\n * ${M} - generated file\n */`],
    ["an HTML comment", "src/a.js", `<!-- ${M} -->`],
  ]) {
    test(`${label} exempts the file`, () => assert.ok(exempt(name, head)));
  }

  for (const [label, head] of [
    ["the marker in a string", `const MARKER = "${M}";`],
    ["the marker in a regex", `const re = /${M}/;`],
    ["a comment that talks about the marker", `// Add the ${M} marker to skip a file.`],
    ["a backquoted mention in a comment", `// the \`${M}\` marker is supported`],
    ["a trailing comment after code", `run(); // ${M}`],
    ["a longer word that starts with the marker", `// ${M}ion`],
  ]) {
    test(`${label} does not exempt the file`, () => assert.ok(!exempt("src/a.js", head)));
  }
});

// ---------------------------------------------------------------------------
// BUG-059: what an audit exemption means for the project checks
// ---------------------------------------------------------------------------
//
// An exemption silences findings about a file; it never hides the file
// as evidence. An absence check (DEP-001, WEB-002: "nothing in the
// project does X") still reads exempt files, so a health route or a CSP
// header in one still counts. A presence check (DEP-002: "this file is
// committed") is a finding about the file itself, so an exempt file is
// left out of its evidence.

describe("BUG-059: exemptions and the project checks", () => {
  const express = JSON.stringify({ dependencies: { express: "4.21.2" } });

  test("DEP-001: a health route in an allowlisted file still counts", () => {
    assert.ok(!auditFires({
      "package.json": express,
      "src/server.js": "app.get('/health', (req, res) => res.send('ok'));\napp.listen(3000);\n",
      "security/.audit-allowlist": "src/server.js  # reason: fixture\n",
    }, "DEP-001"));
  });

  test("DEP-001: a health route in a marker-exempt file still counts", () => {
    assert.ok(!auditFires({
      "package.json": express,
      "src/server.js": "// otlc-guardian:" + "audit-exempt - fixture\napp.get('/health', (req, res) => res.send('ok'));\napp.listen(3000);\n",
    }, "DEP-001"));
  });

  test("WEB-002: a CSP header set in an allowlisted file still clears it", () => {
    assert.ok(!auditFires({
      "nginx/site.conf": "server {\n  listen 80;\n  server_name example.com;\n}\n",
      "src/app.js": "app.use(helmet());\n",
      "security/.audit-allowlist": "src/app.js  # reason: fixture\n",
    }, "WEB-002"));
  });

  test("WEB-002 still fires when no file sets a CSP", () => {
    assert.ok(auditFires({
      "nginx/site.conf": "server {\n  listen 80;\n  server_name example.com;\n}\n",
      "src/app.js": "export const a = 1;\n",
    }, "WEB-002"));
  });

  test("DEP-002: an allowlisted .env is not reported", () => {
    assert.ok(!auditFires({
      ".env": "PORT=3000\n",
      "security/.audit-allowlist": ".env  # reason: committed defaults, no secrets\n",
    }, "DEP-002"));
  });
});

// ---------------------------------------------------------------------------
// BUG-052: test-file exclusions judge the path inside the project
// ---------------------------------------------------------------------------
//
// TEST_FILE_EXCLUDES used to run on the absolute path, so a project that
// lives under a folder named test, tests or spec lost every
// test-excluded rule on every file.

describe("BUG-052: a project under a test-named folder keeps its rules", () => {
  const withNested = (parent, files, fn) => withTempProject({}, (base) => {
    const root = path.join(base, parent, "proj");
    mkdirSync(path.join(root, ".git"), { recursive: true });
    for (const [name, content] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      writeFileSync(path.join(root, name), content, "utf8");
    }
    return fn(root);
  });

  for (const parent of ["tests", "test", "spec", "__tests__"]) {
    test(`ERR-003 fires in src/ of a project under ${parent}/`, () => {
      withNested(parent, { "src/a.js": "console.log('x');\n" }, (root) => {
        assert.ok(hasFinding(runAuditOn(root), "ERR-003"));
      });
    });
  }

  test("a tests/ folder inside the project is still excluded", () => {
    withNested("tests", { "tests/a.js": "console.log('x');\n", "src/test_b.py": "print('x')\n" }, (root) => {
      const report = runAuditOn(root);
      assert.ok(!hasFinding(report, "ERR-003"), JSON.stringify(report.findings.map((f) => [f.rule.id, f.file])));
    });
  });

  test("a subfolder scan of tests/ inside the project is still excluded", () => {
    withNested("spec", { "tests/a.js": "console.log('x');\n" }, (root) => {
      assert.ok(!hasFinding(runAuditOn(path.join(root, "tests")), "ERR-003"));
    });
  });

  test("a root-level test_*.py is still excluded, and app.py beside it is not", () => {
    const url = `URL = "http://localhost:3000"\n`;
    withNested("tests", { "test_app.py": url, "app.py": url, "requirements.txt": "fastapi\n" }, (root) => {
      const files = runAuditOn(root).findings.filter((f) => f.rule.id === "CFG-001").map((f) => path.basename(f.file));
      assert.deepEqual(files, ["app.py"]);
    });
  });
});

// ---------------------------------------------------------------------------
// BUG-039: DEP-002 sees a .env, and asks git whether it is kept out
// ---------------------------------------------------------------------------
//
// A bare .env has no extension, so the walker never collected it and
// DEP-002 could not fire. Once it is collected, a .env that git ignores
// and does not track is the correct setup, not a finding.

function git(dir, ...args) {
  return spawnSync("git", ["-C", dir, ...args], { encoding: "utf8", shell: false });
}
const HAS_GIT = git(".", "--version").status === 0;

describe("BUG-039: DEP-002 reports a .env that git does not keep out", () => {
  const env = { ".env": "API_URL=https://api.example.com\n", "src/index.js": "export {};\n" };

  test("a .env outside any git repository is reported", () => {
    assert.ok(auditFires(env, "DEP-002"));
  });

  test("a .env given as the single-file target is reported", () => {
    withTempProject(env, (dir) => {
      assert.ok(hasFinding(runAuditOn(path.join(dir, ".env")), "DEP-002"));
    });
  });

  test("a .env.example alone is not reported", () => {
    assert.ok(!auditFires({ ".env.example": "API_URL=\n" }, "DEP-002"));
  });

  if (!HAS_GIT) {
    console.log("  (git not on PATH: the git cases below are skipped)");
    return;
  }

  const inRepo = (files, setup) => withTempProject(files, (dir) => {
    assert.equal(git(dir, "init", "-q").status, 0);
    setup?.(dir);
    return hasFinding(runAuditOn(dir), "DEP-002");
  });

  test("a .env that .gitignore covers and git does not track is not reported", () => {
    assert.ok(!inRepo({ ...env, ".gitignore": ".env\n" }));
  });

  test("a .env that git tracks is reported even when .gitignore lists it", () => {
    assert.ok(inRepo({ ...env, ".gitignore": ".env\n" }, (dir) => {
      assert.equal(git(dir, "add", "-f", ".env").status, 0);
    }));
  });

  test("a .env in a repository that does not ignore it is reported", () => {
    assert.ok(inRepo(env));
  });

  test("the secret rules still do not read a bare .env", () => {
    const report = withTempProject({ ".env": `KEY=${"AKIA" + "ABCDEFGHIJKLMNOP"}\n` }, (dir) => runAuditOn(dir));
    assert.ok(!hasFinding(report, "SEC-002"));
  });

  test("a health variable in .env does not satisfy DEP-001", () => {
    assert.ok(auditFires({
      "package.json": JSON.stringify({ dependencies: { express: "4.21.2" } }),
      "src/server.js": "app.listen(3000);\n",
      ".env": "HEALTHCHECK_URL=/healthz\n",
    }, "DEP-001"));
  });
});

// ---------------------------------------------------------------------------
// BUG-030: AUTHZ-013 needs an ownership check tied to the caller
// ---------------------------------------------------------------------------
//
// A 404 says the row is missing, not whose it is, and a user_id or org_id
// path parameter is supplied by the caller. Neither is an ownership check.

describe("BUG-030: AUTHZ-013 catches the textbook IDOR", () => {
  const handler = (decorator, signature, ...body) => [decorator, signature, ...body.map((l) => "    " + l), ""].join("\n");
  const fires = (src) => auditFires({ "portal/documents.py": src }, "AUTHZ-013");
  const authed = "db = Depends(get_db), user = Depends(get_current_user)";

  test("fires when the only check is a 404 for a missing row", () => {
    assert.ok(fires(handler(
      `@router.delete("/documents/{doc_id}")`,
      `async def remove(doc_id: int, ${authed}):`,
      `doc = db.get(Document, doc_id)`,
      `if doc is None:`,
      `    raise HTTPException(status_code=404)`,
      `db.delete(doc)`,
      `db.commit()`,
    )));
  });

  test("fires when user_id comes from the path", () => {
    assert.ok(fires(handler(
      `@router.delete("/users/{user_id}/documents/{doc_id}")`,
      `async def remove(user_id: int, doc_id: int, ${authed}):`,
      `doc = db.query(Document).filter(Document.user_id == user_id, Document.id == doc_id).first()`,
      `db.delete(doc)`,
      `db.commit()`,
    )));
  });

  test("fires when org_id comes from the path", () => {
    assert.ok(fires(handler(
      `@router.put("/orgs/{org_id}/documents/{doc_id}")`,
      `async def replace(org_id: int, doc_id: int, body: DocBody, ${authed}):`,
      `doc = db.query(Document).filter_by(org_id=org_id, id=doc_id).first()`,
      `doc.content = body.content`,
      `db.commit()`,
    )));
  });

  for (const [label, check] of [
    ["filter_by(owner_id=current_user.id)", `doc = db.query(Document).filter_by(id=doc_id, owner_id=current_user.id).first()`],
    ["a comparison with the caller, then 403", `doc = db.get(Document, doc_id)\n    if doc.owner_id != user.id:\n        raise HTTPException(status_code=403)`],
    ["the caller on the left", `doc = db.get(Document, doc_id)\n    if user.id != doc.owner_id:\n        abort(403)`],
    ["a tenant column scoped to the caller", `doc = db.query(Document).filter(Document.id == doc_id, Document.tenant_id == user.tenant_id).first()`],
    ["an authorize() helper", `doc = db.get(Document, doc_id)\n    authorize(user, "delete", doc)`],
    ["a name taken from the caller first (BUG-069 parity)", `uid = current_user.id\n    doc = db.query(Document).filter_by(id=doc_id, owner_id=uid).first()`],
    ["a name taken from the caller, path id named user_id elsewhere", `owner = user.id\n    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == owner).first()`],
  ]) {
    test(`silent with ${label}`, () => {
      assert.ok(!fires(handler(
        `@router.delete("/documents/{doc_id}")`,
        `async def remove(doc_id: int, ${authed}):`,
        check,
        `db.delete(doc)`,
        `db.commit()`,
      )));
    });
  }
});

// ---------------------------------------------------------------------------
// BUG-031: AUTHZ-011 blind spots
// ---------------------------------------------------------------------------

describe("BUG-031: AUTHZ-011 router dependencies, public routes, api_key", () => {
  const fires = (src) => auditFires({ "api/routes.py": src }, "AUTHZ-011");
  const write = (decorator, signature = "def handle(payload: dict, db = Depends(get_db)):") =>
    [decorator, signature, "    db.add(Item(**payload))", "    db.commit()", ""].join("\n");

  test("a router-level Depends(get_db) is not auth", () => {
    assert.ok(fires([`router = APIRouter(dependencies=[Depends(get_db)])`, "", write(`@router.post("/items")`)].join("\n")));
  });

  test("an auth dependency on one router does not cover another router's handlers", () => {
    const src = [
      `admin = APIRouter(dependencies=[Depends(require_admin)])`,
      `public = APIRouter()`,
      "",
      write(`@admin.post("/admin/items")`),
      write(`@public.post("/items")`),
    ].join("\n");
    const report = withTempProject({ "api/routes.py": src }, (dir) => runAuditOn(dir));
    const lines = report.findings.filter((f) => f.rule.id === "AUTHZ-011").map((f) => f.line);
    assert.deepEqual(lines, [9]);
  });

  test("a router-level auth dependency nested in a call still counts", () => {
    assert.ok(!fires([`router = APIRouter(prefix="/x", dependencies=[Depends(require_role(["admin"]))])`, "", write(`@router.post("/items")`)].join("\n")));
  });

  test("a route decorator's dependencies=[Depends(get_db)] does not silence the file", () => {
    const src = [
      write(`@router.post("/a", dependencies=[Depends(get_db)])`),
      write(`@router.post("/b")`),
    ].join("\n");
    assert.ok(fires(src));
  });

  test("a route decorator's auth dependency covers that route", () => {
    assert.ok(!fires(write(`@router.post("/a", dependencies=[Depends(verify_token)])`)));
  });

  test("/api/tokens/{token_id} is not a public route", () => {
    assert.ok(fires(write(`@router.delete("/api/tokens/{token_id}")`, "def revoke(token_id: int, payload: dict, db = Depends(get_db)):")));
  });

  for (const route of ["/auth/login", "/token", "/webhooks/stripe", "/users/verify-email", "/password/reset", "/sign-up"]) {
    test(`${route} is still public on purpose`, () => {
      assert.ok(!fires(write(`@router.post("${route}")`)));
    });
  }

  test("a bare api_key mention is not auth", () => {
    assert.ok(fires([
      `@router.post("/keys")`,
      `def create_key(payload: dict, db = Depends(get_db)):`,
      `    db.add(ApiKey(api_key=secrets.token_hex(16), name=payload["name"]))`,
      `    db.commit()`,
      ``,
    ].join("\n")));
  });

  for (const [label, signature] of [
    ["Depends(get_api_key)", "def handle(payload: dict, db = Depends(get_db), key = Depends(get_api_key)):"],
    ["an APIKeyHeader security dependency", "def handle(payload: dict, db = Depends(get_db), key: str = Security(APIKeyHeader(name=\"X-API-Key\"))):"],
  ]) {
    test(`${label} is auth`, () => {
      assert.ok(!fires(write(`@router.post("/items")`, signature)));
    });
  }
});

// ---------------------------------------------------------------------------
// BUG-032: a read is not an unauthenticated side effect
// ---------------------------------------------------------------------------

describe("BUG-032: AUTHZ-011 does not report reads", () => {
  const fires = (...body) => auditFires({ "api/reports.py": [
    `@router.get("/reports")`,
    `def list_reports(db = Depends(get_db)):`,
    ...body.map((l) => "    " + l),
    ``,
  ].join("\n") }, "AUTHZ-011");

  for (const [label, body] of [
    ["db.execute(select(...))", [`rows = db.execute(select(Report).where(Report.public == True)).scalars().all()`, `return rows`]],
    ["a select statement built first", [`stmt = select(Report).order_by(Report.created)`, `return db.execute(stmt).scalars().all()`]],
    ["cursor.execute of a SELECT string", [`cur = db.cursor()`, `cur.execute("SELECT id, title FROM reports")`, `return cur.fetchall()`]],
    ["a dict.update next to a select", [`params = {}`, `params.update(limit=10)`, `return db.execute(select(Report).limit(params["limit"])).all()`]],
  ]) {
    test(`silent on ${label}`, () => assert.ok(!fires(...body)));
  }

  for (const [label, body] of [
    ["db.execute(update(...))", [`db.execute(update(Report).values(seen=True))`, `db.commit()`]],
    ["a DELETE in text()", [`db.execute(text("DELETE FROM reports WHERE stale"))`]],
    ["an INSERT string", [`cur = db.cursor()`, `cur.execute("INSERT INTO hits (path) VALUES ('/reports')")`]],
    ["an execute of an unknown statement", [`db.execute(build_statement())`]],
  ]) {
    test(`still fires on ${label}`, () => assert.ok(fires(...body)));
  }

  test("AUTHZ-013 still reports a read by a caller-supplied id with no owner check", () => {
    assert.ok(auditFires({ "api/reports.py": [
      `@router.get("/reports/{report_id}")`,
      `def get_report(report_id: int, db = Depends(get_db), user = Depends(get_current_user)):`,
      `    return db.execute(select(Report).where(Report.id == report_id)).scalar_one()`,
      ``,
    ].join("\n") }, "AUTHZ-013"));
  });
});

// ---------------------------------------------------------------------------
// BUG-033: WEB-001 matches credential words, not substrings
// ---------------------------------------------------------------------------

describe("BUG-033: WEB-001 token constants, wrapped tokens, refreshCount", () => {
  const fires = (code) => auditFires({ "src/auth.js": code + "\n" }, "WEB-001");

  for (const [label, code] of [
    ["a key constant", `localStorage.setItem(TOKEN_KEY, accessToken);`],
    ["a key on a constants object", `localStorage.setItem(STORAGE_KEYS.authToken, t);`],
    ["a token wrapped in JSON", `localStorage.setItem("auth", JSON.stringify({ accessToken }));`],
    ["a token property wrapped in JSON", `sessionStorage.setItem("auth", JSON.stringify({ token: res.token }));`],
    ["an upper-case session id key", `sessionStorage.setItem("SESSION_ID", sid);`],
    ["an api key value", `localStorage.setItem("cfg", apiKey);`],
  ]) {
    test(`fires on ${label}`, () => assert.ok(fires(code)));
  }

  for (const [label, code] of [
    ["refreshCount", `localStorage.setItem("refreshCount", "1");`],
    ["design tokens", `localStorage.setItem("theme", JSON.stringify(themeTokens));`],
    ["a flag that names tokens", `localStorage.setItem("prefs", JSON.stringify({ showTokenCount: true }));`],
    ["a tokenizer value", `localStorage.setItem("cursor", tokenizer.position);`],
    ["a property that only contains the letters", `localStorage.tokensSeen = 3;`],
  ]) {
    test(`silent on ${label}`, () => assert.ok(!fires(code)));
  }

  test("a long minified line stays fast", () => {
    const line = `localStorage.setItem("a", ${"x".repeat(50000)});`;
    const start = Date.now();
    fires(line);
    assert.ok(Date.now() - start < 5000, `took ${Date.now() - start} ms`);
  });
});

// ---------------------------------------------------------------------------
// BUG-069: AUTHZ-003 needs an ownership check tied to the caller
// ---------------------------------------------------------------------------
//
// The JS twin of BUG-030. An owner or tenant column scoped by a value the
// caller sent (req.params, req.query, req.body) is no ownership check.

describe("BUG-069: AUTHZ-003 catches caller-supplied ownership", () => {
  const route = (path, ...body) => [
    `router.delete("${path}", async (req, res) => {`,
    `  if (!req.user) return res.status(401).end();`,
    ...body.map((l) => "  " + l),
    `  res.status(204).end();`,
    `});`,
    ``,
  ].join("\n");
  const fires = (src) => auditFires({ "src/routes.js": src }, "AUTHZ-003");

  test("fires when userId comes from the path", () => {
    assert.ok(fires(route("/users/:userId/docs/:docId",
      `await prisma.doc.delete({ where: { id: req.params.docId, userId: req.params.userId } });`)));
  });

  test("fires when teamId is copied from the path first", () => {
    assert.ok(fires(route("/teams/:teamId/docs/:docId",
      `const teamId = req.params.teamId;`,
      `await prisma.doc.delete({ where: { id: req.params.docId, teamId } });`)));
  });

  test("fires when only a 404 guards the row", () => {
    assert.ok(fires(route("/docs/:docId",
      `const doc = await prisma.doc.findUnique({ where: { id: req.params.docId } });`,
      `if (!doc) return res.status(404).end();`,
      `await prisma.doc.delete({ where: { id: doc.id } });`)));
  });

  for (const [label, ...body] of [
    ["userId bound to req.user", `await prisma.doc.delete({ where: { id: req.params.docId, userId: req.user.id } });`],
    ["a column compared with the caller", `const doc = await prisma.doc.findUnique({ where: { id: req.params.docId } });`, `if (doc.ownerId !== req.user.id) return res.status(403).end();`, `await prisma.doc.delete({ where: { id: doc.id } });`],
    ["the caller on the left", `const doc = await Doc.findById(req.params.docId);`, `if (req.user.id !== doc.authorId) return res.sendStatus(404);`, `await doc.remove();`],
    ["a name taken from the caller first", `const userId = req.user.id;`, `await prisma.doc.delete({ where: { id: req.params.docId, userId } });`],
    ["a destructured session value", `const { orgId } = req.user;`, `await prisma.doc.delete({ where: { id: req.params.docId, orgId: orgId } });`],
    ["a Supabase eq on the caller", `await supabase.from("docs").delete().eq("id", req.params.docId).eq("user_id", req.user.id);`],
    ["an access helper", `await assertObjectAccess(req.user, req.params.docId, "delete");`, `await prisma.doc.delete({ where: { id: req.params.docId } });`],
  ]) {
    test(`silent with ${label}`, () => assert.ok(!fires(route("/docs/:docId", ...body))));
  }
});

// ---------------------------------------------------------------------------
// BUG-070: AUTHZ-001 sees route-level and router-level middleware
// ---------------------------------------------------------------------------

describe("BUG-070: AUTHZ-001 honors auth middleware", () => {
  const del = (args) => [
    `router.delete("/docs/:docId", ${args}async (req, res) => {`,
    `  await prisma.doc.delete({ where: { id: req.params.docId } });`,
    `  res.status(204).end();`,
    `});`,
    ``,
  ].join("\n");
  const report = (src) => withTempProject({ "src/routes.js": src }, (dir) => runAuditOn(dir));
  const ids = (src) => report(src).findings.map((f) => f.rule.id);

  for (const [label, args] of [
    ["requireAuth before the handler", "requireAuth, "],
    ["passport.authenticate", `passport.authenticate("jwt", { session: false }), `],
    ["a middleware array", "[requireAuth, isAdmin], "],
  ]) {
    test(`${label} counts as auth (and the IDOR is then AUTHZ-003's)`, () => {
      const found = ids(del(args));
      assert.ok(!found.includes("AUTHZ-001"), found.join(", "));
      assert.ok(found.includes("AUTHZ-003"), found.join(", "));
    });
  }

  test("a non-auth middleware does not count", () => {
    assert.ok(ids(del("rateLimiter, ")).includes("AUTHZ-001"));
  });

  test("router.use(requireAuth) covers the routes registered after it", () => {
    assert.ok(!ids([`router.use(requireAuth);`, del("")].join("\n")).includes("AUTHZ-001"));
  });

  test("router.use(requireAuth) does not cover a route registered before it", () => {
    assert.ok(ids([del(""), `router.use(requireAuth);`].join("\n")).includes("AUTHZ-001"));
  });

  test("auth on one router does not cover another router", () => {
    const src = [`admin.use(requireAuth);`, del("")].join("\n");
    assert.ok(ids(src).includes("AUTHZ-001"));
  });

  test("a path-scoped app.use(\"/api\", verifyToken) counts for that object", () => {
    const src = [`router.use("/api", verifyToken);`, del("")].join("\n");
    assert.ok(!ids(src).includes("AUTHZ-001"));
  });

  test("an inline auth middleware before the handler counts", () => {
    const found = ids(del("(req, res, next) => { if (!req.user) return res.status(401).end(); next(); }, "));
    assert.ok(!found.includes("AUTHZ-001"), found.join(", "));
  });

  test("a handler passed by name is not misread from the next block", () => {
    const src = [`router.delete("/docs/:docId", removeDoc);`, `const cfg = { db: prisma.doc.delete({ where: {} }) };`, ``].join("\n");
    assert.ok(!ids(src).includes("AUTHZ-001"));
  });

  test("a handler longer than 4000 characters is still read", () => {
    const filler = Array.from({ length: 200 }, (_, k) => `  const v${k} = "${"x".repeat(20)}";`).join("\n");
    const src = [`router.delete("/docs/:docId", async (req, res) => {`, filler,
      `  await prisma.doc.delete({ where: { id: req.params.docId } });`, `});`, ``].join("\n");
    assert.ok(ids(src).includes("AUTHZ-001"));
  });
});

// ---------------------------------------------------------------------------
// Per-rule allowlist entries (1.5.0)
// ---------------------------------------------------------------------------
//
// `<path>  [RULE-ID, ...]  # reason: <text>` suppresses only the named
// rules in that file. A path-only entry still exempts the whole file.

describe("Per-rule allowlist entries", () => {
  // One file that trips INJ-003, SEC-002 and ERR-003.
  const source = [
    `export function Box({ html }) {`,
    `  console.log("render");`,
    `  return <div dangerouslySetInnerHTML={{ __html: html }} />;`,
    `}`,
    `const k = "${"AKIA" + "ABCDEFGHIJKLMNOP"}";`,
    ``,
  ].join("\n");
  const run = (allowlist) => withTempProject({ "src/Box.jsx": source, "security/.audit-allowlist": allowlist + "\n" }, (dir) => {
    const r = runAuditArgs(dir, "--json");
    return { report: JSON.parse(r.stdout), stderr: r.stderr };
  });
  const ids = (report) => report.findings.map((f) => f.rule.id).sort();

  test("baseline: the file trips INJ-003, SEC-002 and ERR-003", () => {
    const { report } = run("# nothing");
    for (const id of ["INJ-003", "SEC-002", "ERR-003"]) assert.ok(ids(report).includes(id), ids(report).join(", "));
  });

  test("the named rule is suppressed and every other rule still fires", () => {
    const { report, stderr } = run("src/Box.jsx  [INJ-003]  # reason: sanitized upstream");
    assert.ok(!ids(report).includes("INJ-003"), ids(report).join(", "));
    assert.ok(ids(report).includes("SEC-002") && ids(report).includes("ERR-003"), ids(report).join(", "));
    assert.deepEqual(report.exempt.rules, [{ file: "src/Box.jsx", rules: ["INJ-003"] }]);
    assert.equal(report.exempt.total, 0, "a per-rule entry must not exempt the whole file");
    assert.ok(!/line ignored/.test(stderr), stderr.slice(0, 300));
  });

  test("several rule ids, any case and spacing", () => {
    const { report } = run("src/Box.jsx  [ inj-003 ,ERR-003 ]  # reason: fixture");
    assert.deepEqual(ids(report).filter((id) => ["INJ-003", "ERR-003", "SEC-002"].includes(id)), ["SEC-002"]);
  });

  test("an analyzer rule can be named", () => {
    const handler = `router.post("/x", async (req, res) => {\n  await db.items.create({ data: {} });\n  res.end();\n});\n`;
    const r = withTempProject({ "src/r.js": handler, "security/.audit-allowlist": "src/r.js  [AUTHZ-001]  # reason: internal network only\n" },
      (dir) => JSON.parse(runAuditArgs(dir, "--json").stdout));
    assert.ok(!ids(r).includes("AUTHZ-001"), ids(r).join(", "));
  });

  test("a path-only entry still exempts the whole file", () => {
    const { report } = run("src/Box.jsx  # reason: generated");
    assert.deepEqual(ids(report).filter((id) => ["INJ-003", "ERR-003", "SEC-002"].includes(id)), []);
    assert.equal(report.exempt.total, 1);
  });

  for (const [label, line, message] of [
    ["an unknown rule id", "src/Box.jsx  [INJ-999]  # reason: typo", /\.audit-allowlist:1 - unknown rule id "INJ-999", line ignored/],
    ["a runtime GUARD- id", "src/Box.jsx  [GUARD-INJ-001]  # reason: wrong engine", /unknown rule id "GUARD-INJ-001", line ignored/],
    ["an empty rule list", "src/Box.jsx  []  # reason: x", /empty rule list, line ignored/],
    ["a project check, which an entry cannot suppress", "src/Box.jsx  [DEP-001]  # reason: x", /DEP-001 is a project check and cannot be suppressed per file, line ignored/],
    ["an empty reason", "src/Box.jsx  [INJ-003]  # reason:", /reason is empty, line ignored/],
    ["no reason at all", "src/Box.jsx  [INJ-003]", /missing reason, line ignored/],
  ]) {
    test(`${label} is rejected loudly and suppresses nothing`, () => {
      const { report, stderr } = run(line);
      assert.ok(message.test(stderr), stderr.slice(0, 400));
      assert.ok(ids(report).includes("INJ-003"), ids(report).join(", "));
    });
  }

  test("the human report lists per-rule exemptions", () => {
    const r = withTempProject({ "src/Box.jsx": source, "security/.audit-allowlist": "src/Box.jsx  [INJ-003]  # reason: x\n" },
      (dir) => runAuditArgs(dir));
    assert.ok(/\[allowlist rule\] src\/Box\.jsx \[INJ-003\]/.test(r.stdout + r.stderr), (r.stdout + r.stderr).slice(0, 600));
  });

  test("a Next.js path with brackets still parses as a path-only entry", () => {
    const r = withTempProject({ "app/docs/[id]/page.jsx": source, "security/.audit-allowlist": "app/docs/[id]/page.jsx  # reason: x\n" },
      (dir) => JSON.parse(runAuditArgs(dir, "--json").stdout));
    assert.equal(r.exempt.total, 1);
  });
});

// ---------------------------------------------------------------------------
// BUG-003: stock shadcn chart.jsx and a per-rule INJ-003 entry
// ---------------------------------------------------------------------------
//
// shadcn's ChartStyle writes the `id` prop and the ChartConfig colours into
// a <style> element through dangerouslySetInnerHTML, unescaped. INJ-003 is
// right to report it: under server rendering a config value holding
// `</style>` breaks out of the style tag. Whether that can happen depends
// on where ChartConfig comes from, which a per-file audit cannot see, so
// the rule stays and the project records its decision per rule.

describe("BUG-003: shadcn chart.jsx with a per-rule INJ-003 entry", () => {
  const chart = [
    `const THEMES = { light: "", dark: ".dark" }`,
    `const ChartStyle = ({ id, config }) => {`,
    `  const colorConfig = Object.entries(config).filter(([, config]) => config.theme || config.color)`,
    `  if (!colorConfig.length) {`,
    `    return null`,
    `  }`,
    `  return (`,
    `    (<style`,
    `      dangerouslySetInnerHTML={{`,
    `        __html: Object.entries(THEMES)`,
    `          .map(([theme, prefix]) => \`${"$"}{prefix} [data-chart=${"$"}{id}] {${"$"}{colorConfig.map(([key, c]) => \`--color-${"$"}{key}: ${"$"}{c.color};\`).join("\\n")}}\`)`,
    `          .join("\\n"),`,
    `      }} />)`,
    `  );`,
    `}`,
    `console.log("chart loaded")`,
    ``,
  ].join("\n");
  const run = (allowlist) => withTempProject({
    "src/components/ui/chart.jsx": chart,
    ...(allowlist ? { "security/.audit-allowlist": allowlist + "\n" } : {}),
  }, (dir) => JSON.parse(runAuditArgs(dir, "--json").stdout).findings.map((f) => f.rule.id));

  test("INJ-003 still reports the stock component", () => {
    assert.ok(run(null).includes("INJ-003"));
  });

  test("the documented per-rule line clears INJ-003 and keeps every other rule", () => {
    const ids = run("src/components/ui/chart.jsx  [INJ-003]  # reason: stock shadcn ChartStyle; ChartConfig and id are developer constants, never user input");
    assert.ok(!ids.includes("INJ-003"), ids.join(", "));
    assert.ok(ids.includes("ERR-003"), `other rules must still run on the file: ${ids.join(", ")}`);
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
