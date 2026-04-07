/**
 * ============================================================
 * OTLC GUARDIAN — sql-guard tagged template tests
 * // tests · onthelevelconcepts.com
 * Version: 1.0.0
 * ============================================================
 *
 * Tests the OWASP-aligned SQL injection defense helper at
 * security/04-sql-guard.js. The helper's entire job is to make
 * parameterized queries the path of least resistance, so the
 * test suite asserts the five security properties listed in the
 * handoff plus the end-to-end "injection payload is passed as a
 * value, never spliced into SQL text" contract.
 *
 *   1. All ${expr} interpolations become placeholders, never
 *      inline text — even when expr contains SQL metacharacters,
 *      quotes, comments, or full DROP TABLE payloads.
 *   2. SQL keywords and structure are preserved literally so the
 *      developer's intended query is what reaches the database.
 *   3. Nested sql`` calls compose safely — text merges, values
 *      concatenate, placeholders renumber.
 *   4. Identifier interpolation is an explicit escape hatch via
 *      sql.identifier(name, allowList) — raw identifier
 *      interpolation through ${} is not supported and must throw.
 *   5. The helper performs zero input scanning, blocklist
 *      filtering, or keyword detection. Parameter values pass
 *      through unchanged because the driver handles them as data.
 *
 * Both dialects (postgres $1 and mysql/sqlite ?) are first-class.
 * Tests cover the factory API (createSqlHelper) and the default
 * export with .toMysql()/.toSqlite() instance methods.
 *
 * Same zero-dep mini test runner as tests/init.test.js.
 *
 * Run: node tests/sql-guard.test.js
 * ============================================================
 */

import { strict as assert } from "assert";
import { sql, createSqlHelper } from "../security/04-sql-guard.js";

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
// PROPERTY 1 — interpolations become placeholders, never inline text
// ---------------------------------------------------------------------------

describe("Property 1 — all ${expr} become placeholders", () => {
  test("postgres: single interpolation becomes $1", () => {
    const id = 42;
    const q = sql`SELECT * FROM users WHERE id = ${id}`;
    assert.equal(q.text, "SELECT * FROM users WHERE id = $1");
    assert.deepEqual(q.values, [42]);
    assert.equal(q.driver, "postgres");
  });

  test("postgres: multiple interpolations become $1, $2, $3 in order", () => {
    const a = "alice";
    const b = 7;
    const c = true;
    const q = sql`SELECT * FROM users WHERE name = ${a} AND age > ${b} AND active = ${c}`;
    assert.equal(
      q.text,
      "SELECT * FROM users WHERE name = $1 AND age > $2 AND active = $3"
    );
    assert.deepEqual(q.values, ["alice", 7, true]);
  });

  test("mysql: interpolations become ? placeholders", () => {
    const id = 42;
    const name = "bob";
    const q = sql`SELECT * FROM u WHERE id = ${id} AND name = ${name}`.toMysql();
    assert.equal(q.text, "SELECT * FROM u WHERE id = ? AND name = ?");
    assert.deepEqual(q.values, [42, "bob"]);
    assert.equal(q.driver, "mysql");
  });

  test("sqlite: interpolations become ? placeholders (same as mysql)", () => {
    const id = 42;
    const q = sql`SELECT * FROM logs WHERE id = ${id}`.toSqlite();
    assert.equal(q.text, "SELECT * FROM logs WHERE id = ?");
    assert.deepEqual(q.values, [42]);
    assert.equal(q.driver, "sqlite");
  });

  test("factory: createSqlHelper({driver:'mysql'}) uses ? placeholders from the start", () => {
    const sqlMy = createSqlHelper({ driver: "mysql" });
    const id = 9;
    const q = sqlMy`SELECT * FROM t WHERE id = ${id}`;
    assert.equal(q.text, "SELECT * FROM t WHERE id = ?");
    assert.deepEqual(q.values, [9]);
    assert.equal(q.driver, "mysql");
  });

  test("factory: createSqlHelper({driver:'postgres'}) uses $N placeholders", () => {
    const sqlPg = createSqlHelper({ driver: "postgres" });
    const id = 9;
    const q = sqlPg`SELECT * FROM t WHERE id = ${id}`;
    assert.equal(q.text, "SELECT * FROM t WHERE id = $1");
    assert.deepEqual(q.values, [9]);
  });

  test("factory: createSqlHelper({driver:'sqlite'}) uses ? placeholders", () => {
    const sqlLite = createSqlHelper({ driver: "sqlite" });
    const id = 9;
    const q = sqlLite`SELECT * FROM t WHERE id = ${id}`;
    assert.equal(q.text, "SELECT * FROM t WHERE id = ?");
    assert.deepEqual(q.values, [9]);
  });

  test("factory: unknown driver throws", () => {
    assert.throws(() => createSqlHelper({ driver: "oracle" }), /driver/i);
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 2 — SQL keywords and structure preserved literally
// ---------------------------------------------------------------------------

describe("Property 2 — SQL text preserved byte-for-byte around placeholders", () => {
  test("whitespace and case preserved exactly", () => {
    const x = 1;
    const q = sql`  SELECT
      *
    FROM   users
    WHERE  id = ${x}`;
    assert.equal(
      q.text,
      "  SELECT\n      *\n    FROM   users\n    WHERE  id = $1"
    );
  });

  test("no-interpolation query passes through unchanged", () => {
    const q = sql`SELECT COUNT(*) FROM users`;
    assert.equal(q.text, "SELECT COUNT(*) FROM users");
    assert.deepEqual(q.values, []);
  });

  test("trailing interpolation at end of query", () => {
    const limit = 10;
    const q = sql`SELECT * FROM users LIMIT ${limit}`;
    assert.equal(q.text, "SELECT * FROM users LIMIT $1");
    assert.deepEqual(q.values, [10]);
  });

  test("leading interpolation at start of query", () => {
    const schema = "public.users";
    // leading interpolations are still values — the schema name here is
    // being treated as a VALUE for this test (and is not a real-world
    // safe pattern for schema names; that's what sql.identifier is for).
    // But the helper must still produce a placeholder and preserve the
    // rest of the text.
    const q = sql`${schema} is the target`;
    assert.equal(q.text, "$1 is the target");
    assert.deepEqual(q.values, ["public.users"]);
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 3 — injection payloads pass through as VALUES, never text
// ---------------------------------------------------------------------------

describe("Property 3 — injection payloads are parameter values, not SQL text", () => {
  test("classic drop-table payload is a value, not text", () => {
    const userInput = "'; DROP TABLE users; --";
    const q = sql`SELECT * FROM users WHERE name = ${userInput}`;
    assert.equal(q.text, "SELECT * FROM users WHERE name = $1");
    assert.deepEqual(q.values, ["'; DROP TABLE users; --"]);
    // Text must NOT contain the payload — that's the whole point.
    assert.ok(!q.text.includes("DROP TABLE"));
    assert.ok(!q.text.includes("'"));
  });

  test("boolean-based injection payload passes through as value", () => {
    const userInput = "1 OR 1=1";
    const q = sql`SELECT * FROM users WHERE id = ${userInput}`;
    assert.equal(q.text, "SELECT * FROM users WHERE id = $1");
    assert.deepEqual(q.values, ["1 OR 1=1"]);
    assert.ok(!q.text.includes("1=1"));
  });

  test("union-based injection payload passes through as value", () => {
    const userInput = "1 UNION SELECT password FROM admin";
    const q = sql`SELECT name FROM users WHERE id = ${userInput}`;
    assert.equal(q.text, "SELECT name FROM users WHERE id = $1");
    assert.deepEqual(q.values, ["1 UNION SELECT password FROM admin"]);
    assert.ok(!q.text.includes("UNION"));
  });

  test("comment injection payload passes through as value", () => {
    const userInput = "admin'--";
    const q = sql`SELECT * FROM users WHERE name = ${userInput}`;
    assert.equal(q.text, "SELECT * FROM users WHERE name = $1");
    assert.deepEqual(q.values, ["admin'--"]);
    assert.ok(!q.text.includes("'"));
    assert.ok(!q.text.includes("--"));
  });

  test("stacked-query injection payload passes through as value", () => {
    const userInput = "1; INSERT INTO users VALUES ('hacker', 'admin')";
    const q = sql`SELECT * FROM users WHERE id = ${userInput}`;
    assert.equal(q.text, "SELECT * FROM users WHERE id = $1");
    assert.deepEqual(q.values, [
      "1; INSERT INTO users VALUES ('hacker', 'admin')",
    ]);
    assert.ok(!q.text.includes("INSERT"));
  });

  test("null byte in input passes through untouched as value", () => {
    const userInput = "admin\x00";
    const q = sql`SELECT * FROM users WHERE name = ${userInput}`;
    assert.deepEqual(q.values, ["admin\x00"]);
  });

  test("mysql: drop-table payload is a value, not text", () => {
    const userInput = "'; DROP TABLE users; --";
    const q =
      sql`SELECT * FROM users WHERE name = ${userInput}`.toMysql();
    assert.equal(q.text, "SELECT * FROM users WHERE name = ?");
    assert.deepEqual(q.values, ["'; DROP TABLE users; --"]);
    assert.ok(!q.text.includes("DROP TABLE"));
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 4 — identifier escape hatch with allow-list validation
// ---------------------------------------------------------------------------

describe("Property 4 — sql.identifier allow-list escape hatch", () => {
  test("identifier on allow-list is inlined into query text", () => {
    const col = "name";
    const q = sql`SELECT * FROM users ORDER BY ${sql.identifier(col, [
      "name",
      "id",
      "created_at",
    ])}`;
    assert.equal(q.text, 'SELECT * FROM users ORDER BY "name"');
    assert.deepEqual(q.values, []);
  });

  test("identifier off allow-list throws", () => {
    assert.throws(
      () =>
        sql`SELECT * FROM users ORDER BY ${sql.identifier("password", [
          "name",
          "id",
        ])}`,
      /not in allow/i
    );
  });

  test("identifier allow-list must be a non-empty array", () => {
    assert.throws(() => sql.identifier("name", []), /allow/i);
    assert.throws(() => sql.identifier("name", null), /allow/i);
    assert.throws(() => sql.identifier("name", undefined), /allow/i);
  });

  test("identifier containing a quote is rejected even if on allow-list", () => {
    // Defense in depth: even if someone puts a malicious string on the
    // allow-list by mistake, the identifier must still match a safe shape.
    assert.throws(
      () => sql.identifier('name"; DROP TABLE users; --', ['name"; DROP TABLE users; --']),
      /invalid identifier/i
    );
  });

  test("raw string interpolation in ORDER BY is a parameter, NOT an identifier", () => {
    // This is the "you must use sql.identifier" contract: a bare string
    // in ${} is always a value, never a column name. If the developer
    // wants a dynamic column name they must explicitly opt in.
    const col = "name"; // raw string, not sql.identifier
    const q = sql`SELECT * FROM users ORDER BY ${col}`;
    assert.equal(q.text, "SELECT * FROM users ORDER BY $1");
    assert.deepEqual(q.values, ["name"]);
  });

  test("mysql: identifier uses backticks instead of double quotes", () => {
    const col = "name";
    const q = sql`SELECT * FROM users ORDER BY ${sql.identifier(col, [
      "name",
      "id",
    ])}`.toMysql();
    assert.equal(q.text, "SELECT * FROM users ORDER BY `name`");
  });

  test("sqlite: identifier uses double quotes", () => {
    const col = "name";
    const q = sql`SELECT * FROM users ORDER BY ${sql.identifier(col, [
      "name",
      "id",
    ])}`.toSqlite();
    assert.equal(q.text, 'SELECT * FROM users ORDER BY "name"');
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 5 — nested sql`` composition
// ---------------------------------------------------------------------------

describe("Property 5 — nested sql`` composition", () => {
  test("nested sql`` merges text and renumbers placeholders", () => {
    const id = 42;
    const tenant = "acme";
    const where = sql`id = ${id}`;
    const q = sql`SELECT * FROM users WHERE ${where} AND tenant = ${tenant}`;
    assert.equal(
      q.text,
      "SELECT * FROM users WHERE id = $1 AND tenant = $2"
    );
    assert.deepEqual(q.values, [42, "acme"]);
  });

  test("nested sql`` placed before top-level interpolation still renumbers correctly", () => {
    const id = 42;
    const tenant = "acme";
    const inner = sql`${tenant}`;
    const q = sql`SELECT * FROM users WHERE tenant = ${inner} AND id = ${id}`;
    assert.equal(
      q.text,
      "SELECT * FROM users WHERE tenant = $1 AND id = $2"
    );
    assert.deepEqual(q.values, ["acme", 42]);
  });

  test("two-level nested sql`` composes correctly", () => {
    const id = 1;
    const tenant = "acme";
    const name = "alice";
    const tenantClause = sql`tenant = ${tenant}`;
    const idAndTenant = sql`id = ${id} AND ${tenantClause}`;
    const q = sql`SELECT * FROM users WHERE ${idAndTenant} AND name = ${name}`;
    assert.equal(
      q.text,
      "SELECT * FROM users WHERE id = $1 AND tenant = $2 AND name = $3"
    );
    assert.deepEqual(q.values, [1, "acme", "alice"]);
  });

  test("nested sql`` preserves mysql dialect when outer is mysql", () => {
    const id = 42;
    const tenant = "acme";
    const where = sql`id = ${id}`;
    const q =
      sql`SELECT * FROM users WHERE ${where} AND tenant = ${tenant}`.toMysql();
    assert.equal(
      q.text,
      "SELECT * FROM users WHERE id = ? AND tenant = ?"
    );
    assert.deepEqual(q.values, [42, "acme"]);
  });

  test("nested sql`` carrying an identifier composes into outer query", () => {
    const col = "name";
    const id = 5;
    const orderBy = sql`ORDER BY ${sql.identifier(col, ["name", "id"])}`;
    const q = sql`SELECT * FROM users WHERE id = ${id} ${orderBy}`;
    assert.equal(
      q.text,
      'SELECT * FROM users WHERE id = $1 ORDER BY "name"'
    );
    assert.deepEqual(q.values, [5]);
  });

  test("nested sql`` injection payload in inner block is still parameterized", () => {
    const payload = "'; DROP TABLE users; --";
    const inner = sql`name = ${payload}`;
    const q = sql`SELECT * FROM users WHERE ${inner}`;
    assert.equal(q.text, "SELECT * FROM users WHERE name = $1");
    assert.deepEqual(q.values, ["'; DROP TABLE users; --"]);
    assert.ok(!q.text.includes("DROP TABLE"));
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 6 — no input scanning / no blocklist / no keyword filtering
// ---------------------------------------------------------------------------

describe("Property 6 — zero input scanning, values pass through unchanged", () => {
  test("value containing DROP TABLE keyword is NOT rejected or filtered", () => {
    const userInput = "DROP TABLE users"; // legitimate search term in a help article DB
    const q = sql`SELECT * FROM articles WHERE body LIKE ${userInput}`;
    // Helper did NOT reject, did NOT filter, did NOT sanitize the value.
    // It just placed it in the values array. The driver will escape it.
    assert.deepEqual(q.values, ["DROP TABLE users"]);
  });

  test("value containing SQL comment syntax is NOT filtered", () => {
    const userInput = "-- this is a comment";
    const q = sql`INSERT INTO notes (body) VALUES (${userInput})`;
    assert.deepEqual(q.values, ["-- this is a comment"]);
  });

  test("numeric zero is preserved (truthiness bug guard)", () => {
    const id = 0;
    const q = sql`SELECT * FROM users WHERE id = ${id}`;
    assert.deepEqual(q.values, [0]);
  });

  test("empty string is preserved", () => {
    const name = "";
    const q = sql`SELECT * FROM users WHERE name = ${name}`;
    assert.deepEqual(q.values, [""]);
  });

  test("null value is preserved and passed as parameter", () => {
    const q = sql`SELECT * FROM users WHERE deleted_at = ${null}`;
    assert.equal(q.text, "SELECT * FROM users WHERE deleted_at = $1");
    assert.deepEqual(q.values, [null]);
  });
});

// ---------------------------------------------------------------------------
// PROPERTY 7 — .toMysql() / .toSqlite() conversion idempotency and purity
// ---------------------------------------------------------------------------

describe("Property 7 — dialect conversion is pure and idempotent", () => {
  test(".toMysql() twice returns the same result", () => {
    const id = 42;
    const q = sql`SELECT * FROM u WHERE id = ${id}`;
    const my1 = q.toMysql();
    const my2 = q.toMysql();
    assert.equal(my1.text, my2.text);
    assert.deepEqual(my1.values, my2.values);
  });

  test(".toMysql() does not mutate the original postgres result", () => {
    const id = 42;
    const q = sql`SELECT * FROM u WHERE id = ${id}`;
    const originalText = q.text;
    q.toMysql();
    assert.equal(q.text, originalText);
    assert.equal(q.driver, "postgres");
  });

  test("conversion across 10 placeholders stays consistent", () => {
    const q = sql`
      INSERT INTO t (a, b, c, d, e, f, g, h, i, j)
      VALUES (${1}, ${2}, ${3}, ${4}, ${5}, ${6}, ${7}, ${8}, ${9}, ${10})
    `;
    assert.ok(q.text.includes("$1"));
    assert.ok(q.text.includes("$10"));
    assert.deepEqual(q.values, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    const my = q.toMysql();
    const questionMarkCount = (my.text.match(/\?/g) || []).length;
    assert.equal(questionMarkCount, 10);
    assert.deepEqual(my.values, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });
});

// ---------------------------------------------------------------------------
// SUMMARY
// ---------------------------------------------------------------------------

console.log(`\n${"=".repeat(60)}`);
console.log(`sql-guard tests:  ${passed} passed, ${failed} failed`);
console.log(`${"=".repeat(60)}\n`);

if (failed > 0) {
  console.error("FAILURES:");
  for (const f of failures) {
    console.error(`  • ${f.name}`);
    console.error(`    ${f.error}`);
  }
  process.exit(1);
}
