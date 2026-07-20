// ============================================================
// OTLC Guardian — SQL injection defense (tagged-template helper)
// // onthelevelconcepts.com
// Version: 1.4.1
// ============================================================
//
// OWASP SQL Injection Prevention Cheat Sheet, defense #1:
//
//   "Primary Defenses:
//    Option 1: Use of Prepared Statements (with Parameterized Queries)"
//
//   https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
//
// This module exports a `sql` tagged template literal that makes
// parameterized queries the path of least resistance. Every
// interpolated value becomes a placeholder in the rendered query
// text and is pushed into a separate `values` array that the
// database driver passes to the database as data, never as code.
//
// What this module is NOT:
//
//   • It is NOT a runtime blocklist or keyword scanner. OWASP
//     explicitly warns that input filtering is not a primary
//     defense against SQL injection — it is bypassable by encoding,
//     second-order injection, and comment tricks. The audit at
//     security/03-audit.js catches the bad concatenation pattern
//     statically; this helper makes the safe pattern easy.
//
//   • It is NOT an ORM. STANDARDS.md already mandates Prisma or
//     SQLAlchemy for projects that want an ORM. This is the
//     zero-dependency alternative for projects that write raw SQL
//     and need a safe way to do it.
//
//   • It does NOT validate identifiers against a live schema. The
//     caller provides an explicit allow-list via sql.identifier().
//
// Dialect support — both first-class:
//
//   • postgres (pg, node-postgres)  — uses $1, $2, $3 placeholders
//   • mysql    (mysql2)              — uses ? placeholders
//   • sqlite   (better-sqlite3)      — uses ? placeholders
//
// Two APIs — pick whichever is cleanest for your code:
//
//   1. Default `sql` (postgres) with conversion methods:
//        import { sql } from './security/04-sql-guard.js';
//        const q = sql`SELECT * FROM users WHERE id = ${id}`;
//        await pg.query(q.text, q.values);
//        // or:
//        const qMy = q.toMysql();
//        await mysql.query(qMy.text, qMy.values);
//
//   2. Factory per file:
//        import { createSqlHelper } from './security/04-sql-guard.js';
//        const sql = createSqlHelper({ driver: 'mysql' });
//        const q = sql`SELECT * FROM users WHERE id = ${id}`;
//        await mysql.query(q.text, q.values);
//
// Nested composition is supported — `sql\`WHERE ${sql\`id = ${id}\`}\``
// inlines the inner parts into the outer query and renumbers
// placeholders automatically. Values from nested blocks are
// concatenated in document order.
//
// Dynamic identifiers (ORDER BY ${col}, FROM ${table}) must go
// through sql.identifier(name, allowList) — a bare string in ${}
// is always treated as a VALUE, never as an identifier. This is
// the one case where OWASP allows non-parameterized interpolation,
// and only with strict allow-list validation.
//
// ============================================================

// Brand symbols let us distinguish a nested sql`` result and an
// identifier marker from an arbitrary string or object the caller
// might pass. Module-level Symbols are unique per module load,
// which is enough — the only code that creates these objects lives
// here.
const QUERY_BRAND = Symbol("otlc-guardian:sql-query");
const IDENT_BRAND = Symbol("otlc-guardian:sql-identifier");

// Supported dialects. Anything else throws from createSqlHelper.
// Keep this set in lockstep with placeholderFor / quoteIdentifier.
const SUPPORTED_DRIVERS = new Set(["postgres", "mysql", "sqlite"]);

// Safe identifier shape — letters, digits, underscores, optional
// schema prefix (one dot). Matches standard ANSI unquoted-identifier
// rules and is strict enough to exclude every known injection
// metacharacter (', ", ;, space, --, /*, parentheses, etc.).
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

// ---------------------------------------------------------------------------
// INTERNAL — render a compiled parts array into text + values for a dialect
// ---------------------------------------------------------------------------

/**
 * Compiled query parts:
 *   { type: "text",       value: string }  — literal SQL text
 *   { type: "value",      value: any    }  — becomes a placeholder
 *   { type: "identifier", name:  string }  — becomes a quoted identifier
 *
 * The parts array is the single source of truth — `text` and `values`
 * are derived from it at render time. That's what makes `.toMysql()`,
 * `.toSqlite()`, and `.toPostgres()` pure: they re-render the same
 * parts in a different dialect without mutating anything.
 */
function render(parts, driver) {
  let text = "";
  const values = [];
  let counter = 1;

  for (const part of parts) {
    if (part.type === "text") {
      text += part.value;
    } else if (part.type === "value") {
      text += placeholderFor(driver, counter);
      counter++;
      values.push(part.value);
    } else if (part.type === "identifier") {
      text += quoteIdentifier(part.name, driver);
    }
    // No default — unknown part types are impossible because only
    // compile() creates parts, and compile() is exhaustive.
  }

  return { text, values };
}

function placeholderFor(driver, n) {
  if (driver === "postgres") return `$${n}`;
  // mysql2 and better-sqlite3 both use ? — no numbered form.
  return "?";
}

function quoteIdentifier(name, driver) {
  if (driver === "mysql") return "`" + name + "`";
  // postgres and sqlite both use double-quoted identifiers per ANSI SQL.
  return `"${name}"`;
}

// ---------------------------------------------------------------------------
// INTERNAL — compile a template strings array into a parts array
// ---------------------------------------------------------------------------

/**
 * Walk the tagged-template arguments and build the compiled parts array.
 *
 * For each interpolation value:
 *   • Nested sql`` result  → inline its parts (placeholders get renumbered
 *                            on render; values concatenate in document order)
 *   • Identifier marker    → emit an "identifier" part, no value
 *   • Anything else        → emit a "value" part, preserving null/0/"" as-is
 */
function compile(strings, values, driver) {
  const parts = [];

  for (let i = 0; i < strings.length; i++) {
    parts.push({ type: "text", value: strings[i] });

    if (i < values.length) {
      const v = values[i];

      if (isQueryResult(v)) {
        // Inline the nested result's compiled parts verbatim. The
        // outer render() pass will renumber placeholders and quote
        // identifiers in the OUTER dialect, which is correct — a
        // single query goes to a single database.
        for (const p of v[QUERY_BRAND]) parts.push(p);
      } else if (isIdentifier(v)) {
        parts.push({ type: "identifier", name: v.name });
      } else {
        // Everything else — including null, undefined, 0, "", false,
        // objects, buffers — passes through as a VALUE. The driver
        // handles encoding; the helper does not filter or sanitize.
        parts.push({ type: "value", value: v });
      }
    }
  }

  return makeResult(parts, driver);
}

/**
 * Build the public QueryResult object from a compiled parts array.
 * The object exposes `text`, `values`, and `driver` for immediate use
 * with pg / mysql2 / better-sqlite3, plus `.toMysql()`, `.toSqlite()`,
 * and `.toPostgres()` for cross-dialect conversion.
 *
 * The parts array is stashed under a Symbol-keyed property so:
 *   • Normal object enumeration (`Object.keys`, spread, JSON.stringify)
 *     doesn't leak internals into the user's logs.
 *   • Nested sql`` detection has a stable brand that can't collide
 *     with an arbitrary user object that happens to have a `parts` key.
 */
function makeResult(parts, driver) {
  const { text, values } = render(parts, driver);

  const result = {
    text,
    values,
    driver,
    toPostgres() {
      return makeResult(parts, "postgres");
    },
    toMysql() {
      return makeResult(parts, "mysql");
    },
    toSqlite() {
      return makeResult(parts, "sqlite");
    },
  };

  // Brand + parts live under a Symbol key so they're not enumerable
  // and cannot be accidentally trampled by a caller doing { ...q }.
  Object.defineProperty(result, QUERY_BRAND, {
    value: parts,
    enumerable: false,
    writable: false,
    configurable: false,
  });

  return result;
}

function isQueryResult(v) {
  return v !== null && typeof v === "object" && QUERY_BRAND in v;
}

function isIdentifier(v) {
  return (
    v !== null &&
    typeof v === "object" &&
    v.__brand === IDENT_BRAND
  );
}

// ---------------------------------------------------------------------------
// PUBLIC — sql.identifier(name, allowList)
// ---------------------------------------------------------------------------

/**
 * Create an identifier marker for dynamic column or table names.
 *
 * This is the ONE legitimate case where a value is inlined into the
 * SQL text instead of becoming a placeholder. OWASP requires strict
 * allow-list validation for this case, and this function enforces:
 *
 *   1. allowList is a non-empty array (caller must commit to a list)
 *   2. name matches a safe identifier shape (letters, digits, _,
 *      optional single dot for schema.table)
 *   3. name is a member of allowList
 *
 * All three checks throw loudly on failure. There is no soft-fail
 * or silent fallback — a failed identifier check MUST abort the
 * query, not substitute a default.
 *
 * The safe-shape check runs before the membership check so that even
 * if a caller accidentally adds a malicious string to the allow-list,
 * the regex rejects it. Defense in depth.
 */
function identifier(name, allowList) {
  if (!Array.isArray(allowList) || allowList.length === 0) {
    throw new Error(
      "sql.identifier: allow-list must be a non-empty array of permitted identifiers"
    );
  }

  if (typeof name !== "string" || !IDENT_RE.test(name)) {
    throw new Error(
      `sql.identifier: invalid identifier "${name}" ` +
        `(must match ${IDENT_RE.source})`
    );
  }

  if (!allowList.includes(name)) {
    throw new Error(
      `sql.identifier: "${name}" is not in allow-list [${allowList.join(", ")}]`
    );
  }

  return { __brand: IDENT_BRAND, name };
}

// ---------------------------------------------------------------------------
// PUBLIC — createSqlHelper({ driver })
// ---------------------------------------------------------------------------

/**
 * Create a dialect-bound tagged template tag.
 *
 *   const sql = createSqlHelper({ driver: 'mysql' });
 *   const q = sql`SELECT * FROM u WHERE id = ${id}`;
 *   // q.text  === 'SELECT * FROM u WHERE id = ?'
 *   // q.values === [id]
 *
 * The returned function is a valid tagged template tag AND carries
 * an `.identifier` method for dynamic-identifier interpolation.
 */
export function createSqlHelper({ driver } = {}) {
  if (!SUPPORTED_DRIVERS.has(driver)) {
    throw new Error(
      `createSqlHelper: unknown driver "${driver}". ` +
        `Supported drivers: ${[...SUPPORTED_DRIVERS].join(", ")}`
    );
  }

  function sqlTag(strings, ...values) {
    return compile(strings, values, driver);
  }

  sqlTag.identifier = identifier;
  return sqlTag;
}

// ---------------------------------------------------------------------------
// PUBLIC — default `sql` export (postgres dialect)
// ---------------------------------------------------------------------------

/**
 * The default `sql` tag is bound to the postgres dialect. Callers
 * who target mysql or sqlite can either use .toMysql() / .toSqlite()
 * on the result, or call createSqlHelper({ driver: '...' }) for a
 * natively-bound tag.
 */
export const sql = createSqlHelper({ driver: "postgres" });
