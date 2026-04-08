#!/usr/bin/env node
/**
 * ============================================================
 * OTLC GUARDIAN — Safety Audit Tool
 * // security · onthelevelconcepts.com
 * Version: 1.3.1
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
// TEST FILE RECOGNITION
// ---------------------------------------------------------------------------
//
// Rules whose intent is "production code only" (ERR-003 console.log,
// CFG-001 / CFG-002 / CFG-003 hardcoded URL/IP, INJ-002 innerHTML,
// TS-001 any-type, SEC-006 API-key assignment) should not fire on test
// code that legitimately uses these patterns. The pre-1.2.2 list only
// knew about *.test.* and *.spec.* and the substring "test/" — it
// missed pytest's test_*.py and *_test.py, custom test runners like
// test-site.js, the standard /tests/ directory on Windows where the
// path separator is backslash, etc. The expanded list below recognizes
// the full set of conventional test-file naming + directory locations
// across JS, TS, and Python ecosystems. The anchored character class
// [\/\\] is what makes the directory matchers work on Windows AND Unix.
//
// Defined at module top so AUDIT_RULES below can reference it. Hoisted
// `const` declarations are OK in modern V8 but a forward reference
// from a `const` initializer to another `const` declaration further
// down the same module trips the temporal dead zone — keep this above
// the rules array.
const TEST_FILE_EXCLUDES = [
  /\.test\./i,                       // *.test.{js,ts,...}  Jest / Vitest
  /\.spec\./i,                       // *.spec.{js,ts,...}  Mocha / Jasmine / Karma
  /[\/\\]__tests__[\/\\]/i,          // /__tests__/         Jest folder convention
  /[\/\\]tests?[\/\\]/i,             // /test/ or /tests/   most other frameworks
  /[\/\\]spec[\/\\]/i,               // /spec/              Rails / RSpec
  /[\/\\]test[_-][^\/\\]+$/i,        // /test_*.py /test-*.js  pytest + custom runners
  /[_-]test\.[a-z]+$/i,              // /*_test.py /*-test.js  alt pytest convention
];

// ---------------------------------------------------------------------------
// CENTRALIZED FILE EXTENSIONS (1.3.1)
// ---------------------------------------------------------------------------
//
// Pre-1.3.1 each rule hardcoded its own fileTypes list. Most rules
// said `[".js", ".ts", ".jsx", ".tsx"]` and silently missed
// `.mjs/.cjs/.mts/.cts` — modern ESM/CommonJS module extensions that
// any post-2020 Node project uses. The 1.3.0 release fixed this for
// INJ-005b only; this release applies the same fix consistently.
//
// JS_TS_EXTS  — every JavaScript/TypeScript module extension we want
//               to scan. Use this for any rule whose pattern looks
//               for JS/TS source-level constructs (eval, console.log,
//               innerHTML, dangerouslySetInnerHTML, raw SQL, any-type).
// JS_TS_PY_EXTS — same plus Python. Use this for cross-language rules
//                 (secrets, credentials, hardcoded URLs/IPs).
// SECRET_FILE_EXTS — JS/TS/Python plus the data-format extensions
//                    where credentials commonly leak: .env, .json,
//                    .yaml, .yml. Use this for any SEC-* rule.
// TS_EXTS — TypeScript-only extensions for rules like TS-001
//           (`any` type detection) that are not relevant in plain JS.
//
// Defining these as `const` arrays at module top means a future rule
// addition only has to reference the constant; new file-extension
// support flows through the whole rule set automatically.

const JS_TS_EXTS    = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts", ".cts"];
const JS_TS_PY_EXTS = [...JS_TS_EXTS, ".py"];
const SECRET_FILE_EXTS = [...JS_TS_PY_EXTS, ".env", ".json", ".yaml", ".yml"];
const TS_EXTS       = [".ts", ".tsx", ".mts", ".cts"];

// ---------------------------------------------------------------------------
// PROJECT SHAPE DETECTION — "does this project look like an HTTP server?"
// ---------------------------------------------------------------------------
//
// Gate for DEP-001 (and any future deploy-shaped rules). Returns true only
// when the project clearly has an HTTP server framework or clearly calls
// a listen-style bootstrap in source.
//
// Pre-1.2.4 DEP-001 fired on every project that didn't contain the
// substring "health" anywhere. That's correct for real HTTP services but
// produces a spurious MEDIUM finding on every CLI tool, static site,
// library, npm package, code-generation skill, desktop app, and notebook
// — none of which should have a /health endpoint. Audit testing across 12
// real projects on the user's machine showed 9 of them hitting exactly
// this false positive.
//
// The detector runs in two stages so it's cheap on the common case:
//
//   1. MANIFEST CHECK — the fast path. Looks at package.json /
//      requirements.txt / pyproject.toml / Pipfile in the project root
//      for any known HTTP server framework dependency. 95% of real server
//      projects are detectable this way with a few tens of bytes of I/O.
//
//   2. SOURCE-PATTERN CHECK — the fallback. Only runs when the manifest
//      check comes back empty. Scans a capped sample of .js/.ts/.py
//      source files for `.listen(`, `createServer(`, `fastify(`, etc.
//      The source check exists because some projects (typically single-
//      file servers run via tsx / bun / deno) have no manifest but are
//      still clearly servers. The cap keeps the worst-case cost bounded
//      on massive repos that happen not to have a manifest.
//
// This helper is a `function` declaration (hoisted), not a `const`, so
// AUDIT_RULES below can reference it without tripping the temporal dead
// zone. Same pattern as the TEST_FILE_EXCLUDES hoisting note above.

// Known HTTP server frameworks. Conservative list — only frameworks whose
// presence in a manifest unambiguously means the project listens on a
// port. Client libraries (axios, got, undici) are deliberately NOT here.
const HTTP_SERVER_FRAMEWORKS_JS = [
  "express", "fastify", "koa", "@hapi/hapi", "hapi", "restify",
  "@nestjs/core", "nest", "polka", "tinyhttp", "@tinyhttp/app",
  "connect", "h3", "hono", "feathersjs", "@feathersjs/feathers",
  "micro", "sails", "loopback", "adonisjs", "@adonisjs/core",
];

const HTTP_SERVER_FRAMEWORKS_PY = [
  "fastapi", "flask", "django", "starlette", "tornado",
  "aiohttp", "bottle", "sanic", "quart", "falcon", "pyramid",
  "cherrypy", "masonite", "litestar",
];

// Source-file listen / createServer patterns. Anchored on a word boundary
// so substrings inside comments / identifiers don't trigger, and wrapped
// with `\s*\(` so we only match call sites. Kept tight so this is a
// SECOND-chance signal — if a project has one of these, it's a server.
const LISTEN_PATTERNS = [
  /\b(?:app|server|fastify|instance)\.listen\s*\(/,
  /\bhttp\.createServer\s*\(/,
  /\bhttps\.createServer\s*\(/,
  /\bnet\.createServer\s*\(/,
  /\bcreateServer\s*\(/,                                      // hono / polka
  /\bfastify\s*\(\s*[{)]/,                                    // const f = fastify({...})
  /\bserver\.bind\s*\(/,                                      // raw net servers
  /\buvicorn\.run\s*\(/,                                      // Python: uvicorn.run(app, ...)
  /\bapp\.run\s*\(/,                                          // Python Flask: app.run(...)
];

// Cap on how many source files we scan for listen patterns in the
// fallback check. 150 files is enough to catch any realistic "single-file
// server" while keeping worst-case cost bounded for repos with thousands
// of source files. We sort by filename length so shallow paths are
// examined first — the bootstrap is almost always at the project root or
// one level deep.
const LISTEN_SCAN_FILE_CAP = 150;

function looksLikeHttpServer(rootDir, files) {
  // Stage 1 — manifest check (fast path)

  // package.json: express, fastify, koa, etc. Check both `dependencies`
  // and `devDependencies` — some projects put their web framework under
  // devDependencies when it's only used during tests or tooling. Either
  // way, if express is in the manifest it's a server shape.
  const pkgPath = path.join(rootDir, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg  = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const deps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
        ...(pkg.peerDependencies ?? {}),
      };
      for (const name of HTTP_SERVER_FRAMEWORKS_JS) {
        if (deps[name]) return true;
      }
    } catch {
      // Malformed package.json — fall through to source check. Not our
      // job to surface JSON parse errors here; other tooling will.
    }
  }

  // requirements.txt: fastapi, flask, django, etc. One package per line,
  // optional version pin, comment lines start with #. Stripped to the
  // bare package name then lowercased for comparison.
  const reqPath = path.join(rootDir, "requirements.txt");
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, "utf8");
      for (const rawLine of content.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        // Strip version pins, extras, env markers: `fastapi[all]==0.104.0 ; python_version >= '3.8'`
        const name = line.split(/[=<>!~;\s[]/)[0].toLowerCase();
        if (HTTP_SERVER_FRAMEWORKS_PY.includes(name)) return true;
      }
    } catch {
      // ignore
    }
  }

  // pyproject.toml: substring-scan for each framework name. We don't pull
  // in a TOML parser for a dependency-free project — a substring match on
  // `"fastapi"` / `"flask"` etc. inside the dependencies table is reliable
  // enough in practice. False positives would require someone to mention
  // a framework name in a pure string context, which is rare.
  const pyprojectPath = path.join(rootDir, "pyproject.toml");
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, "utf8").toLowerCase();
      for (const name of HTTP_SERVER_FRAMEWORKS_PY) {
        // Match `"fastapi"` or `fastapi =` (poetry and PEP 621 both used)
        if (new RegExp(`["']${name}["']|\\b${name}\\s*[=~]`).test(content)) return true;
      }
    } catch {
      // ignore
    }
  }

  // Pipfile: same substring approach as pyproject.toml.
  const pipfilePath = path.join(rootDir, "Pipfile");
  if (fs.existsSync(pipfilePath)) {
    try {
      const content = fs.readFileSync(pipfilePath, "utf8").toLowerCase();
      for (const name of HTTP_SERVER_FRAMEWORKS_PY) {
        if (new RegExp(`["']${name}["']|\\b${name}\\s*=`).test(content)) return true;
      }
    } catch {
      // ignore
    }
  }

  // Stage 2 — source-pattern fallback (slow path, capped)
  //
  // Only runs when the manifest check came back empty. Handles the single-
  // file-server / no-manifest case without paying for file I/O on every
  // run of a normal manifest-having project.
  const candidates = files
    .filter((f) => /\.(?:js|mjs|cjs|ts|mts|cts|py)$/i.test(f))
    .sort((a, b) => a.length - b.length) // shallow paths first
    .slice(0, LISTEN_SCAN_FILE_CAP);

  for (const file of candidates) {
    let content;
    try { content = fs.readFileSync(file, "utf8"); }
    catch { continue; }
    for (const re of LISTEN_PATTERNS) {
      if (re.test(content)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// AUDIT RULES
// Each rule: { id, category, severity, description, pattern, fileTypes }
// ---------------------------------------------------------------------------

const AUDIT_RULES = [
  // --- SECRETS ---
  //
  // SEC-001 (and the other sk-* rules): the pre-1.1.1 pattern was
  // `/sk-[a-zA-Z0-9]{20,}/` which silently missed both current-format
  // OpenAI project keys (`sk-proj-...`) and Anthropic Claude keys
  // (`sk-ant-api03-...`) because the hyphen after the provider tag is
  // outside [a-zA-Z0-9]. The regex stopped matching at 4 chars — far
  // below the {20,} threshold — and reported files as clean. A leaked
  // current-format key would pass the audit with no finding.
  //
  // Fix: split into provider-labelled rules so the violation report
  // names the provider the operator just leaked, and keep a legacy
  // fallback for historical `sk-` tokens still in circulation. Kept in
  // lockstep with the runtime SECRET_PATTERNS in 01-injection-guard.js
  // and security/injection_guard.py.
  {
    id: "SEC-001", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded OpenAI Project API key (sk-proj-...)",
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-010", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded Anthropic API key (sk-ant-api...)",
    pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-001b", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded OpenAI API key (legacy sk- format)",
    pattern: /sk-(?!proj-|ant-api\d{2}-)[a-zA-Z0-9]{20,}/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-002", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-003", category: "Secrets", severity: "CRITICAL",
    description: "Hardcoded GitHub token",
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-004", category: "Secrets", severity: "CRITICAL",
    description: "Private key embedded in code",
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-005", category: "Secrets", severity: "HIGH",
    description: "Inline password assignment",
    pattern: /password\s*[:=]\s*["'][^"']{6,}["']/i,
    fileTypes: SECRET_FILE_EXTS,
  },
  {
    id: "SEC-006", category: "Secrets", severity: "HIGH",
    description: "Hardcoded API key assignment",
    pattern: /api[_-]?key\s*[:=]\s*["'][^"']{8,}["']/i,
    fileTypes: SECRET_FILE_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
  },
  {
    // SEC-011: connection strings with embedded credentials.
    // Previously nothing in the audit flagged something like
    //   "postgresql://admin:hunter2@db.internal:5432/prod"
    // even though every part of the Guardian philosophy treats that as
    // a hardcoded secret. Covers the common protocols developers pin
    // into source without thinking: postgres, mysql, mongodb
    // (including mongodb+srv SRV records), redis/rediss, and amqp/amqps.
    // User part uses `*` so the redis "password only" variant
    // (`redis://:mypass@host`) also matches. Character classes
    // exclude `@` and `/` so the regex cannot walk past the credential
    // boundary into the host portion.
    id: "SEC-011", category: "Secrets", severity: "HIGH",
    description: "Connection string with embedded credentials (user:pass@host)",
    pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:@\/\s"'`]*:[^@\s"'`]+@/i,
    fileTypes: SECRET_FILE_EXTS,
  },

  // --- HARDCODED CONFIG ---
  {
    id: "CFG-001", category: "Configuration", severity: "HIGH",
    description: "Hardcoded localhost URL",
    pattern: /["'`]https?:\/\/localhost:\d+/,
    fileTypes: JS_TS_PY_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
  },
  {
    id: "CFG-002", category: "Configuration", severity: "HIGH",
    description: "Hardcoded 127.0.0.1 address",
    pattern: /["'`]https?:\/\/127\.0\.0\.1/,
    fileTypes: JS_TS_PY_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
  },
  // CFG-003: hardcoded IP address. Excludes test files via the
  // standard TEST_FILE_EXCLUDES list. The excludeLinePatterns list
  // below distinguishes "binding to localhost" (security best
  // practice — refuses external connections) from "URL pointing at a
  // hardcoded IP" (real config leak). Pre-1.2.2 the rule conflated
  // those two opposite things and flagged the safe form as a bug,
  // which is actively misleading security advice. The bind-context
  // patterns are anchored on the syntactic shape of the listen / bind
  // call so they cannot match a URL string in the same line.
  {
    id: "CFG-003", category: "Configuration", severity: "MEDIUM",
    description: "Hardcoded IP address (potential config leak)",
    pattern: /["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/,
    fileTypes: JS_TS_PY_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
    excludeLinePatterns: [
      /\bhost\s*[:=]\s*["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/,         // host: '127.0.0.1' / host = '127.0.0.1'
      /\.listen\s*\([^,)]*,\s*["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/,  // .listen(port, '127.0.0.1', ...)
      /\bbind\s*\(\s*["'`]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'`]/,           // bind('127.0.0.1', ...)
    ],
  },

  // --- ERROR HANDLING ---
  //
  // ERR-001: a catch block whose body contains only whitespace and/or
  // comments. The pre-1.1.1 pattern was `catch (...) { }` — literal empty
  // braces only — which missed the most common lazy-dev variant:
  //   try { ... } catch (e) { /* silent failure */ }
  // The comment makes the body non-empty to a character counter but
  // identically harmful to error handling: exceptions are swallowed,
  // recovery paths never execute, and the operator sees no log line
  // when production breaks. The updated pattern accepts any sequence
  // of whitespace, `//` line comments, and `/* ... */` block comments
  // inside the braces and treats that as "silent" for audit purposes.
  //
  // Multiline is required because a multi-line catch body spans lines;
  // the scanner passes whole-file content in so the dotall class works
  // end-to-end.
  {
    id: "ERR-001", category: "Error Handling", severity: "HIGH",
    description: "Silent catch block — swallows errors (empty or comments-only body)",
    pattern: /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*\}/,
    fileTypes: JS_TS_EXTS,
    wholeFile: true,
  },
  {
    id: "ERR-002", category: "Error Handling", severity: "HIGH",
    description: "catch block with only console.log — not structured logging",
    pattern: /catch\s*\([^)]*\)\s*\{\s*console\.log/,
    fileTypes: JS_TS_EXTS,
  },
  {
    id: "ERR-003", category: "Error Handling", severity: "MEDIUM",
    description: "console.log() in non-test code — use structured logger",
    pattern: /console\.log\(/,
    fileTypes: JS_TS_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
  },

  // --- API DESIGN ---
  {
    id: "API-001", category: "API Design", severity: "MEDIUM",
    description: "API route without version prefix (/api/v1/...)",
    pattern: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`]\/api\/(?!v\d)/,
    fileTypes: JS_TS_EXTS,
  },

  // --- SECURITY PATTERNS ---
  {
    id: "INJ-001", category: "Injection Risk", severity: "CRITICAL",
    description: "Direct user input passed to eval()",
    pattern: /eval\s*\(/,
    fileTypes: JS_TS_EXTS,
  },
  {
    id: "INJ-002", category: "Injection Risk", severity: "HIGH",
    description: "innerHTML assignment — potential XSS",
    pattern: /\.innerHTML\s*=/,
    excludePatterns: TEST_FILE_EXCLUDES,
    fileTypes: JS_TS_EXTS,
  },
  {
    id: "INJ-003", category: "Injection Risk", severity: "HIGH",
    description: "dangerouslySetInnerHTML — potential XSS (ensure sanitized)",
    pattern: /dangerouslySetInnerHTML/,
    fileTypes: JS_TS_EXTS,
  },
  //
  // INJ-004 / INJ-005: raw SQL detection. The README has claimed "raw SQL"
  // detection for a long time, but prior to 1.1.1 no rule implemented it.
  // A planted test file with `db.raw("SELECT * FROM users WHERE id = " + id)`
  // received zero findings and sailed past the audit. Fixed here.
  //
  // INJ-004 catches the concatenation form: a query keyword followed by
  // a string concatenation in the same query. Matches both single and
  // double quotes, both template literals (backticks), and covers the
  // common DB driver entry points (query, execute, raw, run, all).
  //
  // INJ-005 catches interpolation inside a template literal containing
  // SQL — `db.query(\`SELECT * FROM users WHERE id = ${userId}\`)`.
  // Template strings with ${} are just as dangerous as + concatenation;
  // many junior devs think the backticks make them "different" but the
  // value still lands in the query string unescaped.
  //
  // Both rules are wholeFile: true because SQL queries frequently span
  // multiple lines and the string concat or interpolation may not sit
  // on the same physical line as the query verb.
  {
    id: "INJ-004", category: "Injection Risk", severity: "CRITICAL",
    description: "Raw SQL built with string concatenation — SQL injection risk",
    // Verbs deliberately limited to the ones that are unambiguously
    // "pass this string to the database": `query`, `execute`, `exec`,
    // `raw`, `prepare`. Looser verbs like `get`/`run`/`all` are common
    // in HTTP clients (axios.get), array methods, and build tools —
    // including them would produce too many false positives to be
    // worth it. If your ORM uses one of those verbs, add a custom rule
    // in your own fork rather than loosening the default.
    //
    // Bounded lazy spans (`{0,300}?`) around the SQL keyword so queries
    // whose content contains a nested apostrophe like
    //   db.raw("DELETE FROM sessions WHERE id = '" + sid + "'")
    // still match. A prior [^`'"]* form tried to skip the inner quote
    // and either matched at the wrong boundary or not at all. The
    // quantifier bound prevents catastrophic backtracking on pathological
    // inputs — 300 chars is long enough for a realistic query and short
    // enough that worst-case work is millisecond-scale.
    pattern: /\b(?:query|execute|exec|raw|prepare)\s*\(\s*['"`][\s\S]{0,300}?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[\s\S]{0,300}?['"`]\s*\+/i,
    fileTypes: JS_TS_PY_EXTS,
    wholeFile: true,
  },
  {
    id: "INJ-005", category: "Injection Risk", severity: "CRITICAL",
    description: "Raw SQL in template literal with ${} interpolation — SQL injection risk",
    pattern: /\b(?:query|execute|exec|raw|prepare)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{[^`]*`/i,
    fileTypes: JS_TS_EXTS,
    wholeFile: true,
  },
  //
  // INJ-005b (new in 1.3.0) — variable-indirection companion to INJ-005.
  //
  // The pre-1.3.0 INJ-005 required the backtick template to be the first
  // argument of `query|execute|exec|raw|prepare`. A simple two-line refactor
  // bypassed the rule entirely:
  //
  //   const sql = `SELECT * FROM users WHERE id = ${userId}`;
  //   db.query(sql);
  //
  // The SQL is still unparameterized; the user input is still spliced into
  // the query text; the injection surface is identical — but the old regex
  // only saw `db.query(sql)` (no backtick, no match) and the bug sailed
  // through the audit.
  //
  // INJ-005b catches the DECLARATION SITE instead of the CALL site. Writing
  //   `SELECT ... ${x}`
  // anywhere in a source file is independently dangerous: if that line
  // exists, the code is broken whether the variable is then passed directly
  // to `db.query(sql)` or through ten more levels of indirection.
  //
  // Both rules are kept. A single vulnerable line like
  //   db.query(`SELECT * FROM u WHERE id = ${id}`)
  // fires both INJ-005 and INJ-005b — slightly redundant but harmless,
  // and splitting them lets the two match independently so a project
  // using only one form still gets caught. Running INJ-005b as a
  // `wholeFile` rule means a multi-line template literal split across
  // several physical lines is still detected.
  {
    id: "INJ-005b", category: "Injection Risk", severity: "CRITICAL",
    description: "Template-literal SQL with ${} interpolation — SQL injection risk (variable form)",
    pattern: /`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{[^`]*`/i,
    fileTypes: JS_TS_EXTS,
    wholeFile: true,
    // This rule is very noisy on documentation files that show the pattern
    // as an example of what NOT to do (e.g. STANDARDS.md, an ORM README).
    // The global doc-exempt marker `otlc-guardian:doc` plus the per-file
    // `otlc-guardian:audit-exempt` marker both already short-circuit it
    // at the scanner layer, so no per-rule exclude list is needed here.
  },
  {
    id: "INJ-006", category: "Injection Risk", severity: "CRITICAL",
    description: "Python SQL with f-string or % formatting — SQL injection risk",
    // Python equivalents: f"SELECT ... {user}" and "SELECT ... %s" % (user,).
    // cursor.execute is the standard entry point; sqlalchemy's
    // session.execute(text(...)) with f-strings is also caught here.
    //
    // Pre-1.3.0 the inner character class was `[^"']*` which excluded BOTH
    // quote styles. That meant any real-world f-string containing a literal
    // like `WHERE name = 'admin'` broke the match and the rule silently
    // did nothing on most production-shaped SQL.
    //
    // Fix (1.3.0): split into quote-specific alternation branches so each
    // outer quote style allows the opposite inner quote style through.
    //
    //   Branch 1: f"..."  — inner class is `[^"]` (allows `'`)
    //   Branch 2: f'...'  — inner class is `[^']` (allows `"`)
    //   Branch 3: "..." % (user,) / '...' % (user,)  — legacy % formatting
    //             (same two inner classes for the same reason)
    //
    // The third branch also catches `.execute("SELECT ... %s" % user)` via
    // the trailing `%` operator — the old regex had this branch as well,
    // now split into two quote-specific sub-branches.
    pattern: /\bexecute\s*\(\s*(?:f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"]*\{[^"]*"|f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^']*\{[^']*'|"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"]*%[sd][^"]*"\s*%|'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^']*%[sd][^']*'\s*%)/i,
    fileTypes: [".py"],
    wholeFile: true,
  },

  // --- DEPLOYMENT ---
  //
  // DEP-001 is gated on `looksLikeHttpServer()` so it only fires when the
  // project actually has an HTTP server framework (express, fastify, koa,
  // fastapi, flask, ...) or clearly calls `.listen(` / `createServer(` in
  // source. Pre-1.2.4 the rule fired on every project without a "health"
  // substring, which produced spurious findings on CLI tools, static
  // sites, libraries, notebooks, and desktop apps — none of which should
  // have a /health endpoint. The gate mirrors how `isPythonProject()` in
  // bin/guardian.js only requires the Python injection module when the
  // project actually looks Python-shaped. See 1.2.4 CHANGELOG entry.
  {
    id: "DEP-001", category: "Deployment", severity: "MEDIUM",
    description: "No health check endpoint found",
    pattern: null, // checked separately
    fileTypes: [],
    // 1.3.1: signature is `(files, projectRoot)`. The second arg is
    // the upward-walked project root, NOT the scan target. That lets
    // looksLikeHttpServer find the manifest even when the user runs
    // `guardian audit ./src` from a project whose package.json lives
    // one level up. Pre-1.3.1 the manifest check failed silently in
    // that case and the rule fell through to the source-pattern
    // fallback (which still worked for express because of `app.listen`,
    // but failed for projects whose framework only registered via the
    // manifest).
    checkFn: (files, projectRoot) => {
      if (!looksLikeHttpServer(projectRoot, files)) return false;
      return !files.some((f) => /health/.test(fs.readFileSync(f, "utf8").toLowerCase()));
    },
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
    fileTypes: TS_EXTS,
    excludePatterns: TEST_FILE_EXCLUDES,
  },
];

// ---------------------------------------------------------------------------
// FILE SCANNER
// ---------------------------------------------------------------------------

// Directories the audit walker refuses to enter. Two categories:
//
//   1. Dependency / vendored code — `node_modules` (npm), `vendor`
//      (PHP composer), `bower_components` (legacy JS), `target` (Rust /
//      Maven build outputs that bundle dependencies), `site-packages` /
//      `dist-packages` (Python install dirs). The auditor's job is to
//      scan YOUR code for YOUR bugs. Dependency code is not your code,
//      you can't fix it, and security scanning of dependencies is a
//      different tool's job (npm audit, pip-audit, composer audit) —
//      all of which are already in Guardian's CI workflow as separate
//      steps. Walking these dirs produces 100% noise that drowns real
//      findings.
//
//   2. Caches and build artifacts — `__pycache__`, `.pytest_cache`,
//      `.mypy_cache`, `.ruff_cache`, `.turbo`, `.cache`, `coverage`,
//      `dist`, `build`, `.next`, `out`, `.git`. Generated content,
//      not source. The auditor would re-flag the same issues as the
//      source dirs above, with confusing line numbers from minified
//      bundles.
//
// Python venvs (`venv`, `.venv`) are kept on the list because most
// projects also store their venv inside the project root. `env` is
// deliberately NOT on this list — too many real projects have a
// legitimate `env/` source directory and we'd rather have false
// positives than false negatives for source code.
const SKIP_DIRS = new Set([
  // JS / TS dependency dirs
  "node_modules", "bower_components",
  // PHP composer
  "vendor",
  // Python venvs and install dirs
  "venv", ".venv", "site-packages", "dist-packages",
  // Build outputs
  "dist", "build", ".next", "out", "target",
  // Caches
  "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
  ".turbo", ".cache", "coverage",
  // Git
  ".git",
]);

// (TEST_FILE_EXCLUDES is defined at the top of this file, before
// AUDIT_RULES, because the rules reference it. See the block there.)

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

  // `wholeFile: true` rules need to see the file as one string. This
  // is required for any pattern that legitimately spans multiple lines
  // (e.g. a silent catch block whose comment body wraps, a raw SQL
  // query built from a template literal that runs across lines). For
  // those, we match against the full content and compute the line
  // number from the match offset so the reporter still points at a
  // specific line.
  //
  // Line-by-line scanning is kept as the default because it's faster,
  // more cache-friendly, and correct for the majority of single-line
  // patterns (hardcoded secrets, console.log, innerHTML, any-type).
  if (rule.wholeFile) {
    let match;
    // Clone the regex with the global flag so `.exec` advances through
    // the string. Rules are written without `g` to keep
    // `.test(line)` semantics clean in the default line-by-line path;
    // we add it here only for whole-file scanning.
    const globalRe = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    while ((match = globalRe.exec(content)) !== null) {
      const before = content.slice(0, match.index);
      const lineNo = before.split("\n").length;
      // Best-effort one-line snippet for the report: the matched text
      // collapsed to a single line and truncated to 120 chars.
      const snippet = match[0].replace(/\s+/g, " ").trim().slice(0, 120);
      findings.push({
        file:    filePath,
        line:    lineNo,
        content: snippet,
        rule,
      });
      // Prevent zero-width infinite loops on oddly anchored patterns.
      if (match.index === globalRe.lastIndex) globalRe.lastIndex++;
    }
    return findings;
  }

  const lines = content.split("\n");

  lines.forEach((line, index) => {
    if (rule.pattern.test(line)) {
      // excludeLinePatterns lets a rule suppress findings whose
      // surrounding line matches one of a list of "this is the safe
      // form" patterns. Used by CFG-003 to distinguish a server bind
      // call (host: '127.0.0.1', listen(port, '127.0.0.1', ...)) —
      // which is a security best practice — from a hardcoded IP in a
      // URL or config string, which is the real bug. Pre-1.2.2 the
      // rule conflated those two opposite things and flagged the safe
      // form as a config leak.
      if (rule.excludeLinePatterns?.some((p) => p.test(line))) return;

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
// PROJECT ROOT DETECTION (1.3.1)
// ---------------------------------------------------------------------------
//
// Walks upward from the scan target looking for project markers. Used
// to separate `projectRoot` (where the manifest, .git, and central
// allowlist live) from `scanRoot` (the directory the user told the
// audit to scan). Pre-1.3.1 the auditor conflated the two: if you
// ran `guardian audit ./src` from a project root, manifest lookups
// hit `./src/package.json` (which doesn't exist) and the central
// allowlist at `<root>/security/.audit-allowlist` was ignored.
//
// Markers, in priority order:
//   1. `.git/` directory — the strongest signal a project root exists
//   2. `security/.audit-allowlist` — Guardian's own central allowlist
//   3. `package.json` (Node), `requirements.txt`/`pyproject.toml`/`Pipfile` (Python)
//
// Walk caps at 8 levels deep or the filesystem root, whichever comes
// first. If no markers are found, falls back to the scan target as
// its own project root (matches pre-1.3.1 behavior for orphan dirs).
//
// Returns an absolute path string.

const PROJECT_ROOT_MARKERS = [
  ".git",
  path.join("security", ".audit-allowlist"),
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "Pipfile",
];

function findProjectRoot(scanDir) {
  let current = path.resolve(scanDir);
  // Cap depth at 8 — most real projects sit no more than a few levels
  // below the filesystem root, and an attacker-controlled symlink
  // farm shouldn't be able to make us walk forever.
  for (let depth = 0; depth < 8; depth++) {
    for (const marker of PROJECT_ROOT_MARKERS) {
      if (fs.existsSync(path.join(current, marker))) return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break; // hit filesystem root
    current = parent;
  }
  // No markers found anywhere up the tree — fall back to the original
  // scan target. This matches pre-1.3.1 behavior for orphan dirs and
  // avoids surprising users who run audits in /tmp scratch directories.
  return path.resolve(scanDir);
}

// ---------------------------------------------------------------------------
// MAIN AUDIT RUNNER
// ---------------------------------------------------------------------------

function runAudit(targetDir, options = {}) {
  const { outputJson = false, failOnError = false } = options;
  // 1.3.1: scanRoot is what the user asked to scan; projectRoot is where
  // manifests, .git, and the central allowlist live. They're identical
  // when the user audits the project root directly (the common case)
  // and divergent when the user audits a subdirectory.
  const scanRoot    = path.resolve(targetDir);
  const projectRoot = findProjectRoot(scanRoot);

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
  status(`    Target  : ${scanRoot}`);
  if (projectRoot !== scanRoot) {
    // Visibility — surfacing the project root makes it obvious why a
    // root-level allowlist is being honored on a subdirectory scan,
    // and helps debug "wrong project root" detection issues.
    status(`    Project : ${projectRoot}`);
  }
  status(`    Rules   : ${AUDIT_RULES.filter((r) => r.pattern).length} pattern rules`);

  // ── Load exemption state once, up front ──────────────────────────────
  // 1.3.1: load from projectRoot, not scanRoot. Pre-1.3.1 a subdir
  // scan would silently ignore the central allowlist at
  // <projectRoot>/security/.audit-allowlist.
  const allowlist = loadAllowlist(projectRoot);

  // Collect all relevant files. Walker scans the user's requested
  // target, NOT the upward-walked project root — the user said "audit
  // ./src" and they meant "audit ./src", not "audit my whole repo".
  const allExtensions = [...new Set(AUDIT_RULES.flatMap((r) => r.fileTypes))];
  const files         = collectFiles(scanRoot, allExtensions);

  // Precompute which files are exempt and via which mechanism. We do
  // this once here instead of inside scanFile so the same file isn't
  // re-checked once per rule, and so the audit summary can report
  // exemption counts up front.
  //
  // 1.3.1: exemptionMechanism resolves the file's path RELATIVE TO
  // projectRoot (not scanRoot) when checking against the allowlist.
  // The central .audit-allowlist contains entries like
  // `bin/guardian.js  # reason: ...` which are project-root-relative;
  // computing the rel-path against scanRoot would produce paths like
  // `../../bin/guardian.js` and the lookup would never match.
  const exemptPaths     = new Set();
  const exemptByMarker  = [];
  const exemptByList    = [];

  for (const file of files) {
    let head;
    try { head = fs.readFileSync(file, "utf8"); }
    catch { continue; }
    const mech = exemptionMechanism(file, head, allowlist, projectRoot);
    if (mech === "marker") {
      exemptPaths.add(file);
      exemptByMarker.push(path.relative(scanRoot, file).replace(/\\/g, "/"));
    } else if (mech === "allowlist") {
      exemptPaths.add(file);
      exemptByList.push(path.relative(scanRoot, file).replace(/\\/g, "/"));
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

  // Function-based rules. Signature: checkFn(files, projectRoot).
  // The second arg was added in 1.2.4 so project-shape gates (e.g.
  // DEP-001's looksLikeHttpServer check) can read root-level
  // manifests. In 1.3.1 it was renamed from `rootDir` to
  // `projectRoot` because the auditor now distinguishes the upward-
  // walked project root from the scan target — manifest checks must
  // see the project root, not the subdirectory the user happened to
  // scan. Existing rules that only need the file list (e.g. DEP-002)
  // can still ignore the second argument.
  for (const rule of AUDIT_RULES) {
    if (!rule.checkFn) continue;
    const triggered = rule.checkFn(files, projectRoot);
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
      // Compact one-line severity summary instead of the trailing
      // four-line "Summary:" block the pre-1.2.3 reporter printed
      // after the findings list. Uses middle-dot separators so the
      // four counts read as a single status line.
      const summaryLine =
        `${bySeverity.CRITICAL.length} CRITICAL · ` +
        `${bySeverity.HIGH.length} HIGH · ` +
        `${bySeverity.MEDIUM.length} MEDIUM · ` +
        `${bySeverity.LOW.length} LOW`;

      console.warn(`⚠️  [OTLC GUARDIAN] AUDIT COMPLETE — ${allFindings.length} issue(s) found`);
      console.warn(`    ${summaryLine}\n`);

      // Layout per severity bucket:
      //
      //   ICON SEVERITY (count)
      //
      //     [RULE-ID] description · N occurrence(s)
      //       relative/path/to/file.ts:12, 34, 56
      //         offending line snippet (first occurrence on that file)
      //       relative/path/to/another/file.ts:9
      //         offending line snippet
      //
      //     [NEXT-RULE] ...
      //
      // The pre-1.2.3 layout repeated `[CFG-001] Hardcoded localhost
      // URL` 14 times in a row when the same rule fired on 14 lines,
      // each with a full absolute path. Real-world DevNeural audit
      // (56 findings) was over 200 lines of console output that all
      // looked the same. The grouping below collapses that to one
      // header per rule + one line per file + one snippet per file,
      // with relative paths. Same DevNeural audit now fits in ~30
      // lines that you can actually scan.
      for (const [severity, findings] of Object.entries(bySeverity)) {
        if (findings.length === 0) continue;
        const icon = severity === "CRITICAL" ? "🚨" : severity === "HIGH" ? "⚠️ " : severity === "MEDIUM" ? "🔶" : "🔵";
        console.warn(`${icon} ${severity} (${findings.length})\n`);

        // Group this severity's findings by rule ID. Map preserves
        // insertion order so rules appear in the order they were
        // first encountered in the AUDIT_RULES list.
        const byRule = new Map();
        for (const f of findings) {
          if (!byRule.has(f.rule.id)) {
            byRule.set(f.rule.id, { rule: f.rule, items: [] });
          }
          byRule.get(f.rule.id).items.push(f);
        }

        for (const { rule, items } of byRule.values()) {
          const occLabel = items.length === 1 ? "1 occurrence" : `${items.length} occurrences`;
          console.warn(`   [${rule.id}] ${rule.description} · ${occLabel}`);

          // Within a rule, group findings by the file they hit.
          // Multiple line numbers on the same file collapse to a
          // single comma-separated list (`file.ts:7, 12, 34`) with
          // the first finding's snippet shown once underneath as
          // context — repeating the snippet for every line was the
          // visual mush the pre-1.2.3 reporter produced.
          const byFile = new Map();
          for (const f of items) {
            if (!byFile.has(f.file)) byFile.set(f.file, []);
            byFile.get(f.file).push(f);
          }

          for (const [file, fileItems] of byFile) {
            // Display paths relative to scanRoot (what the user asked
            // to scan), not projectRoot (where the manifest lives).
            // The user thinks in terms of "I ran audit on this dir"
            // and the report should reflect that mental model.
            const relFile = path.relative(scanRoot, file).replace(/\\/g, "/") || file;
            const lineNumbers = fileItems
              .map((f) => f.line)
              .filter((n) => typeof n === "number")
              .sort((a, b) => a - b);
            const lineSuffix = lineNumbers.length > 0
              ? `:${lineNumbers.join(", ")}`
              : "";
            console.warn(`     ${relFile}${lineSuffix}`);

            // First non-empty snippet for this file, indented one
            // step deeper than the file path. Rules without snippets
            // (e.g. DEP-001 which is project-level) print no body.
            const snippet = fileItems.find((f) => f.content)?.content;
            if (snippet) console.warn(`       ${snippet}`);
          }

          console.warn(""); // blank line between rules within a severity
        }
      }
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
