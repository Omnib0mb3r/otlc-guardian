# OTLC Guardian coverage map

State of 1.5.0 (unreleased), commit `0fa32ce`, 2026-11-10. Gate plan step 0, item 4.

This map says what Guardian checks, by language and against two public lists:
OWASP ASVS 5.0 (chapters V1 to V17) and the CWE Top 25 for 2025. It is a
skeleton: each row maps a chapter or weakness to the rules that target it,
not to individual ASVS requirements. A requirement-level map is future work.

Grades:

- **covered**: the rules check the main forms of the weakness in the languages listed.
- **partial**: some forms or some languages are checked; the gaps are named.
- **not covered**: no rule targets it.
- **needs check**: the mapping itself is not confirmed. Never read it as covered.

No row is graded covered today. Every Guardian rule is a static pattern or a
per-file analyzer, so it finds common shapes of a weakness, not all of them.

Sources: CWE Top 25 2025 from https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
and ASVS 5.0 chapter names from https://github.com/OWASP/ASVS/tree/master/5.0/en,
both read on 2026-11-10. Rule ids and file types from `security/03-audit.js`
(rule table, lines about 835 to 1430, and the extension constants near line 86).

## 1. By language

Audit rules run per file, chosen by extension. Project checks run once per
project.

| Language or file type | Extensions | Rule families that apply |
|---|---|---|
| JavaScript and TypeScript | `.js .ts .jsx .tsx .mjs .cjs .mts .cts` | SEC, CFG, ERR, API-001, INJ-001 to INJ-005b, AUTHZ-001 to AUTHZ-005, VAL, WEB-001, REP-005; REP-002 on `.js .mjs .cjs`; REP-004 on `.js` |
| TypeScript only | `.ts .tsx .mts .cts` | TS-001 |
| Python | `.py` | SEC, CFG, INJ-004, INJ-006, AUTHZ-011, AUTHZ-013 |
| HTML and components | `.html .htm .vue .svelte` | WEB-001 (`.html .vue .svelte`); REP-001, REP-003, REP-004 (`.html .htm`) |
| Data and config | `.env .json .yaml .yml` | SEC (all secret rules, not on a bare `.env`). A bare `.env` is collected by name for DEP-002 only (BUG-039) |
| nginx config | read by the project check | WEB-002 (no Content-Security-Policy anywhere in the project) |
| Any project | project checks | DEP-001 (no health route, only when the project looks like an HTTP server), DEP-002, WEB-002 |
| Any text, at runtime | not file based | Runtime guard `GUARD-INJ-*` and `GUARD-SEC-*` on AI model input and output; the PreToolUse hook on agent writes to watched paths |

Not scanned by any audit rule: Go, Rust, Java, C#, C and C++, PHP, Ruby,
shell scripts, SQL files, Dockerfiles, CI workflow files, Terraform.

## 2. OWASP ASVS 5.0

| Chapter | Grade | Rules | Gaps |
|---|---|---|---|
| V1 Encoding and Sanitization | partial | INJ-002, INJ-003 (HTML sinks), INJ-004, INJ-005, INJ-005b, INJ-006 (SQL), VAL-002 (email header CRLF) | No output-encoding check beyond the two HTML sinks; no LDAP, XPath, OS command or template injection rules |
| V2 Validation and Business Logic | partial | VAL-001 (request body reaches a side effect without schema validation, JS/TS) | Python not covered; business logic rules are out of reach for a static pattern |
| V3 Web Frontend Security | partial | WEB-001 (token in browser storage), WEB-002 (no CSP, nginx), REP-003, REP-004, INJ-002, INJ-003 | CSP is only checked for nginx; no cookie flag, frame, CORS or subresource-integrity rules. BUG-033, BUG-038 |
| V4 API and Web Service | needs check | API-001 (no `/api/v1` prefix) | API-001 is a house style rule; whether any ASVS V4 requirement maps to it needs check. No rules for HTTP method handling, GraphQL or WebSocket |
| V5 File Handling | not covered | none | Upload type, size and path checks |
| V6 Authentication | partial | AUTHZ-001 (JS/TS), AUTHZ-011 (Python): side effect with no authentication check; AUTHZ-004 (secret compared with `===`) | Password storage, MFA, credential recovery. BUG-031, BUG-032 |
| V7 Session Management | partial | WEB-001 (session token in localStorage or sessionStorage) | Session lifetime, rotation, logout |
| V8 Authorization | partial | AUTHZ-002 (identity from request), AUTHZ-003 and AUTHZ-013 (IDOR, no ownership check), AUTHZ-005 (cache key not scoped to the user) | Per-file analyzers cannot see authorization wired in another file. |
| V9 Self-contained Tokens | not covered | none | JWT algorithm, expiry and audience checks |
| V10 OAuth and OIDC | not covered | none | |
| V11 Cryptography | partial | AUTHZ-004 (non constant-time comparison of a secret) | Weak algorithms, key sizes, random sources. Which V11 section AUTHZ-004 maps to needs check |
| V12 Secure Communication | not covered | none | TLS configuration, plain `http://` endpoints |
| V13 Configuration | partial | SEC-001 to SEC-014 (hardcoded secrets), CFG-001 to CFG-003 (hardcoded hosts), DEP-002 (`.env` that git does not keep out) | Whether ASVS 5.0 places secret management in V13 or elsewhere needs check |
| V14 Data Protection | needs check | Runtime `guardOutput` scans model output for secrets (`GUARD-SEC-*`) | Mapping to a V14 requirement needs check; no rules for PII in logs or caching headers |
| V15 Secure Coding and Architecture | needs check | TS-001 (`any` type), INJ-001 (`eval`, BUG-040) | Dependency auditing is planned (Self-Growing Gate, Lane 4), not built; no deserialization rule. Mapping needs check |
| V16 Security Logging and Error Handling | partial | ERR-001 (silent catch), ERR-002 (catch that only logs to console), ERR-003 (`console.log` in non-test code) | JS/TS only; no check that security events are logged, or that logs hold no secrets |
| V17 WebRTC | not covered | none | |

## 3. CWE Top 25, 2025

| Rank | CWE | Name | Grade | Rules | Notes |
|---|---|---|---|---|---|
| 1 | CWE-79 | Cross-site Scripting | partial | INJ-002, INJ-003 | `innerHTML` and `dangerouslySetInnerHTML` sinks in JS/TS; no template engine or Python sinks |
| 2 | CWE-89 | SQL Injection | partial | INJ-004, INJ-005, INJ-005b, INJ-006; `security/04-sql-guard.js` as the safe path | String-built SQL in JS/TS and Python; ORM raw-query escapes not all seen |
| 3 | CWE-352 | Cross-Site Request Forgery | not covered | none | |
| 4 | CWE-862 | Missing Authorization | partial | AUTHZ-003, AUTHZ-013, AUTHZ-005 | Per-file analyzers |
| 5 | CWE-787 | Out-of-bounds Write | not covered | none | Memory safety; no C or C++ rules |
| 6 | CWE-22 | Path Traversal | not covered | none | |
| 7 | CWE-416 | Use After Free | not covered | none | Memory safety |
| 8 | CWE-125 | Out-of-bounds Read | not covered | none | Memory safety |
| 9 | CWE-78 | OS Command Injection | not covered | none | No `exec`/`spawn` with input rule |
| 10 | CWE-94 | Code Injection | partial | INJ-001 | `eval(` only, JS/TS; misses `new Function`; BUG-040 false positives |
| 11 | CWE-120 | Classic Buffer Overflow | not covered | none | Memory safety |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | not covered | none | |
| 13 | CWE-476 | NULL Pointer Dereference | not covered | none | |
| 14 | CWE-121 | Stack-based Buffer Overflow | not covered | none | Memory safety |
| 15 | CWE-502 | Deserialization of Untrusted Data | not covered | none | |
| 16 | CWE-122 | Heap-based Buffer Overflow | not covered | none | Memory safety |
| 17 | CWE-863 | Incorrect Authorization | partial | AUTHZ-002, AUTHZ-005 | |
| 18 | CWE-20 | Improper Input Validation | partial | VAL-001; runtime `guardInput` for AI model input | JS/TS only for VAL-001 |
| 19 | CWE-284 | Improper Access Control | partial | AUTHZ family | Parent of 862 and 863; same gaps |
| 20 | CWE-200 | Exposure of Sensitive Information | partial | SEC family (secrets in source), WEB-001, runtime `guardOutput` | Error detail sent to clients is not checked |
| 21 | CWE-306 | Missing Authentication for Critical Function | partial | AUTHZ-001, AUTHZ-011 | BUG-031, BUG-032 |
| 22 | CWE-918 | Server-Side Request Forgery | not covered | none | |
| 23 | CWE-77 | Command Injection | not covered | none | |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | partial | AUTHZ-003, AUTHZ-013 | AUTHZ-013 requires the check to name the caller (BUG-030) |
| 25 | CWE-770 | Allocation of Resources Without Limits | not covered | none | The runtime guard caps its own input (`GUARD-INJ-OVERSIZE`); no rule checks the application |

Totals: 0 covered, 10 partial, 15 not covered. Seven of the 15 (the six
buffer, bounds and use-after-free entries plus NULL pointer dereference) are
memory safety weaknesses in languages Guardian does not scan.

## 4. Outside both lists

| Area | Grade | Where |
|---|---|---|
| Prompt injection into an AI model (CWE-1427; OWASP LLM01) | partial | Runtime guard, 28 `GUARD-INJ-*` patterns, normalization and decode passes (chapter 03 of the manual); pattern based, so reworded instructions pass |
| Indirect injection through files agents load (CLAUDE.md, memory, plans) | partial | PreToolUse hook, deny on CRITICAL additions to watched paths; routes it cannot see are listed in `SECURITY.md` |
| Indirect injection through web content | partial | PostToolUse web content guard; warns only |
| Hardcoded credentials (CWE-798) | partial | SEC-001 to SEC-014 in the audit; `GUARD-SEC-*` at runtime (BUG-026 for formats added in 1.5.0; BUG-054 brought the audit to the same set) |
| AV reputation of shipped static sites | partial | REP-001 to REP-005 |

## 5. How to keep this current

A rule added, removed or widened to a new language updates the rows it
touches in the same commit. A row moves to covered only with fixtures for
each form the row names, in `tests/audit.test.js`. The Self-Growing Gate
spec (`TODO.md`) plans a coverage report generated from the rule table;
until then this file is edited by hand.
