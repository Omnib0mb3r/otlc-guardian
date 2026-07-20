/**
 * ============================================================
 * OTLC GUARDIAN — Prompt Injection Guard
 * // security · onthelevelconcepts.com
 * Version: 1.4.0
 * ============================================================
 *
 * Runtime input sanitizer for AI-powered applications.
 * Drop into any Node.js project. Call guardInput() before
 * every call to an AI API.
 *
 * Usage:
 *   import { guardInput } from './security/01-injection-guard.js';
 *   const clean = guardInput(userMessage, { onViolation: myLogger });
 *   const reply = await callAI(clean);
 *
 * ============================================================
 */

// ---------------------------------------------------------------------------
// INJECTION PATTERN REGISTRY
// Extended from original OTLC patterns + adversarial research additions
// ---------------------------------------------------------------------------

export const INJECTION_PATTERNS = [
  // Classic instruction override
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i,          severity: "CRITICAL", id: "INJ-001" },
  { pattern: /ignore\s+(all\s+)?above\s+instructions/i,             severity: "CRITICAL", id: "INJ-002" },
  { pattern: /disregard\s+(all\s+)?previous/i,                      severity: "CRITICAL", id: "INJ-003" },
  { pattern: /forget\s+(all\s+)?(your\s+)?instructions/i,           severity: "CRITICAL", id: "INJ-004" },
  { pattern: /override\s+(system|previous)\s+(prompt|instructions)/i, severity: "CRITICAL", id: "INJ-005" },

  // Role hijacking
  { pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i,                  severity: "HIGH",     id: "INJ-006" },
  { pattern: /pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)/i,        severity: "HIGH",     id: "INJ-007" },
  { pattern: /from\s+now\s+on,?\s+you\s+(?:are|will|should|must)/i, severity: "HIGH",     id: "INJ-008" },
  { pattern: /act\s+as\s+(?:a|an|the)\s+(?!user|customer|person)/i, severity: "HIGH",     id: "INJ-009" },
  { pattern: /roleplay\s+as/i,                                       severity: "HIGH",     id: "INJ-010" },
  { pattern: /simulate\s+(?:a|an|the)\s+/i,                         severity: "MEDIUM",   id: "INJ-011" },

  // Prompt extraction
  { pattern: /(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i, severity: "HIGH", id: "INJ-012" },
  { pattern: /what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions/i, severity: "HIGH", id: "INJ-013" },
  { pattern: /tell\s+me\s+your\s+(?:system\s+)?prompt/i,            severity: "HIGH",     id: "INJ-014" },

  // Token/delimiter injection (LLM-specific)
  { pattern: /<\/?(?:system|assistant|human|user)>/i,                severity: "CRITICAL", id: "INJ-015" },
  { pattern: /\[SYSTEM\]/i,                                          severity: "CRITICAL", id: "INJ-016" },
  { pattern: /\[INST\]/i,                                            severity: "CRITICAL", id: "INJ-017" },
  { pattern: /<<\s*SYS\s*>>/i,                                       severity: "CRITICAL", id: "INJ-018" },
  { pattern: /###\s*(?:System|Instruction|Prompt)/i,                 severity: "CRITICAL", id: "INJ-019" },
  { pattern: /---\s*SYSTEM/i,                                        severity: "CRITICAL", id: "INJ-020" },

  // Jailbreak classics
  { pattern: /do\s+anything\s+now/i,                                 severity: "HIGH",     id: "INJ-021" },
  { pattern: /DAN\s+mode/i,                                          severity: "HIGH",     id: "INJ-022" },
  { pattern: /developer\s+mode/i,                                    severity: "HIGH",     id: "INJ-023" },
  { pattern: /jailbreak/i,                                           severity: "HIGH",     id: "INJ-024" },
  { pattern: /without\s+(?:any\s+)?restrictions/i,                   severity: "HIGH",     id: "INJ-025" },
  { pattern: /bypass\s+(?:your\s+)?(?:safety|filter|guideline)/i,   severity: "HIGH",     id: "INJ-026" },

  // Context poisoning via markup.
  // Lazy quantifiers + explicit newline class — the previous greedy
  // `.*` form was ReDoS-vulnerable on long inputs without a closing
  // delimiter. `[\s\S]*?` also lets the pattern span lines so a
  // multi-line comment doesn't slip past the scan.
  { pattern: /<!--[\s\S]*?(?:ignore|override|system)[\s\S]*?-->/i,    severity: "MEDIUM",   id: "INJ-027" },
  { pattern: /\/\*[\s\S]*?(?:ignore|override|system)[\s\S]*?\*\//i,   severity: "MEDIUM",   id: "INJ-028" },
];

// ---------------------------------------------------------------------------
// INVISIBLE UNICODE DETECTOR
// Used in steganographic injection attacks
// ---------------------------------------------------------------------------

const INVISIBLE_UNICODE_PATTERN = /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/;

// ---------------------------------------------------------------------------
// PRE-SCAN NORMALIZER
// v1.0.1 patch: normalize before scanning to defeat Unicode/encoding bypasses
// ---------------------------------------------------------------------------

/**
 * Normalizes text before scanning.
 * - NFKC normalization converts fullwidth/homoglyph Unicode to ASCII equivalents
 * - Attempts base64 and URL decode to catch encoded payloads
 * - Strips invisible characters for clean comparison
 * @param {string} text
 * @returns {string} normalized text ready for pattern scanning
 */
function normalizeForScan(text) {
  // NFKC: converts ｉｇｎｏｒｅ → ignore, fullwidth chars → ASCII
  let normalized = text.normalize("NFKC");

  // Strip invisible Unicode so zero-width bypasses don't survive
  normalized = normalized.replace(/[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/g, "");

  // Attempt URL decode — catch %69%67%6E%6F%72%65 style payloads
  try {
    const urlDecoded = decodeURIComponent(normalized);
    if (urlDecoded !== normalized) {
      // Scan both original and decoded — return the more dangerous one
      normalized = `${normalized}\n${urlDecoded}`;
    }
  } catch {
    // Invalid URL encoding — not a bypass attempt, continue with original
  }

  // Attempt base64 decode — catch aWdub3Jl... style payloads
  // Only attempt on strings that look like valid base64 (no spaces, right charset)
  const base64Candidate = text.replace(/\s/g, "");
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(base64Candidate)) {
    try {
      const decoded = Buffer.from(base64Candidate, "base64").toString("utf8");
      // Only append if decoded result looks like readable text (not binary garbage)
      if (/^[\x20-\x7E\s]{10,}$/.test(decoded)) {
        normalized = `${normalized}\n${decoded}`;
      }
    } catch {
      // Not valid base64 — continue
    }
  }

  return normalized;
}

// ---------------------------------------------------------------------------
// SECRET LEAK DETECTOR
// Warns if output or input accidentally contains secret-shaped strings
// SEC-006 scoped to context-adjacent matches to reduce false positives (v1.0.1)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SEC-001 / SEC-010 — OpenAI + Anthropic key formats
// ---------------------------------------------------------------------------
// The original SEC-001 pattern was /sk-[a-zA-Z0-9]{20,}/ which silently
// broke on current-generation API keys:
//   - OpenAI projects keys are `sk-proj-...`  (introduced mid-2024)
//   - Anthropic / Claude keys are `sk-ant-api03-...`
// The hyphen after `sk-proj` or `sk-ant` is outside [a-zA-Z0-9], so the
// regex engine stopped at 4 characters — far below the {20,} threshold —
// and reported the input as clean. A leaked key of either format would
// sail through guardOutput() unseen.
//
// Fix: allow hyphen and underscore inside the key body and require the
// full minimum length across the whole token. Split into two rules so
// the label in the violation report tells the operator which provider
// they just leaked (operational clarity matters when you're triaging).
// Test coverage in tests/injection-guard.test.js.
const SECRET_PATTERNS = [
  { pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/,               label: "OpenAI Project API Key",    id: "SEC-001" },
  { pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/,       label: "Anthropic API Key",         id: "SEC-010" },
  // Legacy OpenAI format (`sk-...` without a provider tag) — kept for
  // historical keys still in circulation. Negative lookahead excludes
  // the provider-tagged variants so they're reported under their
  // specific label above rather than this generic one.
  { pattern: /sk-(?!proj-|ant-api\d{2}-)[a-zA-Z0-9]{20,}/, label: "OpenAI API Key (legacy)", id: "SEC-001b" },
  { pattern: /AIza[0-9A-Za-z\-_]{35}/,                 label: "Google API Key",     id: "SEC-002" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/,                    label: "GitHub Token",       id: "SEC-003" },
  { pattern: /gho_[a-zA-Z0-9]{36}/,                    label: "GitHub OAuth Token", id: "SEC-004" },
  { pattern: /AKIA[0-9A-Z]{16}/,                        label: "AWS Access Key",     id: "SEC-005" },
  // SEC-006: scoped to secret-adjacent context only — avoids false positives on JWTs/images
  { pattern: /(?:secret|token|key|password|auth)\s*[:=]\s*["']?[A-Za-z0-9+/]{40,}["']?/i, label: "Context-Adjacent Base64 Secret", id: "SEC-006" },
  { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/, label: "Private Key",   id: "SEC-007" },
  { pattern: /password\s*[:=]\s*["']?[^\s"']{8,}/i,    label: "Inline Password",   id: "SEC-008" },
  { pattern: /api[_-]?key\s*[:=]\s*["']?[^\s"']{8,}/i, label: "Inline API Key",    id: "SEC-009" },
  // SEC-011: connection strings with embedded credentials.
  // Covers the common protocol schemes (postgres/postgresql, mysql,
  // mongodb and mongodb+srv SRV records, redis/rediss, amqp/amqps)
  // when they contain a `user:pass@host` authority. The user part
  // uses `*` (not `+`) so the "password-only, no user" variant still
  // matches. Character classes explicitly exclude `@`, `/`, and `:`
  // so the regex cannot walk past the credential boundary into the
  // host portion. See tests/injection-guard.test.js for the full set
  // of examples the rule must and must not match.
  { pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:@\/\s"'`]*:[^@\s"'`]+@/i, label: "Connection String with Embedded Credentials", id: "SEC-011" },
];

// ---------------------------------------------------------------------------
// CORE SCANNER
// ---------------------------------------------------------------------------

/**
 * Hard cap on raw input size before `scan()` does any work. Protects
 * direct callers of `scan()` from:
 *   - accidental mega-inputs (a user dumping a megabyte log file)
 *   - deliberate DoS via crafted comment patterns (see INJ-027/028)
 *   - the normalizer's own amplification (URL + base64 decode concat)
 *
 * `guardInput()` already enforces its own `maxLength` (default 4000),
 * but `scan()` is exported and used directly by the audit CLI, the
 * hooks, and third-party callers. Without a cap, a bad actor who gets
 * a huge string into any of those paths can burn CPU without blocking.
 * 100 KB is well above any legitimate injection payload and still fast
 * to scan in the millisecond range.
 *
 * This does not silently corrupt the text — if truncation happens we
 * still scan the first 100 KB (where any injection would realistically
 * sit) and the caller's protection is unchanged. The console note
 * mirrors `guardInput()`'s existing truncation log so operators see it.
 */
const MAX_SCAN_LENGTH = 100_000;

/**
 * Scans text for injection patterns and secret leaks.
 * v1.0.1: normalizes text before scanning to defeat Unicode/encoding bypasses.
 * v1.1.1: caps input at MAX_SCAN_LENGTH before scan for DoS protection.
 * @param {string} text
 * @param {'injection'|'secrets'|'all'} mode
 * @returns {{ violations: Array, hasSecrets: boolean, hasCritical: boolean }}
 */
export function scan(text, mode = "all") {
  if (typeof text !== "string") return { violations: [], hasSecrets: false, hasCritical: false };

  // Hard cap BEFORE normalization — the normalizer concatenates
  // URL-decoded and base64-decoded copies onto the original, so a
  // large input could double or triple in size inside normalizeForScan.
  // Capping upstream makes the downstream work bounded.
  if (text.length > MAX_SCAN_LENGTH) {
    console.warn(`⚠️  [OTLC GUARDIAN] scan() input truncated: ${text.length} chars > ${MAX_SCAN_LENGTH} limit`);
    text = text.slice(0, MAX_SCAN_LENGTH);
  }

  // Normalize before scanning — defeats fullwidth, homoglyph, encoded payloads
  const normalized = normalizeForScan(text);

  const violations = [];

  if (mode === "injection" || mode === "all") {
    for (const { pattern, severity, id } of INJECTION_PATTERNS) {
      if (pattern.test(normalized)) {
        violations.push({
          type: "injection",
          id,
          severity,
          matched: normalized.match(pattern)?.[0] ?? "",
          pattern: pattern.source,
          timestamp: new Date().toISOString(),
        });
      }
    }

    if (INVISIBLE_UNICODE_PATTERN.test(text)) {
      violations.push({
        type: "injection",
        id: "INJ-UNICODE",
        severity: "HIGH",
        matched: "invisible unicode characters detected",
        pattern: INVISIBLE_UNICODE_PATTERN.source,
        timestamp: new Date().toISOString(),
      });
    }
  }

  let hasSecrets = false;
  if (mode === "secrets" || mode === "all") {
    for (const { pattern, label, id } of SECRET_PATTERNS) {
      if (pattern.test(normalized)) {
        hasSecrets = true;
        violations.push({
          type: "secret",
          id,
          severity: "CRITICAL",
          matched: `[REDACTED — ${label}]`,
          label,
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  const hasCritical = violations.some((v) => v.severity === "CRITICAL");

  return { violations, hasSecrets, hasCritical };
}

// ---------------------------------------------------------------------------
// VISIBLE OUTPUT FORMATTER
// Security visibility is a feature, not noise.
// ---------------------------------------------------------------------------

/**
 * Formats scan results into visible console output.
 * Always call this — never suppress security output.
 * @param {Array} violations
 * @param {string} context - Where the scan was triggered (e.g. "chat input", "API request")
 */
export function reportViolations(violations, context = "input") {
  if (violations.length === 0) return;

  const injections = violations.filter((v) => v.type === "injection");
  const secrets    = violations.filter((v) => v.type === "secret");

  if (injections.length > 0) {
    console.warn(`\n⚠️  [OTLC GUARDIAN] PROMPT INJECTION DETECTED`);
    console.warn(`    Context  : ${context}`);
    console.warn(`    Count    : ${injections.length} pattern(s) matched`);
    injections.forEach((v) => {
      console.warn(`    [${v.severity}] ${v.id} — matched: "${v.matched}"`);
    });
    console.warn("");
  }

  if (secrets.length > 0) {
    console.error(`\n🚨 [OTLC GUARDIAN] SECRET LEAK DETECTED`);
    console.error(`    Context  : ${context}`);
    console.error(`    Count    : ${secrets.length} secret pattern(s) found`);
    secrets.forEach((v) => {
      console.error(`    [CRITICAL] ${v.id} — ${v.label}`);
    });
    console.error(`    → Remove secrets from code immediately. Use environment variables.`);
    console.error("");
  }
}

// ---------------------------------------------------------------------------
// INPUT SANITIZER
// ---------------------------------------------------------------------------

/**
 * Strips known injection delimiter tokens from input.
 * Does not remove all flagged content — that is the caller's decision.
 * @param {string} input
 * @returns {string}
 */
export function sanitize(input) {
  return input
    .replace(/<\/?(?:system|assistant|human|user)>/gi, "")
    .replace(/\[SYSTEM\]|\[INST\]/gi, "")
    .replace(/<<\s*SYS\s*>>/gi, "")
    .replace(/###\s*(?:System|Instruction|Prompt)/gi, "")
    .replace(/---\s*SYSTEM/gi, "")
    .replace(/[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/g, "");
}

// ---------------------------------------------------------------------------
// COMBINED GUARD — PRIMARY ENTRY POINT
// ---------------------------------------------------------------------------

/**
 * One-call guard. Validates, scans, reports, and returns safe input.
 *
 * @param {string} input - Raw user input
 * @param {object} options
 * @param {number}   options.maxLength        - Max allowed input length (default: 4000)
 * @param {boolean}  options.blockOnCritical  - Throw on CRITICAL violations (default: true)
 * @param {boolean}  options.blockOnSecrets   - Throw if secrets detected (default: true)
 * @param {function} options.onViolation      - Callback for custom logging/alerting
 * @param {string}   options.context          - Label for log output
 * @returns {string} sanitized input safe to pass to AI
 * @throws {GuardianError} if critical violation and blockOnCritical is true
 */
export function guardInput(input, options = {}) {
  const {
    maxLength       = 4000,
    blockOnCritical = true,
    blockOnSecrets  = true,
    onViolation     = null,
    context         = "user input",
  } = options;

  if (typeof input !== "string") {
    throw new GuardianError("guardInput requires a string.", []);
  }

  // Length check
  if (input.length > maxLength) {
    console.warn(`⚠️  [OTLC GUARDIAN] Input truncated: ${input.length} chars > ${maxLength} limit`);
    input = input.slice(0, maxLength);
  }

  // Scan
  const { violations, hasSecrets, hasCritical } = scan(input, "all");

  // Report visibly
  reportViolations(violations, context);

  // Fire custom callback
  if (onViolation && violations.length > 0) {
    violations.forEach(onViolation);
  }

  // Block on secrets
  if (hasSecrets && blockOnSecrets) {
    throw new GuardianError("Input contains secret-shaped content. Blocked.", violations);
  }

  // Block on critical injection
  if (hasCritical && blockOnCritical) {
    throw new GuardianError("Critical prompt injection attempt detected. Blocked.", violations);
  }

  // Sanitize delimiter tokens
  const sanitized = sanitize(input);

  // v1.0.1: re-scan after sanitize — catches payloads that only appear after stripping
  // e.g. zero-width space between "i​gnore" becomes "ignore" after strip
  const postSanitizeScan = scan(sanitized, "injection");
  if (postSanitizeScan.violations.length > 0) {
    reportViolations(postSanitizeScan.violations, `${context} [post-sanitize]`);
    if (blockOnCritical && postSanitizeScan.hasCritical) {
      throw new GuardianError("Critical injection detected after sanitization. Blocked.", postSanitizeScan.violations);
    }
  }

  return sanitized;
}

// ---------------------------------------------------------------------------
// OUTPUT GUARD — v1.0.1
// Scans AI responses before they reach the user or get stored.
// Catches: leaked secrets in AI output, reflected injection attempts.
// ---------------------------------------------------------------------------

/**
 * Guards AI output before it reaches the user or is stored.
 * Scans for secrets that the AI may have inadvertently included in its response.
 *
 * @param {string} output - Raw AI response text
 * @param {object} options
 * @param {boolean}  options.blockOnSecrets  - Throw if secrets detected (default: true)
 * @param {function} options.onViolation     - Callback for each violation
 * @param {string}   options.context         - Label for log output
 * @returns {string} output safe to send to user
 * @throws {GuardianError} if secrets found and blockOnSecrets is true
 */
export function guardOutput(output, options = {}) {
  const {
    blockOnSecrets = true,
    onViolation    = null,
    context        = "AI output",
  } = options;

  if (typeof output !== "string") {
    throw new GuardianError("guardOutput requires a string.", []);
  }

  // Scan output for secrets only — injection patterns in output are informational
  const { violations, hasSecrets } = scan(output, "secrets");

  // Also scan for reflected injection patterns (AI echoing back attack content)
  const { violations: injViolations } = scan(output, "injection");
  const allViolations = [...violations, ...injViolations];

  reportViolations(allViolations, context);

  if (onViolation && allViolations.length > 0) {
    allViolations.forEach(onViolation);
  }

  if (hasSecrets && blockOnSecrets) {
    throw new GuardianError("AI output contains secret-shaped content. Blocked before delivery.", violations);
  }

  return output;
}

// ---------------------------------------------------------------------------
// CUSTOM ERROR CLASS
// ---------------------------------------------------------------------------

export class GuardianError extends Error {
  constructor(message, violations = []) {
    super(message);
    this.name     = "GuardianError";
    this.violations = violations;
    this.timestamp  = new Date().toISOString();
  }
}

// ---------------------------------------------------------------------------
// EXPRESS MIDDLEWARE
// ---------------------------------------------------------------------------

/**
 * Express middleware that guards all request bodies.
 * Attach to any route that accepts user input destined for an AI.
 *
 * Usage:
 *   import { injectionMiddleware } from './security/01-injection-guard.js';
 *   app.use('/api/chat', injectionMiddleware());
 */
export function injectionMiddleware(options = {}) {
  return (req, res, next) => {
    const fields = options.fields ?? ["message", "prompt", "query", "input", "content"];
    const context = `${req.method} ${req.path}`;

    try {
      for (const field of fields) {
        if (req.body?.[field]) {
          req.body[field] = guardInput(req.body[field], { ...options, context });
        }
      }
      next();
    } catch (err) {
      if (err instanceof GuardianError) {
        return res.status(400).json({
          success: false,
          error: {
            code: "ERR_INJECTION_DETECTED",
            message: "Input rejected by security guard.",
          },
          requestId: req.requestId ?? crypto.randomUUID(),
        });
      }
      next(err);
    }
  };
}
