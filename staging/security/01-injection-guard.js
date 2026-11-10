/**
 * ============================================================
 * OTLC GUARDIAN — Prompt Injection Guard
 * // security · onthelevelconcepts.com
 * Version: 1.5.0
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
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i,          severity: "CRITICAL", id: "GUARD-INJ-001" },
  { pattern: /ignore\s+(all\s+)?above\s+instructions/i,             severity: "CRITICAL", id: "GUARD-INJ-002" },
  { pattern: /disregard\s+(all\s+)?previous/i,                      severity: "CRITICAL", id: "GUARD-INJ-003" },
  { pattern: /forget\s+(all\s+)?(your\s+)?instructions/i,           severity: "CRITICAL", id: "GUARD-INJ-004" },
  { pattern: /override\s+(system|previous)\s+(prompt|instructions)/i, severity: "CRITICAL", id: "GUARD-INJ-005" },

  // Role hijacking
  { pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i,                  severity: "HIGH",     id: "GUARD-INJ-006" },
  { pattern: /pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)/i,        severity: "HIGH",     id: "GUARD-INJ-007" },
  { pattern: /from\s+now\s+on,?\s+you\s+(?:are|will|should|must)/i, severity: "HIGH",     id: "GUARD-INJ-008" },
  { pattern: /act\s+as\s+(?:a|an|the)\s+(?!user|customer|person)/i, severity: "HIGH",     id: "GUARD-INJ-009" },
  { pattern: /roleplay\s+as/i,                                       severity: "HIGH",     id: "GUARD-INJ-010" },
  { pattern: /simulate\s+(?:a|an|the)\s+/i,                         severity: "MEDIUM",   id: "GUARD-INJ-011" },

  // Prompt extraction
  { pattern: /(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i, severity: "HIGH", id: "GUARD-INJ-012" },
  { pattern: /what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions/i, severity: "HIGH", id: "GUARD-INJ-013" },
  { pattern: /tell\s+me\s+your\s+(?:system\s+)?prompt/i,            severity: "HIGH",     id: "GUARD-INJ-014" },

  // Token/delimiter injection (LLM-specific)
  // BUG-043: a role tag named as a noun ("wrap in <user> tags") is prose.
  { pattern: /<\/?(?:system|assistant|human|user)>(?!(?:[ \t]*(?:and|or|,|\/|\.\.\.|\u2026)?[ \t]*<\/?(?:system|assistant|human|user)>)*[ \t]*(?:tags?|elements?|blocks?)\b)/i, severity: "CRITICAL", id: "GUARD-INJ-015" },
  { pattern: /\[SYSTEM\]/i,                                          severity: "CRITICAL", id: "GUARD-INJ-016" },
  { pattern: /\[INST\]/i,                                            severity: "CRITICAL", id: "GUARD-INJ-017" },
  { pattern: /<<\s*SYS\s*>>/i,                                       severity: "CRITICAL", id: "GUARD-INJ-018" },
  // GUARD-INJ-019 / GUARD-INJ-020 match the prompt-template delimiter forms
  // ("### Instruction:", "--- SYSTEM ---"), not ordinary headings. The
  // 1.4 forms matched "### System Overview", "### Instructions" and any
  // YAML front matter whose first key starts with "system", which made
  // the hook deny legitimate writes to planning files.
  // BUG-043: a delimiter ends its line ("### Instruction:") or sits against
  // the hashes ("###System:"), so "### System: Billing" is a heading; a
  // bare "system" separator is upper case ("--- SYSTEM ---"), so
  // "--- System ---" between sections is not one.
  { pattern: /#{3,6}(?:[ \t]*(?:system(?:[ \t]+prompt)?|instructions?|prompt)[ \t]*:[ \t]*$|(?:system(?:[ \t]+prompt)?|instructions?|prompt)[ \t]*:)/im, severity: "CRITICAL", id: "GUARD-INJ-019" },
  { pattern: /-{3,}[ \t]*(?:SYSTEM|[Ss][Yy][Ss][Tt][Ee][Mm][ \t]+(?:[Pp][Rr][Oo][Mm][Pp][Tt]|[Mm][Ee][Ss][Ss][Aa][Gg][Ee]|[Ii][Nn][Ss][Tt][Rr][Uu][Cc][Tt][Ii][Oo][Nn][Ss]?))[ \t]*(?:-{3,}|:|$)/m, severity: "CRITICAL", id: "GUARD-INJ-020" },

  // Jailbreak classics
  { pattern: /do\s+anything\s+now/i,                                 severity: "HIGH",     id: "GUARD-INJ-021" },
  { pattern: /DAN\s+mode/i,                                          severity: "HIGH",     id: "GUARD-INJ-022" },
  { pattern: /developer\s+mode/i,                                    severity: "HIGH",     id: "GUARD-INJ-023" },
  { pattern: /jailbreak/i,                                           severity: "HIGH",     id: "GUARD-INJ-024" },
  { pattern: /without\s+(?:any\s+)?restrictions/i,                   severity: "HIGH",     id: "GUARD-INJ-025" },
  { pattern: /bypass\s+(?:your\s+)?(?:safety|filter|guideline)/i,   severity: "HIGH",     id: "GUARD-INJ-026" },

  // Context poisoning via markup.
  //
  // These two rules use a `match` function instead of a bare regex. The
  // regex form (`<!--[\s\S]*?(?:ignore|override|system)[\s\S]*?-->`) was
  // cubic on input made of many unterminated openers: 44 KB of
  // "<!--ignore " took 16 seconds and 99 KB ran past a minute, which
  // stalled both hooks. The matcher below walks comments with indexOf,
  // so the cost is linear in the input. It is also more precise: the
  // keyword has to sit inside one comment, where the regex could span
  // from one comment into the next. `pattern` is kept as a cheap
  // descriptor for callers that report `pattern.source`. `matchAll`
  // yields every hit, for scanChange().
  { pattern: /<!--/,  ...commentMatcher("<!--", "-->"), severity: "MEDIUM", id: "GUARD-INJ-027" },
  { pattern: /\/\*/,  ...commentMatcher("/*", "*/"),    severity: "MEDIUM", id: "GUARD-INJ-028" },
];

/**
 * Builds a linear-time matcher for "comment containing a control word".
 * `match` returns the first such comment or null; `matchAll` yields each;
 * `spans` yields each with its offset.
 * @param {string} open  - comment opener, e.g. "<!--"
 * @param {string} close - comment closer, e.g. "-->"
 * @returns {{ match: (text: string) => string | null, matchAll: (text: string) => Generator<string>, spans: (text: string) => Generator<{ text: string, index: number }> }}
 */
function commentMatcher(open, close) {
  const keyword = /ignore|override|system/i;
  /** Each hit with its offset, for scanChange(). */
  function* spans(text) {
    let pos = 0;
    for (;;) {
      const start = text.indexOf(open, pos);
      if (start < 0) return;
      const end = text.indexOf(close, start + open.length);
      // No closer anywhere after this opener means no later opener can
      // be closed either, so the search is over.
      if (end < 0) return;
      const comment = text.slice(start, end + close.length);
      if (keyword.test(comment)) yield { text: comment, index: start };
      pos = end + close.length;
    }
  }
  function* matchAll(text) {
    for (const span of spans(text)) yield span.text;
  }
  return { match: (text) => matchAll(text).next().value ?? null, matchAll, spans };
}

// ---------------------------------------------------------------------------
// INVISIBLE UNICODE
// Used in steganographic injection attacks
// ---------------------------------------------------------------------------
//
// Two sets, on purpose:
//
//   DETECT: characters whose presence is itself reported (GUARD-INJ-UNICODE).
//           Zero-width and bidi controls, word joiner and its invisible
//           operator siblings, the Mongolian vowel separator, the Arabic
//           letter mark, and the Unicode tag block (U+E0000..U+E007F).
//           The tag block is the "ASCII smuggling" channel: every ASCII
//           character has an invisible twin there that many models read.
//
//   STRIP:  everything in DETECT plus characters that are invisible but
//           common in honest text (variation selectors after emoji,
//           Hangul fillers). They are removed before pattern matching so
//           they cannot split a keyword, but they do not raise a finding
//           on their own.

const INVISIBLE_UNICODE_PATTERN =
  /[\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\u2066-\u206F\uFEFF\u{E0000}-\u{E007F}]/u;

const INVISIBLE_STRIP_PATTERN =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202F\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\u{E0000}-\u{E0FFF}]/gu;

const TAG_CHAR_PATTERN = /[\u{E0020}-\u{E007E}]/gu;

// ---------------------------------------------------------------------------
// CONFUSABLES
// ---------------------------------------------------------------------------
//
// NFKC folds fullwidth and other compatibility forms, but it does not
// touch Cyrillic or Greek letters that render the same as Latin ones.
// "ignоre" with a Cyrillic о is a different string to a regex and the
// same string to a reader. This table covers the lookalikes that can
// stand in for the Latin letters used by the patterns above.

const CONFUSABLES = new Map(Object.entries({
  // Cyrillic lowercase
  "а": "a", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "о": "o",
  "р": "p", "ѕ": "s", "у": "y", "х": "x", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ӏ": "l",
  // Cyrillic uppercase
  "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
  "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "У": "Y", "Х": "X",
  // Greek
  "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "υ": "u", "τ": "t", "ϲ": "c",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
  "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}));

const CONFUSABLE_PATTERN = new RegExp(`[${[...CONFUSABLES.keys()].join("")}]`, "g");

const HTML_NAMED_ENTITIES = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'", nbsp: " " };

// Embedded base64 runs. Bounded on both ends so one giant run cannot
// force a giant decode, and capped in count below.
const BASE64_RUN_PATTERN   = /[A-Za-z0-9+/_-]{24,20000}={0,2}/g;
const MAX_BASE64_CANDIDATES = 64;
const PRINTABLE_PATTERN     = /^[\x20-\x7E\s]{10,}$/;

// ---------------------------------------------------------------------------
// PRE-SCAN NORMALIZER
// ---------------------------------------------------------------------------

function decodeBase64Printable(candidate) {
  try {
    const standard = candidate.replace(/-/g, "+").replace(/_/g, "/");
    const decoded  = Buffer.from(standard, "base64").toString("utf8");
    return PRINTABLE_PATTERN.test(decoded) ? decoded : null;
  } catch (err) {
    // Buffer.from is lenient and should not throw, but a decode failure
    // only means "not base64", which is not a finding.
    return null;
  }
}

/**
 * Percent-decodes each run of %XX on its own. `decodeURIComponent` on
 * the whole text throws on any stray "%" ("100% sure"), and the old
 * code then skipped URL decoding for the entire input. One literal
 * percent sign was enough to hide a %-encoded payload.
 */
function percentDecodeTolerant(text) {
  return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch (err) {
      // Not valid UTF-8 once decoded. Leave the run as written.
      return run;
    }
  });
}

function decodeHtmlEntities(text) {
  return text.replace(/&(?:#(\d{1,7})|#[xX]([0-9A-Fa-f]{1,6})|([A-Za-z]{2,6}));/g, (whole, dec, hex, name) => {
    if (name) return HTML_NAMED_ENTITIES[name.toLowerCase()] ?? whole;
    const code = dec ? Number.parseInt(dec, 10) : Number.parseInt(hex, 16);
    return code > 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : whole;
  });
}

/**
 * Every decoded view of the text, always in this order. A view that does
 * not apply is the empty string, so view N of one text can be compared
 * with view N of another (scanChange() relies on that).
 *
 * Views:
 *   1. NFKC-normalized text with invisible characters removed
 *   2. Unicode tag characters mapped back to the ASCII they shadow
 *   3. Cyrillic/Greek lookalikes folded to Latin
 *   4. Percent-decoded (tolerant of stray "%")
 *   5. HTML entities decoded
 *   6. Markdown emphasis markers removed ("**previous**" -> "previous")
 *   7. The whole input as base64 (whitespace-wrapped payloads)
 *   8. Each embedded base64 run that decodes to printable text
 *
 * @param {string} text
 * @returns {string[]}
 */
function scanViews(text) {
  const base   = text.normalize("NFKC").replace(INVISIBLE_STRIP_PATTERN, "");
  const tagRun = text.match(TAG_CHAR_PATTERN);

  const compact = text.replace(/\s/g, "");
  const wholeBase64 = compact.length <= 20000 && /^[A-Za-z0-9+/_-]{20,}={0,2}$/.test(compact)
    ? decodeBase64Printable(compact) ?? ""
    : "";

  const decodedRuns = [];
  let candidates = 0;
  for (const run of text.matchAll(BASE64_RUN_PATTERN)) {
    if (++candidates > MAX_BASE64_CANDIDATES) break;
    const decoded = decodeBase64Printable(run[0]);
    if (decoded) decodedRuns.push(decoded);
  }

  return [
    base,
    tagRun ? tagRun.map((ch) => String.fromCodePoint(ch.codePointAt(0) - 0xE0000)).join("") : "",
    base.replace(CONFUSABLE_PATTERN, (ch) => CONFUSABLES.get(ch) ?? ch),
    percentDecodeTolerant(base),
    decodeHtmlEntities(base),
    base.replace(/[*_`~]+/g, ""),
    wholeBase64,
    decodedRuns.join("\n"),
  ];
}

/**
 * Normalizes text before scanning: the distinct views of it, joined by
 * newlines, so the patterns run over all of them in one pass.
 * @param {string} text
 * @returns {string} normalized text ready for pattern scanning
 */
function normalizeForScan(text) {
  const [base, ...rest] = scanViews(text);
  const views = [base];
  for (const view of rest) {
    if (view && !views.includes(view)) views.push(view);
  }
  return views.join("\n");
}

// ---------------------------------------------------------------------------
// SECRET LEAK DETECTOR
// Warns if output or input accidentally contains secret-shaped strings
// GUARD-SEC-006 scoped to context-adjacent matches to reduce false positives (v1.0.1)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GUARD-SEC-001 / GUARD-SEC-010 — OpenAI + Anthropic key formats
// ---------------------------------------------------------------------------
// The original GUARD-SEC-001 pattern was /sk-[a-zA-Z0-9]{20,}/ which silently
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
  { pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/,               label: "OpenAI Project API Key",    id: "GUARD-SEC-001" },
  { pattern: /sk-ant-(?:api|oat|admin)\d{2}-[a-zA-Z0-9_-]{20,}/, label: "Anthropic API Key",  id: "GUARD-SEC-010" },
  // Legacy OpenAI format (`sk-...` without a provider tag) — kept for
  // historical keys still in circulation. Negative lookahead excludes
  // the provider-tagged variants so they're reported under their
  // specific label above rather than this generic one.
  { pattern: /sk-(?!proj-|ant-api\d{2}-)[a-zA-Z0-9]{20,}/, label: "OpenAI API Key (legacy)", id: "GUARD-SEC-001b" },
  { pattern: /AIza[0-9A-Za-z\-_]{35}/,                 label: "Google API Key",     id: "GUARD-SEC-002" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/,                    label: "GitHub Token",       id: "GUARD-SEC-003" },
  { pattern: /gho_[a-zA-Z0-9]{36}/,                    label: "GitHub OAuth Token", id: "GUARD-SEC-004" },
  { pattern: /AKIA[0-9A-Z]{16}/,                        label: "AWS Access Key",     id: "GUARD-SEC-005" },
  // GUARD-SEC-006: scoped to secret-adjacent context only — avoids false positives on JWTs/images
  { pattern: /(?:secret|token|key|password|auth)\s*[:=]\s*["']?[A-Za-z0-9+/]{40,}["']?/i, label: "Context-Adjacent Base64 Secret", id: "GUARD-SEC-006" },
  // GUARD-SEC-007: any PEM private key header (RSA, EC, DSA, OPENSSH, ENCRYPTED, bare).
  // The old form only allowed an optional "RSA", so OpenSSH and EC keys passed clean.
  { pattern: /-----BEGIN\s+(?:[A-Z0-9]+\s+){0,3}PRIVATE\s+KEY-----/, label: "Private Key", id: "GUARD-SEC-007" },
  { pattern: /password\s*[:=]\s*["']?[^\s"']{8,}/i,    label: "Inline Password",   id: "GUARD-SEC-008" },
  { pattern: /api[_-]?key\s*[:=]\s*["']?[^\s"']{8,}/i, label: "Inline API Key",    id: "GUARD-SEC-009" },
  // GUARD-SEC-011: connection strings with embedded credentials.
  // Covers the common protocol schemes (postgres/postgresql, mysql,
  // mongodb and mongodb+srv SRV records, redis/rediss, amqp/amqps)
  // when they contain a `user:pass@host` authority. The user part
  // uses `*` (not `+`) so the "password-only, no user" variant still
  // matches. Character classes explicitly exclude `@`, `/`, and `:`
  // so the regex cannot walk past the credential boundary into the
  // host portion. See tests/injection-guard.test.js for the full set
  // of examples the rule must and must not match.
  { pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:@\/\s"'`]{0,256}:[^@\s"'`]{1,512}@/i, label: "Connection String with Embedded Credentials", id: "GUARD-SEC-011" },
  // GUARD-SEC-011 note: both credential parts are length-bounded. Unbounded,
  // a long run of "redis://a:b" with no "@" made the rule quadratic.
  { pattern: /github_pat_[A-Za-z0-9_]{40,}/,            label: "GitHub Fine-Grained Token",   id: "GUARD-SEC-012" },
  { pattern: /gh[sur]_[A-Za-z0-9]{36,}/,                label: "GitHub App/Server Token",     id: "GUARD-SEC-013" },
  { pattern: /xox[abprs]-[A-Za-z0-9-]{10,}/,            label: "Slack Token",                 id: "GUARD-SEC-014" },
  { pattern: /[sr]k_live_[A-Za-z0-9]{20,}/,             label: "Stripe Live Key",             id: "GUARD-SEC-015" },
];

// ---------------------------------------------------------------------------
// CORE SCANNER
// ---------------------------------------------------------------------------

/**
 * Hard cap on raw input size before `scan()` does any work. Protects
 * direct callers of `scan()` from:
 *   - accidental mega-inputs (a user dumping a megabyte log file)
 *   - deliberate DoS via crafted comment patterns (see GUARD-INJ-027/028)
 *   - the normalizer's own amplification (URL + base64 decode concat)
 *
 * `guardInput()` already enforces its own `maxLength` (default 4000),
 * but `scan()` is exported and used directly by the audit CLI, the
 * hooks, and third-party callers. Without a cap, a bad actor who gets
 * a huge string into any of those paths can burn CPU without blocking.
 * 1 MB is well above any legitimate injection payload. Every pattern
 * and every normalizer pass is linear in the input, so the cap is a
 * memory bound, not a workaround for slow regexes.
 *
 * This does not silently corrupt the text — if truncation happens we
 * still scan everything under the cap and report an GUARD-INJ-OVERSIZE
 * finding for the remainder, so truncation is never silent. The console note
 * mirrors `guardInput()`'s existing truncation log so operators see it.
 */
const MAX_SCAN_LENGTH = 1_000_000;

/**
 * Scans text for injection patterns and secret leaks.
 * v1.0.1: normalizes text before scanning to defeat Unicode/encoding bypasses.
 * v1.1.1: caps input at MAX_SCAN_LENGTH before scan for DoS protection.
 * @param {string} text
 * @param {'injection'|'secrets'|'all'} mode
 * @returns {{ violations: Array, hasSecrets: boolean, hasCritical: boolean }}
 *   hasCritical: any CRITICAL finding, injection or secret
 * @throws {GuardianError} for a mode other than the three, or text that is not a string (BUG-049)
 */
/**
 * Rule ids carry the engine prefix GUARD- (1.5.0) so they cannot be
 * confused with the audit's ids, which reuse INJ-* and SEC-* for other
 * rules. `legacyId` is the pre-1.5.0 id, kept for one release so callers
 * that match on it can migrate. Removed in 1.6.0.
 */
const legacyId = (id) => id.replace(/^GUARD-/, "");

const SCAN_MODES = new Set(["injection", "secrets", "all"]);

/**
 * A mode that is not one of the three, or text that is not a string, would
 * scan nothing and report clean, so a caller's typo would switch the guard
 * off. Both are errors instead (BUG-049).
 */
function assertScanArgs(fn, text, mode) {
  if (!SCAN_MODES.has(mode)) {
    throw new GuardianError(`${fn}() mode must be "injection", "secrets" or "all"; got ${JSON.stringify(mode) ?? String(mode)}.`, []);
  }
  if (typeof text !== "string") {
    throw new GuardianError(`${fn}() requires a string; got ${text === null ? "null" : typeof text}.`, []);
  }
}

export function scan(text, mode = "all") {
  assertScanArgs("scan", text, mode);

  // Hard cap BEFORE normalization — the normalizer concatenates
  // URL-decoded and base64-decoded copies onto the original, so a
  // large input could double or triple in size inside normalizeForScan.
  // Capping upstream makes the downstream work bounded.
  let unscanned = 0;
  if (text.length > MAX_SCAN_LENGTH) {
    unscanned = text.length - MAX_SCAN_LENGTH;
    console.warn(`⚠️  [OTLC GUARDIAN] scan() input truncated: ${text.length} chars > ${MAX_SCAN_LENGTH} limit`);
    text = text.slice(0, MAX_SCAN_LENGTH);
  }

  // Normalize before scanning — defeats fullwidth, homoglyph, encoded payloads
  const normalized = normalizeForScan(text);

  const violations = [];

  if (mode === "injection" || mode === "all") {
    for (const { pattern, match, severity, id } of INJECTION_PATTERNS) {
      const matched = match ? match(normalized) : (normalized.match(pattern)?.[0] ?? null);
      if (matched !== null) {
        violations.push({
          type: "injection",
          id,
          legacyId: legacyId(id),
          severity,
          matched,
          pattern: pattern.source,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Truncation is a finding, not a footnote. Content past the cap was
    // not scanned, so padding a payload behind filler must never read
    // as "clean".
    if (unscanned > 0) {
      violations.push({
        type: "injection",
        id: "GUARD-INJ-OVERSIZE",
        legacyId: "INJ-OVERSIZE",
        severity: "MEDIUM",
        matched: `${unscanned} characters past the ${MAX_SCAN_LENGTH} scan limit were not scanned`,
        pattern: "length",
        timestamp: new Date().toISOString(),
      });
    }

    if (INVISIBLE_UNICODE_PATTERN.test(text)) {
      violations.push({
        type: "injection",
        id: "GUARD-INJ-UNICODE",
        legacyId: "INJ-UNICODE",
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
          legacyId: legacyId(id),
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
// CHANGE SCANNER
// ---------------------------------------------------------------------------

/**
 * Characters kept on each side of a change. A pattern that joins new text
 * to the text around it ("...previous" on disk, "instructions" added) is
 * seen whole as long as the old part sits within this distance.
 */
const CHANGE_CONTEXT = 2048;

const INVISIBLE_UNICODE_GLOBAL = new RegExp(INVISIBLE_UNICODE_PATTERN.source, "gu");

/** Every match of one rule in one view, as { text, index }. */
function* ruleMatches(rule, view) {
  if (!view) return;
  if (rule.spans) {
    yield* rule.spans(view);
    return;
  }
  const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
  for (const m of view.matchAll(new RegExp(rule.pattern.source, flags))) yield { text: m[0], index: m.index };
}

// ---------------------------------------------------------------------------
// Context kind (BUG-042). A match is "data" when it sits whole inside a
// fenced code block, or inside one quoted or inline-code span on its line;
// anything else is "live". A pattern quoted as an example is data; the same
// words moved onto an ordinary line are a live directive, which a count
// alone cannot tell apart.
// ---------------------------------------------------------------------------

const FENCE_LINE = /^ {0,3}(`{3,}|~{3,})(.*)$/;

/**
 * The fence state after one line: the open fence ({ char, length }) or
 * null. A backtick fence's info string cannot hold a backtick; a closing
 * fence uses the opening character, at least as many, and nothing after.
 */
function nextFence(fence, line) {
  const m = FENCE_LINE.exec(line);
  if (!m) return fence;
  const [, run, rest] = m;
  if (fence) return run[0] === fence.char && run.length >= fence.length && rest.trim() === "" ? null : fence;
  return run[0] === "`" && rest.includes("`") ? null : { char: run[0], length: run.length };
}

/** The fence state at the end of `text`, read line by line. */
function fenceAtEnd(text) {
  let fence = null;
  for (const line of text.split("\n")) fence = nextFence(fence, line.replace(/\r$/, ""));
  return fence;
}

// A quote opens and closes on one line. A single quote touching a letter
// or digit on its outer side is an apostrophe ("don't"), not a quote.
const QUOTE_SPAN = /"[^"\n]*"|“[^”\n]*”|`[^`\n]+`|(?<![\p{L}\p{N}])'[^'\n]*'(?![\p{L}\p{N}])|(?<![\p{L}\p{N}])‘[^’\n]*’(?![\p{L}\p{N}])/gu;

/**
 * A classifier for matches in one view: kind(match) is "data" or "live".
 * `fence` is the fence state where the view starts; `partial` says the
 * view starts mid-line (a window cut), so its first line is not read as
 * a fence line.
 */
function contextKinds(view, fence, partial) {
  const lineStarts = [0];
  for (let i = view.indexOf("\n"); i >= 0; i = view.indexOf("\n", i + 1)) lineStarts.push(i + 1);
  // block[n]: the fenced block line n belongs to (fence lines included), or -1
  const block = new Int32Array(lineStarts.length).fill(-1);
  let blocks = fence ? 1 : 0;
  for (let n = 0; n < lineStarts.length; n++) {
    const line = view.slice(lineStarts[n], (lineStarts[n + 1] ?? view.length + 1) - 1).replace(/\r$/, "");
    const next = n === 0 && partial ? fence : nextFence(fence, line);
    if (fence || next) block[n] = fence ? blocks - 1 : blocks++;
    fence = next;
  }
  const lineOf = (offset) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  return ({ text, index }) => {
    const first = lineOf(index);
    const last  = lineOf(index + Math.max(0, text.length - 1));
    if (block[first] >= 0 && block[first] === block[last]) return "data";
    if (first !== last) return "live";
    const start = lineStarts[first];
    const line  = view.slice(start, (lineStarts[first + 1] ?? view.length + 1) - 1);
    for (const q of line.matchAll(QUOTE_SPAN)) {
      if (start + q.index <= index && index + text.length <= start + q.index + q[0].length) return "data";
    }
    return "live";
  };
}

/** View indexes that keep the text's lines, quotes and fences in place (see scanViews()). */
const POSITIONAL_VIEWS = new Set([0, 2, 3, 4]);

/**
 * The context is counted in characters that are not padding (BUG-046).
 * Padding is what some scan view reads as whitespace or as nothing:
 * whitespace, invisible characters, markdown emphasis markers, and
 * entities or %-escapes of whitespace. Counted by raw length, 5,000
 * spaces between "ignore all" on disk and "previous instructions" added
 * would push the old half out of the window. The text itself is never
 * changed, so every view still reads it as written.
 */
const INVISIBLE_CLASS = INVISIBLE_STRIP_PATTERN.source.slice(1, -1);
const CONTEXT_TOKEN = new RegExp(
  `((?:[\\s*_\`~]|[${INVISIBLE_CLASS}])+)` +              // 1: padding run
  `|(&#?[0-9A-Za-z]{1,8};|(?:%[0-9A-Fa-f]{2})+)` +        // 2: entity or %-run
  `|[^\\s*_\`~&%${INVISIBLE_CLASS}]+|[^]`,                // text
  "gu",
);

function tokenWeight([token, padding, encoded]) {
  if (padding) return 0;
  if (encoded && /^\s+$/u.test(decodeHtmlEntities(percentDecodeTolerant(token)))) return 0;
  return token.length;
}

/** Where the context before `end` starts: CHANGE_CONTEXT weighed characters back. */
function contextStart(text, end) {
  for (let span = CHANGE_CONTEXT * 4; ; span *= 4) {
    const start  = Math.max(0, end - span);
    const tokens = [...text.slice(start, end).matchAll(CONTEXT_TOKEN)];
    let need = CHANGE_CONTEXT;
    for (let k = tokens.length - 1; k >= 0; k--) {
      const weight = tokenWeight(tokens[k]);
      if (weight >= need) return start + tokens[k].index + tokens[k][0].length - need;
      need -= weight;
    }
    if (start === 0) return 0;
  }
}

/** Where the context after `begin` ends: CHANGE_CONTEXT weighed characters on. */
function contextEnd(text, begin) {
  for (let span = CHANGE_CONTEXT * 4; ; span *= 4) {
    const end = Math.min(text.length, begin + span);
    let need = CHANGE_CONTEXT;
    for (const token of text.slice(begin, end).matchAll(CONTEXT_TOKEN)) {
      const weight = tokenWeight(token);
      if (weight >= need) return begin + token.index + need;
      need -= weight;
    }
    if (end === text.length) return end;
  }
}

/**
 * Trims the common prefix and suffix, keeping CHANGE_CONTEXT around the
 * change. Returns both windows and the offset they start at.
 */
function changedWindows(before, after) {
  const shorter = Math.min(before.length, after.length);
  let head = 0;
  while (head < shorter && before.charCodeAt(head) === after.charCodeAt(head)) head++;
  let tail = 0;
  while (tail < shorter - head && before.charCodeAt(before.length - 1 - tail) === after.charCodeAt(after.length - 1 - tail)) tail++;
  const from = contextStart(before, head);
  const keep = before.length - contextEnd(before, before.length - tail);
  return [before.slice(from, before.length - keep), after.slice(from, after.length - keep), from];
}

/**
 * The first string a rule matches in `after` that `before` does not
 * account for, view by view, or null when the change adds no match.
 *
 * Matches are counted by string and context kind (BUG-042). A live match
 * is accounted for only by a live match of the same string in `before`;
 * a data match by a data match, or else by a live one, so moving a
 * pattern into quotes is never a finding but moving it out is. `kinds[i]`
 * classifies matches in view i of each text; a view without a classifier
 * counts every match as live.
 */
function firstAddedMatch(rule, beforeViews, afterViews, beforeKinds, afterKinds) {
  const take = (counts, text) => {
    const left = counts.get(text) ?? 0;
    if (left > 0) counts.set(text, left - 1);
    return left > 0;
  };
  for (let i = 0; i < afterViews.length; i++) {
    const old = { live: new Map(), data: new Map() };
    for (const m of ruleMatches(rule, beforeViews[i])) {
      const counts = old[beforeKinds[i]?.(m) ?? "live"];
      counts.set(m.text, (counts.get(m.text) ?? 0) + 1);
    }
    const added = { live: [], data: [] };
    for (const m of ruleMatches(rule, afterViews[i])) added[afterKinds[i]?.(m) ?? "live"].push(m.text);
    for (const text of added.live) if (!take(old.live, text)) return text;
    for (const text of added.data) if (!take(old.data, text) && !take(old.live, text)) return text;
  }
  return null;
}

/** Context-kind classifiers for the positional views of one window. */
function viewKinds(views, fence, partial) {
  return views.map((view, i) => (POSITIONAL_VIEWS.has(i) && view ? contextKinds(view, fence, partial) : null));
}

/**
 * Scans what a change adds to a text: the findings in `after` that
 * `before` does not already account for.
 *
 * `scan()` reports one finding per rule, so judging a whole file would
 * either flag every edit to a file that already quotes a pattern (a
 * security doc, Guardian's own CLAUDE.md) or, judged by rule id, let a
 * second copy of the same rule through. Here each rule's matched strings
 * are counted per decoded view, and a finding is new when some view of
 * `after` holds a matched string more often than the same view of
 * `before`. Removing a pattern is never a finding.
 *
 * Only the changed region plus CHANGE_CONTEXT on each side is compared,
 * so a small edit to a large file costs a small scan, and a payload
 * appended past the 1 MB scan limit of the whole file is still seen.
 *
 * @param {string} before - text as it is now ("" for a new file)
 * @param {string} after  - text as it will be
 * @param {'injection'|'secrets'|'all'} mode
 * @returns {{ violations: Array, hasSecrets: boolean, hasCritical: boolean }}
 *   hasCritical: any CRITICAL finding, injection or secret
 * @throws {GuardianError} for a mode other than the three, or text that is not a string (BUG-049)
 */
export function scanChange(before, after, mode = "all") {
  assertScanArgs("scanChange", after, mode);
  const original = typeof before === "string" ? before : "";
  const [oldWindow, newWindow, from] = changedWindows(original, after);

  const { violations } = scan(newWindow, mode);
  const oldViews = scanViews(oldWindow.slice(0, MAX_SCAN_LENGTH));
  const newViews = scanViews(newWindow.slice(0, MAX_SCAN_LENGTH));
  const rules    = new Map([...INJECTION_PATTERNS, ...SECRET_PATTERNS].map((r) => [r.id, r]));
  // Both windows start at `from` after the same text, so they share the
  // fence state there, read from that text as the base view reads it.
  const fence    = fenceAtEnd(original.slice(0, from).normalize("NFKC").replace(INVISIBLE_STRIP_PATTERN, ""));
  const partial  = from > 0 && original[from - 1] !== "\n";
  const oldKinds = viewKinds(oldViews, fence, partial);
  const newKinds = viewKinds(newViews, fence, partial);
  const countInvisible = (text) => text.match(INVISIBLE_UNICODE_GLOBAL)?.length ?? 0;

  const added = [];
  for (const v of violations) {
    if (v.id === "GUARD-INJ-OVERSIZE") {
      added.push(v); // unscanned text is never "already accounted for"
    } else if (v.id === "GUARD-INJ-UNICODE") {
      if (countInvisible(newWindow) > countInvisible(oldWindow)) added.push(v);
    } else {
      const matched = firstAddedMatch(rules.get(v.id), oldViews, newViews, oldKinds, newKinds);
      if (matched !== null) added.push(v.type === "secret" ? v : { ...v, matched });
    }
  }

  return {
    violations:  added,
    hasSecrets:  added.some((v) => v.type === "secret"),
    hasCritical: added.some((v) => v.severity === "CRITICAL"),
  };
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
    .replace(INVISIBLE_STRIP_PATTERN, "");
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
 * @param {boolean}  options.blockOnCritical  - Throw on CRITICAL injection findings (default: true)
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

  // Scan. Every secret rule is CRITICAL, so scan()'s hasCritical covers
  // secrets too; blockOnCritical is decided on injection findings alone,
  // or blockOnSecrets: false would not let a secret through (BUG-050).
  const { violations, hasSecrets } = scan(input, "all");
  const hasCriticalInjection = violations.some((v) => v.type === "injection" && v.severity === "CRITICAL");

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
  if (hasCriticalInjection && blockOnCritical) {
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
