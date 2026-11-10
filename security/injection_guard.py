"""
============================================================
OTLC GUARDIAN - Prompt Injection Guard (Python)
// security · onthelevelconcepts.com
Version: 1.5.0
============================================================

Runtime input sanitizer for Python AI-powered applications.
Compatible with FastAPI, Flask, Django, or plain Python.

Usage:
    from security.injection_guard import guard_input, GuardianError

    try:
        clean = guard_input(user_message, context="chat endpoint")
        reply = call_ai(clean)
    except GuardianError as e:
        return {"error": "Input rejected by security guard."}

============================================================
"""

import re
import os
import sys
import json
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Callable

# ---------------------------------------------------------------------------
# STRUCTURED LOGGING SETUP
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger("otlc-guardian")

# ---------------------------------------------------------------------------
# INJECTION PATTERN REGISTRY
# ---------------------------------------------------------------------------

@dataclass
class InjectionPattern:
    id: str
    pattern: re.Pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    # Optional linear-time matcher used instead of `pattern` (see _comment_matcher).
    matcher: Optional[Callable[[str], Optional[str]]] = None


def _comment_matcher(open_tok: str, close_tok: str) -> Callable[[str], Optional[str]]:
    """
    Linear-time matcher for "comment containing a control word".

    Replaces the regex form of GUARD-INJ-027/GUARD-INJ-028, which backtracked
    cubically on input made of many unterminated comment openers.
    Returns the full comment on a hit, else None.
    """
    keyword = re.compile(r"ignore|override|system", re.I)

    def match(text: str) -> Optional[str]:
        pos = 0
        while True:
            start = text.find(open_tok, pos)
            if start < 0:
                return None
            end = text.find(close_tok, start + len(open_tok))
            # No closer after this opener means no later opener can close either.
            if end < 0:
                return None
            comment = text[start:end + len(close_tok)]
            if keyword.search(comment):
                return comment
            pos = end + len(close_tok)

    return match


INJECTION_PATTERNS: list[InjectionPattern] = [
    InjectionPattern("GUARD-INJ-001", re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "CRITICAL", "Classic instruction override"),
    InjectionPattern("GUARD-INJ-002", re.compile(r"ignore\s+(all\s+)?above\s+instructions",    re.I), "CRITICAL", "Above instruction override"),
    InjectionPattern("GUARD-INJ-003", re.compile(r"disregard\s+(all\s+)?previous",              re.I), "CRITICAL", "Disregard previous"),
    InjectionPattern("GUARD-INJ-004", re.compile(r"forget\s+(all\s+)?(your\s+)?instructions",  re.I), "CRITICAL", "Forget instructions"),
    InjectionPattern("GUARD-INJ-005", re.compile(r"override\s+(system|previous)\s+(prompt|instructions)", re.I), "CRITICAL", "System override"),
    InjectionPattern("GUARD-INJ-006", re.compile(r"you\s+are\s+now\s+(?:a|an|the)\s+",         re.I), "HIGH",     "Role hijack: you are now"),
    InjectionPattern("GUARD-INJ-007", re.compile(r"pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)", re.I), "HIGH",   "Role hijack: pretend"),
    InjectionPattern("GUARD-INJ-008", re.compile(r"from\s+now\s+on,?\s+you\s+(?:are|will|should|must)", re.I), "HIGH", "Role hijack: from now on"),
    InjectionPattern("GUARD-INJ-009", re.compile(r"act\s+as\s+(?:a|an|the)\s+(?!user|customer|person)", re.I), "HIGH", "Role hijack: act as"),
    InjectionPattern("GUARD-INJ-010", re.compile(r"roleplay\s+as",                               re.I), "HIGH",     "Roleplay hijack"),
    InjectionPattern("GUARD-INJ-011", re.compile(r"simulate\s+(?:a|an|the)\s+",                 re.I), "MEDIUM",   "Simulation hijack"),
    InjectionPattern("GUARD-INJ-012", re.compile(r"(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", re.I), "HIGH", "Prompt extraction"),
    InjectionPattern("GUARD-INJ-013", re.compile(r"what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions", re.I), "HIGH", "Instruction extraction"),
    InjectionPattern("GUARD-INJ-014", re.compile(r"tell\s+me\s+your\s+(?:system\s+)?prompt",    re.I), "HIGH",     "System prompt extraction"),
    InjectionPattern("GUARD-INJ-015", re.compile(r"</?(?:system|assistant|human|user)>",        re.I), "CRITICAL", "Delimiter injection"),
    InjectionPattern("GUARD-INJ-016", re.compile(r"\[SYSTEM\]",                                 re.I), "CRITICAL", "SYSTEM tag injection"),
    InjectionPattern("GUARD-INJ-017", re.compile(r"\[INST\]",                                   re.I), "CRITICAL", "INST tag injection"),
    InjectionPattern("GUARD-INJ-018", re.compile(r"<<\s*SYS\s*>>",                              re.I), "CRITICAL", "SYS tag injection"),
    # GUARD-INJ-019 / GUARD-INJ-020 match prompt-template delimiters ("### Instruction:",
    # "--- SYSTEM ---"), not ordinary headings or YAML front matter.
    InjectionPattern("GUARD-INJ-019", re.compile(r"#{3,6}[ \t]*(?:system(?:[ \t]+prompt)?|instructions?|prompt)[ \t]*:", re.I), "CRITICAL", "Markdown system tag"),
    InjectionPattern("GUARD-INJ-020", re.compile(r"-{3,}[ \t]*system(?:[ \t]+(?:prompt|message|instructions?))?[ \t]*(?:-{3,}|:|$)", re.I | re.M), "CRITICAL", "YAML system override"),
    InjectionPattern("GUARD-INJ-021", re.compile(r"do\s+anything\s+now",                        re.I), "HIGH",     "DAN variant"),
    InjectionPattern("GUARD-INJ-022", re.compile(r"DAN\s+mode",                                 re.I), "HIGH",     "DAN mode"),
    InjectionPattern("GUARD-INJ-023", re.compile(r"developer\s+mode",                           re.I), "HIGH",     "Developer mode jailbreak"),
    InjectionPattern("GUARD-INJ-024", re.compile(r"jailbreak",                                  re.I), "HIGH",     "Jailbreak keyword"),
    InjectionPattern("GUARD-INJ-025", re.compile(r"without\s+(?:any\s+)?restrictions",          re.I), "HIGH",     "Restriction bypass"),
    InjectionPattern("GUARD-INJ-026", re.compile(r"bypass\s+(?:your\s+)?(?:safety|filter|guideline)", re.I), "HIGH", "Safety bypass"),
    # Context poisoning via markup - lazy quantifiers + DOTALL so the
    # pattern can span lines and does not ReDoS on long inputs without
    # a closing delimiter. Mirrors the JS module's GUARD-INJ-027 / GUARD-INJ-028.
    InjectionPattern("GUARD-INJ-027", re.compile(r"<!--"), "MEDIUM", "HTML-comment context poisoning",  _comment_matcher("<!--", "-->")),
    InjectionPattern("GUARD-INJ-028", re.compile(r"/\*"), "MEDIUM", "Block-comment context poisoning", _comment_matcher("/*", "*/")),
]

# Invisible unicode used in steganographic attacks
# Reported as GUARD-INJ-UNICODE when present: zero-width and bidi controls, the
# word joiner family, Mongolian vowel separator, Arabic letter mark, and
# the Unicode tag block (the "ASCII smuggling" channel).
INVISIBLE_UNICODE_PATTERN = re.compile(
    "[\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\u2066-\u206F\uFEFF\U000E0000-\U000E007F]"
)

# Removed before pattern matching. Superset of the above: also covers
# invisible characters that are common in honest text (variation
# selectors after emoji, Hangul fillers), which are stripped so they
# cannot split a keyword but do not raise a finding by themselves.
INVISIBLE_STRIP_PATTERN = re.compile(
    "[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202F\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\U000E0000-\U000E0FFF]"
)

TAG_CHAR_PATTERN = re.compile("[\U000E0020-\U000E007E]")

# Cyrillic and Greek letters that render like Latin ones. NFKC does not
# fold these, so "ignore" spelled with a Cyrillic o passed every pattern.
CONFUSABLES = str.maketrans({
    "а": "a", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "о": "o",
    "р": "p", "ѕ": "s", "у": "y", "х": "x", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ӏ": "l",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "У": "Y", "Х": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "υ": "u", "τ": "t", "ϲ": "c",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})

BASE64_RUN_PATTERN    = re.compile(r"[A-Za-z0-9+/_-]{24,20000}={0,2}")
MAX_BASE64_CANDIDATES = 64
PRINTABLE_PATTERN     = re.compile(r"^[\x20-\x7E\s]{10,}$")

# Hard cap on raw input to `scan()`. `guard_input()` enforces its own
# `max_length` (default 4000), but `scan()` is imported and used directly
# by test code and third-party callers. Without a cap, a huge payload
# through a direct caller can burn CPU inside the normalizer (which
# appends URL-decoded + base64-decoded copies onto the original). The cap
# is 1,000,000 characters, the same as the Node module; input past it is
# reported as GUARD-INJ-OVERSIZE, not dropped silently.
MAX_SCAN_LENGTH = 1_000_000

# ---------------------------------------------------------------------------
# SECRET LEAK PATTERNS - Python parity with security/01-injection-guard.js
# Catches secrets that leak into AI input or output.
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    id: str
    pattern: re.Pattern
    label: str

# GUARD-SEC-001 / GUARD-SEC-001b / GUARD-SEC-010 / GUARD-SEC-011 rationale:
# The pre-1.1.1 GUARD-SEC-001 pattern was `sk-[a-zA-Z0-9]{20,}`, which broke on
# the two provider formats users are actually leaking today:
#   - OpenAI project keys  : sk-proj-...     (mid-2024 onward)
#   - Anthropic Claude keys: sk-ant-api03-...
# The hyphen after `sk-proj`/`sk-ant` falls outside [a-zA-Z0-9], so the
# regex halted at 4 chars and reported the input clean. A leaked current
# key would sail through guard_output() unnoticed.
#
# Fix: split into provider-specific rules so the label names the provider
# (operationally useful when triaging an incident), plus a legacy fallback
# for historical `sk-...` keys still in circulation. GUARD-SEC-011 adds coverage
# for connection strings with embedded credentials - the common protocol
# schemes (postgres, mysql, mongodb, redis, amqp) whose URLs pin a
# user:pass@host authority into source. See tests/audit.test.js for the
# full matrix of examples the rule must and must not fire on.
SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("GUARD-SEC-001",  re.compile(r"sk-proj-[a-zA-Z0-9_-]{20,}"),          "OpenAI Project API Key"),
    SecretPattern("GUARD-SEC-010",  re.compile(r"sk-ant-(?:api|oat|admin)\d{2}-[a-zA-Z0-9_-]{20,}"),  "Anthropic API Key"),
    SecretPattern("GUARD-SEC-001b", re.compile(r"sk-(?!proj-|ant-api\d{2}-)[a-zA-Z0-9]{20,}"), "OpenAI API Key (legacy)"),
    SecretPattern("GUARD-SEC-002",  re.compile(r"AIza[0-9A-Za-z\-_]{35}"),              "Google API Key"),
    SecretPattern("GUARD-SEC-003",  re.compile(r"ghp_[a-zA-Z0-9]{36}"),                 "GitHub Token"),
    SecretPattern("GUARD-SEC-004",  re.compile(r"gho_[a-zA-Z0-9]{36}"),                 "GitHub OAuth Token"),
    SecretPattern("GUARD-SEC-005",  re.compile(r"AKIA[0-9A-Z]{16}"),                    "AWS Access Key"),
    SecretPattern("GUARD-SEC-006",  re.compile(r"(?:secret|token|key|password|auth)\s*[:=]\s*[\"']?[A-Za-z0-9+/]{40,}[\"']?", re.I), "Context-Adjacent Base64 Secret"),
    SecretPattern("GUARD-SEC-007",  re.compile(r"-----BEGIN\s+(?:[A-Z0-9]+\s+){0,3}PRIVATE\s+KEY-----"), "Private Key"),
    SecretPattern("GUARD-SEC-008",  re.compile(r"password\s*[:=]\s*[\"']?[^\s\"']{8,}",  re.I), "Inline Password"),
    SecretPattern("GUARD-SEC-009",  re.compile(r"api[_-]?key\s*[:=]\s*[\"']?[^\s\"']{8,}", re.I), "Inline API Key"),
    SecretPattern("GUARD-SEC-011",  re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:@/\s\"'`]{0,256}:[^@\s\"'`]{1,512}@", re.I), "Connection String with Embedded Credentials"),
    SecretPattern("GUARD-SEC-012",  re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),        "GitHub Fine-Grained Token"),
    SecretPattern("GUARD-SEC-013",  re.compile(r"gh[sur]_[A-Za-z0-9]{36,}"),            "GitHub App/Server Token"),
    SecretPattern("GUARD-SEC-014",  re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),        "Slack Token"),
    SecretPattern("GUARD-SEC-015",  re.compile(r"[sr]k_live_[A-Za-z0-9]{20,}"),         "Stripe Live Key"),
]

# ---------------------------------------------------------------------------
# VIOLATION DATACLASS
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    type: str       # "injection" | "secret"
    id: str
    severity: str
    matched: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Rule ids carry the engine prefix GUARD- (1.5.0) so they cannot be
    # confused with the audit's INJ-* / SEC-* ids. legacy_id is the
    # pre-1.5.0 id, kept for one release so callers can migrate.
    legacy_id: str = ""

    def __post_init__(self) -> None:
        if not self.legacy_id:
            self.legacy_id = self.id[len("GUARD-"):] if self.id.startswith("GUARD-") else self.id


# ---------------------------------------------------------------------------
# PRE-SCAN NORMALIZER - Python parity with JS version (v1.0.1 patches)
# - NFKC: fullwidth/homoglyph Unicode → ASCII (defeats ｉｇｎｏｒｅ bypass)
# - Strip invisible Unicode (defeats zero-width-space bypass)
# - URL-decode and base64-decode candidates so encoded payloads are scanned
# ---------------------------------------------------------------------------

def _decode_base64_printable(candidate: str) -> Optional[str]:
    import base64, binascii
    standard = candidate.replace("-", "+").replace("_", "/")
    standard += "=" * (-len(standard) % 4)
    try:
        decoded = base64.b64decode(standard).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return None  # not base64, which is not a finding
    return decoded if PRINTABLE_PATTERN.match(decoded) else None


def _normalize_for_scan(text: str) -> str:
    """
    Normalize before scanning. Returns every decoded view of the text,
    newline-joined, so the patterns run over all of them in one pass.
    Mirrors normalizeForScan() in 01-injection-guard.js:

      1. NFKC with invisible characters removed
      2. Unicode tag characters mapped back to the ASCII they shadow
      3. Cyrillic/Greek lookalikes folded to Latin
      4. Percent-decoded
      5. HTML entities decoded
      6. Markdown emphasis markers removed
      7. Each embedded base64 run that decodes to printable text
    """
    import unicodedata, urllib.parse, html

    base = INVISIBLE_STRIP_PATTERN.sub("", unicodedata.normalize("NFKC", text))
    views = [base]

    def add_view(view: Optional[str]) -> None:
        if view and view != base and view not in views:
            views.append(view)

    tag_run = TAG_CHAR_PATTERN.findall(text)
    if tag_run:
        add_view("".join(chr(ord(ch) - 0xE0000) for ch in tag_run))

    add_view(base.translate(CONFUSABLES))
    add_view(urllib.parse.unquote(base))
    add_view(html.unescape(base))
    add_view(re.sub(r"[*_`~]+", "", base))

    compact = re.sub(r"\s", "", text)
    if len(compact) <= 20000 and re.match(r"^[A-Za-z0-9+/_-]{20,}={0,2}$", compact):
        add_view(_decode_base64_printable(compact))
    for count, run in enumerate(BASE64_RUN_PATTERN.finditer(text)):
        if count >= MAX_BASE64_CANDIDATES:
            break
        add_view(_decode_base64_printable(run.group(0)))

    return "\n".join(views)


SCAN_MODES = frozenset({"injection", "secrets", "all"})


def scan(text: str, mode: str = "all") -> list[Violation]:
    """
    Scans text for injection patterns and (optionally) secret leaks.

    v1.1.1: caps input at MAX_SCAN_LENGTH before work so direct callers
    (audit CLI, hooks, third-party) get the same DoS protection that
    guard_input() provides.

    Args:
        text: input text
        mode: 'injection' | 'secrets' | 'all'

    Returns:
        list of Violation objects (empty if clean)

    Raises:
        ValueError: mode is not one of the three. Any other mode would scan
            nothing and report clean, so a typo would switch the guard off
            (BUG-049).
        TypeError: text is not a string, for the same reason.
    """
    if mode not in SCAN_MODES:
        raise ValueError(f"scan() mode must be 'injection', 'secrets' or 'all'; got {mode!r}.")
    if not isinstance(text, str):
        raise TypeError(f"scan() requires a string; got {type(text).__name__}.")

    unscanned = 0
    if len(text) > MAX_SCAN_LENGTH:
        logger.warning(
            f"⚠️  [OTLC GUARDIAN] scan() input truncated: {len(text)} chars > {MAX_SCAN_LENGTH} limit"
        )
        unscanned = len(text) - MAX_SCAN_LENGTH
        text = text[:MAX_SCAN_LENGTH]

    normalized = _normalize_for_scan(text)
    violations: list[Violation] = []

    if mode in ("injection", "all"):
        for rule in INJECTION_PATTERNS:
            if rule.matcher is not None:
                matched = rule.matcher(normalized)
            else:
                found = rule.pattern.search(normalized)
                matched = found.group(0) if found else None
            if matched is not None:
                violations.append(Violation(
                    type="injection",
                    id=rule.id,
                    severity=rule.severity,
                    matched=matched,
                    description=rule.description,
                ))

        # Truncation is a finding. Content past the cap was not scanned,
        # so a payload hidden behind filler must never read as clean.
        if unscanned > 0:
            violations.append(Violation(
                type="injection",
                id="GUARD-INJ-OVERSIZE",
                severity="MEDIUM",
                matched=f"{unscanned} characters past the {MAX_SCAN_LENGTH} scan limit were not scanned",
                description="Input exceeds scan limit",
            ))

        if INVISIBLE_UNICODE_PATTERN.search(text):
            violations.append(Violation(
                type="injection",
                id="GUARD-INJ-UNICODE",
                severity="HIGH",
                matched="invisible unicode characters",
                description="Invisible Unicode detected - potential steganographic injection",
            ))

    if mode in ("secrets", "all"):
        for rule in SECRET_PATTERNS:
            if rule.pattern.search(normalized):
                violations.append(Violation(
                    type="secret",
                    id=rule.id,
                    severity="CRITICAL",
                    matched=f"[REDACTED - {rule.label}]",
                    description=rule.label,
                ))

    return violations


# ---------------------------------------------------------------------------
# VISIBLE REPORT
# Security visibility is a feature, not noise.
# ---------------------------------------------------------------------------

def report_violations(violations: list[Violation], context: str = "input") -> None:
    """Prints visible security output. Never suppress this."""
    if not violations:
        return

    injections = [v for v in violations if v.type == "injection"]
    secrets    = [v for v in violations if v.type == "secret"]

    if injections:
        logger.warning(f"\n⚠️  [OTLC GUARDIAN] PROMPT INJECTION DETECTED")
        logger.warning(f"    Context : {context}")
        logger.warning(f"    Count   : {len(injections)} pattern(s) matched")
        for v in injections:
            logger.warning(f"    [{v.severity}] {v.id} - {v.description} - matched: \"{v.matched}\"")

    if secrets:
        logger.error(f"\n🚨 [OTLC GUARDIAN] SECRET LEAK DETECTED")
        logger.error(f"    Context : {context}")
        for v in secrets:
            logger.error(f"    [CRITICAL] {v.id} - {v.description}")
        logger.error(f"    → Remove secrets from code. Use environment variables.")


# ---------------------------------------------------------------------------
# SANITIZER
# ---------------------------------------------------------------------------

SANITIZE_PATTERNS = [
    re.compile(r"</?(?:system|assistant|human|user)>", re.I),
    re.compile(r"\[SYSTEM\]|\[INST\]",                 re.I),
    re.compile(r"<<\s*SYS\s*>>",                       re.I),
    re.compile(r"###\s*(?:System|Instruction|Prompt)", re.I),
    re.compile(r"---\s*SYSTEM",                        re.I),
    INVISIBLE_STRIP_PATTERN,
]

def sanitize(text: str) -> str:
    """Strips known injection delimiter tokens."""
    for pattern in SANITIZE_PATTERNS:
        text = pattern.sub("", text)
    return text


# ---------------------------------------------------------------------------
# GUARDIAN ERROR
# ---------------------------------------------------------------------------

class GuardianError(Exception):
    def __init__(self, message: str, violations: list[Violation] = None):
        super().__init__(message)
        self.violations = violations or []
        self.timestamp  = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# COMBINED GUARD - PRIMARY ENTRY POINT
# ---------------------------------------------------------------------------

def guard_input(
    text: str,
    max_length: int = 4000,
    block_on_critical: bool = True,
    block_on_secrets:  bool = True,
    context: str = "user input",
    on_violation: Optional[Callable[[Violation], None]] = None,
) -> str:
    """
    One-call guard. Validates length, scans for injection + secrets, reports visibly.

    Args:
        text:               Raw user input
        max_length:         Maximum allowed input length
        block_on_critical:  Raise GuardianError on CRITICAL injection findings
        block_on_secrets:   Raise GuardianError if secret-shaped content detected
        context:            Label for log output (e.g. "chat API", "search query")
        on_violation:       Optional callback for each violation found

    Returns:
        Sanitized string safe to pass to AI API

    Raises:
        GuardianError: if critical violation found and block_on_critical is True,
                       or secrets found and block_on_secrets is True
    """
    if not isinstance(text, str):
        raise TypeError("guard_input requires a string.")

    # Length check
    if len(text) > max_length:
        logger.warning(f"⚠️  [OTLC GUARDIAN] Input truncated: {len(text)} chars > {max_length} limit")
        text = text[:max_length]

    # Scan (injection + secrets)
    violations = scan(text, mode="all")

    # Report visibly
    report_violations(violations, context)

    # Fire callbacks
    if on_violation:
        for v in violations:
            on_violation(v)

    # Block on secrets
    has_secrets = any(v.type == "secret" for v in violations)
    if has_secrets and block_on_secrets:
        raise GuardianError("Input contains secret-shaped content. Blocked.", violations)

    # Block on critical injection
    has_critical = any(v.type == "injection" and v.severity == "CRITICAL" for v in violations)
    if has_critical and block_on_critical:
        raise GuardianError("Critical prompt injection attempt detected. Blocked.", violations)

    sanitized = sanitize(text)

    # Post-sanitize re-scan - catches payloads that only appear after stripping
    # delimiters (e.g. zero-width space between i​g leaves "ignore" behind).
    post = scan(sanitized, mode="injection")
    if post:
        report_violations(post, f"{context} [post-sanitize]")
        if block_on_critical and any(v.severity == "CRITICAL" for v in post):
            raise GuardianError("Critical injection detected after sanitization. Blocked.", post)

    return sanitized


# ---------------------------------------------------------------------------
# OUTPUT GUARD - Python parity with security/01-injection-guard.js
# Scan AI responses before they reach the user or get stored.
# Catches: leaked secrets in AI output, reflected injection (model echoing back).
# ---------------------------------------------------------------------------

def guard_output(
    output: str,
    block_on_secrets: bool = True,
    context: str = "AI output",
    on_violation: Optional[Callable[[Violation], None]] = None,
) -> str:
    """
    Guards AI output before it reaches the user or is stored.

    Args:
        output:           Raw AI response text
        block_on_secrets: Raise GuardianError if secret-shaped content found
        context:          Label for log output
        on_violation:     Optional callback for each violation

    Returns:
        Output text safe to send to user

    Raises:
        GuardianError: if secrets found and block_on_secrets is True
    """
    if not isinstance(output, str):
        raise TypeError("guard_output requires a string.")

    # Scan for both - secrets always block-eligible, injection patterns are
    # informational only on output (the AI is just echoing them back).
    secret_violations    = scan(output, mode="secrets")
    injection_violations = scan(output, mode="injection")
    all_violations       = secret_violations + injection_violations

    report_violations(all_violations, context)

    if on_violation:
        for v in all_violations:
            on_violation(v)

    if secret_violations and block_on_secrets:
        raise GuardianError(
            "AI output contains secret-shaped content. Blocked before delivery.",
            secret_violations,
        )

    return output


# ---------------------------------------------------------------------------
# FASTAPI DEPENDENCY (optional)
# ---------------------------------------------------------------------------

def make_fastapi_guard(field: str = "message", **guard_kwargs):
    """
    Returns a FastAPI dependency that guards a specific request body field
    AND returns the sanitized value so the endpoint receives clean input.

    Pre-1.3.1 the dependency called `guard_input()` for its side effect
    (raising on critical violations) but discarded the sanitized return
    value entirely. That meant non-blocking but sanitizable input - for
    example a string with a zero-width-space bypass - would reach the
    endpoint UNCHANGED. The Node middleware (`injectionMiddleware()` in
    01-injection-guard.js) writes the sanitized value back into
    `req.body[field]`; the Python dependency now mirrors that behavior
    by returning the sanitized field value, which the endpoint receives
    through `Depends()`.

    Usage (1.3.1+):
        from fastapi import Depends
        from security.injection_guard import make_fastapi_guard

        guard = make_fastapi_guard(field="message")

        @app.post("/api/v1/chat")
        async def chat(clean_message: str = Depends(guard)):
            # clean_message is the SANITIZED version of body["message"].
            # Use it directly - do NOT re-read body["message"], that would
            # be the unsanitized original.
            reply = await call_your_ai(clean_message)
            ...

    The endpoint receives the dependency's return value, not the raw
    request body field. If your endpoint needs other fields from the
    body in addition to the guarded one, take them from a separate
    Pydantic model parameter - Pydantic models and Depends() coexist
    cleanly.

    Note: FastAPI is imported lazily so this module remains importable
    in projects that don't use FastAPI. The previous version had a
    bug where the `request` parameter had no type annotation, so
    FastAPI's dependency injection could not provide it. Calling the
    dependency would raise an internal error from FastAPI before our
    code ran. Fixed by adding the Request type hint and resolving the
    fastapi import once at decorator-build time.
    """
    try:
        from fastapi import Request, HTTPException
    except ImportError as e:
        raise ImportError(
            "make_fastapi_guard requires fastapi to be installed. "
            "Run: pip install fastapi"
        ) from e

    async def dependency(request: Request) -> str:
        body = await request.json()
        raw  = body.get(field, "") if isinstance(body, dict) else ""
        try:
            sanitized = guard_input(
                raw,
                context=f"{request.method} {request.url.path}",
                **guard_kwargs,
            )
        except GuardianError:
            raise HTTPException(status_code=400, detail={
                "success": False,
                "error": {
                    "code":    "ERR_INJECTION_DETECTED",
                    "message": "Input rejected by security guard.",
                },
            })
        # 1.3.1: return the sanitized value so the endpoint actually
        # receives clean input. Pre-1.3.1 this return was missing and
        # the unsanitized raw body field reached the endpoint.
        return sanitized

    return dependency


# ---------------------------------------------------------------------------
# CLI - scan a string from the command line
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Enter text to scan: ")
    violations = scan(text)
    report_violations(violations, context="CLI")
    if not violations:
        print("✅ [OTLC GUARDIAN] No injection patterns detected.")
