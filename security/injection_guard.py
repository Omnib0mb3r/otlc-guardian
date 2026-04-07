"""
============================================================
OTLC GUARDIAN — Prompt Injection Guard (Python)
// security · onthelevelconcepts.com
Version: 1.1.1
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


INJECTION_PATTERNS: list[InjectionPattern] = [
    InjectionPattern("INJ-001", re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "CRITICAL", "Classic instruction override"),
    InjectionPattern("INJ-002", re.compile(r"ignore\s+(all\s+)?above\s+instructions",    re.I), "CRITICAL", "Above instruction override"),
    InjectionPattern("INJ-003", re.compile(r"disregard\s+(all\s+)?previous",              re.I), "CRITICAL", "Disregard previous"),
    InjectionPattern("INJ-004", re.compile(r"forget\s+(all\s+)?(your\s+)?instructions",  re.I), "CRITICAL", "Forget instructions"),
    InjectionPattern("INJ-005", re.compile(r"override\s+(system|previous)\s+(prompt|instructions)", re.I), "CRITICAL", "System override"),
    InjectionPattern("INJ-006", re.compile(r"you\s+are\s+now\s+(?:a|an|the)\s+",         re.I), "HIGH",     "Role hijack: you are now"),
    InjectionPattern("INJ-007", re.compile(r"pretend\s+(?:you(?:'re| are)\s+|to\s+be\s+)", re.I), "HIGH",   "Role hijack: pretend"),
    InjectionPattern("INJ-008", re.compile(r"from\s+now\s+on,?\s+you\s+(?:are|will|should|must)", re.I), "HIGH", "Role hijack: from now on"),
    InjectionPattern("INJ-009", re.compile(r"act\s+as\s+(?:a|an|the)\s+(?!user|customer|person)", re.I), "HIGH", "Role hijack: act as"),
    InjectionPattern("INJ-010", re.compile(r"roleplay\s+as",                               re.I), "HIGH",     "Roleplay hijack"),
    InjectionPattern("INJ-011", re.compile(r"simulate\s+(?:a|an|the)\s+",                 re.I), "MEDIUM",   "Simulation hijack"),
    InjectionPattern("INJ-012", re.compile(r"(?:print|output|reveal|show|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", re.I), "HIGH", "Prompt extraction"),
    InjectionPattern("INJ-013", re.compile(r"what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions", re.I), "HIGH", "Instruction extraction"),
    InjectionPattern("INJ-014", re.compile(r"tell\s+me\s+your\s+(?:system\s+)?prompt",    re.I), "HIGH",     "System prompt extraction"),
    InjectionPattern("INJ-015", re.compile(r"</?(?:system|assistant|human|user)>",        re.I), "CRITICAL", "Delimiter injection"),
    InjectionPattern("INJ-016", re.compile(r"\[SYSTEM\]",                                 re.I), "CRITICAL", "SYSTEM tag injection"),
    InjectionPattern("INJ-017", re.compile(r"\[INST\]",                                   re.I), "CRITICAL", "INST tag injection"),
    InjectionPattern("INJ-018", re.compile(r"<<\s*SYS\s*>>",                              re.I), "CRITICAL", "SYS tag injection"),
    InjectionPattern("INJ-019", re.compile(r"###\s*(?:System|Instruction|Prompt)",        re.I), "CRITICAL", "Markdown system tag"),
    InjectionPattern("INJ-020", re.compile(r"---\s*SYSTEM",                               re.I), "CRITICAL", "YAML system override"),
    InjectionPattern("INJ-021", re.compile(r"do\s+anything\s+now",                        re.I), "HIGH",     "DAN variant"),
    InjectionPattern("INJ-022", re.compile(r"DAN\s+mode",                                 re.I), "HIGH",     "DAN mode"),
    InjectionPattern("INJ-023", re.compile(r"developer\s+mode",                           re.I), "HIGH",     "Developer mode jailbreak"),
    InjectionPattern("INJ-024", re.compile(r"jailbreak",                                  re.I), "HIGH",     "Jailbreak keyword"),
    InjectionPattern("INJ-025", re.compile(r"without\s+(?:any\s+)?restrictions",          re.I), "HIGH",     "Restriction bypass"),
    InjectionPattern("INJ-026", re.compile(r"bypass\s+(?:your\s+)?(?:safety|filter|guideline)", re.I), "HIGH", "Safety bypass"),
    # Context poisoning via markup — lazy quantifiers + DOTALL so the
    # pattern can span lines and does not ReDoS on long inputs without
    # a closing delimiter. Mirrors the JS module's INJ-027 / INJ-028.
    InjectionPattern("INJ-027", re.compile(r"<!--.*?(?:ignore|override|system).*?-->",    re.I | re.S), "MEDIUM", "HTML-comment context poisoning"),
    InjectionPattern("INJ-028", re.compile(r"/\*.*?(?:ignore|override|system).*?\*/",     re.I | re.S), "MEDIUM", "Block-comment context poisoning"),
]

# Invisible unicode used in steganographic attacks
INVISIBLE_UNICODE_PATTERN = re.compile(r"[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]")

# Hard cap on raw input to `scan()`. `guard_input()` enforces its own
# `max_length` (default 4000), but `scan()` is imported and used directly
# by test code and third-party callers. Without a cap, a huge payload
# through a direct caller can burn CPU inside the normalizer (which
# appends URL-decoded + base64-decoded copies onto the original). 100 KB
# is well above any legitimate injection payload and stays in the
# millisecond range on modern hardware.
MAX_SCAN_LENGTH = 100_000

# ---------------------------------------------------------------------------
# SECRET LEAK PATTERNS — Python parity with security/01-injection-guard.js
# Catches secrets that leak into AI input or output.
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    id: str
    pattern: re.Pattern
    label: str

# SEC-001 / SEC-001b / SEC-010 / SEC-011 rationale:
# The pre-1.1.1 SEC-001 pattern was `sk-[a-zA-Z0-9]{20,}`, which broke on
# the two provider formats users are actually leaking today:
#   - OpenAI project keys  : sk-proj-...     (mid-2024 onward)
#   - Anthropic Claude keys: sk-ant-api03-...
# The hyphen after `sk-proj`/`sk-ant` falls outside [a-zA-Z0-9], so the
# regex halted at 4 chars and reported the input clean. A leaked current
# key would sail through guard_output() unnoticed.
#
# Fix: split into provider-specific rules so the label names the provider
# (operationally useful when triaging an incident), plus a legacy fallback
# for historical `sk-...` keys still in circulation. SEC-011 adds coverage
# for connection strings with embedded credentials — the common protocol
# schemes (postgres, mysql, mongodb, redis, amqp) whose URLs pin a
# user:pass@host authority into source. See tests/audit.test.js for the
# full matrix of examples the rule must and must not fire on.
SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("SEC-001",  re.compile(r"sk-proj-[a-zA-Z0-9_-]{20,}"),          "OpenAI Project API Key"),
    SecretPattern("SEC-010",  re.compile(r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}"),  "Anthropic API Key"),
    SecretPattern("SEC-001b", re.compile(r"sk-(?!proj-|ant-api\d{2}-)[a-zA-Z0-9]{20,}"), "OpenAI API Key (legacy)"),
    SecretPattern("SEC-002",  re.compile(r"AIza[0-9A-Za-z\-_]{35}"),              "Google API Key"),
    SecretPattern("SEC-003",  re.compile(r"ghp_[a-zA-Z0-9]{36}"),                 "GitHub Token"),
    SecretPattern("SEC-004",  re.compile(r"gho_[a-zA-Z0-9]{36}"),                 "GitHub OAuth Token"),
    SecretPattern("SEC-005",  re.compile(r"AKIA[0-9A-Z]{16}"),                    "AWS Access Key"),
    SecretPattern("SEC-006",  re.compile(r"(?:secret|token|key|password|auth)\s*[:=]\s*[\"']?[A-Za-z0-9+/]{40,}[\"']?", re.I), "Context-Adjacent Base64 Secret"),
    SecretPattern("SEC-007",  re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), "Private Key"),
    SecretPattern("SEC-008",  re.compile(r"password\s*[:=]\s*[\"']?[^\s\"']{8,}",  re.I), "Inline Password"),
    SecretPattern("SEC-009",  re.compile(r"api[_-]?key\s*[:=]\s*[\"']?[^\s\"']{8,}", re.I), "Inline API Key"),
    SecretPattern("SEC-011",  re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:@/\s\"'`]*:[^@\s\"'`]+@", re.I), "Connection String with Embedded Credentials"),
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


# ---------------------------------------------------------------------------
# PRE-SCAN NORMALIZER — Python parity with JS version (v1.0.1 patches)
# - NFKC: fullwidth/homoglyph Unicode → ASCII (defeats ｉｇｎｏｒｅ bypass)
# - Strip invisible Unicode (defeats zero-width-space bypass)
# - URL-decode and base64-decode candidates so encoded payloads are scanned
# ---------------------------------------------------------------------------

def _normalize_for_scan(text: str) -> str:
    """Normalize before scanning. Returns text ready for pattern matching."""
    import unicodedata, base64, urllib.parse

    normalized = unicodedata.normalize("NFKC", text)
    normalized = INVISIBLE_UNICODE_PATTERN.sub("", normalized)

    # URL-decode — catches %69%67%6E%6F%72%65 style payloads
    try:
        url_decoded = urllib.parse.unquote(normalized)
        if url_decoded != normalized:
            normalized = f"{normalized}\n{url_decoded}"
    except Exception:
        pass

    # Base64 decode — only on strings that look like valid base64
    candidate = re.sub(r"\s", "", text)
    if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", candidate):
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            if re.match(r"^[\x20-\x7E\s]{10,}$", decoded):
                normalized = f"{normalized}\n{decoded}"
        except Exception:
            pass

    return normalized


# ---------------------------------------------------------------------------
# SCAN FUNCTION
# ---------------------------------------------------------------------------

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
    """
    if not isinstance(text, str):
        return []

    if len(text) > MAX_SCAN_LENGTH:
        logger.warning(
            f"⚠️  [OTLC GUARDIAN] scan() input truncated: {len(text)} chars > {MAX_SCAN_LENGTH} limit"
        )
        text = text[:MAX_SCAN_LENGTH]

    normalized = _normalize_for_scan(text)
    violations: list[Violation] = []

    if mode in ("injection", "all"):
        for rule in INJECTION_PATTERNS:
            match = rule.pattern.search(normalized)
            if match:
                violations.append(Violation(
                    type="injection",
                    id=rule.id,
                    severity=rule.severity,
                    matched=match.group(0),
                    description=rule.description,
                ))

        # Scan original text for invisible unicode (normalizer strips it)
        if INVISIBLE_UNICODE_PATTERN.search(text):
            violations.append(Violation(
                type="injection",
                id="INJ-UNICODE",
                severity="HIGH",
                matched="invisible unicode characters",
                description="Invisible Unicode detected — potential steganographic injection",
            ))

    if mode in ("secrets", "all"):
        for rule in SECRET_PATTERNS:
            if rule.pattern.search(normalized):
                violations.append(Violation(
                    type="secret",
                    id=rule.id,
                    severity="CRITICAL",
                    matched=f"[REDACTED — {rule.label}]",
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
            logger.warning(f"    [{v.severity}] {v.id} — {v.description} — matched: \"{v.matched}\"")

    if secrets:
        logger.error(f"\n🚨 [OTLC GUARDIAN] SECRET LEAK DETECTED")
        logger.error(f"    Context : {context}")
        for v in secrets:
            logger.error(f"    [CRITICAL] {v.id} — {v.description}")
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
    INVISIBLE_UNICODE_PATTERN,
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
# COMBINED GUARD — PRIMARY ENTRY POINT
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

    # Post-sanitize re-scan — catches payloads that only appear after stripping
    # delimiters (e.g. zero-width space between i​g leaves "ignore" behind).
    post = scan(sanitized, mode="injection")
    if post:
        report_violations(post, f"{context} [post-sanitize]")
        if block_on_critical and any(v.severity == "CRITICAL" for v in post):
            raise GuardianError("Critical injection detected after sanitization. Blocked.", post)

    return sanitized


# ---------------------------------------------------------------------------
# OUTPUT GUARD — Python parity with security/01-injection-guard.js
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

    # Scan for both — secrets always block-eligible, injection patterns are
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
    Returns a FastAPI dependency that guards a specific request body field.

    Usage:
        from fastapi import Depends
        from security.injection_guard import make_fastapi_guard

        guard = make_fastapi_guard(field="message")

        @app.post("/api/v1/chat")
        async def chat(body: ChatRequest, _=Depends(guard)):
            ...

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

    async def dependency(request: Request):
        body = await request.json()
        raw  = body.get(field, "") if isinstance(body, dict) else ""
        try:
            guard_input(raw, context=f"{request.method} {request.url.path}", **guard_kwargs)
        except GuardianError:
            raise HTTPException(status_code=400, detail={
                "success": False,
                "error": {
                    "code":    "ERR_INJECTION_DETECTED",
                    "message": "Input rejected by security guard.",
                },
            })

    return dependency


# ---------------------------------------------------------------------------
# CLI — scan a string from the command line
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Enter text to scan: ")
    violations = scan(text)
    report_violations(violations, context="CLI")
    if not violations:
        print("✅ [OTLC GUARDIAN] No injection patterns detected.")
