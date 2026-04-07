"""
============================================================
OTLC GUARDIAN — Prompt Injection Guard (Python)
// security · onthelevelconcepts.com
Version: 1.0.0
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
]

# Invisible unicode used in steganographic attacks
INVISIBLE_UNICODE_PATTERN = re.compile(r"[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]")

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
# SCAN FUNCTION
# ---------------------------------------------------------------------------

def scan(text: str) -> list[Violation]:
    """Scans text for injection patterns. Returns list of violations."""
    if not isinstance(text, str):
        return []

    violations: list[Violation] = []

    for rule in INJECTION_PATTERNS:
        match = rule.pattern.search(text)
        if match:
            violations.append(Violation(
                type="injection",
                id=rule.id,
                severity=rule.severity,
                matched=match.group(0),
                description=rule.description,
            ))

    if INVISIBLE_UNICODE_PATTERN.search(text):
        violations.append(Violation(
            type="injection",
            id="INJ-UNICODE",
            severity="HIGH",
            matched="invisible unicode characters",
            description="Invisible Unicode detected — potential steganographic injection",
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
    context: str = "user input",
    on_violation: Optional[Callable[[Violation], None]] = None,
) -> str:
    """
    One-call guard. Validates length, scans for injection, reports visibly.

    Args:
        text:               Raw user input
        max_length:         Maximum allowed input length
        block_on_critical:  Raise GuardianError on CRITICAL findings
        context:            Label for log output (e.g. "chat API", "search query")
        on_violation:       Optional callback for each violation found

    Returns:
        Sanitized string safe to pass to AI API

    Raises:
        GuardianError: if critical violation found and block_on_critical is True
    """
    if not isinstance(text, str):
        raise TypeError("guard_input requires a string.")

    # Length check
    if len(text) > max_length:
        logger.warning(f"⚠️  [OTLC GUARDIAN] Input truncated: {len(text)} chars > {max_length} limit")
        text = text[:max_length]

    # Scan
    violations = scan(text)

    # Report visibly
    report_violations(violations, context)

    # Fire callbacks
    if on_violation:
        for v in violations:
            on_violation(v)

    # Block on critical
    if block_on_critical and any(v.severity == "CRITICAL" for v in violations):
        raise GuardianError("Critical prompt injection attempt detected. Blocked.", violations)

    return sanitize(text)


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
    """
    async def dependency(request):
        from fastapi import Request, HTTPException
        body = await request.json()
        raw  = body.get(field, "")
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
