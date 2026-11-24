"""Optional adapter to ProtectAI LLM Guard's documented scan functions.

LLM Guard is an optional, archived upstream dependency. Aegis does not install
or enable it by default. When enabled, any import or scanner failure blocks the
request rather than silently bypassing the configured scanner.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class ScannerUnavailable(RuntimeError):
    """The optional security scanner could not run; callers must fail closed."""


class ScanRejected(RuntimeError):
    """A scanner marked content invalid; callers must block the operation."""


def build_default_scanners() -> tuple[list[Any], list[Any]]:
    """Build modest default input/output scanners from the optional package."""
    try:
        from llm_guard.input_scanners import Secrets
        from llm_guard.output_scanners import Sensitive

        return [Secrets()], [Sensitive()]
    except Exception:
        raise ScannerUnavailable("LLM Guard scanners could not be initialized") from None


def scan_input(text: str, scanners: Sequence[Any]) -> tuple[str, int]:
    """Run LLM Guard input scanners; return sanitized text and a count only."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    try:
        from llm_guard import scan_prompt

        sanitized, valid, _scores = scan_prompt(list(scanners), text)
    except Exception:
        raise ScannerUnavailable("LLM Guard input scan failed") from None
    if not isinstance(sanitized, str) or not isinstance(valid, dict):
        raise ScannerUnavailable("LLM Guard returned an invalid scan result")
    if not all(value is True for value in valid.values()):
        raise ScanRejected("LLM Guard rejected input")
    return sanitized, int(sanitized != text)


def scan_output(text: str, prompt: str, scanners: Sequence[Any]) -> tuple[str, int]:
    """Run LLM Guard output scanners; fail closed on invalid or malformed results."""
    if not isinstance(text, str) or not isinstance(prompt, str):
        raise TypeError("text and prompt must be strings")
    try:
        from llm_guard import scan_output as run_scan_output

        sanitized, valid, _scores = run_scan_output(list(scanners), prompt, text)
    except Exception:
        raise ScannerUnavailable("LLM Guard output scan failed") from None
    if not isinstance(sanitized, str) or not isinstance(valid, dict):
        raise ScannerUnavailable("LLM Guard returned an invalid scan result")
    if not all(value is True for value in valid.values()):
        raise ScanRejected("LLM Guard rejected output")
    return sanitized, int(sanitized != text)
