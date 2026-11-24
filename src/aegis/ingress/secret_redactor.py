"""In-memory secret redaction and restoration for Aegis ingress.

Secrets are held only in :class:`SessionVault` memory and are never logged.
The module has no mandatory third-party dependencies.
"""

from __future__ import annotations

import math
import re
import threading
import time
from typing import Final

_PLACEHOLDER_PREFIX: Final[str] = "__AEGIS_SEC_"
_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"__AEGIS_SEC_\d{3,}__")
_ENTROPY_MIN_LENGTH: Final[int] = 20
_ENTROPY_THRESHOLD: Final[float] = 4.5
_MAX_REDACTION_SPANS: Final[int] = 2048

# Explicit formats are redacted even when their character entropy is low.
_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{1,})", re.IGNORECASE),
    re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|rk_live_[A-Za-z0-9_-]{12,})\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    # JWTs are secret-bearing credentials regardless of their measured entropy.
    re.compile(r"\b[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\b"),
    # Named key/value fields commonly found in configuration and HTTP headers.
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
        r"client[_-]?secret|secret[_-]?key|password|passwd|credential|private[_-]?key|"
        r"x-api-key|authorization)\b\s*[:=]\s*(['\"]?)([^\s,;\"']{1,})"
    ),
)

# Candidates for entropy inspection. Punctuation useful in opaque tokens is included.
_ENTROPY_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_./+=~-]{20,}")


class SessionVault:
    """Thread-safe in-memory placeholder vault with a fixed TTL.

    The vault does not persist data and its representation deliberately omits
    stored secrets. Entries expire after ``ttl_seconds`` since insertion.
    """

    __slots__ = ("_ttl", "_entries", "_reverse", "_next_id", "_lock")

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool):
            raise TypeError("ttl_seconds must be a positive number")
        if not math.isfinite(float(ttl_seconds)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive number")
        self._ttl = float(ttl_seconds)
        self._entries: dict[str, tuple[str, float]] = {}
        self._reverse: dict[str, str] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        """Return a representation that never includes secret material."""
        return f"{type(self).__name__}(ttl_seconds={self._ttl:g})"

    def _purge_expired(self, now: float) -> None:
        expired = [
            placeholder for placeholder, (_, deadline) in self._entries.items() if deadline <= now
        ]
        for placeholder in expired:
            secret, _ = self._entries.pop(placeholder)
            # Remove only if the reverse entry still points to this placeholder.
            if self._reverse.get(secret) == placeholder:
                self._reverse.pop(secret, None)

    def store(self, secret: str, *, avoid: str = "") -> str:
        """Store a secret and return its opaque placeholder.

        ``avoid`` is the source text, used to ensure a generated placeholder
        cannot collide with literal text already present in that input.
        """
        if not isinstance(secret, str) or not isinstance(avoid, str):
            raise TypeError("secret and avoid must be strings")
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            existing = self._reverse.get(secret)
            if existing is not None and existing not in avoid:
                self._entries[existing] = (secret, now + self._ttl)
                return existing
            while True:
                placeholder = f"{_PLACEHOLDER_PREFIX}{self._next_id:03d}__"
                self._next_id += 1
                if placeholder not in self._entries and placeholder not in avoid:
                    break
            self._entries[placeholder] = (secret, now + self._ttl)
            self._reverse[secret] = placeholder
            return placeholder

    def resolve(self, placeholder: str) -> str | None:
        """Resolve a live placeholder, or return ``None`` if it is unknown/expired."""
        if not isinstance(placeholder, str):
            return None
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            entry = self._entries.get(placeholder)
            return entry[0] if entry is not None else None

    def clear(self) -> None:
        """Discard all vault contents from this process's in-memory mappings."""
        with self._lock:
            self._entries.clear()
            self._reverse.clear()


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character for a string."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _collect_spans(text: str) -> list[tuple[int, int]]:
    """Find sensitive spans using known token formats and entropy heuristics."""
    spans: list[tuple[int, int]] = []
    for pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            # For bearer and named key/value expressions, redact only the value.
            if pattern is _SECRET_PATTERNS[1]:
                start, end = match.span(1)
            elif pattern is _SECRET_PATTERNS[-1]:
                start, end = match.span(2)
            else:
                start, end = match.span(0)
            if start < end:
                spans.append((start, end))

    for match in _ENTROPY_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if (
            len(candidate) >= _ENTROPY_MIN_LENGTH
            and _shannon_entropy(candidate) > _ENTROPY_THRESHOLD
        ):
            spans.append(match.span())

    if not spans:
        return []
    spans.sort()
    merged: list[tuple[int, int]] = []
    start, end = spans[0]
    for next_start, next_end in spans[1:]:
        if next_start <= end:
            end = max(end, next_end)
        else:
            merged.append((start, end))
            start, end = next_start, next_end
    merged.append((start, end))
    return merged


def redact_text(text: str, vault: SessionVault) -> tuple[str, int]:
    """Replace detected secrets with vault placeholders.

    Returns the redacted text and the number of distinct secret spans replaced.
    No scanner dependency is required; redaction is performed locally.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(vault, SessionVault):
        raise TypeError("vault must be a SessionVault")
    spans = _collect_spans(text)
    if len(spans) > _MAX_REDACTION_SPANS:
        # Refuse oversized inputs rather than redacting only a prefix and
        # accidentally forwarding the remaining candidate secrets.
        raise ValueError("redaction span limit exceeded")
    if not spans:
        return text, 0

    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.append(text[cursor:start])
        pieces.append(vault.store(text[start:end], avoid=text))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), len(spans)


def restore_text(text: str, vault: SessionVault) -> str:
    """Restore unexpired placeholders from ``vault``; leave unknown ones intact."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(vault, SessionVault):
        raise TypeError("vault must be a SessionVault")

    def replace(match: re.Match[str]) -> str:
        secret = vault.resolve(match.group(0))
        return match.group(0) if secret is None else secret

    return _PLACEHOLDER_RE.sub(replace, text)
