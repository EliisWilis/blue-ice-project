"""Opt-in synthetic HMAC canaries for Aegis ingress.

A canary is a synthetic marker, never a user's real secret. If injected into a
request, it is visible to the selected provider. Its presence in a response or
elsewhere is not, by itself, evidence of training-data leakage.

Generation is disabled by default. The HMAC key must be supplied explicitly by
the caller; this module never reads environment variables or logs payloads,
keys, or tokens. When an audit path is configured, the only persisted fields
are UTC timestamp, provider label, and SHA-256 hash of the canary.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime
from os import PathLike
from typing import TypeAlias

AuditPath: TypeAlias = str | PathLike[str]

_TOKEN_RE = re.compile(r"aegis-canary-v1\.[0-9a-f]{32}\.[0-9a-f]{64}")
_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_DOMAIN = b"aegis-honey-token:v1\x00"


async def generate_canary(
    key: bytes,
    *,
    enabled: bool = False,
    provider: str = "unspecified",
    audit_path: AuditPath | None = None,
) -> str | None:
    """Generate a synthetic HMAC-SHA256 canary when explicitly enabled.

    Args:
        key: Caller-supplied HMAC key (at least 32 bytes); never persisted.
        enabled: Must be set to ``True`` to generate a canary.
        provider: Short, non-sensitive provider label for optional audit.
        audit_path: Optional append-only JSONL audit destination. If supplied,
            audit failure raises and no canary is returned (fail closed).

    Returns:
        A synthetic token, or ``None`` when disabled.

    Raises:
        TypeError: If the supplied key is not ``bytes``.
        ValueError: For a short key or invalid provider label.
        OSError: If optional audit storage cannot be safely written.

    Audit I/O runs in a worker thread so the async caller's event loop is not
    blocked. No third-party provider or service is contacted.
    """
    if not enabled:
        return None
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes supplied by the caller")
    if len(key) < 32:
        raise ValueError("key must contain at least 32 bytes")
    if not isinstance(provider, str) or not _PROVIDER_RE.fullmatch(provider):
        raise ValueError("provider must be a short, non-sensitive label")

    nonce = secrets.token_bytes(16)
    mac = hmac.new(key, _DOMAIN + nonce, hashlib.sha256).hexdigest()
    token = f"aegis-canary-v1.{nonce.hex()}.{mac}"

    if audit_path is not None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "provider": provider,
            "hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
        }
        # Serialize only the three permitted audit fields. Never pass key,
        # token, or request content to the audit writer.
        line = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        await asyncio.to_thread(_append_restricted_audit, audit_path, line)
    return token


def inject_canary(text: str, canary: str | None, *, enabled: bool = False) -> str:
    """Append a canary to text only when injection is explicitly enabled.

    The marker is placed on its own line. This function only accepts the
    module's synthetic token shape; it does not accept or inspect real secrets.
    A disabled or absent canary leaves ``text`` unchanged.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if not enabled or canary is None:
        return text
    if not isinstance(canary, str) or not _TOKEN_RE.fullmatch(canary):
        raise ValueError("canary is not a syntactically valid Aegis token")
    if canary in text:
        return text
    separator = "" if not text or text.endswith(("\n", "\r")) else "\n"
    return f"{text}{separator}{canary}"


def remove_canary(text: str) -> str:
    """Remove all syntactically valid Aegis canary tokens from text.

    Surrounding text and whitespace are preserved. This is a syntactic
    remover, not an authenticity check; it requires no key and never logs data.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return _TOKEN_RE.sub("", text)


def _append_restricted_audit(path: AuditPath, line: bytes) -> None:
    """Append one minimal audit record with owner-only file permissions."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(os.fspath(path), flags, 0o600)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("audit destination must be a regular file")
        # Tighten permissions even when the file already existed.
        os.fchmod(fd, 0o600)
        written = os.write(fd, line)
        if written != len(line):
            raise OSError("incomplete audit record write")
    finally:
        os.close(fd)
