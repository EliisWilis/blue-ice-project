"""Owner-only JSONL audit containing metadata only, never prompts or secrets."""

from __future__ import annotations

import json
import os
import re
import stat
import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_MAX_AUDIT_LINE = 16_384
_MAX_AUDIT_FILE_BYTES = 20_000_000
_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")


def append_event(
    path: Path,
    *,
    event: str,
    outcome: str,
    provider: str,
    counts: dict[str, int] | None = None,
    rules: list[str] | None = None,
    latency_ms: int | None = None,
) -> None:
    """Append a bounded, allowlisted event record to an owner-only file."""
    safe_events = {
        "chat_request",
        "chat_blocked",
        "chat_error",
        "response_request",
        "response_blocked",
        "response_error",
    }
    safe_outcomes = {"allowed", "blocked", "error"}
    safe_providers = {"openrouter", "groq", "google", "cerebras", "ollama", "none"}
    if (
        event not in safe_events
        or outcome not in safe_outcomes
        or not isinstance(provider, str)
        or (provider not in safe_providers and not _PROVIDER_NAME.fullmatch(provider))
    ):
        raise ValueError("Invalid audit metadata")
    clean_counts = {}
    for key, value in (counts or {}).items():
        if (
            key
            in {
                "secrets_redacted",
                "identifiers_anonymized",
                "secrets_restored",
                "identifiers_restored",
                "canaries_removed",
            }
            and type(value) is int
            and 0 <= value <= 1_000_000
        ):
            clean_counts[key] = value
    clean_rules = [
        item
        for item in (rules or [])
        if isinstance(item, str) and item.isascii() and item.isprintable() and 0 < len(item) <= 80
    ][:32]
    if latency_ms is not None and (type(latency_ms) is not int or not 0 <= latency_ms <= 3_600_000):
        latency_ms = None
    record: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "event": event,
        "outcome": outcome,
        "provider": provider,
        "counts": clean_counts,
        "rules": clean_rules,
    }
    if latency_ms is not None:
        record["latency_ms"] = latency_ms
    encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if len(encoded) > _MAX_AUDIT_LINE:
        raise ValueError("Audit record exceeded its fixed size limit")

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    with _lock:
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("Audit destination must be an owner-owned regular file")
            if info.st_size + len(encoded) > _MAX_AUDIT_FILE_BYTES:
                raise OSError("Audit file reached its fixed size limit")
            os.fchmod(fd, 0o600)
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Incomplete audit record write")
                remaining = remaining[written:]
        finally:
            os.close(fd)


def read_events(path: Path, limit: int = 50) -> list[dict[str, Any]]:
    """Return the newest valid metadata records without echoing malformed data."""
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_AUDIT_FILE_BYTES
        ):
            os.close(fd)
            fd = None
            return []
        with os.fdopen(fd, "rb") as source:
            fd = None
            lines = deque(source, maxlen=limit)
    except (OSError, ValueError):
        return []
    finally:
        if fd is not None:
            os.close(fd)
    result: list[dict[str, Any]] = []
    for line in lines:
        if len(line) > _MAX_AUDIT_LINE:
            continue
        try:
            row = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(row, dict):
            continue
        event = row.get("event")
        if not isinstance(event, str) or event not in {
            "chat_request",
            "chat_blocked",
            "chat_error",
            "response_request",
            "response_blocked",
            "response_error",
        }:
            continue
        outcome = row.get("outcome")
        if not isinstance(outcome, str) or outcome not in {"allowed", "blocked", "error"}:
            continue
        provider = row.get("provider")
        if not isinstance(provider, str) or not _PROVIDER_NAME.fullmatch(provider):
            continue
        timestamp = row.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp.isascii() or len(timestamp) > 40:
            continue
        rules = row.get("rules", [])
        counts = row.get("counts", {})
        if not isinstance(rules, list) or not isinstance(counts, dict):
            continue
        clean_rules = [
            item
            for item in rules[:32]
            if isinstance(item, str) and item.isascii() and item.isprintable() and len(item) <= 80
        ]
        clean_counts = {
            key: value
            for key, value in counts.items()
            if key
            in {
                "secrets_redacted",
                "identifiers_anonymized",
                "secrets_restored",
                "identifiers_restored",
                "canaries_removed",
            }
            and type(value) is int
            and 0 <= value <= 1_000_000
        }
        clean_row: dict[str, Any] = {
            "timestamp": timestamp,
            "event": event,
            "outcome": outcome,
            "provider": provider,
            "rules": clean_rules,
            "counts": clean_counts,
        }
        latency = row.get("latency_ms")
        if type(latency) is int and 0 <= latency <= 3_600_000:
            clean_row["latency_ms"] = latency
        event_id = row.get("id")
        if isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{32}", event_id):
            clean_row["id"] = event_id
        result.append(clean_row)
    return result
