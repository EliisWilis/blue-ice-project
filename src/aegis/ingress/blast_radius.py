"""Conservative inspection of message text for filesystem path references.

This module never opens referenced paths or reads a ``.privacyignore`` file.
Callers that already have privacy-ignore rules in memory may pass them via
``privacyignore_path`` as an iterable of glob patterns.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote

__all__ = ["inspect_messages", "is_path_within_root"]

# Match only path-shaped tokens. In particular, don't scan arbitrary words or
# URLs as paths: absolute filesystem paths, explicit ./ or ../ paths, and
# slash-separated relative paths are the cases worth checking.
_PATH_TOKEN_RE = re.compile(
    r"(?<![\w:/])"
    r"(?:"
    r"(?P<unix>/[A-Za-z0-9._~+@%-]+(?:/[A-Za-z0-9._~+@%-]+)*)"
    r"|(?P<relative>(?:\.{1,2}/)[A-Za-z0-9._~+@%/-]+)"
    r"|(?P<relative_parts>[A-Za-z0-9._~+@%-]+(?:/[A-Za-z0-9._~+@%-]+)+)"
    r"|(?P<windows>(?:[A-Za-z]:[\\/]|\\\\)[A-Za-z0-9._~+@%\\/-]+)"
    r")"
    r"(?![\w/])"
)

# Safe baseline rules apply even when no caller-supplied privacy-ignore rules
# are available. They are intentionally specific to likely secret artifacts.
_DEFAULT_SENSITIVE_GLOBS = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*.pem",
    "**/*.pem",
    "*.key",
    "**/*.key",
    "id_rsa*",
    "**/id_rsa*",
    "*secret*",
    "**/*secret*",
    "*credential*",
    "**/*credential*",
    "*.p12",
    "**/*.p12",
    "*.pfx",
    "**/*.pfx",
    ".privacyignore",
    "**/.privacyignore",
    ".git-credentials*",
    "**/.git-credentials*",
)
_PROTECTED_SYSTEM_ROOTS = ("/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys")


def is_path_within_root(path: str | os.PathLike[str], project_root: str | os.PathLike[str]) -> bool:
    """Return whether ``path`` resolves inside ``project_root``.

    ``Path.resolve(strict=False)`` canonicalizes ``..`` and existing symlinks,
    so this also rejects traversal and symlink escapes. Any malformed path or
    resolution error fails closed. No file is opened or read.
    """
    try:
        root = Path(project_root).expanduser().resolve(strict=False)
        raw_candidate = Path(path).expanduser()
        candidate = (
            raw_candidate if raw_candidate.is_absolute() else root / raw_candidate
        ).resolve(strict=False)
        candidate.relative_to(root)
        return True
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def _message_strings(value: Any, seen: set[int] | None = None) -> Iterable[str]:
    """Yield string leaves from message structures without stringifying data."""
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (bytes, bytearray, memoryview)) or value is None:
        return
    if seen is None:
        seen = set()
    identity = id(value)
    if identity in seen:
        return
    if isinstance(value, Mapping):
        seen.add(identity)
        for child in value.values():
            yield from _message_strings(child, seen)
    elif isinstance(value, (list, tuple)):
        seen.add(identity)
        for child in value:
            yield from _message_strings(child, seen)


def _path_candidates(text: str) -> Iterable[str]:
    """Extract path-shaped substrings, trimming common sentence punctuation."""
    for match in _PATH_TOKEN_RE.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)]}>'\"`")
        if candidate and candidate not in {".", "..", "/"}:
            yield candidate


def _privacy_patterns(value: Any) -> tuple[list[str], str | None]:
    """Return in-memory glob rules and an optional protected ignore-file path.

    A path-like argument is treated as the location of the ignore file itself;
    its contents are deliberately never read. An iterable may provide rules
    already loaded by the caller, avoiding filesystem access here.
    """
    patterns = list(_DEFAULT_SENSITIVE_GLOBS)
    ignore_file: str | None = None
    if value is None:
        return patterns, ignore_file
    if isinstance(value, os.PathLike):
        try:
            ignore_file = str(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError, TypeError):
            # An invalid policy location is represented as unresolvable; callers
            # still get the baseline fail-closed checks.
            ignore_file = None
        return patterns, ignore_file
    if isinstance(value, str):
        try:
            ignore_file = str(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError, TypeError):
            ignore_file = None
        return patterns, ignore_file
    if isinstance(value, Iterable):
        for entry in value:
            if not isinstance(entry, str):
                continue
            rule = entry.strip().replace("\\", "/")
            if rule and not rule.startswith("#"):
                # Negations are not interpreted: treating them as exclusions
                # could accidentally permit a protected path.
                patterns.append(rule.lstrip("!"))
    return patterns, ignore_file


def _matches_sensitive(candidate: str, patterns: list[str], ignore_file: str | None) -> bool:
    """Match a candidate against supplied/default globs without leaking it."""
    try:
        canonical = str(Path(candidate).expanduser().resolve(strict=False))
        if ignore_file is not None and canonical == ignore_file:
            return True
        parts = {part.casefold() for part in Path(canonical).parts}
        if ".git" in parts:
            return True
        if any(
            canonical == protected or canonical.startswith(protected + os.sep)
            for protected in _PROTECTED_SYSTEM_ROOTS
        ):
            return True
        normalized = candidate.replace("\\", "/").lstrip("./")
        basename = normalized.rsplit("/", 1)[-1]
        for pattern in patterns:
            normalized_pattern = pattern.replace("\\", "/").lstrip("./")
            if fnmatch.fnmatchcase(normalized, normalized_pattern) or fnmatch.fnmatchcase(
                basename, normalized_pattern
            ):
                return True
    except (OSError, RuntimeError, ValueError, TypeError):
        # A sensitive-path evaluation error must not turn into an allow.
        return True
    return False


def _decoded_variants(candidate: str) -> Iterable[str]:
    """Yield the literal path and a small number of URL-decoded forms."""
    current = candidate
    yield current
    for _ in range(2):
        if "%" not in current:
            return
        try:
            decoded = unquote(current, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return
        if decoded == current:
            return
        current = decoded
        yield current


def inspect_messages(
    messages: Any,
    project_root: str | os.PathLike[str],
    privacyignore_path: str | os.PathLike[str] | Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Inspect OpenAI-style messages for out-of-root and sensitive paths.

    Findings contain only stable rule identifiers, severity, and message index;
    they never include the matched text, path, or any other payload content.
    This function performs no file reads and never opens a referenced path.
    """
    try:
        root = Path(project_root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError, TypeError):
        return [{"code": "invalid_project_root", "severity": "block", "message_index": None}]

    patterns, ignore_file = _privacy_patterns(privacyignore_path)
    try:
        message_items = list(messages) if not isinstance(messages, str) else [messages]
    except (TypeError, ValueError):
        return [{"code": "invalid_messages", "severity": "block", "message_index": None}]

    findings: list[dict[str, Any]] = []
    emitted: set[tuple[int, str]] = set()
    for message_index, message in enumerate(message_items):
        for text in _message_strings(message):
            for candidate in _path_candidates(text):
                code: str | None = None
                for variant in _decoded_variants(candidate):
                    # Windows absolute paths are not valid paths under the host's
                    # project root and are rejected rather than reinterpreted.
                    is_foreign_absolute = bool(re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", variant))
                    if is_foreign_absolute or not is_path_within_root(variant, root):
                        code = "path_outside_project_root"
                        break
                    if _matches_sensitive(variant, patterns, ignore_file):
                        code = "sensitive_path_reference"
                if code is not None and (message_index, code) not in emitted:
                    emitted.add((message_index, code))
                    findings.append(
                        {"code": code, "severity": "block", "message_index": message_index}
                    )
    return findings
