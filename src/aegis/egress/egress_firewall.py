"""Heuristic response inspection for dangerous shell commands and remote Markdown URLs.

This module never executes commands, fetches URLs, or logs response content. Its
regular expressions are defensive indicators, not a complete semantic firewall.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

__all__ = ["inspect_output"]

# Deliberately detect common, high-risk spellings. These patterns are heuristics;
# shell syntax, aliases, encoding, and command composition can evade them.
_COMMAND_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "rm_recursive_root",
        re.compile(
            r"\b(?:sudo\s+)?rm\s+"
            r"(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|"
            r"--recursive(?:\s+--force)?|--force\s+--recursive)\s+"
            r"(?:(?:--no-preserve-root|--preserve-root)\s+)?(?:--\s+)?"
            r"(?:['\"])?(?:/+(?:\*|(?=\s|$|['\";&|]))|"
            r"/root(?:/|(?=\s|$|['\";&|]))|"
            r"~/?(?=\s|$|['\";&|]))(?:['\"])?",
            re.IGNORECASE,
        ),
        "Possible recursive forced deletion of a root-level path.",
    ),
    (
        "curl_pipe_shell",
        re.compile(r"\bcurl\b[^\n;|]*\|\s*(?:/\S*/)?(?:sh|bash)\b", re.IGNORECASE),
        "Possible curl-to-shell pipeline.",
    ),
    (
        "wget_pipe_shell",
        re.compile(r"\bwget\b[^\n;|]*\|\s*(?:/\S*/)?(?:sh|bash)\b", re.IGNORECASE),
        "Possible wget-to-shell pipeline.",
    ),
    (
        "nc_exec",
        re.compile(r"\b(?:nc|netcat|ncat)\b[^\n;|]*\s-e(?:\s|$)", re.IGNORECASE),
        "Possible netcat command using the -e execution option.",
    ),
    (
        "chmod_world_writable",
        re.compile(r"\bchmod\b\s+(?:-[^\s]+\s+)*0?777(?:\s|$)", re.IGNORECASE),
        "Possible chmod command granting mode 777.",
    ),
)

# Match inline Markdown link/image openers; the destination is parsed below so
# nested parentheses and angle-bracket destinations can be handled safely.
_MARKDOWN_OPEN = re.compile(r"(!?)\[([^\]\n]*)\]\(")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _normalize_domain(value: object) -> str | None:
    """Return a canonical hostname, or None for an invalid allowlist entry."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None

    # Accept plain hostnames and origin-like allowlist entries, but never let
    # credentials or a path turn into an accidental broader allow rule.
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
            if parsed.username is not None or parsed.password is not None:
                return None
            host = parsed.hostname
            if not host or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                return None
            candidate = host
        except ValueError:
            return None
    else:
        candidate = candidate.removeprefix(".")
        if "/" in candidate or "@" in candidate or "?" in candidate or "#" in candidate:
            return None
        # A port is accepted only when it is unambiguous. IPv6 literals are
        # supported in bracket form.
        if candidate.startswith("[") and "]" in candidate:
            close = candidate.find("]")
            suffix = candidate[close + 1 :]
            if suffix and not re.fullmatch(r":\d{1,5}", suffix):
                return None
            candidate = candidate[1:close]
        elif candidate.count(":") == 1:
            possible_host, possible_port = candidate.rsplit(":", 1)
            if possible_port.isdigit():
                if int(possible_port) > 65535:
                    return None
                candidate = possible_host
            else:
                return None
        elif ":" in candidate:
            # Unbracketed IPv6 allowlist literal.
            pass

    candidate = candidate.rstrip(".").lower()
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        pass
    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_host


def _allowed(host: str, allowlist: set[str]) -> bool:
    """Check exact domains and their subdomains; IP addresses match exactly."""
    normalized = _normalize_domain(host)
    if normalized is None:
        return False
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return any(
            normalized == domain or normalized.endswith("." + domain) for domain in allowlist
        )
    return normalized in allowlist


def _read_markdown_destination(text: str, position: int) -> tuple[str | None, int]:
    """Read one inline Markdown destination starting immediately after ``(``."""
    length = len(text)
    cursor = position
    while cursor < length and text[cursor].isspace():
        cursor += 1
    if cursor >= length or text[cursor] == ")":
        return None, cursor

    if text[cursor] == "<":
        start = cursor + 1
        cursor = start
        escaped = False
        while cursor < length:
            char = text[cursor]
            if char == ">" and not escaped:
                return text[start:cursor], cursor + 1
            if char == "\\" and not escaped:
                escaped = True
            else:
                escaped = False
            if char == "\n":
                return None, cursor
            cursor += 1
        return None, cursor

    start = cursor
    depth = 0
    escaped = False
    while cursor < length:
        char = text[cursor]
        if escaped:
            escaped = False
            cursor += 1
            continue
        if char == "\\":
            escaped = True
            cursor += 1
            continue
        if char == "(" and depth == 0:
            depth = 1
        elif char == ")":
            if depth == 0:
                break
            depth = 0
        elif char.isspace() and depth == 0:
            break
        cursor += 1
    destination = text[start:cursor]
    # A title may follow the destination; it is intentionally not part of it.
    return destination or None, cursor


def _remote_host(destination: str) -> str | None:
    """Return host for an external URL, or None for a relative/local target.

    Malformed absolute HTTP(S) destinations return an empty string so they are
    denied rather than treated as relative paths.
    """
    target = unquote(destination.strip())
    if not target:
        return None
    try:
        parsed = urlsplit(target)
    except ValueError:
        return ""

    if parsed.scheme:
        if parsed.scheme.lower() in {"http", "https"}:
            return parsed.hostname or ""
        # Other absolute schemes with an authority are also remote resources.
        if parsed.netloc:
            return parsed.hostname or ""
        return None
    if target.startswith("//"):
        return parsed.hostname or ""
    return None


def _allowlist_domains(allowed_domains: Iterable[str] | str | None) -> set[str]:
    """Normalize allowlist values; invalid entries fail closed by being ignored."""
    if allowed_domains is None:
        return set()
    values: Iterable[object]
    if isinstance(allowed_domains, str):
        values = (allowed_domains,)
    else:
        try:
            values = iter(allowed_domains)
        except TypeError:
            return set()
    result: set[str] = set()
    try:
        for value in values:
            domain = _normalize_domain(value)
            if domain is not None:
                result.add(domain)
    except Exception:
        # A broken/custom iterable must not accidentally approve remote hosts.
        return set()
    return result


def inspect_output(text: str, allowed_domains: Iterable[str] = ()) -> list[dict[str, object]]:
    """Inspect response text for risky command snippets and disallowed URLs.

    Args:
        text: Untrusted model/provider output. It is inspected in memory only.
        allowed_domains: Hostnames (or origins) allowed for Markdown links and
            images. A hostname permits itself and its subdomains; IPs require an
            exact match. Invalid entries are ignored. The default is deny-all
            for external URLs.

    Returns:
        A list of findings with rule, category, severity, offsets, and a generic
        message. Matched payloads, URLs, and hostnames are never included.

    Raises:
        TypeError: If ``text`` is not a string.

    Note:
        Detection is intentionally heuristic and cannot guarantee semantic
        safety. This synchronous function performs local parsing only; it makes
        no network calls and executes no commands.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    findings: list[dict[str, object]] = []
    for rule, pattern, message in _COMMAND_RULES:
        for match in pattern.finditer(text):
            findings.append(
                {
                    "category": "command",
                    "rule": rule,
                    "severity": "high",
                    "start": match.start(),
                    "end": match.end(),
                    "message": message,
                }
            )

    allowlist = _allowlist_domains(allowed_domains)
    for opener in _MARKDOWN_OPEN.finditer(text):
        destination, _ = _read_markdown_destination(text, opener.end())
        if destination is None:
            continue
        host = _remote_host(destination)
        # An empty host marks a malformed absolute/protocol-relative URL and is
        # denied; relative and non-network schemes are not external URLs here.
        if host is not None and (not host or not _allowed(host, allowlist)):
            findings.append(
                {
                    "category": "url",
                    "rule": "markdown_remote_domain_denied",
                    "severity": "high",
                    "start": opener.start(),
                    "end": opener.end(),
                    "message": "Markdown link or image targets an unapproved remote domain.",
                }
            )

    findings.sort(key=lambda finding: (int(finding["start"]), str(finding["rule"])))
    return findings
