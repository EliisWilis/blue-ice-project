"""Bounded package-name extraction and public-registry slopsquat checks.

This module never installs packages, follows package-supplied URLs, or probes
arbitrary hosts. Only package names found in recognized pip/npm/yarn commands
are checked, against fixed PyPI/npm JSON API endpoints.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import shlex
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

__all__ = ["check_packages", "extract_packages"]

_MAX_TEXT: Final[int] = 16_384
_MAX_PACKAGES: Final[int] = 50
_TIMEOUT_SECONDS: Final[float] = 4.0
_CACHE_TTL_SECONDS: Final[int] = 6 * 60 * 60
_RECENT_DAYS: Final[int] = 30
_PYPI_URL: Final[str] = "https://pypi.org/pypi/"
_NPM_URL: Final[str] = "https://registry.npmjs.org/"
_SHELL_SEPARATORS: Final[frozenset[str]] = frozenset({";", "&&", "||", "|", "&", "\n"})
_PIP_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,213})$")
_NPM_PART_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9._~-]{0,213}$")


@dataclass(frozen=True, slots=True)
class _PackageRef:
    ecosystem: str
    name: str


def _normalize_name(ecosystem: str, value: str) -> str | None:
    """Validate and normalize a package name without accepting URLs or paths."""
    candidate = value.strip()
    if not candidate or len(candidate) > 214 or any(ch in candidate for ch in "\\/:?#"):
        return None
    if ecosystem == "pypi":
        if not _PIP_NAME_RE.fullmatch(candidate):
            return None
        return re.sub(r"[-_.]+", "-", candidate).lower()
    if ecosystem == "npm":
        candidate = candidate.lower()
        if candidate.startswith("@"):
            parts = candidate[1:].split("/")
            if len(parts) != 2 or not all(_NPM_PART_RE.fullmatch(part) for part in parts):
                return None
        elif not _NPM_PART_RE.fullmatch(candidate):
            return None
        return candidate
    if ecosystem == "cargo":
        if not _PIP_NAME_RE.fullmatch(candidate):
            return None
        return candidate.lower()
    if ecosystem == "go":
        # Go module paths aren't queried by this MVP, but extraction stays strict.
        if len(candidate) > 200 or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._~+-]*(?:/[A-Za-z0-9][A-Za-z0-9._~+-]*)*", candidate
        ):
            return None
        return candidate
    return None


def _without_version(ecosystem: str, token: str) -> str | None:
    """Take the package portion of a requirement-like token; reject sources."""
    token = token.strip().rstrip(",")
    if not token or token.startswith("-") or token in {".", ".."}:
        return None
    lowered = token.lower()
    if lowered.startswith(("http:", "https:", "git+", "git:", "file:", "ssh:", "svn+", "hg+")):
        return None
    if token.startswith(("/", "./", "../", "~", "\\")) or "://" in token:
        return None

    if ecosystem == "pypi":
        # Requirement specifiers / extras / environment markers are not names.
        token = token.split(";", 1)[0].strip()
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:\s*(?:===|==|~=|!=|<=|>=|<|>)|\s*$)",
            token,
        )
        return match.group(1) if match else None
    if ecosystem in {"npm", "cargo", "go"}:
        # Scoped npm names contain one slash, and an optional @version suffix.
        if ecosystem == "npm" and token.startswith("@"):
            scope_name = token.split("@", 2)
            base = scope_name[0] + "@" + scope_name[1] if len(scope_name) >= 2 else token
            if "/" not in base:
                return None
            return base
        return token.split("@", 1)[0]
    return None


def _segments(text: str) -> list[list[str]]:
    """Tokenize bounded shell-like text, separating commands without executing it."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|\n")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    result: list[list[str]] = []
    segment: list[str] = []
    try:
        for token in lexer:
            if token in _SHELL_SEPARATORS:
                if segment:
                    result.append(segment)
                    segment = []
            else:
                segment.append(token)
    except ValueError:
        # An unterminated quote makes the remainder untrustworthy.
        pass
    if segment:
        result.append(segment)
    return result


def _command_context(tokens: list[str]) -> tuple[str, int] | None:
    """Identify a small set of explicit package-manager command forms."""
    if not tokens:
        return None
    executable = os.path.basename(tokens[0]).lower()
    if executable in {"pip", "pip3"}:
        return ("pypi", 2) if len(tokens) > 1 and tokens[1] == "install" else None
    if executable in {"python", "python3", "python3.12"} and len(tokens) >= 4:
        if tokens[1:3] == ["-m", "pip"] and tokens[3] == "install":
            return "pypi", 4
        return None
    if executable == "npm" and len(tokens) > 1 and tokens[1] in {"install", "i", "add"}:
        return "npm", 2
    if executable == "yarn" and len(tokens) > 1 and tokens[1] in {"add", "global"}:
        index = 2
        if tokens[1] == "global" and len(tokens) > 2 and tokens[2] == "add":
            index = 3
        elif tokens[1] == "global":
            return None
        return "npm", index
    if executable == "cargo" and len(tokens) > 1 and tokens[1] == "add":
        return "cargo", 2
    if executable == "go" and len(tokens) > 1 and tokens[1] == "get":
        return "go", 2
    return None


def _extract_refs(text: str) -> list[_PackageRef]:
    if not isinstance(text, str) or not text:
        return []
    refs: list[_PackageRef] = []
    seen: set[tuple[str, str]] = set()
    for tokens in _segments(text[:_MAX_TEXT]):
        context = _command_context(tokens)
        if context is None:
            continue
        ecosystem, start = context
        index = start
        while index < len(tokens) and len(refs) < _MAX_PACKAGES:
            token = tokens[index]
            index += 1
            if token == "--":
                # Tokens after the option terminator are still validated as names.
                continue
            if token.startswith("-"):
                # Skip known options that consume a following argument.
                option = token.split("=", 1)[0]
                if (
                    option
                    in {
                        "-c",
                        "--constraint",
                        "-r",
                        "--requirement",
                        "-e",
                        "--editable",
                        "-i",
                        "--index-url",
                        "--extra-index-url",
                        "--trusted-host",
                        "--registry",
                        "--tag",
                        "--loglevel",
                        "--config-settings",
                    }
                    and "=" not in token
                    and index < len(tokens)
                ):
                    index += 1
                continue
            base = _without_version(ecosystem, token)
            if base is None:
                continue
            normalized = _normalize_name(ecosystem, base)
            if normalized is None:
                continue
            key = (ecosystem, normalized)
            if key not in seen:
                seen.add(key)
                refs.append(_PackageRef(*key))
    return refs[:_MAX_PACKAGES]


def extract_packages(text: str) -> list[dict[str, str]]:
    """Extract validated package names from recognized pip/npm/yarn/cargo/go commands.

    Input is treated only as text; no shell command is run. Results are deduplicated
    and bounded, and contain normalized ecosystem/name pairs. Cargo and Go names are
    exposed for caller use but are not probed by :func:`check_packages`.
    """
    return [{"ecosystem": ref.ecosystem, "name": ref.name} for ref in _extract_refs(text)]


def _cache_path(cache: Any) -> str | None:
    """Accept only a filesystem path for the optional SQLite cache."""
    if isinstance(cache, (str, os.PathLike)):
        path = os.fspath(cache)
        return path if path else None
    return None


def _cache_get(path: str, key: str, ttl: int) -> dict[str, Any] | None:
    now = int(datetime.now(UTC).timestamp())
    try:
        with sqlite3.connect(path, timeout=1.0) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS aegis_registry_cache (cache_key TEXT PRIMARY KEY, saved_at INTEGER NOT NULL, value TEXT NOT NULL)"
            )
            row = db.execute(
                "SELECT saved_at, value FROM aegis_registry_cache WHERE cache_key = ?", (key,)
            ).fetchone()
            if not row or now - int(row[0]) < 0 or now - int(row[0]) > ttl:
                return None
            value = json.loads(row[1])
            return value if isinstance(value, dict) else None
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return None


def _cache_put(path: str, key: str, value: dict[str, Any]) -> None:
    saved_at = int(datetime.now(UTC).timestamp())
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
        with sqlite3.connect(path, timeout=1.0) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS aegis_registry_cache (cache_key TEXT PRIMARY KEY, saved_at INTEGER NOT NULL, value TEXT NOT NULL)"
            )
            db.execute(
                "INSERT INTO aegis_registry_cache(cache_key, saved_at, value) VALUES(?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET saved_at=excluded.saved_at, value=excluded.value",
                (key, saved_at, encoded),
            )
    except (OSError, sqlite3.Error, TypeError, ValueError):
        # Cache failures must never prevent the safety check from completing.
        return


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _created_at(ecosystem: str, payload: Any) -> datetime | None:
    """Extract only authoritative package creation timestamps from registry JSON."""
    if not isinstance(payload, dict):
        return None
    if ecosystem == "npm":
        times = payload.get("time")
        return _parse_datetime(times.get("created")) if isinstance(times, dict) else None
    info = payload.get("info")
    if isinstance(info, dict):
        created = _parse_datetime(info.get("upload_time"))
        if created is not None:
            return created
    releases = payload.get("releases")
    if isinstance(releases, dict):
        earliest: datetime | None = None
        for release_files in releases.values():
            if not isinstance(release_files, list):
                continue
            for item in release_files:
                if isinstance(item, dict):
                    uploaded = _parse_datetime(item.get("upload_time_iso_8601")) or _parse_datetime(
                        item.get("upload_time")
                    )
                    if uploaded is not None and (earliest is None or uploaded < earliest):
                        earliest = uploaded
        return earliest
    return None


def _json_response(response: Any) -> Any:
    method = getattr(response, "json", None)
    if not callable(method):
        return None
    return method()


async def _request_json(client: Any, url: str) -> tuple[int | None, Any]:
    """Fetch one fixed-registry JSON endpoint, with bounded timeout and no redirects."""
    if client is not None:
        try:
            response = await client.get(url, timeout=_TIMEOUT_SECONDS, follow_redirects=False)
            status = getattr(response, "status_code", getattr(response, "status", None))
            status = int(status) if status is not None else None
            if status != 200:
                return status, None
            payload = _json_response(response)
            if inspect.isawaitable(payload):
                payload = await payload
            return status, payload
        except Exception:
            return None, None

    def fetch() -> tuple[int | None, Any]:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "Aegis-slopsquat-guard/1.0"},
            method="GET",
        )

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
            ) -> None:
                return None

        try:
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
                status = int(response.status)
                if status != 200:
                    return status, None
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    return status, None
                return status, json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return int(exc.code), None
        except Exception:
            return None, None

    return await asyncio.to_thread(fetch)


def _registry_url(ref: _PackageRef) -> str | None:
    """Build a URL using a fixed origin and a strictly encoded validated name."""
    if ref.ecosystem == "pypi":
        return _PYPI_URL + urllib.parse.quote(ref.name, safe="") + "/json"
    if ref.ecosystem == "npm":
        return _NPM_URL + urllib.parse.quote(ref.name, safe="@")
    return None


async def _check_one(ref: _PackageRef, client: Any, path: str | None) -> dict[str, Any] | None:
    url = _registry_url(ref)
    if url is None:
        return None
    key = f"{ref.ecosystem}:{ref.name}"
    cached = await asyncio.to_thread(_cache_get, path, key, _CACHE_TTL_SECONDS) if path else None
    if cached is not None:
        status = cached.get("status")
        payload = cached.get("payload")
    else:
        status, payload = await _request_json(client, url)
        # Only verified 200/404 responses are cacheable; transport errors and
        # undecodable responses expire immediately rather than becoming findings.
        if path and (status == 404 or (status == 200 and isinstance(payload, dict))):
            await asyncio.to_thread(_cache_put, path, key, {"status": status, "payload": payload})

    if status == 404:
        return {"ecosystem": ref.ecosystem, "package": ref.name, "reason": "not_found"}
    if status != 200 or not isinstance(payload, dict):
        return {
            "ecosystem": ref.ecosystem,
            "package": ref.name,
            "reason": "verification_unavailable",
        }
    created = _created_at(ref.ecosystem, payload)
    if created is None:
        return {
            "ecosystem": ref.ecosystem,
            "package": ref.name,
            "reason": "verification_unavailable",
        }
    now = datetime.now(UTC)
    age_seconds = (now - created).total_seconds()
    if age_seconds < 0:
        return {
            "ecosystem": ref.ecosystem,
            "package": ref.name,
            "reason": "verification_unavailable",
        }
    if age_seconds >= _RECENT_DAYS * 24 * 60 * 60:
        return None
    return {
        "ecosystem": ref.ecosystem,
        "package": ref.name,
        "reason": "recently_created",
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "age_days": max(0, int(age_seconds // 86_400)),
    }


async def check_packages(text: str, client: Any = None, cache: Any = None) -> list[dict[str, Any]]:
    """Check extracted pip/npm/yarn package names against PyPI or npm asynchronously.

    Findings are emitted only for a verified registry 404 or an authoritative
    creation timestamp under 30 days old. Registry origins are hard-coded; the
    input is never interpreted as a URL, and package installation is never tried.
    ``client`` may be an async HTTP client exposing ``get``. ``cache`` may be a
    SQLite database path; responses are cached for six hours. Network, malformed
    API responses, and unexpected checker errors surface as ``verification_unavailable``
    findings so callers can apply an explicit fail-closed policy. No payload is logged.
    """
    refs = [ref for ref in _extract_refs(text) if ref.ecosystem in {"pypi", "npm"}]
    if not refs:
        return []
    path = _cache_path(cache)
    semaphore = asyncio.Semaphore(8)

    async def bounded_check(ref: _PackageRef) -> dict[str, Any] | None:
        async with semaphore:
            return await _check_one(ref, client, path)

    results = await asyncio.gather(*(bounded_check(ref) for ref in refs), return_exceptions=True)
    findings: list[dict[str, Any]] = []
    for ref, result in zip(refs, results, strict=True):
        if isinstance(result, dict):
            findings.append(result)
        elif isinstance(result, Exception):
            findings.append(
                {
                    "ecosystem": ref.ecosystem,
                    "package": ref.name,
                    "reason": "verification_unavailable",
                }
            )
    return findings
