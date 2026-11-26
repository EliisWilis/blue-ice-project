"""Optional MCP stdio server exposing narrowly scoped, read-only project tools."""

from __future__ import annotations

import fnmatch
import json
import os
import stat
from pathlib import PurePosixPath
from typing import Any

from aegis.audit import append_event
from aegis.config import Settings
from aegis.egress.egress_firewall import inspect_output
from aegis.ingress.secret_redactor import SessionVault, redact_text
from aegis.llm_guard_adapter import (
    ScannerUnavailable,
    ScanRejected,
    build_default_scanners,
    scan_input,
)


class ProjectAccessBlocked(RuntimeError):
    """A project capability request failed a local path or content policy."""


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if not isinstance(relative_path, str) or len(relative_path) > 2_048:
        raise ProjectAccessBlocked("Invalid project-relative path")
    if "\\" in relative_path or "\x00" in relative_path:
        raise ProjectAccessBlocked("Invalid project-relative path")
    path = PurePosixPath(relative_path or ".")
    if path.is_absolute() or any(part in {"..", ""} for part in path.parts):
        raise ProjectAccessBlocked("Path is outside the configured project root")
    parts = tuple(part for part in path.parts if part != ".")
    if any(part == ".git" for part in parts) or ".privacyignore" in parts:
        raise ProjectAccessBlocked("Project policy files are not exposed as tools")
    return parts


def _open_project_path(settings: Settings, relative_path: str, *, directory: bool = False) -> int:
    """Open a project path one component at a time without following symlinks."""
    parts = _relative_parts(relative_path)
    root_fd = os.open(
        settings.project_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    current_fd = root_fd
    try:
        if not parts:
            if not directory:
                raise ProjectAccessBlocked("A project directory is not a readable file")
            return os.dup(root_fd)
        for index, part in enumerate(parts):
            is_final = index == len(parts) - 1
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            if not is_final or directory:
                flags |= getattr(os, "O_DIRECTORY", 0)
            next_fd = os.open(part, flags, dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        result_fd = current_fd
        current_fd = -1
        info = os.fstat(result_fd)
        if directory and not stat.S_ISDIR(info.st_mode):
            os.close(result_fd)
            raise ProjectAccessBlocked("Requested path is not a project directory")
        if not directory and not stat.S_ISREG(info.st_mode):
            os.close(result_fd)
            raise ProjectAccessBlocked("Requested path is not a regular project file")
        return result_fd
    except ProjectAccessBlocked:
        raise
    except (OSError, ValueError):
        raise ProjectAccessBlocked(
            "Path is missing, unsafe, or outside the configured project root"
        ) from None
    finally:
        if current_fd >= 0 and current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)


def _ignored(settings: Settings, relative_path: str) -> bool:
    normalized = relative_path.strip("/")
    if not normalized or normalized == ".privacyignore":
        return normalized == ".privacyignore"
    parts = PurePosixPath(normalized).parts
    if ".git" in parts or ".privacyignore" in parts:
        return True
    return any(
        fnmatch.fnmatchcase(normalized, pattern)
        or PurePosixPath(normalized).match(pattern)
        or (pattern.startswith("**/") and fnmatch.fnmatchcase(normalized, pattern[3:]))
        for pattern in settings.privacyignore_rules
    )


def _audit(settings: Settings, *, outcome: str, count: int = 0, rule: str | None = None) -> None:
    append_event(
        settings.audit_path,
        event="mcp_tool_request"
        if outcome == "allowed"
        else ("mcp_tool_blocked" if outcome == "blocked" else "mcp_tool_error"),
        outcome=outcome,
        provider=settings.provider,
        counts={"secrets_redacted": count},
        rules=[rule] if rule else [],
    )


def _prepare_text(
    text: str,
    settings: Settings,
    input_scanners: list[Any],
) -> tuple[str, int]:
    vault = SessionVault(ttl_seconds=30.0)
    try:
        safe, redacted_count = redact_text(text, vault)
        if settings.llm_guard_enabled:
            safe, scanned_count = scan_input(safe, input_scanners)
            redacted_count += scanned_count
        findings = inspect_output(safe, allowed_domains=settings.allowed_domains)
        if findings:
            raise ProjectAccessBlocked("Project content was blocked by egress policy")
        return safe, redacted_count
    except (ScannerUnavailable, ProjectAccessBlocked):
        raise
    finally:
        vault.clear()


def build_mcp_server(settings: Settings) -> Any:
    """Build an MCP v2 server. Imports the optional SDK only when explicitly used."""
    if not settings.mcp_enabled:
        raise RuntimeError("MCP project tools are disabled by local policy")
    try:
        from mcp.server import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError as exc:
        raise RuntimeError(
            "MCP support requires the optional dependency group: pip install 'blue-ice-project[mcp]'"
        ) from exc

    input_scanners: list[Any] = []
    if settings.llm_guard_enabled:
        input_scanners, _ = build_default_scanners()

    server = MCPServer("Blue Ice Project")
    read_only = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )

    @server.tool(annotations=read_only)
    def list_project_files(
        relative_path: str = ".",
        max_entries: int = 200,
    ) -> str:
        """List non-private entries in a project directory; does not follow symlinks."""
        try:
            if type(max_entries) is not int or not 1 <= max_entries <= 500:
                raise ProjectAccessBlocked("Requested listing size is outside the tool policy")
            if _ignored(settings, relative_path):
                raise ProjectAccessBlocked("Directory is excluded by local privacy policy")
            directory_fd = _open_project_path(settings, relative_path, directory=True)
            try:
                entries = os.listdir(directory_fd)
                base = PurePosixPath(relative_path or ".")
                safe_rows: list[dict[str, str]] = []
                for name in sorted(entries):
                    relative = name if str(base) == "." else f"{base.as_posix()}/{name}"
                    if _ignored(settings, relative):
                        continue
                    try:
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISLNK(info.st_mode) or not (
                        stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
                    ):
                        continue
                    safe_rows.append(
                        {
                            "path": relative,
                            "type": "directory" if stat.S_ISDIR(info.st_mode) else "file",
                        }
                    )
                    if len(safe_rows) >= max_entries:
                        break
            finally:
                os.close(directory_fd)
            output = json.dumps(
                {"entries": safe_rows, "truncated": len(safe_rows) >= max_entries},
                ensure_ascii=False,
            )
            safe_output, count = _prepare_text(output, settings, input_scanners)
            _audit(settings, outcome="allowed", count=count)
            return safe_output
        except ProjectAccessBlocked:
            _audit(settings, outcome="blocked", rule="project_path_policy")
            raise RuntimeError("Project path is outside the read-only tool policy") from None
        except (ScannerUnavailable, ScanRejected):
            _audit(settings, outcome="blocked", rule="scanner_unavailable")
            raise RuntimeError(
                "Configured scanner rejected or could not inspect project listing"
            ) from None
        except OSError:
            _audit(settings, outcome="error", rule="filesystem_error")
            raise RuntimeError("Project directory could not be read safely") from None

    @server.tool(annotations=read_only)
    def read_project_file(
        relative_path: str,
        max_bytes: int = 65_536,
    ) -> str:
        """Read a UTF-8 project file within the configured root, after policy filtering."""
        try:
            if type(max_bytes) is not int or not 1 <= max_bytes <= 1_000_000:
                raise ProjectAccessBlocked("Requested read size is outside the tool policy")
            if _ignored(settings, relative_path):
                raise ProjectAccessBlocked("File is excluded by local privacy policy")
            file_fd = _open_project_path(settings, relative_path)
            try:
                info = os.fstat(file_fd)
                if info.st_size > max_bytes:
                    raise ProjectAccessBlocked("File exceeds the requested read limit")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(file_fd, min(16_384, max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        raise ProjectAccessBlocked("File exceeds the requested read limit")
            finally:
                os.close(file_fd)
            try:
                text = b"".join(chunks).decode("utf-8")
            except UnicodeDecodeError:
                raise ProjectAccessBlocked("Only UTF-8 text files can be read") from None
            safe_text, count = _prepare_text(text, settings, input_scanners)
            _audit(settings, outcome="allowed", count=count)
            return safe_text
        except ProjectAccessBlocked:
            _audit(settings, outcome="blocked", rule="project_content_policy")
            raise RuntimeError("Project file is blocked by the read-only privacy policy") from None
        except ScannerUnavailable:
            _audit(settings, outcome="blocked", rule="scanner_unavailable")
            raise RuntimeError(
                "Configured scanner is unavailable; project content withheld"
            ) from None
        except ScanRejected:
            _audit(settings, outcome="blocked", rule="scanner_rejected")
            raise RuntimeError(
                "Configured scanner rejected project content; output withheld"
            ) from None
        except OSError:
            _audit(settings, outcome="error", rule="filesystem_error")
            raise RuntimeError("Project file could not be read safely") from None

    @server.tool(annotations=read_only)
    def get_project_policy() -> str:
        """Return non-secret policy metadata for the configured project context."""
        summary = {
            "project_name": settings.project_root.name,
            "read_only": True,
            "privacy_rules_loaded": len(settings.privacyignore_rules),
            "allowed_domain_count": len(settings.allowed_domains),
            "llm_guard_enabled": settings.llm_guard_enabled,
            "filesystem_writes_enabled": False,
            "shell_execution_enabled": False,
        }
        _audit(settings, outcome="allowed")
        return json.dumps(summary, ensure_ascii=False)

    @server.resource("blueice://project/policy")
    def project_policy_resource() -> str:
        """Expose the same non-secret project policy summary as a read-only resource."""
        return get_project_policy()

    return server


def run_stdio(settings: Settings) -> None:
    """Run MCP over stdio. Stdout is reserved for MCP protocol frames by the SDK."""
    server = build_mcp_server(settings)
    server.run(transport="stdio")
