"""Configuration loading with explicit credential and custom-provider boundaries.

Policy YAML may contain provider URLs but never API keys. Credentials are read
from an explicitly selected environment variable or the OS keyring.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

_ALLOWED_PROVIDERS = {"openai", "openrouter", "groq", "google", "cerebras", "ollama"}
_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")
_DEFAULT_PRIVACY_RULES = (
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
)


class ConfigurationError(ValueError):
    """A generic configuration error that does not contain secret values."""


@dataclass(frozen=True, slots=True)
class Settings:
    config_path: Path
    project_root: Path
    provider: str
    model: str
    allowed_domains: tuple[str, ...]
    privacyignore_rules: tuple[str, ...]
    max_request_bytes: int
    max_response_bytes: int
    audit_path: Path
    token_path: Path
    require_local_auth: bool
    key_source: str
    registry_checks: bool
    llm_guard_enabled: bool
    custom_provider_urls: tuple[tuple[str, str], ...]
    custom_models_urls: tuple[tuple[str, str], ...]
    custom_responses_urls: tuple[tuple[str, str], ...]
    native_anthropic_enabled: bool = False
    native_gemini_enabled: bool = False
    mcp_enabled: bool = False
    a2a_enabled: bool = False


def default_config(home: Path | None = None) -> dict[str, Any]:
    base = home or Path.home()
    return {
        "provider": "openrouter",
        "model": "openrouter/auto",
        "project_root": str(Path.cwd().resolve()),
        "allowed_domains": [],
        "max_request_bytes": 2_000_000,
        "max_response_bytes": 8_000_000,
        "require_local_auth": True,
        "key_source": "env",
        "registry_checks": False,
        "llm_guard_enabled": False,
        "native_anthropic_enabled": False,
        "native_gemini_enabled": False,
        "mcp_enabled": False,
        "a2a_enabled": False,
        "custom_providers": [],
        "audit_path": str(base / ".aegis" / "audit.jsonl"),
        "token_path": str(base / ".aegis" / "local-token"),
    }


def validate_custom_provider(name: str, url: str) -> tuple[str, str]:
    """Validate a configured custom OpenAI-compatible endpoint, never payload URLs."""
    if (
        not isinstance(name, str)
        or not _PROVIDER_NAME_RE.fullmatch(name)
        or name in _ALLOWED_PROVIDERS
    ):
        raise ConfigurationError("Custom provider name must be a unique lowercase identifier")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(ch) < 32 for ch in url):
        raise ConfigurationError("Custom provider URL is invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ConfigurationError("Custom provider URL is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or not parsed.path.endswith("/chat/completions")
        or hostname.lower() in {"localhost", "localhost.localdomain"}
        or hostname.lower().endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise ConfigurationError(
            "Custom provider URL must be a public HTTPS chat-completions endpoint without credentials, query, or fragment"
        )
    try:
        hostname.encode("idna")
    except UnicodeError:
        raise ConfigurationError("Custom provider host is invalid") from None
    return name, url


def validate_custom_responses_provider(name: str, url: str) -> tuple[str, str]:
    """Validate an explicitly configured native Responses API endpoint."""
    if (
        not isinstance(name, str)
        or not _PROVIDER_NAME_RE.fullmatch(name)
        or name in _ALLOWED_PROVIDERS
    ):
        raise ConfigurationError("Custom provider name must be a unique lowercase identifier")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(ch) < 32 for ch in url):
        raise ConfigurationError("Custom Responses URL is invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ConfigurationError("Custom Responses URL is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or not parsed.path.endswith("/responses")
        or hostname.lower() in {"localhost", "localhost.localdomain"}
        or hostname.lower().endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise ConfigurationError(
            "Custom Responses URL must be a public HTTPS /responses endpoint without credentials, query, or fragment"
        )
    try:
        hostname.encode("idna")
    except UnicodeError:
        raise ConfigurationError("Custom provider host is invalid") from None
    return name, url


def validate_custom_models_provider(name: str, url: str) -> tuple[str, str]:
    """Validate an explicitly configured OpenAI-compatible models-list endpoint."""
    if (
        not isinstance(name, str)
        or not _PROVIDER_NAME_RE.fullmatch(name)
        or name in _ALLOWED_PROVIDERS
    ):
        raise ConfigurationError("Custom provider name must be a unique lowercase identifier")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(ch) < 32 for ch in url):
        raise ConfigurationError("Custom models URL is invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ConfigurationError("Custom models URL is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or not parsed.path.endswith("/models")
        or hostname.lower() in {"localhost", "localhost.localdomain"}
        or hostname.lower().endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise ConfigurationError(
            "Custom models URL must be a public HTTPS /models endpoint without credentials, query, or fragment"
        )
    try:
        hostname.encode("idna")
    except UnicodeError:
        raise ConfigurationError("Custom provider host is invalid") from None
    return name, url


def _read_privacyignore(root: Path) -> tuple[str, ...]:
    path = root / ".privacyignore"
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
        if path.is_symlink() or not path.exists():
            return ()
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64_000:
            raise ConfigurationError(".privacyignore must be a regular file under 64 KB")
        content = path.read_text(encoding="utf-8")
    except ConfigurationError:
        raise
    except (OSError, UnicodeError, ValueError, RuntimeError):
        raise ConfigurationError("Could not safely read .privacyignore") from None
    return tuple(
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def load_settings(config_path: str | os.PathLike[str] | None = None) -> Settings:
    path = (
        Path(config_path or (Path.home() / ".aegis" / "config.yaml"))
        .expanduser()
        .resolve(strict=False)
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigurationError(
            "Blue Ice Project is not initialized; run `blue-ice init` first"
        ) from None
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ConfigurationError("Configuration could not be read as valid YAML") from None
    if not isinstance(raw, dict):
        raise ConfigurationError("Configuration must be a YAML object")

    allowed_keys = set(default_config().keys())
    if set(raw) - allowed_keys:
        raise ConfigurationError("Configuration contains unsupported fields")
    merged = {**default_config(), **raw}
    custom_raw = merged["custom_providers"]
    if not isinstance(custom_raw, list) or len(custom_raw) > 32:
        raise ConfigurationError("custom_providers must be a list of at most 32 endpoints")
    custom: dict[str, str] = {}
    custom_models: dict[str, str] = {}
    custom_responses: dict[str, str] = {}
    for entry in custom_raw:
        if (
            not isinstance(entry, dict)
            or not {"name", "url"}.issubset(entry)
            or set(entry) - {"name", "url", "models_url", "responses_url"}
        ):
            raise ConfigurationError(
                "Each custom provider must contain name and url, with optional models_url and responses_url"
            )
        name, url = validate_custom_provider(entry["name"], entry["url"])
        if name in custom:
            raise ConfigurationError("Custom provider names must be unique")
        custom[name] = url
        if "models_url" in entry:
            _, models_url = validate_custom_models_provider(name, entry["models_url"])
            custom_models[name] = models_url
        if "responses_url" in entry:
            _, responses_url = validate_custom_responses_provider(name, entry["responses_url"])
            custom_responses[name] = responses_url

    provider = merged["provider"]
    model = merged["model"]
    if not isinstance(provider, str) or (
        provider not in _ALLOWED_PROVIDERS and provider not in custom
    ):
        raise ConfigurationError(
            "Provider must be a built-in provider or a registered custom provider"
        )
    if (
        not isinstance(model, str)
        or not model.strip()
        or len(model) > 200
        or any(ord(ch) < 32 for ch in model)
    ):
        raise ConfigurationError("Model must be a non-empty, bounded string")
    if merged["key_source"] not in {"env", "keyring"}:
        raise ConfigurationError("key_source must be env or keyring")
    for key in (
        "require_local_auth",
        "registry_checks",
        "llm_guard_enabled",
        "native_anthropic_enabled",
        "native_gemini_enabled",
        "mcp_enabled",
        "a2a_enabled",
    ):
        if type(merged[key]) is not bool:
            raise ConfigurationError(f"{key} must be true or false")
    for key in ("max_request_bytes", "max_response_bytes"):
        if type(merged[key]) is not int or not 1024 <= merged[key] <= 64_000_000:
            raise ConfigurationError(f"{key} must be between 1024 and 64000000")

    root = Path(merged["project_root"]).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise ConfigurationError("project_root must be an existing directory")
    domains = merged["allowed_domains"]
    if not isinstance(domains, list) or any(
        not isinstance(item, str) or len(item) > 253 for item in domains
    ):
        raise ConfigurationError("allowed_domains must be a list of domain strings")
    rules = _read_privacyignore(root)
    return Settings(
        config_path=path,
        project_root=root,
        provider=provider,
        model=model.strip(),
        allowed_domains=tuple(domains),
        privacyignore_rules=(*_DEFAULT_PRIVACY_RULES, *rules),
        max_request_bytes=merged["max_request_bytes"],
        max_response_bytes=merged["max_response_bytes"],
        audit_path=Path(os.path.abspath(Path(merged["audit_path"]).expanduser())),
        token_path=Path(os.path.abspath(Path(merged["token_path"]).expanduser())),
        require_local_auth=merged["require_local_auth"],
        key_source=merged["key_source"],
        registry_checks=merged["registry_checks"],
        llm_guard_enabled=merged["llm_guard_enabled"],
        custom_provider_urls=tuple(custom.items()),
        custom_models_urls=tuple(custom_models.items()),
        custom_responses_urls=tuple(custom_responses.items()),
        native_anthropic_enabled=merged["native_anthropic_enabled"],
        native_gemini_enabled=merged["native_gemini_enabled"],
        mcp_enabled=merged["mcp_enabled"],
        a2a_enabled=merged["a2a_enabled"],
    )


def read_local_token(settings: Settings) -> str | None:
    """Read an owner-only token file; never return its contents in an error."""
    if not settings.require_local_auth:
        return None
    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(settings.token_path, flags)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > 512
        ):
            raise ConfigurationError(
                "Local auth token file must be a private regular file owned by this user"
            )
        with os.fdopen(fd, "r", encoding="ascii") as source:
            fd = None
            token = source.read(513).strip()
    except FileNotFoundError:
        raise ConfigurationError(
            "Local auth token file is missing; run `blue-ice init` again"
        ) from None
    except ConfigurationError:
        raise
    except (OSError, UnicodeError):
        raise ConfigurationError("Local auth token file could not be read safely") from None
    finally:
        if fd is not None:
            os.close(fd)
    if len(token) < 32 or len(token) > 512:
        raise ConfigurationError("Local auth token file has an invalid format")
    return token


def resolve_provider_key(settings: Settings, provider: str | None = None) -> str | None:
    """Resolve a key only from the explicitly selected environment/keyring source."""
    selected_provider = provider or settings.provider
    if selected_provider == "ollama":
        return None
    if settings.key_source == "env":
        specific = {
            "openai": "AEGIS_OPENAI_API_KEY",
            "openrouter": "AEGIS_OPENROUTER_API_KEY",
            "groq": "AEGIS_GROQ_API_KEY",
            "google": "AEGIS_GOOGLE_API_KEY",
            "anthropic": "AEGIS_ANTHROPIC_API_KEY",
            "cerebras": "AEGIS_CEREBRAS_API_KEY",
        }.get(
            selected_provider,
            f"AEGIS_CUSTOM_{selected_provider.upper().replace('-', '_')}_API_KEY",
        )
        value = os.environ.get(specific)
        return value.strip() if isinstance(value, str) and value.strip() else None
    try:
        import keyring

        value = keyring.get_password("aegis-llm-proxy", selected_provider)
        return value if isinstance(value, str) and value.strip() else None
    except Exception:
        return None
