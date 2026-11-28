"""Plain-text control interface for Blue Ice Project."""

from __future__ import annotations

import getpass
import ipaddress
import os
import secrets
import sys
import tempfile
from pathlib import Path

import typer
import yaml

from aegis.audit import read_events
from aegis.config import (
    ConfigurationError,
    default_config,
    load_settings,
    validate_custom_models_provider,
    validate_custom_provider,
    validate_custom_responses_provider,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Blue Ice Project local OpenAI-compatible privacy proxy",
)
provider_app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="Manage explicitly configured AI providers"
)
app.add_typer(provider_app, name="provider")


def _read_writable_config(path: Path) -> dict[str, object]:
    target = path.expanduser()
    if target.is_symlink():
        raise ConfigurationError("Refusing to modify a symlinked configuration file")
    try:
        value = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ConfigurationError("Configuration could not be read") from None
    if not isinstance(value, dict):
        raise ConfigurationError("Configuration must be a YAML object")
    return value


def _write_private_config(path: Path, value: dict[str, object]) -> None:
    target = path.expanduser()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    if target.is_symlink():
        raise ConfigurationError("Refusing to modify a symlinked configuration file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            yaml.safe_dump(value, output, sort_keys=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


@app.command("init")
def init_command(
    project_root: Path = typer.Option(
        Path.cwd(), "--project-root", help="Project directory to protect"
    ),
    provider: str = typer.Option(
        "openrouter",
        "--provider",
        help="Provider: openai, openrouter, groq, google, cerebras, or ollama",
    ),
    force: bool = typer.Option(
        False, "--force", help="Replace existing policy files; never replaces a key"
    ),
) -> None:
    """Create private local policy and token files."""
    allowed = {"openai", "openrouter", "groq", "google", "cerebras", "ollama"}
    root = project_root.expanduser().resolve(strict=False)
    if not root.is_dir():
        typer.echo("Project root must be an existing directory.", err=True)
        raise typer.Exit(2)
    if provider not in allowed:
        typer.echo("Provider must be one of the documented provider names.", err=True)
        raise typer.Exit(2)

    aegis_dir = Path.home() / ".aegis"
    aegis_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(aegis_dir, 0o700)
    config_path = aegis_dir / "config.yaml"
    token_path = aegis_dir / "local-token"
    if not force and config_path.exists():
        typer.echo(
            "Blue Ice Project configuration already exists. Use --force to replace policy settings."
        )
        raise typer.Exit(1)

    config = default_config()
    config["provider"] = provider
    config["model"] = (
        "llama3.2"
        if provider == "ollama"
        else ("openrouter/auto" if provider == "openrouter" else "default")
    )
    config["project_root"] = str(root)
    config["token_path"] = str(token_path)
    config["audit_path"] = str(aegis_dir / "audit.jsonl")
    _write_private_config(config_path, config)

    if not token_path.exists():
        token = secrets.token_urlsafe(48)
        descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(token + "\n")

    ignore_path = root / ".privacyignore"
    if ignore_path.is_symlink():
        typer.echo("Refusing to write .privacyignore through a symlink.", err=True)
        raise typer.Exit(2)
    if force or not ignore_path.exists():
        ignore_path.write_text(
            "# Aegis rejects references matching these patterns.\n"
            ".env\n.env.*\n**/.env\n**/.env.*\n*.pem\n**/*.pem\n*.key\n**/*.key\n"
            "id_rsa*\n**/id_rsa*\n*secret*\n**/*secret*\n*credential*\n**/*credential*\n*.p12\n**/*.p12\n*.pfx\n**/*.pfx\n",
            encoding="utf-8",
        )
        os.chmod(ignore_path, 0o600)

    typer.echo("Blue Ice Project policy initialized.")
    typer.echo(f"Configuration: {config_path}")
    typer.echo(f"Project root: {root}")
    typer.echo(
        "Local bearer token saved in an owner-only file; configure your agent CLI to read it from that file."
    )
    if provider != "ollama":
        typer.echo(
            f"Provider credential source: {config['key_source']}; set the provider-specific AEGIS_*_API_KEY environment variable."
        )
        if typer.confirm("Store a provider API key in the OS keyring instead?", default=False):
            try:
                import keyring
                from keyring.errors import NoKeyringError

                backend = keyring.get_keyring()
                if getattr(backend, "priority", 0) <= 0:
                    raise NoKeyringError("No secure keyring backend")
                username = provider
                value = getpass.getpass("Provider API key (input hidden): ")
                if value.strip():
                    keyring.set_password("aegis-llm-proxy", username, value.strip())
                    config["key_source"] = "keyring"
                    _write_private_config(config_path, config)
                    typer.echo("Provider key stored in the selected OS keyring.")
                else:
                    typer.echo("No key stored.")
            except Exception:
                typer.echo(
                    "Could not store a key in the OS keyring; no key was written to the config file.",
                    err=True,
                )
    typer.echo(
        "Review the config before starting. Blue Ice Project never rotates keys or silently fails over to cloud providers."
    )


@app.command("start")
def start_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Loopback interface only"),
    port: int = typer.Option(8080, min=1, max=65535, help="Listening port"),
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """Start the local API proxy."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        typer.echo("Host must be a loopback IP address; DNS names are not accepted.", err=True)
        raise typer.Exit(2)
    if not address.is_loopback:
        typer.echo("Blue Ice Project refuses non-loopback bind addresses.", err=True)
        raise typer.Exit(2)
    try:
        settings = load_settings(config)
        import uvicorn

        from aegis.app import create_app

        typer.echo(f"Blue Ice Project listening on http://{host}:{port}/v1")
        typer.echo(f"Provider: {settings.provider}; project root: {settings.project_root}")
        uvicorn.run(
            create_app(settings), host=host, port=port, access_log=False, log_level="warning"
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)


@app.command("mcp")
def mcp_command(
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """Serve the read-only MCP endpoint over STDIO for local coding agents."""
    try:
        settings = load_settings(config)
        import asyncio

        from aegis.mcp_server import serve_stdio

        asyncio.run(serve_stdio(settings))
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)


@app.command("audit")
def audit_command(
    limit: int = typer.Option(50, min=1, max=500, help="Number of recent metadata records"),
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """Show local threat and request metadata without prompts or secrets."""
    try:
        settings = load_settings(config)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)
    rows = read_events(settings.audit_path, limit=limit)
    if not rows:
        typer.echo("No audit events found.")
        return
    for row in rows:
        timestamp = str(row.get("timestamp", "unknown"))
        outcome = str(row.get("outcome", "unknown"))
        provider = str(row.get("provider", "unknown"))
        rules = row.get("rules", [])
        counts = row.get("counts", {})
        safe_rules = (
            ", ".join(item for item in rules if isinstance(item, str))
            if isinstance(rules, list)
            else ""
        )
        safe_counts = (
            ", ".join(
                f"{key}={value}"
                for key, value in counts.items()
                if isinstance(key, str) and isinstance(value, int)
            )
            if isinstance(counts, dict)
            else ""
        )
        fields = [timestamp, outcome, provider]
        if safe_rules:
            fields.append("rules: " + safe_rules)
        if safe_counts:
            fields.append("counts: " + safe_counts)
        typer.echo(" | ".join(fields))


@provider_app.command("add")
def provider_add(
    name: str = typer.Argument(..., help="Lowercase provider identifier"),
    url: str = typer.Option(
        ..., "--url", help="HTTPS OpenAI-compatible /chat/completions endpoint"
    ),
    models_url: str | None = typer.Option(
        None, "--models-url", help="Optional HTTPS OpenAI-compatible /models endpoint"
    ),
    responses_url: str | None = typer.Option(
        None, "--responses-url", help="Optional native HTTPS /responses endpoint"
    ),
    model: str = typer.Option("default", "--model", help="Default model name to show to clients"),
    keyring_store: bool = typer.Option(
        False, "--keyring", help="Prompt for an API key and store it in OS keyring"
    ),
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """Add an owner-configured endpoint; the key is never accepted as an argument."""
    path = config or Path.home() / ".aegis" / "config.yaml"
    try:
        entry_name, endpoint = validate_custom_provider(name, url)
        entry = {"name": entry_name, "url": endpoint}
        if models_url is not None:
            _, validated_models_url = validate_custom_models_provider(name, models_url)
            entry["models_url"] = validated_models_url
        if responses_url is not None:
            _, validated_responses_url = validate_custom_responses_provider(name, responses_url)
            entry["responses_url"] = validated_responses_url
        if (
            not isinstance(model, str)
            or not model.strip()
            or len(model) > 200
            or any(ord(ch) < 32 for ch in model)
        ):
            raise ConfigurationError("Model must be a non-empty, bounded string")
        values = _read_writable_config(path)
        custom = values.get("custom_providers", [])
        if not isinstance(custom, list):
            raise ConfigurationError("custom_providers must be a list")
        if any(isinstance(item, dict) and item.get("name") == entry_name for item in custom):
            raise ConfigurationError("A provider with that name already exists")
        custom.append(entry)
        values["custom_providers"] = custom
        values["provider"] = entry_name
        values["model"] = model.strip()
        if keyring_store:
            import keyring

            if getattr(keyring.get_keyring(), "priority", 0) <= 0:
                raise ConfigurationError("No secure OS keyring backend is available")
            secret = getpass.getpass("Provider API key (input hidden): ")
            if not secret.strip():
                raise ConfigurationError("No API key entered; provider was not added")
            keyring.set_password("aegis-llm-proxy", entry_name, secret.strip())
            values["key_source"] = "keyring"
        else:
            values["key_source"] = "env"
        _write_private_config(path, values)
    except (ConfigurationError, OSError, ImportError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)
    typer.echo(
        f"Provider {entry_name} added. Endpoint URL is stored in local policy; API key is not stored in YAML."
    )
    if not keyring_store:
        env_name = f"AEGIS_CUSTOM_{entry_name.upper().replace('-', '_')}_API_KEY"
        typer.echo(f"Set {env_name} in your shell environment before starting the proxy.")


@provider_app.command("use")
def provider_use(
    name: str = typer.Argument(..., help="Built-in or previously registered provider"),
    model: str | None = typer.Option(None, "--model", help="Model identifier"),
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """Select one provider explicitly; no failover or key rotation is performed."""
    path = config or Path.home() / ".aegis" / "config.yaml"
    try:
        values = _read_writable_config(path)
        settings = load_settings(path)
        builtins = {"openai", "openrouter", "groq", "google", "cerebras", "ollama"}
        registered = dict(settings.custom_provider_urls)
        if name not in builtins and name not in registered:
            raise ConfigurationError("Provider is not registered")
        values["provider"] = name
        if model is not None:
            if not model.strip() or len(model) > 200 or any(ord(ch) < 32 for ch in model):
                raise ConfigurationError("Model must be a non-empty, bounded string")
            values["model"] = model.strip()
        _write_private_config(path, values)
    except (ConfigurationError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)
    typer.echo(f"Selected provider: {name}. Blue Ice Project will use only this destination.")


@provider_app.command("list")
def provider_list(
    config: Path | None = typer.Option(None, "--config", help="Configuration YAML path"),
) -> None:
    """List built-in and locally registered providers without credential data."""
    try:
        settings = load_settings(config)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)
    for name in ("openai", "openrouter", "groq", "google", "cerebras", "ollama"):
        marker = " (selected)" if settings.provider == name else ""
        typer.echo(f"{name}{marker}")
    for name, endpoint in settings.custom_provider_urls:
        marker = " (selected)" if settings.provider == name else ""
        typer.echo(f"{name}{marker} | {endpoint}")


def main() -> None:
    args = sys.argv[1:]
    wants_help = not args or "--help" in args or "-h" in args
    if wants_help:
        command = next((arg for arg in args if not arg.startswith("-")), "")
        nested = args[args.index("provider") + 1 :] if "provider" in args else []
        if command == "provider" and nested:
            subcommand = next((arg for arg in nested if not arg.startswith("-")), "")
            usage = {
                "add": "Usage: blue-ice provider add NAME --url URL [--models-url URL] [--responses-url URL] [--model MODEL] [--keyring] [--config PATH]",
                "use": "Usage: blue-ice provider use NAME [--model MODEL] [--config PATH]",
                "list": "Usage: blue-ice provider list [--config PATH]",
            }.get(subcommand)
            if usage:
                typer.echo(usage)
                typer.echo("Provider API keys are never accepted as command-line arguments.")
                if subcommand == "add":
                    typer.echo(
                        "Use an OpenAI Chat Completions-compatible HTTPS endpoint; the /models URL is derived when omitted."
                    )
                return
        if command in {"init", "start", "mcp", "audit"}:
            usage = {
                "init": "Usage: blue-ice init [--project-root PATH] [--provider NAME] [--force]",
                "start": "Usage: blue-ice start [--host LOOPBACK_IP] [--port PORT] [--config PATH]",
                "mcp": "Usage: blue-ice mcp [--config PATH]",
                "audit": "Usage: blue-ice audit [--limit 1..500] [--config PATH]",
            }[command]
            typer.echo(usage)
            return
        typer.echo("Blue Ice Project local OpenAI-compatible privacy proxy")
        typer.echo("")
        typer.echo("Commands:")
        typer.echo("  init      Create private local policy and token files")
        typer.echo("  start     Start the local API proxy")
        typer.echo("  mcp       Serve read-only MCP tools over STDIO")
        typer.echo("  audit     Show metadata-only audit events")
        typer.echo("  provider  Manage explicitly configured AI providers")
        typer.echo("")
        typer.echo("Run blue-ice COMMAND --help for command usage.")
        return
    app()


if __name__ == "__main__":
    main()
