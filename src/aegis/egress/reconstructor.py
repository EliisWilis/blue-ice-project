"""Reconstruct sanitized text using only session-resident mappings.

This module performs no file, network, logging, or provider operations. Callers
are responsible for supplying mappings scoped to the current session.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def _snapshot_mapping(value: Any, name: str) -> dict[str, str]:
    """Copy and validate a string-to-string mapping without exposing its values."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping or None")

    try:
        pairs = tuple(value.items())
    except Exception:
        # Do not propagate potentially value-bearing exception text.
        raise ValueError(f"{name} could not be read") from None

    result: dict[str, str] = {}
    for key, replacement in pairs:
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(replacement, str):
            raise ValueError(f"{name} values must be strings")
        result[key] = replacement
    return result


def _snapshot_canaries(value: Iterable[str]) -> tuple[str, ...]:
    """Validate and deduplicate exact canary strings."""
    if isinstance(value, (str, bytes)):
        raise TypeError("canaries must be an iterable of strings")
    try:
        items = tuple(value)
    except Exception:
        raise ValueError("canaries could not be read") from None

    unique: dict[str, None] = {}
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError("canaries must contain non-empty strings")
        unique[item] = None
    return tuple(unique)


def reconstruct(
    text: str,
    vault: Mapping[str, str] | None = None,
    identifier_map: Mapping[str, str] | None = None,
    canaries: Iterable[str] = (),
) -> tuple[str, dict[str, int]]:
    """Restore exact in-memory placeholders and remove registered canaries.

    ``vault`` maps exact secret placeholders to their session-resident values.
    ``identifier_map`` maps exact AST-masked identifiers to their originals.
    Only the supplied canary strings are removed; no pattern or broad regular
    expression is used. Replacement is a single pass, so restored values are
    never interpreted as additional placeholders or canaries.

    The returned audit contains occurrence counts only and never includes
    mapping keys, replacements, or input text. Conflicting vault and identifier
    entries are left unchanged. A canary matching a mapping key is removed.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    secrets = _snapshot_mapping(vault, "vault")
    identifiers = _snapshot_mapping(identifier_map, "identifier_map")
    exact_canaries = _snapshot_canaries(canaries)

    # Avoid guessing when two mapping sources disagree for the same token.
    conflicts = {
        token
        for token in secrets.keys() & identifiers.keys()
        if secrets[token] != identifiers[token]
    }
    replacements: dict[str, tuple[str, str]] = {}
    for token, replacement in secrets.items():
        if token not in conflicts:
            replacements[token] = ("vault", replacement)
    for token, replacement in identifiers.items():
        if token not in conflicts and token not in replacements:
            replacements[token] = ("identifier", replacement)

    # Trie performs literal exact matching in one pass and prefers the longest
    # registered token at a position, avoiding partial replacement of tokens.
    trie: dict[str, Any] = {}
    for token, (kind, replacement) in replacements.items():
        node = trie
        for char in token:
            node = node.setdefault(char, {})
        node[""] = (kind, replacement)
    for token in exact_canaries:
        node = trie
        for char in token:
            node = node.setdefault(char, {})
        node[""] = ("canary", "")

    counts = {"vault_restored": 0, "identifiers_restored": 0, "canaries_removed": 0}
    if not trie or not text:
        return text, counts

    output: list[str] = []
    position = 0
    text_length = len(text)
    while position < text_length:
        node = trie
        cursor = position
        best: tuple[int, str, str] | None = None

        while cursor < text_length:
            child = node.get(text[cursor])
            if child is None:
                break
            node = child
            cursor += 1
            terminal = node.get("")
            if terminal is not None:
                kind, replacement = terminal
                best = (cursor, kind, replacement)

        if best is None:
            output.append(text[position])
            position += 1
            continue

        end, kind, replacement = best
        if kind == "vault":
            counts["vault_restored"] += 1
            output.append(replacement)
        elif kind == "identifier":
            counts["identifiers_restored"] += 1
            output.append(replacement)
        else:
            counts["canaries_removed"] += 1
        position = end

    return "".join(output), counts
