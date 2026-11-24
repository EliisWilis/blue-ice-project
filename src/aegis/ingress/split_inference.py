"""Fail-closed planner for explicitly approved split inference.

This module only describes message-index boundaries. It does not transmit, copy,
log, or otherwise process message payloads, and it does not contact providers.
A plan involving two providers means that two separate cloud parties would
receive different portions of the conversation if a caller later executes it;
that arrangement is not automatically zero-knowledge or private computation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_ALLOWED_ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
_MAX_PROVIDER_ID_LENGTH = 64


def _disabled(reason: str) -> dict[str, Any]:
    """Return a uniform disabled result without including caller data."""
    return {
        "enabled": False,
        "reason": reason,
        "plan": None,
        "notice": (
            "Split inference is disabled. No payload was included and no network request was made."
        ),
    }


def _provider_id_is_safe(value: object) -> bool:
    """Accept only short, opaque provider identifiers, never credentials."""
    if not isinstance(value, str) or not value or len(value) > _MAX_PROVIDER_ID_LENGTH:
        return False
    if value != value.strip():
        return False
    first = value[0]
    if not first.isascii() or not first.isalnum():
        return False
    return all(char.isascii() and (char.isalnum() or char in "._:-") for char in value)


def build_split_plan(
    messages: Sequence[Mapping[str, Any]],
    strict_isolation: bool = False,
    approved_providers: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a payload-free split plan, disabled unless explicitly approved.

    The planner requires exactly two distinct, safe provider identifiers and
    at least two valid chat messages. It partitions message indices into two
    contiguous, non-empty ranges, preserving their order. Message contents are
    never copied into the returned result. The function is synchronous but
    performs only bounded in-memory validation and never performs I/O.

    Args:
        messages: OpenAI-compatible chat messages. Only each mapping's role is
            inspected; content and other fields are never read.
        strict_isolation: When true, prohibit any plan that would assign data
            to cloud providers, regardless of provider approvals.
        approved_providers: Explicit approval for exactly two provider IDs.

    Returns:
        A dictionary with ``enabled``, ``reason``, ``plan``, and ``notice``.
        Disabled results contain no provider IDs or message data.
    """
    if type(strict_isolation) is not bool:
        return _disabled("invalid_strict_isolation_flag")
    if strict_isolation:
        return _disabled("strict_isolation_enabled")

    if isinstance(approved_providers, (str, bytes)) or not isinstance(approved_providers, Sequence):
        return _disabled("invalid_provider_approvals")
    if len(approved_providers) != 2:
        return _disabled("exactly_two_providers_must_be_approved")

    provider_ids = tuple(approved_providers)
    if not all(_provider_id_is_safe(provider) for provider in provider_ids):
        return _disabled("invalid_provider_approval")
    if provider_ids[0].casefold() == provider_ids[1].casefold():
        return _disabled("two_distinct_providers_required")

    if isinstance(messages, (str, bytes)) or not isinstance(messages, Sequence):
        return _disabled("invalid_messages")
    message_count = len(messages)
    if message_count < 2:
        return _disabled("at_least_two_messages_required_for_split")

    # Inspect only role metadata. Do not access content or serialize messages.
    try:
        for message in messages:
            if not isinstance(message, Mapping):
                return _disabled("invalid_message_shape")
            role = message.get("role")
            if not isinstance(role, str) or role not in _ALLOWED_ROLES:
                return _disabled("invalid_message_role")
    except Exception:
        # Custom Sequence/Mapping implementations can fail during inspection;
        # fail closed without exposing exception details or message data.
        return _disabled("message_validation_failed")

    split_at = message_count // 2
    first_indices = list(range(0, split_at))
    second_indices = list(range(split_at, message_count))
    return {
        "enabled": True,
        "reason": None,
        "plan": {
            "strategy": "contiguous_message_boundary",
            "providers": [
                {
                    "provider": provider_ids[0],
                    "message_indices": first_indices,
                },
                {
                    "provider": provider_ids[1],
                    "message_indices": second_indices,
                },
            ],
            "message_count": message_count,
            "payload_included": False,
            "network_requests": False,
        },
        "notice": (
            "Executing this plan would send separate conversation portions to "
            "two distinct cloud providers. Two-provider splitting is not "
            "automatically zero-knowledge and does not itself provide a "
            "privacy guarantee."
        ),
    }
