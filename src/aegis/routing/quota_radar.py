"""Small in-memory availability helper for already-configured providers.

This module only records results supplied by the caller. It never probes a
provider, reads credentials, handles request payloads, or writes logs. An
unseen provider is considered unavailable until a successful status result has
been recorded. A later unsuccessful result makes it unavailable again.

The synchronous operations are deliberately short and bounded, so callers can
use them around async request routing without spawning background work.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

_MAX_TRACKED_PROVIDERS = 128
_MAX_PROVIDER_NAME_LENGTH = 256
_EWMA_ALPHA = 0.25


@dataclass(slots=True)
class _ProviderState:
    """Minimal state derived from caller-supplied status and latency values."""

    available: bool
    latency_ewma_ms: float
    updated_ns: int


_states: dict[str, _ProviderState] = {}
_lock = threading.Lock()


def _valid_provider(provider: object) -> bool:
    """Return whether a provider identifier is safe to retain in bounded state."""
    return (
        isinstance(provider, str) and bool(provider) and len(provider) <= _MAX_PROVIDER_NAME_LENGTH
    )


def record_result(provider: str, status_code: int, latency_ms: float) -> bool:
    """Record one caller-observed result for a configured provider.

    Only the provider identifier, whether the status was 2xx, and a smoothed
    latency value are retained. Invalid input is rejected without changing
    state. This function performs no I/O and emits no logs.

    Args:
        provider: Opaque configured provider identifier (not a credential).
        status_code: Caller-observed HTTP status code, from 100 through 599.
        latency_ms: Finite, non-negative caller-measured latency in milliseconds.

    Returns:
        ``True`` if the result was accepted; otherwise ``False``.
    """
    if not _valid_provider(provider):
        return False
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        return False
    if not 100 <= status_code <= 599:
        return False
    if isinstance(latency_ms, bool) or not isinstance(latency_ms, (int, float)):
        return False
    try:
        latency = float(latency_ms)
    except (OverflowError, ValueError):
        return False
    if not math.isfinite(latency) or latency < 0:
        return False

    now_ns = time.monotonic_ns()
    is_available = 200 <= status_code < 300
    with _lock:
        previous = _states.get(provider)
        if previous is None:
            # Keep retained state bounded; evict the least recently updated
            # entry. Evicted providers fail closed until observed again.
            if len(_states) >= _MAX_TRACKED_PROVIDERS:
                oldest = min(_states, key=lambda name: _states[name].updated_ns)
                del _states[oldest]
            smoothed_latency = latency
        else:
            smoothed_latency = (
                _EWMA_ALPHA * latency + (1.0 - _EWMA_ALPHA) * previous.latency_ewma_ms
            )
        _states[provider] = _ProviderState(
            available=is_available,
            latency_ewma_ms=smoothed_latency,
            updated_ns=now_ns,
        )
    return True


def choose_available(providers: Sequence[str]) -> str | None:
    """Choose the currently available supplied provider with lowest EWMA latency.

    Providers are considered only if they appear in the caller's configured
    sequence and have a retained latest 2xx result. Unknown, invalid, or
    previously failed providers are skipped. Ties preserve input order. Returns
    ``None`` when no listed provider is known to be available. No probing,
    retries, credential handling, or key rotation is performed.

    Args:
        providers: Finite sequence of configured provider identifiers.

    Returns:
        The selected identifier, or ``None`` to fail closed.
    """
    if isinstance(providers, (str, bytes)):
        return None

    with _lock:
        best_provider: str | None = None
        best_latency = math.inf
        seen: set[str] = set()
        for provider in providers:
            if not _valid_provider(provider) or provider in seen:
                continue
            seen.add(provider)
            state = _states.get(provider)
            if state is None or not state.available:
                continue
            if state.latency_ewma_ms < best_latency:
                best_provider = provider
                best_latency = state.latency_ewma_ms
        return best_provider
