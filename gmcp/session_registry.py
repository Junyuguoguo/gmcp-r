# -*- coding: utf-8 -*-
# gmcp/session_registry.py
#
# Per-session state isolation with configurable lock strategy.
# Supports "per_session_lock" (default) and "global_lock" modes.

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass
class SessionContext:
    """Holds all mutable state for one session under a single lock."""
    session_id: str
    state: Any               # GMCPState or equivalent
    verifier: Any            # GMCPVerifier or equivalent
    checkpoint_manager: Any = None
    stats: Dict[str, int] = field(default_factory=lambda: {"total": 0, "accepted": 0, "rejected": 0})
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionRegistry:
    """
    Manages creation and lookup of SessionContext objects.

    lock_strategy:
      - "per_session_lock": each session gets its own Lock (concurrent across sessions)
      - "global_lock": all sessions share one Lock (serialised)
    """

    VALID_STRATEGIES = ("per_session_lock", "global_lock")

    def __init__(
        self,
        factory: Callable[[str, int], SessionContext],
        lock_strategy: str = "per_session_lock",
    ):
        if lock_strategy not in self.VALID_STRATEGIES:
            raise ValueError(
                f"lock_strategy must be one of {self.VALID_STRATEGIES}, got {lock_strategy!r}"
            )
        self._factory = factory
        self.lock_strategy = lock_strategy
        self._contexts: Dict[str, SessionContext] = {}
        self._registry_lock = threading.Lock()
        self._global_lock = threading.Lock()

    def get_or_create(self, session_id: str, checkpoint_interval: int = 100) -> SessionContext:
        """
        Return the existing context for *session_id*, or create a new one.

        The registry lock is held only for the dict lookup / insert — the
        returned context's own lock protects session-level state mutations.
        """
        if checkpoint_interval < 10 or checkpoint_interval > 1000:
            raise ValueError(
                f"checkpoint_interval must be in [10, 1000], got {checkpoint_interval}"
            )

        with self._registry_lock:
            ctx = self._contexts.get(session_id)
            if ctx is None:
                ctx = self._factory(session_id, checkpoint_interval)
                ctx.lock = (
                    self._global_lock
                    if self.lock_strategy == "global_lock"
                    else threading.Lock()
                )
                self._contexts[session_id] = ctx
            return ctx

    def get_all(self) -> Dict[str, SessionContext]:
        """Return a snapshot of all registered contexts."""
        with self._registry_lock:
            return dict(self._contexts)
