"""Workflow phase state machine for the kernelCTF research platform.

The platform runs a strict Online-setup -> Offline-research progression:

    UNINITIALIZED
        -> ONLINE_DOCUMENTATION
        -> ONLINE_PROVISIONING
        -> ENVIRONMENT_VERIFICATION
        -> READY_FOR_OFFLINE
        -> OFFLINE_RESEARCH
        -> LOCAL_REPORTING

Key safety property: once in OFFLINE_RESEARCH (or later), the machine never
transitions back to an online phase on its own. Re-entering an online phase
requires an *explicit* user action (`reset_online()`), never an automatic
fallback triggered by an error. The phase is persisted to `.system-agent-phase`
in the workspace root as JSON so the workflow is resumable across invocations.

This module performs no network, no inference, and no privileged operation; it
only records and guards phase transitions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# Ordered phases. The index defines the forward progression.
PHASES: tuple[str, ...] = (
    "UNINITIALIZED",
    "ONLINE_DOCUMENTATION",
    "ONLINE_PROVISIONING",
    "ENVIRONMENT_VERIFICATION",
    "READY_FOR_OFFLINE",
    "OFFLINE_RESEARCH",
    "LOCAL_REPORTING",
)

# Phases that use the Online (OpenAI) provider for setup work.
ONLINE_PHASES = frozenset({"ONLINE_DOCUMENTATION", "ONLINE_PROVISIONING", "ENVIRONMENT_VERIFICATION"})
# Phases that use the Offline (Ollama) provider only.
OFFLINE_PHASES = frozenset({"OFFLINE_RESEARCH", "LOCAL_REPORTING"})

# Allowed forward transitions. A phase may advance to the next phase, and a few
# convenience self/neighbour moves are allowed, but nothing in OFFLINE_PHASES
# may transition to an ONLINE_PHASE except through reset_online().
_INDEX = {name: i for i, name in enumerate(PHASES)}


class PhaseError(RuntimeError):
    """Raised when a requested phase transition is not permitted."""


@dataclass
class PhaseState:
    phase: str = "UNINITIALIZED"
    updated_at: str = ""
    history: list[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.phase not in _INDEX:
            raise PhaseError(f"Unknown phase: {self.phase}")
        if self.history is None:
            self.history = []


class StateMachine:
    """Persisted phase controller. One file per workspace root."""

    FILENAME = ".system-agent-phase"

    def __init__(self, root: Path):
        self.path = Path(root).resolve() / self.FILENAME

    def load(self) -> PhaseState:
        if not self.path.exists():
            return PhaseState(phase="UNINITIALIZED")
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return PhaseState(phase="UNINITIALIZED")
        phase = raw.get("phase", "UNINITIALIZED")
        if phase not in _INDEX:
            phase = "UNINITIALIZED"
        return PhaseState(phase=phase, updated_at=raw.get("updated_at", ""), history=list(raw.get("history", [])))

    def _write(self, state: PhaseState) -> None:
        state.updated_at = datetime.now(timezone.utc).isoformat()
        self.path.write_text(json.dumps({"phase": state.phase, "updated_at": state.updated_at, "history": state.history[-50:]}, indent=2) + "\n")

    @staticmethod
    def is_online_phase(phase: str) -> bool:
        return phase in ONLINE_PHASES

    @staticmethod
    def is_offline_phase(phase: str) -> bool:
        return phase in OFFLINE_PHASES

    def can_advance(self, current: str, target: str) -> tuple[bool, str]:
        """Return (allowed, reason). Pure check; no side effects."""
        if target not in _INDEX:
            return False, f"Unknown phase: {target}"
        if current == target:
            return True, "no-op"
        # The one-way rule: never auto-move from an offline phase to an online phase.
        if current in OFFLINE_PHASES and target in ONLINE_PHASES:
            return False, (
                "Offline research never returns to an online phase automatically. "
                "Run an explicit online reset to re-enter setup."
            )
        # Forward progression is allowed (setup steps may advance several phases at
        # once). Movement among offline phases is allowed. The one invariant above is
        # the only hard block: offline never auto-returns to online.
        ci, ti = _INDEX[current], _INDEX[target]
        if ti > ci:
            return True, "advance"
        if current in OFFLINE_PHASES and target in OFFLINE_PHASES:
            return True, "offline-move"
        return False, f"Backward transition not allowed: {current} -> {target}. Use an explicit online reset to re-enter setup."

    def advance(self, target: str, *, note: str = "") -> PhaseState:
        state = self.load()
        ok, reason = self.can_advance(state.phase, target)
        if not ok:
            raise PhaseError(reason)
        state.history.append({"from": state.phase, "to": target, "note": note, "at": datetime.now(timezone.utc).isoformat()})
        state.phase = target
        self._write(state)
        return state

    def reset_online(self, target: str = "ONLINE_DOCUMENTATION", *, note: str = "explicit user reset to online") -> PhaseState:
        """Explicit, user-initiated return to an online setup phase.

        This is the ONLY way to move from an offline phase back into online setup.
        It is never called as an automatic error-recovery fallback.
        """
        if target not in ONLINE_PHASES and target != "UNINITIALIZED":
            raise PhaseError(f"reset_online target must be an online phase, got {target}")
        state = self.load()
        state.history.append({"from": state.phase, "to": target, "note": note, "at": datetime.now(timezone.utc).isoformat()})
        state.phase = target
        self._write(state)
        return state
