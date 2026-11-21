"""External N20 pilot shutdown controller. No cloud backend or credentials.
Production must provide an independently supervised scheduler, exclusive
state storage and an exact-ID provider adapter with bounded API calls.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import json
import math
import os
import re
import tempfile


@dataclass(frozen=True)
class Binding:
    run_id: str
    resource_id: str
    bucket: str
    deadline: float
    armed_at: float
    stale_after: float
    retry_seconds: float = 15
    max_attempts: int = 5

    def __post_init__(self):
        if not re.fullmatch(r"[0-9a-f]{32}", self.run_id):
            raise ValueError("Invalid pilot run ID")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", self.resource_id):
            raise ValueError("An exact resource ID is required")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", self.bucket):
            raise ValueError("Invalid bucket")
        if not all(math.isfinite(t) for t in (self.deadline, self.armed_at, self.stale_after, self.retry_seconds)):
            raise ValueError("All timing values must be finite")
        if not (0 < self.deadline - self.armed_at <= 7200 and
                0 < self.stale_after <= 7200 and 1 <= self.retry_seconds <= 60 and
                type(self.max_attempts) is int and 1 <= self.max_attempts <= 10):
            raise ValueError("Pilot deadline, stale window and retries must be bounded")

    @property
    def key(self):
        return f"tcc/piloto/n20-{self.run_id}.zip"


@dataclass(frozen=True)
class Resource:
    resource_id: str
    owner_run_id: str
    phase: str  # adapter-confirmed active/stopping/stopped/terminated; never infer from 404


class StopBackend(Protocol):
    def inspect_exact(self, resource_id: str) -> Resource: ...
    def stop_exact(self, resource_id: str, *, expected_run_id: str) -> None:
        """Non-destructive, idempotent stop; atomically enforce ownership or prove ID is immutable."""
        ...


@dataclass
class State:
    binding: Binding
    last_seen: float
    attempts: int = 0
    retry_at: float = 0
    reason: str = ""
    verified_phase: str = ""
    diagnostics: str = ""

    @classmethod
    def load(cls, path: Path):
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
        return cls(binding=Binding(**value.pop("binding")), **value)

    def persist(self, path: Path, *, arm: bool = False):
        """Controller-owned file. Use an exclusive scheduler lock for serial ticks."""
        value = {**vars(self), "binding": vars(self.binding)}
        fd, name = tempfile.mkstemp(prefix=".watchdog-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(value, out, allow_nan=False)
                out.flush()
                os.fsync(out.fileno())
            if arm:
                os.link(name, path)  # fail atomically if this run was already armed
            else:
                os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)


def arm(path: Path, binding: Binding):
    """Persist the exact binding before the runner is allowed to start."""
    state = State(binding, last_seen=binding.armed_at)
    state.persist(path, arm=True)
    return state


def matches_receipt(binding: Binding, receipt: dict | None) -> bool:
    if not isinstance(receipt, dict):
        return False
    return (
        receipt.get("schema") == "tcc-n20-r2-receipt/v1"
        and receipt.get("status") == "verified"
        and receipt.get("run_id") == binding.run_id
        and receipt.get("bucket") == binding.bucket
        and receipt.get("key") == binding.key
        and all(type(receipt.get(k)) is int and receipt[k] == v
                for k, v in {"nodes": 20, "rounds": 5, "verified_own_generations": 100}.items())
        and isinstance(receipt.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", receipt["sha256"]) is not None
    )


def evaluate(binding: Binding, state: State, now: float, *,
             local: dict | None, receipt: dict | None, heartbeat: dict | None, cancel: bool):
    if not math.isfinite(now) or now < binding.armed_at:
        raise ValueError("Invalid controller clock")
    local = local if isinstance(local, dict) and local.get("run_id") == binding.run_id else {}
    heartbeat = heartbeat.get("heartbeat_at_epoch") if isinstance(heartbeat, dict) and heartbeat.get("run_id") == binding.run_id else None
    if type(heartbeat) in (int, float) and binding.armed_at <= heartbeat <= now:
        state.last_seen = max(state.last_seen, heartbeat)
    if state.reason:
        return state.reason
    if cancel:
        return "cancelled"
    if local.get("status") in ("failed", "cancelled", "interrupted"):
        return local["status"]
    if local.get("completed") is True and matches_receipt(binding, receipt):
        return "success_verified"
    if now >= binding.deadline:
        return "deadline"
    if local.get("completed") is not True and now >= state.last_seen + binding.stale_after:
        return "stale"
    return ""


def tick(path: Path, now: float, *, local=None, receipt=None, heartbeat=None, cancel=False,
         backend: StopBackend | None = None, apply=False):
    """One externally scheduled tick. No provider operation or file update unless apply=True."""
    state = State.load(path)
    b = state.binding
    reason = evaluate(b, state, now, local=local, receipt=receipt, heartbeat=heartbeat, cancel=cancel)
    if not apply:
        return {"status": "dry-run", "reason": reason, "resource_id": b.resource_id}
    if backend is None:
        raise ValueError("No verified provider adapter configured")
    if state.verified_phase:
        return {"status": state.verified_phase, "reason": state.reason}
    if not reason:
        state.persist(path)
        return {"status": "watching"}
    state.reason = reason
    state.persist(path)

    def observe():
        resource = backend.inspect_exact(b.resource_id)
        if (resource.resource_id != b.resource_id or resource.owner_run_id != b.run_id or
                resource.phase not in ("active", "stopping", "stopped", "terminated")):
            raise ValueError("Ownership or provider phase not verified")
        return resource.phase

    try:
        phase = observe()
    except Exception:
        state.diagnostics = "inspection_unverified"
        state.persist(path)
        return {"status": "unverified", "reason": reason, "alert": True}
    if phase not in ("stopped", "terminated") and now >= state.retry_at and state.attempts < b.max_attempts:
        state.attempts += 1
        state.retry_at = now + b.retry_seconds
        state.persist(path)  # survives controller death before or during request
        try:
            backend.stop_exact(b.resource_id, expected_run_id=b.run_id)
            phase = observe()
        except Exception:
            # No raw adapter exception: it could contain a URL or secret.
            phase = "unverified"
    if phase in ("stopped", "terminated"):
        state.verified_phase = phase
        state.diagnostics = ""
        state.persist(path)
        return {"status": phase, "reason": reason}
    state.diagnostics = "stop_not_confirmed"
    state.persist(path)
    return {"status": "unverified", "reason": reason,
            "alert": state.attempts >= b.max_attempts, "attempts": state.attempts}
