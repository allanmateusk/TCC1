"""Offline whole-batch protection; deliberately no live provider or storage API."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re

from .batch_sequence import _hex
from .incremental_same_host import IncrementalPlan, IncrementalSameHost
from .same_host_batch import HostPolicy, SameHostBatch
from .watchdog import Resource

SCHEMA = "tcc-n20-incremental-batch-protection-offline/v1"
PHASES = {"active", "stopping", "stopped", "terminated"}


@dataclass(frozen=True)
class BatchProtection:
    batch_id: str
    resource_id: str
    owner_id: str
    datacenter_id: str
    pod_name: str
    git_sha: str
    profile_sha256: str
    opened_at: int
    stop_at: int
    hard_deadline: int
    max_attempt_seconds: int
    stale_seconds: int
    hourly_compute_microusd: int
    fixed_and_other_microusd: int
    approved_cap_microusd: int

    def __post_init__(self):
        for value in (self.owner_id, self.resource_id, self.datacenter_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
                raise ValueError("Exact provider owner/resource/datacenter required")
        if not _hex(self.batch_id, 32) or self.pod_name != "tcc-n20-batch-" + self.batch_id:
            raise ValueError("Exact batch ID and dedicated resource name required")
        numeric = (self.opened_at, self.stop_at, self.hard_deadline, self.hourly_compute_microusd,
                   self.fixed_and_other_microusd, self.approved_cap_microusd)
        if any(type(value) is not int or not 0 <= value <= 10**12 for value in numeric):
            raise ValueError("Use finite nonnegative integers for timestamps and micro-USD")
        if not (self.opened_at > 0 and 4*3600 <= self.stop_at-self.opened_at
                and self.hard_deadline-self.opened_at <= 7*3600
                and 60 <= self.hard_deadline-self.stop_at <= 600):
            raise ValueError("Absolute 4–7 h protection and 60–600 s reconciliation reserve required")
        if not (self.hourly_compute_microusd > 0 and self.approved_cap_microusd > 0
                and self.cost_ceiling_microusd <= self.approved_cap_microusd):
            raise ValueError("Batch quote including shutdown reserve exceeds the approved cap")
        self.queue_plan()  # also validates the exact campaign/profile and full code SHA
        self.host_policy()
        if 5 * self.host_policy().retry_seconds >= self.hard_deadline-self.stop_at:
            raise ValueError("Stop retry schedule requires enough reconciliation reserve")

    @property
    def cost_ceiling_microusd(self):
        # Round upward once. Includes reconciliation window; extras are an explicit quote,
        # not a prediction of taxes, indefinite storage, or billing after cutoff failure.
        seconds = self.hard_deadline - self.opened_at
        return (seconds*self.hourly_compute_microusd + 3599)//3600 + self.fixed_and_other_microusd

    def queue_plan(self):
        return _ProtectedQueuePlan(self.batch_id, self.git_sha, self.profile_sha256, "tcc",
                                   self.opened_at, self.stop_at, self.max_attempt_seconds,
                                   self.digest)

    def host_policy(self):
        return HostPolicy(self.resource_id, self.stale_seconds, retry_seconds=10, max_attempts=5)

    @property
    def digest(self):
        payload = json.dumps({"schema": SCHEMA, **asdict(self)}, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class _ProtectedQueuePlan(IncrementalPlan):
    protection_sha256: str


@dataclass(frozen=True)
class FixtureObservation:
    resource_id: str
    owner_id: str
    datacenter_id: str
    pod_name: str
    batch_id: str
    phase: str

    def resource_for(self, p):
        actual = (self.resource_id, self.owner_id, self.datacenter_id, self.pod_name, self.batch_id)
        expected = (p.resource_id, p.owner_id, p.datacenter_id, p.pod_name, p.batch_id)
        if actual != expected or self.phase not in PHASES:
            raise ValueError("Independent fixture has no exact ownership/phase evidence")
        return Resource(self.resource_id, self.batch_id, self.phase)


class FixtureProvider:
    """Sealed test double: inspection and stop never use a real provider."""
    def __init__(self, observation):
        if type(observation) is not FixtureObservation:
            raise ValueError("Expected a fixture observation")
        self.observation = observation
        self.stop_requests = 0
        self.lose_response = False
        self.fail_inspect = False

    def inspect(self):
        if self.fail_inspect:
            raise OSError("fixture inspection unavailable")
        return self.observation

    def stop(self, binding):
        proof = self.inspect().resource_for(binding)
        if proof.phase != "active":
            raise ValueError("Fixture not actively running")
        self.stop_requests += 1
        self.observation = FixtureObservation(**{**asdict(self.observation), "phase": "stopped"})
        if self.lose_response:
            raise OSError("fixture accepted STOP before response was lost")


class _Observer:
    def __init__(self, binding, fixture, now):
        self.binding, self.fixture, self.now = binding, fixture, now

    def inspect_exact(self, resource_id):
        if resource_id != self.binding.resource_id:
            raise ValueError("Not the protected Pod")
        return self.fixture.inspect().resource_for(self.binding)

    def stop_exact(self, resource_id, *, expected_run_id):
        if (resource_id, expected_run_id) != (self.binding.resource_id, self.binding.batch_id):
            raise ValueError("Not the protected Pod/batch")
        if self.now >= self.binding.hard_deadline:
            raise ValueError("Offline protected stop dispatch window exhausted")
        if self.inspect_exact(resource_id).phase != "active":
            # An independently observed stop-in-progress is never re-dispatched.
            raise ValueError("No active fixture authorized for another STOP")
        self.fixture.stop(self.binding)


class ProtectedIncrementalBatch(IncrementalSameHost):
    """Not live admission. Caller must keep the plan pin/control DB off the worker."""
    def __init__(self, path, protection, *, approved_sha256):
        if (type(protection) is not BatchProtection or not _hex(approved_sha256, 64)
                or not hmac.compare_digest(approved_sha256, protection.digest)):
            raise ValueError("Missing or inconsistent independently pinned batch protection")
        self.protection = protection
        plan = protection.queue_plan()
        # Use the same sequencing/storage spine, with a dedicated serialized plan pin.
        SameHostBatch.__init__(self, path, plan, protection.host_policy())

    def _fixture_resource(self, trusted):
        if type(trusted) is not FixtureObservation:
            raise ValueError("Independent exact fixture observation required")
        try:
            return trusted.resource_for(self.protection)
        except ValueError:
            # Existing transaction durably latches mismatch without accepting ownership.
            return Resource("", "", "unverified")

    def arm(self, trusted, *, now):
        if type(now) is not int or not self.protection.opened_at <= now < min(
                self.protection.stop_at, self.protection.opened_at+self.policy.stale_seconds):
            raise ValueError("Arm fresh, before the absolute cutoff")
        return super().arm(self._fixture_resource(trusted))

    def reserve(self, now, run_id, *, trusted):
        return super().reserve(now, run_id, trusted=self._fixture_resource(trusted))

    def beat(self, now, when, *, trusted):
        return super().beat(now, when, trusted=self._fixture_resource(trusted))

    def require_active_case(self, now, run_id, *, trusted):
        return super().require_active_case(now, run_id, trusted=self._fixture_resource(trusted))

    def finish(self, now, run_id, *, trusted_receipt, trusted):
        return super().finish(now, run_id, trusted_receipt=trusted_receipt,
                              trusted=self._fixture_resource(trusted))

    def tick(self, now, *, provider=None, apply=False, cancel=False):
        if not apply:
            return {**SameHostBatch.tick(self, now), "mock_provider": True, "real_stop_verified": False}
        if type(provider) is not FixtureProvider:
            raise ValueError("Tests never accept a live provider")
        adapter = _Observer(self.protection, provider, now)
        # Independent status checking also runs before a terminal trigger.
        try:
            observed = adapter.inspect_exact(self.policy.resource_id)
        except (ValueError, OSError):
            observed = Resource("", "", "unverified")
        with self._tx(now, trusted=observed, cancel=cancel):
            pass
        if now >= self.protection.hard_deadline and observed.phase not in ("stopped", "terminated"):
            return {"status": "unverified", "reason": SameHostBatch.tick(self, now)["reason"],
                    "alert": True, "hard_deadline_reached": True,
                    "mock_provider": True, "real_stop_verified": False}
        outcome = SameHostBatch.tick(self, now, backend=adapter, apply=True, cancel=cancel)
        if now >= self.protection.hard_deadline and outcome["status"] not in ("stopped", "terminated"):
            outcome.update(alert=True, hard_deadline_reached=True)
        return {**outcome, "mock_provider": True, "real_stop_verified": False}
