"""Offline sequencing policy. No launch, cloud, upload, retry, or Git interfaces."""
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
import json
import math
import re
import sqlite3

from .campaign import IDS
from .watchdog import Binding, Resource, matches_receipt


def _hex(value, digits):
    return isinstance(value, str) and re.fullmatch(rf"[a-f0-9]{{{digits}}}", value) is not None


@dataclass(frozen=True)
class BatchPlan:
    batch_id: str
    git_sha: str
    profile_sha256: str
    bucket: str
    opened_at: float
    deadline: float
    max_attempt_seconds: int

    def __post_init__(self):
        if (not _hex(self.batch_id, 32) or not _hex(self.git_sha, 40)
            or not _hex(self.profile_sha256, 64)
            or not isinstance(self.bucket, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", self.bucket)
            or not math.isfinite(self.opened_at) or not math.isfinite(self.deadline)
            or not 0 < self.deadline - self.opened_at <= 168 * 3600
            or type(self.max_attempt_seconds) is not int or not 1 <= self.max_attempt_seconds <= 7200):
            raise ValueError("Missing identity or invalid batch deadline")

    @property
    def case_ids(self):
        return IDS

    def serialized(self):
        return json.dumps({**asdict(self), "scenarios": self.case_ids, "run_kind": "official",
                           "seed": 0, "nodes": 20, "rounds": 50},
                          sort_keys=True, allow_nan=False)


class Sequencer:
    """One grant per scenario, with no automatic reset/resume of an uncertain grant.

    State must be on an independent controller-owned durable SQLite volume
    supporting file locks/fsync; never accept a workload-writable database.
    """
    def __init__(self, path: Path, plan: BatchPlan):
        if (not path.is_absolute() or not path.parent.is_dir() or path.is_symlink()
            or path.parent.resolve(strict=True) != path.parent):
            raise ValueError("Use an isolated protected absolute SQLite path")
        self.path = path
        self.plan = plan

    def _db(self):
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    def initialize(self):
        """Create one immutable plan; reopening requires byte-identical plan identity."""
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS batch
                (singleton INTEGER PRIMARY KEY CHECK(singleton=1), plan TEXT NOT NULL,
                 paused TEXT NOT NULL DEFAULT '', last_now REAL NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS cases
                (idx INTEGER PRIMARY KEY, scenario TEXT NOT NULL UNIQUE,
                 status TEXT NOT NULL DEFAULT 'pending', run_id TEXT UNIQUE,
                 started REAL, cutoff REAL, resource_id TEXT UNIQUE,
                 expected_sha256 TEXT, expected_bytes INTEGER, receipt TEXT, stop_phase TEXT)""")
            old = db.execute("SELECT plan FROM batch WHERE singleton=1").fetchone()
            if not old:
                db.execute("INSERT INTO batch(singleton,plan,last_now) VALUES (1,?,?)",
                           (self.plan.serialized(), self.plan.opened_at))
                db.executemany("INSERT INTO cases(idx,scenario) VALUES (?,?)", enumerate(self.plan.case_ids))
            elif old["plan"] != self.plan.serialized():
                raise ValueError("Stored plan differs; do not reuse this batch database")
            self._check_cases(db)
            db.commit()

    def _check_cases(self,db):
        rows = db.execute("SELECT idx,scenario,status FROM cases ORDER BY idx").fetchall()
        if [(r["idx"], r["scenario"]) for r in rows] != list(enumerate(self.plan.case_ids)):
            raise ValueError("Stored case order differs from campaign")
        statuses = [r["status"] for r in rows]
        if any(x not in ("pending", "active", "complete") for x in statuses):
            raise ValueError("Unrecognized persisted case state")
        completed = statuses.count("complete")
        if statuses[:completed] != ["complete"] * completed or statuses.count("active") > 1:
            raise ValueError("Invalid persisted progression")
        pending = statuses[completed:]
        if "active" in pending and pending[0] != "active":
            raise ValueError("Attempt is not at the next case")

    @contextmanager
    def _tx(self, now):
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("A trusted finite controller clock is required")
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            head = db.execute("SELECT * FROM batch WHERE singleton=1").fetchone()
            if not head or head["plan"] != self.plan.serialized() or now < head["last_now"]:
                raise ValueError("Plan or trusted controller clock mismatch")
            self._check_cases(db)
            db.execute("UPDATE batch SET last_now=? WHERE singleton=1", (now,))
            row = db.execute("SELECT * FROM cases WHERE status='active'").fetchone()
            pause = head["paused"]
            incomplete = db.execute("SELECT 1 FROM cases WHERE status!='complete' LIMIT 1").fetchone()
            if not pause and incomplete:
                if now >= self.plan.deadline:
                    pause = "batch_deadline"
                elif row and now >= row["cutoff"]:
                    pause = "attempt_deadline"
                if pause:
                    self._pause(db, pause)
            yield db, pause, row
            db.commit()

    @staticmethod
    def _pause(db, why):
        db.execute("UPDATE batch SET paused=? WHERE singleton=1 AND paused=''", (why,))

    def reserve(self, now, run_id):
        """Return an at-most-once reservation, never permission to bypass provider policy."""
        if not _hex(run_id, 32):
            raise ValueError("Use a unique lowercase 32-hex attempt ID")
        with self._tx(now) as (db, pause, active):
            if pause:
                return {"status": "paused", "reason": pause}
            if active:
                return {"status": "blocked_active", "scenario_id": active["scenario"]}
            row = db.execute("SELECT * FROM cases WHERE status='pending' ORDER BY idx LIMIT 1").fetchone()
            if not row:
                return {"status": "complete"}
            if db.execute("SELECT 1 FROM cases WHERE run_id=?", (run_id,)).fetchone():
                raise ValueError("Attempt ID was already consumed")
            deadline = min(now + self.plan.max_attempt_seconds, self.plan.deadline)
            db.execute("UPDATE cases SET status='active',run_id=?,started=?,cutoff=? WHERE idx=?",
                       (run_id, now, deadline, row["idx"]))
            return {"status": "reserved", "run_kind": "official", "scenario_id": row["scenario"],
                    "run_id": run_id, "deadline": deadline, "seed": 0, "nodes": 20, "rounds": 50,
                    "git_sha": self.plan.git_sha, "profile_sha256": self.plan.profile_sha256}

    def abort(self, now, run_id, reason):
        if reason not in {"failed", "cancelled", "uncertain_launch", "uncertain_evidence"}:
            raise ValueError("Unrecognized pause reason")
        with self._tx(now) as (db, pause, active):
            if pause:
                return {"status":"paused", "reason":pause}
            if not active or active["run_id"] != run_id:
                raise ValueError("No matching active attempt to pause")
            self._pause(db, reason)
            return {"status":"paused", "reason":reason}

    def bind(self, now, run_id, resource: Resource):
        """Bind a dedicated allocation from a trusted exact-ID provider observation."""
        with self._tx(now) as (db, pause, active):
            if pause:
                return False
            if not active or active["run_id"] != run_id:
                raise ValueError("No matching active attempt")
            expected = (resource.owner_run_id == run_id and resource.phase == "active"
                        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", resource.resource_id))
            prior = db.execute("SELECT 1 FROM cases WHERE idx!=? AND resource_id=?",
                               (active["idx"], resource.resource_id)).fetchone()
            if not expected or prior or active["resource_id"] not in (None, resource.resource_id):
                self._pause(db, "uncertain_resource")
                return False
            db.execute("UPDATE cases SET resource_id=? WHERE idx=?", (resource.resource_id, active["idx"]))
            return True

    def seal(self, now, run_id, *, sha256, size):
        """Publish expected digest from trusted local preparation before uploader starts."""
        if not _hex(sha256, 64) or type(size) is not int or not 0 < size <= 64 * 1024**2:
            raise ValueError("Invalid expected artifact proof")
        with self._tx(now) as (db, pause, active):
            if pause:
                return False
            if not active or active["run_id"] != run_id or not active["resource_id"]:
                raise ValueError("No matching bound active attempt")
            old = active["expected_sha256"]
            if old and (old, active["expected_bytes"]) != (sha256, size):
                self._pause(db, "uncertain_expected_content")
                return False
            db.execute("UPDATE cases SET expected_sha256=?,expected_bytes=? WHERE idx=?",
                       (sha256, size, active["idx"]))
            return True

    def finish(self, now, run_id, *, trusted_receipt, stopped: Resource):
        """Advance only with trusted S3 content proof and independent provider stop observation."""
        with self._tx(now) as (db, pause, active):
            if pause:
                return {"status":"paused", "reason":pause}
            if not active or active["run_id"] != run_id:
                raise ValueError("No matching active attempt")
            if not active["resource_id"] or not active["expected_sha256"]:
                self._pause(db, "missing_expected_evidence")
                return {"status":"paused", "reason":"missing_expected_evidence"}
            binding = Binding(run_id, active["resource_id"], self.plan.bucket, active["cutoff"],
                              active["started"], self.plan.max_attempt_seconds,
                              run_kind="official", scenario_id=active["scenario"])
            proof = (matches_receipt(binding, trusted_receipt)
                     and trusted_receipt.get("sha256") == active["expected_sha256"]
                     and type(trusted_receipt.get("bytes")) is int
                     and trusted_receipt["bytes"] == active["expected_bytes"])
            host = (stopped.resource_id == binding.resource_id and stopped.owner_run_id == run_id
                    and stopped.phase in ("stopped", "terminated"))
            if not (proof and host):
                self._pause(db, "uncertain_evidence")
                return {"status":"paused", "reason":"uncertain_evidence"}
            safe = {k:trusted_receipt[k] for k in ("schema", "status", "run_id", "run_kind",
                "scenario_id", "bucket", "key", "sha256", "bytes", "nodes", "rounds", "verified_own_generations")}
            db.execute("UPDATE cases SET status='complete',receipt=?,stop_phase=? WHERE idx=?",
                       (json.dumps(safe, sort_keys=True), stopped.phase, active["idx"]))
            return {"status":"verified", "scenario_id":active["scenario"]}


    def snapshot(self):
        """Read outstanding work for reconciliation; this never reissues a reservation."""
        if not self.path.is_file():
            raise ValueError("Batch is not initialized")
        with closing(self._db()) as db:
            db.execute("BEGIN")
            head = db.execute("SELECT * FROM batch WHERE singleton=1").fetchone()
            if not head or head["plan"] != self.plan.serialized():
                raise ValueError("Stored batch plan differs")
            self._check_cases(db)
            cases = [dict(r) for r in db.execute(
                "SELECT scenario,status,run_id,resource_id,cutoff,expected_sha256,stop_phase FROM cases ORDER BY idx")]
            return {"paused": head["paused"], "last_observed": head["last_now"], "cases": cases}
