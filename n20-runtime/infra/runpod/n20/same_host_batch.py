"""Offline same-host batch and provider stop policy; no external backend is supplied."""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import json
import math
import re

from .batch_sequence import Sequencer,_hex
from .watchdog import Binding,Resource,matches_receipt


@dataclass(frozen=True)
class HostPolicy:
    resource_id: str
    stale_seconds: int
    retry_seconds: int = 15
    max_attempts: int = 5

    def __post_init__(self):
        if (not re.fullmatch("[A-Za-z0-9][A-Za-z0-9_-]{0,127}",self.resource_id)
            or type(self.stale_seconds) is not int or not 10<=self.stale_seconds<=7200
            or type(self.retry_seconds) is not int or not 1<=self.retry_seconds<=120
            or type(self.max_attempts) is not int or not 1<=self.max_attempts<=10):
            raise ValueError("Invalid exact host or watchdog limits")


class SameHostBatch:
    """Owns a separate state DB; never combines with the old per-case host controller."""
    def __init__(self,path,plan,policy):
        self.queue=Sequencer(path,plan)
        self.plan=plan
        self.policy=policy
        self._spec=json.dumps(vars(policy),sort_keys=True)

    def arm(self, trusted: Resource):
        if not self._matches(trusted) or trusted.phase!="active":
            raise ValueError("Exact batch allocation and ownership not verified")
        self.queue.initialize()
        with closing(self.queue._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS shared_host(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                policy TEXT NOT NULL, heartbeat REAL NOT NULL,
                stop_reason TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0,
                next_retry REAL NOT NULL DEFAULT 0, verified_phase TEXT NOT NULL DEFAULT '')""")
            if db.execute("SELECT 1 FROM cases WHERE status!='pending'").fetchone() and not db.execute(
                    "SELECT 1 FROM shared_host WHERE singleton=1").fetchone():
                raise ValueError("Not a fresh same-host batch database")
            db.execute("INSERT OR IGNORE INTO shared_host(singleton,policy,heartbeat) VALUES(1,?,?)",
                       (self._spec,self.plan.opened_at))
            self._host(db)
            db.commit()

    def _matches(self,resource):
        return (isinstance(resource,Resource) and resource.resource_id==self.policy.resource_id
                and resource.owner_run_id==self.plan.batch_id)

    def _host(self,db):
        host=db.execute("SELECT * FROM shared_host WHERE singleton=1").fetchone()
        if not host or host["policy"]!=self._spec:
            raise ValueError("Host binding not armed or is different")
        return host

    def _stop(self,db,reason):
        db.execute("UPDATE shared_host SET stop_reason=? WHERE singleton=1 AND stop_reason=''",(reason,))

    @contextmanager
    def _tx(self,now,*,trusted=None,heartbeat=None,cancel=False):
        with self.queue._tx(now) as (db,pause,active):
            host=self._host(db)
            reason=host["stop_reason"]
            if not reason:
                if trusted is not None and (not self._matches(trusted) or trusted.phase!="active"):
                    reason="ownership_or_phase_unverified"
                elif heartbeat is not None:
                    # Heartbeat is from an independent observer, never the worker alone.
                    if trusted is None or type(heartbeat) not in (int,float) or not math.isfinite(heartbeat) or not (
                        self.plan.opened_at<=heartbeat<=now
                    ):
                        reason="heartbeat_unverified"
                    elif now < host["heartbeat"]+self.policy.stale_seconds:
                        db.execute("UPDATE shared_host SET heartbeat=? WHERE singleton=1",
                                   (max(heartbeat,host["heartbeat"]),))
                host=self._host(db)
                reason=reason or pause or ("cancelled" if cancel else "")
                if not reason and now>=host["heartbeat"]+self.policy.stale_seconds:
                    reason="stale"
                if reason:
                    self._stop(db,reason)
            yield db,reason,active

    def beat(self,now,when,*,trusted: Resource):
        with self._tx(now,trusted=trusted,heartbeat=when) as (_,reason,_2):
            return not bool(reason)

    def reserve(self,now,run_id,*,trusted: Resource):
        if not _hex(run_id,32) or not isinstance(trusted,Resource):
            raise ValueError("Fresh attempt ID and trusted exact resource observation required")
        with self._tx(now,trusted=trusted) as (db,reason,active):
            if reason: return {"status":"stop_required","reason":reason}
            if active: return {"status":"blocked_active","scenario_id":active["scenario"]}
            row=db.execute("SELECT * FROM cases WHERE status='pending' ORDER BY idx LIMIT 1").fetchone()
            if row is None: raise ValueError("Inconsistent batch completion state")
            if db.execute("SELECT 1 FROM cases WHERE run_id=?",(run_id,)).fetchone():
                raise ValueError("Attempt ID already used")
            cutoff=min(now+self.plan.max_attempt_seconds,self.plan.deadline)
            db.execute("UPDATE cases SET status='active',run_id=?,started=?,cutoff=? WHERE idx=?",
                       (run_id,now,cutoff,row["idx"]))
            return {"status":"reserved","batch_id":self.plan.batch_id,"resource_id":self.policy.resource_id,
                    "run_id":run_id,"scenario_id":row["scenario"],"run_kind":"official",
                    "nodes":20,"rounds":50,"seed":0,"deadline":cutoff,
                    "git_sha":self.plan.git_sha,"profile_sha256":self.plan.profile_sha256}

    def seal(self,now,run_id,*,sha256,size):
        if not _hex(sha256,64) or type(size) is not int or not 0<size<=64*1024**2:
            raise ValueError("Invalid pre-upload evidence")
        with self._tx(now) as (db,reason,active):
            if reason: return False
            if not active or active["run_id"]!=run_id: raise ValueError("Wrong active attempt")
            if active["expected_sha256"] and (sha256,size)!=(active["expected_sha256"],active["expected_bytes"]):
                self._stop(db,"changed_preupload_proof")
                return False
            db.execute("UPDATE cases SET expected_sha256=?,expected_bytes=? WHERE idx=?",
                       (sha256,size,active["idx"]))
            return True

    def finish(self,now,run_id,*,trusted_receipt,trusted: Resource):
        if not isinstance(trusted,Resource):
            raise ValueError("Trusted exact resource observation required")
        with self._tx(now,trusted=trusted) as (db,reason,active):
            if reason: return {"status":"stop_required","reason":reason}
            if not active or active["run_id"]!=run_id: raise ValueError("Wrong active attempt")
            # Binding is used solely to compare per-case receipt fields; host
            # ownership remains batch_id and never changes across cases.
            b=Binding(run_id,self.policy.resource_id,self.plan.bucket,active["cutoff"],
                      active["started"],self.policy.stale_seconds,run_kind="official",
                      scenario_id=active["scenario"])
            if (not active["expected_sha256"] or not matches_receipt(b,trusted_receipt)
                or trusted_receipt.get("sha256")!=active["expected_sha256"]
                or type(trusted_receipt.get("bytes")) is not int
                or trusted_receipt["bytes"]!=active["expected_bytes"]):
                self._stop(db,"receipt_mismatch")
                return {"status":"stop_required","reason":"receipt_mismatch"}
            selected={k:trusted_receipt[k] for k in ("schema","status","run_id","run_kind",
                "scenario_id","bucket","key","sha256","bytes","nodes","rounds","verified_own_generations")}
            db.execute("UPDATE cases SET status='complete',receipt=? WHERE idx=?",
                       (json.dumps(selected,sort_keys=True),active["idx"]))
            final=db.execute("SELECT 1 FROM cases WHERE status!='complete' LIMIT 1").fetchone() is None
            if final: self._stop(db,"all_receipts_verified")
            return {"status":"verified","scenario_id":active["scenario"],"stop_required":final}

    def fail(self,now,run_id,reason):
        if reason not in ("failed","cancelled","uncertain_launch","uncertain_evidence"):
            raise ValueError("Unknown terminal case reason")
        with self._tx(now) as (db,prior,active):
            if prior: return prior
            if not active or active["run_id"]!=run_id: raise ValueError("Wrong active attempt")
            self._stop(db,reason)
            return reason

    def tick(self,now,*,backend=None,apply=False,cancel=False):
        """Independent supervisor. Serialize ticks; never trust an API acknowledgement alone."""
        if not apply:
            # No state mutation or backend calls in the default path.
            with closing(self.queue._db()) as db:
                host=self._host(db)
                return {"status":"dry_run","reason":host["stop_reason"]}
        if backend is None: raise ValueError("No authenticated backend")
        with self._tx(now,cancel=cancel) as (db,reason,_):
            if not reason: return {"status":"watching"}
            host=self._host(db)
            if host["verified_phase"]:
                return {"status":host["verified_phase"],"reason":reason}
            rid=self.policy.resource_id

            def observe():
                r=backend.inspect_exact(rid)
                if not self._matches(r) or r.phase not in ("active","stopping","stopped","terminated"):
                    raise ValueError("Unverified ownership/status")
                return r.phase

            try: phase=observe()
            except Exception: return {"status":"unverified","reason":reason,"alert":True}
            should_stop=(phase in ("active","stopping") and now>=host["next_retry"] and host["attempts"]<self.policy.max_attempts)
            if should_stop:
                db.execute("UPDATE shared_host SET attempts=attempts+1,next_retry=? WHERE singleton=1",
                           (now+self.policy.retry_seconds,))
                # Persist count first even if controller crashes while requesting stop.
                db.commit()
                try:
                    backend.stop_exact(rid,expected_run_id=self.plan.batch_id)
                    phase=observe()
                except Exception:
                    phase="unverified"
                db.execute("BEGIN IMMEDIATE")
                host=self._host(db)
            if phase in ("stopped","terminated"):
                db.execute("UPDATE shared_host SET verified_phase=? WHERE singleton=1",(phase,))
                return {"status":phase,"reason":reason}
            exhausted=host["attempts"]>=self.policy.max_attempts
            return {"status":"unverified","reason":reason,"alert":exhausted}
