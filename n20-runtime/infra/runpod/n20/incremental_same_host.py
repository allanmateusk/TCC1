"""Offline orchestration for the sealed incremental 20-case plan on one Pod.

This module has no launcher or real provider/storage client. Receipts produced
here identify a fixture and are intentionally not production R2 receipts.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
import json

from . import artifact_store as store, campaign_profiles as cp, incremental_campaign as inc
from .batch_sequence import BatchPlan, _hex
from .same_host_batch import SameHostBatch
from .watchdog import Resource

PROOF_SCHEMA="tcc-n20-incremental-independent-get-fixture/v1"
_PERMIT="tcc-n20-incremental-put-intent-fixture/v1"
_MINT=object()


def _campaign():
    return cp.scope(cp.resolve("incremental-v1"))


@dataclass(frozen=True)
class IncrementalPlan(BatchPlan):
    """Same timer contract, deliberately a different serialized plan."""
    def __post_init__(self):
        super().__post_init__()
        if self.bucket!="tcc" or self.profile_sha256!=_campaign()["profile_sha256"]:
            raise ValueError("Incremental batch requires the sealed local campaign profile")

    @property
    def case_ids(self):
        return inc.IDS

    def serialized(self):
        base=json.loads(super().serialized())
        base.update(_campaign(),candidate_only=True)
        return json.dumps(base,sort_keys=True,allow_nan=False)


@dataclass(frozen=True)
class FixtureGetProof:
    record: str
    source: object


def verify_fixture_get(intent, downloaded, validator_facts):
    """Only for tests: simulate independent reader comparing sealed bytes + semantics.

    The caller owns the offline transport and offline validator. Even an exact
    returned proof has a fixture-only schema and never qualifies live use.
    """
    keys={"schema","batch_id","resource_id","run_id","scenario_id","key","sha256","bytes",
          "campaign_id","profile_sha256","candidate_only"}
    if (type(intent) is not dict or set(intent)!=keys or intent["schema"]!=_PERMIT
        or intent["candidate_only"] is not True or not _hex(intent["batch_id"],32)
        or not _hex(intent["run_id"],32) or intent["scenario_id"] not in inc.IDS
        or not cp.matches_record(intent,_campaign()) or intent["key"]!=cp.candidate_key(intent["run_id"])):
        raise ValueError("Not a sealed authorized fixture attempt")
    if downloaded is None:
        return None
    if (type(downloaded) is not bytes or type(intent["bytes"]) is not int
        or not _hex(intent["sha256"],64) or len(downloaded)!=intent["bytes"]
        or not 0<len(downloaded)<=store.MAX_ZIP
        or not hmac.compare_digest(hashlib.sha256(downloaded).hexdigest(),intent["sha256"])):
        raise ValueError("Independent GET did not match sealed SHA-256 and bytes")
    profile=cp.resolve("incremental-v1")
    row=next(r for r in profile["scenarios"] if r["id"]==intent["scenario_id"])
    plan=cp.plan(profile,row,0,50)
    expected={"run_kind":"official","scenario_id":row["id"],"nodes":20,"rounds":50,"verified_own_generations":1000,
              "verified_ledgers":20,"verified_genesis_rounds":[],
              "verified_audit_rounds":plan["planned_rounds"],
              "verified_intentional_absences":sum(map(len,plan["simulated_absences"].values())),
              **_campaign()}
    if type(validator_facts) is not dict or any(validator_facts.get(k)!=v for k,v in expected.items()):
        raise ValueError("Independent artifact validator did not verify pinned scenario semantics")
    out={**intent,**expected,"schema":PROOF_SCHEMA,"status":"mock_independent_get_verified",
         "real_r2_verified":False,"eligible_for_live_admission":False}
    return FixtureGetProof(json.dumps(out,sort_keys=True,allow_nan=False),_MINT)


class FakeStopBackend:
    """Only an in-memory Pod lifecycle double; no network/provider primitives."""
    def __init__(self,resource):
        if type(resource) is not Resource:
            raise ValueError("A fake resource identity is required")
        self.resource=resource
        self.stop_requests=0
        self.lose_stop_confirmation=False

    def inspect_exact(self,resource_id):
        if resource_id!=self.resource.resource_id:
            raise ValueError("Fake resource is another Pod")
        return self.resource

    def stop_exact(self,resource_id,*,expected_run_id):
        if (resource_id,expected_run_id)!=(self.resource.resource_id,self.resource.owner_run_id):
            raise ValueError("Fake Pod ownership mismatch")
        self.stop_requests+=1
        if not self.lose_stop_confirmation:
            self.resource=Resource(resource_id,expected_run_id,"stopped")


class IncrementalSameHost(SameHostBatch):
    def __init__(self,path,plan,policy):
        if type(plan) is not IncrementalPlan:
            raise ValueError("The 20-case controller requires an IncrementalPlan")
        super().__init__(path,plan,policy)

    def arm(self,trusted):
        super().arm(trusted)
        with closing(self.queue._db()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS upload_intents(
                run_id TEXT PRIMARY KEY, detail TEXT NOT NULL)""")

    def reserve(self,now,run_id,*,trusted):
        return {**super().reserve(now,run_id,trusted=trusted),**_campaign(),
                "candidate_only":True,"eligible_for_live_admission":False}

    def seal(self,now,run_id,*,sha256,size):
        if type(size) is not int or not 0<size<=store.MAX_ZIP:
            raise ValueError("Archive size exceeds the frozen candidate contract")
        return super().seal(now,run_id,sha256=sha256,size=size)

    def _attempt(self,active):
        return {"schema":_PERMIT,"batch_id":self.plan.batch_id,"resource_id":self.policy.resource_id,
                "run_id":active["run_id"],"scenario_id":active["scenario"],"key":cp.candidate_key(active["run_id"]),
                "sha256":active["expected_sha256"],"bytes":active["expected_bytes"],
                "candidate_only":True,**_campaign()}

    def reserve_upload(self,now,run_id):
        """Consume at most one PUT grant; a later wake can only reconcile GET."""
        with self._tx(now) as (db,reason,active):
            if reason:
                return {"status":"stop_required","reason":reason}
            if not active or active["run_id"]!=run_id:
                raise ValueError("Wrong active attempt")
            if not active["expected_sha256"]:
                self._stop(db,"missing_preupload_seal")
                return {"status":"stop_required","reason":"missing_preupload_seal"}
            intent=self._attempt(active)
            record=json.dumps(intent,sort_keys=True,allow_nan=False)
            current=db.execute("SELECT detail FROM upload_intents WHERE run_id=?",(run_id,)).fetchone()
            if current is not None:
                if current["detail"]!=record:
                    self._stop(db,"changed_upload_intent")
                    return {"status":"stop_required","reason":"changed_upload_intent"}
                return {"status":"get_only","fixture_intent":intent}
            db.execute("INSERT INTO upload_intents(run_id,detail) VALUES (?,?)",(run_id,record))
            return {"status":"mock_put_reserved_once","fixture_intent":intent}

    def finish(self,now,run_id,*,trusted_receipt,trusted):
        """Advance only for the typed, matching offline GET. Missing waits until cutoff."""
        if type(trusted) is not Resource:
            raise ValueError("Independent fixture host observation required")
        with self._tx(now,trusted=trusted) as (db,reason,active):
            if reason:
                return {"status":"stop_required","reason":reason}
            if not active or active["run_id"]!=run_id:
                raise ValueError("Wrong active attempt")
            if trusted_receipt is None:
                return {"status":"awaiting_independent_get","scenario_id":active["scenario"],"stop_required":False}
            stored=db.execute("SELECT detail FROM upload_intents WHERE run_id=?",(run_id,)).fetchone()
            intent=self._attempt(active)
            proof=None
            if type(trusted_receipt) is FixtureGetProof and trusted_receipt.source is _MINT:
                try:
                    proof=json.loads(trusted_receipt.record)
                except (ValueError,TypeError):
                    pass
            expected={**intent,"schema":PROOF_SCHEMA,"status":"mock_independent_get_verified",
                      "real_r2_verified":False,"eligible_for_live_admission":False,"run_kind":"official",
                      "nodes":20,"rounds":50,"verified_own_generations":1000,"verified_ledgers":20}
            if (not stored or stored["detail"]!=json.dumps(intent,sort_keys=True,allow_nan=False)
                or not isinstance(proof,dict) or any(proof.get(k)!=v for k,v in expected.items())):
                self._stop(db,"receipt_mismatch")
                return {"status":"stop_required","reason":"receipt_mismatch"}
            db.execute("UPDATE cases SET status='complete',receipt=? WHERE idx=?",
                       (json.dumps(proof,sort_keys=True),active["idx"]))
            final=db.execute("SELECT 1 FROM cases WHERE status!='complete' LIMIT 1").fetchone() is None
            if final:
                self._stop(db,"all_mock_receipts_verified")
            return {"status":"mock_verified","scenario_id":active["scenario"],"stop_required":final,
                    "eligible_for_live_admission":False}

    def accept_fixture_get(self,now,run_id,intent,downloaded,validator_facts,*,trusted):
        """A corrupt/mismatched GET requests stop; absence may reconcile GET-only."""
        try:
            receipt=verify_fixture_get(intent,downloaded,validator_facts)
        except ValueError:
            reason=self.fail(now,run_id,"uncertain_evidence")
            return {"status":"stop_required","reason":reason}
        return self.finish(now,run_id,trusted_receipt=receipt,trusted=trusted)

    def tick(self,now,*,backend=None,apply=False,cancel=False):
        if apply and type(backend) is not FakeStopBackend:
            raise ValueError("Candidate controller never accepts a real stop adapter")
        return {**super().tick(now,backend=backend,apply=apply,cancel=cancel),
                "mock_provider":True,"real_stop_verified":False}
