"""Offline regression for 20 sequential scenarios, one fixture resource."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import Mock

from . import batch_sequence, campaign, campaign_profiles as cp, incremental_campaign as catalog, incremental_same_host as q
from .same_host_batch import HostPolicy
from .watchdog import Resource


class SamePodVersionedTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory(prefix="tcc20samepod-fixture-")
        self.addCleanup(d.cleanup)
        self.path=Path(d.name).resolve()/"offline-batch.sqlite"
        self.profile=cp.resolve("incremental-v1")
        self.scope=cp.scope(self.profile)
        self.plan=q.IncrementalPlan("a"*32,"b"*40,self.scope["profile_sha256"],"tcc",100,1200,40)
        self.policy=HostPolicy("fixture-exact-pod",500)
        self.resource=Resource(self.policy.resource_id,self.plan.batch_id,"active")
        self.stop=q.FakeStopBackend(self.resource)
        self.control=self.reopen()
        self.control.arm(self.resource)

    def reopen(self):
        return q.IncrementalSameHost(self.path,self.plan,self.policy)

    def start(self,now,idx):
        rid=f"{idx+1:032x}"
        grant=self.control.reserve(now,rid,trusted=self.resource)
        self.assertEqual(grant["scenario_id"],catalog.IDS[idx])
        self.assertEqual(grant["resource_id"],self.resource.resource_id)
        self.assertTrue(grant["candidate_only"])
        self.assertFalse(grant["eligible_for_live_admission"])
        return rid,grant

    def staged(self,now,rid,case):
        body=f"CPU stand-in, benchmark result is NOT modeled here: {case}".encode()
        self.assertTrue(self.control.seal(now,rid,sha256=hashlib.sha256(body).hexdigest(),size=len(body)))
        issued=self.control.reserve_upload(now+1,rid)
        self.assertEqual(issued["status"],"mock_put_reserved_once")
        return issued["fixture_intent"],body

    def facts(self,case):
        row=next(r for r in self.profile["scenarios"] if r["id"]==case)
        plan=cp.plan(self.profile,row,0,50)
        return {"run_kind":"official","scenario_id":case,"nodes":20,"rounds":50,"verified_own_generations":1000,
                "verified_audit_rounds":plan["planned_rounds"],"verified_ledgers":20,"verified_genesis_rounds":[],
                "verified_intentional_absences":sum(map(len,plan["simulated_absences"].values())),**self.scope}

    def test_all_twenty_order_same_pod_no_intermediate_stop(self):
        cases=[]
        for i,expected in enumerate(catalog.IDS):
            now=101+i*5
            rid,grant=self.start(now,i)
            cases.append(grant["scenario_id"])
            intent,body=self.staged(now+1,rid,expected)
            proof=q.verify_fixture_get(intent,body,self.facts(expected))
            observed=self.control.finish(now+3,rid,trusted_receipt=proof,trusted=self.resource)
            self.assertEqual(observed["status"],"mock_verified")
            self.assertEqual(observed["stop_required"],i==19)
            self.assertFalse(observed["eligible_for_live_admission"])
            state=self.control.tick(now+4,apply=True,backend=self.stop)
            self.assertFalse(state["real_stop_verified"])
            self.assertEqual(self.stop.stop_requests,int(i==19))
        self.assertEqual(tuple(cases),catalog.IDS)
        self.assertEqual(self.control.tick(201,apply=True,backend=self.stop)["status"],"stopped")
        self.assertEqual(self.stop.stop_requests,1)
        self.assertEqual(self.control.reserve(202,"f"*32,trusted=self.resource)["status"],"stop_required")

    def test_upload_no_rerun_after_reopen_missing_get_only(self):
        rid,grant=self.start(101,0)
        case=grant["scenario_id"]
        intent,body=self.staged(102,rid,case)
        reopen=self.reopen()
        self.assertEqual(reopen.reserve(104,"f"*32,trusted=self.resource)["status"],"blocked_active")
        self.assertEqual(reopen.reserve_upload(105,rid),{"status":"get_only","fixture_intent":intent})
        self.assertIsNone(q.verify_fixture_get(intent,None,self.facts(case)))
        self.assertEqual(reopen.finish(106,rid,trusted_receipt=None,trusted=self.resource)["status"],"awaiting_independent_get")
        self.assertEqual(reopen.reserve(107,"f"*32,trusted=self.resource)["status"],"blocked_active")
        proof=q.verify_fixture_get(intent,body,self.facts(case))
        self.assertEqual(reopen.finish(108,rid,trusted_receipt=proof,trusted=self.resource)["status"],"mock_verified")
        self.assertEqual(reopen.reserve(109,"f"*32,trusted=self.resource)["scenario_id"],catalog.IDS[1])

    def test_wrong_get_cannot_advance_and_requests_owned_stop(self):
        rid,grant=self.start(101,0)
        case=grant["scenario_id"]
        packet,body=self.staged(102,rid,case)
        got=self.control.accept_fixture_get(104,rid,packet,b"x"*len(body),self.facts(case),trusted=self.resource)
        self.assertEqual(got,{"status":"stop_required","reason":"uncertain_evidence"})
        self.assertEqual(self.control.reserve(105,"f"*32,trusted=self.resource)["reason"],"uncertain_evidence")
        self.assertEqual(self.control.tick(106,apply=True,backend=self.stop)["status"],"stopped")
        self.assertEqual(self.stop.stop_requests,1)

    def test_cannot_forge_production_receipt_or_change_seal(self):
        rid,grant=self.start(101,0)
        packet,body=self.staged(102,rid,grant["scenario_id"])
        fake={"schema":"tcc-n20-r2-receipt/v1","status":"verified",**packet}
        self.assertEqual(self.control.finish(104,rid,trusted_receipt=fake,trusted=self.resource)["reason"],"receipt_mismatch")
        adapter=Mock()
        with self.assertRaises(ValueError): self.control.tick(105,apply=True,backend=adapter)
        adapter.inspect_exact.assert_not_called()
        self.assertEqual(self.stop.stop_requests,0)

    def test_cutoff_bad_owner_abort_confirmed_exact_stop(self):
        rid,grant=self.start(101,0)
        self.staged(102,rid,grant["scenario_id"])
        owner=Resource(self.resource.resource_id,"0"*32,"active")
        foreign=q.FakeStopBackend(owner)
        state=self.control.tick(141,apply=True,backend=foreign)
        self.assertEqual(state["reason"],"attempt_deadline")
        self.assertEqual(state["status"],"unverified")
        self.assertEqual(foreign.stop_requests,0)
        self.stop.lose_stop_confirmation=True
        self.assertEqual(self.control.tick(142,apply=True,backend=self.stop)["status"],"unverified")
        self.assertEqual(self.stop.stop_requests,1)
        self.assertEqual(self.control.tick(143,apply=True,backend=self.stop)["status"],"unverified")
        self.assertEqual(self.stop.stop_requests,1)
        self.stop.lose_stop_confirmation=False
        self.assertEqual(self.control.tick(157,apply=True,backend=self.stop)["status"],"stopped")
        self.assertEqual(self.stop.stop_requests,2)

    def test_legacy_plan_serialization_unchanged_and_cannot_reopen(self):
        old=batch_sequence.BatchPlan("a"*32,"b"*40,"c"*64,"tcc",100,1200,40)
        raw=json.loads(old.serialized())
        self.assertEqual(raw["scenarios"],list(campaign.IDS))
        self.assertNotIn("candidate_only",raw)
        with self.assertRaises(ValueError): batch_sequence.Sequencer(self.path,old).initialize()

    def test_changed_seal_and_cancel_never_allocate_another_case(self):
        rid,_=self.start(101,0)
        self.assertTrue(self.control.seal(102,rid,sha256="d"*64,size=200))
        self.assertFalse(self.control.seal(103,rid,sha256="e"*64,size=200))
        self.assertEqual(self.reopen().reserve(104,"f"*32,trusted=self.resource)["reason"],"changed_preupload_proof")
        self.assertEqual(self.control.tick(105,apply=True,backend=self.stop)["status"],"stopped")

    def test_explicit_cancel_and_global_deadline_are_terminal(self):
        self.assertEqual(self.control.tick(101,apply=True,backend=self.stop,cancel=True)["reason"],"cancelled")
        self.assertEqual(self.control.reserve(102,"f"*32,trusted=self.resource)["reason"],"cancelled")
        # Independent fresh fixture DB: global deadline before any case grant.
        with tempfile.TemporaryDirectory(prefix="tcc-global-deadline-") as d:
            other=q.IncrementalSameHost(Path(d).resolve()/"offline.sqlite",self.plan,self.policy)
            other.arm(self.resource)
            fake=q.FakeStopBackend(self.resource)
            self.assertEqual(other.tick(1200,apply=True,backend=fake)["reason"],"batch_deadline")
            self.assertEqual(fake.stop_requests,1)
