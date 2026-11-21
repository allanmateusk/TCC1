"""Offline checks of the full warm dispatcher; no GPU or controller API."""
import unittest
from unittest.mock import patch

from . import incremental_warm_live as live
from .incremental_campaign import IDS


class FixtureLane:
    def __init__(self,n,fail_at=None):
        self.case_limit=n
        self.fail_at=fail_at
        self.events=[]
        self.current=self._case(0)

    def _case(self,i):
        return {"index":i,"scenario_id":IDS[i],"run_id":f"fixture-{i}"}

    def execute(self):
        self.events.append(("worker",self.current["index"]))
        return live.Seal(self.current["run_id"],self.current["scenario_id"],"7"*64,100),None

    def await_next(self,seal,_):
        prev=self.current["index"]
        self.events.append(("independent",prev))
        if prev==self.fail_at:
            raise ValueError("No independently verified signed GET")
        self.current=self._case(prev+1)

    def _accept_incremental_readback(self,admission):
        assert admission is self
        self.events.append(("readback_committed",self.current["index"]))


class LoopTest(unittest.TestCase):
    def test_full_sequence_has_only_20_and_each_next_requires_prior_gate(self):
        f=FixtureLane(20)
        results=live._run_ordered(f,f,f.execute)
        self.assertEqual([s.scenario_id for s,_ in results],list(IDS))
        for i in range(19):
            self.assertEqual(f.events[i*3:i*3+3],[("worker",i),("independent",i),("readback_committed",i+1)])
        self.assertEqual(f.events[-1],("worker",19))
        self.assertEqual(len(f.events),58)

    def test_invalid_prior_cannot_open_third_and_short_has_none(self):
        f=FixtureLane(20,fail_at=1)
        with self.assertRaisesRegex(ValueError,"independently"):
            live._run_ordered(f,f,f.execute)
        self.assertEqual([i for ev,i in f.events if ev=="worker"],[0,1])
        q=FixtureLane(2)
        self.assertEqual(len(live._run_ordered(q,q,q.execute)),2)
        self.assertEqual([i for ev,i in q.events if ev=="worker"],[0,1])

    def test_full_still_fails_before_any_worker_without_protected_linux(self):
        with patch.object(live.first.sys,"platform","win32"),patch.object(
                live,"ResidentPool",side_effect=AssertionError("No residents without admission")):
            with self.assertRaisesRegex(ValueError,"Protected Linux"):
                live.supervise_full_campaign()



class SignedLateGateTest(unittest.TestCase):
    def test_case_20_requires_exact_19_and_full_scope_never_accepts_21(self):
        from dataclasses import replace
        from . import test_incremental_warm_journal as tj
        from .artifact_store import sha,json_bytes
        from .incremental_warm_journal import Authorities
        fx=tj.WarmJournalTest()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        scope=replace(fx.scope,mode="official-full")
        trust=Authorities(scope,fx.trust.lease_pem,fx.trust.readback_pem,fx.openssl)
        fx.scope=scope
        prior=fx.lease(18,tj.RUN1,"9"*64)["evidence"]
        seal=live.Seal(tj.RUN1,IDS[18],"3"*64,1234)
        get=fx.get(18,tj.RUN1)
        nxt=fx.lease(19,tj.RUN2,fx.hash_proof(get))
        commit=fx._sign(dict(schema=live.COMMITTED,scope_sha256=scope.digest,
            receipt_sha256=fx.hash_proof(get),lease_sha256=fx.hash_proof(nxt),index=19,run_id=tj.RUN2,
            committed_at=fx.now,expires_at=fx.now+20),"observer")
        relay={"readback":get,"next_lease":nxt,"committed":commit}
        self.assertEqual(live.verify_transition(trust,relay,prior=prior,seal=seal,now=fx.now)["scenario_id"],IDS[19])
        badget=fx.get(17,tj.RUN1)
        with self.assertRaises(ValueError):
            live.verify_transition(trust,{**relay,"readback":badget},prior=prior,seal=seal,now=fx.now)
        with self.assertRaisesRegex(ValueError,"No further"):
            live.verify_transition(trust,relay,prior=nxt["evidence"],
                seal=live.Seal(tj.RUN2,IDS[19],"3"*64,1234),now=fx.now)
