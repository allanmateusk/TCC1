from pathlib import Path
import tempfile
import unittest

from .batch_sequence import BatchPlan
from .campaign import IDS
from .same_host_batch import HostPolicy,SameHostBatch
from .watchdog import Resource


class Fake:
    def __init__(self,resource):
        self.r=resource
        self.calls=[]
        self.delay=False
    def inspect_exact(self,rid):
        self.calls.append(("inspect",rid))
        return self.r
    def stop_exact(self,rid,*,expected_run_id):
        self.calls.append(("stop",rid,expected_run_id))
        if not self.delay:
            self.r=Resource(rid,expected_run_id,"stopped")


class SharedTest(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.path=Path(folder.name).resolve()/"shared.sqlite"
        self.plan=BatchPlan("a"*32,"b"*40,"c"*64,"private",10,500,40)
        self.policy=HostPolicy("pod-one",45,max_attempts=2)
        self.host=Resource("pod-one",self.plan.batch_id,"active")
        self.fake=Fake(self.host)
        self.q=SameHostBatch(self.path,self.plan,self.policy)
        self.q.arm(self.host)

    def proof(self,run,case,*,sha="9"*64):
        return dict(schema="tcc-n20-r2-receipt/v1",status="verified",run_kind="official",
                    scenario_id=case,run_id=run,key=f"tcc/prod/n20-{run}.zip",
                    bucket="private",sha256=sha,bytes=123,nodes=20,rounds=50,verified_own_generations=1000)

    def test_shared_no_stop_between_cases_and_once_at_end(self):
        for i,case in enumerate(IDS):
            now=10+i
            run=f"{i+1:032x}"
            self.assertTrue(self.q.beat(now,now,trusted=self.host))
            grant=self.q.reserve(now,run,trusted=self.host)
            self.assertEqual((grant["scenario_id"],grant["resource_id"]),(case,"pod-one"))
            self.q.seal(now,run,sha256="9"*64,size=123)
            step=self.q.finish(now,run,trusted_receipt=self.proof(run,case),trusted=self.host)
            self.assertEqual(step["stop_required"],i==16)
            if i<16:
                self.assertEqual(self.q.tick(now,backend=self.fake,apply=True),{"status":"watching"})
                self.assertEqual(self.fake.calls,[])
        self.assertEqual(self.q.tick(26,backend=self.fake)["status"],"dry_run")
        self.assertEqual(self.fake.calls,[])
        self.assertEqual(self.q.tick(26,backend=self.fake,apply=True)["status"],"stopped")
        self.assertEqual(self.q.tick(27,backend=self.fake,apply=True)["status"],"stopped")
        self.assertEqual([c for c in self.fake.calls if c[0]=="stop"],
                         [("stop","pod-one",self.plan.batch_id)])

    def test_bad_receipt_stops_exact_host_and_no_next_case(self):
        run="3"*32
        self.q.reserve(10,run,trusted=self.host)
        self.q.seal(10,run,sha256="9"*64,size=123)
        self.assertEqual(self.q.finish(10,run,trusted_receipt=self.proof(run,"C01",sha="8"*64),
                                       trusted=self.host)["reason"],"receipt_mismatch")
        self.assertEqual(self.q.reserve(11,"4"*32,trusted=self.host)["status"],"stop_required")
        self.assertEqual(self.q.tick(11,backend=self.fake,apply=True)["status"],"stopped")

    def test_stale_and_wrong_provider_owner_block(self):
        self.fake.r=Resource("pod-one","e"*32,"active")
        r=self.q.tick(55,backend=self.fake,apply=True)
        self.assertEqual((r["status"],r["reason"],r["alert"]),("unverified","stale",True))
        self.assertFalse(any(x[0]=="stop" for x in self.fake.calls))

    def test_ambiguous_stop_retries_bounded_then_verifies(self):
        self.q.reserve(10,"3"*32,trusted=self.host)
        self.q.fail(10,"3"*32,"failed")
        self.fake.delay=True
        self.assertEqual(self.q.tick(10,backend=self.fake,apply=True)["status"],"unverified")
        self.q.tick(11,backend=self.fake,apply=True)
        self.assertTrue(self.q.tick(25,backend=self.fake,apply=True)["alert"])
        self.q.tick(40,backend=self.fake,apply=True)
        self.assertEqual(len([x for x in self.fake.calls if x[0]=="stop"]),2)
        self.fake.r=Resource("pod-one",self.plan.batch_id,"stopped")
        self.assertEqual(self.q.tick(41,backend=self.fake,apply=True)["status"],"stopped")

    def test_cutoffs_no_retry_resume_or_next(self):
        run="3"*32
        self.q.reserve(10,run,trusted=self.host)
        resumed=SameHostBatch(self.path,self.plan,self.policy)
        resumed.arm(self.host)
        self.assertEqual(resumed.reserve(11,run,trusted=self.host)["status"],"blocked_active")
        self.assertEqual(resumed.tick(50,backend=self.fake,apply=True)["reason"],"attempt_deadline")
        self.assertEqual(resumed.reserve(51,"4"*32,trusted=self.host)["status"],"stop_required")
