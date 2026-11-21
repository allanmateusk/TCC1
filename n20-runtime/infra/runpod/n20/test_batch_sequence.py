from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from .batch_sequence import BatchPlan, Sequencer
from .campaign import IDS
from .watchdog import Resource


class SequencerTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name).resolve() / "batch.sqlite"
        self.plan = BatchPlan("a"*32,"b"*40,"c"*64,"private-bucket",10,500,40)
        self.q = Sequencer(self.path, self.plan)
        self.q.initialize()

    def proof(self, run, case, **overrides):
        return {"schema":"tcc-n20-r2-receipt/v1", "status":"verified", "run_kind":"official",
                "nodes":20,"rounds":50,"verified_own_generations":1000,"scenario_id":case,
                "run_id":run,"bucket":self.plan.bucket,"key":f"tcc/prod/n20-{run}.zip",
                "sha256":"9"*64,"bytes":123,**overrides}

    def prepare(self, now=10, run="3"*32, resource="pod-1"):
        reservation = self.q.reserve(now, run)
        self.assertEqual(reservation["status"],"reserved")
        self.assertTrue(self.q.bind(now, run, Resource(resource,run,"active")))
        self.assertTrue(self.q.seal(now,run,sha256="9"*64,size=123))
        return reservation

    def test_all_cases_in_exact_order_with_meta_and_independent_stop(self):
        for i, case in enumerate(IDS):
            run = f"{i:032x}"
            pod = f"pod-{i}"
            r = self.prepare(10+i,run,pod)
            self.assertEqual((r["scenario_id"],r["seed"],r["rounds"],r["git_sha"],
                              r["profile_sha256"],r["run_kind"]),
                             (case,0,50,self.plan.git_sha,self.plan.profile_sha256,"official"))
            self.assertEqual(self.q.finish(10+i,run,trusted_receipt=self.proof(run,case),
                                           stopped=Resource(pod,run,"stopped"))["status"],"verified")
        self.assertEqual(self.q.reserve(1000,"a"*32)["status"],"complete")

    def test_concurrent_reservations_and_restart_never_grant_twice(self):
        with ThreadPoolExecutor(max_workers=2) as threads:
            results = list(threads.map(lambda i:self.q.reserve(10,f"{i:032x}"),range(2)))
        self.assertEqual(sorted(r["status"] for r in results),["blocked_active","reserved"])
        restarted = Sequencer(self.path,self.plan)
        restarted.initialize()
        active = restarted.snapshot()["cases"][0]["run_id"]
        self.assertEqual(restarted.reserve(11,active)["status"],"blocked_active")
        restarted.abort(12,active,"uncertain_launch")
        self.assertEqual(restarted.reserve(13,"8"*32),
                         {"status":"paused","reason":"uncertain_launch"})

    def test_wrong_evidence_pauses_persistently(self):
        run = "3"*32
        self.prepare()
        proof = self.proof(run,"C01",sha256="0"*64)
        stop = Resource("pod-1",run,"stopped")
        self.assertEqual(self.q.finish(12,run,trusted_receipt=proof,stopped=stop)["reason"],
                         "uncertain_evidence")
        self.assertEqual(self.q.finish(13,run,trusted_receipt=self.proof(run,"C01"),stopped=stop)["status"],"paused")

    def test_exact_production_proof_cannot_advance_while_gpu_active(self):
        run = "3"*32
        self.prepare()
        self.assertEqual(self.q.finish(11,run,trusted_receipt=self.proof(run,"C01"),
                                       stopped=Resource("pod-1",run,"active"))["reason"],"uncertain_evidence")

    def test_deadlines_no_auto_retry(self):
        self.prepare()
        self.assertEqual(self.q.reserve(50,"4"*32)["reason"],"attempt_deadline")
        self.assertEqual(self.q.reserve(51,"4"*32)["status"],"paused")

    def test_batch_deadline_before_first_reservation(self):
        self.assertEqual(self.q.reserve(500,"4"*32)["reason"],"batch_deadline")

    def test_no_scenario_advance_on_cancel(self):
        run="3"*32
        self.q.reserve(10,run)
        self.q.abort(11,run,"cancelled")
        self.assertEqual(self.q.reserve(12,"4"*32)["reason"],"cancelled")
        self.assertEqual(self.q.snapshot()["cases"][1]["status"],"pending")

    def test_wrong_plan_and_reused_runid(self):
        with self.assertRaises(ValueError):
            Sequencer(self.path,replace(self.plan,profile_sha256="d"*64)).initialize()
        run = "3"*32
        self.prepare()
        self.q.finish(19,run,trusted_receipt=self.proof(run,"C01"),stopped=Resource("pod-1",run,"stopped"))
        with self.assertRaises(ValueError):
            self.q.reserve(20,run)

    def test_pilot_or_other_case_receipt_rejected(self):
        run="3"*32
        self.prepare()
        self.assertEqual(self.q.finish(11,run,trusted_receipt=self.proof(run,"C16",run_kind="pilot"),
                         stopped=Resource("pod-1",run,"stopped"))["reason"],"uncertain_evidence")
