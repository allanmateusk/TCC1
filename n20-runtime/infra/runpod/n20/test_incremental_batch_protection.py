from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from . import campaign_profiles as cp, incremental_campaign as catalog, incremental_same_host as queue
from .incremental_batch_protection import (
    BatchProtection, FixtureObservation, FixtureProvider, ProtectedIncrementalBatch,
)


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="batch-timeout-fixture-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name).resolve()/"batch.sqlite"
        self.profile = cp.resolve("incremental-v1")
        self.scope = cp.scope(self.profile)
        self.start = 1_790_000_000
        self.args = dict(batch_id="b"*32, resource_id="fixture-pod", owner_id="fixture-owner",
                         datacenter_id="fixture-dc", pod_name="tcc-n20-batch-"+"b"*32,
                         git_sha="a"*40, profile_sha256=self.scope["profile_sha256"],
                         opened_at=self.start, stop_at=self.start+4*3600, hard_deadline=self.start+4*3600+91,
                         stale_seconds=180, max_attempt_seconds=120,
                         hourly_compute_microusd=4_000_001, fixed_and_other_microusd=200_000,
                         approved_cap_microusd=17_000_000)
        self.spec = BatchProtection(**self.args)
        self.observation = FixtureObservation(self.spec.resource_id, self.spec.owner_id, self.spec.datacenter_id,
                                              self.spec.pod_name, self.spec.batch_id, "active")
        self.provider = FixtureProvider(self.observation)
        self.controller = self.reopen()

    def reopen(self):
        return ProtectedIncrementalBatch(self.path, self.spec, approved_sha256=self.spec.digest)

    def arm(self):
        self.controller.arm(self.observation, now=self.start)

    def test_budget_cutoffs_and_missing_independent_pin_fail_closed(self):
        expected_ceiling = 16_301_116
        self.assertEqual(self.spec.cost_ceiling_microusd, expected_ceiling)
        replace(self.spec, approved_cap_microusd=expected_ceiling)
        for change in (
            {"approved_cap_microusd":expected_ceiling-1}, {"stop_at":self.start+4*3600-1},
            {"hard_deadline":self.start+7*3600+1, "stop_at":self.start+7*3600-90},
            {"hard_deadline":self.spec.stop_at+59}, {"hard_deadline":self.spec.stop_at+601},
            {"hourly_compute_microusd":True}, {"opened_at":float(self.start)}, {"owner_id":""},
            {"git_sha":"a"*39}, {"profile_sha256":"9"*64}, {"pod_name":"previous-pilot"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                BatchProtection(**{**self.args, **change})
        replace(self.spec, stop_at=self.start+7*3600-91, hard_deadline=self.start+7*3600,
                approved_cap_microusd=30_000_000)
        with self.assertRaises(TypeError):
            ProtectedIncrementalBatch(self.path, self.spec)
        with self.assertRaises(ValueError):
            ProtectedIncrementalBatch(self.path, self.spec, approved_sha256="0"*64)
        self.assertFalse(self.path.exists())

    def test_changed_exact_observation_or_plan_refused(self):
        for changed in (
            {"owner_id":"wrong"}, {"resource_id":"wrong"}, {"datacenter_id":"wrong"},
            {"pod_name":"wrong"}, {"batch_id":"c"*32}, {"phase":"stopped"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.controller.arm(replace(self.observation, **changed), now=self.start)
        self.assertFalse(self.path.exists())
        self.arm()
        new = replace(self.spec, git_sha="e"*40)
        other = ProtectedIncrementalBatch(self.path, new, approved_sha256=new.digest)
        with self.assertRaisesRegex(ValueError, "Stored plan differs"):
            other.arm(self.observation, now=self.start)
        with self.assertRaises(ValueError):
            self.controller.reserve(self.start+1, "1"*32, trusted=Mock())

    def test_loss_of_worker_and_controller_restart_still_hit_absolute_deadline(self):
        self.arm()
        reopened = self.reopen()
        dry = reopened.tick(self.spec.stop_at, provider=Mock())
        self.assertEqual(dry["status"], "dry_run")
        self.assertEqual(dry["reason"], "")
        outcome = reopened.tick(self.spec.stop_at, provider=self.provider, apply=True)
        self.assertEqual((outcome["status"], outcome["reason"]), ("stopped", "batch_deadline"))
        self.assertFalse(outcome["real_stop_verified"])
        tick = self.reopen().tick(self.spec.stop_at+1, provider=self.provider, apply=True, cancel=True)
        self.assertEqual(tick["reason"], "batch_deadline")
        self.assertEqual(self.provider.stop_requests, 1)
        self.assertEqual(self.reopen().reserve(self.spec.stop_at+2, "1"*32,
                                              trusted=self.observation)["status"], "stop_required")

    def test_error_latches_after_worker_loss_and_lost_ack_is_read_back(self):
        self.arm()
        rid = "1"*32
        self.controller.reserve(self.start+1, rid, trusted=self.observation)
        self.controller.fail(self.start+2, rid, "failed")
        self.provider.lose_response = True
        first = self.controller.tick(self.start+3, provider=self.provider, apply=True)
        self.assertEqual((first["status"], first["reason"]), ("unverified", "failed"))
        second = self.reopen().tick(self.start+4, provider=self.provider, apply=True, cancel=True)
        self.assertEqual((second["status"], second["reason"]), ("stopped", "failed"))
        self.assertEqual(self.provider.stop_requests, 1)

    def test_foreign_and_unavailable_provider_are_not_mutated_at_cutoff(self):
        self.arm()
        foreign = FixtureProvider(replace(self.observation, owner_id="wrong"))
        outcome = self.controller.tick(self.spec.stop_at, provider=foreign, apply=True)
        self.assertEqual(outcome["status"], "unverified")
        self.assertTrue(outcome["alert"])
        self.assertEqual(foreign.stop_requests, 0)
        with self.assertRaises(ValueError):
            self.controller.tick(self.spec.stop_at+1, provider=Mock(), apply=True)
        self.provider.fail_inspect = True
        outcome = self.reopen().tick(self.spec.hard_deadline, provider=self.provider, apply=True)
        self.assertTrue(outcome["hard_deadline_reached"])
        self.provider.fail_inspect = False
        outcome = self.reopen().tick(self.spec.hard_deadline+1, provider=self.provider, apply=True)
        self.assertTrue(outcome["alert"])
        self.assertEqual(self.provider.stop_requests, 0)
        self.provider.observation = replace(self.observation, phase="stopped")
        outcome = self.reopen().tick(self.spec.hard_deadline+2, provider=self.provider, apply=True)
        self.assertEqual(outcome["status"], "stopped")
        self.assertFalse(outcome["real_stop_verified"])

    def test_all_verified_cases_same_fake_pod_one_terminal_stop_decision(self):
        self.arm()
        for i, case in enumerate(catalog.IDS, 1):
            t = self.start+i*6
            rid = f"{i:032x}"
            self.assertTrue(self.controller.beat(t, t, trusted=self.observation))
            grant = self.controller.reserve(t, rid, trusted=self.observation)
            self.assertEqual(grant["scenario_id"], case)
            self.assertEqual(grant["resource_id"], self.spec.resource_id)
            blob = f"fixture-{i}".encode()
            self.assertTrue(self.controller.seal(t+1, rid, sha256=hashlib.sha256(blob).hexdigest(), size=len(blob)))
            intent = self.controller.reserve_upload(t+2, rid)["fixture_intent"]
            row = next(r for r in self.profile["scenarios"] if r["id"] == case)
            plan = cp.plan(self.profile, row, 0, 50)
            facts = {"run_kind":"official", "scenario_id":case, "nodes":20, "rounds":50, "verified_own_generations":1000,
                     "verified_ledgers":20, "verified_genesis_rounds":[], "verified_audit_rounds":plan["planned_rounds"],
                     "verified_intentional_absences":sum(map(len, plan["simulated_absences"].values())), **self.scope}
            proof = queue.verify_fixture_get(intent, blob, facts)
            finish = self.controller.finish(t+3, rid, trusted_receipt=proof, trusted=self.observation)
            self.assertEqual(finish["stop_required"], i == 20)
            outcome = self.reopen().tick(t+4, provider=self.provider, apply=True)
            self.assertEqual(outcome["status"], "stopped" if i == 20 else "watching")
            self.assertEqual(self.provider.stop_requests, int(i == 20))
        self.assertEqual(self.reopen().tick(self.start+125, provider=self.provider, apply=True)["reason"],
                         "all_mock_receipts_verified")
        self.assertEqual(self.provider.stop_requests, 1)
