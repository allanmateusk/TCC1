"""Provider-side lifecycle policy tested offline with a fake backend."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from .watchdog import Binding, Resource, State, arm, tick


class Fake:
    def __init__(self, binding):
        self.binding = binding
        self.resource = Resource(binding.resource_id, binding.run_id, "active")
        self.calls = []
        self.deferred = False
        self.failure = False

    def inspect_exact(self, resource_id):
        self.calls.append(("inspect", resource_id))
        return self.resource

    def stop_exact(self, resource_id, *, expected_run_id):
        self.calls.append(("stop", resource_id, expected_run_id))
        if self.failure:
            raise TimeoutError("not confirmed")
        if not self.deferred:
            self.resource = replace(self.resource, phase="stopped")


class WatchdogTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state.json"
        self.b = Binding("a" * 32, "pod-test-1", "private-output", 1100, 1000, 40, max_attempts=2)
        arm(self.path, self.b)
        self.fake = Fake(self.b)
        self.local = {"run_id": self.b.run_id, "completed": True}
        self.receipt = {"schema": "tcc-n20-r2-receipt/v1", "status": "verified",
                        "run_id": self.b.run_id, "bucket": self.b.bucket, "key": self.b.key,
                        "nodes": 20, "rounds": 5, "verified_own_generations": 100, "sha256": "f"*64}

    def active(self, now, **kwargs):
        return tick(self.path, now, backend=self.fake, apply=True, **kwargs)

    def test_dry_and_arm_once(self):
        before = self.path.read_bytes()
        self.assertEqual(tick(self.path, 1100, backend=self.fake)["reason"], "deadline")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.fake.calls, [])
        with self.assertRaises(FileExistsError):
            arm(self.path, self.b)
        with self.assertRaises(ValueError):
            tick(self.path, 1100, apply=True)

    def test_success_requires_receipt_key_run_and_hash(self):
        self.assertEqual(self.active(1002, local=self.local)["status"], "watching")
        for bad in ({"key": "wrong"}, {"run_id": "c" * 32}, {"sha256": ""}, {"bucket": "wrong"}):
            self.assertEqual(self.active(1003, local=self.local, receipt={**self.receipt, **bad})["status"], "watching")
        self.assertEqual(self.active(1004, local=self.local, receipt=self.receipt),
                         {"status": "stopped", "reason": "success_verified"})
        self.assertEqual(self.fake.calls, [("inspect", self.b.resource_id),
            ("stop", self.b.resource_id, self.b.run_id), ("inspect", self.b.resource_id)])

    def test_failed(self):
        result = self.active(1002, local={"run_id": self.b.run_id, "status": "failed"})
        self.assertEqual(result, {"status": "stopped", "reason": "failed"})

    def test_cancelled(self):
        self.assertEqual(self.active(1002, cancel=True)["reason"], "cancelled")

    def test_stale_and_ignored_wrong_run_heartbeat(self):
        self.assertEqual(self.active(1042, heartbeat={"run_id": "c"*32, "heartbeat_at_epoch": 1041})["reason"], "stale")

    def test_deadline_wins_despite_recent_heartbeat(self):
        self.assertEqual(self.active(1100, heartbeat={"run_id": self.b.run_id, "heartbeat_at_epoch": 1099})["reason"], "deadline")

    def test_ownership_check_blocks_stop(self):
        self.fake.resource = replace(self.fake.resource, owner_run_id="c"*32)
        self.assertTrue(self.active(1100)["alert"])
        self.assertFalse(any(item[0] == "stop" for item in self.fake.calls))

    def test_retry_no_false_success(self):
        self.fake.failure = True
        self.assertFalse(self.active(1100)["alert"])
        self.assertEqual(self.active(1101)["attempts"], 1)
        self.assertTrue(self.active(1115)["alert"])
        self.assertEqual(self.active(1130)["attempts"], 2)
        self.assertEqual(State.load(self.path).verified_phase, "")
        self.fake.resource = replace(self.fake.resource, phase="stopped")
        self.assertEqual(self.active(1140)["status"], "stopped")

    def test_local_completion_windows_upload_until_deadline(self):
        self.assertEqual(self.active(1045, local=self.local)["status"], "watching")
        self.assertEqual(self.active(1100, local=self.local)["reason"], "deadline")