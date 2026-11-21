"""Synthetic state/transport fixtures: never emit a production archive or receipt."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from . import artifact_store as store, campaign_profiles as cp, first_case_handoff as h


class FirstCaseHandoffTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="tcc-first-case-mock-")
        self.addCleanup(tmp.cleanup)
        base=Path(tmp.name).resolve()
        self.run_id="c"*32
        self.ctrl=base/"mock-controller"
        self.run=base/self.run_id
        self.ctrl.mkdir();self.run.mkdir()
        self.archive=self.run/store.CANDIDATE_ARCHIVE
        self.raw=b"synthetic fixture bytes; not a production archive"
        self.archive.write_bytes(self.raw)
        self.flow=h.FirstCaseOffline(self.ctrl,self.run,self.run_id)
        self.bucket=h.FakeBucket()
        self.facts={
            "run_kind":"official","scenario_id":h.CASE,"nodes":20,"rounds":50,"verified_own_generations":1000,
            "verified_audit_rounds":[10,20,30,40,50],"verified_ledgers":20,"verified_intentional_absences":0,
            "verified_genesis_rounds":[], **cp.scope(cp.resolve("incremental-v1")),
        }

    def test_real_validator_does_not_treat_synthetic_bytes_as_sealable(self):
        from zipfile import BadZipFile
        with self.assertRaises((ValueError,BadZipFile)):
            self.flow.seal()
        self.assertFalse((self.ctrl/h.SEAL).exists())

    def test_exact_seal_separate_roles_no_next_case(self):
        reader=self.bucket.verifier()
        with patch.object(store,"verify_archive",return_value=self.facts) as validator:
            seal=self.flow.seal()
            self.assertEqual(seal["scenario_id"],h.CASE)
            ahead=self.flow.verify_get(reader)
            self.assertEqual(ahead["status"],"unattempted")
            self.assertEqual(self.bucket.get_calls,0)
            put=self.flow.pod_put(self.bucket.writer())
            self.assertEqual(put["status"],"mock_put_ack_not_evidence")
            self.assertFalse((self.ctrl/h.PROOF).exists())
            self.assertEqual(validator.call_count,1)
            proof=self.flow.verify_get(reader)
            self.assertEqual(validator.call_count,2)
        self.assertEqual(proof["status"],"mock_get_bytes_verified")
        self.assertFalse(proof["eligible_for_next_case"])
        self.assertFalse(proof["real_r2_verified"])
        self.assertEqual(proof["schema"],h.PROOF_SCHEMA)
        self.assertNotEqual(proof["schema"],"tcc-n20-r2-receipt/v1")
        self.assertEqual(self.archive.read_bytes(),self.raw)

    def test_missing_corrupt_then_get_only_after_restart(self):
        self.bucket.lose_put_ack=True # Existing remote bytes, lost ACK.
        with patch.object(store,"verify_archive",return_value=self.facts):
            self.flow.seal()
            self.assertEqual(self.flow.pod_put(self.bucket.writer())["status"],"mock_put_ambiguous_get_only")
            restart=h.FirstCaseOffline(self.ctrl,self.run,self.run_id)
            self.assertEqual(restart.pod_put(self.bucket.writer())["status"],"already_attempted_get_only")
            self.assertEqual(self.bucket.put_calls,1)
            self.bucket.hide_get=True
            self.assertEqual(restart.verify_get(self.bucket.verifier())["status"],"missing")
            self.bucket.hide_get=False
            self.bucket.get_override=b"x"*len(self.raw)
            self.assertEqual(restart.verify_get(self.bucket.verifier())["status"],"bytes_mismatch")
            self.assertFalse((self.ctrl/h.PROOF).exists())
            self.bucket.get_override=None
            self.assertEqual(restart.verify_get(self.bucket.verifier())["status"],"mock_get_bytes_verified")
            self.assertEqual(self.bucket.get_calls,3)
        self.assertEqual(self.archive.read_bytes(),self.raw)

    def test_rejects_other_case_wrong_audits_and_untrusted_callbacks(self):
        for changes in ({"scenario_id":"e4-c0-m20-p10-exact-u00-s0"},{"verified_audit_rounds":[]},
                        {"profile_sha256":"0"*64},{"verified_own_generations":999}):
            with patch.object(store,"verify_archive",return_value={**self.facts,**changes}):
                with self.assertRaises(ValueError):
                    self.flow.seal()
        cb=Mock()
        with self.assertRaises(ValueError): self.flow.pod_put(cb)
        with self.assertRaises(ValueError): self.flow.verify_get(cb)
        cb.assert_not_called()
        self.assertFalse((self.ctrl/h.SEAL).exists())

    def test_local_mutation_and_torn_intent_fail_closed(self):
        with patch.object(store,"verify_archive",return_value=self.facts):
            self.flow.seal()
            self.archive.write_bytes(b"corrupt local")
            with self.assertRaises(ValueError):
                self.flow.pod_put(self.bucket.writer())
            self.assertFalse((self.ctrl/h.INTENT).exists())
            self.archive.write_bytes(self.raw)
            (self.ctrl/h.INTENT).write_bytes(b"{")
            self.assertEqual(self.flow.pod_put(self.bucket.writer())["status"],"already_attempted_get_only")
            with self.assertRaises(ValueError):
                self.flow.verify_get(self.bucket.verifier())
        self.assertEqual(self.bucket.put_calls,0)
        self.assertEqual(self.bucket.get_calls,0)
