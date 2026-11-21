"""Small regressions for the isolated same-host runner transport seam."""
from pathlib import Path
import unittest
from unittest.mock import Mock

from .warm_batch import _transfer_steps


class TestCandidateRunner(unittest.TestCase):
    def setUp(self):
        self.context={"run_id":"a"*32,"scenario_id":"a","key":"fixture-only","sha256":"c"*64,
                      "profile_sha256":"d"*64,"campaign_id":"offline","size":1,"deadline":99,"bucket":"tcc"}
        keys=("run_id","scenario_id","key","sha256","campaign_id","profile_sha256")
        self.intent={**{k:self.context[k] for k in keys},"bytes":1}
        self.out=Path("unused")

    def transfer(self, state, put, get, intent=None):
        return _transfer_steps(claim_upload=lambda:{"status":state,"fixture_intent":intent or self.intent},
                               pod_upload=put,verify_transfer=get,out=self.out,**self.context)

    def test_get_only_never_repeats_put(self):
        put,get=Mock(),Mock(return_value=b"X")
        self.assertEqual(self.transfer("get_only",put,get),(self.intent,b"X"))
        put.assert_not_called()
        get.assert_called_once_with(self.out,**self.context)

    def test_missing_receipt_is_not_replaced_by_a_successful_put_ack(self):
        put,get=Mock(return_value={"status":"success"}),Mock(return_value=None)
        self.assertEqual(self.transfer("mock_put_reserved_once",put,get),(self.intent,None))
        put.assert_called_once()
        get.assert_called_once()

    def test_ambiguous_accepted_put_can_only_get(self):
        put,get=Mock(side_effect=TimeoutError()),Mock(return_value=b"X")
        self.assertEqual(self.transfer("mock_put_reserved_once",put,get),(self.intent,b"X"))
        put.assert_called_once()
        get.assert_called_once()

    def test_foreign_transfer_key_never_dispatches(self):
        put,get=Mock(),Mock()
        with self.assertRaisesRegex(ValueError,"exact-object"):
            self.transfer("mock_put_reserved_once",put,get,{**self.intent,"key":"wrong"})
        put.assert_not_called()
        get.assert_not_called()
