import contextlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from . import artifact_store as store, incremental_warm_live as live, incremental_warm_start as start
from .incremental_campaign import IDS


class BootstrapTest(unittest.TestCase):
    def test_no_start_even_with_flags_before_protected_linux(self):
        with patch.object(live.first.sys,"platform","win32"),patch.object(
                live,"ResidentPool",side_effect=AssertionError("No CUDA before admission")),patch.dict(
                start.os.environ,{"TCC_LIVE_N20_APPROVED":"true","TCC_N20_RESIDENT_QUALIFIED":"true"}):
            with self.assertRaisesRegex(ValueError,"Protected Linux"):
                start.prepare(8)

    def test_full_runner_refuses_missing_relay_before_resident(self):
        # Only the method seam is mocked; no credential or runtime context is created.
        fake=object.__new__(live.WarmAdmission)
        fake.full=True
        with patch.object(live,"ResidentPool",side_effect=AssertionError("No CUDA before relay")):
            with self.assertRaisesRegex(ValueError,"publication gate"):
                live.supervise_full_campaign(admission=fake)

    def test_frame_protocol_has_only_put_and_validates_limits(self):
        self.assertEqual(start._decode_frame(b'{"put_envelope":{},"put_url":"fixture"}')["put_url"],"fixture")
        for bad in (b"",b"x"*(start.MAX_FRAME+1),b'{"get_url":"fixture","put_envelope":{}}',
                    b'{"put_envelope":{},"put_url":"x","put_url":"y"}'):
            with self.subTest(), self.assertRaises(ValueError):
                start._decode_frame(bad)

    def test_pipe_bounded_split_frame_and_unexpected_close(self):
        relay=object.__new__(start.PutRelay)
        relay._admission=SimpleNamespace(check=lambda:None,current={"case_deadline":2000})
        relay._pending=bytearray()
        relay._fd=8
        relay._poll=Mock()
        relay._poll.poll.return_value=[(8,1)]
        with patch.object(start.time,"time",return_value=1000),patch.object(
                start.os,"read",side_effect=[b'{"put_envelope":{},',b'"put_url":"fake"}\n']):
            with patch.multiple(start.select,create=True,POLLERR=8,POLLNVAL=32):
                self.assertEqual(relay._receive()["put_url"],"fake")
        with patch.object(start.time,"time",return_value=1000),patch.object(start.os,"read",return_value=b""):
            with patch.multiple(start.select,create=True,POLLERR=8,POLLNVAL=32):
                with self.assertRaisesRegex(ValueError,"closed"):
                    relay._receive()

    def test_signed_put_receiver_logs_no_grant_and_ack_never_verifies_get(self):
        relay=object.__new__(start.PutRelay)
        admission=SimpleNamespace(check=lambda:None,current={"run_id":"fixture","scenario_id":IDS[0]})
        relay._admission=admission
        body=b"fixture not a zip"
        seal=live.Seal("fixture",IDS[0],store.sha(body),len(body))
        relay._trust=lambda: "fixture_trust_not_production"
        frame={"put_envelope":{"fixture":True},"put_url":"DO_NOT_LOG_FIXTURE_GRANT"}
        relay._receive=lambda:frame
        with patch.object(live,"_read_sealed_zip",return_value=body),patch.object(
                start.transfer,"publish_full_case_from_pod",return_value="ambiguous_get_only") as offline, \
                contextlib.redirect_stdout(io.StringIO()) as logs:
            relay.publish(admission,seal,"fixture-dir")
        offline.assert_called_once()
        self.assertEqual(offline.call_args.kwargs["archive"],body)
        self.assertEqual(frame,{})
        self.assertNotIn("DO_NOT_LOG",logs.getvalue())
        self.assertFalse(json.loads(logs.getvalue().splitlines()[-1])["independent_get_verified"])
        with patch.object(live,"_read_sealed_zip",return_value=body+b"!"),patch.object(
                start.transfer,"publish_full_case_from_pod",side_effect=AssertionError("No network")):
            with self.assertRaisesRegex(ValueError,"changed"):
                relay.publish(admission,seal,"fixture-dir")
