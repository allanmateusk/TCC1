from io import BytesIO
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from . import artifact_store as store, incremental_linux_bridge as bridge

RID="f721260cfedf4fdaad015544d2c49de2"
NEXT="82e2415e840a4aacb77e712bd08670ca"
H="a"*64
NOW=1000


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.body=b"synthetic local test; no model and no provider"
        self.cur={"index":0,"run_id":RID,"scenario_id":"fixture-case","case_deadline":2000}
        s=NS(digest=H,allocation=NS(resource_id="fixture-pod",stop_at=3000),case_limit=20)
        self.service=bridge.Bridge(s,object(),self.cur,None,b"fake",None,1234,9)
        tick=patch.object(bridge.time,"time",return_value=NOW)
        tick.start()
        self.addCleanup(tick.stop)

    def request(self,op,run_id=RID,**kw):
        return store.json_bytes(dict(schema=bridge.BRIDGE,operation=op,
            scope_sha256=H,resource_id="fixture-pod",run_id=run_id,**kw))

    def test_two_way_caps_and_reject_extra_fields(self):
        self.assertEqual(bridge._read_stream(BytesIO(b"hey").read,3),b"hey")
        with self.assertRaises(ValueError):
            bridge._read_stream(BytesIO(b"longer").read,3)
        for bad in (self.request("get_url"),self.request("fetch_archive",path="/etc/shadow"),
                    self.request("fetch_archive",run_id="../../etc/passwd")):
            with self.assertRaises(ValueError):
                bridge._parse(bad)

    def test_only_active_scope_and_archive_bytes_for_fetch(self):
        with patch.object(self.service,"_verified_archive",return_value=self.body) as read:
            self.assertEqual(self.service.handle(self.request("fetch_archive")),self.body)
            with self.assertRaises(ValueError):
                self.service.handle(self.request("fetch_archive",run_id=NEXT))
            read.assert_called_once()

    def test_only_verified_put_is_queued_and_never_repeat(self):
        request=self.request("send_put",frame={"put_envelope":{},"put_url":"redacted-fixture-only"})
        signed=NS(sha256=store.sha(self.body),size=len(self.body))
        with patch.object(self.service,"_verified_archive",return_value=self.body),patch.object(
            self.service,"_trust"),patch.object(bridge.transfer,"_authorize_envelope",return_value=(signed,None,None)) as verify, \
            patch.object(bridge.os,"fpathconf",create=True,return_value=4096),patch.object(
                bridge.os,"write",side_effect=lambda fd,raw:len(raw)) as pipe:
            self.assertEqual(self.service.handle(request),b"QUEUED\n")
            with self.assertRaisesRegex(ValueError,"No repeat"):
                self.service.handle(request)
            pipe.assert_called_once()
            self.assertEqual(verify.call_args.args[-1],"PUT")
        self.assertEqual(self.service.put_attempted,{RID})

    def test_relay_exact_index_and_signed_local_seal_before_install(self):
        new={"index":1,"run_id":NEXT,"case_deadline":2200,"expires_at":1050}
        relay={"fixture":"no real envelope"}
        req=self.request("install_relay",run_id=NEXT,index=1,relay=relay)
        raw=store.json_bytes(relay)
        with patch.object(self.service,"_verified_archive",return_value=self.body),patch.object(
            bridge,"verify_transition",side_effect=ValueError("Bad signed fixture")),patch.object(bridge,"_install") as fs:
            with self.assertRaisesRegex(ValueError,"Bad signed"):
                self.service.handle(req)
            fs.assert_not_called()
        with patch.object(self.service,"_verified_archive",return_value=self.body),patch.object(
            bridge,"verify_transition",return_value=new) as check,patch.object(bridge,"_install") as fs:
            self.assertEqual(self.service.handle(req),(store.sha(raw)+"\n").encode("ascii"))
            fs.assert_called_once_with(1,raw,1234)
            self.assertEqual(check.call_args.kwargs["seal"].sha256,store.sha(self.body))
            with self.assertRaises(ValueError):
                self.service.handle(self.request("install_relay",run_id=NEXT,index=20,relay=relay))
        with patch.object(bridge.first,"_root_only",return_value=raw),patch.object(bridge,"_install") as fs:
            self.assertEqual(self.service.handle(req),(store.sha(raw)+"\n").encode("ascii"))
            fs.assert_not_called()

    def test_default_platform_rejects_before_creating_or_launching_anything(self):
        with patch.object(bridge.sys,"platform","win32"),patch.object(
            bridge.subprocess,"Popen",side_effect=AssertionError("No runtime")):
            with self.assertRaisesRegex(ValueError,"root supervisor"):
                bridge.serve()
