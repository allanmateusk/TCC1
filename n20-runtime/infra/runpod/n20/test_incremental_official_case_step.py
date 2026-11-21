"""External case dispatch with ephemeral signing and simulated SSH/R2."""
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from . import artifact_store as store, incremental_official_case_step as step
from . import incremental_transport as tx
from . import test_incremental_official_controller as fixture


class StepTests(fixture.OfficialControllerTests):
    test_all_twenty_in_order_on_same_pod_last_receipt_no_twenty_first=None
    test_definitive_corrupt_content_halts_and_cannot_be_replaced_after_restart=None
    test_short_scope_cannot_even_validate_signed_third_lease=None

    def setUp(self):
        super().setUp()
        ssh=self.root/"ssh.exe"
        ssh.write_bytes(b"not an executable; subprocess is not invoked in this fixture")
        identity=self.root/"not-a-private-key"
        identity.write_bytes(b"public test text")
        self.known=self.root/"only-known-host"
        self.known.write_bytes(b"[fixture.invalid]:2200 ssh-ed25519 AAAA\n")
        self.pod=self.controller._scope.allocation.resource_id
        known_hash=store.sha(self.known.read_bytes())
        public={"schema":step.BRIDGE,"scope_sha256":self.scope.digest,"resource_id":self.pod,
                "host":"fixture.invalid","port":2200,"user":"testonly","known_hosts_sha256":known_hash}
        self.bridge=step.OpenSSH(self.scope.digest,self.pod,"fixture.invalid",2200,"testonly",ssh,identity,
                    self.known,known_hash,store.sha(store.json_bytes(public)))
        self.dispatch=step.CaseStep(self.controller,self.bridge,self.keys["publication"],self.pems["publication"])
        self.put_role=step.StorageRole("W"*32,"S"*64)
        self.get_role=step.StorageRole("R"*32,"T"*64)

    def execute(self,next_run_id):
        return self.dispatch.execute(write_role=self.put_role,read_role=self.get_role,
                cf_read_token="cf-fixture",pod_read_token="pod-fixture",next_run_id=next_run_id)

    def test_lost_put_and_relay_ack_recovers_only_get_and_same_committed_bytes(self):
        lease=self.lease0()
        tr,facts,archive,_=self.setup_current(lease)
        ledger=[]
        seen=[]
        arrival=False
        install_confirm=False
        def bridge(b,cap):
            self.assertEqual(b["schema"],step.BRIDGE)
            self.assertEqual((b["scope_sha256"],b["resource_id"]),(self.scope.digest,self.pod))
            op=b["operation"]
            ledger.append(op)
            if op=="fetch_archive":
                self.assertEqual((cap,b["run_id"]),(store.MAX_ZIP,lease["run_id"]))
                return archive
            if op=="send_put":
                self.assertEqual(set(b["frame"]),{"put_envelope","put_url"})
                put=b["frame"]
                self.assertEqual(put["put_envelope"]["evidence"]["method"],"PUT")
                self.assertTrue(parse_qs(urlsplit(put["put_url"]).query)["X-Amz-Credential"][0].startswith("W"*32+"/"))
                self.assertEqual(put["put_envelope"]["evidence"]["sha256"],store.sha(archive))
                return b"LOST\n"
            if op=="install_relay":
                self.assertEqual((b["index"],b["run_id"]),(1,self.case_uuid(1)))
                raw=store.json_bytes(b["relay"])
                seen.append(raw)
                return (store.sha(raw)+"\n").encode("ascii") if install_confirm else b"unverified\n"
            self.fail("Unexpected bridge operation")
        def r2(req,*,timeout):
            self.assertEqual(req.get_method(),"GET")
            self.assertTrue(parse_qs(urlsplit(req.full_url).query)["X-Amz-Credential"][0].startswith("R"*32+"/"))
            if not arrival:
                raise HTTPError(req.full_url,404,"fixture",None,None)
            return fixture.previous.Reply(archive)
        with patch.object(step.OpenSSH,"_invoke",autospec=True,side_effect=lambda _self,b,cap:bridge(b,cap)), \
                 patch.object(tx,"tls_opener",return_value=r2),patch.object(store,"verify_archive",return_value=facts), \
                 patch.object(tx.time,"sleep"):
            with self.assertRaises(tx.TransferError):
                self.execute(self.case_uuid(1))
            self.assertEqual(ledger,["fetch_archive","send_put"])
            self.assertEqual(len(self.controller.journal.status()),1)
            arrival=True
            with self.assertRaisesRegex(ValueError,"relay install"):
                self.execute(self.case_uuid(1))
            self.assertEqual(ledger,["fetch_archive","send_put","install_relay"])
            self.assertEqual(len(self.controller.journal.status()),2)
            with self.assertRaisesRegex(ValueError,"Deliver"):
                self.execute(self.case_uuid(2))
            install_confirm=True
            self.dispatch.deliver_existing(index=1)
            self.assertEqual(ledger,["fetch_archive","send_put","install_relay","install_relay"])
            self.assertEqual(seen[0],seen[1])
        self.assertTrue((self.root/"warm-transition-02.json.delivered.json").is_file())
        for path in self.root.glob("*.json"):
            data=path.read_bytes()
            self.assertNotIn(b"X-Amz",data)
            self.assertNotIn(b"S"*64,data)
            self.assertNotIn(b"T"*64,data)

    def test_strict_host_key_and_no_third_party_credential_identity(self):
        result=self.bridge._args()
        self.assertIn("StrictHostKeyChecking=yes",result)
        self.assertIn("IdentityAgent=none",result)
        self.assertEqual(result[-2:],["testonly@fixture.invalid","tcc-official-case-bridge"])
        with self.assertRaisesRegex(ValueError,"distinct"):
            self.dispatch.execute(write_role=self.put_role,read_role=self.put_role,cf_read_token=None,pod_read_token=None)
        self.known.write_bytes(b"[fixture.invalid]:2200 ssh-ed25519 CHANGED\n")
        with self.assertRaisesRegex(ValueError,"host key"):
            self.bridge._args()
