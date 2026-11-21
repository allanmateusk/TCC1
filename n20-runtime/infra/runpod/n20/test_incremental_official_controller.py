"""Full official controller regression using sealed synthetic bytes and fake HTTPS."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
from io import BytesIO
import uuid
from unittest.mock import patch
from zipfile import ZipFile

from . import artifact_store as store, campaign_profiles as cp, incremental_transport as tx
from . import incremental_external_controller as controller, incremental_first_transfer as transfer
from . import incremental_first_observer as observer, incremental_warm_journal as warm, r2_pilot_prompt
from . import incremental_warm_live as runtime
from . import test_incremental_external_controller as previous


class OfficialControllerTests(previous.ControllerTests):
    # Reuse existing key/material helpers without running inherited test methods.
    test_only_after_authenticated_get_journal_commits_and_signs_relay_once=None
    test_untrusted_or_corrupt_readback_or_wrong_pin_can_never_issue_relay=None
    test_case_two_role_upload_and_independent_get_terminal_no_third=None

    def setUp(self):
        super().setUp()
        self.qualification=self.controller
        self.short_digest=self.scope.digest
        self.scope=replace(self.scope,mode=warm.OFFICIAL)
        self.assertNotEqual(self.scope.digest,self.short_digest)
        self.approval=store.sha(store.json_bytes({"schema":controller.APPROVAL,"scope_sha256":self.scope.digest,
              "observer_sha256":store.sha(self.approved),"endpoint":self.endpoint,
              "publication_spki_sha256":self.pins["publication"]}))
        self.controller=self.full_reopen()
        self.profile=cp.resolve("incremental-v1")

    def full_reopen(self):
        a=warm.Authorities(self.scope,self.pems["lease"],self.pems["readback"],self.openssl)
        j=warm.Journal(self.root/"full.sqlite",a,clock=lambda:self.now)
        return controller.Controller(j,self.root,self.approved,store.sha(self.approved),self.endpoint,
            self.pins["publication"],self.approval,self.keys["observer"],self.keys["lease"],self.keys["readback"])

    def lease0(self):
        return self.controller.first(cf_read_token="cf-fixture",pod_read_token="pod-fixture")["first_lease"]["evidence"]

    @staticmethod
    def case_uuid(index):
        return uuid.UUID(int=1000+index,version=4).hex

    def setup_current(self, lease):
        i=lease["index"]
        self.now+=3
        rel=transfer.FullCaseRelease(*(self.t[k] for k in ("batch_id","resource_id","owner_id","datacenter_id",
                    "pod_name","git_sha","profile_sha256")),lease["run_id"],lease["guard_observation_sha256"],
                    self.scope.guard_instance_id,self.scope.guard_version_id,self.t["stop_at"],
                    self.scope.digest,i,lease["case_deadline"])
        pub=self.pems["publication"]
        trust=transfer.TransferTrust(rel,pub,store.sha(pub),self.endpoint,self.openssl)
        b=BytesIO()
        with ZipFile(b,"w") as z:
            z.writestr(store.MANIFEST,store.json_bytes({"git_sha":self.t["git_sha"],"index":i}))
        blob=b.getvalue()
        row=next(r for r in self.profile["scenarios"] if r["id"]==rel.case)
        p=cp.plan(self.profile,row,0,50)
        facts={"scenario_id":rel.case,"campaign_id":self.profile["schema"],
               "profile_sha256":rel.profile_sha256,"run_kind":"official","nodes":20,"rounds":50,
               "verified_own_generations":1000,"verified_ledgers":20,"verified_audit_rounds":p["planned_rounds"],
               "verified_genesis_rounds":p["genesis_rounds"],
               "verified_intentional_absences":sum(map(len,p["simulated_absences"].values()))}
        with patch.object(store,"verify_archive",return_value=facts):
            seal=self.controller.seal_full_case(archive=blob,transfer_trust=trust)
        oid=f"tcc/prod/incremental-v1/n20-{rel.run_id}.zip"
        def grant(method):
            url=r2_pilot_prompt._presign(method,host=self.endpoint[8:],path="/tcc/"+oid,region="auto",
                          access_key_id="A"*32,secret_key="B"*64,
                          now=datetime.fromtimestamp(self.now,timezone.utc),expires=30)
            ev={"schema":transfer.FULL_SCHEMA,"release":asdict(rel),"method":method,"scenario_id":rel.case,
                "campaign_id":self.profile["schema"],"bucket":"tcc","key":oid,"sha256":seal["sha256"],
                "size":seal["size"],"observed_at":self.now,"deadline":min(self.now+50,rel.case_deadline),
                "guard_phase":"running","sleep_name":"absolute-batch-cutoff","sleep_end":rel.stop_at,
                "url_sha256":store.sha(url.encode("ascii"))}
            return observer._sign(ev,self.keys["publication"],self.openssl,self.pins["publication"]),url
        return trust,facts,blob,grant

    def accept(self,trust,grant,url,nextid):
        return self.controller.accept_full_case(transfer_trust=trust,get_envelope=grant,get_url=url,
              cf_read_token="cf-fixture",pod_read_token="pod-fixture",next_run_id=nextid)

    def test_all_twenty_in_order_on_same_pod_last_receipt_no_twenty_first(self):
        lease=self.lease0()
        with self.assertRaises(ValueError):
            self.qualification.seal_full_case(archive=b"x",transfer_trust=None)
        for i,case in enumerate(self.scope.case_ids):
            with self.subTest(index=i,case=case):
                self.assertEqual((lease["index"],lease["scenario_id"]),(i,case))
                tr,facts,blob,grant=self.setup_current(lease)
                self.assertEqual(tr.release.resource_id,self.t["resource_id"])
                self.remote=blob
                if i in (0,2,19):
                    with self.assertRaises(ValueError):
                        transfer.verify_second_at_controller(trust=tr,get_envelope={},get_url="",receipt_dir=self.root)
                with patch.object(store,"verify_archive",return_value=facts):
                    gp,url=grant("GET")
                    if i==0:
                        with self.assertRaises(ValueError):
                            self.accept(tr,gp,url,lease["run_id"])
                    if i==19:
                        with self.assertRaises(ValueError):
                            self.accept(tr,gp,url,self.case_uuid(20))
                    r=self.accept(tr,gp,url,self.case_uuid(i+1) if i<19 else None)
                if i<19:
                    approvers=self.controller.journal.authorities
                    opened=runtime.verify_transition(approvers,r,prior=lease,
                        seal=runtime.Seal(lease["run_id"],case,store.sha(blob),len(blob)),now=self.now)
                    self.assertEqual(opened,r["next_lease"]["evidence"])
                    self.assertTrue((self.root/f"warm-transition-{i+2:02d}.json").is_file())
                    self.assertFalse((self.root/controller.FULL_FINAL_FILE).exists())
                    lease=opened
                else:
                    e=r["verified"]["evidence"]
                    self.assertEqual(e["verified_cases"],20)
                    self.assertFalse(e["next_case_authorized"])
                    self.assertFalse(e["stop_authorized"])
                    self.assertEqual([item["scenario_id"] for item in r["receipt_set"]],list(self.scope.case_ids))
                    self.assertEqual(e["receipt_set_sha256"],store.sha(store.json_bytes(r["receipt_set"])))
                    self.assertTrue((self.root/controller.FULL_FINAL_FILE).is_file())
                    with self.assertRaises(ValueError):
                        self.accept(tr,gp,url,None)
        status=self.full_reopen().journal.status()
        self.assertEqual(len(status),20)
        self.assertEqual(self.gets,20)
        self.assertTrue(all(r["receipt_sha"] for r in status))
        self.assertFalse((self.root/"warm-transition-21.json").exists())

    def test_definitive_corrupt_content_halts_and_cannot_be_replaced_after_restart(self):
        lease=self.lease0()
        tr,facts,blob,grant=self.setup_current(lease)
        self.remote=bytes(len(blob))
        gp,url=grant("GET")
        with self.assertRaises(tx.ReadbackMismatch):
            self.accept(tr,gp,url,self.case_uuid(1))
        stopped=self.full_reopen()
        self.assertEqual(stopped.journal.failure(),{"run_id":lease["run_id"],"reason":"corrupt_readback"})
        self.controller=stopped
        self.remote=blob
        with self.assertRaisesRegex(ValueError,"halted"):
            self.accept(tr,gp,url,self.case_uuid(1))
        self.assertEqual(self.gets,1)
        self.assertEqual(len(stopped.journal.status()),1)

    def test_short_scope_cannot_even_validate_signed_third_lease(self):
        a=self.qualification.journal.authorities
        e={"schema":warm.LEASE,"scope_sha256":a.scope.digest,"index":2,"scenario_id":warm.IDS[2],
           "run_id":self.case_uuid(2),"observed_at":self.now,"expires_at":self.now+60,
           "guard_observation_sha256":"1"*64,"case_deadline":self.now+600,"prior_readback_sha256":"2"*64}
        proof=observer._sign(e,self.keys["lease"],self.openssl,self.pins["lease"])
        with self.assertRaisesRegex(ValueError,"ordered"):
            a.validate(proof,warm.LEASE,self.now)
