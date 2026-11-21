"""HTTP fixture and ephemeral keys; no R2, Cloudflare, RunPod or GPU."""
import base64
from dataclasses import asdict, replace
from io import BytesIO
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from . import artifact_store as store, incremental_warm_journal as warm
from . import incremental_external_controller as control, incremental_first_transfer as transfer
from . import incremental_first_observer as observer, incremental_transport as tx, r2_pilot_prompt
from . import incremental_first_live as live
from .incremental_batch_protection import BatchProtection
from .test_incremental_first_live import fixture


class Reply(BytesIO):
    status=200


class ControllerTests(unittest.TestCase):
    def setUp(self):
        p=shutil.which("openssl")
        w=Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
        if not p and w.is_file():
            p=str(w)
        if not p:
            self.skipTest("OpenSSL missing")
        self.openssl=Path(p).resolve(strict=True)
        d=tempfile.TemporaryDirectory(prefix="tcc-external-controller-test-")
        self.addCleanup(d.cleanup)
        self.root=Path(d.name).resolve(strict=True)
        self.now=int(time.time())
        self.clock=patch.object(control.time,"time",side_effect=lambda:self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        t,e,self.profile=fixture()
        t.update(opened_at=self.now-900,stop_at=self.now-900+4*3600-300,hard_deadline=self.now-900+4*3600)
        self.t=t
        self.cold={k:t[k] for k in live.TRUST_KEYS-{"durable_root","snapshot","service_uid"}}
        self.cold=dict(e,**self.cold,armed_at_ms=(t["opened_at"]+100)*1000)
        self.cold["sleep"]={**e["sleep"],"end":live._iso(t["stop_at"])}
        a=BatchProtection(*(t[k] for k in ("batch_id","resource_id","owner_id","datacenter_id",
            "pod_name","git_sha","profile_sha256","opened_at","stop_at","hard_deadline")),
            600,180,2_000_000,0,10_000_000)
        self.keys={}
        self.pems={}
        for role in ("observer","lease","readback","publication"):
            self.keys[role]=self.root/(role+".isolated-fixture-key")
            self.exec("genpkey","-algorithm","ED25519","-out",self.keys[role])
            if os.name=="posix":
                self.keys[role].chmod(0o600)
            self.pems[role]=self.exec("pkey","-in",self.keys[role],"-pubout")
        self.pins={role:store.sha(warm._key_der(pem)) for role,pem in self.pems.items()}
        self.scope=warm.Scope(a,self.cold["workflow_instance_id"],t["workflow_version"],t["worker_version"],
                         self.pins["lease"],self.pins["readback"])
        self.approved=store.json_bytes({"schema":observer.PLAN_SCHEMA,"linux_trust":t,"run_id":e["run_id"],
             "worker_deployment_id":"f721260c-fedf-4fda-ad01-5544d2c49de6",
             "observer_spki_sha256":self.pins["observer"],"terminal_pub_key":None})
        self.endpoint="https://"+"a"*32+".r2.cloudflarestorage.com"
        self.approval=store.sha(store.json_bytes({"schema":control.APPROVAL,"scope_sha256":self.scope.digest,
              "observer_sha256":store.sha(self.approved),"endpoint":self.endpoint,
              "publication_spki_sha256":self.pins["publication"]}))
        self.controller=self.reopen()
        # Route the live controller into fixture provider observations only.
        # Actual publication and journal authorization signatures are still used.
        op=patch.object(observer,"_collect",side_effect=self.observe)
        op.start()
        self.addCleanup(op.stop)
        self.gets=0
        op=patch.object(tx,"tls_opener",return_value=self.local_get)
        op.start()
        self.addCleanup(op.stop)
        b=BytesIO()
        with ZipFile(b,"w") as z:
            z.writestr(store.MANIFEST,store.json_bytes({"git_sha":t["git_sha"]}))
        self.archive=b.getvalue()
        self.remote=self.archive
        self.next_id="94882c58afa745a1b069c2be10a34856"
        facts={"scenario_id":transfer.CASE,"campaign_id":self.profile["schema"],
            "profile_sha256":t["profile_sha256"],"run_kind":"official","nodes":20,"rounds":50,
            "verified_own_generations":1000,"verified_ledgers":20,"verified_audit_rounds":transfer.AUDITS,
            "verified_genesis_rounds":[],"verified_intentional_absences":0}
        # Real transport compares downloaded byte count and digest (bad bytes fail).
        # Scientific semantic facts in this focused state-machine test are fixtures.
        op=patch.object(store,"verify_archive",return_value=facts)
        op.start()
        self.addCleanup(op.stop)

    def exec(self,*args):
        return subprocess.run([str(self.openssl),*map(str,args)],check=True,capture_output=True,timeout=4).stdout

    def reopen(self):
        authority=warm.Authorities(self.scope,self.pems["lease"],self.pems["readback"],self.openssl)
        j=warm.Journal(self.root/"control.sqlite",authority,clock=lambda:self.now)
        return control.Controller(j,self.root,self.approved,store.sha(self.approved),self.endpoint,
              self.pins["publication"],self.approval,self.keys["observer"],self.keys["lease"],self.keys["readback"])

    def observe(self,plan,cf,pod):
        self.assertEqual((cf,pod),("cf-fixture","pod-fixture"))
        self.assertEqual(plan["linux_trust"],self.t)
        e={**self.cold,"observed_at":self.now,"expires_at":self.now+60}
        return live.verify_evidence(e,self.t,now=self.now,profile=self.profile)

    def local_get(self,req,*,timeout):
        self.assertEqual(req.get_method(),"GET")
        self.assertGreater(timeout,0)
        self.gets+=1
        return Reply(self.remote)

    def setup_first(self):
        first=self.controller.first(cf_read_token="cf-fixture",pod_read_token="pod-fixture")
        e=first["first_lease"]["evidence"]
        release=transfer.PinnedRelease(
            *(self.t[k] for k in ("batch_id","resource_id","owner_id","datacenter_id",
              "pod_name","git_sha","profile_sha256")), e["run_id"],e["guard_observation_sha256"],
            self.scope.guard_instance_id,self.scope.guard_version_id,self.t["stop_at"])
        pub=self.pems["publication"]
        tr=transfer.TransferTrust(release,pub,store.sha(pub),self.endpoint,self.openssl)
        self.now+=20
        record=self.controller.seal_first(archive=self.archive,transfer_trust=tr)
        key=f"tcc/prod/incremental-v1/n20-{release.run_id}.zip"
        get=r2_pilot_prompt._presign("GET",host=self.endpoint[8:],path="/tcc/"+key,
              region="auto",access_key_id="A"*32,secret_key="B"*64,
              now=datetime.fromtimestamp(self.now,timezone.utc),expires=40)
        e={"schema":transfer.SCHEMA,"release":asdict(release),"method":"GET","scenario_id":transfer.CASE,
             "campaign_id":self.profile["schema"],"bucket":"tcc","key":key,
             "sha256":record["sha256"],"size":record["size"],"deadline":self.now+50,"observed_at":self.now,
             "guard_phase":"running","sleep_name":"absolute-batch-cutoff","sleep_end":release.stop_at,
             "url_sha256":store.sha(get.encode("ascii"))}
        envelope=observer._sign(e,self.keys["publication"],self.openssl,self.pins["publication"])
        return tr,envelope,get

    def second(self,tr,envelope,url,**override):
        return self.controller.second(**{"next_run_id":self.next_id,"transfer_trust":tr,"get_envelope":envelope,
                "get_url":url,"cf_read_token":"cf-fixture","pod_read_token":"pod-fixture",**override})

    def test_only_after_authenticated_get_journal_commits_and_signs_relay_once(self):
        tr,grant,url=self.setup_first()
        self.controller=self.reopen()
        out=self.second(tr,grant,url)
        self.assertEqual(self.gets,1)
        self.assertEqual(set(out),{"readback","next_lease","committed"})
        a=self.controller.journal.authorities
        r,rd=a.validate(out["readback"],warm.GET,self.now)
        g,gd=a.validate(out["next_lease"],warm.LEASE,self.now)
        committed=out["committed"]["evidence"]
        self.assertEqual(committed,{"schema":control.COMMITTED,"scope_sha256":self.scope.digest,
            "receipt_sha256":rd,"lease_sha256":gd,"index":1,"run_id":self.next_id,
            "committed_at":self.now,"expires_at":min(r["expires_at"],g["expires_at"])})
        sig=base64.b64decode(out["committed"]["signature_ed25519_base64"])
        real=subprocess.run
        with patch.object(live.subprocess,"run",side_effect=lambda args,**kwargs:real([str(self.openssl),*args[1:]],**kwargs)):
            live._verify_signature(committed,sig,self.pems["lease"])
        self.assertEqual([(x["idx"],x["run_id"],x["receipt_sha"]) for x in self.reopen().journal.status()],
             [(0,tr.release.run_id,rd),(1,self.next_id,None)])
        self.assertEqual(store.json_bytes(out),(self.root/control.RELAY_FILE).read_bytes())
        with self.assertRaises(ValueError):
            self.second(tr,grant,url)
        self.assertEqual(self.gets,1)

    def test_untrusted_or_corrupt_readback_or_wrong_pin_can_never_issue_relay(self):
        tr,grant,url=self.setup_first()
        clean=self.controller.journal.status()
        with self.assertRaises(ValueError):
            self.second(tr,{"schema":transfer.READBACK,"status":"verified"},url)
        with self.assertRaises(ValueError):
            self.second(tr,grant,url,next_run_id=tr.release.run_id)
        with self.assertRaises(ValueError):
            replace(self.controller,approval_sha256="f"*64)
        self.assertEqual(self.gets,0)
        self.remote=b"x"*len(self.archive)
        with self.assertRaises(tx.TransferError):
            self.second(tr,grant,url)
        self.assertEqual(self.gets,1)
        self.assertEqual(self.controller.journal.status(),clean)
        self.assertFalse((self.root/control.RELAY_FILE).exists())
