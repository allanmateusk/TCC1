"""Offline tests for the first-case admission envelope; no runner or GPU loaded."""
from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from . import benchmark, campaign_profiles, incremental_first_live as live

NOW=1795400100


def fixture():
    profile,_=benchmark.load_profile("incremental-v1")
    batch="f721260cfedf4fdaad015544d2c49de2"
    t=dict(batch_id=batch,resource_id="fixture-pod",owner_id="fixture-owner",datacenter_id="TEST-1",
        pod_name="tcc-n20-batch-"+batch,git_sha="2"*40,profile_sha256=campaign_profiles.digest(profile),
        snapshot_revision=profile["model_revision"],opened_at=NOW-100,stop_at=NOW+17900,hard_deadline=NOW+18200,
        workflow_id="f721260c-fedf-4fda-ad01-5544d2c49de3",workflow_version="f721260c-fedf-4fda-ad01-5544d2c49de4",
        worker_version="f721260c-fedf-4fda-ad01-5544d2c49de5",cloudflare_account_id="a"*32,
        durable_root="/workspace/results",snapshot="/workspace/snapshot",peak_vram_mib=6200,service_uid=12345)
    e={k:t[k] for k in set(t)-{"durable_root","snapshot","service_uid"}}
    e.update(schema="tcc-incremental-first-case-trusted-observation/v2",scenario_id=live.CASE,
             run_id="82e2415e840a4aacb77e712bd08670ca",workflow_instance_id="f721260c-fedf-4fda-ad01-5544d2c49de2",
             armed_at_ms=(NOW-95)*1000+117,observed_at=NOW-5,expires_at=NOW+30,status="running",cloud="SECURE",provider_phase="RUNNING",
             stop_enabled=True,sleep=dict(name="absolute-batch-cutoff-1",type="sleep",finished=False,
                                        end=live._iso(t["stop_at"]),error=None))
    return t,e,profile


class FirstAdmissionTest(unittest.TestCase):
    def test_exact_actual_raw_wait_shape(self):
        t,e,profile=fixture()
        self.assertEqual(live.verify_evidence(e,t,now=NOW,profile=profile),e)
        e["status"]="waiting"
        self.assertEqual(live.verify_evidence(e,t,now=NOW,profile=profile),e)

    def test_late_launch_needs_early_durable_arm_with_fresh_exact_wait(self):
        t,e,profile=fixture()
        t.update(opened_at=NOW-900,stop_at=NOW-900+4*3600-300,hard_deadline=NOW-900+4*3600)
        e.update(opened_at=t["opened_at"],stop_at=t["stop_at"],hard_deadline=t["hard_deadline"],
                 armed_at_ms=(t["opened_at"]+300)*1000)
        e["sleep"]["end"]=live._iso(t["stop_at"])
        self.assertEqual(live.verify_evidence(e,t,now=NOW,profile=profile),e)
        for bad in (e["armed_at_ms"]+1,t["opened_at"]*1000-1,True):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                live.verify_evidence({**e,"armed_at_ms":bad},t,now=NOW,profile=profile)
        del e["armed_at_ms"]
        with self.assertRaises(ValueError):
            live.verify_evidence(e,t,now=NOW,profile=profile)

    def test_reject_near_stop_and_hard_deadline_below_exact_four_hours(self):
        for open_at,stop_at,hard_at in (
                (NOW-4*3600+599,NOW+299,NOW+599),
                (NOW-4*3600+1201,NOW+900,NOW+1200)):
            t,e,profile=fixture()
            t.update(opened_at=open_at,stop_at=stop_at,hard_deadline=hard_at)
            e.update(opened_at=open_at,stop_at=stop_at,hard_deadline=hard_at,armed_at_ms=open_at*1000)
            e["sleep"]["end"]=live._iso(stop_at)
            with self.subTest(remaining=stop_at-NOW,duration=hard_at-open_at),self.assertRaises(ValueError):
                live.verify_evidence(e,t,now=NOW,profile=profile)

    def test_any_binding_change_is_denied(self):
        for field,value in (("owner_id","someone"),("resource_id","other"),("git_sha","0"*40),
              ("profile_sha256","3"*64),("workflow_version","f721260c-fedf-4fda-ad01-5544d2c49de8"),
              ("workflow_instance_id","f721260c-fedf-4fda-ad01-5544d2c49de8"),("scenario_id","pilot"),
              ("provider_phase","EXITED"),("stop_enabled",1),("status","queued"),
              ("schema","tcc-cloudflare-batch-proposal-offline/v1")):
            t,e,profile=fixture()
            e[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                live.verify_evidence(e,t,now=NOW,profile=profile)

    def test_expiry_wrong_or_missing_sleep_and_unbound_input_denied(self):
        for field,value in (("finished",True),("finished",0),("end","2026-01-01T00:00:00.000Z"),
                            ("name","other"),("error","something")):
            t,e,profile=fixture()
            e["sleep"][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                live.verify_evidence(e,t,now=NOW,profile=profile)
        t,e,profile=fixture()
        with self.assertRaises(ValueError):
            live.verify_evidence(e,t,now=NOW+31,profile=profile)
        with self.assertRaises(ValueError):
            live.verify_evidence({**e,"signed":True},t,now=NOW,profile=profile)
        with self.assertRaises(ValueError):
            live._load('{"e":1,"e":2}')

    def test_env_flags_cannot_bypass_non_linux_or_missing_protection(self):
        with patch.object(live.sys,"platform","win32"),patch.dict(os.environ,{
              "TCC_LIVE_N20_APPROVED":"true","TCC_N20_OFFICIAL_QUALIFIED":"true"}),patch.object(
              benchmark,"verify_cuda_hardware",side_effect=AssertionError("CUDA must not run")):
            with self.assertRaisesRegex(ValueError,"Protected Linux"):
                live.run()

    def test_legacy_entry_still_denies_incremental_even_with_flags(self):
        profile,cases=benchmark.load_profile("incremental-v1")
        with patch.dict(os.environ,{"TCC_LIVE_N20_APPROVED":"true","TCC_N20_OFFICIAL_QUALIFIED":"true"}):
            with self.assertRaisesRegex(RuntimeError,"not qualified"):
                benchmark.live(profile,cases[live.CASE],0,Path("missing"))



    def test_crypto_rejects_self_signed_wrong_anchor_and_tampering(self):
        import shutil
        import subprocess
        import tempfile
        from . import artifact_store

        opener=shutil.which("openssl")
        if not opener and os.name=="nt":
            installed=Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
            if installed.is_file():
                opener=str(installed)
        if not opener:
            self.skipTest("No existing OpenSSL binary")
        real=subprocess.run
        def openssl(args,**kwargs):
            return real([opener,*args[1:]],**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            # Deliberately not a release envelope or admission path.
            msg={"schema":"TEST-CRYPTO-NOT-ADMISSION","expires_at":1,"body":"fixture"}
            (d/"msg").write_bytes(artifact_store.json_bytes(msg))
            for label in ("trusted","rogue"):
                real([opener,"genpkey","-algorithm","ED25519","-out",str(d/f"{label}.key")],check=True,capture_output=True)
                real([opener,"pkey","-in",str(d/f"{label}.key"),"-pubout","-out",str(d/f"{label}.pub")],
                     check=True,capture_output=True)
                real([opener,"pkeyutl","-sign","-inkey",str(d/f"{label}.key"),"-rawin","-in",str(d/"msg"),
                      "-out",str(d/f"{label}.sig")],check=True,capture_output=True)
            anchor=(d/"trusted.pub").read_bytes()
            good=(d/"trusted.sig").read_bytes()
            wrong=(d/"rogue.sig").read_bytes()
            with patch.object(live.subprocess,"run",side_effect=openssl):
                live._verify_signature(msg,good,anchor)
                with self.assertRaisesRegex(ValueError,"signature invalid"):
                    live._verify_signature(msg,wrong,anchor)
                with self.assertRaisesRegex(ValueError,"signature invalid"):
                    live._verify_signature({**msg,"body":"tampered"},good,anchor)
