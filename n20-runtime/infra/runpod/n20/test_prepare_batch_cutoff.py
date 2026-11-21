import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from . import campaign_profiles
from .prepare_batch_cutoff import GUARD, iso, no_duplicates, prepare, write_proposal

START=1_795_400_000
GIT="2"*40
BATCH="f721260cfedf4fdaad015544d2c49de2"


def fixture():
    p={"batch_id":BATCH,"resource_id":"fixture-pod","owner_id":"fixture-owner",
       "datacenter_id":"TEST-1","pod_name":"tcc-n20-batch-"+BATCH,"git_sha":GIT,
       "profile_sha256":campaign_profiles.digest(campaign_profiles.resolve("incremental-v1")),
       "opened_at":START,"stop_at":START+18000,"hard_deadline":START+18300,
       "max_attempt_seconds":600,"stale_seconds":120,"hourly_compute_microusd":3_000_000,
       "fixed_and_other_microusd":0,"approved_cap_microusd":16_000_000}
    obs={k:p[k] for k in ("batch_id","owner_id","resource_id","datacenter_id","pod_name")}
    return {"protection":p,"operator_observation":{**obs,"status":"RUNNING","cloud":"SECURE",
                                                   "stop_enabled":True,"observed_at":START+100}}


class ProposalTest(unittest.TestCase):
    def prepare(self,x):
        return prepare(x,release=GIT,source_hashes={"local":"fixture"},now=START+120)

    def test_binds_protection_and_is_never_authorizing(self):
        result=self.prepare(fixture())
        payload=result["unarmed_payload_proposal"]
        self.assertEqual(payload["batch"].replace("-",""),BATCH)
        self.assertEqual(payload["stopAt"],iso(START+18000))
        self.assertIsNone(payload["terminalPubKey"])
        for k in ("source_modified","eligible_for_live_admission","real_stop_verified","authenticated_provider_observed"):
            self.assertIs(result[k],False)

    def test_identity_phase_and_unsolicited_data_refused(self):
        for field,value in (("resource_id","other"),("owner_id","other"),("batch_id","other"),
             ("status","EXITED"),("cloud","COMMUNITY"),("stop_enabled",1),("token","fixture-not-a-secret")):
            f=fixture()
            f["operator_observation"][field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare(f)

    def test_stale_clock_revision_budget_and_margin_refused(self):
        for area,k,v in (("operator_observation","observed_at",START),("protection","git_sha","3"*40),
            ("protection","profile_sha256","9"*64),("protection","approved_cap_microusd",10),
            ("protection","hard_deadline",START+18120)):
            f=fixture(); f[area][k]=v
            with self.subTest(k=k),self.assertRaises(ValueError):
                self.prepare(f)

    def test_write_once_and_reject_live_filenames(self):
        result=self.prepare(fixture())
        with TemporaryDirectory() as scratch:
            root=Path(scratch).resolve(); out=root/"offline-proposal.json"
            write_proposal(out,result)
            self.assertEqual(json.loads(out.read_bytes()),result)
            with self.assertRaises(FileExistsError):
                write_proposal(out,{"overwrite":"no"})
            self.assertEqual(json.loads(out.read_bytes()),result)
            with self.assertRaises(ValueError):
                write_proposal(root/"controller-state.json",result)
        with self.assertRaises(ValueError):
            json.loads('{"x":1,"x":2}',object_pairs_hook=no_duplicates)

    @unittest.skipUnless(shutil.which("node"),"Node required for JS parity")
    def test_payload_shape_matches_actual_guard_pin(self):
        result=self.prepare(fixture())
        script='import {pin} from "./src/batch-guard.mjs"; const r=JSON.parse(process.argv[1]); pin(r,r,r.batch);'
        p=subprocess.run(["node","--input-type=module","-e",script,json.dumps(result["unarmed_payload_proposal"])],
                         cwd=GUARD,check=False,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
