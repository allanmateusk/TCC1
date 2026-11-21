import base64
from copy import deepcopy
from email.message import Message
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from . import artifact_store as store, incremental_first_live as live, incremental_first_observer as observer
from .test_incremental_first_live import fixture

CF_TOKEN = "cf-fixture-not-a-token"
POD_TOKEN = "pod-fixture-not-a-token"


class Reply(BytesIO):
    status=200
    def __init__(self, body, url):
        super().__init__(store.json_bytes(body))
        self.url=url
        self.headers=Message()
        self.headers["Content-Type"]="application/json"
    def geturl(self):
        return self.url


class ObserverTests(unittest.TestCase):
    def setUp(self):
        t,e,self.profile=fixture()
        now=int(time.time())
        t.update(opened_at=now-900,stop_at=now-900+4*3600-300,hard_deadline=now-900+4*3600)
        self.t=t
        self.instance=e["workflow_instance_id"]
        self.plan={"schema":observer.PLAN_SCHEMA,"linux_trust":t,"run_id":e["run_id"],
                   "worker_deployment_id":"f721260c-fedf-4fda-ad01-5544d2c49de6",
                   "observer_spki_sha256":"a"*64,"terminal_pub_key":None}
        payload=observer._payload(t,self.instance)
        self.responses={
            "workflow":{"id":t["workflow_id"],"name":observer.CF_WORKFLOW,"script_name":observer.CF_WORKER,
                        "class_name":observer.CF_CLASS},
            "version":{"id":t["workflow_version"],"workflow_id":t["workflow_id"],
                       "class_name":observer.CF_CLASS,"language":"javascript"},
            "deployment":{"id":self.plan["worker_deployment_id"],"strategy":"percentage",
                          "versions":[{"version_id":t["worker_version"],"percentage":100}]},
            "arm":{"status":"complete","error":None,"output":{"batch":self.instance,"pod":t["resource_id"],
                    "stopAt":payload["stopAt"],"deadline":payload["deadline"],"gitSha":t["git_sha"],
                    "profileSha256":t["profile_sha256"],"workerVersion":t["worker_version"],
                    "armedAtMs":(t["opened_at"]+120)*1000+7}},
            "instance":{"status":"running","versionId":t["workflow_version"],"end":None,"error":None,
                        "params":payload,"steps":[{"name":observer.ARM,"type":"step","success":True},
                            {"name":observer.SLEEP,"type":"sleep","finished":False,"error":None,
                             "end":payload["stopAt"]}]},
            "account":{"id":t["owner_id"],"email":"fixture@example.invalid"},
            "pod":{"id":t["resource_id"],"name":t["pod_name"],"dataCenterId":t["datacenter_id"],
                   "status":"RUNNING","cloud":"SECURE","actions":["stop","terminate"],
                   "startedAt":live._iso(t["opened_at"]), "env":{"secret":"not-output"}},
        }
        self.calls=[]
        self.wrap_arm=False
        self.redirect=False
        op=patch.object(observer,"_opener",return_value=self.local_open)
        op.start()
        self.addCleanup(op.stop)

    def local_open(self, request, *, timeout):
        uri=urlsplit(request.full_url)
        self.assertEqual(request.get_method(),"GET")
        self.assertEqual(uri.scheme,"https")
        self.assertLessEqual(timeout,3)
        if uri.hostname==observer.CF_HOST:
            self.assertEqual(request.get_header("Authorization"),"Bearer "+CF_TOKEN)
            base=f"/client/v4/accounts/{self.t['cloudflare_account_id']}"
            wf=f"{base}/workflows/{observer.CF_WORKFLOW}"
            inst=f"{wf}/instances/{self.instance}"
            dep=f"{base}/workers/scripts/{observer.CF_WORKER}/deployments/{self.plan['worker_deployment_id']}"
            key={wf:"workflow",f"{wf}/versions/{self.t['workflow_version']}":"version",
                 dep:"deployment",inst:"instance",inst+"/step":"arm"}[uri.path]
            self.assertEqual(parse_qs(uri.query),{"name":[observer.ARM],"type":["step"]} if key=="arm" else {})
            raw=self.responses[key]
            if key!="arm" or self.wrap_arm:
                raw={"success":True,"errors":[],"result":raw}
        else:
            self.assertEqual(uri.hostname,observer.RUNPOD_HOST)
            self.assertEqual(request.get_header("Authorization"),"Bearer "+POD_TOKEN)
            key={"/v2/account":"account",f"/v2/pods/{self.t['resource_id']}":"pod"}[uri.path]
            raw=self.responses[key]
        self.calls.append(key)
        return Reply(raw,"https://not-a-provider.invalid" if self.redirect else request.full_url)

    def collect(self):
        return observer._collect(self.plan,CF_TOKEN,POD_TOKEN)

    def test_exact_reads_accept_both_step_response_shapes(self):
        for wrap in (False,True):
            with self.subTest(wrap=wrap):
                self.wrap_arm=wrap
                self.calls.clear()
                e=self.collect()
                self.assertEqual(self.calls,["workflow","version","deployment","arm","account","pod","instance"])
                self.assertEqual(e["schema"],"tcc-incremental-first-case-trusted-observation/v2")
                self.assertEqual(e["armed_at_ms"],self.responses["arm"]["output"]["armedAtMs"])
                self.assertEqual(live.verify_evidence(e,self.t,now=time.time(),profile=self.profile),e)
                self.assertNotIn("fixture@example.invalid",str(e))
                self.assertNotIn("not-output",str(e))

    def test_untrusted_rollout_runtime_wake_or_provider_never_signs(self):
        for key,path,value in (
            ("deployment",["versions"],[{"version_id":"wrong","percentage":100}]),
            ("arm",["output","workerVersion"],"unsupported"),
            ("arm",["output","armedAtMs"],(self.t["opened_at"]+301)*1000),
            ("arm",["status"],"running"), ("arm",["output"],"[REDACTED]"),
            ("instance",["versionId"],"wrong"), ("instance",["params","gitSha"],"bad"),
            ("instance",["steps",1,"end"],live._iso(self.t["stop_at"]+1)),
            ("instance",["steps",1,"finished"],True), ("instance",["status"],"queued"),
            ("account",["id"],"wrong"), ("pod",["actions"],["terminate"]),
            ("pod",["cloud"],"COMMUNITY"), ("pod",["status"],"EXITED"), ("pod",["startedAt"],None),
            ("pod",["startedAt"],live._iso(self.t["opened_at"]-1)),
        ):
            with self.subTest(key=key,path=path):
                original=deepcopy(self.responses)
                self.addCleanup(setattr,self,"responses",original)
                entry=self.responses[key]
                for segment in path[:-1]:
                    entry=entry[segment]
                entry[path[-1]]=value
                raw=store.json_bytes(self.plan)
                with patch.object(observer,"_sign") as signer,self.assertRaises(ValueError):
                    observer.collect_and_sign(approved_bytes=raw,approved_sha256=store.sha(raw),
                         cloudflare_read_token=CF_TOKEN,runpod_read_token=POD_TOKEN,key=None,openssl=None)
                signer.assert_not_called()
                self.responses=original

    def test_redirect_and_unapproved_plan_do_not_sign(self):
        raw=store.json_bytes(self.plan)
        with patch.object(observer,"_sign") as signer,self.assertRaisesRegex(ValueError,"digest"):
            observer.collect_and_sign(approved_bytes=raw,approved_sha256="b"*64,
                 cloudflare_read_token=CF_TOKEN,runpod_read_token=POD_TOKEN,key=None,openssl=None)
        self.assertEqual(self.calls,[])
        signer.assert_not_called()
        self.redirect=True
        with self.assertRaisesRegex(ValueError,"Unverified provider"):
            self.collect()
        self.assertEqual(self.calls,["workflow"])

    def test_fixture_crypto_matches_linux_consumer_and_wrong_pin_prohibits_signing(self):
        found=shutil.which("openssl")
        if not found and os.name=="nt":
            fallback=Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
            if fallback.is_file():
                found=str(fallback)
        if not found:
            self.skipTest("No installed OpenSSL")
        openssl=Path(found).resolve(strict=True)
        ev=self.collect()
        # An ephemeral non-operational key; never write evidence to an admission path.
        with tempfile.TemporaryDirectory(prefix="tcc-not-live-observer-") as tmp:
            d=Path(tmp).resolve(strict=True)
            key=d/"not-live-key.pem"
            def cmd(*args):
                return subprocess.run([str(openssl),*map(str,args)],check=True,capture_output=True,timeout=5).stdout
            cmd("genpkey","-algorithm","ED25519","-out",key)
            if os.name=="posix":
                key.chmod(0o600)
            pem=cmd("pkey","-in",key,"-pubout")
            der=cmd("pkey","-in",key,"-pubout","-outform","DER")
            self.plan["observer_spki_sha256"]=store.sha(der)
            raw=store.json_bytes(self.plan)
            with self.assertRaisesRegex(ValueError,"approved Ed25519"):
                observer._sign(ev,key,openssl,"b"*64)
            result=observer.collect_and_sign(approved_bytes=raw,approved_sha256=store.sha(raw),
                cloudflare_read_token=CF_TOKEN,runpod_read_token=POD_TOKEN,key=key,openssl=openssl)
            real=subprocess.run
            def fixture_cli(original,**kwargs):
                return real([str(openssl),*original[1:]],**kwargs)
            with patch.object(live.subprocess,"run",side_effect=fixture_cli):
                live._verify_signature(result["evidence"],base64.b64decode(result["signature_ed25519_base64"]),pem)
