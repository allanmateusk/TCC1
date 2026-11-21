from dataclasses import asdict, replace
from base64 import b64encode
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from zipfile import ZipFile

from . import artifact_store as store, campaign_profiles as cp, incremental_first_transfer as first
from . import incremental_transport as tx, r2_pilot_prompt as signer


def openssl():
    candidate = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    return Path(candidate).resolve(strict=True)


class Reply(BytesIO):
    status=200


class FirstTransferTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory(prefix="tcc-first-transfer-test-")
        self.addCleanup(d.cleanup)
        self.root=Path(d.name).resolve()
        self.pod=self.root/"pod"
        self.pod.mkdir()
        self.reader=self.root/"reader"
        self.reader.mkdir()
        self.now=int(time.time())
        rid="c"*32
        self.release=first.PinnedRelease("a"*32,"test-pod","test-owner","test-dc",
            "tcc-n20-batch-"+"a"*32,"d"*40,cp.scope(cp.resolve("incremental-v1"))["profile_sha256"],
            rid,"e"*64,"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","test-workflow-version",self.now+500)
        openssl_bin=openssl()
        self.openssl=openssl_bin
        self._exec("genpkey","-algorithm","ED25519","-out",self.root/"temporary-fixture-key.pem")
        self._exec("pkey","-in",self.root/"temporary-fixture-key.pem","-pubout","-out",self.root/"fixture-pub.pem")
        pem=(self.root/"fixture-pub.pem").read_bytes()
        self.trust=first.TransferTrust(self.release,pem,store.sha(pem),
            "https://"+"1"*32+".r2.cloudflarestorage.com",openssl_bin)
        self.key=f"tcc/prod/incremental-v1/n20-{rid}.zip"
        self.put,self.get=[self.grant(verb,90) for verb in ("PUT","GET")]
        b=BytesIO()
        with ZipFile(b,"w") as z:
            z.writestr(store.MANIFEST,store.json_bytes({"git_sha":self.release.git_sha}))
        self.archive=b.getvalue()
        self.facts={"scenario_id":first.CASE,"campaign_id":cp.INCREMENTAL_SCHEMA,
            "profile_sha256":self.release.profile_sha256,"run_kind":"official","nodes":20,"rounds":50,
            "verified_own_generations":1000,"verified_ledgers":20,"verified_audit_rounds":first.AUDITS,
            "verified_genesis_rounds":[],"verified_intentional_absences":0}
        val=patch.object(store,"verify_archive",return_value=self.facts)
        val.start()
        self.addCleanup(val.stop)
        self.calls=[]
        self.remote=None
        self.lose_ack=False
        tls=patch.object(tx,"tls_opener",return_value=self.network)
        tls.start()
        self.addCleanup(tls.stop)

    def grant(self, method, expires):
        return signer._presign(method,host="1"*32+".r2.cloudflarestorage.com",path="/tcc/"+self.key,
            region="auto",access_key_id="A"*32,secret_key="B"*64,
            now=datetime.fromtimestamp(self.now,timezone.utc),expires=expires)

    def _exec(self, *args):
        subprocess.run([str(self.openssl),*map(str,args)],check=True,capture_output=True,timeout=4)

    def sign(self, evidence):
        (self.root/"message").write_bytes(store.json_bytes(evidence))
        self._exec("pkeyutl","-sign","-inkey",self.root/"temporary-fixture-key.pem","-rawin",
                   "-in",self.root/"message","-out",self.root/"signature")
        return {"evidence":evidence,"signature_ed25519_base64":b64encode(
            (self.root/"signature").read_bytes()).decode("ascii")}

    def envelope(self, method, url, **changes):
        return self.sign({"schema":first.SCHEMA,"release":asdict(self.release),"method":method,
            "scenario_id":first.CASE,"campaign_id":cp.INCREMENTAL_SCHEMA,"bucket":"tcc","key":self.key,
            "sha256":store.sha(self.archive),"size":len(self.archive),"deadline":self.now+120,
            "observed_at":self.now,"guard_phase":"running","sleep_name":"absolute-batch-cutoff",
            "sleep_end":self.release.stop_at,"url_sha256":store.sha(url.encode("ascii")),**changes})

    def network(self, req, *, timeout):
        self.calls.append(req.get_method())
        if req.get_method()=="PUT":
            self.assertEqual(req.get_header("If-none-match"),"*")
            self.remote=req.data
            if self.lose_ack:
                raise HTTPError(req.full_url,503,"fixture",None,None)
            return Reply()
        return Reply(self.remote or b"")

    def publish(self, envelope=None, url=None, archive=None):
        return first.publish_from_pod(trust=self.trust,put_envelope=envelope or self.envelope("PUT",self.put),
            put_url=url or self.put,archive=self.archive if archive is None else archive,journal_dir=self.pod)

    def verify(self, envelope=None, url=None):
        return first.verify_at_controller(trust=self.trust,get_envelope=envelope or self.envelope("GET",self.get),
            get_url=url or self.get,receipt_dir=self.reader)

    def test_roles_have_separate_grants_and_ack_not_receipt(self):
        self.assertEqual(self.publish(),"put_ack_not_verified")
        self.assertEqual(self.calls,["PUT"])
        self.assertEqual(list(self.reader.iterdir()),[])
        readback=self.verify()
        self.assertEqual(self.calls,["PUT","GET"])
        self.assertEqual(readback["schema"],first.READBACK)
        self.assertEqual(readback["sha256"],store.sha(self.archive))
        self.assertFalse(readback["eligible_for_next_case"])
        self.assertFalse(readback["eligible_for_batch_completion"])
        self.assertEqual(self.verify(),readback)

    def test_uncertain_put_reconciles_only_through_get(self):
        self.lose_ack=True
        self.assertEqual(self.publish(),"ambiguous_get_only")
        self.assertEqual(self.publish(),"already_attempted_get_only")
        self.assertEqual(self.verify()["status"],"verified")
        self.assertEqual(self.calls,["PUT","GET"])

    def test_bad_or_stale_authorizations_never_touch_transport(self):
        for problems in ({"observed_at":self.now-61},{"sleep_name":"wrong"},{"sleep_end":self.release.stop_at-1},
                         {"guard_phase":"complete"},{"scenario_id":"another-case"},
                         {"release":{**asdict(self.release),"resource_id":"another-pod"}},
                         {"sha256":"0"*64},{"deadline":self.release.stop_at+1}):
            with self.subTest(problems=problems), self.assertRaises(ValueError):
                self.publish(self.envelope("PUT",self.put,**problems))
        bad=self.envelope("PUT",self.put)
        bad["signature_ed25519_base64"]=b64encode(b"x"*64).decode("ascii")
        with self.assertRaisesRegex(ValueError,"signature"):
            self.publish(bad)
        with self.assertRaises(ValueError):
            self.publish(self.envelope("GET",self.get),url=self.get)
        with self.assertRaises(ValueError):
            self.verify(self.envelope("PUT",self.put),url=self.put)
        with self.assertRaises(ValueError):
            self.publish(archive=self.archive+b"x")
        long_url=self.grant("PUT",600)
        with self.assertRaisesRegex(ValueError,"outlives"):
            self.publish(self.envelope("PUT",long_url),url=long_url)
        with self.assertRaises(ValueError):
            replace(self.trust,authority_pem_sha256="f"*64)
        self.assertEqual(list(self.pod.iterdir()),[])
        self.assertEqual(self.calls,[])

    def test_bad_download_cannot_emit_receipt(self):
        self.publish()
        self.remote=b"x"*len(self.archive)
        with self.assertRaises(tx.TransferError):
            self.verify()
        self.assertEqual(self.calls,["PUT","GET"])
        self.assertEqual(list(self.reader.iterdir()),[])
