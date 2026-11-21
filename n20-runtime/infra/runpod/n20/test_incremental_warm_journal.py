"""Synthetic signed warm-journal transitions, no provider, cloud, model or scheduler."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import base64
import concurrent.futures
import shutil
import subprocess
import unittest

from . import campaign_profiles as cp
from .artifact_store import json_bytes, sha
from .incremental_batch_protection import BatchProtection
from .incremental_campaign import IDS
from .incremental_warm_journal import Authorities, GET, Journal, LEASE, Scope, _key_der

T=1767323045  # historical fixture; cannot be a deployment release
BATCH="c6bf221c77624be3bf5eb61cd5ab8e44"
RUN1="f721260cfedf4fdaad015544d2c49de2"
RUN2="82e2415e840a4aacb77e712bd08670ca"


class WarmJournalTest(unittest.TestCase):
    def setUp(self):
        path=shutil.which("openssl")
        win=Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
        if not path and win.is_file():
            path=str(win)
        if not path:
            self.skipTest("Existing OpenSSL not installed")
        self.openssl=Path(path).resolve(strict=True)
        tmp=TemporaryDirectory(prefix="n20-journal-fixture-")
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve()
        self.now=T+10
        p=BatchProtection(BATCH,"fixture-pod","fixture-owner","TEST-1","tcc-n20-batch-"+BATCH,"1"*40,
              cp.digest(cp.resolve("incremental-v1")),T,T+17700,T+18000,600,120,3_000_000,0,16_000_000)
        # In-memory role names are explicit; no service, API key, or real release exists.
        observer,reader,rogue=(self._ephemeral(role) for role in ("observer","reader","rogue"))
        self.scope=Scope(p,"c6bf221c-7762-4be3-bf5e-b61cd5ab8e44",
               "95119e3c-d95e-4b62-8236-8ff2401b07d0","0b352f1f-6846-414f-aea2-dc08a6a67663",
               sha(_key_der(observer)),sha(_key_der(reader)))
        self.trust=Authorities(self.scope,observer,reader,self.openssl)
        self.j=Journal(self.root/"fixture.sqlite",self.trust,clock=lambda:self.now)

    def _openssl(self,*args):
        return subprocess.run([str(self.openssl),*args],capture_output=True,check=True,timeout=5).stdout

    def _ephemeral(self,role):
        path=self.root/(role+".fixture-key")
        self._openssl("genpkey","-algorithm","ED25519","-out",str(path))
        return self._openssl("pkey","-in",str(path),"-pubout")

    def _sign(self,evidence,role):
        payload=self.root/"test-statement"
        payload.write_bytes(json_bytes(evidence))
        signed=self._openssl("pkeyutl","-sign","-inkey",str(self.root/(role+".fixture-key")),
                            "-rawin","-in",str(payload))
        return {"evidence":evidence,"signature_ed25519_base64":base64.b64encode(signed).decode("ascii")}

    def base(self,kind,index,run):
        return dict(schema=kind,scope_sha256=self.scope.digest,index=index,scenario_id=IDS[index],run_id=run,
                    observed_at=self.now,expires_at=self.now+30)

    def lease(self,index,run,prior=None,**fields):
        return self._sign({**self.base(LEASE,index,run),"guard_observation_sha256":"2"*64,
                           "case_deadline":self.now+500,"prior_readback_sha256":prior,**fields},"observer")

    def get(self,index,run,*,role="reader",**fields):
        return self._sign({**self.base(GET,index,run),"method":"GET","bucket":"tcc",
                    "key":f"tcc/prod/incremental-v1/n20-{run}.zip","sha256":"3"*64,"size":1234,
                    "verified_own_generations":1000,"verified_ledgers":20,"rounds":50,"nodes":20,
                    "archive_verified":True,"independent_get":True,**fields},role)

    @staticmethod
    def hash_proof(value):
        return sha(json_bytes(value["evidence"]))

    def sealed_first(self):
        self.j.first(self.lease(0,RUN1))
        self.now+=20
        self.j.seal_active(RUN1,sha256="3"*64,size=1234)
        self.now+=10

    def test_two_cases_atomic_advance_unchanged_pod_and_restart_of_controller_state(self):
        self.sealed_first()
        get=self.get(0,RUN1)
        nxt=self.lease(1,RUN2,self.hash_proof(get))
        self.now+=1
        self.assertEqual(self.j.transition(get,nxt),self.hash_proof(nxt))
        j2=Journal(self.root/"fixture.sqlite",self.trust,clock=lambda:self.now)
        self.assertEqual([(r["idx"],r["run_id"],r["receipt_sha"]) for r in j2.status()],
                         [(0,RUN1,self.hash_proof(get)),(1,RUN2,None)])
        with self.assertRaises(ValueError):
            j2.transition(get,nxt)

    def test_missing_corrupt_wrong_key_old_first_receipt_and_invalid_seals_do_not_advance(self):
        self.sealed_first()
        current=self.j.status()
        good=self.get(0,RUN1)
        corrupt={**good,"evidence":{**good["evidence"],"sha256":"0"*64}}
        wrong_digest_signed=self.get(0,RUN1,sha256="0"*64)
        wrong_authority=self.get(0,RUN1,role="observer")
        old={"schema":"tcc-incremental-first-case-independent-readback/v1","eligible_for_next_case":False}
        next=self.lease(1,RUN2,self.hash_proof(good))
        for bad in (None,corrupt,wrong_digest_signed,wrong_authority,old):
            with self.subTest(bad=bad is not None),self.assertRaises(ValueError):
                self.j.transition(bad,next)
            self.assertEqual(self.j.status(),current)
        with self.assertRaises(ValueError):
            self.j.seal_active(RUN1,sha256="a"*64,size=1234)

    def test_reuse_uuid_changed_allocation_skipped_case_and_receipt_chain_denied(self):
        self.sealed_first()
        good=self.get(0,RUN1)
        altered=replace(self.scope,allocation=replace(self.scope.allocation,resource_id="other-fixture"))
        other=Authorities(altered,self.trust.lease_pem,self.trust.readback_pem,self.openssl)
        with self.assertRaises(ValueError):
            Journal(self.root/"fixture.sqlite",other,clock=lambda:self.now)
        for bad in (self.lease(1,RUN1,self.hash_proof(good)),self.lease(1,RUN2,"0"*64),
                    self.lease(1,RUN2,self.hash_proof(good),scope_sha256=altered.digest),
                    self.lease(2,RUN2,self.hash_proof(good))):
            with self.assertRaises(ValueError):
                self.j.transition(good,bad)
        self.assertEqual(len(self.j.status()),1)

    def test_two_concurrent_identical_dispatches_record_one_lease(self):
        self.sealed_first()
        get=self.get(0,RUN1)
        nxt=self.lease(1,RUN2,self.hash_proof(get))
        def attempt():
            try:
                self.j.transition(get,nxt)
                return True
            except ValueError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(lambda _:attempt(),range(2))),[False,True])
        self.assertEqual(len(self.j.status()),2)

    def test_expired_receipt_and_no_unsealed_or_expired_protected_case_never_advance(self):
        self.j.first(self.lease(0,RUN1))
        started=self.j.status()
        get=self.get(0,RUN1)
        next=self.lease(1,RUN2,self.hash_proof(get))
        with self.assertRaises(ValueError):
            self.j.transition(get,next)
        self.j.seal_active(RUN1,sha256="3"*64,size=1234)
        self.now+=31
        with self.assertRaises(ValueError):
            self.j.transition(get,next)
        self.now=T+510
        fresh=self.get(0,RUN1)
        with self.assertRaises(ValueError):
            self.j.transition(fresh,self.lease(1,RUN2,self.hash_proof(fresh)))
        self.assertEqual(self.j.status(),started)


    def _accepted_relay(self):
        from .incremental_warm_live import COMMITTED, Seal
        started=self.lease(0,RUN1)
        self.j.first(started)
        self.now+=1
        self.j.seal_active(RUN1,sha256="3"*64,size=1234)
        self.now+=1
        get=self.get(0,RUN1)
        nxt=self.lease(1,RUN2,self.hash_proof(get))
        lease_sha=self.j.transition(get,nxt)
        commit=self._sign(dict(schema=COMMITTED,scope_sha256=self.scope.digest,receipt_sha256=self.hash_proof(get),
           lease_sha256=lease_sha,index=1,run_id=RUN2,committed_at=self.now,expires_at=self.now+15),"observer")
        return started["evidence"],Seal(RUN1,IDS[0],"3"*64,1234),{"readback":get,"next_lease":nxt,"committed":commit}

    def test_runtime_requires_committed_signature_and_unchanged_seal(self):
        from .incremental_warm_live import verify_transition
        prior,seal,relay=self._accepted_relay()
        self.assertEqual(verify_transition(self.trust,relay,prior=prior,seal=seal,now=self.now)["run_id"],RUN2)
        for bad in (None,{k:v for k,v in relay.items() if k!="committed"},
                    {**relay,"committed":self._sign(relay["committed"]["evidence"],"rogue")}):
            with self.assertRaises(ValueError):
                verify_transition(self.trust,bad,prior=prior,seal=seal,now=self.now)
        for invalid in (replace(seal,sha256="6"*64),replace(seal,size=1233),replace(seal,run_id=RUN2)):
            with self.assertRaises(ValueError):
                verify_transition(self.trust,relay,prior=prior,seal=invalid,now=self.now)
        with self.assertRaises(ValueError):
            verify_transition(self.trust,relay,prior=prior,seal=seal,now=self.now+16)

    def test_default_platform_gate_stops_before_any_resident(self):
        from unittest.mock import patch
        from . import incremental_warm_live as live
        with patch.object(live.first.sys,"platform","win32"),patch.object(
                live,"ResidentPool",side_effect=AssertionError("No GPU path may be reached")):
            with self.assertRaisesRegex(ValueError,"Protected Linux"):
                live.supervise_two_cases()
