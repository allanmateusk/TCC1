from datetime import datetime, timezone
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from . import campaign_profiles as cp, incremental_transport as tx, r2_pilot_prompt as signer, artifact_store as store

CFG = {"endpoint":"https://" + "a"*32 + ".r2.cloudflarestorage.com",
       "bucket":"tcc","region":"auto","prefix":"tcc/prod"}
RAW = b"offline-only-zip-fixture"
RID = "b"*32
KEY = f"tcc/prod/incremental-v1/n20-{RID}.zip"


class Response(io.BytesIO):
    status=200


class TransportTest(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.out = Path(self.directory.name).resolve(strict=True)
        p = cp.resolve("incremental-v1")
        self.case = tx.Scope(RID,p["scenarios"][0]["id"],**cp.scope(p),
                             bucket="tcc",key=KEY,sha256=store.sha(RAW),size=len(RAW),
                             deadline=time.time()+180)
        self.now = datetime.now(timezone.utc)
        self.put, self.get = signer._create_urls(CFG,KEY,"A"*32,"B"*64,self.now,key_pattern=tx.KEY)
        facts = {**self.case.proof_fields(),"run_kind":"official","nodes":20,"rounds":50,
                 "verified_own_generations":1000}
        verify = patch.object(store,"verify_archive",return_value=facts)
        verify.start()
        self.addCleanup(verify.stop)

    def upload(self, opener, *, grant=None, authorize=lambda *_: True, raw=RAW):
        return tx.pod_put_once(self.case,raw,CFG,grant or self.put,self.out,
                               authorize=authorize,opener=opener,now=self.now)

    def test_put_is_conditional_and_not_receipt_get_is_independent(self):
        methods=[]
        def op(req, *, timeout):
            methods.append(req.get_method())
            if req.get_method()=="PUT":
                self.assertEqual(req.get_header("If-none-match"),"*")
                self.assertEqual(req.data,RAW)
                return Response()
            self.assertIsNone(req.data)
            return Response(RAW)
        self.assertEqual(self.upload(op),"put_ack_not_verified")
        self.assertEqual(methods,["PUT"])
        verified=tx.verify_get(self.case,CFG,self.get,authorize=lambda _, method:method=="GET",opener=op,now=self.now)
        self.assertEqual(methods,["PUT","GET"])
        self.assertEqual(verified["sha256"],store.sha(RAW))

    def test_uncertain_write_is_not_retried(self):
        calls=[]
        def op(req, *, timeout):
            calls.append(req.get_method())
            raise HTTPError(req.full_url,503,"fixture",None,None)
        self.assertEqual(self.upload(op),"ambiguous_get_only")
        self.assertEqual(self.upload(op),"already_attempted_get_only")
        self.assertEqual(calls,["PUT"])

    def test_no_operation_without_owner_grant_or_on_modified_bytes(self):
        def op(*_,**__):
            self.fail("unexpected network call")
        with self.assertRaises(tx.TransferError):
            self.upload(op,authorize=lambda *_:False)
        with self.assertRaises(ValueError):
            self.upload(op,grant=self.get)
        with self.assertRaises(tx.TransferError):
            self.upload(op,raw=bytes(len(RAW)))
        self.assertEqual(list(self.out.iterdir()),[])

    def test_get_does_not_certify_wrong_or_missing_bytes(self):
        for raw in (bytes(len(RAW)),b""):
            with self.assertRaises(tx.TransferError):
                tx.verify_get(self.case,CFG,self.get,authorize=lambda *_:True,
                              opener=lambda *_,**__:Response(raw),now=self.now)
