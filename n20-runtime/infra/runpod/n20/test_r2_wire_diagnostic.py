from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from . import incremental_transport as wire, r2_wire_diagnostic as diag

CFG={"endpoint":"https://"+"a"*32+".r2.cloudflarestorage.com","bucket":"tcc",
     "region":"auto","prefix":"tcc/piloto"}
NOW=datetime(2026,1,1,tzinfo=timezone.utc)


class Body(BytesIO):
    status=200


class WireDiagnosticTest(unittest.TestCase):
    def setUp(self):
        scratch=TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root=Path(scratch.name).resolve()/"diagnostic"
        result=diag.prepare(CFG,self.root,now=int(NOW.timestamp()))
        self.assertEqual(result["status"],"prepared_diagnostic_only")
        self.d=diag.Diagnostic(CFG,self.root,now=NOW.timestamp())
        # Distinct fixture-only issuer identities for role separation.
        self.put=self.d.signed_verb("PUT","A"*32,"B"*64,NOW)
        self.get=self.d.signed_verb("GET","C"*32,"D"*64,NOW)
        self.body=diag._payload(self.d.run_id)

    def test_two_roles_use_create_only_before_put_and_verified_independent_get(self):
        verbs=[]
        def put(req,*,timeout):
            verbs.append(req.get_method())
            self.assertEqual(req.get_header("If-none-match"),"*")
            self.assertEqual(req.get_header("Content-type"),"text/plain")
            self.assertEqual(req.data,self.body)
            self.assertEqual(len(list(self.root.glob("*.r2-put-intent.json"))),1)
            return Body()
        def get(req,*,timeout):
            verbs.append(req.get_method())
            self.assertIsNone(req.data)
            return Body(self.body)
        sent=self.d.execute("PUT",self.put,opener=put,utc=NOW)
        self.assertEqual(sent["status"],"put_ack_not_verified")
        self.assertNotIn("X-Amz",str(sent))
        got=self.d.execute("GET",self.get,opener=get,utc=NOW)
        self.assertEqual(verbs,["PUT","GET"])
        self.assertEqual(got["status"],"verified_diagnostic_only")
        self.assertFalse(got["production_evidence"])
        self.assertFalse(got["eligible_for_next_case"])
        self.assertNotEqual(got["schema"],wire.RECEIPT)
        self.assertFalse(wire.KEY.fullmatch(got["key"]))

    def test_ambiguous_put_does_not_send_twice_and_readback_retries_bounded(self):
        write=[]
        def lost(req,*,timeout):
            write.append(req.get_method())
            raise HTTPError(req.full_url,412,"fixture",None,None)
        self.assertEqual(self.d.execute("PUT",self.put,opener=lost,utc=NOW)["status"],"ambiguous_get_only")
        self.assertEqual(self.d.execute("PUT",self.put,opener=lost,utc=NOW)["status"],"already_attempted_get_only")
        self.assertEqual(write,["PUT"])
        reads=[]
        def get(req,*,timeout):
            reads.append(req.get_method())
            if len(reads)<3:
                raise HTTPError(req.full_url,404,"fixture",None,None)
            return Body(self.body)
        with patch.object(wire.time,"sleep"):
            self.assertEqual(self.d.execute("GET",self.get,opener=get,utc=NOW)["status"],"verified_diagnostic_only")
        self.assertEqual(reads,["GET"]*3)

    def test_wrong_digest_role_prod_key_and_foreign_account_never_advance(self):
        def deny(*_a,**_kw):
            self.fail("No request is permitted")
        with self.assertRaises(ValueError):
            self.d.execute("PUT",self.get,opener=deny,utc=NOW)
        with self.assertRaises(ValueError):
            self.d.execute("GET",self.put,opener=deny,utc=NOW)
        with self.assertRaises(ValueError):
            self.d.execute("GET",self.get.replace(self.d.key,"tcc/prod/incremental-v1/n20-"+self.d.run_id+".zip"),
                           opener=deny,utc=NOW)
        with self.assertRaises(ValueError):
            self.d.execute("GET",self.get,opener=lambda *a,**kw:Body(b"!"*len(self.body)),utc=NOW)
        with self.assertRaises(ValueError):
            diag.Diagnostic({**CFG,"endpoint":CFG["endpoint"].replace("a"*32,"b"*32)},self.root,now=NOW.timestamp())
        with self.assertRaises(ValueError):
            diag.Diagnostic(CFG,self.root,now=NOW.timestamp()+900)
