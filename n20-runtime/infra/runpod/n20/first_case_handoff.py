"""OFFLINE-ONLY first incremental case -> one simulated PUT -> separate GET.

This is not an uploader or admission gate. It has no network/process/client
dependencies and accepts only memory-backed fake transport. No case is released.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from . import artifact_store as store, campaign_profiles as cp

CASE = "e4-c0-m00-p10-exact-u00-s0"
AUDITS = [10,20,30,40,50]
SEAL = "first-case-offline-seal.json"
INTENT = "first-case-offline-put-intent.json"
PROOF = "first-case-offline-get-proof.json"
SEAL_SCHEMA = "tcc-n20-first-case-offline-seal/v1"
PROOF_SCHEMA = "tcc-n20-first-case-offline-get-proof/v1"


class FakeBucket:
    """Strictly in-memory; independent handles simulate separate authorization."""
    def __init__(self):
        self._bodies={}
        self.put_calls=0
        self.get_calls=0
        self.lose_put_ack=False
        self.drop_put=False
        self.hide_get=False
        self.get_override=None

    def writer(self):
        return _FixturePodPut(self)

    def verifier(self):
        return _FixtureIndependentGet(self)


class _FixturePodPut:
    def __init__(self,bucket):
        if type(bucket) is not FakeBucket:
            raise ValueError("offline fake bucket only")
        self._bucket=bucket

    def __call__(self,key,data):
        b=self._bucket
        b.put_calls+=1
        if not b.drop_put:
            if key in b._bodies:
                raise FileExistsError("fake create-only collision")
            b._bodies[key]=data
        if b.lose_put_ack or b.drop_put:
            raise TimeoutError("fake PUT outcome not known")


class _FixtureIndependentGet:
    def __init__(self,bucket):
        if type(bucket) is not FakeBucket:
            raise ValueError("offline fake bucket only")
        self._bucket=bucket

    def __call__(self,key):
        b=self._bucket
        b.get_calls+=1
        if b.hide_get:
            return None
        return b.get_override if b.get_override is not None else b._bodies.get(key)


def _read(path, *, cap):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=cap:
        raise ValueError("Missing or unsafe sealed bytes")
    with path.open("rb") as f:
        raw=f.read(cap+1)
    if not 0<len(raw)<=cap:
        raise ValueError("Unexpected sealed byte length")
    return raw


def _dir(path):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or path.resolve(strict=True)!=path:
        raise ValueError("Existing, private, absolute nonredirected directory required")
    return path


def _fixed_fields(run_id):
    profile=cp.resolve("incremental-v1")
    case=profile["scenarios"][0]
    plan=cp.plan(profile,case,0,50)
    if (case["id"],case["malicious_nodes"],case["collusion"],case["audit"],case["score"],
        case["audit_p"],case["unstable_nodes"],plan["planned_rounds"],plan["fixed_test_rounds"])!=(
        CASE,0,False,"fixed","exact",.1,0,AUDITS,AUDITS):
        raise ValueError("Unexpected first-case catalog")
    return {"schema":SEAL_SCHEMA,"run_id":run_id,"scenario_id":CASE,"nodes":20,"rounds":50,"seed":0,
            "verified_own_generations":1000,"verified_audit_rounds":AUDITS,"key":cp.candidate_key(run_id),
            **cp.scope(profile)}


def _metrics(raw,run_id):
    fixed=_fixed_fields(run_id)
    facts=store.verify_archive(raw,run_id)
    expected={k:fixed[k] for k in ("scenario_id","nodes","rounds","verified_own_generations","verified_audit_rounds",*cp.FIELDS)}
    expected.update(run_kind="official",verified_ledgers=20,verified_intentional_absences=0,verified_genesis_rounds=[])
    if any(facts.get(k)!=v for k,v in expected.items()):
        raise ValueError("Archive does not match the first incremental scenario")
    return fixed


class FirstCaseOffline:
    """Only validates already sealed bytes; cannot release another case or use R2."""
    def __init__(self,controller_dir,run_dir,run_id):
        self.controller=_dir(controller_dir)
        self.run=_dir(run_dir)
        if (self.controller==self.run or self.controller.is_relative_to(self.run)
                or self.run.is_relative_to(self.controller) or self.run.name!=run_id):
            raise ValueError("Controller state must be separate and the source bound to UUID")
        self.fixed=_fixed_fields(run_id)
        self.run_id=run_id

    def _archive(self):
        return _read(self.run/store.CANDIDATE_ARCHIVE,cap=store.MAX_ZIP)

    def _record(self,name):
        return json.loads(_read(self.controller/name,cap=16*1024))

    def _sealed(self):
        v=self._record(SEAL)
        if (not isinstance(v,dict) or set(v)!=set(self.fixed)|{"sha256","bytes"}
            or any(v.get(k)!=x for k,x in self.fixed.items()) or not isinstance(v.get("sha256"),str)
            or not cp.HEX.fullmatch(v["sha256"]) or type(v.get("bytes")) is not int or not 0<v["bytes"]<=store.MAX_ZIP):
            raise ValueError("Protected local seal does not match the first case")
        return v

    @staticmethod
    def _matches(raw,seal):
        return (type(raw) is bytes and len(raw)==seal["bytes"]
                and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),seal["sha256"]))

    def seal(self):
        """An independent expected digest of the already-sealed local ZIP."""
        raw=self._archive()
        fixed=_metrics(raw,self.run_id)
        record={**fixed,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        store.write_atomic(self.controller/SEAL,store.json_bytes(record))
        return record

    def pod_put(self,writer):
        """Reserve once before callback. Any ambiguity is reconciled by GET only."""
        if type(writer) is not _FixturePodPut:
            raise ValueError("No network writer accepted; fixture writer only")
        seal=self._sealed()
        raw=self._archive()
        if not self._matches(raw,seal):
            raise ValueError("Candidate is no longer the sealed ZIP")
        intent=self.controller/INTENT
        try:
            with intent.open("xb") as h:
                h.write(store.json_bytes(seal))
                h.flush()
                os.fsync(h.fileno())
            store._sync_dir(self.controller)
        except FileExistsError:
            return {"status":"already_attempted_get_only","eligible_for_next_case":False}
        try:
            writer(seal["key"],raw)
            return {"status":"mock_put_ack_not_evidence","eligible_for_next_case":False}
        except (TimeoutError,FileExistsError):
            return {"status":"mock_put_ambiguous_get_only","eligible_for_next_case":False}

    def verify_get(self,reader):
        """Independently compare exact bytes. No eligible success can leave this test."""
        if type(reader) is not _FixtureIndependentGet:
            raise ValueError("No network reader accepted; fixture reader only")
        seal=self._sealed()
        if not (self.controller/INTENT).exists():
            return {"status":"unattempted","eligible_for_next_case":False}
        if self._record(INTENT)!=seal:
            raise ValueError("Corrupt/torn PUT intent; preserve evidence and stop")
        raw=reader(seal["key"])
        if raw is None:
            return {"status":"missing","eligible_for_next_case":False}
        if not self._matches(raw,seal):
            return {"status":"bytes_mismatch","eligible_for_next_case":False}
        _metrics(raw,self.run_id)
        proof={**seal,"source_schema":SEAL_SCHEMA,"schema":PROOF_SCHEMA,
               "status":"mock_get_bytes_verified","real_r2_verified":False,"eligible_for_next_case":False}
        store.write_atomic(self.controller/PROOF,store.json_bytes(proof))
        return proof
