"""Scoped incremental R2 adapter. No CLI, grants issuance, scheduler, or release.

The Pod gets one short-lived PUT URL; a distinct process gets the GET URL.
The external controller supplies the independently sealed scope and asserts
its bound lease before these callbacks. A PUT acknowledgement is not proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from pathlib import Path
import hmac
import os
import re
import ssl
import time
from urllib.request import build_opener, HTTPSHandler, ProxyHandler, Request

from . import artifact_store as store, campaign_profiles as cp, r2_grants
from .r2_verified_pilot import _request, TransferError, Transient, ExistingObject

KEY = re.compile(r"tcc/prod/incremental-v1/n20-[a-f0-9]{32}\.zip\Z")
RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
RECEIPT = "tcc-n20-incremental-r2-readback/v1"


@dataclass(frozen=True)
class Scope:
    run_id: str
    scenario_id: str
    campaign_id: str
    profile_sha256: str
    bucket: str
    key: str
    sha256: str
    size: int
    deadline: float

    def __post_init__(self):
        if (not RUN_ID.fullmatch(self.run_id or "") or self.bucket != r2_grants.BUCKET
                or self.key != f"tcc/prod/incremental-v1/n20-{self.run_id}.zip"
                or self.campaign_id != cp.INCREMENTAL_SCHEMA
                or not cp.verify_identity(self.scenario_id,50,self.campaign_id,self.profile_sha256)
                or not cp.HEX.fullmatch(self.sha256 or "") or type(self.size) is not int
                or not 0 < self.size <= store.MAX_ZIP or type(self.deadline) not in (int,float)
                or not isfinite(self.deadline)):
            raise ValueError("Invalid immutable incremental publication scope")

    def proof_fields(self):
        return {"run_id":self.run_id,"scenario_id":self.scenario_id,
                "campaign_id":self.campaign_id,"profile_sha256":self.profile_sha256,
                "bucket":self.bucket,"key":self.key,"sha256":self.sha256,"bytes":self.size}

    def valid_bytes(self, data):
        if (type(data) is not bytes or len(data) != self.size
                or not hmac.compare_digest(store.sha(data),self.sha256)):
            raise TransferError("R2 archive bytes do not match the independent seal")
        result = store.verify_archive(data,self.run_id)
        expected = {k:self.proof_fields()[k] for k in ("scenario_id",*cp.FIELDS)}
        expected.update(run_kind="official",nodes=20,rounds=50,verified_own_generations=1000)
        if any(result.get(k) != v for k,v in expected.items()):
            raise TransferError("R2 archive does not match the scoped experiment")


def tls_opener():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return build_opener(ProxyHandler({}),HTTPSHandler(context=ctx),r2_grants._NoRedirect()).open


def _preflight(scope, config, url, method, authorize, *, now):
    # Authorization is supplied by the independent deployment, not by a flag on the Pod.
    # That deployment is still unqualified.
    if type(scope) is not Scope or not callable(authorize) or authorize(scope,method) is not True:
        raise TransferError("Independent bound release is required for this operation")
    left = scope.deadline - time.time()
    if left <= 0:
        raise TransferError("Incremental publication deadline passed")
    r2_grants.validate_config(config,"official")
    r2_grants.validate_url(config,scope.key,url,method=method,now=now,key_pattern=KEY)
    return time.monotonic() + min(left,25)


def pod_put_once(scope, data, config, put_url, journal_dir, *, authorize, opener, now=None):
    """Create-only PUT from the Pod. A persisted attempt always reconciles by GET."""
    transport_deadline = _preflight(scope,config,put_url,"PUT",authorize,now=now)
    scope.valid_bytes(data)
    return _wire_put_once(scope,data,put_url,journal_dir,content_type="application/zip",
                          opener=opener,deadline=transport_deadline)


def _wire_put_once(scope,data,put_url,journal_dir,*,content_type,opener,deadline):
    # Call only after purpose-specific scope and payload authorization.
    journal_dir = Path(journal_dir)
    if (not journal_dir.is_absolute() or journal_dir.resolve(strict=True) != journal_dir
            or not journal_dir.is_dir()):
        raise TransferError("Durable publication journal directory is required")
    intent = journal_dir / (scope.run_id + ".r2-put-intent.json")
    record = store.json_bytes(scope.proof_fields())
    try:
        with intent.open("xb") as handle:
            handle.write(record)
            handle.flush()
            os.fsync(handle.fileno())
        store._sync_dir(journal_dir)
    except FileExistsError:
        if intent.is_symlink() or not intent.is_file() or intent.stat().st_size != len(record) or intent.read_bytes() != record:
            raise TransferError("Ambiguous PUT intent: do not send or advance")
        return "already_attempted_get_only"
    try:
        request = Request(put_url,data=data,method="PUT",
                          headers={"Content-Type":content_type,"If-None-Match":"*"})
        _request(opener,request,deadline,time.monotonic,size=scope.size)
    except (Transient,ExistingObject):
        return "ambiguous_get_only"
    return "put_ack_not_verified"


def verify_get(scope, config, get_url, *, authorize, opener, now=None):
    """Use only the reader grant and independently assigned digest, not the Pod ACK."""
    transport_deadline = _preflight(scope,config,get_url,"GET",authorize,now=now)
    data=_wire_get(get_url,scope.size,opener=opener,deadline=transport_deadline)
    scope.valid_bytes(data)
    return {"schema":RECEIPT,"status":"verified",**scope.proof_fields(),
            "nodes":20,"rounds":50,"verified_own_generations":1000}


def _wire_get(get_url,size,*,opener,deadline):
    # Purpose-specific validators must recheck bytes after this bounded read.
    request = Request(get_url,method="GET")
    for delay in (0,.25,.75):
        if delay:
            time.sleep(delay)
        try:
            return _request(opener,request,deadline,time.monotonic,size=size)
        except Transient:
            continue
    raise TransferError("Independent R2 download not verified")
