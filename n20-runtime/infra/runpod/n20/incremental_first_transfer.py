"""Exact first-case R2 handoff. No CLI, signer, next-case grant, or provider calls.

A trusted installer must supply local immutable pins and a separate authenticated
observer/signer must attest the active release after the archive has sealed.
"""
from __future__ import annotations

from base64 import b64decode
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import BytesIO
import hmac
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile

from . import artifact_store as store, campaign_profiles as cp, incremental_transport as tx, r2_grants
from .incremental_campaign import IDS

CASE = "e4-c0-m00-p10-exact-u00-s0"
SCHEMA = "tcc-incremental-first-case-publication/v1"
READBACK = "tcc-incremental-first-case-independent-readback/v1"
AUDITS = [10, 20, 30, 40, 50]
SECOND_CASE = IDS[1]
SECOND_SCHEMA = "tcc-incremental-second-case-publication/v1"
SECOND_READBACK = "tcc-incremental-second-case-independent-readback/v1"


def _hex(value, length):
    return type(value) is str and bool(re.fullmatch(r"[0-9a-f]{%d}" % length, value))


@dataclass(frozen=True)
class PinnedRelease:
    batch_id: str
    resource_id: str
    owner_id: str
    datacenter_id: str
    pod_name: str
    git_sha: str
    profile_sha256: str
    run_id: str
    launch_evidence_sha256: str
    guard_instance_id: str
    guard_version_id: str
    stop_at: int

    def __post_init__(self):
        if (not _hex(self.batch_id, 32) or not _hex(self.run_id, 32)
                or self.run_id == self.batch_id or not _hex(self.git_sha, 40)
                or not _hex(self.launch_evidence_sha256, 64)
                or type(self.stop_at) is not int or self.stop_at <= 0
                or self.pod_name != "tcc-n20-batch-" + self.batch_id
                or self.guard_instance_id.replace("-", "") != self.batch_id
                or not cp.verify_identity(CASE, 50, cp.INCREMENTAL_SCHEMA, self.profile_sha256)
                or any(type(v) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", v)
                       for v in (self.resource_id,self.owner_id,self.datacenter_id,
                                 self.guard_instance_id,self.guard_version_id))):
            raise ValueError("Missing or inconsistent independently pinned guard release")


@dataclass(frozen=True)
class TransferTrust:
    release: PinnedRelease
    authority_pem: bytes
    authority_pem_sha256: str
    endpoint: str
    openssl: Path

    def __post_init__(self):
        if (type(self.release) is not PinnedRelease or type(self.authority_pem) is not bytes
                or not 0<len(self.authority_pem)<=256
                or not re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n", self.authority_pem)
                or not _hex(self.authority_pem_sha256,64)
                or not hmac.compare_digest(store.sha(self.authority_pem), self.authority_pem_sha256)
                or not self.openssl.is_absolute() or self.openssl.resolve(strict=True)!=self.openssl
                or not self.openssl.is_file() or self.openssl.name.lower() not in ("openssl", "openssl.exe")):
            raise ValueError("Use the separately pinned publication observer key and trusted OpenSSL")
        self.config()

    def config(self):
        return r2_grants.validate_config({"endpoint":self.endpoint,"bucket":"tcc","region":"auto",
                                          "prefix":"tcc/prod"}, "official")


def _verified_signature(trust, evidence, signature):
    encoded = store.json_bytes(evidence)
    if len(encoded)>8192 or type(signature) is not str or len(signature)!=88:
        raise ValueError("Invalid signed publication envelope")
    try:
        sig = b64decode(signature, validate=True)
    except ValueError:
        raise ValueError("Invalid signed publication envelope") from None
    if len(sig)!=64:
        raise ValueError("Invalid signed publication envelope")
    # Only public material and the signed statements (never the grant/URL) reach temp files.
    with tempfile.TemporaryDirectory(prefix="tcc-first-transfer-") as temp:
        d = Path(temp)
        for name, body in (("pub.pem",trust.authority_pem),("proof",encoded),("sig",sig)):
            (d/name).write_bytes(body)
        r = subprocess.run([str(trust.openssl),"pkeyutl","-verify","-pubin","-inkey",str(d/"pub.pem"),
                            "-rawin","-in",str(d/"proof"),"-sigfile",str(d/"sig")],
                           check=False, timeout=5, stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            raise ValueError("Publication proof signature not verified")


def _authorize_envelope(trust, envelope, url, method, *, now, case=CASE):
    schema = {CASE:SCHEMA, SECOND_CASE:SECOND_SCHEMA}[case]
    if (type(trust) is not TransferTrust or type(envelope) is not dict
            or set(envelope) != {"evidence","signature_ed25519_base64"}
            or type(url) is not str or not 0<len(url)<4096):
        raise ValueError("Exact signed publication envelope and role grant required")
    ev = envelope["evidence"]
    fields = {"schema","release","method","scenario_id","campaign_id","bucket","key","sha256","size",
              "deadline","observed_at","guard_phase","sleep_name","sleep_end","url_sha256"}
    p = trust.release
    if (type(ev) is not dict or set(ev)!=fields or ev["schema"]!=schema
            or type(ev["release"]) is not dict or ev["release"]!=asdict(p)
            or ev["method"]!=method or ev["scenario_id"]!=case
            or ev["campaign_id"]!=cp.INCREMENTAL_SCHEMA or ev["bucket"]!="tcc"
            or ev["guard_phase"] not in ("running","waiting") or ev["sleep_name"]!="absolute-batch-cutoff"
            or type(ev["sleep_end"]) is not int or ev["sleep_end"]!=p.stop_at
            or ev["url_sha256"]!=store.sha(url.encode("ascii"))
            or type(ev["observed_at"]) is not int or type(ev["deadline"]) is not int
            or not ev["observed_at"]<=now<=ev["observed_at"]+60
            or not now<ev["deadline"]<=min(p.stop_at,ev["observed_at"]+300)):
        raise ValueError("Publication proof does not match the fresh exact guard, role or grant")
    _verified_signature(trust, ev, envelope["signature_ed25519_base64"])
    scope = tx.Scope(p.run_id,case,cp.INCREMENTAL_SCHEMA,p.profile_sha256,"tcc",ev["key"],
                     ev["sha256"],ev["size"],ev["deadline"])
    cfg = trust.config()
    stamp = datetime.fromtimestamp(now, timezone.utc)
    r2_grants.validate_url(cfg,scope.key,url,method=method,now=stamp,key_pattern=tx.KEY)
    # A leaked bearer URL itself must not outlive the signed lease or guarded cutoff.
    params = parse_qs(urlsplit(url).query, strict_parsing=True, max_num_fields=10)
    issued = datetime.strptime(params["X-Amz-Date"][0], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    if issued.timestamp()+int(params["X-Amz-Expires"][0])>scope.deadline:
        raise ValueError("R2 bearer grant outlives the publication deadline")
    return scope, cfg, stamp


def _inspect_archive(data, release, case):
    if type(release) is not PinnedRelease or type(data) is not bytes or case not in (CASE,SECOND_CASE):
        raise ValueError("Exact two-case release and immutable ZIP bytes required")
    facts = store.verify_archive(data, release.run_id)
    expected = {"scenario_id":case,"campaign_id":cp.INCREMENTAL_SCHEMA,
                "profile_sha256":release.profile_sha256,"run_kind":"official","nodes":20,"rounds":50,
                "verified_own_generations":1000,"verified_ledgers":20,"verified_audit_rounds":AUDITS,
                "verified_genesis_rounds":[],"verified_intentional_absences":0}
    if case==SECOND_CASE:
        profile = cp.resolve("incremental-v1")
        row = next(r for r in profile["scenarios"] if r["id"]==case)
        plan = cp.plan(profile,row,0,50)
        expected.update(verified_audit_rounds=plan["planned_rounds"],
                        verified_genesis_rounds=plan["genesis_rounds"],
                        verified_intentional_absences=sum(map(len,plan["simulated_absences"].values())))
    if any(facts.get(k)!=v for k,v in expected.items()):
        raise ValueError("ZIP does not verify the exact pinned case semantics")
    with ZipFile(BytesIO(data)) as zipped:
        manifest = json.loads(zipped.read(store.MANIFEST))
    if manifest.get("git_sha")!=release.git_sha:
        raise ValueError("ZIP does not prove the approved Git SHA")
    return {"sha256":store.sha(data),"size":len(data)}


def inspect_sealed_archive(data, release):
    """Controller checks case one before a post-run grant may be signed."""
    return _inspect_archive(data,release,CASE)


def inspect_second_archive(data, release):
    """Controller checks only case two before a post-run grant may be signed."""
    return _inspect_archive(data,release,SECOND_CASE)


def _authorization(scope, method):
    # Capability is generated only by the signed-envelope boundary above.
    return lambda got, verb: got is scope and verb==method and time.time()<scope.deadline


def _protected_directory(directory):
    p=Path(directory)
    if not p.is_absolute() or p.resolve(strict=True)!=p or not p.is_dir():
        raise ValueError("Use an existing canonical protected controller directory")
    return p


def _publish(*, trust, put_envelope, put_url, archive, journal_dir, case):
    now=time.time()
    scope,cfg,stamp=_authorize_envelope(trust,put_envelope,put_url,"PUT",now=now,case=case)
    sealed=_inspect_archive(archive,trust.release,case)
    if sealed!={"sha256":scope.sha256,"size":scope.size}:
        raise ValueError("ZIP does not match the signed independent seal")
    return tx.pod_put_once(scope,archive,cfg,put_url,journal_dir,
                           authorize=_authorization(scope,"PUT"),opener=tx.tls_opener(),now=stamp)


def publish_from_pod(*, trust, put_envelope, put_url, archive, journal_dir):
    """Case one Pod role; never provide reader URL or a long-lived key."""
    return _publish(trust=trust,put_envelope=put_envelope,put_url=put_url,archive=archive,
                    journal_dir=journal_dir,case=CASE)


def publish_second_from_pod(*, trust, put_envelope, put_url, archive, journal_dir):
    """Case two Pod role; a case one grant cannot be used here."""
    return _publish(trust=trust,put_envelope=put_envelope,put_url=put_url,archive=archive,
                    journal_dir=journal_dir,case=SECOND_CASE)


def _verify(*, trust, get_envelope, get_url, receipt_dir, case):
    now=time.time()
    scope,cfg,stamp=_authorize_envelope(trust,get_envelope,get_url,"GET",now=now,case=case)
    directory=_protected_directory(receipt_dir)
    receipt=tx.verify_get(scope,cfg,get_url,authorize=_authorization(scope,"GET"),
                          opener=tx.tls_opener(),now=stamp)
    if time.time()>=scope.deadline:
        raise ValueError("Independent readback exceeded the guarded deadline")
    if receipt!={"schema":tx.RECEIPT,"status":"verified",**scope.proof_fields(),
                 "nodes":20,"rounds":50,"verified_own_generations":1000}:
        raise ValueError("Invalid independent readback result")
    # The signer verified the case and Git on the pre-upload seal. Readback revalidates
    # archive semantics and proves it is byte-for-byte that same protected seal.
    schema,suffix = (READBACK,"first") if case==CASE else (SECOND_READBACK,"second")
    result={**receipt,"schema":schema,"release":asdict(trust.release),
            "eligible_for_next_case":False,"eligible_for_batch_completion":False}
    store.write_atomic(directory/(scope.run_id+f".{suffix}-case-readback.json"),store.json_bytes(result))
    return result


def verify_at_controller(*, trust, get_envelope, get_url, receipt_dir):
    """Case one readback lives only on the controller's protected mount."""
    return _verify(trust=trust,get_envelope=get_envelope,get_url=get_url,receipt_dir=receipt_dir,case=CASE)


def verify_second_at_controller(*, trust, get_envelope, get_url, receipt_dir):
    """Case two readback; neither this proof nor the launcher grants a third case."""
    return _verify(trust=trust,get_envelope=get_envelope,get_url=get_url,receipt_dir=receipt_dir,case=SECOND_CASE)
