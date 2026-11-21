"""Authenticated warm case transition policy. No launch, network, signer or STOP API."""
from __future__ import annotations

import base64
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import uuid

from .artifact_store import MAX_ZIP, json_bytes, sha
from .incremental_batch_protection import BatchProtection, QualificationProtection
from .incremental_campaign import IDS, SCHEMA as CAMPAIGN

LEASE="tcc-warm-controller-case-lease/v1"
GET="tcc-warm-external-r2-readback/v1"
QUALIFICATION="qualification-two"
OFFICIAL="official-full"
BASE={"schema","scope_sha256","index","scenario_id","run_id","observed_at","expires_at"}
LEASE_FIELDS=BASE | {"guard_observation_sha256","case_deadline","prior_readback_sha256"}
GET_FIELDS=BASE | {"method","bucket","key","sha256","size","verified_own_generations",
                   "verified_ledgers","rounds","nodes","archive_verified","independent_get"}


def _hex(x,n):
    return type(x) is str and re.fullmatch(rf"[a-f0-9]{{{n}}}",x) is not None


def _uuid(x):
    return _hex(x,32) and uuid.UUID(hex=x).version==4


@dataclass(frozen=True)
class Scope:
    allocation: BatchProtection
    guard_instance_id: str
    guard_version_id: str
    worker_version_id: str
    lease_key_sha256: str
    readback_key_sha256: str
    mode: str = QUALIFICATION

    def __post_init__(self):
        if (self.mode not in (QUALIFICATION,OFFICIAL)
            or self.mode==OFFICIAL and (
                type(self.allocation) is not BatchProtection
                or self.allocation.hard_deadline-self.allocation.stop_at!=300)
            or type(self.allocation) not in (BatchProtection,QualificationProtection) or not _uuid(self.allocation.batch_id)
            or self.guard_instance_id!=str(uuid.UUID(hex=self.allocation.batch_id))
            or not all(type(x) is str and str(uuid.UUID(x))==x for x in (self.guard_version_id,self.worker_version_id))
            or not all(_hex(x,64) for x in (self.lease_key_sha256,self.readback_key_sha256))
            or self.lease_key_sha256==self.readback_key_sha256):
            raise ValueError("Expected immutable allocation/guard and separate authorities")

    @property
    def case_ids(self):
        return IDS if self.mode==OFFICIAL else IDS[:2]

    @property
    def case_limit(self):
        return len(self.case_ids)

    @property
    def digest(self):
        fields=asdict(self)
        if self.mode==QUALIFICATION:
            fields.pop("mode")  # keep archived short/qualification pins readable
            ordered=IDS[:2] if type(self.allocation) is QualificationProtection else IDS
        else:
            ordered=self.case_ids
        return sha(json_bytes({"schema":"tcc-warm-controller-scope/v1","campaign":CAMPAIGN,
                               "scenarios":ordered,**fields}))


def _key_der(pem):
    if type(pem) is not bytes or len(pem)>256:
        raise ValueError("Expected pinned Ed25519 public key")
    lines=pem.strip().splitlines()
    if len(lines)!=3 or lines[0]!=b"-----BEGIN PUBLIC KEY-----" or lines[2]!=b"-----END PUBLIC KEY-----":
        raise ValueError("Expected pinned Ed25519 public key")
    der=base64.b64decode(lines[1],validate=True)
    if len(der)!=44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("Expected pinned Ed25519 algorithm")
    return der


@dataclass(frozen=True)
class Authorities:
    scope: Scope
    lease_pem: bytes
    readback_pem: bytes
    openssl: Path

    def __post_init__(self):
        if type(self.scope) is not Scope or not self.openssl.is_absolute() or self.openssl.resolve(strict=True)!=self.openssl \
                or not self.openssl.is_file() or self.openssl.name.lower() not in {"openssl","openssl.exe"}:
            raise ValueError("Use the locally approved OpenSSL executable")
        got=tuple(hashlib.sha256(_key_der(pem)).hexdigest() for pem in (self.lease_pem,self.readback_pem))
        want=(self.scope.lease_key_sha256,self.scope.readback_key_sha256)
        if not all(hmac.compare_digest(a,b) for a,b in zip(got,want)):
            raise ValueError("Authentication keys don't match external trusted pins")

    def validate(self,envelope,kind,now):
        allowed={"evidence","signature_ed25519_base64"}
        if type(envelope) is not dict or set(envelope)!=allowed or kind not in (LEASE,GET):
            raise ValueError("Expected a purpose-specific signed envelope")
        ev=envelope["evidence"]
        fields=LEASE_FIELDS if kind==LEASE else GET_FIELDS
        if type(ev) is not dict or set(ev)!=fields or ev["schema"]!=kind or ev["scope_sha256"]!=self.scope.digest:
            raise ValueError("No scoped grant (local/mock reports are not grants)")
        if (type(ev["index"]) is not int or not 0<=ev["index"]<len(self.scope.case_ids) or ev["scenario_id"]!=self.scope.case_ids[ev["index"]]
            or not _uuid(ev["run_id"]) or ev["run_id"]==self.scope.allocation.batch_id
            or type(ev["observed_at"]) is not int or type(ev["expires_at"]) is not int
            or not self.scope.allocation.opened_at<=ev["observed_at"]<=now<ev["expires_at"]
                  <=min(ev["observed_at"]+60,self.scope.allocation.stop_at)):
            raise ValueError("Expired or mismatched ordered grant")
        if kind==LEASE:
            if (not _hex(ev["guard_observation_sha256"],64)
                or not (ev["prior_readback_sha256"] is None if ev["index"]==0 else _hex(ev["prior_readback_sha256"],64))
                or type(ev["case_deadline"]) is not int
                or not now<ev["case_deadline"]<=min(ev["observed_at"]+self.scope.allocation.max_attempt_seconds,
                                                   self.scope.allocation.stop_at)):
                raise ValueError("Lease must bind the exact live guard and previous readback")
        else:
            if (ev["method"]!="GET" or ev["bucket"]!="tcc"
                or ev["key"]!="tcc/prod/incremental-v1/n20-"+ev["run_id"]+".zip"
                or not _hex(ev["sha256"],64) or type(ev["size"]) is not int or not 0<ev["size"]<=MAX_ZIP
                or not all(type(ev[k]) is int and ev[k]==n for k,n in {
                    "rounds":50,"nodes":20,"verified_own_generations":1000,"verified_ledgers":20}.items())
                or ev["archive_verified"] is not True or ev["independent_get"] is not True):
                raise ValueError("No independently verified exact archive GET")
        raw=self.verify_signature(ev,envelope["signature_ed25519_base64"],kind=kind)
        # New canonical copy avoids a mutable caller object during transaction.
        return json.loads(raw),sha(raw)


    def verify_signature(self,evidence,signature,*,kind):
        if kind not in (LEASE,GET):
            raise ValueError("Unknown authority role")
        if type(signature) is not str or len(signature)!=88:
            raise ValueError("Missing Ed25519 signature")
        sig=base64.b64decode(signature,validate=True)
        raw=json_bytes(evidence)
        if len(sig)!=64 or len(raw)>4096:
            raise ValueError("Invalid signed statement")
        pem=self.lease_pem if kind==LEASE else self.readback_pem
        with tempfile.TemporaryDirectory(prefix="tcc-warm-public-verification-") as tmp:
            d=Path(tmp)
            for name,body in (("public.pem",pem),("signature",sig),("evidence",raw)):
                (d/name).write_bytes(body)
            # Avoid PATH resolution; never pass a private key or provider credential.
            env={k:v for k,v in os.environ.items()
                 if k.upper() in {"SYSTEMROOT","WINDIR","SYSTEMDRIVE","TEMP","TMP","LANG"}}
            r=subprocess.run([str(self.openssl),"pkeyutl","-verify","-pubin","-rawin","-inkey",str(d/"public.pem"),
                              "-in",str(d/"evidence"),"-sigfile",str(d/"signature")],
                             env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                             check=False,timeout=5)
        if r.returncode!=0:
            raise ValueError("Independent authority signature invalid")
        return raw


class Journal:
    """Controller-local SQLite, installed only in its separate trusted directory.

    This is a transition kernel, not a source of trusted time, keys or observed
    facts. It never launches/releases an OS process and has no network access.
    """

    def __init__(self,path,authorities,*,clock=time.time):
        path=Path(path)
        if (type(authorities) is not Authorities or not path.is_absolute() or path.is_symlink()
            or path.parent.resolve(strict=True)!=path.parent or not path.parent.is_dir()):
            raise ValueError("Independent controller-owned canonical journal path is required")
        self.path,self.authorities,self.clock=path,authorities,clock
        with self._txn(initialize=True):
            pass

    @contextmanager
    def _txn(self,*,initialize=False):
        if self.path.is_symlink():
            raise ValueError("Refuse symlink journal")
        with closing(sqlite3.connect(self.path,timeout=5,isolation_level=None)) as db:
            db.row_factory=sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            if initialize:
                db.execute("CREATE TABLE IF NOT EXISTS plan (one INTEGER PRIMARY KEY CHECK(one=1), digest TEXT NOT NULL)")
                db.execute("""CREATE TABLE IF NOT EXISTS halt (one INTEGER PRIMARY KEY CHECK(one=1),
                           run_id TEXT NOT NULL, reason TEXT NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS cases (idx INTEGER PRIMARY KEY, run_id TEXT UNIQUE NOT NULL,
                     lease_sha TEXT NOT NULL, admitted REAL NOT NULL, cutoff INTEGER NOT NULL,
                     seal_sha TEXT, seal_size INTEGER, sealed REAL, receipt_sha TEXT)""")
                db.execute("INSERT OR IGNORE INTO plan VALUES(1,?)",(self.authorities.scope.digest,))
            row=db.execute("SELECT digest FROM plan WHERE one=1").fetchone()
            if row is None or row["digest"]!=self.authorities.scope.digest:
                raise ValueError("Stored allocation, release or trust does not match")
            yield db
            db.commit()

    def _now(self):
        n=self.clock()
        if type(n) not in (float,int) or not math.isfinite(n):
            raise ValueError("Trusted clock unavailable")
        return n

    def _still_fresh(self,grants):
        now=self._now()
        if any(not g["observed_at"]<=now<g["expires_at"] or
               ("case_deadline" in g and not now<g["case_deadline"]) for g in grants):
            raise ValueError("Signed grant expired before commit")
        return now

    @staticmethod
    def _tip(db):
        return db.execute("SELECT * FROM cases ORDER BY idx DESC LIMIT 1").fetchone()

    @staticmethod
    def _record(db,g,digest,now):
        if db.execute("SELECT 1 FROM cases WHERE run_id=?",(g["run_id"],)).fetchone() is not None:
            raise ValueError("Run UUID already consumed")
        db.execute("INSERT INTO cases(idx,run_id,lease_sha,admitted,cutoff) VALUES (?,?,?,?,?)",
                   (g["index"],g["run_id"],digest,now,g["case_deadline"]))

    @staticmethod
    def _require_open(db):
        if db.execute("SELECT 1 FROM halt WHERE one=1").fetchone() is not None:
            raise ValueError("Protected batch halted; do not advance or relaunch")

    def failure(self):
        with self._txn() as db:
            row=db.execute("SELECT run_id,reason FROM halt WHERE one=1").fetchone()
            return dict(row) if row else None

    def halt(self,run_id,reason):
        if not _uuid(run_id) or reason not in ("cancelled","case_failed","corrupt_readback","invalid_archive"):
            raise ValueError("Expected an exact failed run and known terminal category")
        with self._txn() as db:
            row=self._tip(db)
            if row is None or row["run_id"]!=run_id or row["receipt_sha"] is not None:
                raise ValueError("Cannot halt a different or already completed active attempt")
            db.execute("INSERT OR IGNORE INTO halt VALUES(1,?,?)",(run_id,reason))
            latched=db.execute("SELECT run_id,reason FROM halt WHERE one=1").fetchone()
            return dict(latched)

    def first(self,lease):
        g,digest=self.authorities.validate(lease,LEASE,self._now())
        with self._txn() as db:
            self._require_open(db)
            now=self._still_fresh([g])
            if g["index"]!=0 or self._tip(db) is not None:
                raise ValueError("The sole initial lease has already been used or is not first")
            self._record(db,g,digest,now)
        return digest

    def seal_active(self,run_id,*,sha256,size):
        # Accept only from the protected controller's archive validator, never
        # directly from the Pod or the callback. GET must sign the same bytes.
        if not _uuid(run_id) or not _hex(sha256,64) or type(size) is not int or not 0<size<=MAX_ZIP:
            raise ValueError("Unrecognized local seal")
        with self._txn() as db:
            self._require_open(db)
            row=self._tip(db)
            now=self._now()
            if (row is None or row["run_id"]!=run_id or row["receipt_sha"] is not None or
                not row["admitted"]<=now<row["cutoff"]):
                raise ValueError("No active lease to seal")
            if row["seal_sha"] is not None and (row["seal_sha"],row["seal_size"])!=(sha256,size):
                raise ValueError("Local archive seal is immutable")
            if row["seal_sha"] is None:
                db.execute("UPDATE cases SET seal_sha=?,seal_size=?,sealed=? WHERE idx=?",(sha256,size,now,row["idx"]))

    def transition(self,readback,next_lease):
        # No first-case/fake receipt promotion: this requires a separately
        # authenticated independent GET with this journal's dedicated schema.
        now=self._now()
        r,receipt_sha=self.authorities.validate(readback,GET,now)
        g,lease_sha=self.authorities.validate(next_lease,LEASE,now)
        with self._txn() as db:
            self._require_open(db)
            now=self._still_fresh([r,g])
            row=self._tip(db)
            if (row is None or row["receipt_sha"] is not None or
                (r["index"],r["run_id"],r["sha256"],r["size"]) !=
                    (row["idx"],row["run_id"],row["seal_sha"],row["seal_size"]) or
                row["sealed"] is None or not row["sealed"]<=r["observed_at"]<=g["observed_at"]<=now<row["cutoff"] or
                g["index"]!=row["idx"]+1 or g["prior_readback_sha256"]!=receipt_sha):
                raise ValueError("Next lease does not follow a fresh verified GET for the sealed active case")
            self._record(db,g,lease_sha,now)
            db.execute("UPDATE cases SET receipt_sha=? WHERE idx=?",(receipt_sha,row["idx"]))
        return lease_sha

    def finalize_second(self,readback):
        """Separate legacy qualification: cannot finish or advance official scope."""
        if self.authorities.scope.mode!=QUALIFICATION:
            raise ValueError("Use the explicitly approved official batch finalizer")
        return self.finalize_last(readback)

    def finalize_last(self,readback):
        """Commit an exact signed GET only after every preceding case was committed."""
        count=self.authorities.scope.case_limit
        r,receipt_sha=self.authorities.validate(readback,GET,self._now())
        with self._txn() as db:
            self._require_open(db)
            now=self._still_fresh([r])
            rows=db.execute("SELECT * FROM cases ORDER BY idx").fetchall()
            if len(rows)!=count or [row["idx"] for row in rows]!=list(range(count)) or any(
                not _hex(row["receipt_sha"],64) for row in rows[:-1]):
                raise ValueError("There is no exact prior ordered independently verified receipt set")
            row=rows[-1]
            if (r["index"]!=count-1 or row["receipt_sha"] is not None or row["sealed"] is None
                    or (r["index"],r["run_id"],r["sha256"],r["size"]) !=
                       (row["idx"],row["run_id"],row["seal_sha"],row["seal_size"])
                    or not row["sealed"]<=r["observed_at"]<=now<row["cutoff"]):
                raise ValueError("Last case is not ready for an exact live GET receipt")
            db.execute("UPDATE cases SET receipt_sha=? WHERE idx=?",(receipt_sha,r["index"]))
        return receipt_sha

    def status(self):
        with self._txn() as db:
            return [dict(r) for r in db.execute("SELECT idx,run_id,lease_sha,receipt_sha FROM cases ORDER BY idx")]
