"""User-run R2 diagnostic for shared incremental wire primitives only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import hmac
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
import uuid
import warnings

from . import artifact_store as store, incremental_transport as wire, r2_grants
from .r2_pilot_prompt import _presign

SCHEMA="tcc-warm-wire-diagnostic/v1"
KEY=re.compile(r"tcc/piloto/diag-warm-[a-f0-9]{32}\.txt\Z")
HERE=Path(__file__).resolve().parents[4]


def _payload(rid):
    return ("TCC R2 wire diagnostic; synthetic only; no case data\n"+rid+"\n").encode("ascii")


def _fields(config,rid,expires_at):
    url=urlsplit(config["endpoint"])
    body=_payload(rid)
    return {"schema":SCHEMA,"run_id":rid,"bucket":"tcc","key":f"tcc/piloto/diag-warm-{rid}.txt",
            "account_host_sha256":store.sha(url.hostname.encode("ascii")),
            "size":len(body),"sha256":store.sha(body),"expires_at":expires_at}


def _private_path(root,create=False):
    root=Path(root)
    if (not root.is_absolute() or root.is_relative_to(HERE) or root.resolve()!=root
       or not root.parent.is_dir() or root==Path(root.anchor)):
        raise ValueError("Use a fresh local directory outside the checkout")
    if create:
        root.mkdir(mode=0o700,exist_ok=False)
    if not root.is_dir():
        raise ValueError("Missing local diagnostic directory")
    return root


def prepare(config,root,*,now=None):
    # Explicit caller time for fixtures; CLI always supplies the live clock.
    r2_grants.validate_config(config,"pilot")
    root=_private_path(root,create=True)
    facts=_fields(config,uuid.uuid4().hex,(int(time.time()) if now is None else now)+900)
    store.write_atomic(root/"wire-diagnostic.json",store.json_bytes(facts))
    return {"status":"prepared_diagnostic_only","key":facts["key"],"bytes":facts["size"]}


class Diagnostic:
    def __init__(self,config,root,*,now):
        self.config=r2_grants.validate_config(config,"pilot")
        self.root=_private_path(root)
        facts=json.loads(store.read_file(self.root,"wire-diagnostic.json"))
        if not isinstance(facts,dict) or not re.fullmatch("[a-f0-9]{32}",facts.get("run_id","")):
            raise ValueError("Invalid diagnostic manifest")
        self.run_id=facts["run_id"]
        end=facts.get("expires_at")
        if type(end) is not int or not now < end <= now+900 or facts!=_fields(config,self.run_id,end):
            raise ValueError("Diagnostic expired, cross-account or altered")
        self.facts,self.key,self.size=facts,facts["key"],facts["size"]
        if not KEY.fullmatch(self.key):
            raise ValueError("Diagnostic key outside fixed namespace")

    def proof_fields(self):
        return {"schema":SCHEMA,**{k:self.facts[k] for k in ("run_id","bucket","key","sha256","size")}}

    def signed_verb(self,method,access,secret,utc):
        if not re.fullmatch("[a-zA-Z0-9]{16,128}",access) or not re.fullmatch("[a-zA-Z0-9+/=]{32,128}",secret):
            raise ValueError("Invalid local S3 credential format")
        remaining=self.facts["expires_at"]-int(utc.timestamp())-1
        if remaining<10:
            raise ValueError("Diagnostic authorization too near expiry")
        return _presign(method,host=urlsplit(self.config["endpoint"]).netloc,path=f"/tcc/{self.key}",
                        region="auto",access_key_id=access,secret_key=secret,now=utc,expires=min(300,remaining))

    def execute(self,method,url,*,opener,utc):
        if method not in ("PUT","GET"):
            raise ValueError("PUT or GET only")
        r2_grants.validate_url(self.config,self.key,url,method=method,now=utc,key_pattern=KEY)
        left=self.facts["expires_at"]-utc.timestamp()
        if left<=0:
            raise ValueError("Diagnostic expired")
        deadline=time.monotonic()+min(left,25)
        if method=="PUT":
            status=wire._wire_put_once(self,_payload(self.run_id),url,self.root,
                          content_type="text/plain",opener=opener,deadline=deadline)
        else:
            body=wire._wire_get(url,self.size,opener=opener,deadline=deadline)
            if len(body)!=self.size or not hmac.compare_digest(store.sha(body),self.facts["sha256"]):
                raise ValueError("Independent diagnostic GET did not verify size and hash")
            status="verified_diagnostic_only"
        return {**self.proof_fields(),"status":status,"method":method,
                "production_evidence":False,"eligible_for_next_case":False}


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode",choices=("prepare","put","get"))
    cli.add_argument("--config",required=True,type=Path,help="Existing nonsecret pilot configuration")
    cli.add_argument("--work",required=True,type=Path,help="Same private absolute scratch directory")
    a=cli.parse_args()
    try:
        cfg=r2_grants.load_config("pilot",a.config)
        now=datetime.now(timezone.utc)
        if a.mode=="prepare":
            result=prepare(cfg,a.work,now=int(now.timestamp()))
        else:
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise ValueError("Interactive terminal required")
            m=a.mode.upper()
            d=Diagnostic(cfg,a.work,now=now.timestamp())
            print(f"{m} only; synthetic tcc/{d.key}; use the separate scoped key for this role.")
            with warnings.catch_warnings():
                warnings.simplefilter("error",getpass.GetPassWarning)
                user=getpass.getpass(f"{m} R2 S3 Access Key ID (hidden): ")
                secret=getpass.getpass(f"{m} R2 S3 Secret Access Key (hidden): ")
            try:
                now=datetime.now(timezone.utc)
                url=d.signed_verb(m,user.strip(),secret.strip(),now)
            finally:
                del user,secret
            try:
                result=d.execute(m,url,opener=wire.tls_opener(),utc=now)
            finally:
                del url
        print(json.dumps(result,sort_keys=True))
    except (KeyboardInterrupt,EOFError):
        print("Diagnostic cancelled, not verified.",file=sys.stderr)
        return 130
    except Exception:
        print("Diagnostic not verified. Check only the scoped S3 key, fresh plan and private network access. "
              "Do not retry an uncertain PUT; reconcile by GET. No credential or URL was logged.",file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
