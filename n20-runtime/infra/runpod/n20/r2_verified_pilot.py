"""Publish only a finalized N20 pilot using short-lived single-object R2 grants."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import BadZipFile

from . import artifact_store as store
from . import r2_grants as transport

KEYS = re.compile(r"tcc/piloto/n20-[0-9a-f]{32}\.zip\Z")
SCHEMA = "tcc-n20-r2-receipt/v1"
PUT_ENV = "TCC_N20_R2_PUT_URL"
GET_ENV = "TCC_N20_R2_GET_URL"
SOCKET_TIMEOUT = 5
TOTAL_SECONDS = 35


class TransferError(ValueError):
    """Only sanitized diagnostics, never exceptions carrying bearer URLs."""


class Transient(TransferError):
    pass


def object_key(run_id):
    if not store.RUN_ID.fullmatch(run_id or ""):
        raise ValueError("Malformed run ID")
    return f"tcc/piloto/n20-{run_id}.zip"


def prepare(root, run_id):
    key = object_key(run_id)
    data = store.build_archive(root, run_id)
    store.verify_archive(data, run_id)
    store.write_atomic(root / store.ARCHIVE, data)
    return data, key


def _time_left(clock, deadline):
    left = deadline-clock()
    if left <= 0:
        raise TransferError("R2 transfer time budget exhausted")
    return min(SOCKET_TIMEOUT, left)


def _request(open_url, request, deadline, clock, *, size):
    method = request.get_method()
    try:
        with open_url(request, timeout=_time_left(clock, deadline)) as response:
            status = response.status
            if status in (409,412) and method=="PUT":
                raise TransferError("R2 object key already exists; no overwrite attempted")
            if status in (408,429,500,502,503,504) or (method=="GET" and status==404):
                raise Transient(f"R2 {method} not yet confirmed")
            if method=="PUT" and status in (200,201):
                return None
            if method!="GET" or status!=200:
                raise TransferError(f"R2 {method} denied or unexpected HTTP status")
            data = bytearray()
            read = getattr(response, "read1", response.read)
            while True:
                _time_left(clock, deadline)
                chunk = read(min(32*1024, size+1-len(data)))
                if not chunk:
                    return bytes(data)
                data.extend(chunk)
                if len(data)>size:
                    raise TransferError("Unexpected R2 download size")
    except HTTPError as err:
        code = err.code
        if method=="PUT" and code in (409,412):
            raise TransferError("R2 object key already exists; no overwrite attempted") from None
        if code in (408,429,500,502,503,504) or (method=="GET" and code==404):
            raise Transient(f"R2 {method} not yet confirmed") from None
        raise TransferError(f"R2 {method} rejected with HTTP {code}") from None
    except (URLError, TimeoutError, OSError):
        raise Transient(f"R2 {method} interrupted") from None


def upload(root, run_id, config, put_url, get_url, *, opener=None, now=None,
           clock=time.monotonic, sleep=time.sleep):
    data, key = prepare(root, run_id)
    local_digest = store.sha(data)
    receipt_path = root / store.RECEIPT
    if receipt_path.exists():
        existing = json.loads(store.read_file(root,store.RECEIPT))
        recovered = (root / store.DOWNLOADED)
        if (
            existing.get("schema")!=SCHEMA or existing.get("status")!="verified" or existing.get("run_id")!=run_id
            or existing.get("bucket")!=transport.BUCKET or existing.get("key")!=key
            or existing.get("sha256")!=local_digest or existing.get("bytes")!=len(data)
            or recovered.is_symlink() or not recovered.is_file() or recovered.stat().st_size!=len(data)
            or recovered.read_bytes()!=data
            or any(existing.get(k)!=v for k,v in store.verify_archive(data,run_id).items())
        ):
            raise TransferError("Existing receipt does not match the finalized archive")
        return existing
    for method,url in (("PUT",put_url),("GET",get_url)):
        transport.validate_url(config,key,url,method=method,now=now,key_pattern=KEYS)
    if put_url==get_url:
        raise TransferError("Separate PUT and GET grants required")
    runner = opener or build_opener(ProxyHandler({}), transport._NoRedirect()).open
    deadline = clock()+TOTAL_SECONDS
    put = Request(put_url, data=data, method="PUT",
                  headers={"Content-Type":"application/zip","If-None-Match":"*"})
    downloaded = None
    try:
        _request(runner,put,deadline,clock,size=len(data))
    except Transient:
        # A timed-out write may have landed; do not issue a second PUT.
        # Recovery is read-only; exact bytes are required to certify.
        pass
    for delay in (0,.25,.75):
        if delay:
            _time_left(clock,deadline)
            sleep(delay)
        try:
            downloaded = _request(runner,Request(get_url,method="GET"),deadline,clock,size=len(data))
            break
        except Transient:
            continue
    if downloaded is None:
        raise TransferError("R2 GET did not verify within the bounded attempts")
    if len(downloaded)!=len(data) or not hmac.compare_digest(store.sha(downloaded),local_digest):
        raise TransferError("R2 size or SHA-256 did not match")
    metrics = store.verify_archive(downloaded,run_id)
    store.write_atomic(root / store.DOWNLOADED, downloaded)
    receipt = {"schema":SCHEMA,"status":"verified","run_id":run_id,
               "bucket":transport.BUCKET,"key":key,"sha256":local_digest,"bytes":len(data),
               "verified_at_utc":(now or datetime.now(timezone.utc)).isoformat(),**metrics}
    store.write_atomic(receipt_path,store.json_bytes(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare","upload"))
    parser.add_argument("--durable-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        root = store.durable_run(args.durable_root,args.run_id,repo=Path(__file__).resolve().parents[4])
        if args.operation=="prepare":
            data,key = prepare(root,args.run_id)
            result = {"status":"prepared_local","run_id":args.run_id,"bucket":transport.BUCKET,
                      "key":key,"bytes":len(data),"sha256":store.sha(data)}
        else:
            cfg = transport.load_config()
            result = upload(root,args.run_id,cfg,os.environ.pop(PUT_ENV,None),os.environ.pop(GET_ENV,None))
        print(json.dumps(result,sort_keys=True))
    except TransferError as exc:
        parser.exit(1, f"Pilot not verified: {exc}\n")
    except (ValueError,TypeError,KeyError,RuntimeError,OSError,BadZipFile):
        parser.exit(1,"Pilot not verified: configuration, finalized evidence or local persistence failed.\n")


if __name__=="__main__":
    main()
