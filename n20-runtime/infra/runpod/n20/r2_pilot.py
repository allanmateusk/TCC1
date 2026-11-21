"""Send and verify one tiny synthetic pilot object with narrowly scoped presigned URLs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

LOCAL_CONFIG = Path(__file__).with_name("r2-pilot.local.json")
BUCKET = "tcc"
PREFIX = "tcc/piloto"
REGION = "auto"
KEY_PATTERN = re.compile(r"tcc/piloto/smoke-[0-9a-f]{32}\.txt\Z")
R2_HOST_PATTERN = re.compile(r"[0-9a-f]{32}\.r2\.cloudflarestorage\.com\Z")


def load_config(path=LOCAL_CONFIG):
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Missing or invalid local R2 pilot configuration.") from None
    if not isinstance(cfg, dict) or set(cfg) != {"endpoint", "bucket", "region", "prefix"}:
        raise ValueError("R2 pilot config may contain only non-secret endpoint and scope fields.")
    if not all(isinstance(v, str) for v in cfg.values()):
        raise ValueError("R2 pilot configuration fields must be strings.")
    ep = urlsplit(cfg["endpoint"])
    if (ep.scheme != "https" or not R2_HOST_PATTERN.fullmatch(ep.netloc)
            or ep.path not in ("", "/") or ep.query or ep.fragment
            or (cfg["bucket"], cfg["region"], cfg["prefix"]) != (BUCKET, REGION, PREFIX)):
        raise ValueError("Invalid R2 endpoint or pilot scope.")
    return cfg


def new_key():
    return f"{PREFIX}/smoke-{secrets.token_hex(16)}.txt"


def validate_url(config, key, value, *, method, now=None, key_pattern=KEY_PATTERN):
    if not key_pattern.fullmatch(key):
        raise ValueError("Use a generated synthetic pilot key inside the configured prefix.")
    if not value:
        raise ValueError("Both time-limited R2 URLs are required.")
    ep = urlsplit(config["endpoint"])
    got = urlsplit(value)
    expected_path = f"/{config['bucket']}/{key}"
    if (got.scheme, got.netloc, got.path, got.fragment) != ("https", ep.netloc, expected_path, ""):
        raise ValueError("Presigned URL must target the exact account, bucket and synthetic pilot key.")
    try:
        params = parse_qs(got.query, strict_parsing=True, max_num_fields=10, keep_blank_values=True)
    except ValueError:
        raise ValueError("Malformed presigned query.") from None
    fields = {
        "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date",
        "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
    }
    if (not fields.issubset(params) or set(params) - fields - {"X-Amz-Security-Token"}
            or any(len(v) != 1 for v in params.values())):
        raise ValueError("Presigned URL must use a single, complete SigV4 query.")
    params = {k: v[0] for k, v in params.items()}
    creds = params["X-Amz-Credential"].split("/")
    needed_headers = {"host", "if-none-match"} if method == "PUT" else {"host"}
    headers = set(params["X-Amz-SignedHeaders"].split(";"))
    if (params["X-Amz-Algorithm"] != "AWS4-HMAC-SHA256"
            or len(creds) != 5 or creds[2:] != [config["region"], "s3", "aws4_request"]
            or not re.fullmatch(r"[0-9a-f]{64}", params["X-Amz-Signature"])
            or not needed_headers <= headers
            or headers - needed_headers - ({"content-type"} if method == "PUT" else set())):
        raise ValueError("Presigned URL must sign the intended pilot headers and use R2 auto/S3 scope.")
    try:
        signed_at = datetime.strptime(params["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        expiry = int(params["X-Amz-Expires"])
    except ValueError:
        raise ValueError("Invalid presigned timestamp or expiry.") from None
    age = ((now or datetime.now(timezone.utc)) - signed_at).total_seconds()
    if not (1 <= expiry <= 900 and -30 <= age < expiry and creds[1] == signed_at.strftime("%Y%m%d")):
        raise ValueError("Use a current presigned URL that expires within 15 minutes.")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _send_payload(config, key, put_url, get_url, *, data, key_pattern, content_type, opener=None, now=None,
                  download_consumer=None):
    if not isinstance(data, bytes) or not 0 < len(data) <= 128 * 1024:
        raise ValueError("Pilot payload exceeds the permitted size.")
    validate_url(config, key, put_url, method="PUT", now=now, key_pattern=key_pattern)
    validate_url(config, key, get_url, method="GET", now=now, key_pattern=key_pattern)
    if put_url == get_url:
        raise ValueError("Use separate PUT and GET signatures.")
    runner = opener or build_opener(ProxyHandler({}), _NoRedirect()).open
    digest = hashlib.sha256(data).hexdigest()
    actions = (
        Request(put_url, data=data, method="PUT",
                headers={"Content-Type": content_type, "If-None-Match": "*"}),
        Request(get_url, method="GET"),
    )
    download_receipt = {}
    for req in actions:
        method = req.get_method()
        try:
            with runner(req, timeout=12) as response:
                if response.status not in ((200, 201) if method == "PUT" else (200,)):
                    raise RuntimeError(f"R2 {method} did not return the expected status.")
                if method == "GET":
                    observed = response.read(len(data) + 1)
                    if len(observed) != len(data) or not hmac.compare_digest(
                        hashlib.sha256(observed).hexdigest(), digest
                    ):
                        raise RuntimeError("R2 download did not match the expected size and SHA-256.")
                    if download_consumer is not None:
                        download_receipt = download_consumer(observed)
        except HTTPError as err:
            raise RuntimeError(f"R2 {method} failed with HTTP {err.code}; not verified.") from None
        except (URLError, TimeoutError, OSError):
            raise RuntimeError(f"R2 {method} could not complete; not verified.") from None
    return {"status": "verified", "synthetic": True, "bucket": config["bucket"],
            "key": key, "bytes": len(data), "sha256": digest, **download_receipt}


def send_and_verify(config, key, put_url, get_url, *, opener=None, now=None):
    data = f"TCC N20 R2 synthetic pilot probe\n{key}\n".encode("ascii")
    return _send_payload(config, key, put_url, get_url, data=data, key_pattern=KEY_PATTERN,
                         content_type="application/octet-stream", opener=opener, now=now)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    subs.add_parser("prepare")
    run = subs.add_parser("run")
    run.add_argument("--key", required=True)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.operation == "prepare":
            print(new_key())
        else:
            result = send_and_verify(config, args.key, os.getenv("TCC_R2_PILOT_PUT_URL"),
                                     os.getenv("TCC_R2_PILOT_GET_URL"))
            print(json.dumps(result))
    except (ValueError, RuntimeError) as err:
        parser.exit(1, f"Pilot not verified: {err}\n")


if __name__ == "__main__":
    main()
