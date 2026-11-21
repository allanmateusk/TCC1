"""Strict endpoint and single-object SigV4 grant validation for finalized N20 pilots."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler

LOCAL_CONFIG = {
    "pilot": Path(__file__).with_name("r2-pilot.local.json"),
    "official": Path(__file__).with_name("r2-official.local.json"),
}
PREFIXES = {"pilot":"tcc/piloto", "official":"tcc/prod"}
BUCKET = "tcc"
REGION = "auto"
R2_HOST_PATTERN = re.compile(r"[0-9a-f]{32}\.r2\.cloudflarestorage\.com\Z")


def load_config(kind, path=None):
    try:
        cfg = json.loads((path or LOCAL_CONFIG[kind]).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Missing or invalid local R2 pilot configuration.") from None
    return validate_config(cfg, kind)


def validate_config(cfg, kind):
    if not isinstance(cfg, dict) or set(cfg) != {"endpoint", "bucket", "region", "prefix"}:
        raise ValueError("R2 pilot config may contain only non-secret endpoint and scope fields.")
    if not all(isinstance(v, str) for v in cfg.values()):
        raise ValueError("R2 pilot configuration fields must be strings.")
    ep = urlsplit(cfg["endpoint"])
    if (ep.scheme != "https" or not R2_HOST_PATTERN.fullmatch(ep.netloc)
            or ep.path not in ("", "/") or ep.query or ep.fragment
            or (cfg["bucket"], cfg["region"], cfg["prefix"]) != (BUCKET, REGION, PREFIXES.get(kind))):
        raise ValueError("Invalid R2 endpoint or pilot scope.")
    return cfg


def validate_url(config, key, value, *, method, now=None, key_pattern):
    if not key_pattern.fullmatch(key):
        raise ValueError("Use a generated finalized pilot key inside the approved prefix.")
    if not value:
        raise ValueError("Both time-limited R2 URLs are required.")
    ep = urlsplit(config["endpoint"])
    got = urlsplit(value)
    expected_path = f"/{config['bucket']}/{key}"
    if (got.scheme, got.netloc, got.path, got.fragment) != ("https", ep.netloc, expected_path, ""):
        raise ValueError("Presigned URL must target the exact account, bucket and finalized pilot key.")
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
