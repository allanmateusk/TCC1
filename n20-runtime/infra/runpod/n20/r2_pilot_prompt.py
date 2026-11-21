"""Interactive local-only R2 synthetic probe. No credentials are persisted."""
from __future__ import annotations

from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import json
import re
import sys
from urllib.parse import quote, urlsplit
import warnings

from . import r2_pilot


def _mac(key, value):
    return hmac.digest(key, value.encode("utf-8"), "sha256")


def _aws_encode(value):
    return quote(value, safe="-_.~")


def _presign(method, *, host, path, region, access_key_id, secret_key, now, expires=600):
    if method not in ("PUT", "GET"):
        raise ValueError("Pilot supports PUT and GET only.")
    signed = {"host": host}
    if method == "PUT":
        signed["if-none-match"] = "*"
    names = ";".join(sorted(signed))
    canonical_headers = "".join(f"{key}:{signed[key]}\n" for key in sorted(signed))
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    scope = f"{date}/{region}/s3/aws4_request"
    values = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{access_key_id}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": names,
    }
    query = "&".join(f"{k}={v}" for k, v in sorted(
        (_aws_encode(key), _aws_encode(value)) for key, value in values.items()
    ))
    request = "\n".join((method, path, query, canonical_headers, names, "UNSIGNED-PAYLOAD"))
    request_hash = hashlib.sha256(request.encode("utf-8")).hexdigest()
    signable = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{request_hash}"
    signing_key = _mac(_mac(_mac(_mac(("AWS4" + secret_key).encode("utf-8"), date), region), "s3"), "aws4_request")
    signature = _mac(signing_key, signable).hex()
    return f"https://{host}{path}?{query}&X-Amz-Signature={signature}"


def _create_urls(config, key, access_id, secret, now, *, key_pattern=r2_pilot.KEY_PATTERN):
    if not key_pattern.fullmatch(key):
        raise ValueError("Invalid pilot object key.")
    if not re.fullmatch("[a-zA-Z0-9]{16,128}", access_id) or not re.fullmatch("[a-zA-Z0-9+/=]{32,128}", secret):
        raise ValueError("Invalid R2 S3 credential format.")
    common = {
        "host": urlsplit(config["endpoint"]).netloc,
        "path": f"/{config['bucket']}/{key}",
        "region": config["region"],
        "access_key_id": access_id,
        "secret_key": secret,
        "now": now,
    }
    return _presign("PUT", **common), _presign("GET", **common)


def main():
    if len(sys.argv) != 1 or not sys.stdin.isatty() or not sys.stderr.isatty():
        print("No upload: open a normal interactive terminal. Do not pass credentials as arguments.",
              file=sys.stderr)
        return 2
    try:
        config = r2_pilot.load_config()
        key = r2_pilot.new_key()
        print(f"Probe only: one synthetic attachment to {config['bucket']}/{key}.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            access_id = getpass.getpass("R2 S3 Access Key ID (hidden): ")
            secret = getpass.getpass("R2 S3 Secret Access Key (hidden): ")
        try:
            put, get = _create_urls(config, key, access_id.strip(), secret.strip(), datetime.now(timezone.utc))
        finally:
            del access_id, secret
        try:
            result = r2_pilot.send_and_verify(config, key, put, get)
        finally:
            del put, get
        print(json.dumps(result))
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nProbe cancelled. If a write was already attempted, it is not reported as verified.",
              file=sys.stderr)
        return 130
    except Exception:
        print("Probe not verified. Check the exact bucket's scoped S3 access and network; "
              "no credentials or signed URLs will be printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
