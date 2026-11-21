from datetime import datetime, timezone
import hashlib
import io
import unittest
from urllib.parse import urlencode
from urllib.error import HTTPError

from . import r2_pilot as pilot

NOW = datetime(2026, 11, 21, 1, 0, tzinfo=timezone.utc)
HOST = "0" * 32 + ".r2.cloudflarestorage.com"
CONFIG = {"endpoint": "https://" + HOST, "bucket": "tcc", "region": "auto", "prefix": "tcc/piloto"}
KEY = "tcc/piloto/smoke-" + "a" * 32 + ".txt"


def signed(method, *, key=KEY, host=HOST, expiry=600):
    params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": "synthetic/20261121/auto/s3/aws4_request",
        "X-Amz-Date": "20261121T010000Z",
        "X-Amz-Expires": expiry,
        "X-Amz-SignedHeaders": "host;if-none-match" if method == "PUT" else "host",
        "X-Amz-Signature": ("b" if method == "PUT" else "c") * 64,
    }
    return f"https://{host}/tcc/{key}?{urlencode(params)}"


class _Response(io.BytesIO):
    def __init__(self, data, status=200):
        super().__init__(data)
        self.status = status


class R2PilotTests(unittest.TestCase):
    def test_mock_put_and_get_matches_bytes_and_digest(self):
        sent = []
        def opener(req, timeout):
            self.assertEqual(timeout, 12)
            if req.get_method() == "PUT":
                self.assertEqual(req.get_header("If-none-match"), "*")
                sent.append(req.data)
                return _Response(b"")
            self.assertTrue(sent)
            return _Response(sent[0])
        result = pilot.send_and_verify(CONFIG, KEY, signed("PUT"), signed("GET"), opener=opener, now=NOW)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["sha256"], hashlib.sha256(sent[0]).hexdigest())
        self.assertLess(result["bytes"], 256)

    def test_digest_mismatch_is_not_verified(self):
        def opener(req, timeout):
            body = b"" if req.get_method() == "PUT" else b"corrupt"
            return _Response(body)
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            pilot.send_and_verify(CONFIG, KEY, signed("PUT"), signed("GET"), opener=opener, now=NOW)

    def test_invalid_destination_or_missing_grant_is_never_contacted(self):
        def forbidden(*args, **kwargs):
            self.fail("Unexpected network call")
        invalid = (None, "https://" + HOST, signed("GET", host="evil.example"),
                   signed("GET", key=KEY.replace("piloto", "prod")), signed("GET", expiry=901))
        for get in invalid:
            with self.subTest(), self.assertRaises(ValueError):
                pilot.send_and_verify(CONFIG, KEY, signed("PUT"), get, opener=forbidden, now=NOW)

    def test_existing_key_is_not_overwritten_and_get_does_not_run(self):
        def opener(req, timeout):
            self.assertEqual(req.get_method(), "PUT")
            raise HTTPError(req.full_url, 412, "exists", {}, None)
        with self.assertRaisesRegex(RuntimeError, "HTTP 412"):
            pilot.send_and_verify(CONFIG, KEY, signed("PUT"), signed("GET"), opener=opener, now=NOW)


if __name__ == "__main__":
    unittest.main()
