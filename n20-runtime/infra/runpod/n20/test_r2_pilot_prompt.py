from datetime import datetime, timezone
import io
import sys
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from . import r2_pilot, r2_pilot_prompt as prompt

NOW = datetime(2026, 11, 21, 1, 0, tzinfo=timezone.utc)
HOST = "0" * 32 + ".r2.cloudflarestorage.com"
CONFIG = {"endpoint": "https://" + HOST, "bucket": "tcc", "region": "auto", "prefix": "tcc/piloto"}
KEY = "tcc/piloto/smoke-" + "a" * 32 + ".txt"
DUMMY_ID = "f" * 32
DUMMY_SECRET = "e" * 64


class PromptPilotTests(unittest.TestCase):
    def test_matches_published_aws_s3_presign_vector(self):
        # Published example placeholders, not real account credentials:
        # https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html
        url = prompt._presign(
            "GET", host="examplebucket.s3.amazonaws.com", path="/test.txt", region="us-east-1",
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            now=datetime(2013, 5, 24, tzinfo=timezone.utc), expires=86400,
        )
        self.assertEqual(
            parse_qs(urlsplit(url).query)["X-Amz-Signature"],
            ["aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"],
        )

    def test_condition_and_method_are_signed_for_exact_path(self):
        put, get = prompt._create_urls(CONFIG, KEY, DUMMY_ID, DUMMY_SECRET, NOW)
        r2_pilot.validate_url(CONFIG, KEY, put, method="PUT", now=NOW)
        r2_pilot.validate_url(CONFIG, KEY, get, method="GET", now=NOW)
        p, g = [parse_qs(urlsplit(url).query) for url in (put, get)]
        self.assertEqual(p["X-Amz-Expires"], ["600"])
        self.assertEqual(p["X-Amz-SignedHeaders"], ["host;if-none-match"])
        self.assertEqual(g["X-Amz-SignedHeaders"], ["host"])
        self.assertNotEqual(p["X-Amz-Signature"], g["X-Amz-Signature"])
        self.assertNotIn(DUMMY_SECRET, put)
        self.assertNotIn(DUMMY_SECRET, get)

    def test_api_error_cannot_echo_secrets_or_urls(self):
        with patch.object(sys, "argv", ["r2_pilot_prompt"]), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch("sys.stderr", new_callable=io.StringIO) as stderr, \
             patch.object(stderr, "isatty", return_value=True), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout, \
             patch.object(prompt.r2_pilot, "load_config", return_value=CONFIG), \
             patch.object(prompt.getpass, "getpass", side_effect=(DUMMY_ID, DUMMY_SECRET)), \
             patch.object(prompt.r2_pilot, "send_and_verify", side_effect=RuntimeError(DUMMY_SECRET)):
            self.assertEqual(prompt.main(), 1)
            self.assertNotIn(DUMMY_SECRET, stderr.getvalue() + stdout.getvalue())
            self.assertNotIn("X-Amz", stderr.getvalue() + stdout.getvalue())

    def test_non_interactive_use_fails_before_input_or_network(self):
        with patch.object(sys, "argv", ["r2_pilot_prompt"]), \
             patch.object(sys.stdin, "isatty", return_value=False), \
             patch("sys.stderr", new_callable=io.StringIO), \
             patch.object(prompt.getpass, "getpass") as getpass:
            self.assertEqual(prompt.main(), 2)
            getpass.assert_not_called()


if __name__ == "__main__":
    unittest.main()
