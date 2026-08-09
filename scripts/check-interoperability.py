#!/usr/bin/env python3
"""Reproduce the v1 HMAC golden token independently of the Go package."""

import base64
import hashlib
import hmac
from pathlib import Path


def encode(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


header = b'{"v":1,"typ":"capability","alg":"hmac-sha256","kid":"interop"}'
payload = (
    b'{"v":1,"iss":"interop","aud":["service"],"bearer":true,'
    b'"resource":"objects/42","operation":"read","iat":1786276800,'
    b'"nbf":1786276800,"exp":1786276860,"id":"interop-capability"}'
)
message = b"cap1." + encode(header) + b"." + encode(payload)
signature = hmac.new(bytes(range(32)), message, hashlib.sha256).digest()
actual = (message + b"." + encode(signature)).decode("ascii")
expected = (Path(__file__).parent.parent / "testdata" / "v1-hmac.token").read_text(
    encoding="ascii"
).strip()

if actual != expected:
    raise SystemExit("independent HMAC golden token mismatch")
