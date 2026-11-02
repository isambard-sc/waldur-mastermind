"""Signs each call to the AI reporting harness with Waldur's own Ed25519
private key, so the harness can verify a request genuinely came from
Waldur - not just from something that can reach its NetworkPolicy-
restricted port. See request_signing.py in the waldur-ai-harness repo for
the verifying half and the fuller design rationale.

Asymmetric by design, not a shared secret: only this (private) key is ever
a secret Waldur has to protect; the harness only ever holds the
corresponding public key (see AI_REPORTING_SIGNING_PRIVATE_KEY in
base_settings.py), which isn't sensitive at all - a leak of the harness's
copy is a non-event, unlike a shared secret that would need rotating on
both sides.

Inert when AI_REPORTING_SIGNING_PRIVATE_KEY isn't configured (empty, the
default) - sign_request() just returns no extra headers, and every request
goes out exactly as it did before this existed.
"""

import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings

SIGNATURE_HEADER = "X-Waldur-Signature"
TIMESTAMP_HEADER = "X-Waldur-Signature-Timestamp"


def _canonical_message(timestamp: str, identity: str, path: str, body: bytes) -> bytes:
    """Must match request_signing._canonical_message byte for byte on the
    harness side - timestamp, the claimed identity, the request path, and a
    hash of the body, so a valid signature is bound to exactly this request
    and cannot be replayed for a different identity, path, or payload."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{timestamp}.{identity}.{path}.{body_hash}".encode()


def sign_request(identity: str, path: str, body: bytes) -> dict[str, str]:
    """Headers to add to a call to the harness - an empty dict if no signing
    key is configured, so the request goes out unsigned exactly as before."""
    if not settings.AI_REPORTING_SIGNING_PRIVATE_KEY:
        return {}
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(settings.AI_REPORTING_SIGNING_PRIVATE_KEY)
    )
    timestamp = str(int(time.time()))
    signature = private_key.sign(_canonical_message(timestamp, identity, path, body))
    return {
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: base64.b64encode(signature).decode(),
    }
