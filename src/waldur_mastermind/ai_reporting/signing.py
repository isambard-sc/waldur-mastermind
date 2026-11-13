"""Signs each call to the AI reporting harness with an Ed25519 private key,
so the harness can check it really came from Waldur. The harness only holds
the public key (see request_signing.py in waldur-ai-harness). Does nothing
while no private key is set.

Generate a keypair with:
    python -c "
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print('private (Waldur, keep secret):', base64.b64encode(priv).decode())
    print('public (harness, not secret): ', base64.b64encode(pub).decode())
    "
The private key goes into HarnessConnection.signing_private_key; the public
key goes into the harness's WALDUR_SIGNING_PUBLIC_KEY.
"""

import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from waldur_mastermind.ai_reporting.models import HarnessConnection

SIGNATURE_HEADER = "X-Waldur-Signature"
TIMESTAMP_HEADER = "X-Waldur-Signature-Timestamp"


def _canonical_message(timestamp: str, identity: str, path: str, body: bytes) -> bytes:
    """Must match the harness's request_signing._canonical_message exactly.
    Covers identity, path and body, so a signature can't be reused for a
    different request."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{timestamp}.{identity}.{path}.{body_hash}".encode()


def sign_request(identity: str, path: str, body: bytes) -> dict[str, str]:
    """Signature headers for a harness call, or {} if no key is set."""
    private_key_b64 = HarnessConnection.get().signing_private_key
    if not private_key_b64:
        return {}
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64)
    )
    timestamp = str(int(time.time()))
    signature = private_key.sign(_canonical_message(timestamp, identity, path, body))
    return {
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: base64.b64encode(signature).decode(),
    }
