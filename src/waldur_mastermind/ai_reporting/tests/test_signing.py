import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from rest_framework import test

from waldur_mastermind.ai_reporting import signing
from waldur_mastermind.ai_reporting.models import HarnessConnection


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(
        public_bytes
    ).decode()


def _set_private_key(value: str) -> None:
    connection = HarnessConnection.get()
    connection.signing_private_key = value
    connection.save()


class SignRequestTest(test.APITestCase):
    def test_returns_no_headers_when_unconfigured(self):
        _set_private_key("")
        self.assertEqual(signing.sign_request("user-1", "/query", b"{}"), {})

    def test_returns_headers_when_configured(self):
        private_b64, _ = _keypair()
        _set_private_key(private_b64)
        headers = signing.sign_request("user-1", "/query", b"{}")
        self.assertIn(signing.TIMESTAMP_HEADER, headers)
        self.assertIn(signing.SIGNATURE_HEADER, headers)

    def test_signature_actually_verifies_against_the_public_key(self):
        """Checks the signature really verifies, not just that headers exist."""
        private_b64, public_b64 = _keypair()
        _set_private_key(private_b64)
        headers = signing.sign_request("user-1", "/query", b'{"prompt": "hi"}')

        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        message = signing._canonical_message(
            headers[signing.TIMESTAMP_HEADER], "user-1", "/query", b'{"prompt": "hi"}'
        )
        # Raises InvalidSignature on failure - no exception means it verified.
        public_key.verify(base64.b64decode(headers[signing.SIGNATURE_HEADER]), message)

    def test_signature_does_not_verify_for_a_different_body(self):
        private_b64, public_b64 = _keypair()
        _set_private_key(private_b64)
        headers = signing.sign_request("user-1", "/query", b'{"prompt": "hi"}')

        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        tampered_message = signing._canonical_message(
            headers[signing.TIMESTAMP_HEADER],
            "user-1",
            "/query",
            b'{"prompt": "tampered"}',
        )
        with self.assertRaises(InvalidSignature):
            public_key.verify(
                base64.b64decode(headers[signing.SIGNATURE_HEADER]), tampered_message
            )
