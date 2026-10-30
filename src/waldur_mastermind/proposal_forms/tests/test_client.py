import base64
import time
from urllib.parse import parse_qs, urlsplit

from django.test import RequestFactory, TestCase

from waldur_mastermind.proposal_forms import client, models

# The Standard Webhooks reference vector (also in Svix's documentation), which
# Formbricks implements: an independent check that signatures are computed as
# Formbricks computes them.
VECTOR_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
VECTOR_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
VECTOR_TIMESTAMP = "1614265330"
VECTOR_BODY = b'{"test": 2432232314}'
VECTOR_SIGNATURE = "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


def signed_request(secret, body=b'{"event": "responseFinished"}', **overrides):
    webhook_id = overrides.pop("webhook_id", "msg_1")
    timestamp = overrides.pop("timestamp", str(int(time.time())))
    headers = {
        "HTTP_WEBHOOK_ID": webhook_id,
        "HTTP_WEBHOOK_TIMESTAMP": timestamp,
        "HTTP_WEBHOOK_SIGNATURE": overrides.pop(
            "signature", "v1," + client.sign(secret, webhook_id, timestamp, body)
        ),
    }
    headers.update(overrides)
    return RequestFactory().post(
        "/api/proposal-form-webhook/",
        data=body,
        content_type="application/json",
        **headers,
    )


class SignatureTest(TestCase):
    def set_secret(self, secret):
        models.FormbricksConnection.objects.update_or_create(
            pk=1, defaults={"webhook_secret": secret}
        )

    def test_matches_the_standard_webhooks_reference_vector(self):
        self.assertEqual(
            client.sign(VECTOR_SECRET, VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_BODY),
            VECTOR_SIGNATURE,
        )

    def test_secret_without_prefix_is_still_base64_decoded(self):
        # Formbricks decodes the secret whether or not it carries "whsec_";
        # treating an unprefixed secret as raw text gives the wrong key.
        unprefixed = VECTOR_SECRET[len("whsec_") :]
        self.assertEqual(
            client.sign(unprefixed, VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_BODY),
            VECTOR_SIGNATURE,
        )

    def test_valid_signature_accepted(self):
        self.set_secret(VECTOR_SECRET)
        self.assertTrue(client.verify_signature(signed_request(VECTOR_SECRET)))

    def test_any_of_several_signatures_may_match(self):
        self.set_secret(VECTOR_SECRET)
        body = b"{}"
        timestamp = str(int(time.time()))
        good = client.sign(VECTOR_SECRET, "msg_1", timestamp, body)
        request = signed_request(
            VECTOR_SECRET,
            body=body,
            timestamp=timestamp,
            signature=f"v1,{base64.b64encode(b'x' * 32).decode()} v1,{good}",
        )
        self.assertTrue(client.verify_signature(request))

    def test_no_secret_refuses_everything(self):
        # An empty key would let anyone compute a valid signature.
        self.set_secret("")
        forged = (
            "v1,"
            + base64.b64encode(
                client.hmac.new(b"", b"msg_1.1.{}", client.hashlib.sha256).digest()
            ).decode()
        )
        self.assertFalse(client.verify_signature(signed_request("", signature=forged)))

    def test_secret_that_is_not_base64_refuses_everything(self):
        self.set_secret("not base64!")
        self.assertFalse(client.verify_signature(signed_request(VECTOR_SECRET)))

    def test_wrong_secret_refused(self):
        self.set_secret(VECTOR_SECRET)
        other = "whsec_" + base64.b64encode(b"another secret entirely").decode()
        self.assertFalse(client.verify_signature(signed_request(other)))

    def test_tampered_body_refused(self):
        self.set_secret(VECTOR_SECRET)
        timestamp = str(int(time.time()))
        signature = "v1," + client.sign(VECTOR_SECRET, "msg_1", timestamp, b"{}")
        request = signed_request(
            VECTOR_SECRET,
            body=b'{"a": 1}',
            timestamp=timestamp,
            signature=signature,
        )
        self.assertFalse(client.verify_signature(request))

    def test_old_timestamp_refused(self):
        self.set_secret(VECTOR_SECRET)
        stale = str(int(time.time()) - client.WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS - 60)
        self.assertFalse(
            client.verify_signature(signed_request(VECTOR_SECRET, timestamp=stale))
        )

    def test_missing_headers_refused(self):
        self.set_secret(VECTOR_SECRET)
        request = RequestFactory().post(
            "/", data=b"{}", content_type="application/json"
        )
        self.assertFalse(client.verify_signature(request))

    def test_expected_signature_is_never_logged(self):
        self.set_secret(VECTOR_SECRET)
        timestamp = str(int(time.time()))
        body = b"{}"
        expected = client.sign(VECTOR_SECRET, "msg_1", timestamp, body)
        with self.assertLogs(client.logger, level="WARNING") as logs:
            client.verify_signature(
                signed_request(
                    VECTOR_SECRET, body=body, timestamp=timestamp, signature="v1,AAAA"
                )
            )
        output = "\n".join(logs.output)
        self.assertNotIn(expected, output)
        self.assertNotIn(VECTOR_SECRET[len("whsec_") :], output)


class PrefillTest(TestCase):
    def test_prefill_keeps_simple_answers_only(self):
        prefill = client.prefill_from_answers(
            {
                "q_text": "An answer",
                "q_number": 12,
                "q_multi": ["Isambard-AI", "Zenith"],
                "q_matrix": {"row": "column"},
                "q_files": [{"url": "x"}],
                "proposal_uuid": "abc",
                "redirect_token": "secret",
            }
        )
        self.assertEqual(
            prefill,
            {"q_text": "An answer", "q_number": 12, "q_multi": "Isambard-AI,Zenith"},
        )

    def test_link_params_keep_the_links_own(self):
        url = client.with_params(
            "https://f.example.com/s/s1?suId=abc&suToken=t",
            {"proposal_uuid": "p1", "suId": "forged", "q1": "a b"},
        )
        params = parse_qs(urlsplit(url).query)
        self.assertEqual(params["suId"], ["abc"])
        self.assertEqual(params["suToken"], ["t"])
        self.assertEqual(params["proposal_uuid"], ["p1"])
        self.assertEqual(params["q1"], ["a b"])
        self.assertTrue(url.startswith("https://f.example.com/s/s1?"))
        self.assertEqual(client.single_use_id(url), "abc")


class SurveyParsingTest(TestCase):
    def test_labels_hidden_fields_and_order(self):
        survey = {
            "blocks": [
                {
                    "elements": [
                        {"id": "q2", "headline": {"default": "<p>Title &amp; aim</p>"}},
                        {"id": "q1", "headline": {"default": "Summary"}},
                    ]
                }
            ],
            "hiddenFields": {"enabled": True, "fieldIds": ["proposal_uuid"]},
        }
        self.assertEqual(
            list(client.survey_labels(survey).items()),
            [("q2", "Title & aim"), ("q1", "Summary")],
        )
        self.assertEqual(client.survey_hidden_fields(survey), {"proposal_uuid"})
        survey["hiddenFields"]["enabled"] = False
        self.assertEqual(client.survey_hidden_fields(survey), set())
