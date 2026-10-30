import datetime
import json
import os
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.utils import timezone
from rest_framework import status, test

from waldur_core.core import models as core_models
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, ProposalRole
from waldur_core.permissions.utils import has_user
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.marketplace.tests import factories as marketplace_factories
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.enums import CallStates, ProposalStates
from waldur_mastermind.proposal.tests import factories as proposal_factories
from waldur_mastermind.proposal_forms import client, flows, models

SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

STEPS = [
    {
        "key": "project_details",
        "label": "Project details",
        "survey_id": "survey1",
        "reviewer_visible": True,
        "field_map": {"q_title": "name", "q_summary": "project_summary"},
        "resources": {
            "question_id": "q_service",
            "options": [
                {
                    "label": "Isambard-AI",
                    "offering_slug": "isambard-a-1",
                    "attribute_map": {"q_hours": "allocation"},
                }
            ],
        },
    },
    {"key": "team_details", "label": "Team details", "survey_id": "survey2"},
]

PROJECT_ANSWERS = {
    "q_title": "Protein folding",
    "q_summary": "We fold proteins.",
    "q_service": ["Isambard-AI"],
    "q_hours": "5000",
}


class FormsTestBase(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.support = structure_factories.UserFactory(is_support=True)
        self.user = structure_factories.UserFactory()

        self.call = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        self.round = proposal_factories.RoundFactory(
            call=self.call,
            start_time=timezone.now() - datetime.timedelta(days=1),
            cutoff_time=timezone.now() + datetime.timedelta(days=10),
        )
        self.offering = marketplace_factories.OfferingFactory(slug="isambard-a-1")
        self.requested_offering = proposal_factories.RequestedOfferingFactory(
            call=self.call, offering=self.offering
        )
        self.flow = models.FormFlow.objects.create(
            key="airr-gw", name="AIRR Gateway", steps=flows.validate_steps(STEPS)
        )
        models.CallFormFlow.objects.create(call=self.call, flow=self.flow)
        core_models.Feature.objects.update_or_create(
            key=client.FEATURE, defaults={"value": True}
        )
        models.FormbricksConnection.objects.update_or_create(
            pk=1,
            defaults={
                "enabled": True,
                "base_url": "https://forms.example.com",
                "api_key": "fb-key",
                "webhook_secret": SECRET,
            },
        )

        self.applicant = structure_factories.UserFactory()
        self.proposal = proposal_factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT, created_by=self.applicant
        )
        self.proposal.add_user(self.applicant, ProposalRole.MANAGER)

        self.call_manager = structure_factories.UserFactory()
        CallRole.MANAGER.add_permission(PermissionEnum.UPDATE_CALL)
        CallRole.MANAGER.add_permission(PermissionEnum.LIST_CALLS)
        self.call.add_user(self.call_manager, CallRole.MANAGER)


class ConnectionApiTest(FormsTestBase):
    url = "/api/formbricks-connection/"

    def test_staff_and_support_read_without_secrets(self):
        for user in (self.staff, self.support):
            self.client.force_authenticate(user)
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertNotIn("api_key", response.data)
            self.assertNotIn("webhook_secret", response.data)
            self.assertTrue(response.data["api_key_set"])
            self.assertTrue(response.data["webhook_secret_set"])
            self.assertTrue(
                response.data["webhook_url"].endswith("/api/proposal-form-webhook/")
            )
            self.assertNotIn("fb-key", response.content.decode())

    def test_others_cannot_read(self):
        self.client.force_authenticate(self.user)
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_403_FORBIDDEN
        )

    def test_only_staff_change(self):
        self.client.force_authenticate(self.support)
        response = self.client.patch(self.url, {"base_url": "https://x.example.com"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            self.url, {"base_url": "https://x.example.com", "api_key": "new-key"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        connection = models.FormbricksConnection.get()
        self.assertEqual(connection.base_url, "https://x.example.com")
        self.assertEqual(connection.api_key, "new-key")
        # Left out: kept.
        self.assertEqual(connection.webhook_secret, SECRET)

    def test_secret_must_be_a_signing_secret(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"webhook_secret": "not base64!"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_enable_until_configured(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"api_key": ""})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("enabled", response.data)

        response = self.client.patch(self.url, {"api_key": "", "enabled": False})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["api_key_set"])

    def test_bad_url_refused(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"base_url": "ftp://x"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.patch(
            self.url, {"management_api_url": "http://formbricks:3000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @mock.patch.object(client, "check_connection")
    def test_connection_test(self, check_connection):
        self.client.force_authenticate(self.staff)
        response = self.client.post(self.url + "test/")
        self.assertEqual(response.data, {"ok": True, "detail": "Connected."})

        check_connection.side_effect = client.FormbricksError("401 Unauthorized")
        response = self.client.post(self.url + "test/")
        self.assertFalse(response.data["ok"])

        self.client.force_authenticate(self.support)
        response = self.client.post(self.url + "test/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class FlowApiTest(FormsTestBase):
    url = "/api/form-flows/"

    def detail(self, flow):
        return f"{self.url}{flow.uuid.hex}/"

    def test_anyone_signed_in_reads_flows(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["key"], "airr-gw")
        self.assertEqual(response.data[0]["calls_count"], 1)

    def test_only_staff_create(self):
        payload = {"key": "other", "name": "Other", "steps": [STEPS[1]]}
        self.client.force_authenticate(self.call_manager)
        self.assertEqual(
            self.client.post(self.url, payload, format="json").status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.client.force_authenticate(self.staff)
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["steps"][0]["reviewer_visible"], False)

    def test_invalid_steps_refused_with_reason(self):
        self.client.force_authenticate(self.staff)
        response = self.client.post(
            self.url,
            {"key": "bad", "name": "Bad", "steps": [STEPS[1], STEPS[1]]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("unique", str(response.data["steps"]))

    def test_answered_step_cannot_be_removed(self):
        models.FormStepResponse.objects.create(
            proposal=self.proposal,
            step_key="team_details",
            survey_id="survey2",
            response_id="r1",
        )
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            self.detail(self.flow), {"steps": [STEPS[0]]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("team_details", str(response.data))

        # Changing a survey id is allowed: answers stay filed by step key.
        changed = [STEPS[0], dict(STEPS[1], survey_id="survey2b")]
        response = self.client.patch(
            self.detail(self.flow), {"steps": changed}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_resource_options_must_fit_linked_calls(self):
        step = json.loads(json.dumps(STEPS[0]))
        step["resources"]["options"][0]["offering_slug"] = "no-such-offering"
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            self.detail(self.flow), {"steps": [step, STEPS[1]]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("no-such-offering", str(response.data))

    def test_flow_in_use_cannot_be_deleted(self):
        self.client.force_authenticate(self.staff)
        response = self.client.delete(self.detail(self.flow))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.FormFlow.objects.filter(pk=self.flow.pk).exists())

    @mock.patch.object(client, "get_survey_definition")
    def test_check_against_formbricks(self, get_survey_definition):
        surveys = {
            "survey1": {
                "blocks": [
                    {
                        "elements": [
                            {"id": "q_title", "headline": {"default": "Title"}},
                            {"id": "q_service", "headline": {"default": "Service"}},
                        ]
                    }
                ],
                "hiddenFields": {"enabled": True, "fieldIds": ["proposal_uuid"]},
            },
            "survey2": {
                "blocks": [],
                "hiddenFields": {
                    "enabled": True,
                    "fieldIds": ["proposal_uuid", "redirect_token"],
                },
            },
        }
        get_survey_definition.side_effect = lambda survey_id: surveys[survey_id]
        self.client.force_authenticate(self.staff)
        response = self.client.post(self.detail(self.flow) + "check/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["ok"])
        first, second = response.data["steps"]
        problems = " ".join(first["problems"])
        self.assertIn("redirect_token", problems)
        self.assertIn("q_summary", problems)
        self.assertIn("q_hours", problems)
        self.assertNotIn("q_title", problems)
        self.assertTrue(second["ok"])
        self.assertIn("step=team_details", second["ending_url"])
        self.assertIn("#recall:redirect_token/fallback:#", second["ending_url"])


class CallFlowApiTest(FormsTestBase):
    def url(self, call):
        return f"/api/proposal-form-calls/{call.uuid.hex}/"

    def test_call_field_shows_flow(self):
        self.client.force_authenticate(self.call_manager)
        response = self.client.get(
            f"/api/proposal-protected-calls/{self.call.uuid.hex}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["form_flow"]["key"], "airr-gw")
        self.assertEqual(response.data["form_flow"]["name"], "AIRR Gateway")

        other = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        response = self.client.get(f"/api/proposal-public-calls/{other.uuid.hex}/")
        self.assertIsNone(response.data["form_flow"])

    def test_call_manager_sets_flow_until_proposals_exist(self):
        call = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        proposal_factories.RequestedOfferingFactory(call=call, offering=self.offering)
        call.add_user(self.call_manager, CallRole.MANAGER)
        self.client.force_authenticate(self.call_manager)

        response = self.client.put(
            self.url(call), {"flow": self.flow.uuid.hex}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["flow_key"], "airr-gw")
        self.assertFalse(response.data["locked"])

        proposal_factories.ProposalFactory(
            round=proposal_factories.RoundFactory(call=call)
        )
        response = self.client.put(self.url(call), {"flow": None}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(self.client.get(self.url(call)).data["locked"])

    def test_flow_must_fit_the_calls_offerings(self):
        call = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        call.add_user(self.call_manager, CallRole.MANAGER)
        self.client.force_authenticate(self.call_manager)
        response = self.client.put(
            self.url(call), {"flow": self.flow.uuid.hex}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("isambard-a-1", str(response.data))

    def test_others_cannot_set_flow(self):
        reviewer = structure_factories.UserFactory()
        CallRole.REVIEWER.add_permission(PermissionEnum.LIST_CALLS)
        self.call.add_user(reviewer, CallRole.REVIEWER)
        for user, expected in (
            (reviewer, status.HTTP_403_FORBIDDEN),
            (self.user, status.HTTP_404_NOT_FOUND),
        ):
            self.client.force_authenticate(user)
            response = self.client.put(
                self.url(self.call), {"flow": None}, format="json"
            )
            self.assertEqual(response.status_code, expected)


class StartAndProgressTest(FormsTestBase):
    def test_start_creates_draft_with_first_survey(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(
            "/api/proposal-forms/start/", {"round_uuid": self.round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        proposal = proposal_models.Proposal.objects.get(
            uuid=response.data["proposal_uuid"]
        )
        self.assertEqual(proposal.state, ProposalStates.DRAFT)
        self.assertEqual(proposal.created_by, self.user)
        self.assertTrue(has_user(proposal, self.user, ProposalRole.MANAGER))
        self.assertEqual(response.data["step_key"], "project_details")
        url = urlsplit(response.data["survey_url"])
        self.assertEqual(url.path, "/s/survey1")
        params = parse_qs(url.query)
        self.assertEqual(params["proposal_uuid"], [proposal.uuid.hex])
        self.assertEqual(
            client.verify_redirect_token(
                params["redirect_token"][0], proposal.uuid.hex
            ),
            self.user.pk,
        )

    def test_start_refused_when_not_set_up(self):
        self.client.force_authenticate(self.user)
        other = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        other_round = proposal_factories.RoundFactory(
            call=other,
            start_time=timezone.now() - datetime.timedelta(days=1),
            cutoff_time=timezone.now() + datetime.timedelta(days=1),
        )
        response = self.client.post(
            "/api/proposal-forms/start/", {"round_uuid": other_round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        models.FormbricksConnection.objects.filter(pk=1).update(enabled=False)
        response = self.client.post(
            "/api/proposal-forms/start/", {"round_uuid": self.round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_start_refused_when_round_closed(self):
        self.round.cutoff_time = timezone.now() - datetime.timedelta(minutes=1)
        self.round.save()
        self.client.force_authenticate(self.user)
        response = self.client.post(
            "/api/proposal-forms/start/", {"round_uuid": self.round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def answer(self, step_key, raw):
        return models.FormStepResponse.objects.create(
            proposal=self.proposal,
            step_key=step_key,
            survey_id=flows.get_step(self.flow.steps, step_key)["survey_id"],
            response_id=f"r-{step_key}",
            raw_response=raw,
            question_labels={"q_a": "Question A"},
            question_order=["q_a"],
        )

    def test_applicant_progress(self):
        self.answer("project_details", {"q_a": "yes", "proposal_uuid": "x"})
        self.client.force_authenticate(self.applicant)
        response = self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["can_fill_in"])
        self.assertEqual(
            [(s["key"], s["completed"]) for s in response.data["steps"]],
            [("project_details", True), ("team_details", False)],
        )
        self.assertEqual(response.data["next_step"]["step_key"], "team_details")
        (answers,) = response.data["responses"]
        self.assertEqual(answers["step_label"], "Project details")
        self.assertEqual(
            answers["questions"],
            [{"question_id": "q_a", "label": "Question A", "answer": "yes"}],
        )

    def test_reviewer_sees_only_reviewer_visible_steps(self):
        self.answer("project_details", {"q_a": "yes"})
        self.answer("team_details", {"q_a": "private"})
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        reviewer = structure_factories.UserFactory()
        proposal_factories.ReviewFactory(proposal=self.proposal, reviewer=reviewer)

        self.client.force_authenticate(reviewer)
        response = self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["can_fill_in"])
        self.assertIsNone(response.data["next_step"])
        self.assertEqual(
            [r["step_key"] for r in response.data["responses"]], ["project_details"]
        )

        self.client.force_authenticate(self.call_manager)
        response = self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")
        self.assertEqual(len(response.data["responses"]), 2)

    def test_strangers_cannot_see(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @mock.patch.object(client, "get_response")
    def test_edit_link_prefills_and_carries_token(self, get_response):
        self.answer("project_details", {"q_a": "old"})
        get_response.return_value = {
            "q_title": "New title",
            "q_service": ["Isambard-AI"],
            "redirect_token": "stale",
        }
        self.client.force_authenticate(self.applicant)
        response = self.client.get(
            f"/api/proposal-forms/{self.proposal.uuid.hex}/edit-link/",
            {"step": "project_details"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        params = parse_qs(urlsplit(response.data["survey_url"]).query)
        self.assertEqual(params["q_title"], ["New title"])
        self.assertEqual(params["q_service"], ["Isambard-AI"])
        self.assertIsNotNone(
            client.verify_redirect_token(
                params["redirect_token"][0], self.proposal.uuid.hex
            )
        )

    def test_edit_link_only_for_team_while_draft(self):
        self.answer("project_details", {"q_a": "old"})
        self.client.force_authenticate(self.staff)
        response = self.client.get(
            f"/api/proposal-forms/{self.proposal.uuid.hex}/edit-link/",
            {"step": "project_details"},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.client.force_authenticate(self.applicant)
        response = self.client.get(
            f"/api/proposal-forms/{self.proposal.uuid.hex}/edit-link/",
            {"step": "project_details"},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class RedirectTest(FormsTestBase):
    url = "/api/proposal-form-redirect/"

    def get(self, step, token=None, proposal=None):
        proposal = proposal or self.proposal
        token = token or client.build_redirect_token(self.applicant, proposal)
        return self.client.get(
            self.url,
            {"step": step, "proposal_uuid": proposal.uuid.hex, "redirect_token": token},
        )

    def test_goes_on_to_next_step(self):
        response = self.get("project_details")
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn("/s/survey2?", response["Location"])

    def test_back_to_proposal_when_all_answered(self):
        models.FormStepResponse.objects.create(
            proposal=self.proposal,
            step_key="project_details",
            survey_id="survey1",
            response_id="r1",
        )
        response = self.get("team_details")
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn(f"proposals/{self.proposal.uuid.hex}/", response["Location"])

    def test_token_for_another_proposal_refused(self):
        other = proposal_factories.ProposalFactory(round=self.round)
        other.add_user(self.applicant, ProposalRole.MANAGER)
        token = client.build_redirect_token(self.applicant, other)
        response = self.get("project_details", token=token)
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )

    def test_token_does_not_authenticate_elsewhere(self):
        token = client.build_redirect_token(self.applicant, self.proposal)
        response = self.client.get(
            f"/api/proposal-forms/{self.proposal.uuid.hex}/",
            {"redirect_token": token, "proposal_uuid": self.proposal.uuid.hex},
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class WebhookTest(FormsTestBase):
    url = "/api/proposal-form-webhook/"

    def post(self, payload, secret=SECRET):
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        signature = "v1," + client.sign(secret, "msg_1", timestamp, body)
        return self.client.generic(
            "POST",
            self.url,
            body,
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_1",
            HTTP_WEBHOOK_TIMESTAMP=timestamp,
            HTTP_WEBHOOK_SIGNATURE=signature,
        )

    def payload(self, answers=None, survey_id="survey1", proposal=None, user=None):
        proposal = proposal or self.proposal
        user = user or self.applicant
        data = {
            **(PROJECT_ANSWERS if answers is None else answers),
            "proposal_uuid": proposal.uuid.hex,
            "redirect_token": client.build_redirect_token(user, proposal),
        }
        # The shape Formbricks sends (process-webhook-delivery-job.ts).
        return {
            "webhookId": "wh1",
            "event": "responseFinished",
            "data": {
                "id": "resp1",
                "surveyId": survey_id,
                "finished": True,
                "data": data,
                "survey": {"id": survey_id, "title": "Project details"},
            },
        }

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(
            client,
            "get_survey",
            return_value={"q_title": "Project title", "q_summary": "Summary"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_answers_kept_and_written_onto_proposal(self):
        response = self.post(self.payload())
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.name, "Protein folding")
        self.assertEqual(self.proposal.project_summary, "We fold proteins.")
        resource = self.proposal.requestedresource_set.get(
            requested_offering=self.requested_offering
        )
        self.assertEqual(resource.attributes, {"allocation": "5000"})

        stored = models.FormStepResponse.objects.get(proposal=self.proposal)
        self.assertEqual(stored.step_key, "project_details")
        self.assertEqual(stored.response_id, "resp1")
        self.assertEqual(stored.question_order, ["q_title", "q_summary"])
        # The token is a credential, so it is not kept.
        self.assertNotIn("redirect_token", stored.raw_response)

    def test_answering_again_replaces_resource_choice(self):
        self.post(self.payload())
        answers = dict(PROJECT_ANSWERS, q_service=[])
        self.post(self.payload(answers))
        self.assertFalse(self.proposal.requestedresource_set.exists())
        self.assertEqual(models.FormStepResponse.objects.count(), 1)

    def test_bad_signature_refused(self):
        other = "whsec_" + "QUJD" * 8
        response = self.post(self.payload(), secret=other)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_no_secret_refuses_even_matching_empty_signature(self):
        # Without a secret the connection is not configured, so the webhook
        # stops before the signature is even read; verify_signature refuses
        # an empty key on its own too (test_client.SignatureTest).
        models.FormbricksConnection.objects.filter(pk=1).update(webhook_secret="")
        response = self.post(self.payload(), secret="")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_formbricks_test_ping_acknowledged(self):
        # Formbricks signs its test with a secret Waldur cannot know yet, and
        # fails the test on any 5xx, 404 or 405.
        for configured in (True, False):
            models.FormbricksConnection.objects.filter(pk=1).update(enabled=configured)
            response = self.post(
                {"event": "testEndpoint"}, secret="whsec_" + "QUJD" * 8
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_answers_without_valid_token_refused(self):
        # Anyone can fill in a survey: a hidden proposal_uuid typed into the
        # survey link must not be enough to write onto a proposal.
        payload = self.payload()
        payload["data"]["data"]["redirect_token"] = "forged"
        self.assertEqual(self.post(payload).status_code, status.HTTP_403_FORBIDDEN)

        payload = self.payload()
        del payload["data"]["data"]["redirect_token"]
        self.assertEqual(self.post(payload).status_code, status.HTTP_403_FORBIDDEN)

        other = proposal_factories.ProposalFactory(round=self.round)
        payload = self.payload()
        payload["data"]["data"]["proposal_uuid"] = other.uuid.hex
        self.assertEqual(self.post(payload).status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_submitted_proposal_not_changed(self):
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        response = self.post(self.payload())
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.proposal.refresh_from_db()
        self.assertNotEqual(self.proposal.name, "Protein folding")

    def test_user_no_longer_on_team_refused(self):
        stranger = structure_factories.UserFactory()
        response = self.post(self.payload(user=stranger))
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_survey_not_in_flow_refused(self):
        response = self.post(self.payload(survey_id="elsewhere"))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_missing_answer_saves_nothing(self):
        answers = dict(PROJECT_ANSWERS)
        del answers["q_summary"]
        response = self.post(self.payload(answers))
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertFalse(models.FormStepResponse.objects.exists())
        self.proposal.refresh_from_db()
        self.assertNotEqual(self.proposal.name, "Protein folding")

    def test_other_events_ignored(self):
        payload = self.payload()
        payload["event"] = "responseCreated"
        self.assertEqual(self.post(payload).status_code, status.HTTP_200_OK)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_step_without_mapping_kept(self):
        response = self.post(self.payload({"q_team": "Alice"}, survey_id="survey2"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        stored = models.FormStepResponse.objects.get(step_key="team_details")
        self.assertEqual(stored.raw_response["q_team"], "Alice")


class SwitchedOffTest(FormsTestBase):
    """Nothing reaches applicants unless the feature is on and the
    connection is enabled; switching either off hides it again."""

    def switch_off(self, what, on=False):
        if what == "feature":
            core_models.Feature.objects.filter(key=client.FEATURE).update(value=on)
        else:
            models.FormbricksConnection.objects.filter(pk=1).update(enabled=on)

    def test_each_switch_hides_forms(self):
        for what in ("feature", "connection"):
            with self.subTest(what):
                self.switch_off(what)
                self.client.force_authenticate(self.user)
                response = self.client.post(
                    "/api/proposal-forms/start/", {"round_uuid": self.round.uuid.hex}
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

                # Calls offer Waldur's own form instead.
                response = self.client.get(
                    f"/api/proposal-public-calls/{self.call.uuid.hex}/"
                )
                self.assertIsNone(response.data["form_flow"])

                self.client.force_authenticate(self.applicant)
                response = self.client.get(
                    f"/api/proposal-forms/{self.proposal.uuid.hex}/"
                )
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertIsNone(response.data["next_step"])

                token = client.build_redirect_token(self.applicant, self.proposal)
                response = self.client.get(
                    "/api/proposal-form-redirect/",
                    {
                        "step": "project_details",
                        "proposal_uuid": self.proposal.uuid.hex,
                        "redirect_token": token,
                    },
                )
                self.assertIn(
                    f"proposals/{self.proposal.uuid.hex}/", response["Location"]
                )
                self.switch_off(what, on=True)

    def test_call_flow_cannot_be_chosen_while_off(self):
        self.switch_off("feature")
        call = proposal_factories.CallFactory(state=CallStates.ACTIVE)
        proposal_factories.RequestedOfferingFactory(call=call, offering=self.offering)
        call.add_user(self.call_manager, CallRole.MANAGER)
        self.client.force_authenticate(self.call_manager)
        url = f"/api/proposal-form-calls/{call.uuid.hex}/"
        response = self.client.put(url, {"flow": self.flow.uuid.hex}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("not enabled", str(response.data["flow"]))
        # Taking a flow off is always allowed.
        response = self.client.put(url, {"flow": None}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_webhook_ignored_while_off(self):
        self.switch_off("feature")
        body = b'{"event": "responseFinished"}'
        timestamp = str(int(time.time()))
        response = self.client.generic(
            "POST",
            "/api/proposal-form-webhook/",
            body,
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_1",
            HTTP_WEBHOOK_TIMESTAMP=timestamp,
            HTTP_WEBHOOK_SIGNATURE="v1,"
            + client.sign(SECRET, "msg_1", timestamp, body),
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_staff_can_set_up_before_switching_on(self):
        self.switch_off("feature")
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            "/api/formbricks-connection/", {"base_url": "https://f.example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(
            "/api/form-flows/",
            {"key": "other", "name": "Other", "steps": [STEPS[1]]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class RealPayloadTest(FormsTestBase):
    """A responseFinished delivery captured from a live Formbricks, redacted
    (tests/fixtures/formbricks_response_finished.json), replayed through the
    webhook: the proposal and token are this test's, everything else is as
    Formbricks sent it."""

    FIXTURE = os.path.join(
        os.path.dirname(__file__), "fixtures", "formbricks_response_finished.json"
    )
    LABELS = {
        "cid9d22768jyf65hht3sakqq": "Project title",
        "g81oicc5tihv86395lclkfpz": "Project duration, in months",
        "j4b388ormyl4jiwajx158uel": "GPUh requested",
        "tf4lhp5vsvc7993sx27q5ugd": "AIRR service requested",
    }

    def setUp(self):
        super().setUp()
        self.flow.steps = flows.validate_steps(
            [
                {
                    "key": "project_details",
                    "label": "Project details",
                    "survey_id": "t14sgutihynd7edwluh8trg1",
                    "reviewer_visible": True,
                    "field_map": {"cid9d22768jyf65hht3sakqq": "name"},
                }
            ]
        )
        self.flow.save()
        patcher = mock.patch.object(client, "get_survey", return_value=self.LABELS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def payload(self):
        with open(self.FIXTURE, encoding="utf-8") as f:
            payload = json.load(f)
        answers = payload["data"]["data"]
        answers["proposal_uuid"] = self.proposal.uuid.hex
        answers["redirect_token"] = client.build_redirect_token(
            self.applicant, self.proposal
        )
        return payload

    def post(self, payload):
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        return self.client.generic(
            "POST",
            "/api/proposal-form-webhook/",
            body,
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_real",
            HTTP_WEBHOOK_TIMESTAMP=timestamp,
            HTTP_WEBHOOK_SIGNATURE="v1,"
            + client.sign(SECRET, "msg_real", timestamp, body),
        )

    def test_real_delivery_is_kept_and_mapped(self):
        response = self.post(self.payload())
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.name, "My new project application")

        stored = models.FormStepResponse.objects.get(proposal=self.proposal)
        self.assertEqual(stored.step_key, "project_details")
        self.assertEqual(stored.survey_id, "t14sgutihynd7edwluh8trg1")
        self.assertEqual(stored.response_id, "cmvufemih0003u6014xwem7kl")
        self.assertNotIn("redirect_token", stored.raw_response)
        # Formbricks sends every answer as text.
        self.assertEqual(stored.raw_response["j4b388ormyl4jiwajx158uel"], "1234")

        self.client.force_authenticate(self.applicant)
        response = self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")
        (answers,) = response.data["responses"]
        self.assertEqual(
            [(q["label"], q["answer"]) for q in answers["questions"]],
            [
                ("Project title", "My new project application"),
                ("Project duration, in months", "5"),
                ("GPUh requested", "1234"),
                ("AIRR service requested", "Zenith"),
            ],
        )
        self.assertTrue(response.data["steps"][0]["completed"])
        self.assertIsNone(response.data["next_step"])

    def test_real_delivery_replayed_for_another_proposal_refused(self):
        # The captured body as delivered names a proposal it holds no valid
        # token for: refused.
        with open(self.FIXTURE, encoding="utf-8") as f:
            payload = json.load(f)
        response = self.post(payload)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(models.FormStepResponse.objects.exists())
