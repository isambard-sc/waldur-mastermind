import base64
import hashlib
import hmac
import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.urls import reverse
from rest_framework import status, test

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.permissions.utils import has_user
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.marketplace.tests import factories as marketplace_factories
from waldur_mastermind.proposal import formbricks_client, formbricks_flows, models
from waldur_mastermind.proposal.enums import ProposalStates, RequestedOfferingStates
from waldur_mastermind.proposal.tests import factories, fixtures

TEST_FLOW_KEY = "test-flow"

PROJECT_DETAILS_STEP = {
    "key": "project_details",
    "survey_id": "survey-project-details",
    "field_map": {
        "q_name": "name",
        "q_summary": "project_summary",
    },
    "integer_field_map": {
        "q_duration": "duration_in_days",
    },
    "boolean_field_map": {
        "q_confidential": "project_is_confidential",
        "q_civilian": "project_has_civilian_purpose",
    },
    "resource_question_id": "q_resources",
    # Answers are Formbricks choice *labels*, not slugs - deliberately
    # distinct from the "test-offering" slug key below, to exercise the
    # translation step rather than have it pass by coincidence.
    "resource_label_to_slug": {
        "Test Offering": "test-offering",
    },
    "resource_options": {
        "test-offering": {
            # "allocation" (GPU-hours), not "num_gpus" - matches
            # waldur_openportal's Resource.options["allocation"] key name.
            # No default_attributes: storage isn't assigned by the resource.
            "attribute_field_map": {"q_num_gpus": "allocation"},
            "default_attributes": {},
        },
    },
    "mapper": "map_project_details",
}
TEAM_DETAILS_STEP = {"key": "team_details", "survey_id": "survey-team-details"}
COMPLIANCE_STEP = {"key": "compliance", "survey_id": "survey-compliance"}
ASSESSMENT_STEP = {"key": "assessment", "survey_id": "survey-assessment"}

TEST_FORM_FLOWS = {
    TEST_FLOW_KEY: [
        PROJECT_DETAILS_STEP,
        TEAM_DETAILS_STEP,
        COMPLIANCE_STEP,
        ASSESSMENT_STEP,
    ],
}


def sign(body_bytes, webhook_id="msg_test", timestamp=None):
    """Build Standard Webhooks headers for `body_bytes`, matching
    formbricks_client.verify_signature.

    Reuses formbricks_client._signing_key() rather than reimplementing the
    whsec_-prefix handling here, so this can never silently drift from what
    verify_signature actually checks against (as it did when this secret
    was a plain placeholder string and this helper's own hand-rolled
    key derivation happened to agree with it by coincidence).
    """
    if timestamp is None:
        timestamp = str(int(time.time()))
    secret = settings.WALDUR_PROPOSAL["FORMBRICKS_WEBHOOK_SECRET"]
    signed_content = f"{webhook_id}.{timestamp}.{body_bytes.decode()}"
    signature = base64.b64encode(
        hmac.new(
            formbricks_client._signing_key(secret),
            signed_content.encode(),
            hashlib.sha256,
        ).digest()
    ).decode()
    return webhook_id, timestamp, f"v1,{signature}"


def query_params(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def build_payload(survey_id, response_id, data):
    return {
        "event": "responseFinished",
        "data": {"id": response_id, "surveyId": survey_id, "data": data},
    }


class FormbricksTestCase(test.APITransactionTestCase):
    """Base class wiring a small test-only FORM_FLOWS in place of the real,
    placeholder-filled one in formbricks_flows.py."""

    def setUp(self):
        super().setUp()
        self.fixture = fixtures.ProposalFixture()
        self.fixture.call.formbricks_flow_key = TEST_FLOW_KEY
        self.fixture.call.save()

        # A dedicated offering/RequestedOffering, rather than repurposing
        # self.fixture.offering - that one already backs two RequestedOffering
        # rows via the fixture (requested_offering + requested_offering_accepted),
        # so renaming it would make both match this test's lookup by slug.
        self.test_offering = marketplace_factories.OfferingFactory(
            slug="test-offering", customer=self.fixture.customer
        )
        factories.RequestedOfferingFactory(
            call=self.fixture.call,
            offering=self.test_offering,
            state=RequestedOfferingStates.REQUESTED,
        )

        # Not granted by any migration - every test suite that exercises
        # is_proposal_manager-gated actions (submit/destroy/add_user/here)
        # must grant this itself, same as test_invitation.py does.
        ProposalRole.MANAGER.add_permission(PermissionEnum.MANAGE_PROPOSAL)

        patcher = mock.patch.object(formbricks_flows, "FORM_FLOWS", TEST_FORM_FLOWS)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.webhook_url = reverse("proposal-formbricks-webhook-list")

    def post_webhook(self, payload, **sign_kwargs):
        body = json.dumps(payload).encode()
        webhook_id, timestamp, signature = sign(body, **sign_kwargs)
        return self.client.post(
            self.webhook_url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_ID=webhook_id,
            HTTP_WEBHOOK_TIMESTAMP=timestamp,
            HTTP_WEBHOOK_SIGNATURE=signature,
        )


class WebhookSignatureTest(FormbricksTestCase):
    def test_invalid_signature_is_rejected(self):
        payload = build_payload("survey-team-details", "resp-1", {})
        body = json.dumps(payload).encode()
        response = self.client.post(
            self.webhook_url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_test",
            HTTP_WEBHOOK_TIMESTAMP=str(int(time.time())),
            HTTP_WEBHOOK_SIGNATURE="v1,not-a-real-signature",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_missing_signature_headers_are_rejected(self):
        payload = build_payload("survey-team-details", "resp-1", {})
        response = self.client.post(self.webhook_url, data=payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_stale_timestamp_is_rejected(self):
        payload = build_payload("survey-team-details", "resp-1", {})
        response = self.post_webhook(payload, timestamp=str(int(time.time()) - 3600))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_non_response_finished_event_is_ignored(self):
        payload = {"event": "responseCreated", "data": {}}
        response = self.post_webhook(payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(models.FormStepResponse.objects.count(), 0)


class WebhookMappingTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )

    @mock.patch.object(formbricks_client, "get_survey")
    def test_project_details_step_maps_fields_and_creates_resource(
        self, mock_get_survey
    ):
        mock_get_survey.return_value = {
            "q_name": "Project title",
            "q_summary": "Summary",
            "q_duration": "Duration",
            "q_confidential": "Confidential?",
            "q_civilian": "Civilian purpose?",
            "q_resources": "Which resources?",
            "q_num_gpus": "How many GPU-hours do you need?",
        }
        answers = {
            "proposal_uuid": str(self.proposal.uuid),
            "q_name": "My project",
            "q_summary": "A summary",
            # Formbricks sends every answer as a string (or list of
            # strings), regardless of the question type - this exercises
            # the integer_field_map/boolean_field_map coercion, not just
            # the plain field_map passthrough.
            "q_duration": "30",
            "q_confidential": "Yes",
            "q_civilian": "No",
            "q_resources": ["Test Offering"],
            "q_num_gpus": 4,
        }
        response = self.post_webhook(
            build_payload("survey-project-details", "resp-1", answers)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.name, "My project")
        self.assertEqual(self.proposal.project_summary, "A summary")
        self.assertEqual(self.proposal.duration_in_days, 30)
        self.assertTrue(self.proposal.project_is_confidential)
        self.assertFalse(self.proposal.project_has_civilian_purpose)
        # project_details is not the last step - proposal must stay DRAFT.
        self.assertEqual(self.proposal.state, ProposalStates.DRAFT)

        requested_resource = models.RequestedResource.objects.get(
            proposal=self.proposal
        )
        self.assertEqual(requested_resource.attributes, {"allocation": 4})

        form_step_response = models.FormStepResponse.objects.get(
            proposal=self.proposal, step_key="project_details"
        )
        self.assertEqual(form_step_response.response_id, "resp-1")
        self.assertEqual(form_step_response.raw_response, answers)
        self.assertEqual(form_step_response.question_labels["q_name"], "Project title")

    @mock.patch.object(formbricks_client, "get_survey")
    def test_boolean_field_with_unexpected_value_fails_loudly(self, mock_get_survey):
        mock_get_survey.return_value = {}
        answers = {
            "proposal_uuid": str(self.proposal.uuid),
            "q_name": "My project",
            "q_summary": "A summary",
            "q_duration": "30",
            "q_confidential": "Maybe",  # not "Yes"/"No" - question type may
            "q_civilian": "No",  # have changed without updating the config.
            "q_resources": [],
        }
        # Django's test client re-raises uncaught view exceptions by default
        # (to surface the real traceback in test output) instead of turning
        # them into a 500 response - opt out so this test can observe what a
        # real caller (Formbricks) would actually get back.
        self.client.raise_request_exception = False
        response = self.post_webhook(
            build_payload("survey-project-details", "resp-bad-bool", answers)
        )
        # Uncaught FormbricksMappingError surfaces as a 500 - deliberate:
        # fail loudly rather than silently mis-map a confidentiality flag.
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    @mock.patch.object(formbricks_client, "get_survey")
    def test_integer_field_with_unexpected_value_fails_loudly(self, mock_get_survey):
        mock_get_survey.return_value = {}
        answers = {
            "proposal_uuid": str(self.proposal.uuid),
            "q_name": "My project",
            "q_summary": "A summary",
            "q_duration": "thirty",  # not parseable as an int
            "q_confidential": "Yes",
            "q_civilian": "No",
            "q_resources": [],
        }
        self.client.raise_request_exception = False
        response = self.post_webhook(
            build_payload("survey-project-details", "resp-bad-int", answers)
        )
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    @mock.patch.object(formbricks_client, "get_survey")
    def test_step_without_mapper_is_snapshotted_but_not_mapped(self, mock_get_survey):
        mock_get_survey.return_value = {"q_free_text": "Tell us about your team"}
        answers = {
            "proposal_uuid": str(self.proposal.uuid),
            "q_free_text": "Alice and Bob",
        }
        response = self.post_webhook(
            build_payload("survey-team-details", "resp-2", answers)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        form_step_response = models.FormStepResponse.objects.get(
            proposal=self.proposal, step_key="team_details"
        )
        self.assertEqual(form_step_response.raw_response, answers)

        self.proposal.refresh_from_db()
        # team_details has no field_map - nothing should have been written
        # to any Proposal field, and it's not the last step, so still DRAFT.
        self.assertEqual(self.proposal.state, ProposalStates.DRAFT)

    @mock.patch.object(formbricks_client, "get_survey")
    def test_submit_fires_only_after_last_step(self, mock_get_survey):
        mock_get_survey.return_value = {}

        for step in (PROJECT_DETAILS_STEP, TEAM_DETAILS_STEP, COMPLIANCE_STEP):
            answers = {"proposal_uuid": str(self.proposal.uuid)}
            if step is PROJECT_DETAILS_STEP:
                answers.update(
                    {
                        "q_name": "My project",
                        "q_summary": "Summary",
                        "q_duration": "10",
                        "q_confidential": "No",
                        "q_civilian": "Yes",
                        "q_resources": [],
                    }
                )
            response = self.post_webhook(
                build_payload(step["survey_id"], f"resp-{step['key']}", answers)
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.proposal.refresh_from_db()
            self.assertEqual(self.proposal.state, ProposalStates.DRAFT)

        response = self.post_webhook(
            build_payload(
                ASSESSMENT_STEP["survey_id"],
                "resp-assessment",
                {"proposal_uuid": str(self.proposal.uuid)},
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.SUBMITTED)

    @mock.patch.object(formbricks_client, "get_survey")
    def test_editing_overwrites_the_same_row_not_a_duplicate(self, mock_get_survey):
        mock_get_survey.side_effect = [
            {"q_free_text": "old wording"},
            {"q_free_text": "new wording"},
        ]
        self.post_webhook(
            build_payload(
                "survey-team-details",
                "resp-first",
                {"proposal_uuid": str(self.proposal.uuid), "q_free_text": "v1"},
            )
        )
        self.post_webhook(
            build_payload(
                "survey-team-details",
                "resp-second",
                {"proposal_uuid": str(self.proposal.uuid), "q_free_text": "v2"},
            )
        )

        self.assertEqual(
            models.FormStepResponse.objects.filter(
                proposal=self.proposal, step_key="team_details"
            ).count(),
            1,
        )
        form_step_response = models.FormStepResponse.objects.get(
            proposal=self.proposal, step_key="team_details"
        )
        self.assertEqual(form_step_response.response_id, "resp-second")
        self.assertEqual(form_step_response.raw_response["q_free_text"], "v2")
        self.assertEqual(
            form_step_response.question_labels["q_free_text"], "new wording"
        )

    @mock.patch.object(formbricks_client, "get_survey")
    def test_schema_fetch_failure_is_non_fatal(self, mock_get_survey):
        mock_get_survey.side_effect = Exception("Formbricks unreachable")
        answers = {
            "proposal_uuid": str(self.proposal.uuid),
            "q_free_text": "Alice and Bob",
        }
        response = self.post_webhook(
            build_payload("survey-team-details", "resp-3", answers)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        form_step_response = models.FormStepResponse.objects.get(
            proposal=self.proposal, step_key="team_details"
        )
        self.assertEqual(form_step_response.raw_response, answers)
        self.assertEqual(form_step_response.question_labels, {})


class StartFormbricksFlowTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.url = factories.ProposalFactory.get_list_url(
            action="start-formbricks-flow"
        )
        self.lead = structure_factories.UserFactory()

    def test_creates_draft_proposal_and_grants_lead_role(self):
        self.client.force_authenticate(self.lead)
        response = self.client.post(
            self.url, {"round_uuid": self.fixture.round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        proposal = models.Proposal.objects.get(uuid=response.data["proposal_uuid"])
        self.assertEqual(proposal.state, ProposalStates.DRAFT)
        self.assertTrue(has_user(proposal, self.lead, ProposalRole.MANAGER))
        self.assertIn(PROJECT_DETAILS_STEP["survey_id"], response.data["redirect_url"])
        self.assertIn(str(proposal.uuid), response.data["redirect_url"])

        params = query_params(response.data["redirect_url"])
        self.assertEqual(params["lead_name"], self.lead.full_name)
        self.assertEqual(params["lead_email"], self.lead.email)

    def test_rejects_call_without_formbricks_flow_key(self):
        self.fixture.call.formbricks_flow_key = None
        self.fixture.call.save()

        self.client.force_authenticate(self.lead)
        response = self.client.post(
            self.url, {"round_uuid": self.fixture.round.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class FormbricksRedirectTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )
        self.lead = structure_factories.UserFactory()
        self.proposal.add_user(self.lead, ProposalRole.MANAGER, created_by=self.lead)

    def test_lead_gets_redirected_to_next_step(self):
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-redirect"
        )
        response = self.client.get(url, {"current_step": "project_details"})
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn(TEAM_DETAILS_STEP["survey_id"], response.url)

        params = query_params(response.url)
        self.assertEqual(params["lead_name"], self.lead.full_name)
        self.assertEqual(params["lead_email"], self.lead.email)

    def test_last_step_redirects_to_frontend_completion_url(self):
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-redirect"
        )
        response = self.client.get(url, {"current_step": "assessment"})
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn(str(self.proposal.uuid), response.url)

    def test_unrelated_user_gets_404_not_403(self):
        # A user with no connection to this proposal (not the Lead, not a
        # reviewer, not a call manager) fails the visibility queryset
        # entirely, matching the codebase's existing convention elsewhere
        # (e.g. ProposalGetTest.test_proposal_should_not_be_visible) - 403
        # is reserved for someone who CAN see the proposal but lacks write
        # access (e.g. a reviewer).
        other_user = structure_factories.UserFactory()
        self.client.force_authenticate(other_user)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-redirect"
        )
        response = self.client.get(url, {"current_step": "project_details"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class FormbricksEditLinkTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )
        self.lead = structure_factories.UserFactory()
        self.proposal.add_user(self.lead, ProposalRole.MANAGER, created_by=self.lead)
        models.FormStepResponse.objects.create(
            proposal=self.proposal,
            step_key="team_details",
            survey_id="survey-team-details",
            response_id="resp-1",
            raw_response={"q_free_text": "old answer"},
            question_labels={"q_free_text": "Tell us about your team"},
        )

    @mock.patch.object(formbricks_client, "get_response")
    def test_returns_prefilled_url_from_live_fetch(self, mock_get_response):
        mock_get_response.return_value = {"q_free_text": "current answer"}
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-edit-link"
        )
        response = self.client.get(url, {"step": "team_details"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_get_response.assert_called_once_with("survey-team-details", "resp-1")
        self.assertIn("current+answer", response.data["redirect_url"])

        params = query_params(response.data["redirect_url"])
        self.assertEqual(params["lead_name"], self.lead.full_name)
        self.assertEqual(params["lead_email"], self.lead.email)

    def test_404_if_step_not_yet_submitted(self):
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-edit-link"
        )
        response = self.client.get(url, {"step": "compliance"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_rejected_once_proposal_is_no_longer_draft(self):
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-edit-link"
        )
        response = self.client.get(url, {"step": "team_details"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_staff_user_is_forbidden(self):
        # is_only_proposal_lead deliberately has no is_staff bypass - a
        # staff user can view this proposal (see ProposalFormResponsesTest)
        # but must not be able to fetch an edit link on the Lead's behalf.
        staff_user = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(staff_user)
        url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-edit-link"
        )
        response = self.client.get(url, {"step": "team_details"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class FormbricksProgressTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )
        self.lead = structure_factories.UserFactory()
        self.proposal.add_user(self.lead, ProposalRole.MANAGER, created_by=self.lead)
        self.url = factories.ProposalFactory.get_url(
            self.proposal, action="formbricks-progress"
        )

    def _create_response(self, step_key, survey_id):
        models.FormStepResponse.objects.create(
            proposal=self.proposal,
            step_key=step_key,
            survey_id=survey_id,
            response_id=f"resp-{step_key}",
            raw_response={},
            question_labels={},
        )

    def test_no_steps_completed_points_to_first_step(self):
        self.client.force_authenticate(self.lead)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["completed_steps"], [])
        self.assertEqual(response.data["next_step"]["key"], "project_details")
        self.assertIn(
            PROJECT_DETAILS_STEP["survey_id"], response.data["next_step"]["redirect_url"]
        )
        params = query_params(response.data["next_step"]["redirect_url"])
        self.assertEqual(params["lead_name"], self.lead.full_name)
        self.assertEqual(params["lead_email"], self.lead.email)

    def test_partial_completion_reports_next_incomplete_step_in_flow_order(self):
        self._create_response("project_details", "survey-project-details")
        self._create_response("team_details", "survey-team-details")

        self.client.force_authenticate(self.lead)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["completed_steps"], ["project_details", "team_details"]
        )
        self.assertEqual(response.data["next_step"]["key"], "compliance")

    def test_all_steps_completed_returns_null_next_step(self):
        for step in (
            PROJECT_DETAILS_STEP,
            TEAM_DETAILS_STEP,
            COMPLIANCE_STEP,
            ASSESSMENT_STEP,
        ):
            self._create_response(step["key"], step["survey_id"])

        self.client.force_authenticate(self.lead)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["completed_steps"],
            ["project_details", "team_details", "compliance", "assessment"],
        )
        self.assertIsNone(response.data["next_step"])

    def test_staff_user_is_forbidden(self):
        staff_user = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(staff_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unrelated_user_gets_404_not_403(self):
        other_user = structure_factories.UserFactory()
        self.client.force_authenticate(other_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ProposalFormResponsesTest(FormbricksTestCase):
    """Unlike ProposalReviewSerializer.form_responses (reviewer-restricted
    to REVIEWER_VISIBLE_STEPS), ProposalSerializer.form_responses returns
    every stored step - it's the Lead's own data (and, by the same
    visibility already enforced on ProposalViewSet.get_queryset, a staff
    viewer's)."""

    def setUp(self):
        super().setUp()
        self.proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )
        self.lead = structure_factories.UserFactory()
        self.proposal.add_user(self.lead, ProposalRole.MANAGER, created_by=self.lead)

        for step_key, survey_id in (
            ("project_details", "survey-project-details"),
            ("team_details", "survey-team-details"),
            ("compliance", "survey-compliance"),
            ("assessment", "survey-assessment"),
        ):
            models.FormStepResponse.objects.create(
                proposal=self.proposal,
                step_key=step_key,
                survey_id=survey_id,
                response_id=f"resp-{step_key}",
                raw_response={"q_1": f"answer for {step_key}"},
                question_labels={"q_1": f"question for {step_key}"},
            )

    def test_lead_sees_every_step_not_just_reviewer_visible_ones(self):
        self.client.force_authenticate(self.lead)
        url = factories.ProposalFactory.get_url(self.proposal)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        step_keys = {item["step_key"] for item in response.data["form_responses"]}
        self.assertEqual(
            step_keys, {"project_details", "team_details", "compliance", "assessment"}
        )

    def test_staff_user_can_also_view_every_step_read_only(self):
        staff_user = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(staff_user)
        url = factories.ProposalFactory.get_url(self.proposal)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        step_keys = {item["step_key"] for item in response.data["form_responses"]}
        self.assertEqual(
            step_keys, {"project_details", "team_details", "compliance", "assessment"}
        )


class PublicCallFormbricksFlowKeyTest(FormbricksTestCase):
    def test_formbricks_flow_key_is_exposed_on_the_public_call(self):
        url = factories.CallFactory.get_public_url(self.fixture.call)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["formbricks_flow_key"], TEST_FLOW_KEY)


class ReviewerFormResponsesTest(FormbricksTestCase):
    def setUp(self):
        super().setUp()
        self.proposal = self.fixture.proposal_submitted
        self.proposal.round = self.fixture.round
        self.proposal.save()

        for step_key, survey_id in (
            ("project_details", "survey-project-details"),
            ("team_details", "survey-team-details"),
            ("compliance", "survey-compliance"),
            ("assessment", "survey-assessment"),
        ):
            models.FormStepResponse.objects.create(
                proposal=self.proposal,
                step_key=step_key,
                survey_id=survey_id,
                response_id=f"resp-{step_key}",
                raw_response={"q_1": f"answer for {step_key}"},
                question_labels={"q_1": f"question for {step_key}"},
            )

        self.review = self.fixture.review
        self.review.proposal = self.proposal
        self.review.save()

    @mock.patch.object(formbricks_client, "get_response")
    @mock.patch.object(formbricks_client, "get_survey")
    def test_reviewer_only_sees_project_details_and_assessment(
        self, mock_get_survey, mock_get_response
    ):
        self.client.force_authenticate(self.fixture.reviewer_1)
        url = factories.ReviewFactory.get_url(self.review)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        step_keys = {item["step_key"] for item in response.data["form_responses"]}
        self.assertEqual(step_keys, {"project_details", "assessment"})
        # The reviewer view must never call out to Formbricks live.
        mock_get_survey.assert_not_called()
        mock_get_response.assert_not_called()
