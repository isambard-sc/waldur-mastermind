import datetime
from unittest import mock

from django.utils import timezone
from rest_framework import status, test

from waldur_core.core import models as core_models
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.marketplace.tests import factories as marketplace_factories
from waldur_mastermind.proposal.enums import CallStates, ProposalStates
from waldur_mastermind.proposal.tests import factories as proposal_factories
from waldur_mastermind.proposal_forms import client, flows, models, sync

SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

STEPS = [
    {
        "key": "project_details",
        "label": "Project details",
        "survey_id": "survey1",
        "reviewer_visible": True,
    },
    {"key": "team_details", "label": "Team details", "survey_id": "survey2"},
]


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

    @mock.patch.object(client, "list_surveys", return_value=[{"id": "s1"}])
    def test_connection_test(self, list_surveys):
        self.client.force_authenticate(self.staff)
        response = self.client.post(self.url + "test/")
        self.assertEqual(
            response.data,
            {"ok": True, "detail": "Connected. The key can see 1 survey(s)."},
        )

        list_surveys.side_effect = client.FormbricksError("401 Unauthorized")
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

    def test_flow_in_use_cannot_be_deleted(self):
        self.client.force_authenticate(self.staff)
        response = self.client.delete(self.detail(self.flow))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.FormFlow.objects.filter(pk=self.flow.pk).exists())

    def ready_survey(self, survey_id, **overrides):
        """A survey as Formbricks returns it, already set up for Waldur."""
        url = sync.return_url("http://testserver/", survey_id)
        survey = {
            "id": survey_id,
            "name": f"Survey {survey_id}",
            "type": "link",
            "status": "inProgress",
            "singleUse": {"enabled": True, "isEncrypted": False},
            "hiddenFields": {"enabled": True, "fieldIds": ["proposal_uuid"]},
            "endings": [{"id": "e1", "type": "redirectToUrl", "url": url}],
            "isAnonymizeResponsesEnabled": True,
            "blocks": [
                {
                    "elements": [
                        {
                            "id": "q1",
                            "type": "openText",
                            "headline": {"default": "<p>Why?</p>"},
                        }
                    ]
                }
            ],
        }
        survey.update(overrides)
        return survey

    def test_check_reports_changes_without_making_them(self):
        surveys = {
            "survey1": self.ready_survey(
                "survey1",
                singleUse=None,
                endings=[{"id": "e1", "type": "endScreen", "headline": {}}],
            ),
            "survey2": self.ready_survey("survey2"),
        }
        self.client.force_authenticate(self.support)
        with (
            mock.patch.object(client, "get_survey_definition", side_effect=surveys.get),
            mock.patch.object(client, "update_survey") as update_survey,
        ):
            response = self.client.get(self.detail(self.flow) + "check/")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        update_survey.assert_not_called()
        self.assertFalse(response.data["in_sync"])
        first, second = response.data["steps"]
        self.assertFalse(first["in_sync"])
        self.assertEqual(len(first["changes"]), 2)
        self.assertTrue(second["in_sync"])
        self.assertEqual(
            second["questions"],
            [{"id": "q1", "type": "openText", "label": "Why?", "choices": []}],
        )

    def test_check_reports_unreachable_survey(self):
        self.client.force_authenticate(self.staff)
        error = client.FormbricksError("Formbricks refused GET ... (401)")
        with mock.patch.object(client, "get_survey_definition", side_effect=error):
            response = self.client.get(self.detail(self.flow) + "check/")
        self.assertFalse(response.data["steps"][0]["in_sync"])
        self.assertIn("401", response.data["steps"][0]["problems"][0])

    def test_sync_writes_only_what_is_missing_and_stores_questions(self):
        surveys = {
            "survey1": self.ready_survey("survey1", isAnonymizeResponsesEnabled=False),
            "survey2": self.ready_survey("survey2"),
        }

        def update(survey_id, changes):
            surveys[survey_id] = {**surveys[survey_id], **changes}
            return surveys[survey_id]

        self.client.force_authenticate(self.staff)
        with (
            mock.patch.object(client, "get_survey_definition", side_effect=surveys.get),
            mock.patch.object(client, "update_survey", side_effect=update) as upd,
        ):
            response = self.client.post(self.detail(self.flow) + "sync/")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        upd.assert_called_once_with("survey1", {"isAnonymizeResponsesEnabled": True})
        self.assertTrue(response.data["in_sync"])
        self.flow.refresh_from_db()
        self.assertEqual(
            self.flow.survey_schemas["survey2"]["questions"][0]["label"], "Why?"
        )

    def test_only_staff_sync(self):
        self.client.force_authenticate(self.support)
        response = self.client.post(self.detail(self.flow) + "sync/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_survey_list(self):
        listed = [
            self.ready_survey("survey1", name="Beta", environmentId="env1"),
            self.ready_survey("other", name="alpha", blocks=[]),
        ]
        self.client.force_authenticate(self.staff)
        with mock.patch.object(client, "list_surveys", return_value=listed):
            response = self.client.get("/api/formbricks-surveys/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([s["name"] for s in response.data], ["alpha", "Beta"])
        beta = response.data[1]
        self.assertEqual(beta["used_by_flows"], ["airr-gw"])
        self.assertEqual(beta["question_count"], 1)
        self.assertEqual(beta["environment_id"], "env1")

        self.client.force_authenticate(self.user)
        response = self.client.get("/api/formbricks-surveys/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ReturnRedirectTest(FormsTestBase):
    def test_returns_to_the_proposal_with_the_survey(self):
        response = self.client.get(
            "/api/proposal-form-return/",
            {"proposal_uuid": self.proposal.uuid.hex, "survey": "survey1"},
        )
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn(
            f"proposals/{self.proposal.uuid.hex}/?form_survey=survey1",
            response["Location"],
        )

    def test_unrecognisable_values_go_to_the_proposal_list(self):
        response = self.client.get(
            "/api/proposal-form-return/",
            {"proposal_uuid": "#recall:proposal_uuid/fallback:#", "survey": "x/y"},
        )
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertTrue(response["Location"].endswith("proposals/"))


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
