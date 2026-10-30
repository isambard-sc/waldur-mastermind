import datetime
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.utils import timezone
from rest_framework import status

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, CustomerRole, ProjectRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal_forms import (
    client,
    flows,
    models,
    responses,
    sync,
    tasks,
)

from .test_api import FormsTestBase

CLOSING_STEPS = [
    {"key": "feedback", "label": "Project feedback", "survey_id": "close1"},
]


def mint(survey_id, su):
    return f"https://forms.example.com/s/{survey_id}?suId={su}"


def record(link, answers=None, response_id="resp-c1", finished=True):
    return {
        "id": response_id,
        "surveyId": link.survey_id,
        "singleUseId": link.single_use_id,
        "finished": finished,
        "data": {
            "project_uuid": link.project.uuid.hex,
            **(answers if answers is not None else {"q1": "Great"}),
        },
    }


class ClosingFormsBase(FormsTestBase):
    def setUp(self):
        super().setUp()
        for name, value in (("get_survey", {}), ("get_response_record", {"data": {}})):
            patcher = mock.patch.object(client, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.closing = models.FormFlow.objects.create(
            key="airr-closing",
            name="AIRR end of project",
            purpose=models.FormFlow.Purposes.CLOSING,
            steps=flows.validate_steps(CLOSING_STEPS),
        )
        models.CallFormFlow.objects.filter(call=self.call).update(
            closing_flow=self.closing, closing_forms_open_days_before_end=7
        )
        self.today = timezone.localdate()
        self.project = structure_factories.ProjectFactory(end_date=self.today)
        proposal_models.Proposal.objects.filter(pk=self.proposal.pk).update(
            project=self.project, state=ProposalStates.ACCEPTED
        )

        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.pi = structure_factories.UserFactory(email="pi@example.org")
        self.project.add_user(self.pi, ProjectRole.MANAGER)
        self.owner = structure_factories.UserFactory()
        self.project.customer.add_user(self.owner, CustomerRole.OWNER)
        self.member = structure_factories.UserFactory()
        self.project.add_user(self.member, ProjectRole.MEMBER)
        self.reviewer = structure_factories.UserFactory()
        self.call.add_user(self.reviewer, CallRole.REVIEWER)

    def url(self, action=""):
        suffix = f"{action}/" if action else ""
        return f"/api/project-forms/{self.project.uuid.hex}/{suffix}"

    def get(self, user):
        self.client.force_authenticate(user)
        return self.client.get(self.url())

    def post_link(self, user=None, su="su-c1"):
        self.client.force_authenticate(user or self.pi)
        with mock.patch.object(
            client, "mint_single_use_link", return_value=mint("close1", su)
        ):
            return self.client.post(self.url("link"), {"step": "feedback"})

    def issue(self, su="su-c1"):
        step = self.closing.steps[0]
        with mock.patch.object(
            client, "mint_single_use_link", return_value=mint("close1", su)
        ):
            return responses.issue_link(self.project, step, self.pi)


class OpeningTest(ClosingFormsBase):
    def set_end(self, days_from_today):
        self.project.end_date = self.today + datetime.timedelta(days=days_from_today)
        self.project.save()

    def test_open_from_the_days_before_the_end_and_after_it(self):
        for days, is_open in ((8, False), (7, True), (0, True), (-90, True)):
            with self.subTest(days=days):
                self.set_end(days)
                response = self.get(self.pi)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data["is_open"], is_open)
                self.assertEqual(response.data["can_fill_in"], is_open)
                self.assertEqual(
                    response.data["opens_on"],
                    self.project.end_date - datetime.timedelta(days=7),
                )

    def test_link_refused_before_they_open(self):
        self.set_end(30)
        response = self.post_link()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("open on", str(response.data))

    def test_no_end_date_never_opens(self):
        self.project.end_date = None
        self.project.save()
        response = self.get(self.pi)
        self.assertIsNone(response.data["opens_on"])
        self.assertFalse(response.data["is_open"])

    def test_no_closing_flow_is_a_400(self):
        models.CallFormFlow.objects.filter(call=self.call).update(closing_flow=None)
        response = self.get(self.pi)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("no end-of-project forms", str(response.data))


class SiteFlowTest(ClosingFormsBase):
    """Projects no call granted (existing awards) take the site's flow."""

    def setUp(self):
        super().setUp()
        self.award = structure_factories.ProjectFactory(end_date=self.today)
        self.award.add_user(self.pi, ProjectRole.MANAGER)

    def get_award(self):
        self.client.force_authenticate(self.pi)
        return self.client.get(f"/api/project-forms/{self.award.uuid.hex}/")

    def test_no_site_flow_no_forms(self):
        self.assertEqual(self.get_award().status_code, status.HTTP_400_BAD_REQUEST)

    def test_site_flow_reaches_projects_without_a_call(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            "/api/site-closing-form-flow/",
            {"flow": self.closing.uuid.hex, "closing_forms_open_days_before_end": 3},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        response = self.get_award()
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertTrue(response.data["can_fill_in"])
        self.assertEqual(
            response.data["opens_on"], self.today - datetime.timedelta(days=3)
        )

    def test_site_flow_can_be_limited_to_organisations(self):
        default = models.SiteClosingFormFlow.get()
        default.flow = self.closing
        default.save()
        default.customers.add(structure_factories.CustomerFactory())
        self.assertEqual(self.get_award().status_code, status.HTTP_400_BAD_REQUEST)
        default.customers.add(self.award.customer)
        self.assertEqual(self.get_award().status_code, status.HTTP_200_OK)

    def test_call_flow_wins_over_the_site_flow(self):
        other = models.FormFlow.objects.create(
            key="site-closing",
            name="Site",
            purpose=models.FormFlow.Purposes.CLOSING,
            steps=flows.validate_steps(CLOSING_STEPS),
        )
        default = models.SiteClosingFormFlow.get()
        default.flow = other
        default.save()
        self.assertEqual(self.get(self.pi).data["flow_key"], "airr-closing")

    def test_only_staff_change_the_site_flow(self):
        self.client.force_authenticate(self.support)
        self.assertEqual(
            self.client.get("/api/site-closing-form-flow/").status_code,
            status.HTTP_200_OK,
        )
        response = self.client.patch(
            "/api/site-closing-form-flow/", {"flow": self.closing.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_application_flow_cannot_be_the_site_flow(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            "/api/site-closing-form-flow/", {"flow": self.flow.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PermissionTest(ClosingFormsBase):
    def test_pi_and_owners_fill_in(self):
        for user in (self.pi, self.owner, self.staff):
            with self.subTest(user=user):
                self.assertTrue(self.get(user).data["can_fill_in"])
        response = self.post_link(user=self.owner)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    def test_call_managers_and_support_read_only(self):
        for user in (self.call_manager, self.support):
            with self.subTest(user=user):
                response = self.get(user)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertFalse(response.data["can_fill_in"])
        response = self.post_link(user=self.call_manager)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_reviewers_and_members_refused(self):
        for user in (self.reviewer, self.member, self.user):
            with self.subTest(user=user):
                self.assertEqual(self.get(user).status_code, status.HTTP_404_NOT_FOUND)


class LinkTest(ClosingFormsBase):
    def test_link_carries_ids_only(self):
        response = self.post_link()
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        params = parse_qs(urlsplit(response.data["survey_url"]).query)
        self.assertEqual(
            set(params),
            {"suId", "project_uuid", "proposal_uuid", "call_uuid", "round_uuid"},
        )
        self.assertEqual(params["project_uuid"], [self.project.uuid.hex])
        url = response.data["survey_url"]
        for personal in (self.pi.email, self.pi.full_name, self.project.name):
            self.assertNotIn(personal, url)
        link = models.FormLink.objects.get(single_use_id="su-c1")
        self.assertEqual(link.project, self.project)
        self.assertIsNone(link.proposal)

    def test_open_link_is_reused(self):
        first = self.post_link(su="su-c1").data["survey_url"]
        second = self.post_link(su="su-c2").data["survey_url"]
        self.assertEqual(first, second)


class RoutingTest(ClosingFormsBase):
    def test_response_goes_to_the_project_not_the_proposal(self):
        link = self.issue()
        self.assertEqual(responses.apply_response(record(link)), "applied")
        stored = models.FormStepResponse.objects.get()
        self.assertEqual(stored.project, self.project)
        self.assertIsNone(stored.proposal)
        self.assertFalse(self.proposal.form_step_responses.exists())

        response = self.get(self.call_manager)
        self.assertEqual(response.data["missing"], [])
        self.assertEqual(
            response.data["responses"][0]["questions"][0]["answer"], "Great"
        )
        # The answers are not application answers.
        self.client.force_authenticate(self.applicant)
        proposal_state = self.client.get(
            f"/api/proposal-forms/{self.proposal.uuid.hex}/"
        )
        self.assertEqual(proposal_state.data["responses"], [])

    def test_fetch_routes_to_the_project(self):
        link = self.issue()
        self.client.force_authenticate(self.pi)
        with mock.patch.object(
            client, "iter_survey_responses", return_value=[record(link)]
        ):
            response = self.client.post(self.url("fetch"))
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["fetched"], 1)
        self.assertTrue(self.project.closing_form_responses.exists())

    def test_answers_stay_editable_after_the_end(self):
        link = self.issue()
        responses.apply_response(record(link))
        self.project.end_date = self.today - datetime.timedelta(days=60)
        self.project.save()
        edit = self.issue(su="su-c2")
        self.assertEqual(
            responses.apply_response(
                record(edit, {"q1": "Better"}, response_id="resp-c2")
            ),
            "applied",
        )
        self.assertTrue(
            models.FormbricksDeletion.objects.filter(response_id="resp-c1").exists()
        )


class DeletionTest(ClosingFormsBase):
    def answer(self):
        link = self.issue()
        responses.apply_response(record(link))

    def test_answers_outlive_the_projects_removal_at_its_end(self):
        # What Waldur does to an expired project once its grace period ends.
        self.answer()
        self.project.delete()
        self.assertTrue(models.FormStepResponse.objects.exists())
        self.assertFalse(models.FormbricksDeletion.objects.exists())

        for user in (self.call_manager, self.staff, self.support):
            with self.subTest(user=user):
                response = self.get(user)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertFalse(response.data["can_fill_in"])
                self.assertEqual(len(response.data["responses"]), 1)
        # The PI no longer has the project.
        self.assertEqual(self.get(self.pi).status_code, status.HTTP_404_NOT_FOUND)
        # And the forms are closed.
        self.client.force_authenticate(self.staff)
        response = self.client.post(self.url("link"), {"step": "feedback"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_proposal_still_reports_its_removed_project(self):
        # HomePort finds a granted proposal's end-of-project answers through
        # proposal.project, so the link must survive the project's removal.
        CallRole.MANAGER.add_permission(PermissionEnum.LIST_PROPOSALS)
        self.answer()
        self.project.delete()
        self.client.force_authenticate(self.call_manager)
        response = self.client.get(f"/api/proposal-proposals/{self.proposal.uuid.hex}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertIn(self.project.uuid.hex, response.data["project"])
        self.assertEqual(response.data["project_name"], self.project.name)
        response = self.get(self.call_manager)
        self.assertEqual(len(response.data["responses"]), 1)

    def test_deleting_the_project_row_deletes_them_everywhere(self):
        # A project no proposal created, so nothing protects its row.
        default = models.SiteClosingFormFlow.get()
        default.flow = self.closing
        default.save()
        proposal_models.Proposal.objects.filter(pk=self.proposal.pk).update(
            project=None
        )
        self.answer()
        with (
            mock.patch.object(tasks.process_formbricks_deletions, "delay"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.project.delete(soft=False)
        self.assertFalse(models.FormStepResponse.objects.exists())
        self.assertFalse(models.FormLink.objects.exists())
        self.assertTrue(
            models.FormbricksDeletion.objects.filter(response_id="resp-c1").exists()
        )


class NoticeTest(ClosingFormsBase):
    def notify(self):
        with mock.patch("waldur_core.core.utils.broadcast_mail") as mail:
            tasks.notify_closing_forms_open()
        return mail

    def test_pi_told_once_when_the_forms_open(self):
        mail = self.notify()
        app, event, context, emails = mail.call_args.args
        self.assertEqual((app, event), ("proposal", "closing_forms_open"))
        self.assertEqual(emails, [self.pi.email])
        self.assertFalse(self.notify().called)

    def test_long_ended_projects_are_not_told(self):
        self.project.end_date = self.today - datetime.timedelta(days=60)
        self.project.save()
        self.assertFalse(self.notify().called)


class SyncTest(ClosingFormsBase):
    def survey(self, **overrides):
        survey = {
            "type": "link",
            "status": "inProgress",
            "singleUse": {"enabled": True, "isEncrypted": False},
            "hiddenFields": {
                "enabled": True,
                "fieldIds": [
                    "project_name",
                    "project_slug",
                    "user_name",
                    "user_email",
                    "call_reference",
                ],
            },
            "endings": [{"id": "e1", "type": "endScreen"}],
        }
        survey.update(overrides)
        return survey

    def test_closing_survey_gets_ids_and_returns_to_the_project(self):
        url = sync.return_url("https://api.example.com/", "close1", "closing")
        self.assertIn("project_uuid=#recall:project_uuid/fallback:#", url)
        planned = sync.plan(self.survey(), url, "closing")
        fields = planned["changes"]["hiddenFields"]["fieldIds"]
        for field in ("project_uuid", "proposal_uuid", "call_uuid", "round_uuid"):
            self.assertIn(field, fields)
        self.assertEqual(planned["changes"]["endings"][0]["url"], url)
        self.assertEqual(
            planned["changes"]["endings"][0]["label"], "Back to your project"
        )

    def test_survey_used_both_ways_is_a_problem(self):
        self.flow.steps = flows.validate_steps(
            [{"key": "x", "label": "X", "survey_id": "close1"}]
        )
        self.flow.save()
        with (
            mock.patch.object(
                client, "get_survey_definition", return_value=self.survey()
            ),
            mock.patch.object(client, "update_survey") as update,
        ):
            results = sync.sync_flow(self.closing, "https://api.example.com/")
        self.assertIn("also a step of airr-gw", results[0]["problems"][0])
        update.assert_not_called()

    def test_return_goes_to_the_project_page(self):
        response = self.client.get(
            "/api/proposal-form-return/",
            {"project_uuid": self.project.uuid.hex, "survey": "close1"},
        )
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn(
            f"projects/{self.project.uuid.hex}/?form_survey=close1",
            response["Location"],
        )


class CallSettingTest(ClosingFormsBase):
    def test_call_managers_set_the_closing_flow(self):
        self.client.force_authenticate(self.call_manager)
        url = f"/api/proposal-form-calls/{self.call.uuid.hex}/"
        response = self.client.get(url)
        self.assertEqual(response.data["closing_flow_key"], "airr-closing")
        self.assertEqual(response.data["closing_forms_open_days_before_end"], 7)
        response = self.client.get(
            f"/api/proposal-protected-calls/{self.call.uuid.hex}/"
        )
        self.assertEqual(response.data["closing_form_flow"]["key"], "airr-closing")

    def test_flows_must_suit_their_purpose(self):
        call = self.round.call
        proposal_models.Proposal.objects.filter(round__call=call).delete()
        self.client.force_authenticate(self.call_manager)
        url = f"/api/proposal-form-calls/{call.uuid.hex}/"
        response = self.client.put(url, {"flow": self.closing.uuid.hex}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.put(
            url,
            {"flow": self.flow.uuid.hex, "closing_flow": self.flow.uuid.hex},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_closing_flow_locked_once_projects_started_it(self):
        self.issue()
        self.client.force_authenticate(self.call_manager)
        url = f"/api/proposal-form-calls/{self.call.uuid.hex}/"
        response = self.client.put(
            url, {"flow": self.flow.uuid.hex, "closing_flow": None}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(self.client.get(url).data["closing_locked"])
