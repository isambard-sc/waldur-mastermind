import json
import os
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from rest_framework import exceptions, status

from waldur_core.core import models as core_models
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories as proposal_factories
from waldur_mastermind.proposal_forms import client, handlers, models, responses, tasks

from .test_api import SECRET, FormsTestBase

MINTED = "https://forms.example.com/s/{survey}?suId={su}"


def mint(survey_id, su="su-1"):
    return MINTED.format(survey=survey_id, su=su)


def record(link, answers=None, response_id="resp-1", finished=True, **overrides):
    """A response as Formbricks carries it (webhook data / Management API)."""
    data = {
        "id": response_id,
        "surveyId": link.survey_id,
        "singleUseId": link.single_use_id,
        "finished": finished,
        "data": {
            "proposal_uuid": link.proposal.uuid.hex,
            **(answers if answers is not None else {"q1": "Yes"}),
        },
    }
    data.update(overrides)
    return data


class FormsResponseBase(FormsTestBase):
    def setUp(self):
        super().setUp()
        self.flow.survey_schemas = {
            "survey1": {"name": "S1", "questions": [{"id": "q1", "label": "Why?"}]},
        }
        self.flow.save()
        for name, value in (
            ("get_survey", {}),
            # Prefilling an edit reads the current response from Formbricks.
            ("get_response_record", {"data": {}}),
        ):
            patcher = mock.patch.object(client, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def issue(self, step_key="project_details", su="su-1", user=None):
        step = next(s for s in self.flow.steps if s["key"] == step_key)
        with mock.patch.object(
            client, "mint_single_use_link", return_value=mint(step["survey_id"], su)
        ):
            return responses.issue_link(self.proposal, step, user or self.applicant)

    def answer(self, step_key="project_details", su="su-1", response_id="resp-1"):
        link = self.issue(step_key, su)
        self.assertEqual(
            responses.apply_response(record(link, response_id=response_id)), "applied"
        )
        link.refresh_from_db()
        return link


class LinkTest(FormsResponseBase):
    def url(self):
        return f"/api/proposal-forms/{self.proposal.uuid.hex}/link/"

    def post(self, step="project_details", user=None):
        self.client.force_authenticate(user or self.applicant)
        return self.client.post(self.url(), {"step": step})

    @mock.patch.object(client, "mint_single_use_link")
    def test_issues_a_recorded_single_use_link(self, mint_link):
        mint_link.return_value = mint("survey1", "su-new")
        response = self.post()
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        mint_link.assert_called_once_with("survey1")
        params = parse_qs(urlsplit(response.data["survey_url"]).query)
        self.assertEqual(params["suId"], ["su-new"])
        self.assertEqual(params["proposal_uuid"], [self.proposal.uuid.hex])
        self.assertEqual(params["call_uuid"], [self.proposal.round.call.uuid.hex])
        self.assertEqual(params["round_uuid"], [self.proposal.round.uuid.hex])
        # No name, email or token in the link any more.
        self.assertEqual(
            set(params), {"suId", "proposal_uuid", "call_uuid", "round_uuid"}
        )
        link = models.FormLink.objects.get(single_use_id="su-new")
        self.assertEqual(link.proposal, self.proposal)
        self.assertEqual(link.step_key, "project_details")
        self.assertEqual(link.issued_to, self.applicant)

    @mock.patch.object(client, "mint_single_use_link")
    def test_open_link_is_reused_so_progress_resumes(self, mint_link):
        mint_link.return_value = mint("survey1", "su-1")
        first = self.post().data["survey_url"]
        second = self.post().data["survey_url"]
        self.assertEqual(first, second)
        mint_link.assert_called_once()

    def test_answered_form_gets_a_new_prefilled_link(self):
        self.answer()
        with (
            mock.patch.object(
                client, "mint_single_use_link", return_value=mint("survey1", "su-2")
            ),
            mock.patch.object(
                client,
                "get_response_record",
                return_value={"data": {"q1": "Latest", "proposal_uuid": "x"}},
            ),
        ):
            response = self.post()
        params = parse_qs(urlsplit(response.data["survey_url"]).query)
        self.assertEqual(params["suId"], ["su-2"])
        self.assertEqual(params["q1"], ["Latest"])
        self.assertEqual(params["proposal_uuid"], [self.proposal.uuid.hex])

    def test_only_the_team_while_draft(self):
        self.assertEqual(
            self.post(user=self.staff).status_code, status.HTTP_403_FORBIDDEN
        )
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.assertEqual(self.post().status_code, status.HTTP_403_FORBIDDEN)

    def test_unknown_form_and_formbricks_down(self):
        self.assertEqual(
            self.post(step="nope").status_code, status.HTTP_400_BAD_REQUEST
        )
        with mock.patch.object(
            client, "mint_single_use_link", side_effect=client.FormbricksError("x")
        ):
            response = self.post()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("try again later", str(response.data))
        self.assertFalse(models.FormLink.objects.exists())


class StateTest(FormsResponseBase):
    def get(self, user):
        self.client.force_authenticate(user)
        return self.client.get(f"/api/proposal-forms/{self.proposal.uuid.hex}/")

    def test_applicant_sees_progress(self):
        self.answer()
        self.issue("team_details", su="su-team")
        data = self.get(self.applicant).data
        self.assertTrue(data["available"])
        self.assertTrue(data["can_fill_in"])
        self.assertEqual(
            [(s["key"], s["completed"], s["in_progress"]) for s in data["steps"]],
            [("project_details", True, False), ("team_details", False, True)],
        )
        self.assertEqual(data["missing"], ["Team details"])
        (answers,) = data["responses"]
        self.assertEqual(
            answers["questions"],
            [{"question_id": "q1", "label": "Why?", "answer": "Yes"}],
        )

    def test_reviewer_sees_reviewer_visible_forms_only(self):
        self.answer()
        self.answer("team_details", su="su-team", response_id="resp-team")
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        reviewer = proposal_factories.ReviewFactory(proposal=self.proposal).reviewer
        data = self.get(reviewer).data
        self.assertFalse(data["can_fill_in"])
        self.assertEqual(
            [r["step_key"] for r in data["responses"]], ["project_details"]
        )
        self.assertEqual(len(self.get(self.call_manager).data["responses"]), 2)


class ApplyResponseTest(FormsResponseBase):
    def test_matched_by_link_not_by_hidden_field(self):
        link = self.issue()
        other = proposal_factories.ProposalFactory(round=self.round)
        forged = record(link)
        forged["data"]["proposal_uuid"] = other.uuid.hex
        self.assertEqual(responses.apply_response(forged), "applied")
        self.assertTrue(self.proposal.form_step_responses.exists())
        self.assertFalse(other.form_step_responses.exists())
        stored = self.proposal.form_step_responses.get()
        # Hidden fields are not answers.
        self.assertEqual(stored.raw_response, {"q1": "Yes"})
        self.assertEqual(stored.question_labels, {"q1": "Why?"})
        link.refresh_from_db()
        self.assertEqual(link.state, models.FormLink.States.ANSWERED)

    def test_unknown_link_and_unfinished_ignored(self):
        link = self.issue()
        self.assertEqual(
            responses.apply_response(record(link, finished=False)), "unfinished"
        )
        self.assertEqual(
            responses.apply_response(record(link, singleUseId="made-up")),
            "unknown-link",
        )
        self.assertEqual(
            responses.apply_response(record(link, surveyId="survey2")),
            "unknown-link",
        )
        self.assertEqual(
            responses.apply_response(record(link, singleUseId=None)), "unknown-link"
        )
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_edit_replaces_answers_and_deletes_old_response(self):
        first = self.answer()
        second = self.issue(su="su-2")
        self.assertEqual(
            responses.apply_response(
                record(second, {"q1": "Changed"}, response_id="resp-2")
            ),
            "applied",
        )
        stored = self.proposal.form_step_responses.get()
        self.assertEqual(stored.raw_response, {"q1": "Changed"})
        self.assertEqual(stored.response_id, "resp-2")
        first.refresh_from_db()
        self.assertEqual(first.state, models.FormLink.States.SUPERSEDED)
        self.assertTrue(
            models.FormbricksDeletion.objects.filter(response_id="resp-1").exists()
        )

    def test_after_submission_new_response_is_late_but_corrections_apply(self):
        link = self.answer()
        open_link = self.issue(su="su-open")
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()

        self.assertEqual(
            responses.apply_response(record(open_link, response_id="resp-late")),
            "late",
        )
        open_link.refresh_from_db()
        self.assertEqual(open_link.state, models.FormLink.States.LATE)
        self.assertEqual(self.proposal.form_step_responses.get().response_id, "resp-1")

        # Formbricks is the source of truth: staff correcting the submitted
        # response there reaches Waldur.
        self.assertEqual(
            responses.apply_response(record(link, {"q1": "Corrected"})), "updated"
        )
        self.assertEqual(
            self.proposal.form_step_responses.get().raw_response, {"q1": "Corrected"}
        )
        self.assertEqual(
            responses.apply_response(record(link, {"q1": "Corrected"})), "unchanged"
        )

    def test_form_removed_from_flow_ignored(self):
        link = self.issue()
        self.flow.steps = [s for s in self.flow.steps if s["key"] != "project_details"]
        self.flow.save()
        self.assertEqual(responses.apply_response(record(link)), "step-removed")


class WebhookTest(FormsResponseBase):
    url = "/api/proposal-form-webhook/"

    def post(self, payload, secret=SECRET):
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        return self.client.generic(
            "POST",
            self.url,
            body,
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_1",
            HTTP_WEBHOOK_TIMESTAMP=timestamp,
            HTTP_WEBHOOK_SIGNATURE="v1,"
            + client.sign(secret, "msg_1", timestamp, body),
        )

    def test_finished_and_updated_events_applied(self):
        link = self.issue()
        response = self.post({"event": "responseFinished", "data": record(link)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "applied")
        response = self.post(
            {"event": "responseUpdated", "data": record(link, {"q1": "No"})}
        )
        self.assertEqual(response.data["detail"], "updated")

    def test_other_events_and_bad_signature(self):
        link = self.issue()
        response = self.post({"event": "responseCreated", "data": record(link)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.FormStepResponse.objects.exists())
        other = "whsec_" + "QUJD" * 8
        response = self.post(
            {"event": "responseFinished", "data": record(link)}, secret=other
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(models.FormStepResponse.objects.exists())

    def test_test_ping_and_switched_off(self):
        response = self.post({"event": "testEndpoint"}, secret="whsec_" + "QUJD" * 8)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        link = self.issue()
        core_models.Feature.objects.filter(key=client.FEATURE).update(value=False)
        response = self.post({"event": "responseFinished", "data": record(link)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.FormStepResponse.objects.exists())


class RealPayloadTest(FormsResponseBase):
    """A responseFinished delivery captured from a live Formbricks (4.9),
    redacted, replayed through the webhook with this test's link."""

    FIXTURE = os.path.join(
        os.path.dirname(__file__), "fixtures", "formbricks_response_finished.json"
    )
    url = WebhookTest.url

    def test_real_delivery_matched_by_its_link(self):
        self.flow.steps = [
            {
                "key": "project_details",
                "label": "Project details",
                "survey_id": "t14sgutihynd7edwluh8trg1",
                "reviewer_visible": True,
            }
        ]
        self.flow.survey_schemas = {}
        self.flow.save()
        link = self.issue(su="su-real")
        with open(self.FIXTURE, encoding="utf-8") as f:
            payload = json.load(f)
        payload["data"]["singleUseId"] = link.single_use_id
        with mock.patch.object(
            client,
            "get_survey",
            return_value={
                "cid9d22768jyf65hht3sakqq": "Project title",
                "g81oicc5tihv86395lclkfpz": "Project duration, in months",
                "j4b388ormyl4jiwajx158uel": "GPUh requested",
                "tf4lhp5vsvc7993sx27q5ugd": "AIRR service requested",
            },
        ):
            response = WebhookTest.post(self, payload)
        self.assertEqual(response.data["detail"], "applied")
        stored = self.proposal.form_step_responses.get()
        self.assertEqual(stored.response_id, "cmvufemih0003u6014xwem7kl")
        # Hidden fields from the old integration are not answers either.
        self.assertEqual(
            set(stored.raw_response),
            {
                "cid9d22768jyf65hht3sakqq",
                "g81oicc5tihv86395lclkfpz",
                "j4b388ormyl4jiwajx158uel",
                "tf4lhp5vsvc7993sx27q5ugd",
            },
        )
        # Answers are no longer copied onto the proposal.
        self.proposal.refresh_from_db()
        self.assertNotEqual(self.proposal.name, "My new project application")

    def test_captured_body_without_a_waldur_link_is_ignored(self):
        with open(self.FIXTURE, encoding="utf-8") as f:
            payload = json.load(f)
        response = WebhookTest.post(self, payload)
        self.assertEqual(response.data["detail"], "unknown-link")


class FetchTest(FormsResponseBase):
    def test_fetch_picks_up_missed_and_changed_responses(self):
        answered = self.answer()
        open_link = self.issue("team_details", su="su-team")
        listed = [
            record(open_link, response_id="other", singleUseId="someone-else"),
            record(open_link, response_id="resp-team"),
        ]
        with (
            mock.patch.object(
                client, "iter_survey_responses", return_value=iter(listed)
            ),
            mock.patch.object(
                client,
                "get_response_record",
                side_effect=lambda rid: (
                    record(answered, {"q1": "Fixed"})
                    if rid == "resp-1"
                    else record(open_link, response_id="resp-team")
                ),
            ),
        ):
            self.client.force_authenticate(self.applicant)
            response = self.client.post(
                f"/api/proposal-forms/{self.proposal.uuid.hex}/fetch/"
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["fetched"], 2)
        self.assertEqual(response.data["missing"], [])
        stored = {
            r.step_key: r.raw_response for r in self.proposal.form_step_responses.all()
        }
        self.assertEqual(stored["project_details"], {"q1": "Fixed"})
        self.assertEqual(stored["team_details"], {"q1": "Yes"})

    def test_periodic_fetch_only_for_draft_proposals_with_open_links(self):
        self.issue()
        with mock.patch.object(responses, "fetch_for_subject", return_value={}) as f:
            tasks.fetch_open_form_responses()
        f.assert_called_once_with(self.proposal)
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        with mock.patch.object(responses, "fetch_for_subject", return_value={}) as f:
            tasks.fetch_open_form_responses()
        f.assert_not_called()


class SubmitRuleTest(FormsResponseBase):
    def test_all_forms_answered_before_submission(self):
        with self.assertRaises(exceptions.ValidationError) as raised:
            handlers.validate_forms_answered(self.proposal)
        self.assertIn("Project details, Team details", str(raised.exception.detail))
        self.answer()
        self.answer("team_details", su="su-team", response_id="resp-team")
        handlers.validate_forms_answered(self.proposal)

    def test_enforced_while_formbricks_is_unavailable(self):
        # A paused or unreachable Formbricks must not let a proposal through
        # without its forms.
        models.FormbricksConnection.objects.update(enabled=False)
        with self.assertRaises(exceptions.ValidationError) as raised:
            handlers.validate_forms_answered(self.proposal)
        self.assertIn("cannot be opened just now", str(raised.exception.detail))
        # Answers already in Waldur still count.
        self.answer()
        self.answer("team_details", su="su-team", response_id="resp-team")
        handlers.validate_forms_answered(self.proposal)

    def test_not_enforced_once_the_site_switches_forms_off(self):
        core_models.Feature.objects.filter(key=client.FEATURE).update(value=False)
        handlers.validate_forms_answered(self.proposal)

    def test_submit_endpoint_refuses_missing_forms(self):
        self.client.force_authenticate(self.applicant)
        response = self.client.post(
            f"/api/proposal-proposals/{self.proposal.uuid.hex}/submit/"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("forms", response.data)


class DeletionTest(FormsResponseBase):
    def test_deleting_a_draft_deletes_its_responses_in_formbricks(self):
        self.answer()
        second = self.issue(su="su-2")
        responses.apply_response(record(second, {"q1": "No"}, response_id="resp-2"))
        # Queued while the links still exist, deleted in Formbricks once the
        # proposal's deletion has committed.
        with mock.patch.object(tasks.process_formbricks_deletions, "delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                self.proposal.delete()
        delay.assert_called_once()
        self.assertEqual(
            sorted(
                models.FormbricksDeletion.objects.values_list("response_id", flat=True)
            ),
            ["resp-1", "resp-2"],
        )
        with mock.patch.object(client, "delete_response") as delete:
            tasks.process_formbricks_deletions()
        self.assertEqual(
            sorted(call.args[0] for call in delete.call_args_list), ["resp-1", "resp-2"]
        )
        self.assertFalse(models.FormbricksDeletion.objects.exists())

    def test_failed_deletion_is_kept_for_the_next_run(self):
        responses.queue_deletion("resp-x", "test")
        with mock.patch.object(
            client, "delete_response", side_effect=client.FormbricksError("down")
        ):
            responses.process_deletions()
        deletion = models.FormbricksDeletion.objects.get()
        self.assertEqual(deletion.attempts, 1)
        self.assertIn("down", deletion.last_error)
        with mock.patch.object(client, "delete_response"):
            responses.process_deletions()
        self.assertFalse(models.FormbricksDeletion.objects.exists())

    def test_submitted_proposal_deletion_leaves_formbricks_alone(self):
        self.answer()
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.proposal.delete()
        self.assertFalse(models.FormbricksDeletion.objects.exists())
