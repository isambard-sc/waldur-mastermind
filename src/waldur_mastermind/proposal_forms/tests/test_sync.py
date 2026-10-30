from django.test import SimpleTestCase

from waldur_mastermind.proposal_forms import sync

URL = "https://api.example.com/api/proposal-form-return/?survey=s1&proposal_uuid=x"


class PlanTest(SimpleTestCase):
    def survey(self, **overrides):
        survey = {
            "type": "link",
            "status": "inProgress",
            "singleUse": {"enabled": True, "isEncrypted": False, "heading": "Used"},
            "hiddenFields": {"enabled": True, "fieldIds": ["proposal_uuid"]},
            "endings": [{"id": "e1", "type": "redirectToUrl", "url": URL}],
            "isAnonymizeResponsesEnabled": True,
        }
        survey.update(overrides)
        return survey

    def test_ready_survey_needs_nothing(self):
        self.assertEqual(
            sync.plan(self.survey(), URL),
            {"changes": {}, "notes": [], "problems": []},
        )

    def test_fresh_survey_gets_every_setting(self):
        planned = sync.plan(
            self.survey(
                singleUse=None,
                hiddenFields={"enabled": False, "fieldIds": ["other"]},
                endings=[
                    {"id": "e1", "type": "endScreen", "headline": {"default": "Ta"}},
                    {
                        "id": "e2",
                        "type": "redirectToUrl",
                        "url": "https://x",
                        "label": "Go",
                    },
                ],
                isAnonymizeResponsesEnabled=False,
            ),
            URL,
        )
        changes = planned["changes"]
        self.assertEqual(changes["singleUse"], {"enabled": True, "isEncrypted": False})
        # Other hidden fields are kept.
        self.assertEqual(
            changes["hiddenFields"],
            {"enabled": True, "fieldIds": ["other", "proposal_uuid"]},
        )
        # Ending ids are kept, so survey logic that jumps to them still works.
        self.assertEqual(
            changes["endings"],
            [
                {
                    "id": "e1",
                    "type": "redirectToUrl",
                    "url": URL,
                    "label": "Back to your proposal",
                },
                {"id": "e2", "type": "redirectToUrl", "url": URL, "label": "Go"},
            ],
        )
        self.assertTrue(changes["isAnonymizeResponsesEnabled"])
        self.assertEqual(len(planned["notes"]), 4)
        self.assertEqual(planned["problems"], [])

    def test_encrypted_single_use_turned_off_keeping_messages(self):
        planned = sync.plan(
            self.survey(
                singleUse={"enabled": True, "isEncrypted": True, "heading": "Used"}
            ),
            URL,
        )
        self.assertEqual(
            planned["changes"]["singleUse"],
            {"enabled": True, "isEncrypted": False, "heading": "Used"},
        )

    def test_survey_without_endings_gets_one(self):
        (ending,) = sync.plan(self.survey(endings=[]), URL)["changes"]["endings"]
        self.assertEqual(ending["type"], "redirectToUrl")
        self.assertEqual(ending["url"], URL)
        self.assertRegex(ending["id"], r"^c[a-z0-9]{23}$")

    def test_what_waldur_cannot_fix_is_reported(self):
        planned = sync.plan(self.survey(type="app", status="draft"), URL)
        self.assertEqual(len(planned["problems"]), 2)
        self.assertEqual(planned["changes"], {})

    def test_return_url_recalls_the_hidden_field(self):
        url = sync.return_url("https://api.example.com/", "s1")
        self.assertEqual(
            url,
            "https://api.example.com/api/proposal-form-return/?survey=s1"
            "&proposal_uuid=#recall:proposal_uuid/fallback:#",
        )
