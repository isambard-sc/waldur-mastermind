"""An awarding portal follows the receiving portal to a corrected project identifier.

brics minted its projects' identifiers with the sending portal's name
("u6uk.airr" for "u6uk.brics") until September 2026, and the awarding portal
stored that identifier twice: on the allocation, and as the award record's
key. When brics corrected its identifiers, update_mapping logged that it was
changing the stored one but called a setter that refuses any change, so every
update failed at its last step and 317 awards sat in "Pending".
"""

import io
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import openportal
from django.test import TestCase

from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models

DESTINATION = "airr.brics.isambard-ai"
SCRIPT = (
    Path(__file__).resolve().parents[3] / "scripts/repair_remote_award_identifiers.py"
)


class AwardFixture:
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.settings = structure_factories.ServiceSettingsFactory(
            customer=self.fixture.customer
        )
        self.number = 0

    def award(self, identifier, destination=DESTINATION, with_allocation=True):
        self.number += 1
        allocation = None
        if with_allocation:
            allocation = models.RemoteAllocation.objects.create(
                name=f"award {self.number}",
                project=self.fixture.project,
                service_settings=self.settings,
                backend_id=f"airr-gw_{self.number}.airr",
                remote_project_identifier=identifier,
            )
        return models.RemoteProject.objects.create(
            destination=destination,
            identifier=identifier,
            state=models.RemoteProjectState.PENDING,
            remote_allocation=allocation,
            current_project=structure_factories.ProjectFactory(
                customer=self.fixture.customer
            ),
        )


class UpdateMappingFollowsTheReceivingPortalTest(AwardFixture, TestCase):
    def mapping(self, allocation, identifier):
        return openportal.ProjectMapping(f"{allocation.backend_id}:{identifier}")

    def test_a_corrected_identifier_moves_the_allocation_and_the_award(self):
        award = self.award("u6uk.airr")
        allocation = award.remote_allocation

        allocation.update_mapping(self.mapping(allocation, "u6uk.brics"))

        allocation.refresh_from_db()
        award.refresh_from_db()
        self.assertEqual(allocation.remote_project_identifier, "u6uk.brics")
        self.assertEqual(award.identifier, "u6uk.brics")

    def test_an_unchanged_identifier_changes_nothing(self):
        award = self.award("u6uk.brics")
        allocation = award.remote_allocation

        allocation.update_mapping(self.mapping(allocation, "u6uk.brics"))

        award.refresh_from_db()
        self.assertEqual(award.identifier, "u6uk.brics")

    def test_a_clash_with_another_award_changes_nothing(self):
        award = self.award("u6uk.airr")
        self.award("u6uk.brics", with_allocation=False)
        allocation = award.remote_allocation

        with self.assertRaises(ValueError):
            allocation.update_mapping(self.mapping(allocation, "u6uk.brics"))

        allocation.refresh_from_db()
        award.refresh_from_db()
        self.assertEqual(allocation.remote_project_identifier, "u6uk.airr")
        self.assertEqual(award.identifier, "u6uk.airr")


class RepairScriptTest(AwardFixture, TestCase):
    def run_script(self, apply):
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"REPAIR_APPLY": "1" if apply else "0"}),
            redirect_stdout(out),
        ):
            exec(SCRIPT.read_text(), {"__name__": "__main__"})
        return out.getvalue()

    def setUp(self):
        super().setUp()
        self.stuck = self.award("u6uk.airr")
        self.phase2 = self.award("u6vf.airr", destination=DESTINATION + "-phase2")
        self.other_site = self.award("u7aa.airr", destination="airr.cam-dawn.dawn")
        self.deleted = self.award("u6zz.airr", with_allocation=False)
        self.blocked = self.award("u6qq.airr")
        self.award("u6qq.brics", with_allocation=False)
        self.correct = self.award("u6ab.brics")

    def identifiers(self):
        return {
            name: models.RemoteProject.objects.get(pk=award.pk).identifier
            for name, award in (
                ("stuck", self.stuck),
                ("phase2", self.phase2),
                ("other_site", self.other_site),
                ("deleted", self.deleted),
                ("blocked", self.blocked),
                ("correct", self.correct),
            )
        }

    def test_dry_run_changes_nothing(self):
        before = self.identifiers()

        output = self.run_script(apply=False)

        self.assertEqual(self.identifiers(), before)
        self.assertIn("would change", output)

    def test_apply_repairs_only_live_awards_to_brics(self):
        output = self.run_script(apply=True)

        self.assertEqual(
            self.identifiers(),
            {
                "stuck": "u6uk.brics",
                "phase2": "u6vf.brics",
                "other_site": "u7aa.airr",
                "deleted": "u6zz.airr",
                "blocked": "u6qq.airr",
                "correct": "u6ab.brics",
            },
        )
        self.assertIn("[CLASH]", output)
        self.stuck.remote_allocation.refresh_from_db()
        self.assertEqual(
            self.stuck.remote_allocation.remote_project_identifier, "u6uk.brics"
        )

    def test_a_second_run_finds_nothing(self):
        self.run_script(apply=True)

        output = self.run_script(apply=True)

        self.assertNotIn("[change]", output)
