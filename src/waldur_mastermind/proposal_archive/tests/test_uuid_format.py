"""The archive spells UUIDs the way the rest of the Waldur API does.

Waldur renders every UUID as bare hex -- ``807149e93cea4859a0aa7a60418c498c``.
That comes from ``waldur_core.core.fields.UUIDField``, which loads a
``StringUUID`` whose ``str()`` is ``.hex``. The archive's denormalised
reference fields are plain ``models.UUIDField``s, which load a stdlib
``uuid.UUID``, whose ``str()`` is hyphenated -- and DRF renders with ``str()``.

That was not cosmetic. HomePort matched an archived proposal to its project by
comparing ``project_uuid`` with ``Project.uuid``; the two spellings never
matched, and the "Proposal:" line vanished for every existing award.

The sweep below walks each response recursively instead of listing fields, so
a UUID field added later cannot bring the problem back unnoticed.
"""

import uuid

from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal_archive import models

from . import factories

# Referenced objects need not exist -- that is the point of denormalising.
PROJECT = uuid.uuid4()
AUTHOR = uuid.uuid4()
MEMBER = uuid.uuid4()


def uuid_values(data, path=""):
    """Every ``uuid`` / ``*_uuid`` value in a response, with where it was."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "payload":
                # The original row, verbatim, by design (§4.1). Whatever
                # spelling it holds is part of the record.
                continue
            here = f"{path}.{key}" if path else key
            if (key == "uuid" or key.endswith("_uuid")) and value is not None:
                yield here, value
            else:
                yield from uuid_values(value, here)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            yield from uuid_values(item, f"{path}[{index}]")


class ArchiveUUIDFormatTest(test.APITransactionTestCase):
    def setUp(self):
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))

        self.call = factories.ArchivedCallFactory(
            manager_uuid=uuid.uuid4(),
            customer_uuid=uuid.uuid4(),
            created_by_uuid=AUTHOR,
        )
        self.round = factories.ArchivedRoundFactory(call=self.call)
        self.proposal = factories.ArchivedProposalFactory(
            round=self.round,
            call=self.call,
            project_uuid=PROJECT,
            created_by_uuid=AUTHOR,
            approved_by_uuid=uuid.uuid4(),
        )
        models.ArchivedRequestedResource.objects.create(
            proposal=self.proposal,
            offering_uuid=uuid.uuid4(),
            plan_uuid=uuid.uuid4(),
            resource_uuid=uuid.uuid4(),
            created_by_uuid=AUTHOR,
        )
        self.review = factories.ArchivedReviewFactory(
            proposal=self.proposal, reviewer_uuid=uuid.uuid4()
        )
        self.membership = factories.ArchivedMembershipFactory(
            proposal=self.proposal, call=self.call, user_uuid=MEMBER
        )
        self.organisation_membership = models.ArchivedMembership.objects.create(
            scope_kind=models.ArchivedMembership.Scopes.ORGANISATION,
            organisation_customer_uuid=uuid.uuid4(),
            role_name="CUSTOMER.CALL_ORGANIZER",
            user_uuid=MEMBER,
        )
        models.ArchivedCallDocument.objects.create(call=self.call, file="")
        models.ArchivedProposalDocument.objects.create(proposal=self.proposal, file="")

    def get(self, name, **kwargs):
        response = self.client.get(reverse(name, kwargs=kwargs or None))
        self.assertEqual(response.status_code, status.HTTP_200_OK, name)
        return response.data

    def endpoints(self):
        hex_of = lambda obj: obj.uuid.hex  # noqa: E731
        return {
            "calls list": ("proposal-archive-call-list", {}),
            "call detail": (
                "proposal-archive-call-detail",
                {"uuid": hex_of(self.call)},
            ),
            "rounds list": ("proposal-archive-round-list", {}),
            "round detail": (
                "proposal-archive-round-detail",
                {"uuid": hex_of(self.round)},
            ),
            "proposals list": ("proposal-archive-proposal-list", {}),
            "proposal detail": (
                "proposal-archive-proposal-detail",
                {"uuid": hex_of(self.proposal)},
            ),
            "proposal notes": (
                "proposal-archive-proposal-notes",
                {"uuid": hex_of(self.proposal)},
            ),
            "reviews list": ("proposal-archive-review-list", {}),
            "review detail": (
                "proposal-archive-review-detail",
                {"uuid": hex_of(self.review)},
            ),
            "memberships list": ("proposal-archive-membership-list", {}),
            "membership detail": (
                "proposal-archive-membership-detail",
                {"uuid": hex_of(self.membership)},
            ),
            "resolve": (
                "proposal-archive-resolve-detail",
                {"uuid": hex_of(self.proposal)},
            ),
        }

    def test_no_uuid_anywhere_in_the_archive_is_hyphenated(self):
        for label, (name, kwargs) in self.endpoints().items():
            with self.subTest(endpoint=label):
                found = list(uuid_values(self.get(name, **kwargs)))
                self.assertTrue(found, f"{label} returned no UUIDs to check")
                for where, value in found:
                    self.assertNotIn("-", str(value), f"{label}: {where} = {value}")

    def test_the_reference_fields_are_really_populated(self):
        """Otherwise the sweep could pass by checking nothing but nulls.

        Eleven reference fields reach the API. Two more --
        ArchivedCall.manager_uuid and ArchivedRequestedResource.created_by_uuid
        -- exist only on the model and are not serialized, so they were never
        rendered in any spelling; the field mapping covers them if exposed.
        """
        proposal = self.get(
            "proposal-archive-proposal-detail", uuid=self.proposal.uuid.hex
        )
        call = self.get("proposal-archive-call-detail", uuid=self.call.uuid.hex)
        review = self.get("proposal-archive-review-detail", uuid=self.review.uuid.hex)
        membership = self.get(
            "proposal-archive-membership-detail", uuid=self.membership.uuid.hex
        )
        organisation = self.get(
            "proposal-archive-membership-detail",
            uuid=self.organisation_membership.uuid.hex,
        )
        exposed = {
            "call.customer_uuid": call["customer_uuid"],
            "call.created_by_uuid": call["created_by_uuid"],
            "proposal.project_uuid": proposal["project_uuid"],
            "proposal.created_by_uuid": proposal["created_by_uuid"],
            "proposal.approved_by_uuid": proposal["approved_by_uuid"],
            "resource.offering_uuid": proposal["requested_resources"][0][
                "offering_uuid"
            ],
            "resource.plan_uuid": proposal["requested_resources"][0]["plan_uuid"],
            "resource.resource_uuid": proposal["requested_resources"][0][
                "resource_uuid"
            ],
            "review.reviewer_uuid": review["reviewer_uuid"],
            "membership.user_uuid": membership["user_uuid"],
            "membership.organisation_customer_uuid": organisation[
                "organisation_customer_uuid"
            ],
        }
        self.assertEqual(len(exposed), 11)
        for where, value in exposed.items():
            with self.subTest(field=where):
                self.assertIsNotNone(value)
        self.assertEqual(proposal["project_uuid"], PROJECT.hex)
        self.assertEqual(membership["user_uuid"], MEMBER.hex)

    def test_an_archived_uuid_equals_the_live_one_it_refers_to(self):
        """The comparison HomePort made, which silently never matched."""
        project = structure_factories.ProjectFactory()
        proposal = factories.ArchivedProposalFactory(project_uuid=project.uuid)
        detail = self.get("proposal-archive-proposal-detail", uuid=proposal.uuid.hex)
        live = self.client.get(
            reverse("project-detail", kwargs={"uuid": project.uuid.hex})
        ).data
        self.assertEqual(detail["project_uuid"], live["uuid"])


class ArchiveUUIDFilterTest(test.APITransactionTestCase):
    """A filter must match however the caller spells the UUID."""

    def setUp(self):
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))
        self.proposal = factories.ArchivedProposalFactory(
            project_uuid=PROJECT, created_by_uuid=AUTHOR
        )
        self.membership = factories.ArchivedMembershipFactory(user_uuid=MEMBER)
        # Decoys, so a filter that matched everything would fail.
        factories.ArchivedProposalFactory(
            project_uuid=uuid.uuid4(), created_by_uuid=uuid.uuid4()
        )
        factories.ArchivedMembershipFactory(user_uuid=uuid.uuid4())

    def matching(self, name, field, value):
        response = self.client.get(reverse(name), {field: value})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return [row["uuid"] for row in response.data]

    def test_filters_accept_hex_and_hyphenated_alike(self):
        cases = (
            ("proposal-archive-proposal-list", "project_uuid", PROJECT, self.proposal),
            (
                "proposal-archive-proposal-list",
                "created_by_uuid",
                AUTHOR,
                self.proposal,
            ),
            ("proposal-archive-membership-list", "user_uuid", MEMBER, self.membership),
        )
        for name, field, value, expected in cases:
            for spelling in (value.hex, str(value)):
                with self.subTest(field=field, spelling=spelling):
                    self.assertEqual(
                        self.matching(name, field, spelling), [expected.uuid.hex]
                    )
