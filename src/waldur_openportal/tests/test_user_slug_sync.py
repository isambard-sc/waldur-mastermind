"""
User.slug as a copy of the OpenPortal username.

With the portal-wide user.show_openportal_identifier feature on, homeport
reads the slug *as* the OpenPortal username, so a user who has not chosen one
must have no slug rather than a plausible-looking one generated from their
account name.
"""

from django.test import TestCase

from waldur_core.core.models import (
    OPENPORTAL_IDENTIFIER_FEATURE,
    Feature,
    User,
)
from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import models, utils


def set_feature(value):
    Feature.objects.update_or_create(
        key=OPENPORTAL_IDENTIFIER_FEATURE, defaults={"value": value}
    )


class SlugGenerationTest(TestCase):
    def test_slug_is_generated_from_the_username_while_the_feature_is_off(self):
        set_feature(False)

        user = User.objects.create(username="alice")

        self.assertEqual(user.slug, "alice")

    def test_slug_stays_null_while_the_feature_is_on(self):
        set_feature(True)

        user = User.objects.create(username="alice")

        self.assertIsNone(user.slug)

    def test_other_models_still_generate_their_own_slug(self):
        set_feature(True)

        customer = structure_factories.CustomerFactory(name="Test org")

        self.assertTrue(customer.slug)


class SyncUserSlugsTest(TestCase):
    def setUp(self):
        set_feature(True)

    def make_user(self, shortname=None, slug=None):
        user = structure_factories.UserFactory()
        User.objects.filter(pk=user.pk).update(slug=slug)
        user.refresh_from_db()
        info = models.UserInfo.objects.create(user=user)
        if shortname is not None:
            models.UserInfo.objects.filter(pk=info.pk).update(shortname=shortname)
        return user

    def test_shortname_is_copied_to_an_empty_slug(self):
        user = self.make_user(shortname="alice1")

        result = utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertEqual(user.slug, "alice1")
        self.assertEqual(result["updated"], 1)

    def test_a_slug_that_does_not_match_the_shortname_is_corrected(self):
        user = self.make_user(shortname="alice1", slug="alice-2")

        utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertEqual(user.slug, "alice1")

    def test_a_slug_without_a_shortname_is_cleared(self):
        user = self.make_user(slug="alice-2")

        result = utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertIsNone(user.slug)
        self.assertEqual(result["cleared"], 1)

    def test_a_user_with_no_userinfo_at_all_has_their_slug_cleared(self):
        user = structure_factories.UserFactory()
        User.objects.filter(pk=user.pk).update(slug="leftover")

        utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertIsNone(user.slug)

    def test_a_matching_slug_is_left_alone(self):
        user = self.make_user(shortname="alice1", slug="alice1")

        result = utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertEqual(user.slug, "alice1")
        self.assertEqual(result["updated"], 0)
        self.assertEqual(result["cleared"], 0)
        self.assertEqual(result["unchanged"], 1)

    def test_nothing_happens_while_the_feature_is_off(self):
        set_feature(False)
        user = self.make_user(shortname="alice1", slug="alice-2")

        result = utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertEqual(user.slug, "alice-2")
        self.assertTrue(result["skipped"])

    def test_the_sync_is_idempotent(self):
        self.make_user(shortname="alice1")
        self.make_user(slug="leftover")

        utils.sync_user_slugs()
        second = utils.sync_user_slugs()

        self.assertEqual(second["updated"], 0)
        self.assertEqual(second["cleared"], 0)

    def test_the_set_once_guard_does_not_block_the_sync(self):
        """A user renaming themselves is refused; this reconciliation is not."""
        user = self.make_user(shortname="alice1", slug="something-else")

        utils.sync_user_slugs()

        user.refresh_from_db()
        self.assertEqual(user.slug, "alice1")
