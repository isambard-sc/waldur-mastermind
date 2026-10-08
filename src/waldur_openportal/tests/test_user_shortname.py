"""
Rules for the OpenPortal user shortname, and the API that sets it.

The shortname becomes the user's local (POSIX) username on every system the
portal talks to, and it is set once. The declared validators on
UserInfo.shortname are therefore the contract, and this module pins both that
they are enforced and that a rejected write leaves nothing behind - the
shortname is copied to User.slug, and a copy that outlives a rejected write
would drift away from the value it copies.
"""

from django.test import TestCase
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import models


class SetShortnameTest(test.APITransactionTestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.other = structure_factories.UserFactory()
        self.staff = structure_factories.UserFactory(is_staff=True)

    def set_shortname(self, shortname, as_user=None, target=None):
        self.client.force_authenticate(as_user or self.user)
        return self.client.put(
            f"/api/openportal-userinfo/{(target or self.user).uuid}/set_shortname/",
            {"shortname": shortname},
        )

    def get_shortname(self, user=None):
        info = models.UserInfo.objects.filter(user=user or self.user).first()
        return info.shortname if info else None

    def get_slug(self, user=None):
        user = user or self.user
        user.refresh_from_db()
        return user.slug


class PermissionsTest(SetShortnameTest):
    def test_user_can_set_their_own_shortname(self):
        response = self.set_shortname("alice1")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(self.get_shortname(), "alice1")

    def test_staff_can_set_a_shortname_for_another_user(self):
        response = self.set_shortname("alice1", as_user=self.staff)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(self.get_shortname(), "alice1")

    def test_user_cannot_set_a_shortname_for_another_user(self):
        response = self.set_shortname("alice1", as_user=self.other)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIsNone(self.get_shortname())


class ValidationTest(SetShortnameTest):
    def assert_rejected(self, shortname):
        response = self.set_shortname(shortname)
        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
            f"{shortname!r} was accepted",
        )
        self.assertIsNone(self.get_shortname())
        # The slug is a copy of the shortname, so nothing may be copied from a
        # value that was never stored.
        self.assertNotEqual(self.get_slug(), shortname)
        return response

    def test_valid_shortname_is_accepted(self):
        for shortname in ["alice", "ab12", "x" * 32]:
            with self.subTest(shortname=shortname):
                user = structure_factories.UserFactory()
                response = self.set_shortname(
                    shortname, as_user=self.staff, target=user
                )
                self.assertEqual(
                    response.status_code, status.HTTP_200_OK, response.data
                )
                self.assertEqual(self.get_shortname(user), shortname)
                self.assertEqual(self.get_slug(user), shortname)

    def test_empty_shortname_is_rejected(self):
        self.assert_rejected("")

    def test_missing_shortname_is_rejected(self):
        self.client.force_authenticate(self.user)
        response = self.client.put(
            f"/api/openportal-userinfo/{self.user.uuid}/set_shortname/", {}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_shortname_must_start_with_a_letter(self):
        self.assert_rejected("1alice")

    def test_shortname_must_be_lower_case(self):
        self.assert_rejected("Alice1")

    def test_shortname_cannot_contain_punctuation(self):
        for shortname in ["with-dash", "with_underscore", "with space", "a.b"]:
            with self.subTest(shortname=shortname):
                self.assert_rejected(shortname)

    def test_shortname_below_the_minimum_length_is_rejected(self):
        self.assert_rejected("abc")

    def test_shortname_above_the_maximum_length_is_rejected(self):
        self.assert_rejected("x" * 33)

    def test_reserved_names_are_rejected_anywhere_in_the_shortname(self):
        for shortname in [
            "admin",
            "root",
            "myadmin",
            "adminuser",
            "rootuser",
            "myroot",
            "xadminx",
        ]:
            with self.subTest(shortname=shortname):
                self.assert_rejected(shortname)


class SetOnceTest(SetShortnameTest):
    def test_shortname_cannot_be_changed_once_set(self):
        self.assertEqual(self.set_shortname("alpha1").status_code, status.HTTP_200_OK)

        response = self.set_shortname("beta22")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(self.get_shortname(), "alpha1")
        # The refused rename must not move the copy either.
        self.assertEqual(self.get_slug(), "alpha1")

    def test_setting_the_same_shortname_again_is_accepted(self):
        self.assertEqual(self.set_shortname("alpha1").status_code, status.HTTP_200_OK)
        self.assertEqual(self.set_shortname("alpha1").status_code, status.HTTP_200_OK)
        self.assertEqual(self.get_shortname(), "alpha1")


class UniquenessTest(SetShortnameTest):
    def test_shortname_taken_by_another_user_is_rejected(self):
        self.assertEqual(
            self.set_shortname(
                "shared", as_user=self.staff, target=self.other
            ).status_code,
            status.HTTP_200_OK,
        )

        response = self.set_shortname("shared")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsNone(self.get_shortname())
        self.assertNotEqual(self.get_slug(), "shared")


class ModelTest(TestCase):
    """set_shortname() is the only writer of UserInfo.shortname, so it carries
    the rules for callers that do not come through the API."""

    def test_model_rejects_an_invalid_shortname(self):
        from django.core.exceptions import ValidationError

        user = structure_factories.UserFactory()
        info = models.UserInfo.objects.create(user=user)

        with self.assertRaises(ValidationError):
            info.set_shortname("admin1")

        user.refresh_from_db()
        self.assertNotEqual(user.slug, "admin1")
        info.refresh_from_db()
        self.assertIsNone(info.shortname)
