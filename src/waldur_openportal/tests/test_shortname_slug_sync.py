"""
sync_openportal_shortnames_to_slugs() must not touch an application portal.

On the awards site Project.slug holds the award identifier (0251-4064-4677-1),
not a copy of the OpenPortal project shortname. Overwriting it would destroy
the identifier every link and every award refers to, for every project at once.
ProjectInfo.set_shortname() has always made that distinction; this function is
the bulk one, so it is the more dangerous of the two.
"""

from django.test import TestCase

from waldur_core.core.models import APPLICATION_PORTAL_FEATURE, Feature
from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import models, utils


def set_application_portal(value):
    Feature.objects.update_or_create(
        key=APPLICATION_PORTAL_FEATURE, defaults={"value": value}
    )


class SyncShortnamesToSlugsTest(TestCase):
    def make_project(self, shortname, slug):
        project = structure_factories.ProjectFactory()
        type(project).objects.filter(pk=project.pk).update(slug=slug)
        project.refresh_from_db()
        info = models.ProjectInfo.objects.create(project=project)
        models.ProjectInfo.objects.filter(pk=info.pk).update(shortname=shortname)
        return project

    def test_award_identifiers_survive_on_an_application_portal(self):
        set_application_portal(True)
        project = self.make_project(shortname="abc123", slug="0251-4064-4677-1")

        result = utils.sync_openportal_shortnames_to_slugs()

        project.refresh_from_db()
        self.assertEqual(project.slug, "0251-4064-4677-1")
        self.assertEqual(result["projects_updated"], 0)

    def test_shortname_is_copied_when_the_portal_manages_projects(self):
        set_application_portal(False)
        project = self.make_project(shortname="abc123", slug="something-else")

        result = utils.sync_openportal_shortnames_to_slugs()

        project.refresh_from_db()
        self.assertEqual(project.slug, "abc123")
        self.assertEqual(result["projects_updated"], 1)

    def test_a_missing_feature_row_means_the_portal_manages_projects(self):
        """set_shortname() treats an absent row as False; so must this."""
        Feature.objects.filter(key=APPLICATION_PORTAL_FEATURE).delete()
        project = self.make_project(shortname="abc123", slug="something-else")

        utils.sync_openportal_shortnames_to_slugs()

        project.refresh_from_db()
        self.assertEqual(project.slug, "abc123")
