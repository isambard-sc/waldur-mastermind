import logging

from django.contrib import auth
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse

from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from http import HTTPStatus as status

from waldur_core.structure import models as structure_models
from waldur_core.structure.managers import get_connected_projects

from . import models
from . import utils


logger = logging.getLogger(__name__)

User = auth.get_user_model()


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def access_for_email(request):
    """
    Return the level of access available for the passed email address.
    The aim of this API call is to allow, e.g. Keycloak, to determine whether
    an identity connected to the specified email address is authorised
    to access Waldur, and is thus allowed to log in.

    It also allows collection of access metadata, e.g. which projects
    a user belongs to, which platform they can access, and what account
    should be used.

    The email address to check is passed as a required `email` query
    parameter.

    Note that this is only available to authenticated users, and a user
    can only query emails addresses for which they have access (i.e.
    a staff user can query any email address, but a non-staff user can
    only query email addresses for projects in which they have this
    level of access)

    The returned JSON object is as follows:

    {
        "email": email_in_waldur,
        "status": status_in_waldur,
        "short_name": shortname_in_waldur,
        "projects": projects as described below,
        "invited_by": email of the user who invited this person, if invited
        "reason": the reason for any rejection, if status is rejected
    }

    Where "projects" is a dictionary as follows, with key/value pairs
    for each project the user with the email can access

    {
        "project-a": {
            "name": "Project A",
            "resources": [
                {
                    "name": "batch.cluster1.example",
                    "username": "user.proj-a"
                },
                {
                    "name": "batch.cluster2.example",
                    "username": "user.proj-a"
                }
            ]
        },
        "project-b": {
            "name": "Project B",
            "resources": [
                {
                    "name": "batch.cluster2.example",
                    "username": "user.proj-b"
                }
            ]
        }
    }

    """
    user = request.user

    if not user.is_authenticated:
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    email = request.query_params.get("email")

    if not email:
        response = JsonResponse({"error": "An email address must be provided."})
        response.status_code = status.BAD_REQUEST
        return response

    email = str(email).lstrip().rstrip().lower()

    if "@" not in email:
        response = JsonResponse({"error": "A valid email address must be provided."})
        response.status_code = status.BAD_REQUEST
        return response

    can_query_all_emails = user.is_staff or user.is_support

    if (not can_query_all_emails) and user.email != email:
        response = JsonResponse({"error": "You can only query your own email"})
        response.status_code = status.FORBIDDEN
        return response

    logger.info(
        f"api/openportal/access_for_email request for {email} from {user} ({user.email})"
    )

    qs = User.all_objects.all()

    if not can_query_all_emails:
        qs = qs.filter(is_active=True)

    qs = qs.filter(email__iexact=email)

    reason = None
    is_authorised = False
    projects = {}
    short_name_in_waldur = None

    # Waldur stores old accounts, so can only stop searching
    # when we find an active user - can't break early for an
    # inactive user in case there is another active user with
    # the same email (or if there is a pending invitation for
    # that email)
    for user in qs:
        if user.is_active:
            # how many projects is this user associated with?
            member_of_projects = structure_models.Project.available_objects.filter(
                id__in=get_connected_projects(user)
            )

            if len(member_of_projects) == 0:
                # skip this user as they are not a member of any projects
                logger.warning(f"User {user} is not an active member of any projects")
                reason = "User account is not a member of any projects."
                continue

            # get the UserInfo object for the user
            userinfo, created = models.UserInfo.objects.get_or_create(user=user)
            userinfo.sanitise()

            email_in_waldur = user.email

            if short_name_in_waldur is None:
                short_name_in_waldur = str(userinfo.shortname).strip()

            # special case - brics users can access the notebook
            for project in member_of_projects:
                if project.short_name == "brics":
                    if "brics.brics" not in projects:
                        projects["brics.brics"] = {
                            "name": str(project.name),
                            "resources": [],
                        }

                    projects["brics.brics"]["resources"].append(
                        {
                            "name": "brics.aip1.notebooks.shared",
                            "username": f"{userinfo.shortname}.brics",
                        }
                    )

            # loop over all of the allocations for this user
            for allocation in utils.get_project_allocations(user):
                if allocation.has_project_identifier():
                    project_id = allocation.get_project_identifier()
                    project = str(project_id)
                    project_short_name = str(project_id.project).strip()
                else:
                    # we need to guess the project identifier. Do this by
                    # combining the project short name and the portal name
                    backend = allocation.get_backend()

                    project_short_name = backend.get_project_shortname(
                        allocation.project
                    )

                    if (
                        project_short_name is None
                        or len(str(project_short_name).strip()) == 0
                    ):
                        logger.warning(
                            f"Allocation {allocation} has no project short name - skipping"
                        )
                        continue

                    project_short_name = str(project_short_name).strip()

                    portal = backend.portal()

                    if portal is None or len(str(portal).strip()) == 0:
                        logger.warning(
                            f"Allocation {allocation} has no portal name - skipping"
                        )
                        continue

                    project = f"{project_short_name}.{portal}"
                    logger.warning(
                        f"{allocation} is missing project identifier - guessing '{project}'"
                    )

                destination = str(allocation.get_backend().destination())

                # find the association between the user and the allocation
                try:
                    association = models.Association.objects.get(
                        user=user, allocation=allocation
                    )
                    username = association.username
                except models.Association.DoesNotExist:
                    logger.warning(
                        f"Association between {user} and {allocation} not found"
                    )
                    username = None

                if username is None:
                    # we will have to guess the username too...
                    if short_name_in_waldur is not None:
                        username = f"{short_name_in_waldur}.{project_short_name}"
                        logger.warning(
                            f"Guessing username as '{username}' as this is not set for {project}"
                        )
                    else:
                        logger.warning(
                            f"Skipping {project} as username is not set and short name is not set"
                        )
                        continue

                if project not in projects:
                    projects[project] = {
                        "name": str(allocation.project.name),
                        "resources": [],
                    }

                projects[project]["resources"].append(
                    {
                        "name": destination,
                        "username": username,
                    }
                )

            # this is an active user
            is_authorised = True
            break
        elif reason is None:
            reason = "User account is not active"

    if short_name_in_waldur is None:
        short_name_in_waldur = ""

    if is_authorised:
        response = JsonResponse(
            {
                "email": email_in_waldur,
                "status": "active",
                "short_name": short_name_in_waldur,
                "projects": projects,
                "invited_by": "",
                "reason": "",
            }
        )

        logger.info(f"access_for_email({email}, {user}) {response.content}")

        response.status_code = status.OK
        return response

    # could not find in the list of active users - try to
    # find in the list of pending invitations
    from waldur_core.users.models import Invitation

    qs = Invitation.objects.filter(email__iexact=email)

    # Loop through invitations - can only break early if we find
    # a pending or requested invitation - Waldur stores old invitations
    # so we may find many for this email address
    invited_by = ""

    for invitation in qs:
        if invitation.state in [
            invitation.State.PENDING,
            invitation.State.REQUESTED,
        ]:
            is_authorised = True
            email_in_waldur = invitation.email
            invited_by = invitation.created_by.full_name
            reason = None
            break
        elif reason is None:
            reason = "Invitation to email is neither pending or requested."

    if is_authorised:
        response = JsonResponse(
            {
                "email": email_in_waldur,
                "status": "invited",
                "short_name": short_name_in_waldur,
                "projects": {},
                "invited_by": invited_by,
                "reason": "",
            }
        )

        logger.info(f"access_for_email({email}, {user}) {response.content}")

        response.status_code = status.OK
        return response

    if reason is None:
        reason = "Email address was not found"

    response = JsonResponse(
        {
            "email": email,
            "status": "unknown",
            "short_name": short_name_in_waldur,
            "projects": {},
            "invited_by": "",
            "reason": reason,
        }
    )

    logger.info(f"access_for_email({email}, {user}) {response.content}")

    response.status_code = status.OK
    return response
