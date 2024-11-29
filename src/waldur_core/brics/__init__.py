import logging

from django.contrib import auth
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse

from http import HTTPStatus as status

from waldur_core.structure import models
from waldur_core.structure.managers import get_connected_projects

logger = logging.getLogger(__name__)

User = auth.get_user_model()


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

    This returns a JSON object as follows, with fields

    {
        "email": "email_in_waldur",
        "status": "active | invited | unknown",
        "short_name": "short_name",
        "projects": {
            "project_1": ["platform_1", "platform_2"],
            "project_2": ["platform_1"]
        }
        "invited_by": "invited_by_user",
        "reason": "reason"
    }

    The fields are filled in three different ways, depending on the
    status of the email address:

    Status == active:

    short_name and projects are filled. invited_by and reason are null

    Status == invited:

    invited_by filled, everything else is null

    Status == unknown:

    reason filled, everything else is null

    """
    print("access_for_email")
    print(request)

    user = request.user

    print(user)

    if not user.is_authenticated:
        print("User is NOT AUTHENTICATED!")
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

    qs = User.all_objects.all()

    if not (request.user.is_staff or request.user.is_support):
        qs = qs.filter(is_active=True)

    qs = qs.filter(email__iexact=email)

    reason = None
    is_authorised = False
    short_name = None
    projects = None

    # Waldur stores old accounts, so can only stop searching
    # when we find an active user - can't break early for an
    # inactive user in case there is another active user with
    # the same email (or if there is a pending invitation for
    # that email)
    for person in qs:
        if person.is_active:
            # get the list of projects the user is active on,
            # and the platforms they can access, plus
            # their short name
            email_in_waldur = person.email

            connected_projects = get_connected_projects(person)
            projects = models.Project.available_objects.filter(
                id__in=connected_projects
            )
            project_names = [p.short_name for p in projects]

            if not project_names:
                project_names = []

            projects = {}

            for project in project_names:
                # very simple allocation mechanism for now - if the project
                # name starts with "i3-" then it will only have access to
                # the "slurm.3.isambard" platform, otherwise it will have
                # access to "slurm.aip1.isambard"
                if project in ["benchmarking", "brics"]:
                    projects[project] = [
                        "slurm.aip1.isambard",
                        "jupyter.aip1.isambard",
                        "slurm.3.isambard",
                        "slurm.macs3.isambard",
                    ]
                elif project.endswith("-i3"):
                    projects[project] = ["slurm.3.isambard", "slurm.macs3.isambard"]
                else:
                    projects[project] = [
                        "slurm.aip1.isambard",
                        "jupyter.aip1.isambard",
                    ]

            if len(projects) == 0:
                # this is not an active user
                reason = "User account has no active projects."
            else:
                # this is an active user
                is_authorised = True
                short_name = person.unix_username

                if short_name is None or len(short_name) == 0:
                    short_name = ""

                break
        elif reason is None:
            reason = "User account is not active"

    if is_authorised:
        response = JsonResponse(
            {
                "email": email_in_waldur,
                "status": "active",
                "short_name": short_name,
                "projects": projects,
                "invited_by": "",
                "reason": "",
            }
        )

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
                "projects": {},
                "short_name": "",
                "invited_by": invited_by,
                "reason": "",
            }
        )

        response.status_code = status.OK
        return response

    if reason is None:
        reason = "Email address was not found"

    response = JsonResponse(
        {
            "email": email,
            "status": "unknown",
            "short_name": "",
            "projects": {},
            "invited_by": "",
            "reason": reason,
        }
    )

    response.status_code = status.OK
    return response
