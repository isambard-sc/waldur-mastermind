import logging

from django.contrib import auth
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from http import HTTPStatus as status

from waldur_core.structure import models as structure_models
from waldur_core.structure.managers import get_connected_projects

from . import models
from . import utils


logger = logging.getLogger(__name__)

User = auth.get_user_model()

@api_view(['GET'])
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

    if not request.user.is_staff:
        if user.email != email:
            response = JsonResponse(
                {"error": "You can only query your own email"}
            )
            response.status_code = status.FORBIDDEN
            return response

    logger.info(f"api/openportal/access_for_email request for {email} from {user} ({user.email})")

    qs = User.all_objects.all()

    if not request.user.is_staff:
        qs = qs.filter(is_active=True)

    qs = qs.filter(email__iexact=email)

    reason = None
    is_authorised = False
    projects = {}

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

            # loop over all of the allocations for this user
            for allocation in utils.get_project_allocations(user):
                if not allocation.has_project_identifier():
                    logger.warning(f"OpenPortal - {allocation} has no project identifier, skipping")
                    continue

                project = str(allocation.get_project_identifier())
                destination = str(allocation.get_backend().destination())

                # find the association between the user and the allocation
                try:
                    association = models.Association.objects.get(user=user, allocation=allocation)
                except models.Association.DoesNotExist:
                    logger.warning(f"Association between {user} and {allocation} not found - skipping")
                    continue

                username = association.username

                if username is None:
                    logger.warning(f"Association between {user} and {allocation} has no username '{username}' - skipping")
                    continue

                if project not in projects:
                    projects[project] = []

                access = {
                    "projectname": str(allocation.project.name),
                    "destination": destination,
                    "username": username,
                }

                projects[project].append(access)

            # this is an active user
            is_authorised = True
            break
        elif reason is None:
            reason = "User account is not active"

    if is_authorised:
        response = JsonResponse(
            {
                "email": email_in_waldur,
                "status": "active",
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
            "projects": {},
            "invited_by": "",
            "reason": reason,
        }
    )

    response.status_code = status.OK
    return response
