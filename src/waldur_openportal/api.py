import logging
import datetime
import hashlib
import httpx

from django.contrib import auth
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse
from waldur_core.core import models
from django.core.cache import cache
from waldur_core.core.authentication import refresh_token
from waldur_core.core.authentication import OIDCAuthentication
from django.conf import settings
from rest_framework import status
from waldur_core.core.authentication import set_user_context
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from http import HTTPStatus as status

from waldur_core.core import utils as core_utils
from waldur_core.users.enums import InvitationState
from waldur_core.structure import models as structure_models
from waldur_core.core import models as core_models
from waldur_core.structure.managers import get_connected_projects

from waldur_mastermind.invoices import models as invoice_models

from . import models, tasks, utils
from .board import OpenPortalBoard
from . import op as openportal

logger = logging.getLogger(__name__)

User = auth.get_user_model()


def _get_project_spend_info_by_username(request, user, username):
    logger.info(f"api/openportal/monthly_spend request for username: {username}")

    # use the association to find the project_info, from which we can get the project
    project = None
    project_id = None

    # Note that there could be many projects associated with this username
    # in the general case, but we will only return the first one for now
    # as in BriCS we use project-specific user names
    try:
        associations = models.Association.objects.filter(username=username)

        for association in associations:
            if not (user.is_staff or user.is_support):
                if association.user != user:
                    logger.warning(
                        f"User {user} is not the owner of the association {association}"
                    )
                    continue

            if association.has_project_identifier():
                project_id = association.get_project_identifier()

                try:
                    project_info = models.ProjectInfo.objects.filter(
                        shortname=project_id.project
                    ).first()
                except Exception:
                    continue

                if project_info is not None:
                    if project_info.project is not None:
                        project = project_info.project
                        break
    except Exception as e:
        logger.error(f"Error looking up username {username}: {e}")
        response = JsonResponse({"error": "Username not found."})
        response.status_code = status.NOT_FOUND
        return response

    if project is None:
        logger.error(f"Username {username} not found.")
        response = JsonResponse({"error": "Username not found."})
        response.status_code = status.NOT_FOUND
        return response

    # get the total credit available for this project
    credit = None

    try:
        project_credit = invoice_models.ProjectCredit.objects.get(project=project)

        if project_credit.value is not None:
            credit = float(project_credit.value)

    except Exception:
        pass

    try:
        end_date = project.end_date.strftime("%Y-%m-%d")
    except Exception:
        end_date = None

    # now calculate the total spend across all OpenPortal allocations
    # for this project
    total_spend = None

    # find any openportal allocations associated with the project
    try:
        allocations = models.Allocation.objects.filter(project=project, is_active=True)

        if allocations:
            total_spend = 0.0

            for allocation in allocations:
                total_spend += float(allocation.node_usage)
    except Exception:
        pass

    data = {
        "projects": [
            {
                "name": str(project.name),
                "identifier": str(project_id),
                "usage": total_spend,
                "limit": credit,
                "end_date": end_date,
            }
        ]
    }

    logger.info(f"project_spend_info({username}) {data}")

    return JsonResponse(data)


def _get_project_spend_info_by_email(request, user, email):
    logger.info(f"api/openportal/monthly_spend request for email: {email}")
    # TODO

    return JsonResponse(None)


def _get_project_spend_info_by_project_id(request, user, project_id):
    logger.info(f"api/openportal/monthly_spend request for project_id: {project_id}")
    # TODO

    return JsonResponse(None)


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def project_spend_info(request):
    """
    Return the monthly spend for the user in the format:

    {
        projects: [
            {
                "name": "Project human name"
                "identifier": "Project identifier"
                "usage": 123.45
                "limit": 205.52
                "end_date": "2025-10-31"
            },
            ...
        ]
    }

    This will either search for projects by local username,
    or by email address, or for the current Waldur user,
    or by the project identifier.

    This returns the current spend, and credit limit for the current month
    for each matching project, as well as the project end date (when the
    credits expire).

    Note that the only staff or support users can query any project.
    Non-staff users can only query the projects to which they belong.
    """
    user = request.user

    if not (user.is_authenticated or user.is_active):
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    username = request.query_params.get("username")

    if username:
        username = str(username).lstrip().rstrip()
        if len(username) == 0:
            username = None

    email = request.query_params.get("email")

    if email:
        email = str(email).lstrip().rstrip()
        if len(email) == 0:
            email = None

    project_id = request.query_params.get("project_id")

    if project_id:
        project_id = str(project_id).lstrip().rstrip()
        if len(project_id) == 0:
            project_id = None

    if username is None and email is None and project_id is None:
        email = user.email

    if username is not None:
        return _get_project_spend_info_by_username(request, user, username=username)
    elif email is not None:
        return _get_project_spend_info_by_email(request, user, email=email)
    elif project_id is not None:
        return _get_project_spend_info_by_project_id(
            request, user, project_id=project_id
        )
    else:
        return JsonResponse(None)


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

    if not (user.is_authenticated or user.is_active):
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
    email_in_waldur = None

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

            # this is an active user
            is_authorised = True

            # get the UserInfo object for the user
            userinfo, created = models.UserInfo.objects.get_or_create(user=user)
            userinfo.sanitise()

            email_in_waldur = user.email

            if short_name_in_waldur is None:
                if userinfo.shortname is None:
                    logger.warning(f"User {user} has not set their short name")
                    break

                short_name_in_waldur = str(userinfo.shortname).strip()

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
                    association = utils.get_association(
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
            InvitationState.PENDING,
            InvitationState.REQUESTED,
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


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def customer_spend_info(request):
    user = request.user

    if not (user.is_authenticated or user.is_active):
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    if not (user.is_staff or user.is_support):
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    customer = request.query_params.get("customer")

    if not customer:
        response = JsonResponse({"error": "A customer must be provided."})
        response.status_code = status.BAD_REQUEST
        return response

    customer = str(customer).lstrip().rstrip()

    if len(customer) == 0:
        response = JsonResponse({"error": "A customer must be provided."})
        response.status_code = status.BAD_REQUEST
        return response

    # get an optional "use_project_ids" query parameter
    use_project_ids = request.query_params.get("use_project_ids", "false").lower()

    if use_project_ids not in ["true", "false"]:
        response = JsonResponse(
            {"error": "The 'use_project_ids' parameter must be 'true' or 'false'."}
        )
        response.status_code = status.BAD_REQUEST
        return response

    use_project_ids = use_project_ids == "true"

    # get an optional "start_date" query parameter which is the start month-year
    start_date = request.query_params.get("start_date")

    if start_date:
        start_date = str(start_date).lstrip().rstrip()

        if len(start_date) == 0:
            start_date = None

    if start_date is not None:
        try:
            parts = start_date.split("-")
            start_date = datetime.date(year=int(parts[0]), month=int(parts[1]), day=1)

        except Exception as e:
            response = JsonResponse({"error": str(e)})
            response.status_code = status.BAD_REQUEST
            return response

    # get an optional "end_date" query parameter which is the end month-year
    end_date = request.query_params.get("end_date")

    if end_date:
        end_date = str(end_date).lstrip().rstrip()

        if len(end_date) == 0:
            end_date = None

    if end_date is not None:
        try:
            parts = end_date.split("-")
            end_date = datetime.date(year=int(parts[0]), month=int(parts[1]), day=1)
            end_date = utils.get_last_day_of_month(end_date)

            if start_date is not None and end_date < start_date:
                response = JsonResponse({"error": "End date must be after start date."})
                response.status_code = status.BAD_REQUEST
                return response

        except Exception as e:
            response = JsonResponse({"error": str(e)})
            response.status_code = status.BAD_REQUEST
            return response

    orgs = structure_models.Customer.objects.filter(name=customer)

    if len(orgs) != 1:
        response = JsonResponse({})
        response.status_code = status.BAD_REQUEST
        return response

    org = orgs[0]

    # get all of the projects in this organisation
    projs = structure_models.Project.objects.filter(customer=org)

    response = {}
    response["customer"] = str(org.name)

    if start_date is not None:
        response["start_date"] = start_date.strftime("%Y-%m-%d")

    if end_date is not None:
        response["end_date"] = end_date.strftime("%Y-%m-%d")

    response["use_project_ids"] = use_project_ids

    projects = {}

    current_year = datetime.date.today().year

    for proj in projs:
        try:
            credit = invoice_models.ProjectCredit.objects.filter(project=proj)[0].value
        except Exception:
            credit = 0

        project = {}
        project["total_allocation"] = float(credit)
        project["total_consumption"] = 0.0
        project["resources"] = []

        # get all of the invoice items for this project - this contains
        # all of the consumption details, and is not deleted when the
        # project is deleted
        try:
            invoice_items = invoice_models.InvoiceItem.objects.filter(project=proj)
        except Exception:
            invoice_items = []

        project_start_date = proj.start_date
        project_end_date = proj.end_date

        if project_start_date is None:
            project_start_date = proj.created.date()

        project["start_date"] = project_start_date.strftime("%Y-%m-%d")

        if project_end_date is not None:
            project["end_date"] = project_end_date.strftime("%Y-%m-%d")

        try:
            project["num_members"] = len(proj.get_users())
        except Exception:
            project["num_members"] = 0

        resources = {}

        for invoice_item in invoice_items:
            usage = float(invoice_item.price)

            if usage == 0:
                continue
            elif usage < 0:
                # this is a credit, so add it to the total allocation
                project["total_allocation"] += abs(usage)
                continue

            # get the name of the resource consumed
            try:
                resource = invoice_item.resource.offering.name.strip()
            except Exception:
                logger.warning(
                    f"Invoice item {invoice_item} has no resource offering - skipping"
                )
                continue

            if resource is None or len(str(resource)) == 0:
                logger.warning(
                    f"Invoice item {invoice_item} has no resource name - skipping"
                )
                continue

            if resource not in resources:
                resources[resource] = {
                    "name": resource,
                    "consumption": [],
                }

            # get the month and year of the usage
            try:
                month = invoice_item.invoice.month
                year = invoice_item.invoice.year
            except Exception:
                logger.warning(
                    f"Invoice item {invoice_item} has no invoice month/year - skipping"
                )
                continue

            if month is None or year is None:
                logger.warning(
                    f"Invoice item {invoice_item} has no invoice month/year - skipping"
                )
                continue

            if month < 1 or month > 12:
                logger.warning(
                    f"Invoice item {invoice_item} has invalid month {month} - skipping"
                )
                continue

            if year < 2000 or year > current_year:
                logger.warning(
                    f"Invoice item {invoice_item} has invalid year {year} - skipping"
                )
                continue

            consumption_date = datetime.date(year=year, month=month, day=1)

            # change the day to the last of the month
            consumption_date = utils.get_last_day_of_month(consumption_date)

            if (
                project_start_date is not None
                and consumption_date < project_start_date
                and usage == 0.0
            ):
                # skip this zero usage if it is before the project start date
                continue

            if start_date is not None and consumption_date < start_date:
                continue

            if end_date is not None and consumption_date > end_date:
                continue

            # have we seen this month/year for this resource? - if so,
            # then we need to add the usage to the existing entry
            found = False

            for entry in resources[resource]["consumption"]:
                if entry["year"] == year and entry["month"] == month:
                    entry["value"] += usage
                    found = True
                    break

            if not found:
                resources[resource]["consumption"].append(
                    {
                        "year": year,
                        "month": month,
                        "value": usage,
                    }
                )

            project["total_consumption"] += usage

        project["resources"] = list(resources.values())
        project["balance"] = project["total_allocation"] - project["total_consumption"]

        project_short_name = str(utils.get_project_shortname(proj))

        project["shortname"] = project_short_name

        if use_project_ids:
            # get the shortname for the project from OpenPortal
            project_name = project_short_name
        else:
            project_name = str(proj.name).strip()

        projects[project_name] = project

    response["projects"] = projects

    response = JsonResponse(response)
    response.status_code = status.OK
    return response


@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
def fetch_job(request):
    """
    End-point called by the OpenPortal bridge agent to signal to Waldur
    that new a job has arrived and it needs to be fetched.

    This triggers the code to fetch the job and then submit it for
    processing to one of the backend celery workers.

    As argument, you need to pass in the `job_id` query parameter,
    which must match one of the jobs in the OpenPortal bridge queue.

    If a job is not found, it will return an authorisation error
    (403 Forbidden), thereby preventing "unauthorised" access to
    this end-point.

    If the job is found, it will return a 200 OK response.

    The use of the job-id acts as a bit of authorisation, as the
    job-id is random, and is only known to the OpenPortal bridge agent.
    It is a de-facto secret shared between the OpenPortal bridge agent
    and Waldur, and is not known to any other user or system.
    """

    board = OpenPortalBoard()

    job_id = request.query_params.get("job_id")

    if not job_id:
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    # move to serlialiser django
    job_id = str(job_id).lstrip().rstrip()

    if len(job_id) == 0:
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    # fetch this job from the OpenPortal bridge queue
    try:
        job = board.fetch_job(job_id)
        if job is None:
            response = JsonResponse({})
            response.status_code = status.UNAUTHORIZED
            return response
    except Exception as e:
        logger.error(f"Error fetching job {job_id}: {e}")
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    job_id = str(job.id).lstrip().rstrip()

    if len(job_id) == 0:
        logger.error(f"Job {job} has no job_id")
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    if job.state != openportal.Status.pending():
        logger.error(f"Job {job_id} is not in PENDING state, but in {job.state}")
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    # create a Job model object for this job
    job_model, created = models.Job.objects.get_or_create(
        job_id=job_id,
        defaults={
            "job_data": job.to_json(),
            "state": models.Job.State.PENDING,
        },
    )

    if not created:
        logger.warning(f"Job {job_id} already exists in the database... re-running?")

    if job_model.state != models.Job.State.PENDING:
        logger.error(f"Job {job_id} is not in PENDING state, but in {job_model.state}")
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response

    # submit the job for processing
    logger.info(f"Submitting job {job_id} for processing")
    tasks.run_job.delay(core_utils.serialize_instance(job_model))

    response = JsonResponse({})
    response.status_code = status.OK
    return response

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def whoami(request):

    user = request.user

    if not (user.is_authenticated or user.is_active):
        response = JsonResponse({})
        response.status_code = status.UNAUTHORIZED
        return response
    email = request.query_params.get("email")

    if not email:
        response = JsonResponse({"error": "An email must be provided"})
        response.status_code = status.BAD_REQUEST
        return response

    users = core_models.User.objects.filter(email=f"{email}")

    if len(users)>0:
        user = users[0]
        if user.email==email:
            response = JsonResponse({
            "first_name": f"{user.first_name}",
            "last_name": f"{user.last_name}",
            "user_name": f"{user.username}",
            "email": f"{user.email}",
            "date_joined": f"{user.date_joined}",
            "organization": f"{user.organization}",
            "job_title": f"{user.job_title}",
            "phone_number": f"{user.phone_number}",
            "is_staff": f"{user.is_staff}",
            })
            return response
        response = JsonResponse({"error":"The email does not match or the user has been disabled."})
    else:
        response = JsonResponse({"No users found."})
    return response


@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
def get_API_token(request):
    #Extract OIDC token from Authorisation header
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.lower().startswith("bearer "):
        return JsonResponse({"error":"Authorisation header missing or invalid"}, status=status.BAD_REQUEST)

    raw_oidc_token = auth_header.split(" ", 1)[1].strip()

    if not raw_oidc_token:
        return JsonResponse({"error":"Bearer token not provided"}, status=status.BAD_REQUEST)

    config = settings.WALDUR_CORE
    introspection_url = config.get("OIDC_INTROSPECTION_URL")
    client_id = config.get("OIDC_CLIENT_ID")
    client_secret = config.get("OIDC_CLIENT_SECRET")
    user_field = config.get("OIDC_USER_FIELD", "username")
    cache_timeout = config.get("OIDC_CACHE_TIMEOUT", 300)  # default 5 min
    if not (introspection_url and client_id and client_secret):
        raise JsonResponse({"error":"OIDC config incomplete"}, status=status.BAD_REQUEST)
    # Use SHA-256 to hash token to avoid very long keys
    cache_key = f"oidc_token:{hashlib.sha256(raw_oidc_token.encode()).hexdigest()}"

    data = cache.get(cache_key)

    if not data:
        try:
            response = httpx.post(
                introspection_url,
                data={"token": raw_oidc_token},
                auth=(client_id, client_secret),
                timeout=5.0,
            )

        except Exception as e:
            return JsonResponse({"error":"Introspection failed"}, status=status.BAD_REQUEST)

        if response.status_code != 200:
            return JsonResponse({"error": "Introspection endpoint error."})
            # raise AuthenticationFailed("Introspection endpoint error.")

        data = response.json()
        if not data.get("active"):
            return JsonResponse({"error": "Token is inactive or invalid."})
            # raise AuthenticationFailed("Token is inactive or invalid.")

        cache.set(cache_key, data, timeout=cache_timeout)

    # logger.error(f"Introspection response: {response.json()}")
    user_identifier = data.get(user_field)

    if not user_identifier:
        return JsonResponse({"error": f"Token missing '{user_field}' field"}, status=status.UNAUTHORIZED)

    # GET Waldur user
    user, _ = core_models.User.objects.get_or_create(username=user_identifier)
    set_user_context(user)

    # Check staff access
    user_access = "staff" if user.is_staff else "not a staff"

    # Sync email with Keycloak response email
    email = data.get("email")
    if email and user.email != email:
        user_email = user.email # Sync email with response returned from Keycloak
        user.save(update_fields=["email"])

    # Generate Waldur API token
    waldur_api_token_obj = refresh_token(user)
    waldur_api_token = waldur_api_token_obj.key

    return JsonResponse({"token":waldur_api_token, "user_access": user_access, "user_email": email})
