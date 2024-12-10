import logging
import re

try:
    import openportal
    import os
    have_openportal = True
except ImportError:
    have_openportal = False


from waldur_openportal.base import BaseBatchClient, BatchError
from waldur_openportal.parser import OpenPortalAssociationLine, OpenPortalReportLine
from waldur_openportal.structures import Account, Association
from waldur_openportal.utils import format_current_month


class OpenPortalError(BatchError):
    pass


logger = logging.getLogger(__name__)


class OpenPortalClient(BaseBatchClient):
    """
    This class implements Python client for OpenPortal.
    See also: https://github.com/isambard-sc/openportal
    """

    def __init__(self, instance_name=None):
        # make sure that the OpenPortal config is loaded
        if not have_openportal:
            raise OpenPortalError("OpenPortal is not available")

        if not openportal.is_config_loaded():
            self.load_config()

        self._instance_name = instance_name

    def instance_name(self):
        """
        Return the full path name for the agent instance that
        is being used by this client
        """
        return self._instance_name

    def load_config(self):
        """
        Load the OpenPortal configuration from the file specified
        in the OPENPORTAL_CONFIG environment variable. Raises an
        OpenPortalException if the environment variable is not set
        or if the config file cannot be loaded
        """
        # the name of the config file is held in the
        # OPENPORTAL_CONFIG environment variable
        try:
            config_file = os.environ.get("OPENPORTAL_CONFIG")
        except KeyError:
            raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        if not config_file:
            raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        try:
            # this isn't thread-safe - we should make it thread-save
            # in the OpenPortal python layer
            openportal.load_config(config_file)
        except Exception as e:
            raise OpenPortalError(f"Failed to load OpenPortal config from '{config_file}': {e}")

    def health(self, logger):
        """
        Log the health of the OpenPortal system to the logger
        """
        if not have_openportal:
            raise OpenPortalError("OpenPortal is not available")

        try:
            health = openportal.health()
        except Exception as e:
            raise OpenPortalError(f"Failed to get OpenPortal health: {e}")

        logger.info(f"OpenPortal health: {health}")

    def get(self, uid):
        """
        Return the OpenPortal job with the specified UID
        """
        if not have_openportal:
            raise OpenPortalError(f"OpenPortal is not available - cannot get job with UID '{uid}'")

        try:
            job = openportal.get(uid)
        except Exception as e:
            raise OpenPortalError(f"Failed to get job with UID '{uid}': {e}")

        return job

    def run(self, command):
        """
        Run the OpenPortal command 'command' and return the OpenPortal
        job that was created. Raises an OpenPortalException if anything
        goes wrong
        """
        if not have_openportal:
            raise OpenPortalError(f"OpenPortal is not available - cannot run '{command}'")

        try:
            job = openportal.run_cmd(command)
        except Exception as e:
            raise OpenPortalError(f"Failed to run '{command}': {e}")

        return job

    def list_accounts(self):
        output = self._execute_command(["list", "account"])
        return [
            self._parse_account(line) for line in output.splitlines() if "|" in line
        ]

    def _parse_account(self, line):
        parts = line.split("|")
        return Account(
            name=parts[0],
            description=parts[1],
            organization=parts[2],
        )

    def get_account(self, name):
        output = self._execute_command(["show", "account", name])
        lines = [line for line in output.splitlines() if "|" in line]
        if len(lines) == 0:
            return None
        return self._parse_account(lines[0])

    def create_account(self, name, description, organization, parent_name=None):
        parts = [
            "add",
            "account",
            name,
            'description="%s"' % description,
            'organization="%s"' % organization,
        ]
        if parent_name:
            parts.append("parent=%s" % parent_name)
        return self._execute_command(parts)

    def delete_all_users_from_account(self, name):
        return self._execute_command(["remove", "user", "where", "account=%s" % name])

    def account_has_users(self, account):
        output = self._execute_command(
            ["show", "association", "where", "account=%s" % account]
        )
        items = [
            self._parse_association(line) for line in output.splitlines() if "|" in line
        ]
        return any(item.user != "" for item in items)

    def delete_account(self, name):
        if self.account_has_users(name):
            self.delete_all_users_from_account(name)

        return self._execute_command(["remove", "account", "where", "name=%s" % name])

    def set_resource_limits(self, account, quotas):
        quota = "GrpTRESMins=cpu=%d,gres/gpu=%d,mem=%d" % (
            quotas.cpu,
            quotas.gpu,
            quotas.ram,
        )
        return self._execute_command(["modify", "account", account, "set", quota])

    def get_association(self, user, account):
        output = self._execute_command(
            ["show", "association", "where", "user=%s" % user, "account=%s" % account]
        )
        lines = [line for line in output.splitlines() if "|" in line]
        if len(lines) == 0:
            return None
        return self._parse_association(lines[0])

    def _parse_association(self, line):
        parts = line.split("|")
        value = parts[9]
        match = re.match(r"cpu=(\d+)", value)
        if match:
            value = int(match.group(1))
        return Association(
            account=parts[1],
            user=parts[2],
            value=value,
        )

    def create_association(self, username, account, default_account=""):
        return self._execute_command(
            [
                "add",
                "user",
                username,
                "account=%s" % account,
                "DefaultAccount=%s" % default_account,
            ]
        )

    def delete_association(self, username, account):
        return self._execute_command(
            [
                "remove",
                "user",
                "where",
                "name=%s" % username,
                "and",
                "account=%s" % account,
            ]
        )

    def get_usage_report(self, accounts):
        month_start, month_end = format_current_month()

        args = [
            "--noconvert",
            "--truncate",
            "--allocations",
            "--allusers",
            "--starttime=%s" % month_start,
            "--endtime=%s" % month_end,
            "--accounts=%s" % ",".join(accounts),
            "--format=Account,ReqTRES,Elapsed,User",
        ]
        output = self._execute_command(args, "sacct", immediate=False)
        return [OpenPortalReportLine(line) for line in output.splitlines() if "|" in line]

    def get_resource_limits(self, account):
        args = [
            "show",
            "association",
            "format=account,GrpTRESMins",
            "where",
            "accounts=%s" % account,
        ]
        output = self._execute_command(args, immediate=False)
        return [
            OpenPortalAssociationLine(line) for line in output.splitlines() if "|" in line
        ]

    def list_account_users(self, account):
        args = [
            "list",
            "associations",
            "format=account,user",
            "where",
            "account=%s" % account,
        ]
        output = self._execute_command(args)
        return [
            line.split("|")[1]
            for line in output.splitlines()
            if "|" in line and line[-1] != "|"
        ]

    def _execute_command(self, command, command_name="sacctmgr", immediate=True):
        account_command = [command_name, "--parsable2", "--noheader"]
        if immediate:
            account_command.append("--immediate")
        account_command.extend(command)
        return self.execute_command(account_command)
