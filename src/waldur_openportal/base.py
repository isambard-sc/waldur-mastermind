import abc
import logging
import subprocess  # noqa: S404

from django.utils.functional import cached_property

from .structures import Quotas

logger = logging.getLogger(__name__)


class BatchError(Exception):
    pass


class BaseBatchClient(metaclass=abc.ABCMeta):
    def __init__(self):
        pass

    @abc.abstractmethod
    def list_accounts(self):
        """
        Get accounts list.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_account(self, name):
        """
        Get account info.
        :param name: [string] batch account name
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def create_account(self, name, description, organization, parent_name=None):
        """
        Create account.
        :param name: [string] account name
        :param description: [string] account description
        :param organization: [string] account organization name
        :param parent_name: [string] account parent name. Optional.
        :return: None
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_account(self, name):
        """
        Delete account.
        :param name: [string] account name
        :return: None
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_resource_limits(self, account, quotas):
        """
        Set account limits.
        :param account: [string] account name
        :param quotas: [structures.Quotas object] limits
        :return: None
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_association(self, user, account):
        """
        Get association user and account.
        :param user: [string] user name
        :param account: [string] account name
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def create_association(self, username, account, default_account=None):
        """
        Create association user and account
        :param username: [string] user name
        :param account: [string] account name
        :param default_account: [string] default account name. Optional.
        :return: None
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_association(self, username, account):
        """
        Delete_association user and account.
        :param username: [string] user name
        :param account: [string] account name
        :return: None
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_usage_report(self, accounts):
        """
        Get usages records.
        :param accounts: list[string]
        :return: list[BaseReportLine]
        """
        raise NotImplementedError()

    def execute_command(self, command):
        logger.info(f"Executing command: {command}")
        return ""


class BaseReportLine(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def account(self):
        pass

    @abc.abstractproperty
    def user(self):
        pass

    @property
    def cpu(self):
        return 0

    @property
    def gpu(self):
        return 0

    @property
    def ram(self):
        return 0

    @property
    def duration(self):
        return 0

    @property
    def charge(self):
        return 0

    @property
    def node(self):
        return 0

    @cached_property
    def quotas(self):
        return Quotas(
            self.cpu * self.duration,
            self.gpu * self.duration,
            self.ram * self.duration,
        )

    def __str__(self):
        return f"ReportLine: User={self.user}, Account={self.account}, CPU={self.cpu}, GPU={self.gpu}, RAM={self.ram}, Duration={self.duration}, Charge={self.charge}, Node={self.node}"
