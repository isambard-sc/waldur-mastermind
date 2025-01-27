import abc
import logging

logger = logging.getLogger(__name__)


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
