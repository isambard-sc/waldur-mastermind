class OpenPortalError(Exception):
    pass

    def message(self):
        """
        Returns a user-friendly error message.
        """
        return "An unspecified OpenPortal error occurred."


class OpenPortalOtherError(OpenPortalError):
    def __init__(self, message=None):
        super().__init__()
        self._message = message

    def __str__(self):
        if self._message is None:
            return "OpenPortalError: An unspecified error occurred."
        else:
            return f"OpenPortalError: {self._message}"

    def __repr__(self):
        return f"OpenPortalError(message={self._message})"

    def message(self):
        if self._message is None:
            return "An unspecified error occurred."
        else:
            return self._message


class OpenPortalUnsupportedCommandError(OpenPortalError):
    pass


class ManagedProjectPermissionError(OpenPortalError):
    pass


class ManagedProjectRejectedError(ManagedProjectPermissionError):
    def __init__(self, message=None):
        super().__init__()
        self._message = message

    def __str__(self):
        if self._message is None:
            return "ManagedProjectRejectedError: The project is rejected."
        else:
            return f"ManagedProjectRejectedError: {self._message}"

    def __repr__(self):
        return f"ManagedProjectRejectedError(message={self._message})"

    def message(self):
        if self._message is None:
            return "The project is rejected."
        else:
            return self._message


class ManagedProjectPendingError(ManagedProjectPermissionError):
    def __init__(self, message=None):
        super().__init__()
        self._message = message

    def __str__(self):
        if self._message is None:
            return "ManagedProjectPendingError: The project is pending."
        else:
            return f"ManagedProjectPendingError: {self._message}"

    def __repr__(self):
        return f"ManagedProjectPendingError(message={self._message})"

    def message(self):
        if self._message is None:
            return "The project is pending."
        else:
            return self._message


def convert_to_openportal_error(error_message: str) -> OpenPortalError:
    """
    Converts a Waldur OpenPortal error to an OpenPortalError.
    """
    error_message = error_message.lstrip("RuntimeError{").rstrip("}")

    if error_message.startswith("OpenPortalError: "):
        return OpenPortalOtherError(error_message[16:])
    elif error_message.startswith("ManagedProjectRejectedError: "):
        return ManagedProjectRejectedError(error_message[29:])
    elif error_message.startswith("ManagedProjectPendingError: "):
        return ManagedProjectPendingError(error_message[28:])
    else:
        return OpenPortalOtherError(error_message)


try:
    from openportal import (
        Allocation,
        AwardDetails,
        DomainPattern,
        DailyProjectUsageReport,
        Destination,
        Health,
        Instruction,
        Job,
        Link,
        Node,
        Note,
        Notification,
        PortalIdentifier,
        ProjectDetails,
        ProjectIdentifier,
        ProjectMapping,
        ProjectStorageReport,
        ProjectTemplate,
        ProjectUsageReport,
        Quota,
        Status,
        StorageReport,
        UserIdentifier,
        UserMapping,
        is_config_loaded,
        fetch_job,
        fetch_jobs,
        fetch_notification,
        load_config,
        health,
        get,
        get_portal,
        notify,
        run,
        send_result,
        sync_offerings,
        DateRange,
        UsageReport,
        Usage,
    )

    _have_openportal = True

    def have_openportal():
        return _have_openportal

    def ensure_config_loaded():
        if not is_config_loaded():
            try:
                import os

                config_file = os.environ.get("OPENPORTAL_CONFIG")
            except KeyError:
                raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

            if not config_file:
                raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

            try:
                # this isn't thread-safe - we should make it thread-save
                # in the OpenPortal python layer
                load_config(config_file)
            except Exception as e:
                raise OpenPortalError(
                    f"Failed to load OpenPortal config from '{config_file}': {e}"
                )

except ImportError:
    _have_openportal = False

    def have_openportal():
        return _have_openportal

    def _raise_no_openportal_error():
        raise OpenPortalError("OpenPortal is not installed.")

    class AwardDetails:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def from_json(*args, **kwargs):
            _raise_no_openportal_error()

        def merge(self, *args, **kwargs):
            _raise_no_openportal_error()
            return self

        def to_json(self):
            _raise_no_openportal_error()

    class DomainPattern:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Allocation:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class DailyProjectUsageReport:
        # Properties (Rust #[getter])
        @property
        def num_jobs(self):
            _raise_no_openportal_error()

        @property
        def total_wait_seconds(self):
            _raise_no_openportal_error()

        @property
        def is_consistent(self):
            _raise_no_openportal_error()

        @property
        def average_wait_seconds(self):
            _raise_no_openportal_error()

        @property
        def components(self):
            _raise_no_openportal_error()
            return []

        @property
        def total_usage(self):
            _raise_no_openportal_error()

        @property
        def is_complete(self):
            _raise_no_openportal_error()

        # Regular methods
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        def add_unattributed_usage(self, *args, **kwargs):
            _raise_no_openportal_error()

        def set_complete(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Destination:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Health:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Instruction:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Job:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @property
        def destination(self):
            _raise_no_openportal_error()

        @property
        def forwarded_for(self):
            _raise_no_openportal_error()

    class Node:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Notification:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def from_json(*args, **kwargs):
            _raise_no_openportal_error()

        @property
        def id(self):
            _raise_no_openportal_error()

        @property
        def destination(self):
            _raise_no_openportal_error()

        @property
        def event(self):
            _raise_no_openportal_error()

        @property
        def event_type(self):
            _raise_no_openportal_error()

        @property
        def event_argument(self):
            _raise_no_openportal_error()

        def to_json(self):
            _raise_no_openportal_error()

    class PortalIdentifier:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class ProjectIdentifier:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @property
        def project(self):
            _raise_no_openportal_error()

        @property
        def portal(self):
            _raise_no_openportal_error()

    class ProjectMapping:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class UserIdentifier:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class UserMapping:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class DateRange:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class UsageReport:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def combine(*args, **kwargs):
            _raise_no_openportal_error()

        def filter(self, *args, **kwargs):
            _raise_no_openportal_error()
            return self

    class Usage:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def from_hours(*args, **kwargs):
            _raise_no_openportal_error()

    class Quota:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class StorageReport:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        def filter(self, *args, **kwargs):
            _raise_no_openportal_error()
            return self

    class ProjectStorageReport:
        # Properties (Rust #[getter])
        @property
        def project(self):
            _raise_no_openportal_error()

        @property
        def generated_at(self):
            _raise_no_openportal_error()

        @property
        def project_quotas(self):
            _raise_no_openportal_error()

        @property
        def user_quotas(self):
            _raise_no_openportal_error()

        @property
        def users(self):
            _raise_no_openportal_error()
            return []

        @property
        def user_mapping(self):
            _raise_no_openportal_error()

        # Regular methods
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def from_json(*args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def combine(*args, **kwargs):
            _raise_no_openportal_error()

        def to_json(self):
            _raise_no_openportal_error()

        def is_empty(self):
            _raise_no_openportal_error()

        def daily_reports(self, *args, **kwargs):
            _raise_no_openportal_error()
            return []

        def get_report(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_project(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_portal(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_users(self, *args, **kwargs):
            _raise_no_openportal_error()

        def filter(self, *args, **kwargs):
            _raise_no_openportal_error()
            return self

        def __iadd__(self, other):
            _raise_no_openportal_error()
            return self

        def __add__(self, other):
            _raise_no_openportal_error()
            return self

    class ProjectUsageReport(UsageReport):
        # Properties (Rust #[getter])
        @property
        def dates(self):
            _raise_no_openportal_error()
            return []

        @property
        def components(self):
            _raise_no_openportal_error()
            return []

        @property
        def project(self):
            _raise_no_openportal_error()

        @property
        def portal(self):
            _raise_no_openportal_error()

        @property
        def users(self):
            _raise_no_openportal_error()
            return []

        @property
        def user_mapping(self):
            _raise_no_openportal_error()

        @property
        def unmapped_users(self):
            _raise_no_openportal_error()
            return []

        @property
        def total_usage(self):
            _raise_no_openportal_error()

        @property
        def num_jobs(self):
            _raise_no_openportal_error()

        @property
        def total_wait_seconds(self):
            _raise_no_openportal_error()

        @property
        def average_wait_seconds(self):
            _raise_no_openportal_error()

        @property
        def unmapped_usage(self):
            _raise_no_openportal_error()

        @property
        def is_complete(self):
            _raise_no_openportal_error()

        # Regular methods
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def from_json(*args, **kwargs):
            _raise_no_openportal_error()

        @staticmethod
        def combine(*args, **kwargs):
            _raise_no_openportal_error()

        def to_json(self):
            _raise_no_openportal_error()

        def in_hours(self):
            _raise_no_openportal_error()

        def usage(self, *args, **kwargs):
            _raise_no_openportal_error()

        def get_report(self, *args, **kwargs):
            _raise_no_openportal_error()

        def get_component(self, *args, **kwargs):
            _raise_no_openportal_error()

        def add_mapping(self, *args, **kwargs):
            _raise_no_openportal_error()

        def add_mappings(self, *args, **kwargs):
            _raise_no_openportal_error()

        def set_project(self, *args, **kwargs):
            _raise_no_openportal_error()

        def scale_total(self, *args, **kwargs):
            _raise_no_openportal_error()

        def set_report(self, *args, **kwargs):
            _raise_no_openportal_error()

        def add_report(self, *args, **kwargs):
            _raise_no_openportal_error()

        def daily_reports(self, *args, **kwargs):
            _raise_no_openportal_error()
            return []

        def set_complete(self, *args, **kwargs):
            _raise_no_openportal_error()

        def set_day_complete(self, *args, **kwargs):
            _raise_no_openportal_error()

        def to_usage_report(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_project(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_portal(self, *args, **kwargs):
            _raise_no_openportal_error()

        def remap_users(self, *args, **kwargs):
            _raise_no_openportal_error()

        def filter(self, *args, **kwargs):
            _raise_no_openportal_error()
            return self

        def __iadd__(self, other):
            _raise_no_openportal_error()
            return self

        def __add__(self, other):
            _raise_no_openportal_error()
            return self

    class ProjectTemplate:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    def is_config_loaded():
        _raise_no_openportal_error()

    def load_config(*args, **kwargs):
        _raise_no_openportal_error()

    def health(*args, **kwargs):
        _raise_no_openportal_error()

    def get(*args, **kwargs):
        _raise_no_openportal_error()

    def get_portal(*args, **kwargs):
        _raise_no_openportal_error()

    def sync_offerings(*args, **kwargs):
        _raise_no_openportal_error()

    def notify(*args, **kwargs):
        _raise_no_openportal_error()

    def run(*args, **kwargs):
        _raise_no_openportal_error()

    def ensure_config_loaded():
        _raise_no_openportal_error()
