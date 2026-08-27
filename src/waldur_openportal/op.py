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
