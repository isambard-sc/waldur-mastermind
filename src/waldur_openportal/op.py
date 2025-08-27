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
        DailyProjectUsageReport,
        Destination,
        Health,
        Instruction,
        Job,
        Node,
        PortalIdentifier,
        ProjectDetails,
        ProjectIdentifier,
        ProjectMapping,
        Status,
        UserIdentifier,
        UserMapping,
        is_config_loaded,
        fetch_job,
        fetch_jobs,
        load_config,
        health,
        get,
        run,
        send_result,
        DateRange,
        UsageReport,
        Usage,
        ProjectUsageReport,
    )

    try:
        # Fix for compatibility with older versions of OpenPortal
        # which haven't renamed ProjectClass to ProjectTemplate
        from openportal import ProjectClass as ProjectTemplate

        if not hasattr(ProjectDetails, "project_template"):
            ProjectDetails.project_template = ProjectDetails.project_class

        if not hasattr(ProjectDetails, "merge"):

            def _merge(slf, other):
                from copy import deepcopy

                merged = deepcopy(slf)

                # We only update the project template if it is not already set
                if merged.project_template is None:
                    merged.project_template = other.project_template
                elif (
                    other.project_template is not None
                    and merged.project_template != other.project_template
                ):
                    raise ValueError(
                        "Cannot merge project details with different project templates."
                    )

                # Otherwise, overwrite the existing fields if they are set
                if other.name is not None:
                    merged.name = other.name

                if other.description is not None:
                    merged.description = other.description

                if other.start_date is not None:
                    merged.start_date = other.start_date

                if other.end_date is not None:
                    merged.end_date = other.end_date

                if other.allocation is not None:
                    merged.allocation = other.allocation

                if other.members is not None:
                    merged.members = other.members

                return merged

            ProjectDetails.merge = _merge

    except ImportError:
        from openportal import ProjectTemplate

    _have_openportal = True

    def have_openportal():
        return _have_openportal

except ImportError:
    _have_openportal = False

    def have_openportal():
        return _have_openportal

    def _raise_no_openportal_error():
        raise OpenPortalError("OpenPortal is not installed.")

    class Allocation:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class DailyProjectUsageReport:
        def __init__(self, *args, **kwargs):
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

    class Node:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class PortalIdentifier:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class ProjectIdentifier:
        def __init__(self, *args, **kwargs):
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

    class Usage:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class ProjectUsageReport:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

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

    def run(*args, **kwargs):
        _raise_no_openportal_error()
