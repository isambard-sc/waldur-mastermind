class OpenPortalError(Exception):
    pass


try:
    from openportal import (
        Destination,
        Health,
        Job,
        PortalIdentifier,
        ProjectIdentifier,
        ProjectMapping,
        UserIdentifier,
        UserMapping,
        is_config_loaded,
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

    _have_openportal = True

    def have_openportal():
        return _have_openportal

except ImportError:
    _have_openportal = False

    def have_openportal():
        return _have_openportal

    def _raise_no_openportal_error():
        raise OpenPortalError("OpenPortal is not installed.")

    class Destination:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Health:
        def __init__(self, *args, **kwargs):
            _raise_no_openportal_error()

    class Job:
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
