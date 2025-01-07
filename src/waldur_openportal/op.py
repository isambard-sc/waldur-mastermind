

from waldur_openportal.base import BatchError

class OpenPortalError(BatchError):
    pass

try:
    from openportal import Destination, Health, Job, ProjectIdentifier, ProjectMapping, \
        UserIdentifier, UserMapping, is_config_loaded, load_config, health, \
        get, run

    have_openportal = True
except ImportError:
    have_openportal = False
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
