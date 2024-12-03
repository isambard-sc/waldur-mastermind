
try:
    import openportal
    import os
    have_openportal = True
except ImportError:
    have_openportal = False


class OpenPortalException(Exception):
    pass


class OpenPortalClient:
    """
    Client for the OpenPortal system. See
    https://github.com/isambard-sc/openportal
    """

    def __init__(self):
        # make sure that the OpenPortal config is loaded
        if not have_openportal:
            raise OpenPortalException("OpenPortal is not available")

        # the name of the config file is held in the
        # OPENPORTAL_CONFIG environment variable
        try:
            config_file = os.environ.get("OPENPORTAL_CONFIG")
        except KeyError:
            raise OpenPortalException("OPENPORTAL_CONFIG environment variable not set")

        if not config_file:
            raise OpenPortalException("OPENPORTAL_CONFIG environment variable not set")

        try:
            # this isn't thread-safe - we should make it thread-save
            # in the OpenPortal python layer
            openportal.load_config(config_file)
        except Exception as e:
            raise OpenPortalException(f"Failed to load OpenPortal config from '{config_file}': {e}")

    def get(self, uid):
        """
        Return the OpenPortal job with the specified UID
        """
        if not have_openportal:
            raise OpenPortalException(f"OpenPortal is not available - cannot get job with UID '{uid}'")

        try:
            job = openportal.get(uid)
        except Exception as e:
            raise OpenPortalException(f"Failed to get job with UID '{uid}': {e}")

        return job

    def run(self, command):
        """
        Run the OpenPortal command 'command' and return the OpenPortal
        job that was created. Raises an OpenPortalException if anything
        goes wrong
        """
        if not have_openportal:
            raise OpenPortalException(f"OpenPortal is not available - cannot run '{command}'")

        try:
            job = openportal.run_cmd(command)
        except Exception as e:
            raise OpenPortalException(f"Failed to run '{command}': {e}")

        return job
