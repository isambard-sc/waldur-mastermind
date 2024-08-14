import requests


class OpenPortalException(Exception):
    pass


class OpenPortalClient:
    """
    Python client for OpenPortal
    https://github.com/isambard-sc/openportal
    """

    def __init__(self, api_url, access_token, machinename="cluster"):
        self.api_url = api_url
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Machine-Name": machinename,
        }

    def _request(self, method, url, **kwargs):
        try:
            response = requests.request(
                method, self.api_url + url, headers=self.headers, **kwargs
            )
        except requests.exceptions.RequestException:
            raise OpenPortalException("Unable to perform OpenPortal API request.")
        if response.ok:
            return response.json()
        else:
            raise OpenPortalException(
                f"Message: {response.reason}, status code: {response.status_code}"
            )

    def _get(self, url, **kwargs):
        return self._request("get", url, **kwargs)

    def _post(self, url, **kwargs):
        return self._request("post", url, **kwargs)

    def list_jobs(self, page_size=25, page_number=0):
        """
        Returns OpenPortal task ID which fetches SLURM jobs.
        """
        return self._get(
            "compute/jobs", params={"pageSize": page_size, "pageNumber": page_number}
        )["task_id"]

    def get_task(self, task_id):
        """
        Returns OpenPortal task details by its ID.
        """
        return self._get(f"tasks/{task_id}")["task"]

    def submit_job(self, fileobject):
        return self._post("compute/jobs/upload", files={"file": fileobject})["task_id"]
