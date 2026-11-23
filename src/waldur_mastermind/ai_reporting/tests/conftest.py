from unittest import mock

import pytest

from waldur_mastermind.ai_reporting.models import HarnessConnection


@pytest.fixture(autouse=True)
def signing_key_is_set(request):
    """Most tests don't care about signing; the ones that do set a real key,
    or patch this back to False. test_models checks the property itself."""
    if request.module.__name__.endswith("test_models"):
        yield
        return
    with mock.patch.object(
        HarnessConnection,
        "is_signing_configured",
        new_callable=mock.PropertyMock,
        return_value=True,
    ):
        yield
