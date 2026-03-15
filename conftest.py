import os
import pytest


def pytest_addoption(parser):
    parser.addoption("--pam-user", default=os.environ.get("WEB_UI_PAM_USER", ""),
                     help="PAM username for login tests (env: WEB_UI_PAM_USER)")
    parser.addoption("--pam-pass", default=os.environ.get("WEB_UI_PAM_PASS", ""),
                     help="PAM password for login tests (env: WEB_UI_PAM_PASS)")


@pytest.fixture(scope="session")
def pam_user(request):
    return request.config.getoption("--pam-user")


@pytest.fixture(scope="session")
def pam_pass(request):
    return request.config.getoption("--pam-pass")
