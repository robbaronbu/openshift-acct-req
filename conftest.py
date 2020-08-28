import pytest


def pytest_addoption(parser):
    parser.addoption("--amurl", action="store")
    parser.addoption("--user", action="store")
    parser.addoption("--passwd", action="store")


@pytest.fixture(scope="session")
def acct_mgt_url(request):
    amurl_value = request.config.option.amurl
    if amurl_value is None:
        pytest.skip()
    return amurl_value


@pytest.fixture(scope="session")
def username(request):
    user_value = request.config.option.user
    return user_value


@pytest.fixture(scope="session")
def password(request):
    passwd_value = request.config.option.passwd
    return passwd_value


def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    option_value = metafunc.config.option.amurl
    if "amurl" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("acct_mgt_url", [option_value])
    option_value = metafunc.config.option.user
    metafunc.parametrize("username", [option_value])
    option_value = metafunc.config.option.passwd
    metafunc.parametrize("password", [option_value])
