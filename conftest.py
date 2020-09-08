import pytest


def pytest_addoption(parser):
    parser.addoption("--amurl", action="store")
    parser.addoption("--basic", action="store")
    parser.addoption("--cert", action="store")


@pytest.fixture(scope="session")
def acct_mgt_url(request):
    amurl_value = request.config.option.amurl
    if amurl_value is None:
        pytest.skip()
    return amurl_value


@pytest.fixture(scope="session")
def basic_auth(request):
    user_passwd = request.config.option.basic
    return user_passwd


@pytest.fixture(scope="session")
def password(request):
    cert_value = request.config.option.cert
    return cert_value


def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    option_value = metafunc.config.option.amurl
    if "amurl" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("acct_mgt_url", [option_value])
    option_value = metafunc.config.option.user_passwd
    metafunc.parametrize("username", [option_value])
    metafunc.parametrize("password", [option_value])
    option_value = metafunc.config.option.cert
    metafunc.parametrize("cert", [option_value])
