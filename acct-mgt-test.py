#!/usr/bin/python3
# python3 -m pytest acct-mgt-test.py --amurl [acct_mgt_url] --user [username] --passwd [password]
#
# Note, to do this from apple OSX
#    1) convert the cert and key to a p12 file
#       via: openssl pkcs12 -export -in ./<client_cert> -inkey ./<client_key> -out client.p12
#       openssl pkcs12 -export -in ./acct-mgt-2.crt -inkey ./acct-mgt-2.key -out acct-mgt-2.p12
#
#    2) call curl with
#       curl -v -k -E ./client.p12:password http://url...
#
#    3) auth_opts can be of the following:
#
#          auth_ops = ["-E","./client_cert/acct-mgt-2.crt", "-key", "./client_cert/acct-mgt-2.key"]
#          auth_ops = ["-cert", r"acct-mgt-2",]
#
# Initial test to confirm that something is working
#    curl -kv https://acct-mgt.apps.cnv.massopen.cloud/projects/acct-mgt
#
#  python3 -m pytest acct-mgt-test.py --amurl https://acct-mgt.apps.cnv.massopen.cloud --basic [username]:[password]
#
#  --Only for testing:
#      python3 -m pytest acct-mgt-test.py --amurl http://am2.apps.cnv.massopen.cloud
#
#
import subprocess
import re
import time
import pytest
import pytest_check as check


def get_pod_status(project, pod_name):
    result = subprocess.run(
        ["oc", "-n", project, "-o", "json", "get", "pod", pod_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode == 0:
        result_json = json.loads(result.stdout.decode("utf-8"))
        print(result_json["status"]["phase"])
        return result_json["status"]["phase"]
    print("None")
    return None


# pass in the following parameter:
#   project,pod_name: identify the pod
#   statuses: the array of statuses to wait for
def wait_while(project, pod_name, statuses, time_out=300):
    time_left = time_out
    time_interval = 5
    time.sleep(time_interval)
    status = get_pod_status(project, pod_name)
    while status in statuses and time_left > 0:
        time.sleep(time_interval)
        time_left = time_left - time_interval
        status = get_pod_status(project, pod_name)

    if status in statuses:
        return False
    return True


def user(user_name, op, success_pattern):
    if op == "check":
        url_op = "GET"
    elif op == "add":
        url_op = "PUT"
    elif op == "del":
        url_op = "DELETE"

    # result = subprocess.run(
    #    ["curl", "-X", op, "-v", "-E","./client_cert/acct-mgt-2.crt", "-key", "./client_cert/acct-mgt-2.key", url + "/users/" + user_name],
    #    stdout=subprocess.PIPE,
    #    stderr=subprocess.STDOUT,
    # )
    result = subprocess.run(
        # ["curl", "-X", op, "-kv", "-cert", r"acct-mgt-2", url + "/users/" + user_name],
        ["curl", "-X", op, "-kv", "-cert", r"acct-mgt-2", url + "/users/" + user_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def compare_results(result, pattern):
    if result is not None:
        p1 = re.compile(pattern)
        lines = result.stdout.decode("utf-8").split("\n")
        cnt = 0
        for l in lines:
            if p1.match(l):
                return True
    return False


def oc_resource_exist(resource, kind, name, project=None):
    result = None
    if project is None:
        result = subprocess.run(
            ["oc", "get", resource, name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    else:
        result = subprocess.run(
            ["oc", "-o", "json", "-n", project, "get", resource, name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    if result.returncode == 0:
        result_json = json.loads(result.stdout.decode("utf-8"))
        if result_json["kind"] == kind and result_json["metadata"]["name"] == name:
            return True
    return False


def ms_check_project(acct_mgt_url, username, password, project_name, auth_opts=[]):
    # result = subprocess.run(
    #    ["curl", "-X", "GET", "-v", "-E","./client_cert/acct-mgt-2.crt", "-key", "./client_cert/acct-mgt-2.key", acct_mgt_url + "/projects/" + project_name],
    #    stdout=subprocess.PIPE,
    #    stderr=subprocess.STDOUT,
    # )
    cmd = (
        ["curl", "-X", "GET", "-kv"]
        + auth_ops
        + [acct_mgt_url + "/projects/" + project_name]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    # {"msg": "project exists (test-001)"}
    # print("\n\n***** result: "+result.stdout.decode('utf-8') +"\n\n")
    return compare_results(
        result, r'{"msg": "project exists \(' + project_name + r'\)"}'
    )


# expect this to be called with
#  project_uuid="1234-1234-1234-1234"
#  displayNameStr=None | '{"displayName":"project_name"}' | '{"funkyName":"project_name"}'
def ms_create_project(
    acct_mgt_url, username, password, project_uuid, displayNameStr, auth_opts=[]
):
    if displayNameStr is None:
        cmd = (
            ["curl", "-X", "PUT", "-kv",]
            + auth_opts
            + [acct_mgt_url + "/projects/" + project_uuid]
        )
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    else:
        cmd = (
            ["curl", "-X", "PUT", "-kv", "-d", displayNameStr,]
            + auth_opts
            + [acct_mgt_url + "/projects/" + project_uuid]
        )
        result = subprocess.run(cnd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    return compare_results(
        result, r'{"msg": "project created \(' + project_uuid + r'\)"}'
    )


def ms_delete_project(acct_mgt_url, username, password, project_name, auth_opts=[]):
    cmd = (
        ["curl", "-X", "DELETE", "-kv"]
        + auth_opts
        + [acct_mgt_url + "/projects/" + project_name]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    return compare_results(
        result, r'{"msg": "project deleted \(' + project_name + r'\)"}'
    )


def ms_check_user(acct_mgt_url, username, password, user_name, auth_opts=[]):
    cmd = (
        ["curl", "-X", "GET", "-v", "-E"]
        + auth_opts
        + [acct_mgt_url + "/users/" + user_name]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    return compare_results(result, r'{"msg": "user \(' + user_name + r'\) exists"}')


def ms_create_user(acct_mgt_url, username, password, user_name, auth_opts=[]):

    result = subprocess.run(
        ["curl", "-X", "PUT", "-kv", acct_mgt_url + "/users/" + user_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return compare_results(result, r'{"msg": "user created \(' + user_name + r'\)"}')


def ms_delete_user(acct_mgt_url, username, password, user_name, auth_opts=[]):
    cmd = (
        ["curl", "-X", "DELETE", "-v"]
        + auth_opts
        + [acct_mgt_url + "/users/" + user_name]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    return compare_results(result, r'{"msg": "user deleted \(' + user_name + r'\)"}')


def ms_user_project_get_role(
    acct_mgt_url,
    username,
    basci_auth,
    cert,
    project_name,
    role,
    success_pattern,
    auth_opts=[],
):
    cmd = (
        ["curl", "-X", "GET", "-v",]
        + auth_opts
        + [
            acct_mgt_url
            + "/users/"
            + user_name
            + "/projects/"
            + project_name
            + "/roles/"
            + role
        ]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    print("get role --> result: " + result.stdout.decode("utf-8") + "\n\n")
    return compare_results(result, success_pattern)


def ms_user_project_add_role(
    acct_mgt_url, user_name, project_name, role, success_pattern, auth_opts=[]
):
    cmd = (
        ["curl", "-X", "PUT", "-v"]
        + auth_opts
        + [
            acct_mgt_url
            + "/users/"
            + user_name
            + "/projects/"
            + project_name
            + "/roles/"
            + role
        ]
    )
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
    print("add role --> result: " + result.stdout.decode("utf-8") + "\n\n")
    return compare_results(result, success_pattern)


def ms_user_project_remove_role(
    acct_mgt_url, user_name, project_name, role, success_pattern, auth_opts=[]
):
    up = basic_auth.split(":")
    username = up[0]
    password = up[1]  # result = subprocess.run(
    cmd = (
        ["curl", "-X", "DELETE", "-v"]
        + auth_opts
        + [
            acct_mgt_url
            + "/users/"
            + user_name
            + "/projects/"
            + project_name
            + "/roles/"
            + role
        ]
    )
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )  # print("--> result: "+result.stdout.decode('utf-8') +"\n\n")
    return compare_results(result, success_pattern)


def test_project(acct_mgt_url, basic_auth, cert):
    up = basic_auth.split(":")
    username = up[0]
    password = up[1]
    result = 0
    # if(oc_resource_exist("project", "test-001",'test-001[ \t]*test-001[ \t]','Error from server (NotFound): namespaces "test-001" not found')):
    #    print("Error: test_project failed as a project with a name of test-001 exists.  Please delete first and rerun the tests\n")
    #    assertTrue(False)

    # test if project doesn't exist
    check.is_false(
        ms_check_project(acct_mgt_url, username, password, "test-001"),
        "Project exists (test-001)",
    )

    # test project creation
    if not oc_resource_exist(
        "project",
        "test-001",
        r"test-001[ \t]*test-001[ \t]",
        'Error from server (NotFound): namespaces "test-001" not found',
    ):
        check.is_true(
            ms_create_project(
                acct_mgt_url,
                username,
                password,
                "test-001",
                r'{"displayName":"test-001"}',
            ),
            "Project (test-001) not created",
        )
        wait_until_done(
            "oc get project test-001", r"test-001[ \t]+test-001[ \t]+Active"
        )
    check.is_true(
        oc_resource_exist(
            "project",
            "test-001",
            r"test-001[ \t]+test-001[ \t]+Active",
            r'Error from server (NotFound): namespaces "test-001" not found',
        ),
        "Project (test-001) not created",
    )
    check.is_true(
        ms_check_project(acct_mgt_url, username, password, "test-001"),
        "project test-001 was not found",
    )

    # test creation of a second project with the same name
    if oc_resource_exist(
        "project",
        "test-001",
        r"test-001[ \t]*test-001[ \t]",
        r'Error from server (NotFound): namespaces "test-001" not found',
    ):
        check.is_false(
            ms_create_project(
                acct_mgt_url,
                username,
                password,
                "test-001",
                r'{"displayName":"test-001"}',
            ),
            "Project (test-001) was already created",
        )
    check.is_true(
        oc_resource_exist(
            "project",
            "test-001",
            r"test-001[ \t]*test-001[ \t]",
            r'Error from server (NotFound): namespaces "test-001" not found',
        ),
        "Project test-001 was not found",
    )

    # test project deletion
    if oc_resource_exist(
        "project",
        "test-001",
        "test-001[ \t]*test-001[ \t]",
        'Error from server (NotFound): namespaces "test-001" not found',
    ):
        check.is_true(
            ms_delete_project(acct_mgt_url, username, password, "test-001"),
            "Unable to delete project (test-001)",
        )
        # Wait until test-001 is terminated
        wait_until_done(
            "oc get project test-001",
            r'Error from server (NotFound): namespaces "test-001" not found',
        )
    check.is_false(
        oc_resource_exist(
            "project",
            "test-001",
            r"test-001[ \t]*test-001[ \t]",
            r'Error from server (NotFound): namespaces "test-001" not found',
        ),
        "Project test-001 exists and it shouldn't",
    )

    # test deleting a project that was deleted
    if not oc_resource_exist(
        "project",
        "test-001",
        "test-001[ \t]*test-001[ \t]",
        'Error from server (NotFound): namespaces "test-001" not found',
    ):
        check.is_false(
            ms_delete_project(acct_mgt_url, username, password, "test-001"),
            "shouldn't be able to delete a non-existing project",
        )
    check.is_false(
        oc_resource_exist(
            "project",
            "test-001",
            r"test-001[ \t]*test-001[ \t]",
            r'Error from server (NotFound): namespaces "test-001" not found',
        ),
        "Project test-001 exists and it should not",
    )

    # these tests are primarily done to ensure that the microserver doesn't crash
    #    When the "displayName" is not present, or the json doesn't exist, the displayName shall default to the project_uuid (first parameter)
    check.is_true(
        ms_create_project(
            acct_mgt_url,
            username,
            password,
            "1234-1234-1234-1234",
            r'{"displayName":"test-001"}',
        ),
        "Project (1234-1234-1234-1234) not created",
    )
    ms_delete_project(acct_mgt_url, username, password, "1234-1234-1234-1234")
    check.is_true(
        ms_create_project(
            acct_mgt_url,
            username,
            password,
            "2234-1234-1234-1234",
            r'{"displaName":"test-001"}',
        ),
        "Project (2234-1234-1234-1234) not created",
    )
    ms_delete_project(acct_mgt_url, username, password, "2234-1234-1234-1234")
    check.is_true(
        ms_create_project(
            acct_mgt_url, username, password, "3234-1234-1234-1234", r"{}"
        ),
        "Project (3234-1234-1234-1234) not created",
    )
    ms_delete_project(acct_mgt_url, username, password, "3234-1234-1234-1234")
    check.is_true(
        ms_create_project(
            acct_mgt_url, username, password, "4234-1234-1234-1234", None
        ),
        "Project (4234-1234-1234-1234) not created",
    )
    ms_delete_project(acct_mgt_url, username, password, "4234-1234-1234-1234")


def test_user(acct_mgt_url, basic_auth, cert):
    # if(oc_resource_exist("user", "test01",r'test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01',r'Error from server (NotFound): users.user.openshift.io "test01" not found')):
    #    print("Error: test_user failed as a user with a name of test01 exists.  Please delete first and rerun the tests\n")
    #    assertTrue(False)

    check.is_false(
        ms_check_user(acct_mgt_url, username, password, "test01"),
        "User test01 exists but it shouldn't exist at this point",
    )

    # test user creation
    # test01                    bfd6dab5-11f3-11ea-89a6-fa163e2bb38b                         sso_auth:test01
    if not oc_resource_exist(
        "user",
        "test01",
        r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
        r'Error from server \(NotFound\): users.user.openshift.io "test01" not found',
    ):
        check.is_true(
            ms_create_user(acct_mgt_url, username, password, "test01"),
            "unable to create test01",
        )
    check.is_true(
        oc_resource_exist(
            "user", "test01", r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01", ""
        ),
        "user test01 doesn't exist",
    )
    check.is_true(
        ms_check_user(acct_mgt_url, username, password, "test01"),
        "User test01 doesn't exist but it should",
    )

    # test creation of a second user with the same name
    if oc_resource_exist(
        "user",
        "test01",
        r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
        r'Error from server \(NotFound\): users.user.openshift.io "test01" not found',
    ):
        check.is_false(
            ms_create_user(acct_mgt_url, username, password, "test01"),
            "Should have failed to create a second user with the username of test01",
        )
    check.is_true(
        oc_resource_exist(
            "user", "test01", r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01", ""
        ),
        "user test01 doesn't exist",
    )

    # test user deletion
    if oc_resource_exist(
        "user",
        "test01",
        r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
        r'Error from server (NotFound): users.user.openshift.io "test01" not found',
    ):
        check.is_true(
            ms_delete_user(acct_mgt_url, username, password, "test01"),
            "user test01 deleted",
        )
    check.is_false(
        oc_resource_exist(
            "user",
            "test01",
            r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
            r'Error from server \(NotFound\): users.user.openshift.io "test01" not found',
        ),
        "user test01 not found",
    )

    # test deleting a user that was deleted
    if not oc_resource_exist(
        "user",
        "test01",
        r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
        r'Error from server (NotFound): users.user.openshift.io "test01" not found',
    ):
        check.is_false(
            ms_delete_user(acct_mgt_url, username, password, "test01"),
            "shouldn't be able to delete non-existing user test01",
        )
    check.is_false(
        oc_resource_exist(
            "user",
            "test01",
            r"test01[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test01",
            r'Error from server \(NotFound\): users.user.openshift.io "test01" not found',
        ),
        "user test01 not found",
    )
    check.is_false(
        ms_check_user(acct_mgt_url, username, password, "test01"),
        "User test01 exists but it shouldn't exist at this point",
    )


def test_project_user_role(acct_mgt_url, basic_auth, cert):
    up = basic_auth.split(":")
    username = up[0]
    password = up[1]
    # Create a project
    if not oc_resource_exist(
        "project",
        "test-002",
        r"test-002[ \t]*test-002[ \t]",
        r'Error from server \(NotFound\): namespaces "test-002" not found',
    ):
        check.is_true(
            ms_create_project(
                acct_mgt_url,
                username,
                password,
                "test-002",
                '{"displayName":"test-002"}',
            ),
            "Project (test-002) was unable to be created",
        )
    check.is_true(
        oc_resource_exist(
            "project",
            "test-002",
            r"test-002[ \t]*test-002[ \t]",
            r'Error from server \(NotFound\): namespaces "test-002" not found',
        ),
        "Project (test-002) does not exist",
    )

    # Create some users test02 - test-05
    for x in range(2, 6):
        if not oc_resource_exist(
            "user",
            "test0" + str(x),
            "test0" + str(x) + r"[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test0" + str(x),
            r'Error from server (NotFound): users.user.openshift.io "test0'
            + str(x)
            + '" not found',
        ):
            check.is_true(
                ms_create_user(acct_mgt_url, username, password, "test0" + str(x)),
                "Unable to create user " + "test0" + str(x),
            )
        check.is_true(
            oc_resource_exist(
                "user",
                "test0" + str(x),
                "test0" + str(x) + r"[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test0" + str(x),
                r'Error from server (NotFound): users.user.openshift.io "test0'
                + str(x)
                + r'" not found',
            ),
            "user test0" + str(x) + " not found",
        )

    # now bind an admin role to the user
    check.is_false(
        ms_user_project_get_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "user role exists \(test-002,test02,admin\)"}',
        )
    )
    check.is_true(
        ms_user_project_add_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "rolebinding created \(test02,test-002,admin\)"}',
        ),
        "Role unable to be added",
    )
    check.is_true(
        oc_resource_exist(
            "rolebindings", "admin", "^admin[ \t]*/admin[ \t]*test02", "", "test-002"
        ),
        "role does not exist",
    )
    check.is_true(
        ms_user_project_get_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "user role exists \(test-002,test02,admin\)"}',
        )
    )

    check.is_true(
        ms_user_project_add_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "rolebinding already exists - unable to add \(test02,test-002,admin\)"}',
        ),
        "Added the same role to a user failed as it should",
    )

    check.is_true(
        ms_user_project_remove_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "removed role from user on project"}',
        ),
        "Removed rolebinding successful",
    )
    check.is_false(
        oc_resource_exist(
            "rolebindings", "admin", r"^admin[ \t]*/admin[ \t]*test02", r"", "test-002"
        ),
        "Rolebinding does not exit",
    )

    check.is_true(
        ms_user_project_remove_role(
            acct_mgt_url,
            username,
            password,
            "test02",
            "test-002",
            "admin",
            r'{"msg": "rolebinding does not exist - unable to delete \(test02,test-002,admin\)"}',
        ),
        "Unable to remove non-existing rolebinding",
    )

    # Clean up by removing the users and project (test-002)
    check.is_true(
        ms_delete_project(acct_mgt_url, username, password, "test-002") == True,
        "project (test-002) deleted",
    )
    for x in range(2, 6):
        if oc_resource_exist(
            "user",
            "test0" + str(x),
            "test0" + str(x) + r"[ \t]*[a-f0-9\-]*[ \t]*sso_auth:test0" + str(x),
            r'Error from server (NotFound): users.user.openshift.io "test0'
            + str(x)
            + '" not found',
        ):
            check.is_true(
                ms_delete_user(acct_mgt_url, username, password, "test0" + str(x))
                == True,
                "user " + "test0" + str(x) + "unable to be deleted",
            )


# def test_quota(self):
