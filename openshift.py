import kubernetes
import pprint
import logging
import requests
import json
import re
from flask import Flask, redirect, url_for, request, Response

import sys

# application = Flask(__name__)


class openshift:
    headers = None
    verify = False
    url = None

    def __init__(self, url, token, logger):
        self.set_token(token)
        self.set_url(url)
        self.logger = logger

    def set_token(self, token):
        self.headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def set_url(self, url):
        self.url = url

    def get_url(self):
        return self.url

    def cnvt_project_name(self, project_name):
        suggested_project_name = re.sub("^[^A-Za-z0-9]+", "", project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9]+$", "", suggested_project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9\-]+", "-", suggested_project_name)
        return suggested_project_name

    def get_request(self, url, debug=False):
        r = requests.get(url, headers=self.headers, verify=self.verify)
        if debug == True:
            self.logger.info("url: " + url)
            self.logger.info("r: " + str(r.status_code))
            self.logger.info("r: " + r.text)
        return r

    def del_request(self, url, payload, debug=False):
        if payload is None:
            r = requests.delete(url, headers=self.headers, verify=self.verify)
        else:
            r = requests.delete(
                url, headers=self.headers, data=json.dumps(payload), verify=self.verify
            )
        if debug == True:
            self.logger.info("url: " + url)
            if payload is not None:
                self.logger.info("payload:" + json.dumps(payload))
            self.logger.info("r: " + str(r.status_code))
            self.logger.info("r: " + r.text)
        return r

    def post_request(self, url, payload, debug=False):
        r = requests.post(
            url, headers=self.headers, data=json.dumps(payload), verify=False
        )
        if debug == True:
            self.logger.info("url: " + url)
            self.logger.info("payload: " + json.dumps(payload))
            self.logger.info("r: " + str(r.status_code))
            self.logger.info("r: " + r.text)
        return r


class openshift_3_x(openshift):

    # member functions for projects
    def project_exists(self, project_name):
        url = "https://" + self.get_url() + "/oapi/v1/projects/" + project_name
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_project(self, project_name, display_name, user_name):
        # check project_name
        url = "https://" + self.get_url() + "/oapi/v1/projects"
        payload = {
            "kind": "Project",
            "apiVersion": "v1",
            "metadata": {
                "name": project_name,
                "annotations": {
                    "openshift.io/display-name": display_name,
                    "openshift.io/requester": user_name,
                },
            },
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_project(self, project_name):
        # check project_name
        url = "https://" + self.get_url() + "/oapi/v1/projects/" + project_name
        r = self.del_request(url, True)
        return r

    # member functions for users
    def user_exists(self, api_url, user_name):
        url = "https://" + api_url + "/oapi/v1/users/" + user_name
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_user(self, api_url, user_name, full_name):
        url = "https://" + api_url + "/oapi/v1/users"
        payload = {
            "kind": "User",
            "apiVersion": "v1",
            "metadata": {"name": user_name},
            "fullName": full_name,
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_user(self, api_url, user_name, full_name):
        url = "https://" + api_url + "/oapi/v1/users/" + user_name
        r = self.del_request(url, None, True)
        return r

    # member functions for identities
    def identity_exists(self, api_url, id_provider, id_user):
        url = (
            "https://" + api_url + "/oapi/v1/identities/" + id_provider + ":" + id_user
        )
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_identity(self, api_url, id_provider, id_user):
        url = "https://" + api_url + "/oapi/v1/identities"
        payload = {
            "kind": "Identity",
            "apiVersion": "v1",
            "providerName": id_provider,
            "providerUserName": id_user,
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_identity(self, api_url, id_provider, id_user):
        url = "https://" + api_url + "/oapi/v1/identities"
        payload = {
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "providerName": id_provider,
            "providerUserName": id_user,
            "gracePeriodSeconds": "300",
        }
        r = self.del_request(url, payload, True)
        return r

    def useridentitymapping_exists(token, api_url, user_name, id_provider, id_user):
        url = (
            "https://"
            + api_url
            + "/oapi/v1/useridentitymappings/"
            + id_provider
            + ":"
            + id_user
        )
        r = self.get_request(url, True)
        # it is probably not necessary to check the user name in the useridentity
        # mapping
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_useridentitymapping(token, api_url, user_name, id_provider, id_user):
        url = "https://" + api_url + "/oapi/v1/useridentitymappings"
        payload = {
            "kind": "UserIdentityMapping",
            "apiVersion": "v1",
            "user": {"name": user_name},
            "identity": {"name": id_provider + ":" + id_user},
        }
        r = self.post_request(url, payload, True)
        return r

    # member functions to associate roles for users on projects


class openshift_4_x(openshift):

    # member functions for projects
    def project_exists(self, project_name):
        url = (
            "https://"
            + self.get_url()
            + "/apis/project.openshift.io/v1/projects/"
            + project_name
        )
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_project(self, project_name, display_name, user_name):
        # check project_name
        url = "https://" + self.get_url() + "/apis/project.openshift.io/v1/projects/"
        payload = {
            "kind": "Project",
            "apiVersion": "project.openshift.io/v1",
            "metadata": {
                "name": project_name,
                "annotations": {
                    "openshift.io/display-name": display_name,
                    "openshift.io/requester": user_name,
                },
            },
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_project(self, project_name):
        # check project_name
        url = (
            "https://"
            + self.get_url()
            + "/apis/project.openshift.io/v1/projects/"
            + project_name
        )
        r = self.del_request(url, True)
        return r

    # member functions for users
    def user_exists(self, api_url, user_name):
        url = "https://" + api_url + "/apis/user.openshift.io/v1/users" + user_name
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_user(self, api_url, user_name, full_name):
        url = "https://" + api_url + "/apis/user.openshift.io/v1/users"
        payload = {
            "kind": "User",
            "apiVersion": "user.openshift.io/v1",
            "metadata": {"name": user_name},
            "fullName": full_name,
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_user(self, api_url, user_name, full_name):
        url = "https://" + api_url + "/apis/user.openshift.io/v1/users" + user_name
        r = self.del_request(url, None, True)
        return r

    # member functions for identities
    def identity_exists(self, api_url, id_provider, id_user):
        url = (
            "https://"
            + api_url
            + "/apis/user.openshift.io/v1/identities/"
            + id_provider
            + ":"
            + id_user
        )
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_identity(self, api_url, id_provider, id_user):
        url = "https://" + api_url + "/apis/user.openshift.io/v1/identities"
        payload = {
            "kind": "Identity",
            "apiVersion": "v1",
            "providerName": id_provider,
            "providerUserName": id_user,
        }
        r = self.post_request(url, payload, True)
        return r

    def delete_identity(self, api_url, id_provider, id_user):
        url = (
            "https://"
            + api_url
            + "/apis/user.openshift.io/v1/identities/"
            + id_provider
            + ":"
            + id_user
        )
        payload = {
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "providerName": id_provider,
            "providerUserName": id_user,
            "gracePeriodSeconds": "300",
        }
        r = self.del_request(url, payload, True)
        return r

    def useridentitymapping_exists(token, api_url, user_name, id_provider, id_user):
        url = (
            "https://"
            + api_url
            + "/apis/user.openshift.io/v1/useridentitymappings/"
            + id_provider
            + ":"
            + id_user
        )
        r = self.get_request(url, True)
        # it is probably not necessary to check the user name in the useridentity
        # mapping
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def create_useridentitymapping(token, api_url, user_name, id_provider, id_user):
        url = "https://" + api_url + "/apis/user.openshift.io/v1/useridentitymappings"
        payload = {
            "kind": "UserIdentityMapping",
            "apiVersion": "v1",
            "user": {"name": user_name},
            "identity": {"name": id_provider + ":" + id_user},
        }
        r = self.post_request(url, payload, True)
        return r

    # member functions to associate roles for users on projects
