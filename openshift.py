import kubernetes
import pprint
import logging
import requests
import json
import re
from flask import Flask, redirect, url_for, request, Response

import sys

#application = Flask(__name__)

class openshift:
    headers = None
    verify = False
    url = None
        
    def __init__(self,url,token,logger):
        self.set_token(token)
        self.set_url(url)
        self.logger=logger

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
    
    def cnvt_project_name(project_name):
        suggested_project_name = re.sub("^[^A-Za-z0-9]+", "", project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9]+$", "", suggested_project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9\-]+", "-", suggested_project_name)
        return suggested_project_name
    
    def get_request(self, url, debug=False):
        r = requests.get(url, headers=self.headers, verify=self.verify)
        #        if debug == True:
        self.logger.info("url: " + url)
        self.logger.info("r: " + str(r.status_code))
        self.logger.info("r: " + r.text)
        return r

    def del_request(self, url, debug=False):
        r = requests.delete(url, headers=self.headers, verify=self.verify)
        if debug == True:
            self.logger.info("url: " + url)
            self.logger.info("r: " + str(r.status_code))
            self.logger.info("r: " + r.text)
        return r

    def post_request(self, url, payload, debug=False):
        r = requests.post(url, headers=self.headers, data=json.dumps(payload), verify=False)
        if debug==True:
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

    def delete_project(self, project_name):
        # check project_name
        url = "https://" + self.get_url() + "/oapi/v1/projects/" + project_name
        r = self.del_request(url, True)
        return r

    def create_project(self, project_name, user_name):
        # check project_name
        url = "https://" + self.get_url() + "/oapi/v1/projects"
        payload = {
            "kind": "Project",
            "apiVersion": "v1",
            "metadata": {
                "name": project_uuid,
                "annotations": {
                    "openshift.io/display-name": project_name,
                    "openshift.io/requester": user_name,
                },
            },
        }
        r = self.post_request(url, json.dumps(payload))
        return r

    # member functions for users

    # member functions to associate roles for users on projects

class openshift_4_x(openshift):

    # member functions for projects
    def project_exists(self, project_name):
        url = "https://" + self.get_url() + "/apis/project.openshift.io/v1/projects/" + project_name
        r = self.get_request(url, True)
        if r.status_code == 200 or r.status_code == 201:
            return True
        return False

    def delete_project(self, project_name):
        # check project_name
        url = "https://" + self.get_url() + "/apis/project.openshift.io/v1/projects/" + project_name
        r = self.del_request(url, True)
        return r

    def create_project(self, short_name, project_name, user_name):
        # check project_name
        url = "https://" + self.get_url() + "/apis/project.openshift.io/v1/projects/"
        payload = {
            "kind": "Project",
            "apiVersion": "v1",
            "metadata": {
                "name": short_name,
                "annotations": {
                    "openshift.io/display-name": project_name,
                    "openshift.io/requester": user_name,
                },
            },
        }
        r = self.post_request(url, json.dumps(payload), True)
        return r

    # member functions for users

    # member functions to associate roles for users on projects
   