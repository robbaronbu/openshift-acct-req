import json
import re
import requests


class openshift(requests.Session):
    baseurl = None

    def __init__(self, url, token, verify, logger):
        super().__init__()

        self.set_verify(verify)
        self.set_token(token)
        self.set_baseurl(url)
        self.set_logger(logger)
        self.set_headers()

    def set_verify(self, verify):
        self.verify = verify

    def set_headers(self):
        self.headers.update({
            'Authorization': f'bearer {self.token}',
            'Content-type': 'application/json',
            'Accept': 'application/json'
        })

    def set_logger(self, logger):
        self.logger = logger

    def set_token(self, token):
        self.token = token

    def set_baseurl(self, url):
        self.baseurl = url

    def cnvt_project_name(self, project_name):
        suggested_project_name = re.sub("^[^A-Za-z0-9]+", "", project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9]+$", "", suggested_project_name)
        suggested_project_name = re.sub("[^A-Za-z0-9-]+", "-", suggested_project_name)
        return suggested_project_name

    def request(self, method, url, **kwargs):
        if '://' not in url:
            url = f'{self.baseurl}{url}'

        return super().request(method, url, **kwargs)

    def project_exists(self, project_name):
        url = f"{self.project_api_endpoint}/{project_name}"
        r = self.get(url)
        return r.status_code == 200 or r.status_code == 201

    def delete_project(self, project_name):
        # check project_name
        url = f"{self.project_api_endpoint}/{project_name}"
        r = self.delete(url)
        return r

    def create_project(self, project_id, project_name, user_name):
        # check project_name
        payload = {
            "kind": "Project",
            "apiVersion": self.project_api_version,
            "metadata": {
                "name": project_id,
                "annotations": {
                    "openshift.io/display-name": project_name,
                    "openshift.io/requester": user_name,
                },
            },
        }
        return self.post(self.project_api_endpoint, data=json.dumps(payload))


class openshift_3_x(openshift):

    project_api_endpoint = "/oapi/v1/projects"
    project_api_version = "v1"


class openshift_4_x(openshift):

    project_api_endpoint = "/apis/project.openshift.io/v1/projects"
    project_api_version = "project.openshift.io/v1"
