#!/usr/local/bin/python
# -*- coding: utf-8 -*-

try:
    import json
except ImportError:
    import simplejson as json

HAS_REQUESTS = True
try:
    import requests
except ImportError:
    HAS_REQUESTS = False


class CouchDBError(Exception):
    def __init__(self, status, response, message=None):
        self.status_code = status
        self.response = response
        self.message = message


class AuthenticationException(Exception):
    def __init__(self, user, message):
        self.user = user
        self.message = message


class CouchDB:
    def __init__(self, host="localhost", port="5984", auth_user=None, auth_password=None):
        self.host = host
        self.port = port
        if auth_user is not None and auth_password is not None:
            self.auth = (auth_user, auth_password)
        else:
            self.auth = None

    def get_auth(self, authenticated):
        return self.auth if authenticated is True else None

    def get_admin_user_config_url(self, username):
        return "http://{0}:{1}/_config/admins/{2}".format(self.host, self.port, username)

    def get_password_hash_of_admin_user(self, username, authenticated=False):
        r = requests.get(url=self.get_admin_user_config_url(username),
                         headers={'Accept': 'application/json'},
                         auth=self.get_auth(authenticated))
        if r.status_code == requests.codes.ok:
            password_hash = r.json()
            return password_hash
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            # Retry with authentication
            return self.get_password_hash_of_admin_user(username, authenticated=True)
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            response_body = r.json()
            raise CouchDBError(r.status_code, response_body)

    def create_or_update_admin_user(self, username, password, raw_password=False, authenticated=False):
        if raw_password:
            params = {"raw": "true"}
            current_password = self.get_password_hash_of_admin_user(username, authenticated)
            if current_password == password:
                return False
        else:
            params = {}

        r = requests.put(url=self.get_admin_user_config_url(username),
                         data='"{0}"'.format(password),
                         headers={'Accept': 'application/json'},
                         params=params,
                         auth=self.get_auth(authenticated))

        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            # Retry with authentication
            return self.create_or_update_admin_user(username, password, raw_password, authenticated=True)
        else:
            raise CouchDBError(r.status_code, r.json())

    def remove_admin_user(self, username):
        r = requests.delete(url=self.get_admin_user_config_url(username),
                            headers={'Accept': 'application/json'},
                            auth=self.auth)

        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        else:
            raise CouchDBError(r.status_code, r.json())

    def get_absolute_url(self, path):
        return "http://{0}:{1}{2}".format(self.host, self.port, path)

    def get_user_url(self, username):
        return self.get_absolute_url("/_users/org.couchdb.user:{2}".format(self.host, self.port, username))

    def get_document(self, database, document_id, authenticated=False):
        url = "http://{0}:{1}/{2}/{3}".format(self.host, self.port, database, document_id)
        r = requests.get(url=url,
                         headers={'Accept': 'application/json'},
                         auth=self.get_auth(authenticated))
        if r.status_code == requests.codes.ok or r.status_code == requests.codes.not_modified:
            return r.json()
        elif r.status_code == requests.codes.not_found:
            return None
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.get_document(database, document_id, authenticated=True)
        else:
            raise CouchDBError(r.status_code, r.json())

    def create_session(self, username, password):
        url = self.get_absolute_url("/_session")
        data = "name={0}&password={1}".format(username, password)
        headers = {
            "Accept": "application/json",
            "Content-Length": len(data),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post(url=url, headers=headers, data=data)
        if r.status_code == requests.codes.ok:
            token = r.headers['set-cookie']
            return token
        elif r.status_code == requests.codes.unauthorized:
            reason = r.json()["reason"]
            raise AuthenticationException(user=username, message=reason)
        else:
            raise CouchDBError(r.status_code, r.json())

    def close_session(self, session_token):
        url = self.get_absolute_url("/_session")
        headers = {"Accept": "application/json"}
        cookies = {"AuthSession": session_token}
        requests.post(url=url, headers=headers, cookies=cookies)

    def create_user(self, username, password, roles=None, authenticated=False):
        if not roles:
            roles = []

        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return False
        except AuthenticationException:
            pass

        document = self.get_document("_users", "org.couchdb.user:{0}".format(username), authenticated)
        if not document:
            document = {}
        document["name"] = username
        document["password"] = password
        document["roles"] = roles
        document["type"] = "user"

        headers = {'Accept': 'application/json', 'X-Couch-Full-Commit': 'true'}

        r = requests.put(url=self.get_user_url(username),
                         json=document,
                         headers=headers,
                         auth=self.get_auth(authenticated))

        if r.status_code in [requests.codes.created, requests.codes.accepted]:
            return True
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.create_user(username, password, roles, authenticated=True)
        else:
            # r.status_code in [
            #   requests.codes.bad_request,
            #   requests.codes.not_found,
            #   requests.codes.conflict
            # ]
            raise CouchDBError(r.status_code, r.json())


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', default="localhost"),
            port=dict(type='int', default=5984),
            name=dict(type='str', required=True),
            password=dict(type='str', required=False, no_log=True),
            raw_password=dict(type='bool', choices=BOOLEANS, default='no'),
            admin=dict(type='bool', choices=BOOLEANS, default='no'),
            state=dict(type='str', default="present", choices=["absent", "present"]),
            force_basic_auth=dict(type='bool', choices=BOOLEANS, default='no'),
            auth_user=dict(type='str', required=False),
            auth_password=dict(type='str', required=False, no_log=True)
        ),
        required_together=[['auth_user', 'auth_password']]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests is not installed")

    host = module.params['host']
    port = module.params['port']
    username = module.params['name']
    password = module.params['password']
    raw_password = module.params['raw_password']
    admin = module.params['admin']
    state = module.params['state']
    force_basic_auth = module.params['force_basic_auth']
    auth_user = module.params['auth_user']
    auth_password = module.params['auth_password']

    couchdb = CouchDB(host, port, auth_user, auth_password)

    if admin is True:
        if state == "present":
            try:
                changed = couchdb.create_or_update_admin_user(username, password, raw_password,
                                                              authenticated=force_basic_auth)
                module.exit_json(changed=changed)
            except CouchDBError as e:
                module.fail_json(msg=e.response["reason"], status_code=e.status_code, response=e.response)
        elif state == "absent":
            try:
                changed = couchdb.remove_admin_user(username)
                module.exit_json(changed=changed)
            except CouchDBError as e:
                module.fail_json(msg=e.response["reason"], status_code=e.status_code, response=e.response)
    else:
        if state == "present":
            try:
                changed = couchdb.create_user(username, password, roles=[], authenticated=True)
                module.exit_json(changed=changed)
            except CouchDBError as e:
                module.fail_json(msg=e.response["reason"], status_code=e.status_code, response=e.response)
        elif state == "absent":
            module.fail_json(msg="Support for regular users is work in progress...")


from ansible.module_utils.basic import *

main()