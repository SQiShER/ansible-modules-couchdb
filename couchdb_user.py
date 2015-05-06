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


class CouchDBException(Exception):
    def __init__(self, status_code, error_type="unknown", reason=None, response=None):
        self.status_code = status_code
        self.error_type = error_type
        self.reason = reason
        self.response = response


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

    def get_absolute_url(self, path):
        return "http://{0}:{1}{2}".format(self.host, self.port, path)

    @staticmethod
    def create_exception(r):
        status_code = r.status_code
        if r.headers['content-type'] == 'application/json':
            response_body = r.json()
            error_type = response_body['error']
            reason = response_body['reason']
            return CouchDBException(status_code, reason=reason, error_type=error_type)
        else:
            response_body = r.text
            return CouchDBException(status_code, reason=response_body)

    def create_session(self, username, password):
        url = self.get_absolute_url("/_session")
        data = "name={0}&password={1}".format(username, password)
        headers = {
            "Accept": "application/json",
            "Content-Length": len(data),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post(url, headers=headers, data=data)
        if r.status_code == requests.codes.ok:
            token = r.headers['set-cookie']
            return token
        elif r.status_code == requests.codes.unauthorized:
            reason = r.json()["reason"]
            raise AuthenticationException(user=username, message=reason)
        else:
            raise self.create_exception(r)

    def close_session(self, session_token):
        url = self.get_absolute_url("/_session")
        headers = {"Accept": "application/json"}
        cookies = {"AuthSession": session_token}
        requests.post(url, headers=headers, cookies=cookies)

    def get_auth(self, authenticated):
        return self.auth if authenticated is True else None

    def get_password_hash_of_admin_user(self, username, authenticated=False):
        url = self.get_absolute_url("/_config/admins/{0}".format(username))
        headers = {"Accept": "application/json"}
        auth = self.get_auth(authenticated)
        r = requests.get(url, headers=headers, auth=auth)
        if r.status_code == requests.codes.ok:
            password_hash = r.json()
            return password_hash
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.get_password_hash_of_admin_user(username, authenticated=True)
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            raise self.create_exception(r)

    def create_or_update_admin_user(self, username, password, raw_password=False, authenticated=False):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return False
        except AuthenticationException:
            pass

        if raw_password and self.get_password_hash_of_admin_user(username, authenticated) == password:
            return False

        url = self.get_absolute_url("/_config/admins/{0}".format(username))
        data = '"{0}"'.format(password)
        headers = {"Accept": "application/json"}
        params = {"raw": "true"} if raw_password else {}
        auth = self.get_auth(authenticated)
        r = requests.put(url, data=data, headers=headers, params=params, auth=auth)
        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.create_or_update_admin_user(username, password, raw_password, authenticated=True)
        else:
            raise self.create_exception(r)

    def remove_admin_user(self, username, authenticated=False):
        url = self.get_absolute_url("/_config/admins/{0}".format(username))
        headers = {"Accept": "application/json"}
        auth = self.get_auth(authenticated)
        r = requests.delete(url, headers=headers, auth=auth)
        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.remove_admin_user(username, authenticated=True)
        else:
            raise self.create_exception(r)

    def get_document(self, database, document_id, authenticated=False):
        url = self.get_absolute_url("/{0}/{1}").format(database, document_id)
        headers = {"Accept": "application/json"}
        auth = self.get_auth(authenticated)
        r = requests.get(url, headers=headers, auth=auth)
        if r.status_code == requests.codes.ok or r.status_code == requests.codes.not_modified:
            return r.json()
        elif r.status_code == requests.codes.not_found:
            return None
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.get_document(database, document_id, authenticated=True)
        else:
            raise self.create_exception(r)

    def remove_user(self, username, authenticated=False):
        url = self.get_user_url(username)
        headers = {"Accept": "application/json"}
        auth = self.get_auth(authenticated)
        r = requests.delete(url, headers=headers, auth=auth)
        if r.status_code in [requests.codes.ok, requests.codes.accepted]:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.remove_user(username, authenticated=True)
        else:
            raise self.create_exception(r)

    def get_user_url(self, username):
        return self.get_absolute_url("/_users/org.couchdb.user:{2}".format(self.host, self.port, username))

    def _can_authenticate(self, username, password):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return True
        except AuthenticationException:
            return False

    def create_or_update_user(self, username, password, roles=None, authenticated=False):
        if not roles:
            roles = []
        password_requires_update = not self._can_authenticate(username, password)
        document = self.get_document("_users", "org.couchdb.user:{0}".format(username), authenticated)

        has_changes = False
        if not document:
            document = {}
        if document["name"] != username:
            document["name"] = username
            has_changes = True
        if password_requires_update:
            document["password"] = password
            has_changes = True
        if document["roles"] != roles:
            document["roles"] = roles
            has_changes = True
        document["type"] = "user"

        if not has_changes:
            return False

        headers = {
            "Accept": "application/json",
            "X-Couch-Full-Commit": "true"
        }
        r = requests.put(url=self.get_user_url(username),
                         json=document,
                         headers=headers,
                         auth=self.get_auth(authenticated))
        if r.status_code in [requests.codes.created, requests.codes.accepted]:
            return True
        elif r.status_code == requests.codes.unauthorized and not authenticated:
            return self.create_or_update_user(username, password, roles, authenticated=True)
        else:
            raise self.create_exception(r)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', default="localhost"),
            port=dict(type='int', default=5984),
            name=dict(type='str', required=True),
            password=dict(type='str', required=False, no_log=True),
            raw_password=dict(type='bool', choices=BOOLEANS, default='no'),
            admin=dict(type='bool', choices=BOOLEANS, default='no'),
            roles=dict(type='list', default=None),
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
    roles = module.params['roles']
    state = module.params['state']
    force_basic_auth = module.params['force_basic_auth']
    auth_user = module.params['auth_user']
    auth_password = module.params['auth_password']

    couchdb = CouchDB(host, port, auth_user, auth_password)

    try:
        changed = False
        if admin is True:
            if state == "present":
                changed = couchdb.create_or_update_admin_user(username, password, raw_password, force_basic_auth)
            elif state == "absent":
                changed = couchdb.remove_admin_user(username)
        else:
            if state == "present":
                changed = couchdb.create_or_update_user(username, password, roles=roles, authenticated=True)
            elif state == "absent":
                changed = couchdb.remove_user(username, authenticated=True)
        module.exit_json(changed=changed)
    except CouchDBException as e:
        module.fail_json(msg=e.reason, status_code=e.status_code, error=e.error_type)


from ansible.module_utils.basic import *

main()