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
    def __init__(self, status, response):
        self.status_code = status
        self.response = response


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
        module.fail_json(msg="Support for regular users is work in progress...")


from ansible.module_utils.basic import *

main()