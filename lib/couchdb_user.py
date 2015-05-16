#!/usr/bin/env python

# (c) 2015, Daniel Bechler <daniel@bechler.io>
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

DOCUMENTATION = '''
---
module: couchdb_user
short_description: Adds, changes or removes a user from a CouchDB database.
description:
    - Adds, changes or removes a user from a CouchDB database.
options:
    name:
        description:
            - The name of the user
        required: true
    host:
        description:
            - The host running the database
        required: false
        default: localhost
    port:
        description:
            - The port to connect to
        required: false
        default: 5984
    password:
        description:
            - The password of the user
        required: false
    raw_password:
        description:
            - Indicates whether the password is already salted and hashed
        required: false
        choices: [ "yes", "no" ]
        default: "no"
    admin:
        description:
            - Indicates whether the targeted user is admin or not
        required: false
        choices: [ "yes", "no" ]
        default: "no"
    roles:
        description:
            - The roles of the user
        required: false
        default: []
    state:
        description:
            - The database user state. If set to `absent` a `login_user` and `login_password` must be provided.
        required: false
        default: present
        choices: [ "present", "absent" ]
    login_user:
        description:
            - The username used to authenticate with
        required: false
    login_password:
        description:
            - The password used to authenticate with
        required: false
    authentication_db:
        description:
            - The name of the database in which the user accounts are stored
        required: false
        default: "_users"
version_added: 1.9
requirements: [ "requests" ]
notes:
    - This modules requires the CouchDB cookie authentication handler to be enabled.
author: Daniel Bechler
'''

EXAMPLES = '''
---
# Example
    - foo
'''

try:
    import json
except ImportError:
    import simplejson as json

HAS_REQUESTS = True
try:
    import requests
    from requests.auth import AuthBase
except ImportError:
    HAS_REQUESTS = False


class CouchDBException(Exception):
    def __init__(self, status_code, error_type="unknown", reason=None, origin=None):
        self.status_code = status_code
        self.error_type = error_type
        self.reason = reason
        self.origin = origin


class AuthenticationException(Exception):
    def __init__(self, user, message):
        self.user = user
        self.message = message


class HTTPCookieAuth(AuthBase):
    def __init__(self, session_token):
        self.session_token = session_token

    def __call__(self, r):
        r.headers['Cookies'] = None
        r.prepare_cookies({
            "AuthSession": self.session_token
        })
        return r


class CouchDBClient:
    def __init__(self, host="localhost", port="5984", login_user=None, login_password=None, authentication_db="_users"):
        self._auth = None
        self.host = host
        self.port = port
        self.login_user = login_user
        self.login_password = login_password
        self.authentication_db = authentication_db

    def login(self):
        self._auth = None
        if self.login_user:
            try:
                session = self.create_session(self.login_user, self.login_password)
                self._auth = HTTPCookieAuth(session)
            except AuthenticationException:
                pass

    def logout(self):
        if self._auth:
            session_token = self._auth.session_token
            try:
                self.close_session(session_token)
            finally:
                self._auth = None

    def is_admin_party(self):
        try:
            admins = self._get_config_value("admins")
            return admins is None
        except CouchDBException as e:
            if e.status_code in [requests.codes.unauthorized, requests.codes.forbidden]:
                return False
            else:
                raise e

    def create_session(self, username, password):
        url = self._get_absolute_url("/_session")
        data = "name={0}&password={1}".format(username, password)
        headers = {
            "Accept": "application/json",
            "Content-Length": len(data),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post(url, headers=headers, data=data)
        if r.status_code == requests.codes.ok:
            auth_session = r.cookies.get("AuthSession")
            return auth_session
        elif r.status_code == requests.codes.unauthorized:
            reason = r.json()["reason"]
            raise AuthenticationException(user=username, message=reason)
        else:
            raise self._create_exception(r)

    def close_session(self, session_token):
        url = self._get_absolute_url("/_session")
        requests.post(url, **{
            "headers": {"Accept": "application/json"},
            "cookies": {"AuthSession": session_token}
        })

    def create_or_update_admin_user(self, username, password, raw_password=False):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return False
        except AuthenticationException:
            pass
        if raw_password and self._get_config_value("admins", username) == password:
            return False
        return self._set_config_value("admins", username, '"{0}"'.format(password), raw=raw_password)

    def remove_admin_user(self, username):
        url = self._get_absolute_url("/_config/admins/{0}".format(username))
        headers = {"Accept": "application/json"}
        r = requests.delete(url, headers=headers, auth=self._auth)
        if r.status_code == requests.codes.ok:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        else:
            raise self._create_exception(r)

    def create_or_update_user(self, username, password, raw_password=False, roles=None):
        if not roles:
            roles = []

        has_changes = False
        document = self.get_document(self.authentication_db, "org.couchdb.user:{0}".format(username))
        if not document:
            document = {}
            has_changes = True

        if raw_password:
            password_scheme_and_derived_key, salt, iterations = password.split(",", 3)
            password_scheme, derived_key = password_scheme_and_derived_key[1:].split("-")
            original_data = [
                document.get("password_scheme"),
                document.get("derived_key"),
                document.get("salt"),
                int(document.get("iterations"))
            ]
            desired_data = [password_scheme, derived_key, salt, int(iterations)]
            if original_data != desired_data:
                document["password_scheme"] = password_scheme
                document["derived_key"] = derived_key
                document["salt"] = salt
                document["iterations"] = int(iterations)
                document.pop("password", None)
                has_changes = True
        elif not self._can_authenticate(username, password):
            document["password"] = password
            document.pop("password_scheme", None)
            document.pop("derived_key", None)
            document.pop("salt", None)
            document.pop("iterations", None)
            has_changes = True

        if document.get("name") != username:
            document["name"] = username
            has_changes = True
        if document.get("roles") != roles:
            document["roles"] = roles
            has_changes = True
        document["type"] = "user"

        if not has_changes:
            return False

        headers = {
            "Accept": "application/json",
            "X-Couch-Full-Commit": "true",
            "If-Match": document.get("_rev")
        }
        r = requests.put(url=self._get_user_url(username),
                         data=json.dumps(document),
                         headers=headers,
                         auth=self._auth)
        if r.status_code in [requests.codes.created, requests.codes.accepted]:
            return True
        else:
            raise self._create_exception(r)

    def remove_user(self, username):
        user = self.get_document(self.authentication_db, "org.couchdb.user:{0}".format(username))
        if user is None:
            return False
        url = self._get_user_url(username)
        headers = {
            "Accept": "application/json",
            "If-Match": user.get("_rev")
        }
        r = requests.delete(url, headers=headers, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.accepted]:
            return True
        elif r.status_code == requests.codes.not_found:
            return False
        else:
            raise self._create_exception(r)

    def get_document(self, database, document_id):
        url = self._get_absolute_url("/{0}/{1}".format(database, document_id))
        headers = {"Accept": "application/json"}
        r = requests.get(url, headers=headers, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.not_modified]:
            return r.json()
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            raise self._create_exception(r)

    def _get_absolute_url(self, path):
        return "http://{0}:{1}{2}".format(self.host, self.port, path)

    def _get_user_url(self, username):
        return self._get_absolute_url("/{0}/org.couchdb.user:{1}".format(self.authentication_db, username))

    def _get_config_value(self, section, option=None):
        if option:
            url = self._get_absolute_url("/_config/{0}/{1}".format(section, option))
        else:
            url = self._get_absolute_url("/_config/{0}".format(section))
        r = requests.get(url, auth=self._auth)
        if r.status_code == requests.codes.ok:
            value = r.text
            return value.strip()
        elif r.status_code == requests.codes.not_found:
            return None
        else:
            raise self._create_exception(r)

    def _set_config_value(self, section, option, value, raw=False):
        url = self._get_absolute_url("/_config/{0}/{1}".format(section, option))
        r = requests.put(url, **{
            "headers": {"Accept": "application/json"},
            "auth": self._auth,
            "data": value,
            "params": None if not raw else {"raw": "true"}
        })
        if r.status_code == requests.codes.ok:
            return True if r.text != value else False
        else:
            raise self._create_exception(r)

    def _can_authenticate(self, username, password):
        try:
            session_token = self.create_session(username, password)
            self.close_session(session_token)
            return True
        except AuthenticationException:
            return False

    @staticmethod
    def _create_exception(r):
        status_code = r.status_code
        if r.headers['content-type'] == 'application/json':
            response_body = r.json()
            error_type = response_body['error']
            reason = response_body['reason']
            origin = {
                "url": r.request.url,
                "method": r.request.method,
                "headers": dict(r.request.headers)
            }
            return CouchDBException(status_code, reason=reason, error_type=error_type, origin=origin)
        else:
            response_body = r.text
            return CouchDBException(status_code, reason=response_body)


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
            authentication_db=dict(type='str', default='_users'),
            login_user=dict(type='str', required=False),
            login_password=dict(type='str', required=False, no_log=True)
        ),
        required_together=[['login_user', 'login_password']]
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
    authentication_db = module.params['authentication_db']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    couchdb = CouchDBClient(host, port, login_user, login_password, authentication_db)

    if state == "absent" and not login_user:
        if admin:
            module.fail_json(msg="You need to be admin in order to remove admin users.")
        elif not couchdb.is_admin_party():
            module.fail_json(msg="You need to be authenticated in order to remove users when you have admin users.")

    try:
        couchdb.login()
        changed = False
        kwargs = {}
        if admin is True:
            if state == "present":
                changed = couchdb.create_or_update_admin_user(username, password, raw_password)
            elif state == "absent":
                changed = couchdb.remove_admin_user(username)
        else:
            if state == "present":
                changed = couchdb.create_or_update_user(username, password, raw_password=raw_password, roles=roles)
            elif state == "absent":
                changed = couchdb.remove_user(username)
                kwargs = {
                    "msg": "Notice: Due to CouchDBs secure design, there is no way to tell "
                           "for sure, whether the user has actually been deleted if you didn't "
                           "provide a proper 'login_user' and 'login_password'."
                }
        module.exit_json(changed=changed, **kwargs)
    except CouchDBException as e:
        kwargs = {
            "msg": e.reason,
            "status_code": e.status_code,
            "error": e.error_type,
            "origin": e.origin
        }
        module.fail_json(**kwargs)
    finally:
        couchdb.logout()


from ansible.module_utils.basic import *

main()