#!/usr/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2017 Daniel Bechler
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

DOCUMENTATION = '''
---
module: couchdb_database
short_description: Creates or removes a database and manages its permissions.
description:
    - Creates or removes a database and manages its permissions.
options:
    name:
        description:
            - The name of the database
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
    admin_roles:
        description:
            - The roles that should be able to administer this database
        required: false
        default: []
    admin_names:
        description:
            - The names of users that should be able to administer this database
        required: false
        default: []
    member_roles:
        description:
            - The roles that should be able to read and write from and to this database
        required: false
        default: []
    member_names:
        description:
            - The names of users that should be able to read and write from and to this database
        required: false
        default: []
    state:
        description:
            - The database state
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
version_added: 1.9
requirements: [ "requests" ]
notes:
    - This modules requires the CouchDB cookie authentication handler to be enabled.
author: Daniel Bechler
'''

try:
    import json
except ImportError:
    import simplejson as json

HAS_REQUESTS = True
try:
    import requests
    from requests.auth import AuthBase, HTTPBasicAuth
    from requests.exceptions import ConnectionError

    class HTTPCookieAuth(AuthBase):

        def __init__(self, session_token):
            super(HTTPCookieAuth, self).__init__()
            self.session_token = session_token

        def __call__(self, r):
            r.headers['Cookies'] = None
            r.prepare_cookies({
                "AuthSession": self.session_token
            })
            return r
except ImportError:
    HAS_REQUESTS = False


class CouchDBException(Exception):

    def __init__(self, status_code, error_type="unknown", reason=None, origin=None):
        super(CouchDBException, self).__init__()
        self.status_code = status_code
        self.error_type = error_type
        self.reason = reason
        self.origin = origin


class AuthenticationException(Exception):

    def __init__(self, user, message):
        super(AuthenticationException, self).__init__()
        self.user = user
        self.message = message


class CouchDBClient(object):

    def __init__(self, host="localhost", port="5984", login_user=None, login_password=None):
        self._auth = None
        self.host = host
        self.port = port
        self.login_user = login_user
        self.login_password = login_password

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

    def create_session(self, username, password):
        url = self._get_absolute_url("/_session")
        data = "name={0}&password={1}".format(username, password)
        headers = {
            "Accept": "application/json",
            "Content-Length": str(len(data)),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post(url, headers=headers, data=data, auth=HTTPBasicAuth(username, password))
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

    def database_exist(self, database):
        url = self._get_absolute_url("/_all_dbs")
        r = requests.get(url, auth=self._auth)
        if r.status_code in [requests.codes.ok, requests.codes.not_modified]:
            dbs = r.json()
            return database in dbs
        else:
            raise self._create_exception(r)

    def _get_absolute_url(self, path):
        return "http://{0}:{1}{2}".format(self.host, self.port, path)

    def _get_user_url(self, username):
        return self._get_absolute_url("/{0}/org.couchdb.user:{1}".format('_users', username))

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
        if raw:
            params = {"raw": "true"}
        else:
            params = None
        r = requests.put(url, **{
            "headers": {"Accept": "application/json"},
            "auth": self._auth,
            "data": value,
            "params": params
        })
        if r.status_code == requests.codes.ok:
            return r.text != value
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
            error_type = response_body.get('error')
            reason = response_body.get('reason')
            origin = {
                "url": r.request.url,
                "method": r.request.method,
                "headers": dict(r.request.headers)
            }
            return CouchDBException(status_code, reason=reason, error_type=error_type, origin=origin)
        else:
            response_body = r.text
            return CouchDBException(status_code, reason=response_body)

    @staticmethod
    def update_dict_entry_values(values, target_dict, target_key):
        original_values = target_dict.get(target_key, [])
        if isinstance(values, list) and len(values) > 0:
            target_dict[target_key] = values
        else:
            target_dict[target_key] = []
        changed = original_values != target_dict[target_key]
        return changed

    def database_present(self, name, admin_names, admin_roles, member_names, member_roles):
        if not self.database_exist(name):
            r = requests.put(self._get_absolute_url('/{0}'.format(name)),
                             auth=self._auth,
                             headers={"accept": "application/json"})
            database_created = False
            if r.status_code == 200:
                database_created = True
            elif r.status_code == 201:
                database_created = True
            elif r.status_code == 412:
                database_created = False
            else:
                raise self._create_exception(r)
        else:
            database_created = False

        document = self.get_document(name, '_security')
        if document is None:
            document = {}
        if document.get('admins') is None:
            document['admins'] = {}
        if document.get('members') is None:
            document['members'] = {}

        admin_names_changed = self.update_dict_entry_values(admin_names, document['admins'], 'names')
        admin_roles_changed = self.update_dict_entry_values(admin_roles, document['admins'], 'roles')
        member_names_changed = self.update_dict_entry_values(member_names, document['members'], 'names')
        member_roles_changed = self.update_dict_entry_values(member_roles, document['members'], 'roles')

        security_document_changed = admin_names_changed or admin_roles_changed or member_names_changed or member_roles_changed
        security_document_updated = False
        if security_document_changed:
            r = requests.put(self._get_absolute_url('/{0}/_security'.format(name)), **{
                'data': json.dumps(document),
                'auth': self._auth,
                'headers': {
                    'Accept': 'application/json',
                    'X-Couch-Full-Commit': 'true'
                }
            })
            if r.status_code == requests.codes.ok:
                security_document_updated = True
            else:
                raise self._create_exception(r)

        changed = database_created or security_document_updated
        context = {
            'database_created': database_created,
            'permissions_changed': security_document_updated
        }
        return changed, context

    def database_absent(self, name):
        response = requests.get(self._get_absolute_url('/{0}'.format(name)), auth=self._auth)

        database_deleted = False
        if response.status_code == 200:
            delete_request = requests.delete(self._get_absolute_url('/' + name), auth=self._auth)
            if delete_request.status_code == 200:
                database_deleted = True
            else:
                raise self._create_exception(response)

        context = {
            'database_deleted': database_deleted
        }
        return database_deleted, context


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', default="localhost"),
            port=dict(type='int', default=5984),
            name=dict(type='str', required=True),
            admin_names=dict(type='list', default=None),
            admin_roles=dict(type='list', default=None),
            member_names=dict(type='list', default=None),
            member_roles=dict(type='list', default=None),
            state=dict(type='str', default="present", choices=["absent", "present"]),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True)
        )
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests is not installed")

    host = module.params['host']
    port = module.params['port']
    name = module.params['name']
    admin_names = module.params['admin_names']
    admin_roles = module.params['admin_roles']
    member_names = module.params['member_names']
    member_roles = module.params['member_roles']
    state = module.params['state']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    couchdb = CouchDBClient(host, port, login_user, login_password)
    try:
        couchdb.login()
        changed = False
        kwargs = {}
        if state == "present":
            changed, kwargs = couchdb.database_present(name, admin_names, admin_roles, member_names, member_roles)
        elif state == "absent":
            changed, kwargs = couchdb.database_absent(name)
        module.exit_json(changed=changed, **kwargs)
    except CouchDBException as e:
        kwargs = {
            "msg": e.reason,
            "status_code": e.status_code,
            "error": e.error_type,
            "origin": e.origin
        }
        module.fail_json(**kwargs)
    except ConnectionError:
        kwargs = {
            "msg": "Failed to connect to CouchDB at {0}:{1}".format(host, port),
            "host": host,
            "port": port
        }
        module.fail_json(**kwargs)
    finally:
        couchdb.logout()


from ansible.module_utils.basic import *

main()
