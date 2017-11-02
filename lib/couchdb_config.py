#!/usr/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2015 Leif Hanack, Daniel Bechler
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
module: couchdb_config
short_description: Add, update and delete CouchDB configuration keys
description:
    - This module allows you to change the CouchDB configuration.
    - You can add and update section keys, which is equivalent to a PUT /_config/{section}/{key} using the
    - [CouchDB API](http://docs.couchdb.org/en/latest/api/server/configuration.html#config-section-key).
    - And you can delete section keys, which is equivalent to a DELETE /_config/{section}/{key}.
version_added: 1.0
author: Leif Hanack @leifhanack
requirements:
    - pycouchdb 1.13 or above
    - requests
options:
    section:
        description:
            - The configuration section name
        required: true
    key:
        description:
            - The configuration key name
        required: true
    value:
        description:
            - The configuration value
        required: when state is present, which is the default
    state:
        description:
            - When state is `present` you must provide a value to add or update a section key.
            - State `absent` must be provided when you want to delete a section key.
        required: false
        default: present
        choices: [ "present", "absent" ]
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
    node:
        description:
            - The cluster node to apply the changes to. Required for CouchDB 2.0 and later.
        required: false
    user:
        description:
            - The administrator user used to authenticate with
        required: false
    password:
        description:
            - The administrator password of the user
        required: false
'''

EXAMPLES = '''
# setting multiple values
- couchdb_config:
    section: '{{ item.section }}'
    key: '{{ item.key }}'
    value: '{{ item.value }}'
  with_items:
    - { section: couch_httpd_auth, key: timeout, value: 60 }
    - { section: socket_keys, key: worker_batch_size, value: 510 }

# setting a list of tuples
- couchdb_config: >
    section=httpd
    key=socket_keys
    value='[{recbuf, 262140}, {sndbuf, 262140}]'

# setting a value when CouchDB is secured
- couchdb_config:
    user: admina
    password: @dm1na
    section: couch_httpd_auth
    key: timeout
    value: 60

# changing host and port
- couchdb_config: >
    host=192.168.33.100
    port=5985
    section=couch_httpd_auth
    key=timeout
    value=60

# delete a section key
- couchdb_config:
    section: couch_httpd_auth
    key: timeout
    state: absent
'''

try:
    import json
except ImportError:
    import simplejson as json

IS_INSTALLED_PYCOUCHDB = True
try:
    import pycouchdb
    from pycouchdb.resource import Resource
    from pycouchdb.exceptions import GenericError, Conflict, NotFound, BadRequest, AuthenticationFailed
except ImportError:
    IS_INSTALLED_PYCOUCHDB = False
    pycouchdb = None
    Resource = None
    Conflict = None
    NotFound = None
    BadRequest = None
    AuthenticationFailed = None
    GenericError = None

IS_INSTALLED_REQUESTS = True
try:
    import requests
    from requests.exceptions import ConnectionError
except ImportError:
    IS_INSTALLED_REQUESTS = False
    requests = None
    ConnectionError = None


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(default='localhost'),
            port=dict(type='int', default=5984),
            user=dict(type='str'),
            password=dict(type='str', no_log=True),
            node=dict(type='str'),
            section=dict(type='str', required=True),
            key=dict(type='str', required=True),
            value=dict(type='str'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
        )
    )

    if not IS_INSTALLED_PYCOUCHDB:
        module.fail_json(msg='Please install pycouchdb 1.13 or above.')

    if version_tuple(pycouchdb.__version__) < version_tuple('1.13'):
        module.fail_json(msg='pycouchdb version must be 1.13 or above!')

    if not IS_INSTALLED_REQUESTS:
        module.fail_json(msg='Please install requests')

    couchdb_uri = create_couchdb_uri(module.params['host'], module.params['port'],
                                     user=module.params['user'], password=module.params['password'])

    node = module.params['node']
    section = module.params['section']
    key = module.params['key']
    value = module.params['value']
    state = module.params['state']

    try:
        if state == "present":
            if value is None:
                module.fail_json(msg='Failed. Please specify a value')
            is_changed = update_configuration_key(couchdb_uri, node, section, key, value)
        if state == "absent":
            is_changed = delete_configuration_key(couchdb_uri, node, section, key)
    except ConnectionError:
        module.fail_json(msg='Failed to connect to ' + couchdb_uri)
    except AuthenticationFailed:
        module.fail_json(msg='Failed to authenticate')
    except Conflict:
        module.fail_json(msg='Failed with conflicts')
    except NotFound:
        module.fail_json(msg='Requested resource is not found')
    except BadRequest:
        module.fail_json(msg='Bad request, maybe your values are not a not valid JSON strings')
    except RuntimeError:
        module.fail_json(msg='Unexpected error, maybe your authentication method is invalid')
    except GenericError as error:
        module.fail_json(msg=error.args[0]['error'], reason=error.args[0]['reason'])

    kwargs = {}
    module.exit_json(changed=is_changed, **kwargs)


def create_couchdb_uri(host, port, user=None, password=None):
    if user is not None:
        auth = '{0}:{1}@'.format(user, password)
    else:
        auth = ''

    return ''.join(['http://', auth, host, ':{0}'.format(port)])


def resource_path_to_key(node, section, key):
    if node:
        path = '_node/{0}/_config/{1}/{2}'.format(node, section, key)
    else:
        path = '_config/{0}/{1}'.format(section, key)
    return path


def update_configuration_key(uri, node, section, key, value):
    path = resource_path_to_key(node, section, key)
    response = Resource(uri).put(path, data=json.dumps(value))
    if response is not None and response[1] == value:
        is_changed = False
    else:
        is_changed = True
    return is_changed


def delete_configuration_key(uri, node, section, key):
    path = resource_path_to_key(node, section, key)
    response = Resource(uri).delete(path)
    result = json.loads(response[1])
    if type(result) is dict and 'error' in result:
        is_changed = False
    else:
        is_changed = True
    return is_changed


def version_tuple(version):
    return tuple(map(int, (version.split("."))))

from ansible.module_utils.basic import *
main()
