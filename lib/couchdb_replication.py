#!/usr/bin/env python

# try:
import pycouchdb
#     HAS_REQUESTS = True
# except ImportError:
#     HAS_REQUESTS = False

import requests
import time
import urllib

from ansible.module_utils.basic import *

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


def run_module():
    argument_spec = dict(
        host=dict(type='str', default='localhost'),
        port=dict(type='int', default=5984),
        user=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        source=dict(type='str'),
        target=dict(type='str'),
        create_target=dict(type='bool', default=False),
        persistent=dict(type='bool', default=False),
        continuous=dict(type='bool', default=False),
        replicator_database=dict(type='str', default='_replicator'),
        name=dict(type='str', required=False),
        # doc_ids=dict(type='list'),
        # filter=dict(type='str'),
        state=dict(type='str', choices=['absent', 'present'], default='present')
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ["persistent", "yes", ["name"]],
            ["state", "present", ["source", "target"]]
        ],
        required_together=[
            ["user", "password"]
        ])
    result = dict(changed=False)

    host = module.params['host']
    port = module.params['port']
    source = module.params['source']
    target = module.params['target']
    create_target = module.params['create_target']
    user = module.params['user']
    password = module.params['password']
    state = module.params['state']
    continuous = module.params['continuous']
    persistent = module.params['persistent']

    base_url = get_base_url(user, password, host, port)

    couchdb = pycouchdb.client.Server(base_url=base_url, authmethod="basic")
    major_version, _, _ = couchdb.version().split('.')
    if int(major_version) > 1:
        if source and is_remote_target(source) is False:
            source = get_base_url(user, password, 'localhost', port) + source
        if target and is_remote_target(target) is False:
            target = get_base_url(user, password, 'localhost', port) + target

    replicator_database = module.params['replicator_database']
    if replicator_database != '_replicator':
        if int(major_version) > 1:
            if replicator_database.endswith('/_replicator'):
                replicator_database = urllib.quote(replicator_database, safe='')
                result['wtf'] = replicator_database
            else:
                module.fail_json(msg="Since CouchDB 2.0 alternative replicator databases must end with '/_replicator'")

    try:
        if not persistent:
            if state == 'present':
                if continuous:
                    response = couchdb.replicate(source, target, create_target=create_target, continuous=True)
                    result['changed'] = True
                else:
                    response = couchdb.replicate(source, target, create_target=create_target, continuous=False)
                    history = response['history']
                    session_id = response['session_id']
                    session_statistics = next((entry for entry in history if entry['session_id'] == session_id), None)
                    result['statistics'] = session_statistics
                    result['changed'] = 'no_changes' not in response.keys()
            elif state == 'absent':
                pass
        else:
            name = module.params['name']
            if state == 'present':
                try:
                    replication_doc = couchdb.database(replicator_database).get(name)
                except pycouchdb.exceptions.NotFound:
                    # TODO Make user_ctx configurable
                    replication_doc = dict(_id=name, user_ctx={"roles": ["_admin"]})

                has_changes = False
                for prop in [("source", source),
                             ("target", target),
                             ("create_target", create_target),
                             ("continuous", continuous)]:
                    (key, value) = prop
                    if replication_doc.get(key, None) != value:
                        replication_doc[key] = value
                        has_changes = True

                if has_changes:
                    couchdb.database(replicator_database).save(replication_doc)
                    result['changed'] = True

                for i in range(0, 20):
                    time.sleep(0.25)
                    if int(major_version) <= 1:
                        replication_doc = couchdb.database(replicator_database).get(name)
                        replication_state = replication_doc.get('_replication_state', None)
                    else:
                        url = base_url + '_scheduler/docs/' + replicator_database + '/' + name
                        scheduler_doc = requests.get(url).json()
                        replication_state = scheduler_doc.get('state', None)
                    result['state'] = replication_state
                    if replication_state == 'running':
                        break
                result['failed'] = replication_state in ['failed', 'crashing', 'error']
            elif state == 'absent':
                try:
                    doc = couchdb.database(replicator_database).get(name)
                    couchdb.database(replicator_database).delete(doc)
                    result['changed'] = True
                except pycouchdb.exceptions.NotFound:
                    pass
    except pycouchdb.exceptions.GenericError as error:
        if error.args[0]['error'] == 'db_not_found':
            result['msg'] = error.args[0]['reason'] + '. consider enabling target db creation.'
            module.fail_json(**result)
        elif error.args[0]['error'] == 'unauthorized':
            result['msg'] = error.args[0]['reason']
            module.fail_json(**result)
        else:
            raise error

    module.exit_json(**result)


def get_base_url(user, password, host, port):
    if user and password:
        base_url = "http://{0}:{1}@{2}:{3}/".format(user, password, host, port)
    else:
        base_url = "http://{0}:{1}/".format(host, port)
    return base_url


def is_remote_target(db):
    return db.startswith('http://') or db.startswith('https://')


def main():
    run_module()


if __name__ == '__main__':
    main()
