#!/usr/local/bin/python

try:
    import json
except ImportError:
    import simplejson as json

HAS_REQUESTS = True
try:
    import requests
except ImportError:
    HAS_REQUESTS = False

def main():
    module = AnsibleModule(
        argument_spec = dict(
            host         = dict(default="localhost"),
            port         = dict(default=5984),
            name         = dict(required=True),
            password     = dict(required=False),
            raw_password = dict(type='bool', default='no'),
            admin        = dict(type='bool', default='no'),
            state        = dict(default="present", choices=["absent", "present"])
        )
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests is not installed")

    host = module.params['host']
    port = module.params['port']
    name = module.params['name']
    password = module.params['password']
    raw_password = module.params['raw_password']
    admin = module.params['admin']
    state = module.params['state']

    headers = {'Accept':'application/json'}

    if admin is True:
        uri = 'http://{0}:{1}/_config/admins/{2}'.format(host, port, name)

        if state == "present":
            
            if raw_password == True:
                r = requests.get(uri, headers=headers, auth=('couchdb','couchdb'))
                current_password = r.json()
                if current_password == password:
                    module.exit_json(changed=False)

            if raw_password:
                params = {"raw":"true"}
            else:
                params = {}
            data = '"{0}"'.format(password)
            r = requests.put(uri, data=data, headers=headers, params=params, auth=('couchdb','couchdb'))
            print r.url
            
            if r.status_code == requests.codes.ok:
                module.exit_json(changed=True)
            elif r.status_code == 401:
                response_body = r.json()
                reason = response_body['reason']
                module.fail_json(msg=reason, response=response_body)
            else:
                response_body = r.json()
                reason = "Unexpected status code: {0}".format(r.status_code)
                module.fail_json(msg=reason, response=response_body)
        elif state == "absent":
            
            r = requests.delete(uri, headers=headers, auth=('couchdb','couchdb'))

            if r.status_code == requests.codes.ok:
                module.exit_json(changed=True)
            elif r.status_code == 401:
                response_body = r.json()
                reason = response_body['reason']
                module.fail_json(msg=reason, response=response_body)                
            elif r.status_code == 404:
                module.exit_json(changed=False)
            else:
                response_body = r.json()
                reason = "Unexpected status code: {0}".format(r.status_code)
                module.fail_json(msg=reason, response=response_body)

from ansible.module_utils.basic import *
main()