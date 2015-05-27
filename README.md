# couchdb_user
This module lets you easily manage admin and user accounts of a [CouchDB](http://couchdb.apache.org) database with [Ansible](http://www.ansible.com).

## Installation
To use it, just copy the file [`lib/couchdb_user.py`](https://raw.githubusercontent.com/SQiShER/ansible-modules-couchdb/master/lib/couchdb_user.py?token=AAWkQpA3u6osKY6TyBCT3Yj-3qeN3gjHks5Vb2h1wA%3D%3D) into one of your Ansible [library folders](http://docs.ansible.com/intro_configuration.html#library).

## Usage
The full documentation can be found [at the top of the module file](https://github.com/SQiShER/ansible-modules-couchdb/blob/master/lib/couchdb_user.py#L25-129); but it basically boils down to this:

```yaml
- name: create admin account
  couchdb_user: name=heisenberg password=the-one-who-knocks admin=yes state=present
```

You'll also find plenty more examples in the [integration test suite](https://github.com/SQiShER/ansible-modules-couchdb/tree/master/test/integration/roles/test_couchdb_user/tasks). 

## License
This project is licensed under the terms of the MIT license.

## Goal
Ultimately I'd like to get this module into [ansible-modules-extras](https://github.com/ansible/ansible-modules-extras). 
But that could take a while; as of the time of writing (5/27/2015), they have about 145 pending pull requests dating 
back to October 2014.

Let's use that time and find some more bugs, shall we?