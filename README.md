[![Build Status](https://travis-ci.org/SQiShER/ansible-modules-couchdb.svg?branch=master)](https://travis-ci.org/SQiShER/ansible-modules-couchdb)

# Modules

This repository contains a collection of useful Ansible Modules to manage CouchDB instances. All modules are compatible with CouchDB 1.6.x and >2.x.

## couchdb_user
This module lets you easily manage admin and user accounts of a [CouchDB](http://couchdb.apache.org) database with [Ansible](http://www.ansible.com).

### Installation
To use it, just copy the file [`lib/couchdb_user.py`](https://raw.githubusercontent.com/SQiShER/ansible-modules-couchdb/master/lib/couchdb_user.py?token=AAWkQpA3u6osKY6TyBCT3Yj-3qeN3gjHks5Vb2h1wA%3D%3D) into one of your Ansible [library folders](http://docs.ansible.com/intro_configuration.html#library).

### Usage
The full documentation can be found [at the top of the module file](https://github.com/SQiShER/ansible-modules-couchdb/blob/master/lib/couchdb_user.py#L25-129); but it basically boils down to this:

```yaml
- name: create admin account
  couchdb_user: name=heisenberg password=the-one-who-knocks admin=yes state=present
```

You'll also find plenty more examples in the [integration test suite](https://github.com/SQiShER/ansible-modules-couchdb/tree/master/test/integration/roles/test_couchdb_user/tasks).

## couchdb_config

This module lets you easily change the configuration of a running CouchDB instance via the REST API.

### Installation

To use it, just copy the file [`lib/couchdb_config.py`](https://raw.githubusercontent.com/SQiShER/ansible-modules-couchdb/master/lib/couchdb_config.py) into one of your Ansible [library folders](http://docs.ansible.com/intro_configuration.html#library).

### Example

```yaml
- name: change httpd configuration
  couchdb_config: section=httpd key=socket_keys value='[{recbuf, 262140}, {sndbuf, 262140}]'
```

More examples can be found in the [integration test suite](https://github.com/SQiShER/ansible-modules-couchdb/tree/master/test/integration/roles/test_couchdb_config/tasks).

## couchdb_database

This module lets you easily create and remove databases and manage their permissions.

### Installation

To use it, just copy the file [`lib/couchdb_database.py`](https://raw.githubusercontent.com/SQiShER/ansible-modules-couchdb/master/lib/couchdb_database.py) into one of your Ansible [library folders](http://docs.ansible.com/intro_configuration.html#library).

### Example

```yaml
---
- name: create database
  couchdb_database: name=foo state=present
---
- name: create secured database
  couchdb_database: name=foo member_names=["kevin"]
---
- name: delete database
  couchdb_database: name=foo state=absent
```

More examples can be found in the [integration test suite](https://github.com/SQiShER/ansible-modules-couchdb/tree/master/test/integration/roles/test_couchdb_database/tasks).

# Develop

Check [here](https://github.com/SQiShER/ansible-modules-couchdb/tree/master/test/integration) for instructions on how to start developing on this project.

# License
This project is licensed under the terms of the MIT license.
