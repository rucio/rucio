..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

=================
Rucio RESTful API
=================

Each resource can be accessed or modified using specially formed URLs and the standard HTTP methods:

 * GET to read
 * POST to create
 * PUT to update
 * DELETE to remove

We require that all requests are done over SSL. The API supports JSON formats. Rucio uses OAuth_
to authenticate all API requests. The method is to get an authentication token, and use it for the rest of
the requests. Descriptions of the actions you may perform on each resource can be found below.


.. _OAuth: http://oauth.net/

Service
=======


* :ref:`GET /PING`: Discover server version information

  - Command: :ref:`rucio ping`, method: :ref:`ping`

Authentication
==============

* :ref:`GET auth/userpass`: Retrieve an auth token with an username and password
* :ref:`GET auth/x509`: Retrieve an auth token with a x509 certificate
* :ref:`GET auth/x509_proxy`: Retrieve an auth token with a Globus proxy
* :ref:`GET auth/gss`: Retrieve an auth token with a gss token
* :ref:`GET auth/validate`: Retrieve an auth token with a gss token
* :ref:`DELETE auth/tokens/`: Revoke a  <token> ?

Rucio account
=============

* :ref:`POST accounts/{accountName}`: Create account

  - Command: :ref:`rucio-admin account add`, method: :ref:`add_account`

* :ref:`GET accounts/{accountName}`: Get account information
* :ref:`PUT accounts/{accountName}`: Update account information
* :ref:`GET accounts/{accountName}/usage`: Get account usage information
* :ref:`GET accounts/{accountName}/limits`: Get limits
* :ref:`PUT accounts/{accountName}/limits`: Set limits for a account and a value
* :ref:`GET accounts/whoami`: Get information about account whose token is used
* :ref:`GET accounts/`:  List available accounts
* :ref:`DELETE accounts/{accountName}`: Disable account name

RSE (Rucio Storage Element)
============================

* :ref:`POST rses/{RSEName}`: Create a RSE

  - Command: :ref:`rucio-admin rse add`
  - Method: :ref:`add_rse`

* :ref:`GET rses/{rseName}`: Get RSE information
* :ref:`GET rses/`: List available RSEs
* :ref:`DELETE rses/{rseName}`: Disable a RSE
* :ref:`GET rses/{rseName}/usage`: Get RSE usage information
* :ref:`GET rses/{rseName}/usage/history`: Get RSE usage information history


RSE  attributes
===============

* :ref:`GET rses/{RSEName}/attr/`: List all keys of the RSE with their respective values
* :ref:`GET rses/{rseName}/attr/{key}`: Get the value of the RSE attribute/key
* :ref:`POST rses/{rseName}/attr/{key}/`: Create an RSE key
* :ref:`PUT rses/{rseName}/attr/{key}/`: Update the value of a key
* :ref:`DELETE rses/{rseName}/attr/{key}`: Remove a key from a RSE

Identity
========

* :ref:`POST accounts/{accountName}/identities/{userpass|x509|gss|proxy}/{identityString}`: Grant a \{userpass|x509|gss|proxy\} identity access to an account
* :ref:`GET accounts/{accountName}/identities/`: List all identities on an account
* :ref:`GET identities/{userpass|x509|gss|proxy}/{identityString}/accounts/`: List all account memberships of an identity
* :ref:`DELETE accounts/{accountName}/identities/{userpass|x509|gss|proxy}/{identityString}`:  Revoke a \{userpass|x509|gss|proxy\} identity's access to an account

Scope
=====

* :ref:`POST accounts/{accountName}/scopes/{scopeName}`: Create a scope
* :ref:`GET accounts/{accountName}/scopes/`: List available scopes for an account
* :ref:`GET scopes/`: List/query all scopes with filter parameter lists
* :ref:`DELETE accounts/{accountName}/scopes/{scopeName}`: Delete a scope from an account

Dataset
=======

* :ref:`POST datasets/{scopeName}/{datasetName}`: Register a dataset
* :ref:`GET datasets/{scopeName}/{datasetName}/names/`: List dataset content
* :ref:`GET datasets/{scopeName}/{datasetName}/files/`: List dataset file content
* :ref:`PUT datasets/{scopeName}/{datasetName}/status/`: Update dataset status
* :ref:`GET datasets/{scopeName}/{datasetName}/status/`: Get dataset status
* :ref:`GET datasets/{scopeName}/{datasetName}/meta`: List all keys of the dataset with their respective values
* :ref:`POST datasets/{scopeName}/{datasetName}/meta/{key}`:  Creation of a key for a dataset
* :ref:`GET datasets/{scopeName}/{datasetName}/meta/{key}`: Retrieve the selected key value pair for the given dataset
* :ref:`DELETE datasets/{scopeName}/{datasetName}/meta/{key}`: Remove a key from a dataset
* :ref:`PUT datasets/{scopeName}/{datasetName}/meta/{key}`:  Update the value of the key
* :ref:`GET datasets/`:  Search/list datasets with filter parameters
* :ref:`POST datasets/{scopeName}/{datasetName}/files|names`: Add file(s)/dataset(s) to a dataset
* :ref:`DELETE datasets/{scopeName}/{datasetName}`: Delete a dataset

File
====

* :ref:`POST /rses/{RSEName}/files/{scopeName}/{fileName}`: Register a file replica
* :ref:`GET files/{scopeName}/{datasetName}/meta`: List all keys of the dataset with their respective values
* :ref:`GET files/{scopeName}/{fileName}/meta/{key}`: Retrieve the selected key value pair for the given file
* :ref:`PUT files/{scopeName}/{fileName}/status`: Update file status
* :ref:`GET files/{scopeName}/{fileName}/status`: Get file status
* :ref:`POST files/{scopeName}/{datasetName}/meta/{key}/`:  Creation of a key for a file
* :ref:`PUT files/{scopeName}/{fileName}/meta/{key}`: Update the value of the key
* :ref:`DELETE files/{scopeName}/{fileName}/meta/{key}`: Remove a key from a file
* :ref:`PUT files/{scopeName}/{fileName}/meta/{key}/`:  Set the value of the key to {value}
* :ref:`GET files/{scopeName}/{fileName}/rses/`:  List file replicas


Name
====

* :ref:`GET names/{scopeName}/{name}/rses/`: List file replicas for dataset|file
* :ref:`GET names/{scopeName}/{name}/names/`: List content
* :ref:`GET names/{scopeName}/{name}/files/`: List file content
* :ref:`GET names/{scopeName}/{name}/meta`: List all keys of the name with their respective values
* :ref:`GET names/{scopeName}/{name}/meta/{key}`: Retrieve the selected key value pair for the given name
* :ref:`PUT names/{scopeName}/{name}/meta/{key}`: Set the value of the key to NULL ?
* :ref:`DELETE /names/{scopeName}/{name}/meta/{key}`: Remove a key from a name
* :ref:`PUT /names/{scopeName}/{name}/meta/{key}`:  Set the value of the key to {value}
* :ref:`GET names/`:  Search names with filter parameters

Metadata
=========

What's written below for datasets is applicable to files 1:1 (replace string 'datasets' with 'files').


* :ref:`POST meta/datasets/{key}`: Create a new allowed key (value is NULL)
* :ref:`GET meta/datasets`: List all allowed keys with their default values
* :ref:`POST meta/datasets/{key}/`: Create a new allowed key with a default value
* :ref:`DELETE meta/datasets/{key}`:  Delete an allowed key
* :ref:`DELETE meta/datasets/{key}/{defaultvalue}`: Delete the default value of a key (change the value to NULL)


Replication rule
=================

* :ref:`POST rules/{accountName}/{scopeName}/{name}`: Create a rule on a name
* :ref:`GET rules/{accountName}/{scopeName}/{name}`: Get all the rules associated to a name
* :ref:`DELETE rules/{accountName}/{scopeName}/{name}`: Delete a rule


Subscriptions
=============

+----------------------------------------------------------------------+-----------------------------------------------------------+--------------+
| Resource                                                             | Description                                               | Availability |
+======================================================================+===========================================================+==============+
| :ref:`POST subscriptions/{accountName}/`                             | Register a subscription                                   |  No          |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------------+
| :ref:`DELETE subscriptions/{subscription_id}`                        | Delete a subscription                                     |  No          |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------------+
| :ref:`GET subscriptions/{subscription_id}`                           | Get subscription info                                     |  No          |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------------+
| :ref:`GET subscriptions/`                                            | List all subscriptions                                    |  No          |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------------+


.. Status legend:
.. Stable - feature complete, no major changes planned
.. Beta - usable for integrations with some bugs or missing minor functionality
.. Alpha - major functionality in place, needs feedback from API users and integrators
.. Prototype - very rough implementation, possible major breaking changes mid-version. Not recommended for integration
.. Planned - planned in a future version, depending on developer availability


