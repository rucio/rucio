..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

=============
General notes
=============

Each resource can be accessed or modified using specially formed URLs and the standard HTTP methods:

 * GET to read
 * POST to create
 * PUT to update
 * DELETE to remove

We require that all requests are done over SSL. The API supports JSON formats. Rucio uses OAuth_
to authenticate all API requests. The method is to get an authentication token, and use it for the rest of
the requests. Descriptions of the actions you may perform on each resource can be found below.


**Date format**

All dates returned are in UTC and are strings in the following format (RFC 1123, ex RFC 822)::

 Mon, 13 May 2013 10:23:03 UTC

In code format, which can be used in all programming languages that support strftime or strptime::

'%a, %d %b %Y %H:%M:%S UTC'

**SSL only**

We require that all requests(except for the ping) are done over SSL.

**Response formats**

The currently-available response format for all REST endpoints is the string-based format JavaScript Object Notation(JSON_).
The server answer can be one of the following content-type in the http Header::

    Content-type: application/json
    Content-Type: application/x-json-stream

In the last case, it corresponds to JSON objects delimited by newlines(streaming JSON for large answer), e.g.::

    { "id": 1, "foo": "bar" }
    { "id": 2, "foo": "baz" }
    ...

**Error handling**

Errors are returned using standard HTTP error code syntax.
Any additional info is included in the header of the return call, JSON-formatted with the parameters::
    ExceptionClass
    ExceptionMessage

Where ExceptionClass refers to :ref:`exceptions`.

.. _OAuth: http://oauth.net/
.. _JSON: http://www.json.org/

Service
=======

.. _service:

.. automodule:: rucio.web.rest.ping
    :members:
    :undoc-members:
    :show-inheritance:

* :ref:`GET /ping`: Discover server version information

  - Command: :ref:`rucio ping`, method: :ref:`ping`

Authentication
==============

* :ref:`GET /auth/userpass`: Retrieve an auth token with an username and password
* :ref:`GET /auth/x509`: Retrieve an auth token with a x509 certificate
* :ref:`GET /auth/x509_proxy`: Retrieve an auth token with a Globus proxy
* :ref:`GET /auth/gss`: Retrieve an auth token with a gss token
* :ref:`GET /auth/validate`: Retrieve an auth token with a gss token
* :ref:`DELETE /auth/{token}`: Revoke a token

Rucio account
=============

* :ref:`POST /accounts/{account_name}`: Create account

  - Command: :ref:`rucio-admin account add`, method: :ref:`add_account`

* :ref:`GET /accounts/{account_name}`: Get account information
* :ref:`PUT /accounts/{account_name}`: Update account information
* :ref:`GET /accounts/{account_name}/usage`: Get account usage information
* :ref:`GET /accounts/{account_name}/limits`: Get limits
* :ref:`PUT /accounts/{account_name}/limits`: Set limits for a account and a value
* :ref:`GET /accounts/{account_name}/rules`: Get all rules of the account
* :ref:`GET /accounts/whoami`: Get information about account whose token is used
* :ref:`GET /accounts/`:  List available accounts
* :ref:`DELETE /accounts/{account_name}`: Disable account name

RSE (Rucio Storage Element)
============================

* :ref:`POST /rses/(rse_name)`: Create a RSE
  - Command: :ref:`rucio-admin rse add`
  - Method: :ref:`add_rse`

* :ref:`GET /rses/{rse_name}`: Get RSE information
* :ref:`GET /rses/`: List available RSEs
* :ref:`DELETE /rses/{rse_name}`: Disable a RSE
* :ref:`GET /rses/{rse_name}/usage`: Get RSE usage information
* :ref:`GET /rses/{rse_name}/usage/history`: Get RSE usage information history


RSE  attributes
===============

* :ref:`GET /rses/{rse_name}/attr/`: List all keys of the RSE with their respective values
* :ref:`GET /rses/{rse_name}/attr/{key}`: Get the value of the RSE attribute/key
* :ref:`POST /rses/{rse_name}/attr/{key}`: Create an RSE key
* :ref:`PUT /rses/{rse_name}/attr/{key}`: Update the value of a key
* :ref:`DELETE /rses/{rse_name}/attr/{key}`: Remove a key from a RSE

Identity
========

* :ref:`POST /accounts/{account_name}/identities/{userpass|x509|gss|proxy}/{identityString}`: Grant a \{userpass|x509|gss|proxy\} identity access to an account
* :ref:`GET /accounts/{account_name}/identities`: List all identities on an account
* :ref:`GET /identities/{userpass|x509|gss|proxy}/{identityString}/accounts/`: List all account memberships of an identity
* :ref:`DELETE /accounts/{account_name}/identities/{userpass|x509|gss|proxy}/{identityString}`:  Revoke a \{userpass|x509|gss|proxy\} identity's access to an account

Scope
=====

* :ref:`POST /accounts/{account_name}/scopes/{scope_name}`: Create a scope
* :ref:`GET /accounts/{account_name}/scopes/`: List available scopes for an account
* :ref:`GET /scopes/`: List/query all scopes with filter parameter lists
* :ref:`DELETE /accounts/{account_name}/scopes/{scope_name}`: Delete a scope from an account


Data identifiers
================

* :ref:`GET /dids/`: Search data identifiers over all scopes with filter parameters
* :ref:`POST /dids/{scope_name}/{did}`: Create a new data identifier
* :ref:`GET /dids/{scope_name}/`: List all data identifiers in a scope
* :ref:`DELETE /dids/{scope_name}/{did}`: Obsolete a data identifier
* :ref:`GET /dids/{scope_name}/{did}/rses/`: List replicas for a data identifier
* :ref:`GET /dids/{scope_name}/{did}/`: List content of data identifier
* :ref:`PUT /dids/{scope_name}/{did}/status`: Update data identifier status
* :ref:`GET /dids/{scope_name}/{did}/status`: Get data identifier status
* :ref:`GET /dids/{scope_name}/{did}/rules`: List all rules of this did
* :ref:`GET /dids/{scope_name}/{did}/meta/`: List all keys of the data identifier with their respective values
* :ref:`GET /dids/{scope_name}/{did}/meta/{key}`: Retrieve the selected key value pair for the given data identifier
* :ref:`PUT /dids/{scope_name}/{did}/meta/{key}`: Set the value of the key to NULL ?
* :ref:`DELETE /dids/{scope_name}/{did}/meta/{key}`: Remove a key from a data identifier
* :ref:`PUT /dids/{scope_name}/{did}/meta/{key}`:  Set the value of the key of a data identifier
* :ref:`POST /dids/{scope_name}/{did_super}/{did_sub}`: Add "sub" data identifier into "super" data identifier


Metadata
=========

* :ref:`POST /meta/{key}`: Create a new allowed key (value is NULL)
* :ref:`GET /meta/`: List all allowed keys with their default values
* :ref:`POST /meta/{key}`: Create a new allowed key with a default value
* :ref:`DELETE /meta/{key}`:  Delete an allowed key
* :ref:`DELETE /meta/{key}/{defaultvalue}`: Delete the default value of a key (change the value to NULL)


Replication rule
=================

* :ref:`POST /rules/`: Create a rule on a data identifier
* :ref:`GET /rules/{rule_id}`: Get all the rules associated to a data identifier
* :ref:`DELETE /rules/{rule_id}`: Delete a rule


Subscriptions
=============

* :ref:`POST /subscriptions/{account_name}/`: Register a subscription
* :ref:`DELETE /subscriptions/{subscription_id}`: Delete a subscription
* :ref:`GET /subscriptions/{subscription_id}`: Get subscription info
* :ref:`GET /subscriptions/`: List all subscriptions
* :ref:`GET /subscriptions/{subscription_id}/rules`: Get all rules of this subscription


.. Status legend:
.. Stable - feature complete, no major changes planned
.. Beta - usable for integrations with some bugs or missing minor functionality
.. Alpha - major functionality in place, needs feedback from API users and integrators
.. Prototype - very rough implementation, possible major breaking changes mid-version. Not recommended for integration
.. Planned - planned in a future version, depending on developer availability


