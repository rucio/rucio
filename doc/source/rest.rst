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
 * PUT to create/update
 * DELETE to remove

.. note::

   PUT is idempotent and is used to create objects if the URL object names are created explicitly. If there is some server logic, like the server
   decides the ressource names, then POST is used. With POST you can have 2 requests coming in at the same time making modifications to a URL, and
   they may update different parts of the object.

We require that all requests are done over SSL. The API supports JSON formats. Rucio uses OAuth_
to authenticate all API requests. The method is to get an authentication token, and use it for the rest of
the requests. Descriptions of the actions you may perform on each resource can be found below.


.. _OAuth: http://oauth.net/


Authentication
==============

+------------------------------------+-----------------------------------------------------------+--------+
| Resource                           | Description                                               | Status |
+====================================+===========================================================+========+
| :ref:`GET auth/userpass`           | Retrieve an auth token with via username and password     |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET auth/x509`               | Retrieve an auth token with via a x509 certificate        |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET auth/gss`                | Retrieve an auth token with via a gss token               |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET auth/validate`           | Return accountname and expiration date, if token valid    |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET auth/register_api_token` | Authenticate a Rucio account for interaction with the API |  X     |
+------------------------------------+-----------------------------------------------------------+--------+

Rucio account
=============

+------------------------------------+-----------------------------------------------------------+--------+
| Resource                           | Description                                               | Status |
+====================================+===========================================================+========+
| :ref:`PUT account/{accountName}`   | Create account                                            |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET account/{accountName}`   | Get account information                                   |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET account/whoami`          | Get information about account whose token is used         |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET account/`                | List available accounts                                   |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+
| :ref:`DELETE account/{accountName}`| Disable an account                                        |  OK    |
+------------------------------------+-----------------------------------------------------------+--------+

Location
========

+---------------------------------------+-----------------------------------------------------------+--------+
| Resource                              | Description                                               | Status |
+=======================================+===========================================================+========+
| :ref:`PUT location/{locationName}`    | Create a location                                         |  X     |
+---------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET location/{locationName}`    | Get location information                                  |  X     |
+---------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET location/`                  | List available locations                                  |  OK    |
+---------------------------------------+-----------------------------------------------------------+--------+
| :ref:`DELETE location/{locationName}` | Disable a location                                        |  X     |
+---------------------------------------+-----------------------------------------------------------+--------+


Rucio Storage Element
=====================

+-----------------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                            | Description                                               | Status |
+=====================================================+===========================================================+========+
| :ref:`PUT /location/{locationName}/rse/{rseName}`   | Tag a location with a RSE                                 |  X     |
+-----------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET rse/`                                     | List all RSEs                                             |  X     |
+-----------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET location/{locationName}/rse/`             | List all RSEs associated to a location                    |  X     |
+-----------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`DELETE location/{locationName}/rse/{rseName}` | Disable a RSE for a location                              |  X     |
+-----------------------------------------------------+-----------------------------------------------------------+--------+


Identity
========

+-----------------------------------------------------------------------+-------------------------------------------------------------+--------+
| Resource                                                              | Description                                                 | Status |
+=======================================================================+=============================================================+========+
| :ref:`PUT account/{accountName}/identity/{x509|gss|userpass}/{id}`    | Grant an x509|gss|userpass identity access to an account    |  X     |
+-----------------------------------------------------------------------+-------------------------------------------------------------+--------+
| :ref:`GET account/{accountName}/identity/`                            | List all identities on an account                           |  X     |
+-----------------------------------------------------------------------+-------------------------------------------------------------+--------+
| :ref:`GET identity/{x509|gss|userpass}/{id}/account/`                 | List all account an identity is member of                   |  X     |
+-----------------------------------------------------------------------+-------------------------------------------------------------+--------+
| :ref:`DELETE account/{accountName}/identity/{x509|gss|userpass}/{id}` | Revoke an x509|gss|userpass identity's access to an account |  X     |
+-----------------------------------------------------------------------+-------------------------------------------------------------+--------+


Scope
=====

+--------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                   | Description                                               | Status |
+============================================+===========================================================+========+
| :ref:`PUT scope/{accountName}/{scopeName}` | Create a scope                                            |  OK    |
+--------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET scope/{accountName}/`            | List available scope                                      |  X     |
+--------------------------------------------+-----------------------------------------------------------+--------+


Dataset
=======

+--------------------------------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                                           | Description                                               | Status |
+====================================================================+===========================================================+========+
| :ref:`POST scope/{scopeName}/dataset/{datasetName}`                | Register a dataset                                        |  X     |
+--------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`PUT scope/{scopeName}/dataset/{datasetName}`                 | Update dataset meta-data                                  |  X     |
+--------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET scope/{scopeName}/dataset/{datasetName}/file/`           | List dataset content                                      |  X     |
+--------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`PUT scope/{scopeName}/dataset/{datasetName}/file/{fileName}` | Add a file to a dataset                                   |  X     |
+--------------------------------------------------------------------+-----------------------------------------------------------+--------+

File
====

+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                                              | Description                                               | Status |
+=======================================================================+===========================================================+========+
| :ref:`POST scope/{scopeName}/file/{fileName}/location/{locationName}` | Register a file                                           |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`PUT scope/{scopeName}/file/{fileName}`                          | Update file meta-data                                     |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET scope/{scopeName}/file/{fileName}/location/`                | List file replicas                                        |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+


Replication rule & Transfer request
===================================

+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                                              | Description                                               | Status |
+=======================================================================+===========================================================+========+
| :ref:`POST copy/`                                                     | Register transfer requests                                |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET copy/<transfer_id>`                                         | Query transfer status                                     |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`POST replication/`                                              | Register a replication rule                               |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET replication/`                                               | List replication rules                                    |  X     |
+-----------------------------------------------------------------------+-----------------------------------------------------------+--------+


Subscriptions
=============

+----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| Resource                                                             | Description                                               | Status |
+======================================================================+===========================================================+========+
| :ref:`POST subscription/account/{accountName}/`                      | Register a subscription                                   |  X     |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`DELETE subscription/{subscription_id}`                         | Delete a subscription                                     |  X     |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET subscription/{subscription_id}`                            | Get subscription info                                     |  X     |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------+
| :ref:`GET subscription/`                                             | List all subscriptions                                    |  X     |
+----------------------------------------------------------------------+-----------------------------------------------------------+--------+


.. Status legend:
.. Stable - feature complete, no major changes planned
.. Beta - usable for integrations with some bugs or missing minor functionality
.. Alpha - major functionality in place, needs feedback from API users and integrators
.. Prototype - very rough implementation, possible major breaking changes mid-version. Not recommended for integration
.. Planned - planned in a future version, depending on developer availability


