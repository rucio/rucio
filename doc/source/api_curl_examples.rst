..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0


----------------------------
REST API Examples Using Curl
----------------------------

Below are some examples of The Rucio REST API with Curl. We assume that there is
a Rucio server running on the localhost on port 80/443.


Service
^^^^^^^

.. _`GET /PING`:

`GET /PING`
"""""""""""

Discover server version information.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_ping.txt


Authentication
^^^^^^^^^^^^^^

.. _`GET /auth/userpass`:

`GET /auth/userpass`
""""""""""""""""""""

Requesting a X-Rucio-Auth-Token with curl via username and password.

**Responses**

 * ``200 OK``
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_get_auth_userpass.txt

.. _`GET /auth/x509`:

`GET /auth/x509`
""""""""""""""""

Requesting a X-Rucio-Auth-Token with curl via a X509 certificate.

**Responses**

 * ``200 OK``
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_get_auth_x509.txt


.. _`GET /auth/gss`:

`GET /auth/gss`
"""""""""""""""

Requesting a X-Rucio-Auth-Token with curl via kerberos.

**Responses**

 * ``200 OK``
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_get_auth_gss.txt

.. _`GET /auth/x509_proxy`:

`GET /auth/x509_proxy`
""""""""""""""""""""""

Requesting a X-Rucio-Auth-Token with curl via a Globus proxy.

**Responses**

 * ``200 OK``
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_get_auth_x509_proxy.txt


.. _`GET /auth/validate`:

`GET /auth/validate`
""""""""""""""""""""

Check the validity of a authentication token. Checking the validity of a token will extend its lifetime by one hour.

**Responses**

 * ``200 OK``: the token is valid
 * ``401 Unauthorized``: The token is not valid

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_get_auth_validate.txt


.. _`GET /auth/register_api_token`:

`GET /auth/register_api_token`
""""""""""""""""""""""""""""""

**Responses**

**Example Request**


**Example Response**


Account
^^^^^^^

.. _`POST /accounts/{accountName}`:

`POST /accounts/{accountName}`
""""""""""""""""""""""""""""""

Create account.

**Parameters**

+-------------------+-----------+----------------------------------------------+
| Name              | Type      | Description                                  |
+===================+===========+==============================================+
| ``accountType``   | String    | The type of the account (user, group, atlas) |
+-------------------+-----------+----------------------------------------------+

**Responses**

 * ``201 Created``: Account created
 * ``409 Conflict``: Account already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: example_outputs/success-rucio.tests.test_curl.TestCurlRucio.test_post_account.txt
   :lines: 2

.. _`GET /accounts/{accountName}`:

`GET /accounts/{accountName}`
"""""""""""""""""""""""""""""

Get account information.

**Responses**

 * ``200 OK``
 * ``404 Not Found``

**Example Request**

.. literalinclude:: curl_examples/get_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account.out

.. _`PUT accounts/{accountName}`:

`PUT accounts/{accountName}`
""""""""""""""""""""""""""""

Update account information

**Responses**

 * ``200 OK``
 * ``404 Not Found``

**Example Request**

.. literalinclude:: curl_examples/pu_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/put_account.out

.. _`GET accounts/whoami`:

`GET accounts/whoami`
"""""""""""""""""""""

Get information about account whose token is used to sign the request.

**Responses**

 * ``303 See Other``

**Example Request**

.. literalinclude:: curl_examples/get_account_whoami.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account_whoami.out


.. _`GET accounts/`:

`GET accounts/`
"""""""""""""""

List available accounts.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_accounts.sh
   :lines: 2


**Example Response**

.. literalinclude:: curl_examples/get_accounts.out

.. _`DELETE accounts/{accountName}`:

`DELETE accounts/{accountName}`
"""""""""""""""""""""""""""""""

Disable an account.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/del_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_account.out


Location
^^^^^^^^

.. _`POST locations/`:

`POST locations/`
"""""""""""""""""

Create a location

**Parameters**

+-------------------+-----------+--------------------------+
| Name              | Type      | Description              |
+===================+===========+==========================+
| ``locationName``  | String    | The name of the location |
+-------------------+-----------+--------------------------+

**Responses**

 * ``201 Created``: Location created
 * ``409 Conflict``: Location already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_location.out


.. _`GET locations/{locationName}`:

`GET locations/{locationName}`
""""""""""""""""""""""""""""""

Get location information.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_location.out

.. _`GET locations/`:

`GET locations/`
""""""""""""""""

List available locations.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_locations.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_locations.out

.. _`DELETE locations/{locationName}`:

`DELETE locations/{locationName}`
"""""""""""""""""""""""""""""""""

Disable a location.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/del_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_location.out

Rucio Storage Element
^^^^^^^^^^^^^^^^^^^^^

.. _`POST /locations/{locationName}/rses/`:

`POST /locations/{locationName}/rses/`
""""""""""""""""""""""""""""""""""""""

Tag a location with a RSE.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``rseName``       | String    | RSE name               |
+-------------------+-----------+------------------------+
| ``description``   | String    | Description of the RSE |
| (optional)        |           |                        |
+-------------------+-----------+------------------------+

**Responses**

 * ``201 Created``: Location-RSE created
 * ``409 Conflict``: Location-RSE already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_location_rse.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_location_rse.out


.. _`GET locations/{locationName}/rses/`:

`GET locations/{locationName}/rses/`
""""""""""""""""""""""""""""""""""""

List all RSEs associated to a location.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_rses_location_rse.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_rses_location_rse.out

.. _`GET rses/`:

`GET rses/`
"""""""""""

List all RSEs.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``description``   | String    | Description of the RSE |
| (optional)        |           |                        |
+-------------------+-----------+------------------------+

**Responses**

 * ``200 OK``
 * ``404 Not Found``

**Example Request**

.. literalinclude:: curl_examples/get_rses.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_rses.out

.. _`DELETE locations/{locationName}/rses/{rseName}`:

`DELETE locations/{locationName}/rses/{rseName}`
""""""""""""""""""""""""""""""""""""""""""""""""

Remove a location from a RSE.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/del_location_rse.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_location_rse.out

Identity
^^^^^^^^

.. _`POST accounts/{accountName}/identities/`:

`POST accounts/{accountName}/identities/`
"""""""""""""""""""""""""""""""""""""""""

Grant an x509|gss|userpass identity access to an account.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``type``          | String    |  x509|gss|userpass     |
+-------------------+-----------+------------------------+
| ``identity``      | String    | DN|username|gss user   |
+-------------------+-----------+------------------------+

**Responses**

 * ``201 Created``: Account-identity created
 * ``409 Conflict``: Account-identity already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_account_identity.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_account_identity.out

.. _`GET accounts/{accountName}/identities/`:

`GET accounts/{accountName}/identities/`
""""""""""""""""""""""""""""""""""""""""

List all identities on an account.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``type`   `       | String    |  x509|gss|userpass     |
| (optional)        |           |                        |
+-------------------+-----------+------------------------+

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_account_identities.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account_identities.out


.. _`GET identities/{x509|gss|userpass}/{id}/accounts/`:

`GET identities/{x509|gss|userpass}/{id}/accounts/`
"""""""""""""""""""""""""""""""""""""""""""""""""""

List all accounts an identity is member of.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_identity_accounts.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_identity_accounts.out

.. _`DELETE accounts/{accountName}/identities/{x509|gss|userpass}/{id}`:

`DELETE accounts/{accountName}/identities/{x509|gss|userpass}/{id}`
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Revoke an x509|gss|userpass identity's access to an account.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/del_account_identity.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_account_identity.out

Scope
^^^^^

.. _`POST accounts/{accountName}/scopes/`:

`POST accounts/{accountName}/scopes/`
"""""""""""""""""""""""""""""""""""""

Create a scope within an account.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``scopeName``     | String    |  Scope name            |
+-------------------+-----------+------------------------+

**Responses**

 * ``201 Created``: Account-scope created
 * ``409 Conflict``: Account-scope already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_scope.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_scope.out


.. _`GET accounts/{accountName}/scopes/`:

`GET accounts/{accountName}/scopes/`
""""""""""""""""""""""""""""""""""""

Get the scopes for an account.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_account_scopes.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account_scopes.out


.. _`GET scopes/`:

`GET scopes/`
"""""""""""""

List all scopes.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_scopes.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_scopes.out

.. _`DELETE accounts/{accountName}/scopes/{scopeName}`:

`DELETE accounts/{accountName}/scopes/{scopeName}`
""""""""""""""""""""""""""""""""""""""""""""""""""

Delete a scope from an account.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/del_scope.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_scope.out


Dataset
^^^^^^^

.. _`POST datasets/{scopeName}/`:

`POST datasets/{scopeName}/`
""""""""""""""""""""""""""""

Register a dataset.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``datasetName``   | String    |  dataset name          |
+-------------------+-----------+------------------------+
| ``...``           | ...       |   ...                  |
+-------------------+-----------+------------------------+

**Responses**

 * ``201 Created``: Dataset created
 * ``409 Conflict``: Dataset already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_dataset.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_dataset.out

.. _`GET datasets/{scopeName}/{datasetName}/`:

`GET datasets/{scopeName}/{datasetName}/`
"""""""""""""""""""""""""""""""""""""""""

List dataset content.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_dataset_files.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_dataset_files.out


.. _`GET datasets/{scopeName}/{datasetName}`:

`GET datasets/{scopeName}/{datasetName}`
""""""""""""""""""""""""""""""""""""""""

List dataset meta-data.

**Responses**

 * ``200 OK``

**Example Request**

.. literalinclude:: curl_examples/get_dataset_meta.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_dataset_meta.out

.. _`PUT datasets/{datasetName}`:

`PUT datasets/{datasetName}`
""""""""""""""""""""""""""""

Update dataset meta-data.

.. _`POST datasets/{scopeName}/{datasetName}/`:

`POST datasets/{scopeName}/{datasetName}/`
""""""""""""""""""""""""""""""""""""""""""

Add file(s) to a dataset.


.. _`GET datasets/{scopeName}/{datasetName}/{fileName}`:

`GET datasets/{scopeName}/{datasetName}/{fileName}`
""""""""""""""""""""""""""""""""""""""""""""""""""""

Get file meta-data.

.. _`GET datasets/`:

`GET datasets/`
"""""""""""""""


File
^^^^

.. _`POST /locations/{locationName}/files/`:

`POST /locations/{locationName}/files/`
"""""""""""""""""""""""""""""""""""""""

Register a file.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | Description            |
+===================+===========+========================+
| ``fileName``      | String    |  file name             |
+-------------------+-----------+------------------------+
| ``...``           | ...       |   ...                  |
+-------------------+-----------+------------------------+

**Responses**

 * ``201 Created``: File created
 * ``409 Conflict``: File already exists
 * ``401 Unauthorized``

**Example Request**

.. literalinclude:: curl_examples/post_file.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/post_file.out


.. _`GET /files/{scopeName}/locations/`:

`GET /files/{scopeName}/locations/`
"""""""""""""""""""""""""""""""""""

List file replicas.

.. _`PUT /files/{scopeName}/{fileName}/`:

`PUT /files/{scopeName}/{fileName}/`
""""""""""""""""""""""""""""""""""""

Update file meta-data.


.. _`GET /files/{scopeName}/{fileName}`:

`GET /files/{scopeName}/{fileName}`
"""""""""""""""""""""""""""""""""""

.. _`GET files/`:

`GET files/`
"""""""""""""

Search files.

