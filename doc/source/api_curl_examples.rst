..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0


----------------------------
REST API Examples Using Curl
----------------------------

.. _`GET auth/userpass`:

`GET auth/userpass`
"""""""""""""""""""

Requesting a Rucio-Auth-Token with curl via username and password.

**Example Request**

.. literalinclude:: curl_examples/get_auth_userpass.sh

**Example Response**

.. literalinclude:: curl_examples/get_auth_userpass.out


.. _`GET auth/x509`:

`GET auth/x509`
"""""""""""""""

**Example Request**

.. literalinclude:: curl_examples/get_auth_x509.sh

**Example Response**

.. literalinclude:: curl_examples/get_auth_x509.out


.. _`GET auth/gss`:

`GET auth/gss`
""""""""""""""

**Example Request**

.. literalinclude:: curl_examples/get_auth_gss.sh

**Example Response**

.. literalinclude:: curl_examples/get_auth_gss.out

.. _`GET auth/validate`:

`GET auth/validate`
"""""""""""""""""""

Check the validity of a authentication token.

An HTTP response of 200 OK means the token is valid, and the data returned is the expected lifetime of the token. In case the token is not valid, the response will be a HTTP 401 Unauthorized.

Checking the validity of a token will extend its lifetime by one hour.

**Example Request**

.. literalinclude:: curl_examples/get_auth_validate.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_auth_validate.out

.. _`GET auth/register_api_token`:

`GET auth/register_api_token`
"""""""""""""""""""""""""""""

**Example Request**


**Example Response**


.. _`PUT account/{accountName}`:

`PUT account/{accountName}`
"""""""""""""""""""""""""""

Create account.

**Example Request**

.. literalinclude:: curl_examples/put_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/put_account.out

.. _`GET account/{accountName}`:

`GET account/{accountName}`
"""""""""""""""""""""""""""

Get account information

**Example Request**

.. literalinclude:: curl_examples/get_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account.out

.. _`GET account/whoiam`:

`GET account/whoiam`
""""""""""""""""""""

Get information about account whose token is used to sign the request.

**Example Request**

.. literalinclude:: curl_examples/get_account_whoiam.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_account_whoiam.out


.. _`GET account`:

`GET account`
"""""""""""""

List available accounts.

**Example Request**

.. literalinclude:: curl_examples/get_accounts.sh
   :lines: 2


**Example Response**

.. literalinclude:: curl_examples/get_accounts.out

.. _`DELETE account/{accountName}`:

`DELETE account/{accountName}`
"""""""""""""""""""""""""""""""

Disable an account.

**Example Request**

.. literalinclude:: curl_examples/del_account.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_account.out


.. _`PUT location/{locationName}`:

`PUT location/{locationName}`
"""""""""""""""""""""""""""""

Create a location

**Example Request**

.. literalinclude:: curl_examples/put_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/put_location.out

.. _`GET location/{locationName}`:

`GET location/{locationName}`
"""""""""""""""""""""""""""""

Get location information

**Example Request**

.. literalinclude:: curl_examples/get_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_location.out

.. _`GET location/`:

`GET location/`
"""""""""""""""

List available locations

**Example Request**

.. literalinclude:: curl_examples/get_locations.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_locations.out

.. _`DELETE location/{locationName}`:

`DELETE location/{locationName}`
""""""""""""""""""""""""""""""""

Disable a location.

**Example Request**

.. literalinclude:: curl_examples/del_location.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/del_location.out


.. _`PUT location/{locationName}/rse/{rseName}`:

`PUT location/{locationName}/rse/{rseName}`
"""""""""""""""""""""""""""""""""""""""""""

Tag a location with a RSE.

**Parameters**

+-------------------+-----------+------------------------+
| Name              | Type      | description            |
+===================+===========+========================+
| ``description``   | String    | Description of the RSE |
| (optional)        |           |                        |
+-------------------+-----------+------------------------+

**Example Request**

**Example Response**


.. _`GET location/{locationName}/rse/`:

`GET location/{locationName}/rse/`
""""""""""""""""""""""""""""""""""

.. _`GET rse/`:

`GET rse/`
""""""""""

.. _`DELETE location/{locationName}/rse/{rseName}`:

`DELETE location/{locationName}/rse/{rseName}`
"""""""""""""""""""""""""""""""""""""""""""""""

Remove a location from a RSE.


.. _`PUT scope/{accountName}/{scopeName}`:

`PUT scope/{accountName}/{scopeName}`
"""""""""""""""""""""""""""""""""""""

Create a scope within an account.

**Example Request**

.. literalinclude:: curl_examples/put_scope.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/put_scope.out

.. _`GET scope/{accountName}/`:

`GET scope/{accountName}/`
""""""""""""""""""""""""""

Get the scope for an account

**Example Request**

.. literalinclude:: curl_examples/get_scopes.sh
   :lines: 2

**Example Response**

.. literalinclude:: curl_examples/get_scopes.out


