..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

-----------------------
Authenticate with rucio
-----------------------

.. sequence-diagram::

    HTTPClient::
    REST::
    Authentication::
    Core::
    DB::

    HTTPClient:X-Rucio-Auth-Token=REST.GET auth/{userpass|x509|gss|proxy}
    REST:X-Rucio-Auth-Token=Authentication.authorize(credentials)
    Authentication:DB.store(X-Rucio-Auth-Token)

Every API call needs to provide a valid X-Rucio-Auth-Token. This authentication handshake is therefore omitted from the other sequence diagrams.

The client needs to provide the appropriate credentials for the authentication to succeed:

* ``userpass``

HTTP Header: "Rucio-Username=<username>"

HTTP Header: "Rucio-Password=<password>"

* ``x509``

The client needs to present a valid x509 client certificate.

* ``gss``

The client needs to present a valid Kerberos5/GSSAPI authentication token.

* ``proxy``

The client needs to present a valid Globus proxy certificate.


---------------------------
Validate a X-Rucio-Auth-Token
---------------------------

.. sequence-diagram::

    HTTPClient::
    REST::
    Authentication::
    Core::
    DB::

    HTTPClient:[true|false]=REST.GET auth/validate
    REST:[true|false]=Authentication.validate(X-Rucio-Auth-Token)
    Authentication:storedCredentials=DB.retrieve(X-Rucio-Auth-Token)
    Authentication:[true|false]=Authentication.validIfStoredCredentialsFound()
