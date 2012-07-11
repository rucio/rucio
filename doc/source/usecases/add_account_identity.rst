..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

--------------------------
Add identity to an account
--------------------------

.. sequence-diagram::

    HTTPClient::
    REST::
    Core::
    DB::

    HTTPClient:REST.PUT accounts/{accountName}/identities/{userpass|x509|gss|proxy}/{identityString}
    REST:Core.addAccountIdentity(accountName, identityType, identityString)
    Core:DB.storeIfNecessary(accountName)
    Core:DB.store(identityType, identityString)
    Core:DB.store(accountName, identityType, identityString)
