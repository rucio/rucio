..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

--------------------------
Add identity to an account
--------------------------

.. sequence-diagram::

   client:HTTPClient
   rucio:Core

   client:rucio.PUT accounts/{accountName}/identities/{userpass|x509|gss|proxy}/{identityString}

