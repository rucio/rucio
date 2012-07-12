..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------------------------
Register account
----------------------------------

.. _register_account:

.. sequence-diagram::

   HTTPClient::
   REST::
   Rucio::

   HTTPClient:REST.POST /accounts/
   REST:Rucio.add_account(accountName, accountType)
   

Body of the POST is a JSON dictionary with two fields: 'accountName' and 'accountType'
