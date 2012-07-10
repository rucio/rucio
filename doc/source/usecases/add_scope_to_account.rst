..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------------------------
Add scope to account
----------------------------------

.. _add_scope_to_account:

.. sequence-diagram::

   HTTPClient::Client
   Rucio::Server

   HTTPClient:Rucio.POST /accounts/{accountName}/scopes/

Body of the POST is a JSON dictionary with one field: 'scopeName'
