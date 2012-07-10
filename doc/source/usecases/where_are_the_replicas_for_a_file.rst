..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------------------------
Where are the replicas for a file
----------------------------------

.. _where_are_the_replicas_for_a_file:

.. sequence-diagram::

   HTTPClient::Client
   Rucio::Server

   HTTPClient:[locations]=Rucio.POST /files/{scopeName}/locations/
