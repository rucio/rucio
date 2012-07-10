..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

-------------------------
Add Metadata to a dataset
-------------------------

.. sequence-diagram::

   HTTPClient::
   Rucio::

   HTTPClient:Rucio.POST datasets/{scope}/{datasetName}/metadata

Body must be a JSON dictionary containing the appropriate key/value mappings.
