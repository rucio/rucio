..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

---------------------------------------------
Register a transfer request for a file in FTS
---------------------------------------------

.. sequence-diagram::

    HTTPClient::
    Rucio::
    TransferService:FTS

    HTTPClient:Transfer-ID=Rucio.POST /transfer/file
    Rucio:Transfer-ID=TransferService.submit({fileName,source,destination})
