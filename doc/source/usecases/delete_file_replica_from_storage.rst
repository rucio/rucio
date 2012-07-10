..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

-------------------------------------------
Delete a file replica from a storage system
-------------------------------------------

.. sequence-diagram::

    HTTPClient::
    Rucio::
    Storage:{locationName}

    HTTPClient:Rucio.DELETE /location/{locationName}/{scope}/{fileName}
    Rucio:Storage.delete({physicalFileName})
