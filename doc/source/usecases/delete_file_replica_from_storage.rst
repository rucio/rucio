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
     REST::
     Core::
     DB::
     AsynchronousWorkerManager::
     Worker::
     Storage:{locationName}

     HTTPClient:REST.DELETE /location/{locationName}/{scope}/{fileName}
     REST:Core.delete(locationName, scope, fileName)
     Core:DB.store(physicalFileName)
     DB:AsynchronousWorkerManager.notify()/poll()
     AsynchronousWorkerManager:Worker.delegate(deletionJob)
     Worker:Storage.delete(physicalFileName)
