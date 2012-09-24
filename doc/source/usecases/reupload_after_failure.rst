..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

---------------------------------------
Re-upload a file after an failed upload
---------------------------------------

.. sequence-diagram::

  Client::
  RSE::
  REST::
  Protocol::
  StorageSystem::

  [c loop moreFiles?]
    Client:[files_state]=REST.checkFileStatus(filename)
    [c opt file_state == 'queued']
      Client:REST.updateTracer(filename, 'Re-Uploading')
      Client:RSE.delete(filename)
        RSE:Protocol.delete(filename)
          Protocol:StorageSystem.deleteFile(filename)
        [c opt get failed?]
          RSE:REST.updateTracer(filename, 'DELETE FAILED')
        [/c]
      Client:RSE.put(filename, dataset, scope)
        RSE:Protocol.put(filename)
          Protocol:StorageSystem.putFile(filename)
        RSE:REST.registerFile(filename, dataset, scope, state='active')
        RSE:REST.updateTracer(filename,'uploaded')
        [c opt get failed?]
          RSE:REST.updateTracer(filename, 'PUT FAILED')
        [/c]
    [/c]
  [/c]
