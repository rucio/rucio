..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

---------------------------------
Download files from rucio/storage
---------------------------------

.. sequence-diagram::

  Client::
  RSE::
  REST::
  Protocol::

  Client:RSE.get(filenames[])
  [c loop moreFiles?]
    RSE:[files_state]=REST.checkFileStatus(filename)
    [c opt file_state == 'active']
      RSE:Protocol.get(filename)
      RSE:REST.updateTracer(filename, 'GET')
      [c opt get failed?]
        RSE:REST.updateTracer(filename, 'GET FAILED')
      [/c]
    [/c]
  [/c]
