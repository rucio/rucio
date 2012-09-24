..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

------------------------------------------------------------------------
Download all files from a given list of file replicas from rucio/storage
------------------------------------------------------------------------

List of file replicas = FileURI?

.. sequence-diagram::

  Client::
  RSE::
  REST::
  Protocol::

  Client:RSE.get(filelist[])
  [c loop moreFiles?]
    RSE:[files_state]=REST.checkFileStatus(fileuri)
    [c opt file_state == 'active']
      RSE:Protocol.get(fileuri)
      RSE:REST.updateTracer(fileuri, 'GET')
      [c opt get failed?]
        RSE:REST.updateTracer(fileuri, 'GET FAILED')
      [/c]
    [/c]
  [/c]
