..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------------
Upload file into rucio
----------------------

.. _usecase_upload_file_into_rucio:


.. sequence-diagram::

   PythonClient::
   Rucio::
   Storage::{locationName}

   PythonClient:Rucio.registerFileToLocation()
   PythonClient:Storage.uploadFile()
   PythonClient:Rucio.commitTransaction()

Replica can be in one the following statuses:

* ``queued``

  The replica identifier has been reserved and no data has been uploaded.


* ``active``

  Denotes a replica that is fully available.


.. graphviz::

   digraph foo {
    rankdir=LR;
    size="4"

    node [shape = circle]; queued;
    node [shape = point ]; qi;
    node [shape = circle]; active;
    node [shape = point ]; qf;

    qi -> queued;
    queued  -> active [ label = "commitRegistration" ];
    active -> qf;
   }
