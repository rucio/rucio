----------------------
Upload file into rucio
----------------------

.. _usecase_upload_file_into_rucio:


.. sequence-diagram::
   :maxwidth: 800
   :linewrap: false
   :threadnumber: true

   client:Client
   rucio:Server
   storage:Storage[a]

   client:rucio.registerFileToLocation(**)
   client:storage.uploadFile(**)
   client:rucio.commitRegistration(**)


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
