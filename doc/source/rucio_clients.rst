..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

=============
Rucio Clients
=============


Rucio includes a client class to removes some of the complexity of dealing with raw HTTP requests against the RESTful API.

In the example below, which shows how to instanciate a Rucio Client, we assume that there is a Rucio server running on the localhost on port 80/443.

.. literalinclude:: clients_examples/rucio_client_example.py
   :language: python
   :lines: 12-15

Some other examples of using Rucio’s Client class can be found here: :doc:`client_examples`.
