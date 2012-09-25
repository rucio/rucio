..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

======================
Rucio Clients Examples
======================


Below are some examples of using Rucio’s Client class. We assume that there is
a Rucio server running on the localhost on port 80/443.

.........................................................

Service
^^^^^^^

.. _`client_ping`:

``ping``
"""""""""

Discover server version information.

.. literalinclude:: ../../lib/rucio/tests/test_clients.py
   :language: python
   :lines: 31-35


.........................................................

Account
^^^^^^^

.. _`client_add_account`:

``create_account``
""""""""""""""""""

Add an account.

.. literalinclude:: clients_examples/add_account.py
   :language: python
   :lines: 12-

