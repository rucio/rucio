The Client API Reference
========================

Rucio includes a client class to remove some of the complexities of dealing with raw
HTTP requests against the RESTful API.

All client methods are accessible through the high-level class Client. Below is one
example of using Rucio Client class::

   >>> from rucio.client import Client
   >>> CLIENT = Client()
   >>> CLIENT.ping()


The methods are separated per resource type.

.. toctree::
    :maxdepth: 1

    api/account
    api/accountlimit
    api/scope
    api/did
    api/meta-data
    api/rse
    api/replica
    api/rule
    api/lock
    api/subscription
    api/lifetime
    api/touch
    api/config
    api/exception
    api/ping

..  To add:
..  api/upload
..  api/download


