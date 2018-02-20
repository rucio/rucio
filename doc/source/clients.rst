Rucio Clients
=============

Rucio includes a client class to remove some of the complexity of dealing with raw HTTP
requests against the RESTful API.

Errors and Exceptions
=====================

In the case of an error, Rucio returns a Python Exception with the appropriate Traceback, a detailed error string, and a unique error number. If the error occured on the server side, it will be propagated to the client. The command line clients will exit back to the shell with the POSIX `errno` of the unique Rucio error number. The full and up to date list can be found in the `Exception definition <https://github.com/rucio/rucio/blob/master/lib/rucio/common/exception.py>`_.
