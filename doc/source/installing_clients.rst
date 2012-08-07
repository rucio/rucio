..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0


Installing Rucio Clients
========================

Prerequisites
~~~~~~~~~~~~~

Rucio clients runs on Python 2.6, 2.7.

Platforms: Rucio should run on any Unix-like platform.


Python Dependencies
~~~~~~~~~~~~~~~~~~~

Rucio clients need the following python modules:

.. literalinclude:: ../../tools/pip-requires-client
   :lines: 2-

All Dependencies are automatically installed with pip.

Install via pip
~~~~~~~~~~~~~~~

When ``pip`` is available, the distribution can be downloaded from the Rucio PyPI server and installed in one step::

   $> pip install rucio-clients -i http://atlas-pip.cern.ch/simple

This command will download the latest version of Rucio and install it to your system.

it will ask for the password and login.

To avoid this, you need to create a :file:`~/.pip/pip.conf` with::

    [install]
    index-url =
        http://pypi.python.org/simple

    extra-index-url=
        http://<username>:<password>@atlas-pip.cern.ch/simple

- *username*, which is the registered username on the PyPI server.
- *password*, that will be used to authenticate. If omitted the user
    will be prompt to type it when needed.

Upgrade via pip
~~~~~~~~~~~~~~~

To upgrade via pip::

   $> pip install --upgrade rucio-clients

Install via pip and virtualenv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the Rucio clients in an isolated ``virtualenv`` environment::

   $> wget --no-check-certificate https://raw.github.com/pypa/virtualenv/master/virtualenv.py
   $> python virtualenv.py rucio
   $> source rucio/bin/activate.csh
   $> pip install rucio-clients -i http://atlas-pip.cern.ch/simple
   $> export RUCIO_HOME=`pwd`/rucio/



Installing using setup.py
~~~~~~~~~~~~~~~~~~~~~~~~~


Otherwise, you can install from the distribution using the ``setup.py`` script::

   $> python setup.py install
