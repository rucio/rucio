..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0


Installing ATLAS Rucio Clients
===============================

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

Setup CERN AFS client on lxplus
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CERN Quickstart:

- bash::

   $> source /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/bin/activate

- csh::

   $> source /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/bin/activate.csh

By default the RUCIO_ACCOUNT variable is set to the AFS username.

- To test rucio::

   $> rucio ping
   $> rucio whoami
   $> rucio-admin account list-identities $RUCIO_ACCOUNT

Install via pip
~~~~~~~~~~~~~~~

When ``pip`` is available, the distribution can be downloaded from the Rucio PyPI server and installed in one step::

   $> pip install atlas-rucio-clients

This command will download the latest version of Rucio and install it to your system.

Upgrade via pip
~~~~~~~~~~~~~~~

To upgrade via pip::

   $> pip install --upgrade rucio-clients

Install via pip and virtualenv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the Rucio clients in an isolated ``virtualenv`` environment::

   $> cd /tmp
   $> curl -s https://raw.github.com/pypa/virtualenv/master/virtualenv.py | python2.6 - rucio # install virtual env
   $> source rucio/bin/activate
   $> pip install atlas-rucio-clients # install rucio-clients + atlas config
   $> export RUCIO_ACCOUNT=$USER
   $> source rucio/bin/activate
   $> rucio ping

Installing using setup.py
~~~~~~~~~~~~~~~~~~~~~~~~~


Otherwise, you can install from the distribution using the ``setup.py`` script::

   $> python setup.py install


