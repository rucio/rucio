Installing Rucio Clients
========================

Prerequisites
~~~~~~~~~~~~~

Rucio clients run on Python 2.7, 3.6, 3.7 and 3.8 on any Unix-like platform.


Python Dependencies
~~~~~~~~~~~~~~~~~~~

Rucio clients need the following python modules:

.. literalinclude:: ../../tools/pip-requires-client
   :lines: 2-

All Dependencies are automatically installed with pip.

Install via pip
~~~~~~~~~~~~~~~

When ``pip`` is available, the distribution can be downloaded from the Rucio PyPI server and installed in one step::

   $> pip install rucio-clients

This command will download the latest version of Rucio and install it to your system.


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
   $> pip install rucio-clients
   $> export RUCIO_HOME=`pwd`/rucio/



Installing using setup.py
~~~~~~~~~~~~~~~~~~~~~~~~~


Otherwise, you can install from the distribution using the ``setup.py`` script::

   $> python setup.py install

Installing with docker
~~~~~~~~~~~~~~~~~~~~~~
