..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0


Installing Rucio server
=======================

Prerequisites
~~~~~~~~~~~~~

Rucio server runs on Python 2.6, 2.7.

Platforms: Rucio should run on any Unix-like platform.

Python Dependencies
~~~~~~~~~~~~~~~~~~~

Rucio server needs the following python modules:

.. literalinclude:: ../../tools/pip-requires
   :lines: 2-8

All Dependencies are automatically installed with pip.

Install via puppet
~~~~~~~~~~~~~~~~~~

puppet_ is an open and widely configuration management and automation system, for managing the infrastructure.

.. _puppet: http://puppetlabs.com/


1. On the target node: start with a clean slate::

   $> rm -rf /opt/rucio


2. On the puppet master: install with puppet

   do something like this in /etc/puppet/manifests/nodes.pp::

    node '<hostname>' inherits basenode
    {
      include 'rucio::lighttpd'
      include 'rucio::server-dev'
    }

  then execute and wait::

   $> puppet kick <hostname>


3. back to the target node: configure::

   $> cd /opt/rucio/etc
   $> cp rucio.cfg.template rucio.cfg
   $> cd web
   $> cp lighttpd.conf.template lighttpd.conf


4. startup lighttpd::

   $> cd /opt/rucio
   $> bin/venv_lighttpd.sh


5. test::

   $> curl -vvv -X GET -H "Rucio-Account: ddmlab" -H "Rucio-Username: xxxxx" -H "Rucio-Password: xxxx" https://localhost/auth/userpass

you should get back an HTTP OK with a X-Rucio-Auth-Token in the HTTP header
