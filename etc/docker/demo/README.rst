..  Copyright 2018 CERN for the benefit of the ATLAS collaboration.
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.

     Authors:
   - Thomas Beermann <thomas.beermann@cern.ch>, 2018
   - Cedric Serfon <cedric.serfon@cern.ch>, 2018
   - Vincent Garonne <vgaronne@gmail.com>, 2018

===================================
Setting up a Rucio demo environment
===================================

Prerequisites
--------------

Setting up a Rucio demo environment requires to have `docker` and `docker-compose`
installed. Docker is an application that makes it simple and easy to run
application processes. To install Docker for your platform, please refer to
the `Docker installation guide <https://docs.docker.com/install/>`_.
`Git` should be also `installed <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`_.

The containers provided here can be used to easily setup a small demo instance of
Rucio with some mock data to play around with some Rucio commands.

docker-compose
---------------

A YAML file for `docker-compose` has been provided to allow easily setup of the containers.
to have access to this `docker-compose.yml file <https://github.com/rucio/rucio/blob/master/etc/docker/demo/docker-compose.yml>`_,
you can either:

- `clone <https://help.github.com/articles/cloning-a-repository/>`_ the `Rucio repository <https://github.com/rucio/rucio/>`_,
- or `fork and clone <https://help.github.com/articles/fork-a-repo/>`_ the `Rucio repository <https://github.com/rucio/rucio/>`_ for the ones who want to `contribute <https://github.com/rucio/rucio/blob/master/CONTRIBUTING.rst>`_ to Rucio,

To run the multi-container Rucio Docker applications, do::

    > $ sudo docker-compose --file etc/docker/demo/docker-compose.yml up -d

Here we assume that the command is executed at the root of the Rucio cloned repository.

The names of the two containers (rucio and mysql) should be printed in the terminal for you.

Checking the containers
-----------------------

After you run the docker-compose command you can check the status of the containers::

    > $ sudo docker ps
    CONTAINER ID        IMAGE                    COMMAND                  CREATED             STATUS                     PORTS                  NAMES
    ad03d8dc3b4a        demo_rucio               "httpd -D FOREGROUND"    13 minutes ago      Up 13 minutes              0.0.0.0:443->443/tcp   demo_rucio_1
    8d5f8253f3d8        mysql/mysql-server:5.7   "/entrypoint.sh mysql"   13 minutes ago      Up 13 minutes (healthy)    3306/tcp, 33060/tcp    demo_mysql_1

Initial setup of demo data
--------------------------

After the first start of the demo containers you will have to setup the demo account
and the demo data to be able to use the Rucio commands and the WebUI. To do this you
have to simply run the following command::

    $ sudo docker exec -it demo_rucio_1 /setup_demo.sh

You might see the following error message::
    ...
    sqlalchemy.exc.OperationalError: (_mysql_exceptions.OperationalError) (2003, "Can't connect to MySQL server on 'mysql' (111)") (Background on this error at: http://sqlalche.me/e/e3q8)

This only means that the MySQL container is not ready, yet, and you just have to wait a
moment before you try again. If everything worked fine you should see something like
this::

    INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
    INFO  [alembic.runtime.migration] Running stamp_revision  -> 2962ece31cf4
    Start Automatix
    2018-02-27 12:26:33,216 68      DEBUG   Still 1 active threads
    2018-02-27 12:26:33,718 68      INFO    Thread [1/1] : Getting data distribution
    2018-02-27 12:26:33,719 68      DEBUG   Thread [1/1] : Probabilities {u'type1': 1.0}
    2018-02-27 12:26:33,719 68      INFO    Thread [1/1] : Running on site SITE1_DISK
    2018-02-27 12:26:33,720 68      INFO    Thread [1/1] : Generating file /tmp/tmpOX4uPw/AOD.735cd55130fb4852b8b41656428820fc in dataset tests:test.1925.automatix_stream.recon.AOD.496
    2018-02-27 12:26:33,735 68      DEBUG
    2018-02-27 12:26:33,735 68      DEBUG   1+0 records in
    1+0 records out
    1000000 bytes (1.0 MB) copied, 0.00734248 s, 136 MB/s
    ...

To test that Rucio is set up correctly you can do a ping and you should
get the rucio version::
    $ sudo docker exec -it demo_rucio_1 rucio ping
    1.15.0

Using the container
-------------------

When everything is ready you can log into the container
and start playing around with rucio::

    $ sudo docker exec -it demo_rucio_1 /bin/bash
    [root@ad03d8dc3b4a rucio]# rucio whoami
    status     : ACTIVE
    account    : root
    account_type : SERVICE
    created_at : 2018-02-08T15:37:26
    suspended_at : None
    updated_at : 2018-02-08T15:37:26
    deleted_at : None
    email      : None
    [root@ad03d8dc3b4a rucio]# rucio list-scopes
    tests
    user.jdoe
    [root@ad03d8dc3b4a rucio]#

Stopping the demo
-----------------

To stop the demo, you can do::

    $ docker-compose --file etc/docker/demo/docker-compose.yml down

Accessing the WebUI
-------------------

In the demo container is also an instance of the Rucio WebUI started.

To be able to access it you will first have to install the demo client
certificate in your browser. You can find the p12 file containing the
certificate under::

    etc/docker/demo/certs/rucio_demo_cert.p12

The import password is `rucio-demo`.

Then you can access the WebUI using this url: ´https://<hostname>/ui/´

Normally, it's https://localhost/ui/
