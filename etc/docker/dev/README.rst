==========================================
Setting up a Rucio development environment
==========================================

Prerequisites
--------------

Setting up a Rucio development environment requires to have Docker installed. Docker is an
application that makes it simple and easy to run application processes. To install Docker for
your platform, please refer to the `Docker installation guide <https://docs.docker.com/install/>`_.

Container for Development
-------------------------

The Dockerfile in this container is used to centrally produce the docker container available as rucio/rucio-dev. It
provides a rucio environment which allow you to mount your local code in the containers bin, lib, and tools directory. The
container is set up to run against a mysql database called rucio with user rucio, password rucio. Tests and checks may be
run against the development code without having to rebuild the environment for each test.

docker-compose
--------------

YAML for docker compose has been provided to allow easily setup the containers from the rucio code directory::

   $> docker-compose --file etc/docker/dev/docker-compose.yml up -d

The names of the two containers (rucio and mysql) should be printed in the terminal for you.

Docker By Hand
--------------

The container environment may also be setup by hand. First setup the mysql server::

   $> docker run -it -d --name mysql \
           -e MYSQL_RANDOM_ROOT_PASSWORD=True \
           -e MYSQL_DATABASE=rucio \
           -e MYSQL_USER=rucio \
           -e MYSQL_PASSWORD=rucio \
           mysql/mysql-server:5.7

And to provide a server for rucio monitoring to report to:

  $> docker run -d\
                --name graphite\
                --restart=always\
                -p 80:80\
                -p 2003-2004:2003-2004\
                -p 2023-2024:2023-2024\
                -p 8125:8125/udp\
                -p 8126:8126\
                graphiteapp/graphite-statsd

Then start the rucio container::

   $> docker run -it -d --name rucio -p "443:443" \
           -v `pwd`/tools/:/opt/rucio/tools \
           -v `pwd`/bin/:/opt/rucio/bin \
           -v `pwd`/lib/:/opt/rucio/lib \
           --link mysql:mysql \
           rucio/rucio-dev


Running Tests
-------------

You should have something like this::

   $> docker ps
   CONTAINER ID        IMAGE                         COMMAND                  CREATED             STATUS                    PORTS                        NAMES
   5bbf88de58a7        graphiteapp/graphite-statsd   "/sbin/my_init"           2 hours ago        Up 2 hours                0.0.0.0:80->80/tcp, ...     dev_graphite_1
   3d9dfb317ada        rucio-dev                     "httpd -D FOREGROUND"    28 minutes ago      Up 28 minutes             0.0.0.0:443->443/tcp        dev_rucio_1
   88a5ad6cf6d0        mysql/mysql-server:5.7        "/entrypoint.sh my..."   28 minutes ago      Up 28 minutes (healthy)   3306/tcp, 33060/tcp         dev_mysql_1


Note that the names of the containers may end up looking different on your system. To run the test suite use `docker exec` with the rucio container, e.g.::

   $> docker exec -it dev_rucio_1 tools/run_tests_docker.sh

If needed, it is also possible to login directly to the container::

   $> docker exec -it dev_rucio_1 /bin/bash

Git Hook
--------

Replace the `pre-commit` hook provided in `tools` with the one provided `here <https://github.com/rucio/rucio/blob/master/etc/docker/dev/pre-commit>`_.
It runs `pylint` in the rucio development container rather then in the local system.
