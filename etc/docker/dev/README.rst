Setting up a Rucio development environment
==========================================

Prerequisites
--------------

We provide a containerised version of the Rucio development environment for a quick start. Our containers are ready-made for Docker, which means you need to have a working Docker installation. To install Docker for your platform, please refer to the `Docker installation guide <https://docs.docker.com/install/>`_, for example, for Debian/Ubuntu `follow these instructions for the Docker Community Edition <https://docs.docker.com/install/linux/docker-ce/debian/>`_.

You can confirm that Docker is running properly by executing (might need `sudo`)::

    docker run hello-world

If successful, this will print an informational message telling you that you are ready to go.  Now, also install the `docker-compose` helper tool, e.g., with `sudo apt install docker-compose`, and then start the Docker daemon with `sudo systemctl start docker`. You are now ready to install the Rucio development environment.

Preparing the environment
-------------------------

This container can be found on Dockerhub as `rucio/rucio-dev`, and the corresponding `Dockerfile <https://https://github.com/mlassnig/containers/tree/master/dev>`_ is also available. It provides a Rucio environment which allows you to mount your local code in the containers `bin`, `lib`, and `tools` directory. The container is set up to run against a PostgreSQL database. Tests and checks can be run against the development code without having to rebuild the container.

The first step is to fork the `main Rucio repository on GitHub <https://github.com/rucio/rucio>`_ by clicking the yellow Fork Star button, and then clone your private forked Rucio repository to your `~/dev/rucio`. Afterwards add the main upstream repository as an additional remote to be able to submit pull requests later::

    cd ~/dev
    git clone git@github.com:<your_username>/rucio.git
    cd rucio
    git remote add upstream git@github.com:rucio/rucio.git
    git fetch --all

Now, ensure that the `.git/config` is proper, i.e., mentioning your full name and email address, and that the `.githubtoken` is correctly set. Optionally, you can also replace the `~/dev/rucio/tools/pre-commit` hook with the one provided `here <https://github.com/rucio/rucio/blob/master/etc/docker/dev/pre-commit>`_ so that `pylint` run in the container rather then in the local system.

Next, setup and configure the Rucio development environment (again might need `sudo`)::

   docker-compose --file etc/docker/dev/docker-compose.yml up -d

And verify that it is running properly::

    docker ps

This should show you three running containers: the Rucio server, the Graphite monitoring, and the PostgreSQL database.

Finally, you have to bootstrap the database, so inside the container run::

    docker exec -it dev_rucio_1 bin/bash
    tools/reset_database.sh

To verify that everything is in order, you can now run the unit tests. So again, inside the container::

    tools/run_tests_docker.sh

Development
-----------

The idea for containerised development is that you use your host machine to edit the files, and test the changes within the container environment. On your host machine, you should be able to simply::

    cd ~/dev/rucio
    emacs <file>

To see your changes in action the recommended way is to jump twice into the container in parallel. One terminal to follow the output of the Rucio server, and on terminal to run interactive commands:

From your host, get a separate Terminal 1 (the Rucio "server watcher")::

   docker exec -it dev_rucio_1 /bin/bash
   tail -f /var/log/httpd/*log /var/log/rucio/*log

Terminal 1 can now be left open, and then from your host go into a new Terminal 2 (the "interactive" terminal)::

    docker exec -it dev_rucio_1 /bin/bash
    rucio whoami

The command will output in Terminal 2, and at the same time the server debug output will be shown in Terminal 1.

Development tricks
------------------

Server changes
~~~~~~~~~~~~~~

If you edit server-side files, e.g. in `lib/rucio/web/`, and your changes are not showing up then it is usually helpful to flush the memcache and force the webserver to restart without having to restart the container. Inside the container execute::

    echo 'flush_all' | nc localhost 11211 && httpd -k graceful

Database access
~~~~~~~~~~~~~~~

The default database is PostgreSQL, and `docker-compose` is configured to open its port to the host machine. Using your favourite SQL navigator, e.g., `DBeaver <https://dbeaver.org>`_, you can connect to the database using the default access on `localhost:5432` to database name `rucio`, schema name `dev`, with username `rucio` and password `secret`.


Manual setup without docker-compose
-----------------------------------

The container environment may also be setup by hand. First setup the PostgreSQL server::

    docker run -it -d --name psql \
               -e POSTGRES_USER=rucio \
               -e POSTGRES_DB=rucio \
               -e POSTGRES_PASSWORD=secret \
               -p 5432:5432 \
               postgres:11

And to provide a server for Rucio monitoring to report to::

    docker run -d \
               --name graphite \
               --restart=always \
               -p 80:80 \
               -p 2003-2004:2003-2004 \
               -p 2023-2024:2023-2024 \
               -p 8125:8125/udp \
               -p 8126:8126 \
               graphiteapp/graphite-statsd

Then start the Rucio container::

    docker run -it -d --name rucio \
               -p 443:443 \
               -v `pwd`/tools/:/opt/rucio/tools \
               -v `pwd`/bin/:/opt/rucio/bin \
               -v `pwd`/lib/:/opt/rucio/lib \
               --link psql:psql \
               --link graphite:graphite \
               rucio/rucio-dev
