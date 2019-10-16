Setting up a Rucio development environment
==========================================

Prerequisites
--------------

We provide a containerised version of the Rucio development environment for a quick start. Our containers are ready-made for Docker, which means you need to have a working Docker installation. To install Docker for your platform, please refer to the `Docker installation guide <https://docs.docker.com/install/>`_, for example, for Debian/Ubuntu `follow these instructions for the Docker Community Edition <https://docs.docker.com/install/linux/docker-ce/debian/>`_.

Start the Docker daemon with `sudo systemctl start docker`. You can confirm that Docker is running properly by executing (might need `sudo`)::

    docker run hello-world

If successful, this will print an informational message telling you that you are ready to go.  Now, also install the `docker-compose` helper tool, e.g., with `sudo apt install docker-compose`. You are now ready to install the Rucio development environment.

This container can be found on Dockerhub as `rucio/rucio-dev`, and the corresponding `Dockerfile <https://github.com/rucio/containers/tree/master/dev>`_ is also available. It provides a Rucio environment which allows you to mount your local code in the containers `bin`, `lib`, and `tools` directory. The container is set up to run against a PostgreSQL database with fsync and most durability features for the WAL disabled to improve testing IO throughput. Tests and checks can be run against the development code without having to rebuild the container.

Preparing the environment
-------------------------

The first step is to fork the `main Rucio repository on GitHub <https://github.com/rucio/rucio>`_ by clicking the yellow Fork Star button, and then clone your private forked Rucio repository to your `~/dev/rucio`. Afterwards add the main upstream repository as an additional remote to be able to submit pull requests later::

    cd ~/dev
    git clone git@github.com:<your_username>/rucio.git
    cd rucio
    git remote add upstream git@github.com:rucio/rucio.git
    git fetch --all

Now, ensure that the `.git/config` is proper, i.e., mentioning your full name and email address, and that the `.githubtoken` is correctly set. Optionally, you can also replace the `~/dev/rucio/tools/pre-commit` hook with the one provided `here <https://raw.githubusercontent.com/rucio/containers/master/dev/pre-commit>`_ so that `pylint` run in the container rather then in the local system.

Next, setup and configure the Rucio development environment (again might need `sudo`)::

    docker-compose --file etc/docker/dev/docker-compose.yml up -d

And verify that it is running properly::

    docker ps

This should show you a few running containers: the Rucio server, the PostgreSQL database, FTS and its associated MySQL database, the Graphite monitoring, and three XrootD storage servers.

Finally, you can jump into the container with::

    docker exec -it dev_rucio_1 bin/bash

To verify that everything is in order, you can now either run the full unit tests or only set up the database with initial testing data. So again, inside the container, either run the full testing suite (which takes ~10 minutes)::

    tools/run_tests_docker.sh

Or set up the database and create initial testing data, for either demo purposes or when developing functionality that is related to storage interaction and file transfers::

    tools/run_tests_docker.sh -ir

Alternatively, you can bootstrap the test environment once and then selectively run test case modules, test case groups, or even single test cases, for example::

    tools/run_tests_docker.sh -i
    nosetests -v lib/rucio/tests/test_replica.py
    nosetests -v lib/rucio/tests/test_replica.py:TestReplicaCore
    nosetests -v lib/rucio/tests/test_replica.py:TestReplicaCore.test_delete_replicas_from_datasets

Development
-----------

The idea for containerised development is that you use your host machine to edit the files, and test the changes within the container environment. On your host machine, you should be able to simply::

    cd ~/dev/rucio
    emacs <file>

To see your changes in action the recommended way is to jump twice into the container in parallel. One terminal to follow the output of the Rucio server with a shortcut to tail the logfiles (`logshow`), and one terminal to actually run interactive commands:

From your host, get a separate Terminal 1 (the Rucio "server log show")::

   docker exec -it dev_rucio_1 /bin/bash
   logshow

Terminal 1 can now be left open, and then from your host go into a new Terminal 2 (the "interactive" terminal)::

    docker exec -it dev_rucio_1 /bin/bash
    rucio whoami

The command will output in Terminal 2, and at the same time the server debug output will be shown in Terminal 1.

The same `logshow` is also available in the FTS container::

    docker exec -it dev_fts_1 /bin/bash
    logshow

Development tricks
------------------

Server changes
~~~~~~~~~~~~~~

If you edit server-side files, e.g. in `lib/rucio/web`, and your changes are not showing up then it is usually helpful to flush the memcache and force the webserver to restart without having to restart the container. Inside the container execute::

    echo 'flush_all' | nc localhost 11211 && httpd -k graceful

Database access
~~~~~~~~~~~~~~~

The default database is PostgreSQL, and `docker-compose` is configured to open its port to the host machine. Using your favourite SQL navigator, e.g., `DBeaver <https://dbeaver.org>`_, you can connect to the database using the default access on `localhost:5432` to database name `rucio`, schema name `dev`, with username `rucio` and password `secret`.

Docker is eating my disk space
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can reclaim this with::

    docker system prune -f --volumes

Unleash the daemons
~~~~~~~~~~~~~~~~~~~
Daemons are not running in the docker environment, but all daemons support the --run-once arguemnt. E.g., after do the initialization with::

   tools/run_tests_docker.sh -ir

Some files are created. Let's add them to a new dataset::

   rucio add-dataset test:mynewdataset
   rucio attach test:mynewdataset test:file1 test:file2 test:file3 test:file4

As you can see if you run the command below, the files are not in the RSE XRD3, but in XRD1 and 2.::
   rucio list-file-replicas test:mynewdataset
   > +---------+--------+------------+-----------+------------------------------------------------+
   > | SCOPE   | NAME   | FILESIZE   | ADLER32   | RSE: REPLICA                                   |
   > |---------+--------+------------+-----------+------------------------------------------------|
   > | test    | file1  | 10.486 MB  | 141a641e  | XRD1: root://xrd1:1094//rucio/test/80/25/file1 |
   > | test    | file2  | 10.486 MB  | fdfa7eea  | XRD1: root://xrd1:1094//rucio/test/f3/14/file2 |
   > | test    | file3  | 10.486 MB  | c669167d  | XRD2: root://xrd2:1095//rucio/test/a9/23/file3 |
   > | test    | file4  | 10.486 MB  | 65786e49  | XRD2: root://xrd2:1095//rucio/test/2b/c2/file4 |
   > +---------+--------+------------+-----------+------------------------------------------------+
   
   
So let's add a new rule over our new dataset to oblige rucio to create replicas also in XRD3 RSE::

    rucio add-rule test:mynewdataset 1 XRD3
    > 1aadd685d891400dba050ad43e71fea9

Now we can check the status of the rule. We will see there are 4 files in `Replicating` state::

   rucio rule-info 1aadd685d891400dba050ad43e71fea9|grep Locks
   > Locks OK/REPLICATING/STUCK: 0/4/0

Now we can run the deamons. First judge-evaluator will pick up our rule. Then the conveyor-submitter will send the created transfers to the FTS server. After that, the conveyor-poller will wait till FTS send the signal indicating the replicas was created. Finally, the conveyor-finisher will update the internal state of Rucio to reflect the changes.::

   rucio-judge-evaluator --run-once
   rucio-conveyor-submitter --run-once
   rucio-conveyor-poller --run-once
   rucio-conveyor-finisher --run-once

If we see the state of the rule now, we see the locks are OK::

   rucio rule-info 1aadd685d891400dba050ad43e71fea9|grep Locks
   > Locks OK/REPLICATING/STUCK: 4/0/0

And if we look at the replicas of the dataset, we see the there are copies of the files also in XRD3::

   rucio list-file-replicas test:mynewdataset
   > +---------+--------+------------+-----------+------------------------------------------------+
   > | SCOPE   | NAME   | FILESIZE   | ADLER32   | RSE: REPLICA                                   |
   > |---------+--------+------------+-----------+------------------------------------------------|
   > | test    | file1  | 10.486 MB  | 141a641e  | XRD3: root://xrd3:1096//rucio/test/80/25/file1 |
   > | test    | file1  | 10.486 MB  | 141a641e  | XRD1: root://xrd1:1094//rucio/test/80/25/file1 |
   > | test    | file2  | 10.486 MB  | fdfa7eea  | XRD3: root://xrd3:1096//rucio/test/f3/14/file2 |
   > | test    | file2  | 10.486 MB  | fdfa7eea  | XRD1: root://xrd1:1094//rucio/test/f3/14/file2 |
   > | test    | file3  | 10.486 MB  | c669167d  | XRD2: root://xrd2:1095//rucio/test/a9/23/file3 |
   > | test    | file3  | 10.486 MB  | c669167d  | XRD3: root://xrd3:1096//rucio/test/a9/23/file3 |
   > | test    | file4  | 10.486 MB  | 65786e49  | XRD2: root://xrd2:1095//rucio/test/2b/c2/file4 |
   > | test    | file4  | 10.486 MB  | 65786e49  | XRD3: root://xrd3:1096//rucio/test/2b/c2/file4 |
   > +---------+--------+------------+-----------+------------------------------------------------+


