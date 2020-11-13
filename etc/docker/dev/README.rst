Setting up a Rucio development environment
==========================================

Prerequisites
--------------

We provide a containerised version of the Rucio development environment for a quick start. Our containers are ready-made for Docker, which means you need to have a working Docker installation. To install Docker for your platform, please refer to the `Docker installation guide <https://docs.docker.com/install/>`_, for example, for CentOS `follow these instructions for the Docker Community Edition <https://docs.docker.com/install/linux/docker-ce/centos/>`_. Please make sure that you install this recent Docker version especially if you are on CentOS, i.e. its default version is ancient and does not support some features we rely on.

Start the Docker daemon with `sudo systemctl start docker`. You can confirm that Docker is running properly by executing (might need `sudo`)::

    docker run hello-world

If successful, this will print an informational message telling you that you are ready to go.  Now, also install the `docker-compose` helper tool with `sudo yum install docker-compose` (might need `EPEL <https://fedoraproject.org/wiki/EPEL>`_ enabled). You are now ready to install the Rucio development environment.

Preparing the environment
-------------------------

The first step is to check if SELinux is running. SELinux will block access to the directories mounted inside the container, and so depending on you node might need to be put in permissive mode with `setenforce permissive`.

The second step is to fork the `main Rucio repository on GitHub <https://github.com/rucio/rucio>`_ by clicking the yellow Fork Star button, and then clone your private forked Rucio repository to your `~/dev/rucio`. Afterwards add the main upstream repository as an additional remote to be able to submit pull requests later on::

    cd ~/dev
    git clone git@github.com:<your_username>/rucio.git
    cd rucio
    git remote add upstream git@github.com:rucio/rucio.git
    git fetch --all

Now, ensure that the `.git/config` is proper, i.e., mentioning your full name and email address, and create the `.githubtoken` file that contains a full access token from `Github Account Settings <https://github.com/settings/tokens>`_.

Next, startup the Rucio development environment with docker-compose. There are three different types: a standard one to just run the unittests and do basic development, which includes just Rucio without any transfer capabilities. One slightly larger one, which includes the File Transfer Service (FTS) and three XrootD storage servers to develop upload/download and transfers capabilities. And a third large one, which adds the full monitoring stack with Logstash, Elasticsearch, Kibana and Grafana.

Using the standard environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the containers using docker-compose (again might need `sudo`)::

    docker-compose --file etc/docker/dev/docker-compose.yml up -d

And verify that it is running properly::

    docker ps

This should show you a few running containers: the Rucio server, the PostgreSQL database and the Graphite monitoring.

Finally, you can jump into the container with::

    docker exec -it dev_rucio_1 /bin/bash

To verify that everything is in order, you can now either run the full unit tests or only set up the database. Running the full testing suite takes ~10 minutes::

    tools/run_tests_docker.sh

Alternatively, you can bootstrap the test environment once with the `-i` option and then selectively or repeatedly run test case modules, test case groups, or even single test cases, for example::

    tools/run_tests_docker.sh -i
    pytest -vvvrxs lib/rucio/tests/test_replica.py
    pytest -vvvrxs lib/rucio/tests/test_replica.py:TestReplicaCore
    pytest -vvvrxs --full-trace lib/rucio/tests/test_replica.py:TestReplicaCore.test_delete_replicas_from_datasets

Using the environment including storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Again run the containers using docker-compose::

    docker-compose --file etc/docker/dev/docker-compose-storage.yml up -d

This should show you a few more running containers: the Rucio server, the PostgreSQL database, FTS and its associated MySQL database, the Graphite monitoring, and three XrootD storage servers.

With this container you can upload and download data to/from the storage and submit data transfers. To set this up, add the `-r` option to the setup.

    tools/run_tests_docker.sh -ir

This creates a few random files and uploads them, creates a few datasets and containers, and requests a replication rule for the container, which starts in state REPLICATING. To demonstrate the transfer capability, the daemons can be run in single-execution mode in order:

    rucio rule-info <rule-id>

    rucio-conveyor-submitter --run-once
    rucio-conveyor-poller --run-once --older-than 0
    rucio-conveyor-finisher --run-once

    rucio rule-info <rule-id>

On the second display of the rule, its state has cleared to OK.

Using the environment including monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Again run the containers using docker-compose::

    docker-compose --file etc/docker/dev/docker-compose-storage-monit.yml up -d


Now you will have the same containers as before plus a full monitoring stack with Logstash, Elasticsearch, Kibana and Grafana.

To create some events and write them to Elasticsearch first run again the tests as before::

    tools/run_tests_docker.sh -ir


Then you will have to run the transfer daemons (conveyor-*) and messaging daemon (hermes) to send the events to ActiveMQ. There a script for that which repeats these daemons in single execution mode from the section in a loop::

    run_daemons


When all the daemons ran you will be able to find the events in Kibana. If you run the docker environment on you local machine you can access Kibana at http://localhost:5601. The necessary index pattern will be added automatically. There is also one dashboard available in Kibana. If it is running on remote machine you can SSH forward it::

    ssh -L 5601:127.0.0.1:5601 <hostname>


Additionally, there is also a Grafana server running with one simple dashboard. You can access it at http://localhost:3000. The default credentials are "admin/admin". Also ActiveMQ web console can be accessed at http://localhost:8161.

If you would like to continously create some transfers and events there are scripts available for that. Open two different shells and in one run::

    create_monit_data


And in the other run::

    run_daemons


Development
-----------

The idea for containerised development is that you use your host machine to edit the files, and test the changes within the container environment. On your host machine, you should be able to::

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


Where do I find the Dockerfile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This container can be found on Dockerhub as `rucio/rucio-dev`, and the corresponding `Dockerfile <https://github.com/rucio/containers/tree/master/dev>`_ is also available. It provides a Rucio environment which allows you to mount your local code in the containers `bin`, `lib`, and `tools` directory. The container is set up to run against a PostgreSQL database with fsync and most durability features for the WAL disabled to improve testing IO throughput. Tests and checks can be run against the development code without having to rebuild the container.


I need a Docker based on another branch (not rucio/master)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In such case, you can download the Rucio container files and e.g. choose to modify the dev container before build::

  cd /opt
  sudo git clone https://github.com/rucio/containers
  cd ../containers/dev


Change anything you need, e.g. the code branch cloned to your docker container::

  # from
  RUN git clone https://github.com/rucio/rucio.git /tmp/rucio
  # to e.g.:
  RUN git clone --single-branch --branch next https://github.com/rucio/rucio.git /tmp/rucio


# build your docker
sudo docker build -t rucio/rucio-dev .

Compose as usual using docker-compose::

  cd /opt/rucio
  sudo docker-compose --file etc/docker/dev/docker-compose.yml up -d



Start the daemons
~~~~~~~~~~~~~~~~~~~

Daemons are not running in the docker environment, but all daemons support single-execution mode with the --run-once argument. Reset the system first with::

   tools/run_tests_docker.sh -ir


Some files are created. Let's add them to a new dataset::

   rucio add-dataset test:mynewdataset
   rucio attach test:mynewdataset test:file1 test:file2 test:file3 test:file4


If you run the command below, the files are not in the RSE XRD3, but only in XRD1 and 2.::

   rucio list-file-replicas test:mynewdataset
   > +---------+--------+------------+-----------+------------------------------------------------+
   > | SCOPE   | NAME   | FILESIZE   | ADLER32   | RSE: REPLICA                                   |
   > |---------+--------+------------+-----------+------------------------------------------------|
   > | test    | file1  | 10.486 MB  | 141a641e  | XRD1: root://xrd1:1094//rucio/test/80/25/file1 |
   > | test    | file2  | 10.486 MB  | fdfa7eea  | XRD1: root://xrd1:1094//rucio/test/f3/14/file2 |
   > | test    | file3  | 10.486 MB  | c669167d  | XRD2: root://xrd2:1095//rucio/test/a9/23/file3 |
   > | test    | file4  | 10.486 MB  | 65786e49  | XRD2: root://xrd2:1095//rucio/test/2b/c2/file4 |
   > +---------+--------+------------+-----------+------------------------------------------------+


So let's add a new rule on our new dataset to oblige Rucio to create replicas also on XRD3::

    rucio add-rule test:mynewdataset 1 XRD3
    > 1aadd685d891400dba050ad43e71fea9


Now we can check the status of the rule. We will see there are 4 files in `Replicating` state::

   rucio rule-info 1aadd685d891400dba050ad43e71fea9|grep Locks
   > Locks OK/REPLICATING/STUCK: 0/4/0


Now we can run the daemons. First the rule evaluation daemon (judge-evaluator) will pick up our rule. Then the transfer submitter daemon (conveyor-submitter) will send the newly created transfers requests to the FTS server. After that, the transfer state check daemon (conveyor-poller) will retrieve from FTS the transfer state information. Finally, the transfer sign-off daemon (conveyor-finisher) updates the internal state of the Rucio catalogue to reflect the changes.::

   rucio-judge-evaluator --run-once
   rucio-conveyor-submitter --run-once
   rucio-conveyor-poller --run-once
   rucio-conveyor-finisher --run-once


If we see the state of the rule now, we see the locks are OK::

   rucio rule-info 1aadd685d891400dba050ad43e71fea9|grep Locks
   > Locks OK/REPLICATING/STUCK: 4/0/0


And if we look at the replicas of the dataset, we see the there are replicas of the files also in XRD3::

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

