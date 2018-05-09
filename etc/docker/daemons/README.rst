Rucio Daemons
=============

Data Management for science in the Big Data era.

Rucio is a project that provides services and associated libraries for allowing scientific collaborations to manage large volumes of data spread across facilities at multiple institutions and organizations. Rucio has been developed by the [ATLAS](<https://atlas.cern/>). experiment. It offers advanced features, is highly scalable and modular. Rucio is a data management solution that could cover the needs of different communities in the scientific domain (e.g., HEP, astronomy, biology).

Documentation
-------------

General information and latest documentation about Rucio can be found at [readthedocs](<http://rucio.readthedocs.io>).

Developers
----------

For information on how to contribute to Rucio, please refer and follow our [CONTRIBUTING](<https://github.com/rucio/rucio/blob/master/CONTRIBUTING.rst>) guidelines.

Getting Started
---------------
This image provides the Rucio daemons. Each daemon has to be run in a separate container. It supports MySQL, PostgreSQL, Oracle and SQLite as database backends.

A simple `judge-cleaner` daemon without a additional parameters can be started just by running this:

```docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -e RUCIO_DAEMON=judge-cleaner  rucio/rucio-daemons```

The rucio.cfg is used to configure the database backend and the daemons.

The `RUCIO_DAEMON` environment variable gives the name of the rucio daemon.

By default the daemon logs are written to stdout and stderr if you want to write to a file you can use `RUCIO_ENABLE_LOGS` like this:

```docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -v /tmp/logs:/var/log/rucio -e RUCIO_DAEMON=judge-cleaner  -e RUCIO_ENABLE_LOGS=True rucio/rucio-daemons```

Environment Variables
--------------------------

As shown in the examples above the rucio-daemon image can be configured using environment variables that are passed with `docker run`. Below is a list of all available variables and their behaviour:

`RUCIO_DAEMON`
==============
This variable is mandatory and it specifies the name of the daemon, e.g., `hermes`, `kronos`, `judge-evaluator`, etc.

`RUCIO_DAEMON_ARGS`
===================
Any additional command line parameter can be specified here, e.g., `--run-once`. This field is optional.

`RUCIO_ENABLE_LOGFILE`
=====================
By default the log output of the daemon is written to stdout and stderr. If you set this variable to `True` the output will be written to `access_log` and `error_log` under `/var/log/rucio`.

Getting Support
---------------

If you are looking for support, please contact our mailing list rucio-users@googlegroups.com
or join us on our [slack support](<https://rucio.slack.com/messages/#support>) channel.
