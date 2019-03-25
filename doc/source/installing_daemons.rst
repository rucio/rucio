Installing Rucio daemons
========================

Prerequisites
~~~~~~~~~~~~~

The Rucio daemons run on Python 2.7 on any Unix-like platform.

Install via pip
~~~~~~~~~~~~~~~

Heads up: We recommend to use the docker-based install (see next section) as it will configure many things for you automatically. Only use the pip-based install if you have a good reason and know how to configure your web service manually:

``pip install rucio``

This will pull the latest release from `PyPi <https://pypi.python.org/pypi/rucio/>`_. The Rucio server also needs several Python dependencies. These are all listed in the file ``tools/pip-requires`` and will be pulled in as necessary.


Install via Docker
~~~~~~~~~~~~~~~~~~

This image provides the Rucio daemons. Each daemon has to be run in a separate container. It supports MySQL, PostgreSQL, Oracle, and SQLite as database backends.

This image expects that there is an already initialised Rucio DB. To start a simple `judge-cleaner` daemon using a database on `mysql.db` without an additional parameters just run this:

```docker run --name=rucio-judge-cleaner -e RUCIO_CFG_DATABASE_DEFAULT="mysql://rucio:rucio@mysql.db/rucio" -e RUCIO_DAEMON=judge-cleaner  rucio/rucio-daemons```

The `RUCIO_DAEMON` environment variable gives the name of the rucio daemon.

Rucio can be configured fully using environment variables like `RUCIO_CFG_DATABASE_DEFAULT`. If you want to instead use a complete rucio.cfg it can also be mounted. This will then ignore the `RUCIO_CFG` environment variables:

The rucio.cfg is used to configure the database backend and the daemons:

```docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -e RUCIO_DAEMON=judge-cleaner  rucio/rucio-daemons```

By default the daemon logs are written to stdout and stderr if you want to write to a file you can use `RUCIO_ENABLE_LOGS` like this:

```docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -v /tmp/logs:/var/log/rucio -e RUCIO_DAEMON=judge-cleaner  -e RUCIO_ENABLE_LOGS=True rucio/rucio-daemons```

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

As shown in the examples above the rucio-daemon image can be configured using environment variables that are passed with `docker run`. Below is a list of all available variables and their behaviour:

`RUCIO_DAEMON`
--------------
This variable is mandatory and it specifies the name of the daemon, e.g., `hermes`, `kronos`, `judge-evaluator`, etc.

`RUCIO_DAEMON_ARGS`
-------------------
Any additional command line parameter can be specified here, e.g., `--run-once`. This field is optional.

`RUCIO_ENABLE_LOGFILE`
----------------------
By default, the log output of the daemon is written to stdout and stderr. If you set this variable to `True` the output will be written to `access_log` and `error_log` under `/var/log/rucio`.

`RUCIO_CFG` configuration parameters:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Environment variables can be used to set values for the auto-generated rucio.cfg. The names are derived from the actual names in the configuration file prefixed by `RUCIO_CFG`, e.g., the `default` value in the `database` section becomes `RUCIO_CFG_DATABASE_DEFAULT`.
All available environment variables are:

* RUCIO_CFG_ACCOUNTS_SPECIAL_ACCOUNTS
* RUCIO_CFG_COMMON_LOGDIR
* RUCIO_CFG_COMMON_LOGLEVEL
* RUCIO_CFG_COMMON_MAILTEMPLATEDIR
* RUCIO_CFG_DATABASE_DEFAULT
* RUCIO_CFG_DATABASE_SCHEMA
* RUCIO_CFG_DATABASE_SCHEMA
* RUCIO_CFG_DATABASE_POOL_RESET_ON_RETURN
* RUCIO_CFG_DATABASE_ECHO
* RUCIO_CFG_DATABASE_POOL_RECYCLE
* RUCIO_CFG_DATABASE_POOL_SIZE
* RUCIO_CFG_DATABASE_POOL_TIMEOUT
* RUCIO_CFG_DATABASE_MAX_OVERFLOW
* RUCIO_CFG_DATABASE_POWUSERACCOUNT
* RUCIO_CFG_DATABASE_POWUSERPASSWORD
* RUCIO_CFG_MONITOR_CARBON_SERVER
* RUCIO_CFG_MONITOR_CARBON_PORT
* RUCIO_CFG_MONITOR_USER_SCOPE
* RUCIO_CFG_PERMISSION_POLICY
* RUCIO_CFG_PERMISSION_SCHEMA
* RUCIO_CFG_PERMISSION_LFN2PFN_ALGORITHM_DEFAULT
* RUCIO_CFG_PERMISSION_SUPPORT
* RUCIO_CFG_PERMISSION_SUPPORT_RUCIO
* RUCIO_CFG_AUTOMATIX_SITES
* RUCIO_CFG_AUTOMATIX_SLEEP_TIME
* RUCIO_CFG_AUTOMATIX_DATASET_LIFETIME
* RUCIO_CFG_AUTOMATIX_SET_METADATA
* RUCIO_CFG_AUDITOR_RESULTS
* RUCIO_CFG_AUDITOR_CACHE
* RUCIO_CFG_CONVEYOR_SCHEME
* RUCIO_CFG_CONVEYOR_TRANSFERTOOL
* RUCIO_CFG_CONVEYOR_FTSHOSTS
* RUCIO_CFG_CONVEYOR_CACERT
* RUCIO_CFG_CONVEYOR_USERCERT
* RUCIO_CFG_CONVEYOR_CACHE_TIME
* RUCIO_CFG_CONVEYOR_USE_DETERMINISTIC_ID
* RUCIO_CFG_CONVEYOR_POLL_TIMEOUT
* RUCIO_CFG_CONVEYOR_SUBMIT_TIMEOUT
* RUCIO_CFG_CONVEYOR_BRING_ONLINE
* RUCIO_CFG_CONVEYOR_QUEUE_MODE
* RUCIO_CFG_CONVEYOR_USING_MEMCACHE
* RUCIO_CFG_CONVEYOR_FTSMONHOSTS
* RUCIO_CFG_MESSAGING_FTS3_PORT
* RUCIO_CFG_MESSAGING_FTS3_SSL_KEY_FILE
* RUCIO_CFG_MESSAGING_FTS3_SSL_CERT_FILE
* RUCIO_CFG_MESSAGING_FTS3_DESTINATION
* RUCIO_CFG_MESSAGING_FTS3_BROKERS
* RUCIO_CFG_MESSAGING_FTS3_VONAME
* RUCIO_CFG_MESSAGING_HERMES_USERNAME
* RUCIO_CFG_MESSAGING_HERMES_PASSWORD
* RUCIO_CFG_MESSAGING_HERMES_PORT
* RUCIO_CFG_MESSAGING_HERMES_NONSSL_PORT
* RUCIO_CFG_MESSAGING_HERMES_USE_SSL
* RUCIO_CFG_MESSAGING_HERMES_SSL_KEY_FILE
* RUCIO_CFG_MESSAGING_HERMES_SSL_CERT_FILE
* RUCIO_CFG_MESSAGING_HERMES_DESTINATION
* RUCIO_CFG_MESSAGING_HERMES_BROKERS
* RUCIO_CFG_MESSAGING_HERMES_VONAME
* RUCIO_CFG_MESSAGING_HERMES_EMAIL_FROM
* RUCIO_CFG_MESSAGING_HERMES_EMAIL_TEST
* RUCIO_CFG_TRACER_KRONOS_BROKERS
* RUCIO_CFG_TRACER_KRONOS_PORT
* RUCIO_CFG_TRACER_SSL_KEY_FILE
* RUCIO_CFG_TRACER_SSL_CERT_FILE
* RUCIO_CFG_TRACER_QUEUE
* RUCIO_CFG_TRACER_PREFETCH_SIZE
* RUCIO_CFG_TRACER_CHUNKSIZE
* RUCIO_CFG_TRACER_SUBSCRIPTION_ID
* RUCIO_CFG_TRACER_USE_SSL
* RUCIO_CFG_TRACER_RECONNECT_ATTEMPTS
* RUCIO_CFG_TRACER_EXCLUDED_USRDNS
* RUCIO_CFG_TRACER_KRONOS_USERNAME
* RUCIO_CFG_TRACER_KRONOS_PASSWORD
* RUCIO_CFG_TRACER_DATASET_WAIT
* RUCIO_CFG_MESSAGING_CACHE_PORT
* RUCIO_CFG_MESSAGING_CACHE_SSL_KEY_FILE
* RUCIO_CFG_MESSAGING_CACHE_SSL_CERT_FILE
* RUCIO_CFG_MESSAGING_CACHE_DESTINATION
* RUCIO_CFG_MESSAGING_CACHE_BROKERS
* RUCIO_CFG_MESSAGING_CACHE_VONAME
* RUCIO_CFG_MESSAGING_CACHE_ACCOUNT
* RUCIO_CFG_CREDENTIALS_GCS
* RUCIO_CFG_CREDENTIALS_SIGNATURE_LIFETIME
