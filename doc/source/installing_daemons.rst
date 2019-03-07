Installing Rucio daemons
Prerequisites
The Rucio daemons run on Python 2.7 on any Unix-like platform.

Install via pip
Heads up: We recommend to use the docker-based install (see next section) as it will configure many things for you automatically. Only use the pip-based install if you have a good reason and know how to configure your web services manually:

pip install rucio

This will pull the latest release from PyPi. The Rucio server also needs several Python dependencies. These are all listed in the file tools/pip-requires and will be pulled in as necessary. 

Install via Docker
This image provides the Rucio daemons. Each daemon has to be run in a separate container. It supports MySQL, PostgreSQL, Oracle, and SQLite as database backends. 

This image expects that there is an already initialised Rucio DB. To start a simple judge-cleaner daemon using a database on mysql.db without an additional parameter just run this:

`docker run --name=rucio-judge-cleaner -e RUCIO_CFG_DATABASE_DEFAULT="mysql://rucio:rucio@mysql.db/rucio" -e RUCIO_DAEMON=judge-cleaner rucio/rucio-daemons`

The RUCIO_DAEMON environment variable gives the name of the rucio daemon.

Rucio can be configured fully using environment variables like RUCIO_CFG_DATABASE_DEFAULT. If you want to instead use a complete rucio.cfg it can also be mounted. This will then ignore the RUCIO_CFG environment variables:

The rucio.cfg is used to configure the database backend and the daemons:

`docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -e RUCIO_DAEMON=judge-cleaner rucio/rucio-daemons`

By default the daemon logs are written to stdout and stderr if you want to write to a file you can use RUCIO_ENABLE_LOGS like this:

`docker run --name=rucio-judge-cleaner -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -v /tmp/logs:/var/log/rucio -e RUCIO_DAEMON=judge-cleaner -e RUCIO_ENABLE_LOGS=True rucio/rucio-daemons`

Environment Variables
As shown in the examples above the rucio-daemon image can be configured using environment variables that are passed with docker run. Below is a list of all available variables and their behaviour:

RUCIO_DAEMON
This variable is mandatory and it specifies the name of the daemon, e.g., hermes, kronos, judge-evaluator, etc.

RUCIO_DAEMON_ARGS
Any additional command line parameter can be specified here, e.g., --run-once. This field is optional.

RUCIO_ENABLE_LOGFILE
By default, the log output of the daemon is written to stdout and stderr. If you set this variable to True the output will be written to access_log and error_log under /var/log/rucio.
