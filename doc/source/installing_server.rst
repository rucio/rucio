Installing Rucio server
=======================

Prerequisites
~~~~~~~~~~~~~

The Rucio server runs on Python 2.6 and 2.7 on any Unix-like platform.

Install via pip
~~~~~~~~~~~~~~~

Heads up: We recommend to use the docker-based install (see next section) as it will configure many things for you automatically. Only use the pip-based install if you have a good reason and know how to configure your webservices manually:

``pip install rucio``

This will pull the latest release from `PyPi <https://pypi.python.org/pypi/rucio/>`_. The Rucio server also needs several Python dependencies. These are all listed in the file ``tools/pip-requires`` and will be pulled in as necessary.


Install via Docker
~~~~~~~~~~~~~~~~~~

A simple server without SSL can be started like this:

``docker run --name=rucio-server -p 80:80 -d rucio/rucio-server``

This will start up a simple server using sqlite based on an automatically generated configuration. You can check if the server is running with `curl http://localhost/ping`

This should return the Rucio version used in the container. Any other curl requests will not work as the database backend is not initialized as this image is meant to be used with an already bootstrapped database backend. I.e., that the container has to be configured to point to the correct database. There are two ways to manage the Rucio configuration: using environment variables or by mounting a full rucio.cfg.

If you want to set the connection string for the database it can be done using the `RUCIO_CFG_DATABASE_DEFAULT` environment variable, e.g., to start a container connecting to a MySQL DB running at `mysql.db` you could use something like this:

``docker run --name=rucio-server -e RUCIO_CFG_DATABASE_DEFAULT="mysql://rucio:rucio@mysql.db/rucio" -p 80:80 -d rucio/rucio-server``

The are much more configuration parameters available that will be listed at the end of this readme.

Another way to configure Rucio is to directly mount a complete rucio.cfg into the container. This will then be used instead of the auto-generated one, e.g., if you have a rucio.cfg ready on your host system under `/tmp/rucio.cfg` you could start a container like this:

``docker run --name=rucio-server -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -p 80:80 -d rucio/rucio-server``

The rucio.cfg is used to configure the database backend.

If you want to enable SSL you would need to set the `RUCIO_ENABLE_SSL` variable and also need to include the host certificate, key and the the CA certificate as volumes. E.g.,:

``docker run --name=rucio-server -v /tmp/ca.pem:/etc/grid-security/ca.pem -v /tmp/hostcert.pem:/etc/grid-security/hostcert.pem -v /tmp/hostkey.pem:/etc/grid-security/hostkey.pem -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -p 443:443 -e RUCIO_ENABLE_SSL=True -d rucio/rucio-server``

By default the output of the Apache web server is written directly to stdout and stderr. If you would rather direct them into separate files it can be done using the `RUCIO_ENABLE_LOGS` variable. The storage folder of the logs can be used as a volume:

``docker run --name=rucio-server -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -v /tmp/logs:/var/log/httpd -p 80:80 -e RUCIO_ENABLE_LOGFILE=True -d rucio/rucio-server``

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

As shown in the examples above the rucio-server image can be configured using environment variables that are passed with `docker run`. Below is a list of all available variables and their behaviour:

`RUCIO_ENABLE_SSL`
------------------
By default, the rucio server runs without SSL on port 80. If you want to enable SSL set this variable to `True`. If you enable SSL you will also have to provide the host certificate and key and the certificate authority file. The server will look for `hostcert.pem`, `hostkey.pem` and `ca.pem` under `/etc/grid-security` so you will have to mount them as volumes. Furthermore you will also have to expose port 443.

`RUCIO_CA_PATH`
---------------
If you are using SSL and want use `SSLCACertificatePath` and `SSLCARevocationPath` you can do so by specifying the path in this variable.

`RUCIO_DEFINE_ALIASES`
----------------------
By default, the web server is configured with all common rest endpoints except the authentication endpoint. If you want to specify your own set of aliases you can set this variable to `True`. The web server then expects an alias file under `/opt/rucio/etc/aliases.conf`

`RUCIO_ENABLE_LOGFILE`
----------------------
By default, the log output of the web server is written to stdout and stderr. If you set this variable to `True` the output will be written to `access_log` and `error_log` under `/var/log/httpd`.

`RUCIO_LOG_LEVEL`
-----------------
The default log level is `info`. You can change it using this variable.

`RUCIO_LOG_FORMAT`
------------------
The default rucio log format is `%h\t%t\t%{X-Rucio-Forwarded-For}i\t%T\t%D\t\"%{X-Rucio-Auth-Token}i\"\t%{X-Rucio-RequestId}i\t%{X-Rucio-Client-Ref}i\t\"%r\"\t%>s\t%b`
You can set your own format using this variable.

`RUCIO_HOSTNAME`
----------------
This variable sets the server name in the apache config.

`RUCIO_SERVER_ADMIN`
--------------------
This variable sets the server admin in the apache config.

`RUCIO_CFG` configuration parameters:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Environment variables can be used to set values for the auto-generated rucio.cfg. The names are derived from the actual names in the configuration file prefixed by `RUCIO_CFG`, e.g., the `default` value in the `database` section becomes `RUCIO_CFG_DATABASE_DEFAULT`.
All available environment variables are:

* RUCIO_CFG_COMMON_LOGDIR
* RUCIO_CFG_COMMON_LOGLEVEL
* RUCIO_CFG_COMMON_MAILTEMPLATEDIR
* RUCIO_CFG_DATABASE_DEFAULT
* RUCIO_CFG_DATABASE_SCHEMA
* RUCIO_CFG_DATABASE_POOL_RESET_ON_RETURN
* RUCIO_CFG_DATABASE_ECHO
* RUCIO_CFG_DATABASE_POLL_RECYCLE
* RUCIO_CFG_DATABASE_POOL_SIZE
* RUCIO_CFG_DATABASE_POOL_TIMEOUT
* RUCIO_CFG_DATABASE_MAX_OVERFLOW
* RUCIO_CFG_DATABASE_POWUSERACCOUNT
* RUCIO_CFG_DATABASE_USERPASSWORD
* RUCIO_CFG_MONITOR_CARBON_SERVER
* RUCIO_CFG_MONITOR_CARBON_PORT
* RUCIO_CFG_MONITOR_USER_SCOPE
* RUCIO_CFG_TRACE_TRACEDIR
* RUCIO_CFG_TRACE_BROKERS
* RUCIO_CFG_TRACE_PORT
* RUCIO_CFG_TRACE_USERNAME
* RUCIO_CFG_TRACE_PASSWORD
* RUCIO_CFG_TRACE_TOPIC
* RUCIO_CFG_PERMISSION_POLICY
* RUCIO_CFG_PERMISSION_SCHEMA
* RUCIO_CFG_PERMISSION_LFN2PFN_ALGORITHM_DEFAULT
* RUCIO_CFG_PERMISSION_SUPPORT
* RUCIO_CFG_PERMISSION_SUPPORT_RUCIO
* RUCIO_CFG_WEBUI_USERCERT
