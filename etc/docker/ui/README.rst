Rucio - Scientific Data Management
---
(Web User Interface Container)
===

Rucio is a software framework that provides functionality to organize, manage, and access large volumes of scientific data using customisable policies. The data can be spread across globally distributed locations and across heterogeneous data centers, uniting different storage and network technologies as a single federated entity. Rucio offers advanced features such as distributed data recovery or adaptive replication, and is highly scalable, modular, and extensible. Rucio has been originally developed to meet the requirements of the high-energy physics experiment ATLAS, and is continuously extended to support LHC experiments and other diverse scientific communities.

Documentation
-------------

General information and latest documentation about Rucio can be found at [readthedocs](<http://rucio.readthedocs.io>).

Developers
----------

For information on how to contribute to Rucio, please refer and follow our [CONTRIBUTING](<https://github.com/rucio/rucio/blob/master/CONTRIBUTING.rst>) guidelines.

Getting Started
---------------

This image provides the Rucio WebUI which works as a web frontend to the Rucio server. It supports MySQL, PostgreSQL, Oracle and SQLite as database backends.

A WebUI instance with the minimal configuration can be started like this:

```docker run --name=rucio-webui -v /tmp/ca.pem:/etc/grid-security/ca.pem -v /tmp/hostcert.pem:/etc/grid-security/hostcert.pem -v /tmp/hostkey.pem:/etc/grid-security/hostkey.pem -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -p 443:443 -e RUCIO_PROXY="server.rucio" -e RUCIO_AUTH_PROXY="auth.rucio"  -d rucio/rucio-ui```

The rucio.cfg is used to configure the database backend, which is only needed for authentication and should point to the same database as the Rucio authentication server.

SSL is necessary for the WebUI so you need to include the host certificate, key and the the CA certificate as volumes.

`RUCIO_PROXY` and `RUCIO_AUTH` should point to your rucio server and rucio authentication endpoints. They are necessary for the WebUI to work.

Environment Variables
--------------------------

As shown in the examples above the rucio-server image can be configured using environment variables that are passed with `docker run`. Below is a list of all available variables and their behaviour:

`RUCIO_PROXY`
=============
Set this value to the address where you Rucio server can be reached. The WebUI uses a local httpd proxy to communicated with the Rucio server. This is necessary to circumvent possible cross-origin request problems.

`RUCIO_AUTH_PROXY`
==================
Same as `RUCIO_PROXY` but for the authentication server (which can be add different host as the main server).

`RUCIO_CA_PATH`
===============
If you are using SSL and want use `SSLCACertificatePath` and `SSLCARevocationPath` you can do so by specifying the path in this variable.

`RUCIO_ENABLE_LOGFILE`
======================
By default the log output of the web server is written to stdout and stderr. If you set this variable to `True` the output will be written to `access_log` and `error_log` under `/var/log/httpd`.

`RUCIO_LOG_LEVEL`
=================
The default log level is `info`. You can change it using this variable.

`RUCIO_LOG_FORMAT`
==================
The default rucio log format is `%h\t%t\t%{X-Rucio-Forwarded-For}i\t%T\t%D\t\"%{X-Rucio-Auth-Token}i\"\t%{X-Rucio-RequestId}i\t%{X-Rucio-Client-Ref}i\t\"%r\"\t%>s\t%b`
You can set your own format using this variable.

`RUCIO_HOSTNAME`
================
This variable sets the server name in the apache config.

`RUCIO_SERVER_ADMIN`
====================
This variable sets the server admin in the apache config.

Getting Support
----------------

If you are looking for support, please contact our mailing list rucio-users@googlegroups.com
or join us on our [slack support](<https://rucio.slack.com/messages/#support>) channel.
