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


Install via docker
~~~~~~~~~~~~~~~~~~

First, install the docker environment, e.g., for CentOS-based systems:

``yum install docker``

Afterwards, if you require it, enable the Grid Certificate Authority by adding ``/etc/yum.repos.d/ca.repo`` with content:

.. code-block:: none

    [carepo]
    name=IGTF CA Repository
    baseurl=http://linuxsoft.cern.ch/mirror/repository.egi.eu/sw/production/cas/1/current/
    enabled=1
    gpgcheck=1
    gpgkey=file:///etc/pki/rpm-gpg/GPG-KEY-EUGridPMA-RPM-3

with the public key in file ``/etc/pki/rpm-gpg/GPG-KEY-EUGridPMA-RPM-3``:

.. code-block:: none

    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1.2.1 (GNU/Linux)

    mQGiBELTiyYRBAD8goP2vWdf46e/stZvzgkBgJIFTMkHqZOpLqlCKTRGf4VHUASh
    hdaktDtPx44fVO4E3zmugc7FP6xz/Hj3SqrUKt98vzF1EMb3i4UMCOBif+jM6VFS
    N5N3gDEukNpP2h46LkNPbRPgAEeUmUZy4kTyB9xC/VA7d1sFx6sJZpCHiwCg7DNX
    bj4Wuk5b+FyyCOg9++xabokEAJwt4+iyDX3uYZrkzh9hOXgrbBiyGrorAz3jOpqM
    4L9+OKs5q9UsBwVXs5Zjei/irgxNjHNZCPo/V4f7o2CHxa88rn4GvstftSK6Oeey
    8PaV3vdb5C5SRSbRgvxoUOo6eGVBpv8bVpKm//tNkTboHVsEAKQ1rYzx/m89aCZj
    VCw5A/0c3E0rH4ZCeNg7yvta9ur3U7n/aFhzbU3wFLhcIndrPaufz5Sy/SYhOaS9
    RgH36GbsmOq6JskdtSpBLq0768BUmrjcosgWl3REpMAZc4vvtb55WRYsrNSrqmXZ
    /jHLjQkFHFdObIEcvxl+yIIwUxybMkvdxPZxnpGjF2gg6AoP7rQ5RVVHcmlkUE1B
    IERpc3RyaWJ1dGlvbiBTaWduaW5nIEtleSAzIDxpbmZvQGV1Z3JpZHBtYS5vcmc+
    iFkEExECABkFAkLTiyYECwcDAgMVAgMDFgIBAh4BAheAAAoJEMMtmcg827xx5PQA
    oON2EH0dqfwNjGr1GlGyt1o5bWkzAJ0Y4QOPWaCIJFABoluX5nifjKWV9w==
    =qXx1
    -----END PGP PUBLIC KEY BLOCK-----

You can now ``yum install lcg-CA``.

The next step is to generate a host certificate, which will be used by the webserver:

.. code-block:: bash

    openssl pkcs12 -in hostCert.p12 -clcerts -nokeys -out /etc/grid-security/hostcert.pem
    openssl pkcs12 -in hostCert.p12 -nocerts -nodes -out /etc/grid-security/hostkey.pem
    chmod 0600 /etc/grid-security/hostkey.pem

You can now start the docker service:

.. code-block:: bash

   service docker start

And finally start up the Rucio server:

.. code-block:: bash

    docker run --privileged --name rucio-server -v /etc/hostname:/etc/hostname -v /var/log/httpd:/var/log/httpd -v /etc/grid-security/hostcert.pem:/etc/grid-security/hostcert.pem -v /etc/grid-security/hostkey.pem:/etc/grid-security/hostkey.pem -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /opt/rucio/etc:/opt/rucio/etc -v /etc/grid-security:/etc/grid-security -v /etc/pki:/etc/pki -d -p 443:443  gitlab-registry.cern.ch/rucio01/rucio/mysql_server

Voila. You have a Rucio server up and running.

Miscellaneous
~~~~~~~~~~~~~

Creating alembic.ini
--------------------

The following is only needed if you didn’t bootstrap the database. First, enter the docker container:

``docker exec -i -t rucio-server /bin/bash``

Now, you’re inside the container and you can put in the configuration file ``etc/rucio.cfg`` a new ``[alembic]`` section:

.. code-block:: ini

    [alembic]
    cfg = alembic.ini

And create a new file ``alembic.ini`` with content:

.. code-block:: ini

    # A generic, single database configuration.

    [alembic]
    # path to migration scripts
    script_location =/usr/lib/python2.7/site-packages/rucio/db/sqla/migrate_repo
    sqlalchemy.url = Replace by the DB string here

    # Logging configuration
    [loggers]
    keys = root,sqlalchemy,alembic

    [handlers]
    keys = console

    [formatters]
    keys = generic

    [logger_root]
    level = WARN
    handlers = console
    qualname =

    [logger_sqlalchemy]
    level = WARN
    handlers =
    qualname = sqlalchemy.engine

    [logger_alembic]
    level = INFO
    handlers =
    qualname = alembic

    [handler_console]
    class = StreamHandler
    args = (sys.stderr,)
    level = NOTSET
    formatter = generic

    [formatter_generic]
    format = %(levelname)-5.5s [%(name)s] %(message)s
    datefmt = %H:%M:%S


Eventually, bootstrap the database and restart the webserver:

.. code-block:: bash

    python /usr/rucio/tools/bootstrap.py
    apachectl restart

Special characters in DIDs
--------------------------

To allow DIDs to contain the slash (/) character, one must add the directive

.. code-block:: html

    AllowEncodedSlashes on

to the

.. code-block:: html

    <VirtualHost>
    ...
    </VirtualHost>

section of ``/etc/httpd/conf.d/rucio.conf``


