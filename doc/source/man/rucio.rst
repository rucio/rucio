=====
rucio
=====

-----------------------------
Rucio command line interface
-----------------------------

:Author: rucio@cern.ch
:Date: 2012-01-03
:Copyright: CERN
:Version: 2012.1-dev
:Manual section: 1
:Manual group: cloud computing


SYNOPSIS
========

  rucio <command> [options] [args]


COMMANDS
========

  **help <command>**
        Output help for one of the commands below


MEMBER COMMANDS
===============


OPTIONS
=======

  **--version**
        show program's version number and exit

  **-h, --help**
        show this help message and exit

  **-v, --verbose**
        Print more verbose output

  **-d, --debug**
        Print more verbose output

  **-H ADDRESS, --host=ADDRESS**
        Address of Rucio API host. Default: 0.0.0.0

  **-p PORT, --port=PORT**
        Port the Rucio API host listens on. Default: 9292

  **-U URL, --url=URL**
        URL of Rucio service. This option can be used to specify the hostname,
        port and protocol (http/https) of the rucio server, for example
        -U https://localhost:9292/v1
        Default: None

  **-k, --insecure**
        Explicitly allow rucio to perform insecure SSL (https) requests.
        The server certificate will not be verified against any certificate
        authorities. This option should be used with caution.

  **-A TOKEN, --auth_token=TOKEN**
        Authentication token to use to identify the client to the rucio server

  **-f, --force**
        Prevent select actions from requesting user confirmation

  **--dry-run**
        Don't actually execute the command, just print output showing what
        WOULD happen.



SEE ALSO
========

* `Rucio <http://rucio.cern.ch>`__

BUGS
====

* Trac server: `Rucio <http://trac.cern.ch/rucio>`__

