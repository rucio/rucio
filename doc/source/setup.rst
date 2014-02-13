==========================================
Setting up a Rucio development environment
==========================================

This document describes getting the source from Rucio git repository for development purposes.


.. _`Git Repository`: http://github.com/openstack/keystone


Prerequisites
=============

This document assumes you have the following tools available on your system:

- git_
- Python_ 2.6 or 2.7
- setuptools_/pip_/virtualenv_ or curl_

.. _git: http://git-scm.com/
.. _Python: http://www.python.org/
.. _setuptools: http://pypi.python.org/pypi/setuptools
.. _curl: http://curl.haxx.se/

Getting the latest code
=======================

Make a clone of the code from our git repository::

    $ git clone https://<gerrit_username>@voatlasrucio-gerrit.cern.ch/rucio



.. Or, if you need to do an an anonymous checkout::
..    $ export GIT_SSL_NO_VERIFY=1
..    $ git clone https://atlas-gerrit.cern.ch:8443/p/rucio


Configuring git
===============


Make sure that you get the following pre-commit hooks for Git: commit-msg and pre-commit.

They can be installed by executing the script tools/configure_git.sh::

  $ cd rucio
  $ ./tools/configure_git.sh

Or manually with::

    $ cd rucio
    $ cp tools/commit-msg .git/hooks/commit-msg
    $ chmod +x .git/hooks/commit-msg

Now, copy the pep8 verification commit hook::

    $ cp tools/pre-commit .git/hooks/pre-commit
    $ chmod +x .git/hooks/pre-commit

You should keep it enabled all the time, but if you want to disable it temporarily, then just remove the executable rights::

    $ chmod -x .git/hooks/pre-commit

and afterwards enable it again::

    $ chmod +x .git/hooks/pre-commit

When that is complete, you are ready to play.

Optionally, you can also subscribe to the notes of the code review::

    $ git config --add remote.origin.fetch refs/notes/review:refs/notes/review

You can then add the code review notes to your local git log by adding this parameter::

    $ git log --show-notes=review


Installing dependencies
=======================

Rucio maintains three lists of dependencies::

    tools/pip-requires
    tools/pip-requires-client
    tools/pip-requires-test

The first is the list of dependencies needed for running rucio,
the second list includes dependencies used for the rucio python clients and CLIs and
the third list is for active development and testing of rucio itself.

These depdendencies can be installed from PyPi_ using the python tool pip_ or by using
the tools/install_venv.py script as described in the next section.

.. _PyPi: http://pypi.python.org/
.. _pip: http://pypi.python.org/pypi/pip

However, your system *may* need additional dependencies that `pip` (and by
extension, PyPi) cannot satisfy. These dependencies should be installed
prior to using `pip`, and the installation method may vary depending on
your platform.

PyPi Packages and VirtualEnv
============================

We recommend establishing a virtualenv to run rucio within. Virtualenv limits the python environment
to just what you're installing as dependencies, useful to keep a clean environment for working on
rucio. The tools directory in rucio has a script already created to make this very simple::

    $ python tools/install_venv.py

This will create a local virtual environment in the directory ``.venv``.

If you need to develop only the clients and have a default configuration::

    $ python tools/install_venv.py --atlas-clients

Once created, you can activate this virtualenv for your current shell using::

    $ source .venv/bin/activate

The virtual environment can be disabled using the command::

    $ deactivate

You can also use ``tools\with_venv.sh`` to prefix commands so that they run
within the virtual environment. For more information on virtual environments,
see virtualenv_.

Lastly you have to create a symbolic link from the virtual environments python directory to the rucio source directory::

    $ cd .venv/lib/python2.7/site-packages/
    $ ln PATH_TO_INSTALL_DIRECTORY/lib/rucio/ rucio -s

.. _virtualenv: http://www.virtualenv.org/


Verifying Rucio is set up
=========================

Once set up, either directly or within a virtualenv, you should be able to invoke python and import
the libraries. If you're using a virtualenv, don't forget to activate it::

	$ source .venv/bin/activate
	$ python

You should then be able to `import rucio` from your Python shell
without issue::

    >>> import rucio
    >>>

Registering and using the Package Index
=======================================

The pip server is running on http://voatlasrucio-pip.cern.ch/.

To upload files you need to create a :file:`~/.pypirc` with::

    [distutils]
    index-servers = voatlasrucio-pip

    [atlas-pip]
    username: <username>
    password: <password>
    repository: https://voatlasrucio-pip.cern.ch/

- *username*, which is the registered username on the PyPI server.
- *password*, that will be used to authenticate. If omitted the user
    will be prompt to type it when needed.

Upload a package with::

	$ python setup.py register -r voatlasrucio-pip sdist upload -r voatlasrucio-pip

or::

	$ python setup.py register -r https://voatlasrucio-pip.cern.ch/ sdist upload -r https://voatlasrucio-pip.cern.ch/


To install packages::

	$ pip install rucio -i https://voatlasrucio-pip.cern.ch/simple

it will ask for the password and login.

To avoid this, you need to create a :file:`~/.pip/pip.conf` with::

    [install]
    index-url = https://<username>:<password>@voatlasrucio-pip.cern.ch/simple
    extra-index-url = http://pypi.python.org/simple

- *username*, which is the registered username on the PyPI server.
- *password*, that will be used to authenticate. If omitted the user
    will be prompt to type it when needed.


Configuring Rucio
==================

When starting up Rucio, you can specify the configuration file(rucio.cfg) to
use with the RUCIO_HOME environment variable:  ``$RUCIO_HOME/etc/rucio.cfg``

If you do **not** specify a configuration file, Rucio will look in the ``/opt/rucio/etc/``
directory for a configuration file.

A sample configuration file distributed with Rucio is in the etc directory.
It can be copied locally and configured::

    $ mkdir -p /opt/rucio/
    $ cp etc/rucio.cfg.template /opt/rucio/etc/rucio.cfg
    $ edit  /opt/rucio/etc/rucio.cfg

You should then be able to test the rucio commands::

    $ rucio ping


Generating documentation
========================

Build the Sphinx documentation with::

	$ python setup.py build_sphinx
