==========================================
Setting up a Rucio development environment
==========================================

This document describes getting the source from Rucio git repository for development purposes.


.. _`Git Repository`: http://github.com/openstack/keystone


Prerequisites
=============

This document assumes you have the following tools available on your system:

- git_
- setuptools_
- pip_
- virtualenv_

.. _git: http://git-scm.com/
.. _setuptools: http://pypi.python.org/pypi/setuptools

Getting the latest code
=======================

Make a clone of the code from our git repository::

    $ git clone ssh://<gerrit_username>@atlas-gerrit.cern.ch:29418/rucio



.. Or, if you need to do an an anonymous checkout::
..    $ export GIT_SSL_NO_VERIFY=1
..    $ git clone https://atlas-gerrit.cern.ch:8443/p/rucio    


Configuring git
===============

Make sure that you get the commit-msg hook, this is mandatory::

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

Installing dependencies
=======================

Rucio maintains two lists of dependencies::

    tools/pip-requires
    tools/pip-requires-test

The first is the list of dependencies needed for running rucio, the second list includes dependencies used for active development and testing of rucio itself.

These depdendencies can be installed from PyPi_ using the python tool pip_.

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
Once created, you can activate this virtualenv for your current shell using::

    $ source .venv/bin/activate

The virtual environment can be disabled using the command::

    $ deactivate

You can also use ``tools\with_venv.sh`` to prefix commands so that they run
within the virtual environment. For more information on virtual environments,
see virtualenv_.

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

The pip server is running on http://atlas-pip.cern.ch/.

To upload files you need  to create a :file:`~/.pypirc` with::

    [distutils]
    index-servers =
        atlas-pip

    [atlas-pip]
    username: <username>
    password: <password>
    repository:http://atlas-pip.cern.ch/

- *username*, which is the registered username on the PyPI server.
- *password*, that will be used to authenticate. If omitted the user
    will be prompt to type it when needed.

Upload a package with::

	$ python setup.py register -r atlas-pip sdist upload -r atlas-pip

or::

	$ python  setup.py register -r http://atlas-pip.cern.ch/  sdist upload -r  http://atlas-pip.cern.ch/


To install packages::

	$ pip install rucio -i http://atlas-pip.cern.ch/simple

it will ask for the password and login.

To avoid this, you need to create a :file:`~/.pip/pip.conf` with::

    [install]
    index-url =
        http://pypi.python.org/simple

    extra-index-url=
        http://<username>:<password>@http://atlas-pip.cern.ch/simple

- *username*, which is the registered username on the PyPI server.
- *password*, that will be used to authenticate. If omitted the user
    will be prompt to type it when needed.


Generating documentation
========================

Build the Sphinx documentation with::

	$ python setup.py build_sphinx
