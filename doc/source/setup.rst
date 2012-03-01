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

Make sure that you get the commit-msg hook::

    $ cd rucio/.git
    $ scp -p -P 29418 <gerrit_username>@atlas-gerrit.cern.ch:hooks/commit-msg hooks/
    $ chmod +x hooks/commit-msg
    $ cd ..

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

Code Review and Submitting a patch set
======================================

The code review tool is Gerrit and can be found at::

    https://atlas-gerrit.cern.ch:8443/

In principle, you should always work on a local feature branch until a feature is complete, and then submit the feature as a patch set for review::

    $ git checkout -b new_feature      # create new local branch and switch to it
    $ git branch -a                    # list all branches
    $ git checkout master              # switch to master branch
    $ git branch -d new_feature        # delete the local feature branch

Never push a feature branch directly to origin, it is your local development environment! Origin only keeps the code reviewed master.
    
To submit a new patch set for review::

    $ git commit -m "new feature added"
    $ tools/submit-review

Assuming that the review was not okay, and you have to make some changes, DO NOT COMMIT AGAIN as this will create a new review request! Instead amend the current bad patch set with::

    $ emacs                                          # as needed
    $ git add                                        # as needed
    $ git rm                                         # as needed
    $ tools/submit-review -a "now it is fixed"

In case you need to fix an older commit, stash away your current changes, rebase to the old commit, fix the code, amend for review, re-stash your original changes::

    $ git stash                                      # make sure we don't lose our current changes
    $ git rebase -i HEAD~5                           # go back 5 commits interactively
    $ emacs                                          # as needed
    $ git add                                        # as needed
    $ git rm                                         # as needed
    $ tools/submit-review -a "finally it is fixed"   # amend the change
    $ git apply                                      # get our changes back

Of course, this is potentionally dangerous if someone has already changed files from any of these commits and pushed them to the official master, so some synchronisation with colleagues might be needed.

If the patch set was reviewed and approved, don't forget to fetch the repository metadata, and, optionally, pull the changes from the origin master again::

    $ git fetch
    $ git pull

Should you get confused in any way, don't forget that you can always clone the official master branch afresh, pull the necessary commits, and copy the new files over.

TL;DR If something is weird, ask Mario.

PyPi Packages and VirtualEnv
============================

We recommend establishing a virtualenv to run rucio within. Virtualenv limits the python environment
to just what you're installing as depdendencies, useful to keep a clean environment for working on
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
