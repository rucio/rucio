==========================================
Setting up a Rucio development environment
==========================================

----------------------------------
Contributing patches & code review
----------------------------------

Rucio follows a next/master development scheme: two protected branches called "next" and "master" track all features and patches. Contributors create their own private development branches to do their work, and once finished and code reviewed, these branches are merged into next and/or master.

The hosting is at GitLab, and the upstream is at:

    https://gitlab.cern.ch/rucio01/rucio

-----------
First setup
-----------

Go to the GitLab web-interface mentioned above, and login with your CERN account. It will give you the option to fork the rucio01/rucio repository into your private account (upper left corner). Do this.

Afterwards, switch to your private account and clone it, for example::

   $ git clone https://gitlab.cern.ch/<cern_username>/rucio.git

Setup your git environment. You must provide a valid e-mail address and ask Developer access to the project Rucio in Gitlab::

   $ git config ---global user.name='Joaquin Bogado'
   $ git config ---global user.name='joaquin.bogado@cern.ch'


The repository hooks and upstream are installed by executing the script tools/configure_git.sh::

   $ cd rucio
   $ ./tools/configure_git.sh


Verify that everything is alright. You should see both push/pull remotes for origin (your private account) and upstream (official rucio repository)::

   $ git remote -v
    origin  ssh://git@gitlab.cern.ch:7999/jbogadog/rucio.git (fetch)
    origin  ssh://git@gitlab.cern.ch:7999/jbogadog/rucio.git (push)
    upstream        https://gitlab.cern.ch/rucio01/rucio.git (fetch)
    upstream        xxx (push)

Also, it's necessary to create the file .gitlabkey with the development key provided by the GitLab interface (gitlabkey_) in the local directory.


.. _gitlabkey: https://gitlab.cern.ch/profile/account

-----------------------
Installing dependencies
-----------------------

Rucio maintains three lists of dependencies::

   $ tools/pip-requires
   $ tools/pip-requires-client
   $ tools/pip-requires-test

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

----------------------------
PyPi Packages and VirtualEnv
----------------------------

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

--------------------
Developing a feature
--------------------

Features are scheduled for the next Rucio release and are collected from the protected "next" branch. Create a new feature branch with::

   $ tools/create-feature-branch <ticketnumber> <branch description>

and do your development there. When done, push the branch into origin (your private account) for code review::

   $ tools/submit-merge

------------------
Developing a patch
------------------

A patch works exactly the same, but is branched off the "master". Create a new patch branch with::

   $ tools/create-patch-branch <ticketnumber> <branch description>

and do your development there. When done, push the branch into origin (your private account) for code review:::

   $ tools/submit-merge

-------------------------------
Code review and merging a patch
-------------------------------

Two rules must be obeyed:

  1. Feature branches must be merged into "next"
  2. Patch branches must be merged into "master" and "next"

(For now, step 2 is manual, we will automate it in the future.) Click the "Merge request" button in the web-interface and select the (potentially two) appropriate destination branches, e.g., from youraccount/featurebranch to rucio/next. Don't forget that patch branches need two merge requests, both into "next" and "master". (In the future, this will be automated. It is also possible to do this via CLI only, no web interface is actually needed.)

The merge request will enable the code review. After successful code review, the responsible can merge the patch on the web interface.

*If something is weird, ask for help on rucio-dev@cern.ch :-D*

----------------
Ticketing system
----------------

For Rucio we are using Jira to manage the development of the project:

    https://its.cern.ch/jira/browse/RUCIO

Tickets for new features should be submitted with a functional granularity, that is according to the API call being introduced and at which level it belongs. For example, "register_dataset API (CORE)", "register_dataset (REST)", and "register_dataset API (CLIENT)", instead of big and vague new feature definitions like "new dataset functionality". This level of granularity allows better tracking of the progress of the RUCIO project, informs developers when new interfaces become available, and leads to more meaningful changelogs when a release is made.

In order to avoid generating too many tickets and insuring the documentation of relevant work is placed in a single description, all minor schema changes and corresponding test cases should be included as part of the new feature ticket and seperate tickets should not be made. The exception to this is if additional functionality, a bug fix or a new test case is added to the task in a newer release of Rucio, this then should be documented as a new ticket, rather than modifying the existing ticket (as it is assigned to the previous Rucio release).

The ticket workflow in Jira is summarised here:

    https://confluence.atlassian.com/download/attachments/284367573/system-workflow.png

When one is finished working on a new feature or bug fix and this has been commited and submitted to Code Review for approval, the ticket status should be changed to 'resolved'. Once the new code has been approved and commited to the GIT master the ticket status should be changed to 'closed'.

GIT commits should include the relevant JIRA ticket number(s) in the beginning of the commit message. This is because Jira is integrated with GIT and will associate the tickets to the corresponding GIT commits.

Jira ticket headers and descriptions will be included on release changelogs. For this reason the titles and descriptions should be meaningful.
