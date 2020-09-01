=================
Contributor Guide
=================

* Thank you for participating!
* Please ensure that an `issue <https://github.com/rucio/rucio/issues/new>`_ exists before submitting your contribution as a pull request.
* The issue should contain the motivation, modification and expected results (discussions usually happen there).
* No pull request will be merged without an associated issue (release notes are generated from issues).
* You should make sure to add your name (and organisation) to `AUTHORS <AUTHORS.rst>`_.
* If you have questions, you can reach the core development team on our `Slack <https://rucio.slack.com/>`_ channel, or send an email to our development mailing list `rucio-dev@cern.ch <mailto:rucio-dev@cern.ch>`_.

A contribution can be either be a **patch**, **feature**, or **hotfix**:
 * **Patches** include bugfixes and minor changes to the code and are included in patch releases usually made on a bi-weekly schedule.
 * **Features** include major developments or potentially disruptive changes and are included in feature releases made multiple times a year.
 * **Hotfix** are specific patch releases happening due to the necessity of important fixes.

The `repository <https://github.com/rucio/rucio/>`_  consists of different branches:
 * the **master** branch includes the development for the next major version.
 * the **release-…** branches include the patch/minor development of the releases.
 * the **hotfix-…** branches include the patches for hotfix releases.

On release day both master and the related release branch are essentially the same. Release branches only exist for the currently maintained release versions. Hotfix branches are created on demand. Please communicate to the Rucio maintainers, if you wish to hotfix a previous release.

Generally all `pull requests <https://github.com/rucio/rucio/pulls>`_ are to be created against the Rucio **master** branch. Features will end up in the upstream **master** only and patches are cherry-picked to the maintained releases if applicable. Release-specific changes are excluded from that rule and might be needed if e.g. cherry-picking to the last release was not successful.

The following figure might help you with an overview:

.. image:: https://raw.githubusercontent.com/rucio/rucio/master/doc/source/images/branching_strategy.svg


Getting started
---------------

**Step 1**: Fork the `repository <https://github.com/rucio/rucio/>`_ on Github.

**Step 2**: Clone the repository to your development machine and configure it::

    $ git clone https://github.com/<YOUR_USER>/rucio/
    $ cd rucio
    $ git remote add upstream https://github.com/rucio/rucio.git


Git Hooks
---------

Some git hooks (pre-commit, prepare-commit-msg) can be installed by executing the script::

    $ ./tools/configure_git.sh


Contributing
------------

**Step 1**: If not exist, create an `issue <https://github.com/rucio/rucio/issues/new>`_ with the description of the contribution (motivation, modification and expected results). Every issue will get a **unique issue number**.

**Step 2**: Create a local branch that corresponds to the issue. To easily identify the purpose of branches different keywords must be used:

* Patch branches must be named **patch-[issue number]-[short description]**
* Feature branches must be named **feature-[issue number]-[short description]**
* Hotfix branches must be named **hotfix-[issue number]-[short description]**

If you create these branches by hand please check the spelling because otherwise the test automation might misidentify your branch. There are utility scripts to fetch master and create these branches for you::

    $ ./tools/create-patch-branch <unique issue number> '<short_change_message>'
    $ ./tools/create-feature-branch <unique issue number> '<short_change_message>'
    $ ./tools/create-hotfix-branch <release tag/release branch> <unique issue number> '<short_change_message>'

**Step 3**: Commit your change. The commit command must include a specific message format::

    $ git commit -m "<component>: <change_message> #<issue number>"

Valid component names are listed in the `label list <https://github.com/rucio/rucio/labels>`_ and are usually specified on the issue of the change.

If you use the default commit message template, make sure you edit it.

If you add a `github-recognised keyword <https://help.github.com/articles/closing-issues-using-keywords/>`_ then the associated issue can be closed automatically once the pull request is merged, e.g.::

    <component>: <change_message> Fix #<issue number>

**Step 4**: Push the commit to your forked repository and create the pull request.

While using the `github interface <https://help.github.com/articles/creating-a-pull-request/>`_ is the default interface to create pull requests, you could also use GitHub's command-line wrapper `hub <https://hub.github.com>`_ or the `GitHub CLI <https://cli.github.com/>`_.

The format of the pull request title must be::

    <component>: <short_change_message> #<issue number>

**Step 5**: Watch the pull request for comments and reviews. For any pull requests update, please try to squash/amend your commits to avoid "in-between" commits.


Automatic Testing
-----------------

Every submitted pull request will automatically be run through automated testing through continuous integration. You should see the status of these tests on your pull request.

**Local automatic testing**

There is also a local shell script to run the same autotests: :code:`tools/run_autotests.sh`. For manual local testing within containers, please see `the docker README <etc/docker/dev/README.rst>`_.

**WARNING:** Because of the nature of using the same scripts as continuous integration, some containers may be left running after a test run or when aborting the test run. This is especially the case for running this script without podman.

By default the tool uses 3 worker processes to run all tests that are defined in :code:`etc/docker/test/matrix.yml`. Feel free to modify the matrix to your needs, but be sure to not unintentionally commit your changes to it. The tests run at most 6 hours - after that a TimeoutError will be raised, causing the script to fail. Running the autotests like this can be parameterized with environment variables as follows:

* :code:`USE_PODMAN` 0/1 (default: depends on whether the docker command points to podman)
   Use podman and therefore pods to run the tests.
* :code:`PARALLEL_AUTOTESTS` 0/1 (default: 1)
   1 enables multiple processes to run autotests and 0 disables it.
   When enabled, logs of the running autotests will be written to the :code:`.autotest` directory created in the working directory. Otherwise the log output will be written to the console (stderr).

   *Note that when tests are not running in parallel mode, the test run will always fail fast.*
* :code:`PARALLEL_AUTOTESTS_PROCNUM` (1,) (default: 3)
   Specifies the number of processes to run and therefor the concurrently run autotests. 3 will usually result in more than 8 GB RAM usage and a fair amount of load on the PC.
* :code:`PARALLEL_AUTOTESTS_FAILFAST` 0/1 (default: 0)
   Will abort the parallel run of autotests as soon as possible after at least one autotest failed. Enabling this will leave containers running in case of a failure even on podman.
* :code:`COPY_AUTOTEST_LOGS` 0/1 (default: 0)
   Copies :code:`/var/log` from the rucio container into the :code:`.autotest` directory after the test run. Each test case will have it's specific naming as with the logs from the parallel run above.


Human Review
------------

Anyone is welcome to review merge requests and make comments!

The Rucio development team can approve, request changes, or close pull requests. Merging of approved pull requests is done by the Rucio development lead.


Coding Style
------------

We use flake8 and pylint to sanitize our code. Please do the same before submitting a pull request.
