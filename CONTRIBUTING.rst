=================
Contributor Guide
=================

* Thank you for participating!
*  Please ensure that an `issue <https://github.com/rucio/rucio/issues/new>`_ exists before submitting your contribution as a pull request.
* The issue should contain the motivation, modification and expected results (discussions usually happen there).
* No pull request will be merged without an associated issue (release notes are generated from issues).
* You should make sure to add your name (and organisation) to `AUTHORS <AUTHORS.rst>`_.

A contribution can be either be a **patch**, **feature**, or **hotfix**:
 * **Patches** include bugfixes and minor changes to the code and are included in patch releases usually made on a bi-weekly schedule.
 * **Features** include major developments or potentially disruptive changes and are included in feature releases made multiple times a year.
 * **Hotfix** are specific patch releases happening due to the necessity of important fixes.

Accordingly, the `repository <https://github.com/rucio/rucio/>`_  consists of three different branches:
 * the **master** branch includes the patch/minor development of the current major version.
 * the **next** branch includes the development for the next major version.
 * the **hotfix** branch includes the patch for hotfix releases.

Thus, on release day of a feature release both master and next are the same,
afterwards they diverge until the next feature release.
Pull requests for **features** are only made against the **next** branch.
Pull requests for **patches** are made against the **next** and **master** branch, as
these bugfixes need to be represented in both branches. Thus two
pull requests are needed for patches, and the helper scripts do it
automatically for you.

Setting up the repository
-------------------------

**Step 1**: Fork the `repository <https://github.com/rucio/rucio/>`_ on Github.

**Step 2**: Clone the repository to your development machine and configure it::

  $ git clone https://github.com/<YOUR_USER>/rucio/
  $ cd rucio
  $ git remote add upstream https://github.com/rucio/rucio.git
  # Optional to track changes on the next branch
  $ git branch --track next

Contributing
------------


**Step 1**: Create an `issue <https://github.com/rucio/rucio/issues/new>`_ with the description
of the contribution (motivation, modification and expected results).
Every issue will get a **unique issue number**.

**Step 2**: Create a local branch that corresponds to the issue. There are utility scripts to help you with this::

  $ ./tools/create-patch-branch <unique issue number> '<short_change_message>'
  $ ./tools/create-feature-branch <unique issue number> '<short_change_message>'

**Step 3**: Commit your change. The commit command must include a specific message format::

git commit -m "<component>: <change_message> #<issue number>"

Valid component names are listed in the `label list <https://github.com/rucio/rucio/labels>`_.

If you add a `github-recognised keyword <https://help.github.com/articles/closing-issues-using-keywords/>`_ then
the associated issue can be closed automatically once the pull request is merged, e.g.::

    <component>: <change_message> Fix #<issue number>

**Step 4**: Push the commit to your forked repository and create the pull request(s). There is a helper script to assist you::

  $ ./tools/submit-pull-request

The helper script will propagate the commit message as the pull request title.

If you use different tools to create pull requests like the `github interface <https://help.github.com/articles/creating-a-pull-request/>`_
or the git command-line wrapper `hub <https://hub.github.com>`_, the following logic must be applied:

* If the contribution is a **patch**, two pull requests must be created, one for the **next** branch and another for the **master** branch.
* If the contribution is a new **feature**, one pull request must be created for the **next** branch.

The format of the pull request title must be:

    <component>: <short_change_message> #<issue number>

If you add a `github-recognised keyword <https://help.github.com/articles/closing-issues-using-keywords/>`_ then
the associated issue can be closed automatically once the pull request is merged, e.g.::

<component>: <short_change_message> Fix #<issue number>

For example, with `hub the git command-line wrapper <https://hub.github.com>`_  the commands for a **patch** are::

  $  git pull-request  -m  '<component>: <short_change_message> #<issue number>' -b master
  $  git pull-request  -m  '<component>: <short_change_message> #<issue number>' -b next

and for a new **feature**::

  $  git pull-request  -m  '<short_change_message> #<issue number>' -b next

**Step 5**: Watch the pull request for comments and reviews. For any pull requests update,
please try to squash/amend your commits to avoid "in-between" commits.

Automatic Review
----------------

Every submitted pull request will automatically be run through automated review and
testing(nosetests) with Travis.

Human Review
------------

Anyone is welcome to review merge requests and make comments!

All collaborators, thus the Rucio core development team can approve, request
changes or close pull requests. Merging of approved pull requests is done by the Rucio
development lead.


Coding Style and testing
------------------------

We use flake8 and pylint to sanitize our code. Please do the same before
submitting a pull request.


Git Hooks
---------

Some git hooks (pre-commit, prepare-commit-msg) can be installed by executing the script::

    $ ./tools/configure_git.sh
