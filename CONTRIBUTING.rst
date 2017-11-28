Contributor Guide
=================

* Thank you for participating!
*  Please ensure that an `issue <https://github.com/rucio/rucio/issues/new>`_ exists before submitting your contribution as a pull request.
* The issue should contain the motivation, modification and expected results (discussions usually happen there).
* No pull request will be merged without an associated issue (release notes are generated from issues).
* You should make sure to add your name (and organisation) to `AUTHORS <AUTHORS>`_.

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
=========================

**Step 1**: Fork the `repository <https://github.com/rucio/rucio/>`_ on Github.

**Step 2**: Clone the repository to your development machine and configure it::

  $ git clone https://github.com/<YOUR_USER>/rucio/
  $ git remote add upstream https://github.com/rucio/rucio.git
  # Optional to track changes on the next branch
  $ git branch --track next

Contributing
============

**Step 1**: Create an `issue <https://github.com/rucio/rucio/issues/new>`_ with the description
of the contribution (motivation, modification and expected results).
Every issue will get a **unique issue number**.

**Step 2**: Create a local branch that corresponds to the issue. There are utility scripts to help you with this::

  $ ./tools/create-patch-branch <unique issue number> '<component> #<issue number>: <short_change_message>'
  $ ./tools/create-feature-branch <unique issue number> '<component> #<issue number>: <short_change_message>'

**Step 3**: Commit your change. The format of the commit message must be::

<component>: <change_message> #<issue number>

Valid component names are listed in the `label list <https://github.com/rucio/rucio/labels>`_

**Step 4**: Push the commit to your forked repository and create the pull request(s). There is a helper script to assist you::

  $ ./tools/submit-pull-request

**Step 5**: Watch the pull request for comments and reviews. For any pull requests update,
please try to squash/amend your commits to avoid "in-between" commits.

Automatic Review
================

Every submitted pull request will automatically be run through automated review and
testing(nosetests) with Travis.

Human Review
============

Anyone is welcome to review merge requests and make comments!

All collaborators, thus the Rucio core development team can approve, request
changes or close pull requests. Merging of approved pull requests is done by the Rucio
development lead.


Coding Style and testing
========================

We use flake8 and pylint to sanitize our code. Please do the same before
submitting a pull request.
