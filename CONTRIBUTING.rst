Contributor Guide
=================

* Thank you for participating!
* A contribution(pull request) requires to have one `issue <https://github.com/rucio/rucio/issues/new>`_ created.
* The issue should contain the motivation, modification and expected results (discussions usually happen there).
* No pull request will be merged without an associated issue (release notes are generated from issues).
release notes for your Git project. Works with GitHub, Jira and YouTrack. TFS Support coming soon.
* You should make sure to add your name (and the organisation) to `AUTHORS`_.

A contribution can be either be an **patch**, **feature**, or **hotfix**:
 * **Patch** include bugfixes and minor changes to the code and goes in Patch releases (usually made on a bi-weekly schedule).
 * **Feature** include major developments or potentially disruptive changes and goes in Feature release (made multiple times a year).
 * **Hotfix** are specific patch happening due to the necessity of important fixes and goes in postfix release (made when needed).

Accordingly, the `repository <https://github.com/rucio/rucio/>`_  consists of three different branches:
 * the **master** branch includes the patch/minor development of the current major version.
 * the **next** branch includes the development for the next major version.
 * the **hotfix** branch includes the patch for postfix releases.

Thus, on release day of a feature release both master and next are the same,
afterwards they diverge until the next feature release.
Pull requests for **features** are only made against the **next** branch.
Pull requests for **patches** are made against the **next** and **master** branch.
Simultaneously, as these bugfixes need to be represented in both branches. Thus two
pull requests are needed for patches, and the helper scripts do it
automatically for you.

Setting up the repository
=========================

**Step 1**: Fork the `repository <https://github.com/rucio/rucio/>`_ on Github

**Step 2**: Clone the repository to your development machine and configure it::

  $ git clone https://github.com/<YOUR_USER>/rucio/
  $ git remote add YOUR_USER https://github.com/YOUR_USER/rucio.git
  $ git remote add upstream https://github.com/rucio/rucio.git

Contributing
============

**Step 1**: Create an `issue <https://github.com/rucio/rucio/issues/new>`_ with the description
of the contribution (motivation, modification and expected results) with the
label **Patch**, **Feature** or **Hotfix** and a milestone. Every issue will
get a **unique issue number**.

**Step 2**: Create a local branch that corresponds to the issue. There are utility scripts to help you with this::

  $ ./tools/create-patch-branch <unique issue number> '<component> #<issue number>: <short_change_message>'
  $ ./tools/create-feature-branch <unique issue number> '<component> #<issue number>: <short_change_message>'

**Step 3**: Commit your change. The format of the commit message must be::

<component> #<issue number>: <change_message>

Valid component names are listed in the `label list <https://github.com/rucio/rucio/labels>`_

**Step 4**: Push the commit to your forked repository and create the pull request(s). There is a helper script to assist you::

  $ ./tools/submit-pull-request

**Step 5**: Watch the pull request for comments

***********
Code sanity
***********

- We use nosetests, flake8, and pylint to sanitize our code. Please do the same before submitting a pull request.
- Every submitted pull request will automatically be run through automated testing with Travis.
