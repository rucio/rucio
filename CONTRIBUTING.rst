Contributor Guide
=================

When an developer does a Rucio contribution, he/she should make sure to add his/her name
(and the possible organisation) to `AUTHORS`_.

  Step 1. Fork the Rucio github repository `https://github.com/rucio/rucio/ <https://github.com/rucio/rucio/>`_ and configure it::

    $ git clone https://github.com/<YOUR_USER>/rucio/
    $ git remote add YOUR_USER https://github.com/YOUR_USER/rucio.git
    $ git remote add upstream https://github.com/rucio/rucio.git

  Step 2. Create an issue on `https://github.com/rucio/rucio/issues/new <https://github.com/rucio/rucio/issues/new>`_ with the mandatory tag to know the contribution types: bug, New Feature, Improvement and
  the millestone: X.Y.Z, X.Y.Z-clients, X.Y.Z-webui.

  Step 3. Create a local branch. For this, there are utility scripts::

    $ ./tools/create-patch-branch <issue number> 'new patch'
    $ ./tools/create-feature-branch <issue number> 'new patch'

  Step 4. Commit your change to your forked repository. The commit message should
  include the touched components and the issue number, e.g.,::

    $ git commit -m "clients: Fix #1"
    # push the changes to your remote
    $ git push YOUR_USER <local branch>

   Valid components are: Accounting & Dumps, Atropos / Lifetime Model, Auditor / Consistency checks, Automatix / Functional test, Data injector, BB8 / Data Rebalancing, C3PO / Data Pre-Placement, Conveyor / Transfers, Core / Rucio internals, Documentation, Hermes / Messaging, Infrastructure, Judge / Rules, Kronos / Traces, Popularity, last access time support, Monitoring & Logging, Necromancer / Recovery, Probes & Alarms, Protocols & RSE Manager, Python clients / CLIs, Reaper / Deletion, Release management & deployment, Rucio WebUI, Testing & Code quality, Transmogrifier / Subscriptions, Undertaker / Expired datasets deletion


  Step 5. Create a pull request::

    # For feature
    $ git pull-request -m "clients: Fix #1"  -b next  https://github.com/rucio/rucio/issues/<number>
    # For patch
    $ git pull-request -m "clients: Fix #1"  -b master https://github.com/rucio/rucio/issues/<number>
    $ git pull-request -m "clients: Fix #1"  -b next  https://github.com/rucio/rucio/issues/<number>
    # For hotfix
    $ git pull-request -m "clients: Fix #1"  -b master https://github.com/rucio/rucio/issues/<number>
    $ git pull-request -m "clients: Fix #1"  -b next  https://github.com/rucio/rucio/issues/<number>
    $ git pull-request -m "clients: Fix #1"  -b hotfix  https://github.com/rucio/rucio/issues/<number>

    or use the script:

    $ tools/submit-pull-request

    To iterate on the requests: commit and push.

  Once pull requests are merged, the associate issue will be closed automatically. Locally, you can then delete remote and local branches::

    $ git push -d <remote_name> <branch_name>
    $ git branch -d <branch_name>

