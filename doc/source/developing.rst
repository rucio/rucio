================
Developing Rucio
================

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

Afterwards, switch to your private account and clone it, for example:

    git clone https://gitlab.cern.ch/<cern_username>/rucio

This will be your private copy of Rucio that has no knowledge of upstream. So first, add upstream as a remote:

    git remote add upstream https://gitlab.cern.ch/rucio01/rucio

Verify that everything is alright with:

   git remote -v

You should see both push/pull remotes for origin (your private account) and upstream (official rucio repository).

--------------------
Developing a feature
--------------------

Features are scheduled for the next Rucio release and are collected from the protected "next" branch. Create a new feature branch with:

    tools/create-feature-branch <ticketnumber> <branch description>

and do your development there. When done, push the branch into origin (your private account) for code review:

    git push origin

------------------
Developing a patch
------------------

A patch works exactly the same, but is branched off the "master". Create a new patch branch with

    tools/create-patch-branch <ticketnumber> <branch description>

and do your development there. When done, push the branch into origin (your private account) for code review:

    git push origin

-------------------------------
Code review and merging a patch
-------------------------------

Two rules must be obeyed:

  1. Feature branches must be merged into "next"
  2. Patch branches must be merged into "master" and "next"

(For now, step 2 is manual, we will automate it in the future.) Click the "Merge request" button in the web-interface and select the (potentially two) appropriate destination branches, e.g., from youraccount/featurebranch to rucio/next. Don't forget that patch branches need two merge requests, both into "next" and "master". (In the future, this will be automated. It is also possible to do this via CLI only, no web interface is actually needed.)

The merge request will enable the code review. After successful code review, the responsible can merge the patch on the web interface.

TL;DR: If something is weird, ask for help on rucio-dev@cern.ch :-D

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
