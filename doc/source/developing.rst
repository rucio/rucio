================
Developing Rucio
================

--------------------------------------
Code Review and Submitting a patch set
--------------------------------------

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

    $ git checkout new_feature                       # make sure we're on the right branch
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

--------------------------------------------------------------------
I have a conflict in my patch set and I need to merge. What do I do?
--------------------------------------------------------------------

If you get an error message from gerrit like "Please merge (or rebase) the change locally and upload the resolution for review.", then that means that someone got a change approved for a file while you were working on the same file. This means that you need to fix your commit:

    1. Make sure you're on your master branch::

        git checkout master

    2. Get the newest changesets from origin/master::

        git fetch; git pull

    3. Switch to your feature branch and merge in the changes::

        git checkout my_feature
        git rebase master

    4. This will break at some point at the problematic file(s). Edit them and mark them as resolved::

        emacs file1
        emacs file2
        git add file1
        git add file2

    5. Finish the merge::

        git rebase --continue

    6. Submit for review::

        tools/submit-review -a "merged conflicts"

----------------
Ticketing system
----------------

For Rucio we are using Jira to manage the development of the project:

    https://its.cern.ch/jira/browse/RUCIO

Tickets for new features should be submitted with a functional granularity, that is according to the API call being introduced and at which level it belongs. For example, "register_dataset API (CORE)", "register_dataset (REST)", and "register_dataset API (CLIENT)", instead of big and vague new feature definitions like "new dataset functionality". This level of granularity allows better tracking of the progress of the RUCIO project, informs developers when new interfaces become available, and leads to more meaningful changelogs when a release is made. 

In order to avoid generating too many tickets and insuring the documentation of relevant work is placed in a single description, all minor schema changes and corresponding test cases should be included as part of the new feature ticket and seperate tickets should not be made. The exception to this is if additional functionality, a bug fix or a new test case is added to the task in a newer release of Rucio, this then should be documented as a new ticket, rather than modifying the existing ticket (as it is assigned to the previous Rucio release).

The ticket workflow in Jira is summarised here:

    https://confluence.atlassian.com/download/attachments/284367573/system-workflow.png

When one is finished working on a new feature or bug fix and this has been commited and submitted to Gerrit for approval, the ticket status should be changed to 'resolved'. Once the new code has been approved and commited to the GIT master the ticket status should be changed to 'closed'.

GIT commits should include the relevant JIRA ticket number(s) in the beginning of the commit message. This is because Jira is integrated with GIT and will associate the tickets to the corresponding GIT commits.  

Jira ticket headers and descriptions will be included on release changelogs. For this reason the titles and descriptions should be meaningful.
