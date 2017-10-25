Rucio
=====

Rucio is blah blah.

The master repository is on `<https://github.com/rucio/rucio>`_.

Contributor Guide
------------------

Guidelines::

    no direct pushing via git push, just Merge Request
    Collaborators can Review&Comment Merge Requests
    Collaborators can accept Merge Requests
    The Developer who accepts the Merge Requests must not be the Creator of the Merge Request


Configure git::
    # Fork the repo https://github.com/rucio/rucio/ on https://github.com/<YOUR_USER>/rucio/
    $ git clone https://github.com/<YOUR_USER>/rucio/
    $ git remote add YOUR_USER https://github.com/YOUR_USER/rucio.git
    $  git remote add upstream https://github.com/rucio/rucio.git

Workflow for contributing to rucio::

    # create a patch/feature/hotfix branch
    $ ./tools/create-patch-branch `uuidgen` 'new patch'
    # if topic is for an issue then add the issue number instead of uuidgen
    # ( making changes ... )
    $ git commit -m "done with patch"

    # push the changes to your remote
    $ git push YOUR_USER <local branch>
    # open pull requests for the topic branch you've just pushed
    # For patch
    $ git pull-request $ -m "new patch"  -b next  --labels <label> ---M <milestone>
    $ git pull-request  -m "new patch"  -b master
    # For feature
    $ git pull-request $ -m "new patch"  -b next
    # if an issue should be associated to the pull requests
    # then add the issue url <ISSUE-URL> at the end
    # e.g. git pull-request  -m "new patch"  -b master https://github.com/rucio/rucio/issues/<number>

Once pull requests are merged, delete remote and local branches::
    git push -d <remote_name> <branch_name>
    git branch -d <branch_name>

Link issue and pull requests::

If a pull request solved an issue: fixes #<>  should be added in the comment.
pull request numbers should be added in
