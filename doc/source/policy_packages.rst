Policy packages
===============

Overview
~~~~~~~~

Policy packages are separate Python packages that can be used to add experiment-specific customisations to Rucio. They typically customise Rucio's handling of permissions and schema as well as optionally adding their own algorithms for lfn to pfn conversion and surl construction.

Policy packages may be installed from a Python package repository such as `PyPi <https://pypi.python.org/>`_ or they may simply be installed in a local directory. In the latter case this directory will need to be added to the Rucio server's `PYTHONPATH` environment variable.

The name of the policy package in use is specified by the `package` value in the `[policy]` section of the Rucio configuration file. If no package is specified, a built in `generic` policy will be used. If a package is specified but cannot be loaded, Rucio will exit with an error.

Creating a policy package
~~~~~~~~~~~~~~~~~~~~~~~~~

The structure of a policy package is very simple. It contains the following:

* a `permission.py` module implementing permission customisations.
* a `schema.py` module implementing schema customisations.
* an optional `__init__.py` file that registers lfn to pfn and surl construction algorithms when the package is loaded.

The easiest way to create the `permission.py` and `schema.py` modules is to modify the generic versions from the Rucio codebase. These can be found in `lib/rucio/core/permission/generic.py` and `lib/rucio/common/schema/generic.py` respectively.
