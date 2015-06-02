======================
Development Guidelines
======================

-----------------
Coding Guidelines
-----------------

For the most part we try to follow PEP 8 guidelines which can be viewed here: http://www.python.org/dev/peps/pep-0008/

There is a useful pep8_ command line tool for checking files for pep8 compliance
which can be installed with ``easy_install pep8``. (It is also included in the
virtual environment)

.. _pep8: http://pypi.python.org/pypi/pep8

You can then run it manually with::

    pep8 --repeat --ignore=E501 lib

(Yes, we ignore the "E501 - line too long" warning.)

To run the unit/integrations tests including the test-coverage::

    nosetests -v --with-coverage --cover-package=rucio

------------------------
Documentation Guidelines
------------------------

The documentation in docstrings should follow the PEP 257 conventions (as mentioned in the PEP 8 guidelines).

More specifically:

    1.  Triple quotes should be used for all docstrings.
    2.  If the docstring is simple and fits on one line, then just use one line.
    3.  For docstrings that take multiple lines, there should be a newline after the opening quotes, and before the closing quotes.
    4.  Sphinx is used to build documentation, so use the restructured text markup to designate parameters, return values, etc.  Documentation on the sphinx specific markup can be found here:
        http://sphinx.pocoo.org/markup/index.html

---------------------
License and Copyright
---------------------

Every source file must have the following copyright and license statement at the top::

    # Copyright European Organization for Nuclear Research (CERN)
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # You may not use this file except in compliance with the License.
    # You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
    #
    # Authors:
    # - XXXX XXXXX, <xxxx.xxxx@cern.ch>, 2012

All __init__.py files must have the same header, excluding the authors declaration. e.g.::

    # Copyright European Organization for Nuclear Research (CERN)
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # You may not use this file except in compliance with the License.
    # You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

-----------------------
How to write test cases
-----------------------

The most important rule for API calls: ALWAYS WRITE YOUR TESTCASE AGAINST THE WEB-INTERFACE, NOT THE CORE API ITSELF! IF POSSIBLE, WRITE IT AGAINST THE CLIENT IF ONE EXISTS! This is to make sure that the full call chain works.

    1. Test cases go into either lib/rucio/tests/
    2. Filename must start with ``test_``
    3. Classname must start with Test
    4. Test function names must start with ``test_``
    5. Do not import unittest
    6. Do not subclass from unittest.TestCase
    7. Remove the whole __name__ == '__main__' thing
    8. Run all testcases with nosetests twice.

You can selectively run test cases by giving directories or files as parameters to the nosetests executable.


------------------------------------
Executing unit tests the correct way
------------------------------------

    1. Run ``tools/run_tests -1qa``
