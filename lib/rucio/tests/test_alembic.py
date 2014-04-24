# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

from nose.tools import assert_equal

from rucio.tests.common import execute


class TestAlembicMigration():

    def test_downgrade_and_upgrade(self):
        """ ALEMBIC (CORE): Test the schema migration """

        cmd = 'alembic upgrade head'
        exitcode, out, err = execute(cmd)
        print cmd
        print exitcode, out, err
        assert_equal(exitcode, 0)

        cmd = 'alembic downgrade  -1'
        while exitcode is 0:
            exitcode, out, err = execute(cmd)
            print cmd
            print exitcode, out, err
            if "Relative revision -1 didn't produce 1 migrations" not in out:
                assert_equal(exitcode, 0)
            else:
                assert_equal(exitcode, 255)

        cmd = 'alembic upgrade head'
        exitcode, out, err = execute(cmd)
        print cmd
        print exitcode, out, err
        assert_equal(exitcode, 0)
