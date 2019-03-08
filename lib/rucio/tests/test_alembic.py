# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

from __future__ import print_function

from nose.tools import assert_equal

from rucio.tests.common import execute


class TestAlembicMigration():

    def test_downgrade_and_upgrade(self):
        """ ALEMBIC (CORE): Test the schema migration """

        cmd = 'alembic downgrade base'
        exitcode, out, err = execute(cmd)
        print(cmd)
        print(exitcode, out, err)
        assert_equal(exitcode, 0)

        cmd = 'alembic upgrade head'
        exitcode, out, err = execute(cmd)
        print(cmd)
        print(exitcode, out, err)
        assert_equal(exitcode, 0)
