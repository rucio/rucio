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
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
import nose.tools

from rucio.common.utils import execute, generate_uuid
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core

from rucio.clis.daemons.reaper.reaper import main


def test_reaper():
    """ REAPER (DAEMON): Test the reaper daemon."""
    nb_files = 30
    file_size = 2147483648  # 2G
    for _ in range(nb_files):
        replica_core.add_replica(rse='MOCK', scope='data13_hip',
                                 name='lfn' + generate_uuid(), bytes=file_size,
                                 account='root', adler32=None, md5=None)

    rse_core.set_rse_usage(rse='MOCK', source='srm', used=nb_files * file_size, free=800)
    rse_core.set_rse_limits(rse='MOCK', name='MinFreeSpace', value=10737418240)
    rse_core.set_rse_limits(rse='MOCK', name='MaxBeingDeletedFiles', value=10)

    argv = ['--run-once', '--rses', 'MOCK']
    main(argv)
    # Test the rucio-reaper console script
    cmd = 'rucio-reaper ' + ' '.join(argv)
    exitcode, out, err = execute(cmd)
    print(cmd, out, err)
    nose.tools.assert_equal(exitcode, 0)
