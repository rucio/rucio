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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core
from rucio.daemons.reaper.reaper import reaper


def test_reaper():
    """ REAPER (DAEMON): Test the reaper daemon."""
    nb_files = 30
    file_size = 2147483648  # 2G
    rse_id = rse_core.get_rse_id(rse='MOCK')

    for i in range(nb_files):
        replica_core.add_replica(rse_id=rse_id, scope=InternalScope('data13_hip'),
                                 name='lfn' + generate_uuid(), bytes=file_size,
                                 account=InternalAccount('root'), adler32=None, md5=None)

    rse_core.set_rse_usage(rse_id=rse_id, source='srm', used=nb_files * file_size, free=800)
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=10737418240)
    rse_core.set_rse_limits(rse_id=rse_id, name='MaxBeingDeletedFiles', value=10)

    rses = [rse_core.get_rse(rse_core.get_rse_id('MOCK')), ]
    reaper(once=True, rses=rses)
    reaper(once=True, rses=rses)
