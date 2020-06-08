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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core
from rucio.daemons.reaper.reaper2 import reaper


def test_reaper():
    """ REAPER2 (DAEMON): Test the reaper2 daemon."""

    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
    else:
        vo = {}

    nb_files = 30
    file_size = 2147483648  # 2G
    rse_id = rse_core.get_rse_id(rse='MOCK', **vo)

    for i in range(nb_files):
        replica_core.add_replica(rse_id=rse_id, scope=InternalScope('data13_hip', **vo),
                                 name='lfn' + generate_uuid(), bytes=file_size,
                                 account=InternalAccount('root', **vo), adler32=None, md5=None)

    rse_core.set_rse_usage(rse_id=rse_id, source='srm', used=nb_files * file_size, free=800)
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=10737418240)
    rse_core.set_rse_limits(rse_id=rse_id, name='MaxBeingDeletedFiles', value=10)

    if vo:
        reaper(once=True, rses=[], include_rses='vo=%s&(MOCK)' % vo['vo'], exclude_rses=[])
        reaper(once=True, rses=[], include_rses='vo=%s&(MOCK)' % vo['vo'], exclude_rses=[])
    else:
        reaper(once=True, rses=[], include_rses='MOCK', exclude_rses=[])
        reaper(once=True, rses=[], include_rses='MOCK', exclude_rses=[])
