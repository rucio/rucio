# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from rucio.core import rse as rse_module, distance as distance_module
from rucio.db.sqla.session import transactional_session


@transactional_session
def export_data(session=None):
    """
    Export data.

    :param session: database session in use.
    """
    data = {
        'rses': [rse_module.export_rse(rse['rse'], session=session) for rse in rse_module.list_rses(session=session)],
        'distances': distance_module.export_distances(session=session)
    }
    return data
