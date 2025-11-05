# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import pytest

from rucio.common.exception import InvalidObject
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.naming_convention import add_naming_convention, delete_naming_convention, list_naming_conventions, validate_name
from rucio.db.sqla.constants import DatabaseOperationType, KeyType
from rucio.db.sqla.session import db_session


@pytest.mark.noparallel(reason='changes global naming conventions, breaks other tests')
class TestNamingConventionCore:
    '''
    Class to test naming convention enforcement.
    '''

    def test_naming_convention(self, vo, mock_scope, did_client):
        """ NAMING_CONVENTION(CORE): Add and validate naming convention."""
        conventions = {}
        with db_session(DatabaseOperationType.READ) as session:
            for convention in list_naming_conventions(session=session):
                conventions[convention['scope']] = convention['regexp']

        scope = mock_scope
        if scope not in conventions:
            with db_session(DatabaseOperationType.WRITE) as session:
                add_naming_convention(scope=scope,
                                      regexp=r'^(?P<project>mock)\.(?P<datatype>\w+)\.\w+$',
                                      convention_type=KeyType.DATASET,
                                      session=session)

        with db_session(DatabaseOperationType.READ) as session:
            meta = validate_name(
                scope=InternalScope('mck', vo=vo),
                name='mock.DESD.yipeeee',
                did_type='D',
                session=session)
            assert meta is None

            meta = validate_name(
                scope=scope,
                name='mock.DESD.yipeeee',
                did_type='D',
                session=session)
            assert meta == {'project': 'mock', 'datatype': 'DESD'}

            with pytest.raises(InvalidObject):
                validate_name(
                    scope=scope,
                    name='mockyipeeee',
                    did_type='D',
                    session=session)

        # Register a dataset
        tmp_dataset = 'mock.AD.' + str(generate_uuid())
        with pytest.raises(InvalidObject):
            did_client.add_dataset(scope='mock', name=tmp_dataset, meta={'datatype': 'DESD'})

        with pytest.raises(InvalidObject):
            did_client.add_dataset(scope='mock', name=tmp_dataset)

        tmp_dataset = 'mock.AOD.' + str(generate_uuid())
        did_client.add_dataset(scope='mock', name=tmp_dataset)
        observed_datatype = did_client.get_metadata(scope='mock', name=tmp_dataset)['datatype']
        assert observed_datatype == 'AOD'

        with db_session(DatabaseOperationType.WRITE) as session:
            delete_naming_convention(scope=scope, convention_type=KeyType.DATASET, session=session)
