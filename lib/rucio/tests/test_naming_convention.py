# -*- coding: utf-8 -*-
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

import unittest

import pytest

from rucio.client.didclient import DIDClient
from rucio.common.config import config_get_bool
from rucio.common.exception import InvalidObject
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.naming_convention import (add_naming_convention,
                                          validate_name,
                                          list_naming_conventions,
                                          delete_naming_convention)
from rucio.db.sqla.constants import KeyType
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='changes global naming conventions, breaks other tests')
class TestNamingConventionCore(unittest.TestCase):
    '''
    Class to test naming convention enforcement.
    '''

    def setUp(self):
        """ Constructor."""
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.did_client = DIDClient()

    def test_naming_convention(self):
        """ NAMING_CONVENTION(CORE): Add and validate naming convention."""
        conventions = {}
        for convention in list_naming_conventions():
            conventions[convention['scope']] = convention['regexp']

        scope = InternalScope('mock', **self.vo)
        if scope not in conventions:
            add_naming_convention(scope=scope,
                                  regexp=r'^(?P<project>mock)\.(?P<datatype>\w+)\.\w+$',
                                  convention_type=KeyType.DATASET)

        meta = validate_name(scope=InternalScope('mck', **self.vo), name='mock.DESD.yipeeee', did_type='D')
        assert meta is None

        meta = validate_name(scope=scope, name='mock.DESD.yipeeee', did_type='D')
        assert meta == {u'project': 'mock', u'datatype': 'DESD'}

        with pytest.raises(InvalidObject):
            validate_name(scope=scope, name='mockyipeeee', did_type='D')

        # Register a dataset
        tmp_dataset = 'mock.AD.' + str(generate_uuid())
        with pytest.raises(InvalidObject):
            self.did_client.add_dataset(scope='mock', name=tmp_dataset, meta={'datatype': 'DESD'})

        with pytest.raises(InvalidObject):
            self.did_client.add_dataset(scope='mock', name=tmp_dataset)

        tmp_dataset = 'mock.AOD.' + str(generate_uuid())
        self.did_client.add_dataset(scope='mock', name=tmp_dataset)
        observed_datatype = self.did_client.get_metadata(scope='mock', name=tmp_dataset)['datatype']
        assert observed_datatype == 'AOD'

        delete_naming_convention(scope=scope, convention_type=KeyType.DATASET)
