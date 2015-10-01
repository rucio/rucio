"""
   Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
"""

# pylint: disable=E0611
from nose.tools import assert_equal, assert_raises

from rucio.client.didclient import DIDClient
from rucio.common.exception import InvalidObject
from rucio.common.utils import generate_uuid
from rucio.core.naming_convention import (add_naming_convention,
                                          validate_name,
                                          list_naming_conventions,
                                          delete_naming_convention)
from rucio.db.sqla.constants import KeyType


class TestNamingConventionCore:
    '''
    Class to test naming convention enforcement.
    '''

    def __init__(self):
        """ Constructor."""
        self.did_client = DIDClient()

    def test_naming_convention(self):
        """ NAMING_CONVENTION(CORE): Add and validate naming convention."""
        conventions = {}
        for convention in list_naming_conventions():
            conventions[convention['scope']] = convention['regexp']

        if 'mock' not in conventions:
            add_naming_convention(scope='mock',
                                  regexp='^(?P<project>mock)\.(?P<datatype>\w+)\.\w+$',
                                  convention_type=KeyType.DATASET)

        meta = validate_name(scope='mck', name='mock.DESD.yipeeee', did_type='D')
        assert_equal(meta, None)

        meta = validate_name(scope='mock', name='mock.DESD.yipeeee', did_type='D')
        assert_equal(meta, {u'project': 'mock', u'datatype': 'DESD'})

        with assert_raises(InvalidObject):
            validate_name(scope='mock', name='mockyipeeee', did_type='D')

        # Register a dataset
        tmp_dataset = 'mock.AD.' + str(generate_uuid())
        with assert_raises(InvalidObject):
            self.did_client.add_dataset(scope='mock', name=tmp_dataset, meta={'datatype': 'DESD'})

        with assert_raises(InvalidObject):
            self.did_client.add_dataset(scope='mock', name=tmp_dataset)

        tmp_dataset = 'mock.AOD.' + str(generate_uuid())
        self.did_client.add_dataset(scope='mock', name=tmp_dataset)
        observed_datatype = self.did_client.get_metadata(scope='mock', name=tmp_dataset)['datatype']
        assert_equal(observed_datatype, 'AOD')

        delete_naming_convention(scope='mock',
                                 regexp='(?P<project>mock)\.(\w+)$',
                                 convention_type=KeyType.DATASET)
