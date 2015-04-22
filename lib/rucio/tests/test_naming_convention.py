"""
   Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
"""

from nose.tools import assert_equal, assert_raises

from rucio.common.exception import InvalidObject
from rucio.core.naming_convention import (add_naming_convention, validate_name,
                                          list_naming_conventions)
from rucio.db.constants import KeyType


class TestNamingConventionCore:

    def test_naming_convention(self):
        """ NAMING_CONVENTION(CORE): Add and validate naming convention."""

        conventions = {}
        for d in list_naming_conventions():
            conventions[d['scope']] = d['regexp']

        if 'mock' not in conventions:
            add_naming_convention(scope='mock',
                                  regexp='(?P<project>mock)\.(\w+)$',
                                  convention_type=KeyType.DATASET)

        meta = validate_name(scope='mck', name='mock.yipeeee', did_type='D')
        assert_equal(meta, None)

        meta = validate_name(scope='mock', name='mock.yipeeee', did_type='D')
        assert_equal(meta, {u'project': 'mock'})

        with assert_raises(InvalidObject):
            validate_name(scope='mock', name='mockyipeeee', did_type='D')
