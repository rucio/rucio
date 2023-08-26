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

import contextlib


class MockGfal2(object):
    """
    This is a mock gfal2 to test the Storage dumper
    """
    files = {}

    class MockContext(object):
        '''
        MockContext
        '''
        def open(self, filename, mode='r'):
            '''
            open
            '''
            if mode == 'r':
                pass
            return MockGfal2.files[filename]

    @staticmethod
    def creat_context():
        '''
        creat_context
        '''
        return MockGfal2.MockContext()


@contextlib.contextmanager
def mocked_gfal2(module, **configuration):
    '''
    mocked_gfal2
    '''
    for attr, value in configuration.items():
        setattr(MockGfal2, attr, value)

    setattr(module, 'gfal2', MockGfal2)
    try:
        yield
    finally:
        delattr(module, 'gfal2')
