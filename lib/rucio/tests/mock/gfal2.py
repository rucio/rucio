# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017

import contextlib


class MockGfal2(object):
    """
    This is a mock gfal2 to test the Storage dumper
    """
    files = {}

    class MockContext(object):
        def open(self, filename, mode='r'):
            if mode == 'r':
                pass
            return MockGfal2.files[filename]

    @staticmethod
    def creat_context():
        return MockGfal2.MockContext()


@contextlib.contextmanager
def mocked_gfal2(module, **configuration):
    for attr, value in configuration.items():
        setattr(MockGfal2, attr, value)

    setattr(module, 'gfal2', MockGfal2)
    try:
        yield
    finally:
        delattr(module, 'gfal2')
