# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import pytest


def pytest_collection_modifyitems(items):
    '''
        Automatically adding markers based on test/class names
    '''
    for item in items:
        if "test_rse_protocol" in item.nodeid:
            item.keywords["protocol"] = pytest.mark.protocol
        else:
            item.keywords["non_protocol"] = pytest.mark.non_protocol


@pytest.fixture(scope="session", autouse=True)
def start_apache_server(request):
    print 'start apache'

    def fin():
        print 'stop apache'
    request.addfinalizer(fin)


@pytest.fixture(scope="session", autouse=True)
def boostrap_db(request):
    print 'bootstrap db'

    def fin():
        print 'rset db'
    request.addfinalizer(fin)
