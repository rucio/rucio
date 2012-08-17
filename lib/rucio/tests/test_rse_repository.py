# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import json

from nose.tools import raises

from rucio.common import exception
from rucio.rse import wrapper


class TestRseRepository():
    def test_storage_success(self):
        """ RSE (RSE): Repository => Using a defined storage """
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials['username'] = str(data['lxplus.cern.ch']['username'])
        credentials['password'] = str(data['lxplus.cern.ch']['password'])
        credentials['host'] = 'lxplus.cern.ch'
        self.storage = wrapper.RSEWrapper('lxplus.cern.ch')
        self.storage.connect(credentials)
        self.storage.close()

    @raises(exception.RSENotFound)
    def test_storage_failure(self):
        """ RSE (RSE): Repository => Storage not defined Exception """
        wrapper.RSEWrapper('not.existing')
