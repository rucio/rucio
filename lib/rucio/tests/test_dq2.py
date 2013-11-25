# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from nose.tools import assert_dict_equal

from rucio.client.dq2client import DQ2Client


class TestDQ2Client:

    def setup(self):
        self.client = DQ2Client()

    def test_finger(self):
        """  Finger (DQ2 CLIENT): """
        ret = self.client.finger()
        expected = {'dn': '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch',
                    'nickname': u'root',
                    'email': 'ph-adp-ddm-lab@cern.ch'}
        assert_dict_equal(ret, expected)
