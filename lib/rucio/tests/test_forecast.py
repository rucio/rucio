# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <jbogadog@cern.ch>, 2017

from rucio.extensions.forecast import T3CModel


class TestForecast():
    """
    Class to test the T3C prediction clases
    """

    def test_predict(self):
        model = T3CModel()
        data = [{'src': 'BNL-OSG2_DATADISK', 'dst': 'MWT2_DATADISK',
                 'activity': 'Production_Input', 'size': 213427540000}]
        result = model.predict(data)
        return result[0]['ntime'] > 0 and result[0]['qtime'] > 0
