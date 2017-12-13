# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <jbogadog@cern.ch>, 2017

from rucio.db.sqla import models
from rucio.db.sqla.session import read_session
from rucio.extensions.forecast import T3CModel

from random import choice


@read_session
def get_session(session=None):
    return session


class TestForecast():
    """
    Class to test the T3C prediction clases
    """
    def test_predict(self):
        session = get_session()
        src = choice(session.query(models.RSE).all()).rse
        dst = choice(session.query(models.RSE).all()).rse
        act = 'Production Input'
        size = 10**9

        model = T3CModel()

        data = [{'src': src, 'dst': dst, 'activity': act, 'size': size}]
        result = model.predict(data)
        return result[0]['ntime'] > 0 and result[0]['qtime'] > 0
