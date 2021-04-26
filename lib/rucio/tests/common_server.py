# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
#
# Authors:
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

from rucio.core import config as config_db
from rucio.core.vo import map_vo
from rucio.db.sqla import session, models
from rucio.tests.common import get_long_vo


# Functions containing server-only includes that can't be included in client tests


def reset_config_table():
    """ Clear the config table and install any default entires needed for the tests.
    """
    db_session = session.get_session()
    db_session.query(models.Config).delete()
    db_session.commit()
    config_db.set("vo-map", "testvo1", "tst")
    config_db.set("vo-map", "testvo2", "ts2")


def get_vo():
    """ Gets the current short/mapped VO name for testing.
    Maps the vo name to the short name, if configured.
    :returns: VO name string.
    """
    return map_vo(get_long_vo())
