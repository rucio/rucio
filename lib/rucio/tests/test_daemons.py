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

import sys

import pytest

import rucio.db.sqla.util
from rucio.common import exception
from rucio.daemons.abacus import account, collection_replica, rse
from rucio.daemons.atropos import atropos
from rucio.daemons.automatix import automatix
from rucio.daemons.badreplicas import minos, minos_temporary_expiration, necromancer
from rucio.daemons.c3po import c3po
from rucio.daemons.cache import consumer
from rucio.daemons.conveyor import finisher, poller, receiver, stager, submitter, throttler, preparer
from rucio.daemons.follower import follower
from rucio.daemons.hermes import hermes, hermes2
from rucio.daemons.judge import cleaner, evaluator, injector, repairer
from rucio.daemons.oauthmanager import oauthmanager
from rucio.daemons.reaper import dark_reaper, light_reaper, reaper
from rucio.daemons.replicarecoverer import suspicious_replica_recoverer
from rucio.daemons.tracer import kronos
from rucio.daemons.transmogrifier import transmogrifier
from rucio.daemons.undertaker import undertaker

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock


DAEMONS = [
    account,
    collection_replica,
    rse,
    atropos,
    automatix,
    minos,
    minos_temporary_expiration,
    necromancer,
    c3po,
    consumer,
    finisher,
    poller,
    receiver,
    stager,
    submitter,
    throttler,
    preparer,
    follower,
    hermes,
    hermes2,
    cleaner,
    evaluator,
    injector,
    repairer,
    oauthmanager,
    dark_reaper,
    light_reaper,
    reaper,
    suspicious_replica_recoverer,
    kronos,
    transmogrifier,
    undertaker,
]

ids = [mod.__name__ for mod in DAEMONS]


@pytest.mark.parametrize('daemon', argvalues=DAEMONS, ids=ids)
@mock.patch('rucio.db.sqla.util.is_old_db')
def test_fail_on_old_database(mock_is_old_db, daemon):
    """ DAEMON: Test daemon failure on old database """
    mock_is_old_db.return_value = True
    assert rucio.db.sqla.util.is_old_db() is True

    with pytest.raises(exception.DatabaseException, match='Database was not updated, daemon won\'t start'):
        daemon.run()

    assert mock_is_old_db.call_count > 1
