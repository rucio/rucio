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

import random
import threading
from datetime import datetime, timedelta

import pytest

from rucio.core.heartbeat import live, die, cardiac_arrest, list_payload_counts, list_heartbeats, sanity_check
from rucio.db.sqla.models import Heartbeats
from rucio.db.sqla.session import transactional_session


@pytest.fixture
def executable_factory(function_scope_prefix, db_session):
    executables = []

    def _create_executable():
        executable = f'{function_scope_prefix}_{len(executables)}'
        executables.append(executable)
        return executable

    yield _create_executable

    db_session.query(Heartbeats).where(Heartbeats.executable.in_(executables)).delete()


@pytest.fixture
def thread_factory():
    created_threads = []

    def _create_thread():
        th = threading.Thread()
        created_threads.append(th)
        th.start()
        return th

    yield _create_thread

    for thread in created_threads:
        thread.join()


class TestHeartbeat:

    def _pid(self):
        return random.randint(2, 2**16)

    def test_heartbeat_0(self, thread_factory, executable_factory):
        """ HEARTBEAT (CORE): Single instance """

        pid = self._pid()
        thread = thread_factory()
        executable = executable_factory()
        assert live(executable, 'host0', pid, thread) == {'assign_thread': 0, 'nr_threads': 1}
        assert live(executable, 'host0', pid, thread) == {'assign_thread': 0, 'nr_threads': 1}
        assert live(executable, 'host0', pid, thread) == {'assign_thread': 0, 'nr_threads': 1}

    def test_heartbeat_1(self, thread_factory, executable_factory):
        """ HEARTBEAT (CORE): Multiple instance """

        pids = [self._pid() for _ in range(4)]
        threads = [thread_factory() for _ in range(4)]
        executable = executable_factory()
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 1}
        assert live(executable, 'host1', pids[1], threads[1]) == {'assign_thread': 1, 'nr_threads': 2}
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 2}
        assert live(executable, 'host2', pids[2], threads[2]) == {'assign_thread': 2, 'nr_threads': 3}
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 3}
        assert live(executable, 'host3', pids[3], threads[3]) == {'assign_thread': 3, 'nr_threads': 4}
        assert live(executable, 'host1', pids[1], threads[1]) == {'assign_thread': 1, 'nr_threads': 4}
        assert live(executable, 'host2', pids[2], threads[2]) == {'assign_thread': 2, 'nr_threads': 4}
        assert live(executable, 'host3', pids[3], threads[3]) == {'assign_thread': 3, 'nr_threads': 4}

    def test_heartbeat_2(self, thread_factory, executable_factory):
        """ HEARTBEAT (CORE): Multiple instance with removal"""

        pids = [self._pid() for _ in range(4)]
        threads = [thread_factory() for _ in range(4)]
        executable = executable_factory()
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 1}
        assert live(executable, 'host1', pids[1], threads[1]) == {'assign_thread': 1, 'nr_threads': 2}
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 2}
        assert live(executable, 'host2', pids[2], threads[2]) == {'assign_thread': 2, 'nr_threads': 3}
        assert live(executable, 'host0', pids[0], threads[0]) == {'assign_thread': 0, 'nr_threads': 3}
        die(executable, 'host0', pids[0], threads[0])
        assert live(executable, 'host3', pids[3], threads[3]) == {'assign_thread': 2, 'nr_threads': 3}
        assert live(executable, 'host1', pids[1], threads[1]) == {'assign_thread': 0, 'nr_threads': 3}
        assert live(executable, 'host2', pids[2], threads[2]) == {'assign_thread': 1, 'nr_threads': 3}
        die(executable, 'host2', pids[2], threads[2])
        assert live(executable, 'host3', pids[3], threads[3]) == {'assign_thread': 1, 'nr_threads': 2}

    def test_heartbeat_3(self, executable_factory):
        """ HEARTBEAT (CORE): Single instance without thread. """

        pids = [self._pid() for _ in range(3)]
        executable = executable_factory()
        assert live(executable, 'host0', pids[0]) == {'assign_thread': 0, 'nr_threads': 1}
        assert live(executable, 'host1', pids[1]) == {'assign_thread': 1, 'nr_threads': 2}
        assert live(executable, 'host0', pids[0]) == {'assign_thread': 0, 'nr_threads': 2}

    def test_heartbeat_payload(self, thread_factory, executable_factory):
        """ HEARTBEAT (CORE): Test heartbeat with payload"""

        pids = [self._pid() for _ in range(6)]
        threads = [thread_factory() for _ in range(6)]
        executable = executable_factory()

        live(executable, 'host0', pids[0], threads[0], payload='payload1')
        live(executable, 'host0', pids[1], threads[1], payload='payload1')
        live(executable, 'host0', pids[2], threads[2], payload='payload1')
        live(executable, 'host1', pids[3], threads[3], payload='payload2')
        live(executable, 'host2', pids[4], threads[4], payload='payload3')
        live(executable, 'host3', pids[5], threads[5], payload='payload4')

        assert list_payload_counts(executable) == {'payload4': 1, 'payload2': 1, 'payload3': 1, 'payload1': 3}

        die(executable, 'host0', pids[0], threads[0])
        die(executable, 'host0', pids[1], threads[1])
        die(executable, 'host0', pids[2], threads[2])
        die(executable, 'host1', pids[3], threads[3])
        die(executable, 'host2', pids[4], threads[4])
        die(executable, 'host3', pids[5], threads[5])

        assert list_payload_counts('test5') == {}

    @pytest.mark.noparallel(reason='performs a heartbeat cardiac_arrest')
    @pytest.mark.dirty
    def test_old_heartbeat_cleanup(self, thread_factory, executable_factory):
        cardiac_arrest()
        pids = [self._pid() for _ in range(2)]
        thread = thread_factory()
        executable1 = executable_factory()
        executable2 = executable_factory()

        live(executable1, 'host0', pids[0], thread)
        live(executable2, 'host0', pids[1], thread)
        live(executable1, 'host1', pids[0], thread)
        live(executable2, 'host1', pids[1], thread)
        live(executable1, 'host2', pids[0], thread)
        live(executable2, 'host2', pids[1], thread)

        assert len(list_heartbeats()) == 6

        @transactional_session
        def __forge_updated_at(*, session=None):
            two_days_ago = datetime.utcnow() - timedelta(days=2)
            a_dozen_hours_ago = datetime.utcnow() - timedelta(hours=12)
            session.query(Heartbeats).filter_by(hostname='host1').update({'updated_at': two_days_ago})
            session.query(Heartbeats).filter_by(hostname='host2').update({'updated_at': a_dozen_hours_ago})

        __forge_updated_at()

        # Default expiration delay. Host1 health checks should get removed.
        sanity_check(executable=None, hostname=None)
        assert len(list_heartbeats()) == 4

        # Custom expiration delay. Host2 health checks should get removed too.
        sanity_check(executable2, 'host2', expiration_delay=timedelta(hours=5).total_seconds())
        assert len(list_heartbeats()) == 2
