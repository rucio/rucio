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

from typing import TYPE_CHECKING, Optional

from rucio.common import exception
from rucio.core import heartbeat
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from threading import Thread


def list_heartbeats(issuer: Optional[str] = None, vo: str = 'def') -> list["heartbeat.HeartbeatDict"]:
    """
    Return a list of tuples of all heartbeats.

    :param issuer: The issuer account.
    :param vo: the VO for the issuer.
    :returns: List of tuples [('Executable', 'Hostname', ...), ...]
    """

    kwargs = {'issuer': issuer}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_heartbeats', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot list heartbeats. %s' % (issuer, auth_result.message))
        return heartbeat.list_heartbeats(session=session)


def create_heartbeat(
    executable: str,
    hostname: str,
    pid: int,
    older_than: int,
    payload: Optional[str],
    thread: Optional["Thread"] = None,
    issuer: Optional[str] = None,
    vo: str = 'def',
) -> None:
    """
    Creates a heartbeat.
    :param issuer: The issuer account.
    :param vo: the VO for the issuer.
    :param executable: Executable name as a string, e.g., conveyor-submitter.
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param pid: UNIX Process ID as a number, e.g., 1234.
    :param thread: Python Thread Object.
    :param older_than: Ignore specified heartbeats older than specified nr of seconds.
    :param payload: Payload identifier which can be further used to identify the work a certain thread is executing.

    """
    kwargs = {'issuer': issuer}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='send_heartbeats', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot send heartbeats. %s' % (issuer, auth_result.message))
        heartbeat.live(executable=executable, hostname=hostname, pid=pid, thread=thread, older_than=older_than, payload=payload, session=session)
