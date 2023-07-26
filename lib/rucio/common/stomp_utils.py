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

"""
Common utility functions for stomp connections
"""

import logging
import socket
from time import monotonic
from typing import TYPE_CHECKING

from stomp import Connection

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from typing import Any

    LoggerFunction = Callable[..., Any]


def resolve_ips(fqdns: "Sequence[str]", logger: "LoggerFunction" = logging.log):
    logger(logging.DEBUG, 'resolving dns aliases: %s' % fqdns)
    resolved = []
    for fqdn in fqdns:
        addrinfos = socket.getaddrinfo(fqdn, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        resolved.extend(ai[4][0] for ai in addrinfos)
    logger(logging.DEBUG, 'dns aliases resolved to %s', resolved)
    return resolved


class StompConnectionManager:

    def __init__(self):
        self._brokers = None
        self._port = None
        self._use_ssl = None
        self._vhost = None
        self._reconnect_attempts = None
        self._ssl_key_file = None
        self._timeout = None
        self._heartbeats = None

        self._connections = {}

    def is_stalled(self, connection: Connection, *, logger: "LoggerFunction" = logging.log):
        if not connection.is_connected():
            return True

        if self._heartbeats and getattr(connection, 'received_heartbeat') and connection.received_heartbeat:
            heartbeat_period_seconds = max(0, self._heartbeats[0], self._heartbeats[1]) / 1000

            if not heartbeat_period_seconds:
                return False

            now = monotonic()
            if connection.received_heartbeat + 10 * heartbeat_period_seconds < now:
                logger(logging.WARNING, "Stomp connection missed heartbeats for a long time")
                return True

        return False

    def disconnect(self):
        for conn in self._connections.values():
            if not conn.is_connected():
                conn.disconnect()

    def re_configure(
            self,
            brokers: "Sequence[str]",
            port: int,
            use_ssl: bool,
            vhost,
            reconnect_attempts: int,
            ssl_key_file,
            ssl_cert_file,
            timeout,
            heartbeats=(0, 1000),
            *,
            logger: "LoggerFunction" = logging.log
    ) -> tuple[list, list]:

        configuration_changed = any([
            self._brokers != brokers,
            self._port != port,
            self._use_ssl != use_ssl,
            self._vhost != vhost,
            self._reconnect_attempts != reconnect_attempts,
            self._ssl_key_file != ssl_key_file,
            self._timeout != timeout,
            self._heartbeats != heartbeats,
        ])
        if configuration_changed:
            self._brokers = brokers
            self._port = port
            self._use_ssl = use_ssl
            self._vhost = vhost
            self._reconnect_attempts = reconnect_attempts
            self._ssl_key_file = ssl_key_file
            self._timeout = timeout
            self._heartbeats = heartbeats

        current_remotes = set(self._connections)
        desired_remotes = set((ip, port) for ip in resolve_ips(brokers, logger=logger))

        if configuration_changed:
            # Re-create all connections
            to_delete = current_remotes
            to_create = desired_remotes
        else:
            to_delete = current_remotes.difference(desired_remotes)
            to_create = desired_remotes.difference(current_remotes)

            for remote in current_remotes.intersection(desired_remotes):
                conn = self._connections[remote]

                if self.is_stalled(conn, logger=logger):
                    # Re-create stalled connections
                    to_delete.add(remote)
                    to_create.add(remote)

        deleted_conns = []
        for remote in to_delete:
            conn = self._connections.pop(remote)
            if conn.is_connected():
                conn.disconnect()
            deleted_conns.append(to_delete)

        created_conns = []
        for remote in to_create:
            conn = Connection(
                host_and_ports=[remote],
                vhost=vhost,
                timeout=timeout,
                heartbeats=heartbeats,
                reconnect_attempts_max=reconnect_attempts
            )
            if use_ssl:
                conn.set_ssl(key_file=ssl_key_file, cert_file=ssl_cert_file)
            self._connections[remote] = conn
            created_conns.append(conn)

        if not to_delete and not to_create:
            logger(logging.INFO, "Stomp connections didn't change")
        else:
            logger(logging.INFO, f"Stomp connections refreshed. Deleted: {list(to_delete)}. Added: {list(to_create)}")

        return created_conns, deleted_conns
