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
from __future__ import annotations
import logging
import json
import random
import socket
from time import monotonic
from collections import namedtuple
from functools import partial
from typing import TYPE_CHECKING

from stomp import Connection12, ConnectionListener
from stomp.exception import ConnectFailedException, NotConnectedException

from rucio.core.monitor import MetricManager
from rucio.common.logging import formatted_logger
from rucio.common.config import (config_get, config_get_bool, config_get_int,
                                 config_get_float, config_get_list)

if TYPE_CHECKING:
    from collections.abc import Generator, Callable
    from stomp.connect import Frame


METRICS = MetricManager(module=__name__)


class Connection(Connection12):
    """
    Connection class.

    Wraps Stomp Connection but knows the brokers without accessing
    hidden variables from the Transport.
    """
    def __init__(self, host_and_ports: list[tuple[str, int]], **kwargs):
        """
        Initialise.

        Args:
            host_and_ports (list[tuple[str, int]]): brokers list

        Kwargs:
            Arguments to pass to the Constructor12 base class.
        """
        super().__init__(host_and_ports=host_and_ports, **kwargs)
        self._brokers = host_and_ports

    @property
    def brokers(self) -> list[tuple[str, int]]:
        """
        List brokers.

        Returns:
            list[tuple[str, int]]: All assigned brokers in (host, port) format.
        """
        return self._brokers


class ListenerBase(ConnectionListener):
    """Listener Base."""

    _logger = formatted_logger(logging.log, 'ListenerBase %s')

    def __init__(self,
                 conn: Connection,
                 logger: None | Callable = None,
                 **kwargs):
        """
        Initialise.

        Args:
            conn (Connection12): The connection object that is using this listener
            logger (logging.Logger): Logger to use. Defaults to logging.getLogger(__name__).getChild(__qualname__).

        Kwargs:
            Arguments to pass to the stomp.ConnectionListener base class.
        """
        super().__init__(**kwargs)
        self._conn = conn
        if logger is not None:
            self._logger = logger

    @METRICS.count_it
    def on_heartbeat_timeout(self):
        self._conn.disconnect()

    @METRICS.count_it
    def on_error(self, frame: Frame):
        """
        on_error
        """
        self._logger(logging.ERROR, 'Message receive error: [%s] %s', self._conn.brokers[0][0], frame.body)


StompConfig = namedtuple("StompConfig", ('brokers', 'use_ssl', 'port', 'vhost',
                                         'destination', 'key_file', 'cert_file',
                                         'username', 'password', 'nonssl_port',
                                         'reconnect_attempts_max', 'timeout', 'heartbeats'))


class StompConnectionManager:
    """Stomp Connection Manager."""

    _logger = formatted_logger(logging.log, 'StompConnectionManager %s')

    def __init__(self,
                 config_section: str,
                 logger: None | Callable = None):
        """
        Initialise.

        Args:
            config_section (str): The name of the config section for this manager to parse for configuration.
            logger (logging.Logger): logger to use. Defaults to logging.getLogger(__name__).getChild(__qualname__).
        """
        if logger is not None:
            self._logger = logger
        self._config = self._parse_config(config_section)
        self._listener_factory = None
        self._conns = []
        for broker in self._config.brokers:
            conn = Connection(host_and_ports=[broker],
                              vhost=self._config.vhost,
                              reconnect_attempts_max=self._config.reconnect_attempts_max,
                              timeout=self._config.timeout,
                              heartbeats=self._config.heartbeats)
            if self._config.use_ssl:
                conn.set_ssl(cert_file=self._config.cert_file, key_file=self._config.key_file)
            self._conns.append(conn)

    def set_listener_factory(self, name: str, listener_cls: type, **kwargs):
        """
        Setup listener factory

        This method will setup a factory to create a name and listener for the arguments to
        connection.set_listener based on pre-defined argument values.

        Args:
            name (str): Listener name
            listener_cls (ListenerBase): Listener class.
        """
        def create_listener(name, listener_factory, conn):
            return name, listener_factory(conn=conn)
        self._listener_factory = partial(create_listener,
                                         name=name,
                                         listener_factory=partial(listener_cls, logger=self._logger, **kwargs))

    def _parse_config(self, config_section: str) -> StompConfig:
        """
        Parse config section.

        Args:
            config_section (str): The name of the config section for this manager to parse for configuration.

        Raises:
            RuntimeError: If cannot parse config sections 'brokers' or 'use_ssl' or if misconfigured.

        Returns:
            StompConfig: Stomp manager configuration object.
        """
        try:
            brokers = config_get(config_section, 'brokers')
        except Exception as exc:
            self._logger(logging.ERROR, "Could not load brokers from configuration")
            raise RuntimeError('Could not load brokers from configuration') from exc

        try:
            use_ssl = config_get_bool(config_section, 'use_ssl')
        except Exception as exc:
            self._logger(logging.ERROR, "could not find use_ssl in configuration -- please update your rucio.cfg")
            raise RuntimeError('could not find use_ssl in configuration -- please update your rucio.cfg') from exc

        port = config_get_int(config_section, 'port')
        vhost = config_get(config_section, 'broker_virtual_host', raise_exception=False)
        destination = config_get(config_section, "destination")
        key_file = config_get(config_section, 'ssl_key_file', default=None, raise_exception=False)
        cert_file = config_get(config_section, 'ssl_cert_file', default=None, raise_exception=False)
        username = config_get(config_section, 'username', default=None, raise_exception=False)
        password = config_get(config_section, 'password', default=None, raise_exception=False)
        nonssl_port = config_get_int(config_section, 'nonssl_port', default=0, raise_exception=False)
        timeout = config_get_float(config_section, 'timeout', default=None, raise_exception=False)
        heartbeats = config_get_list(config_section, 'heartbeats', default=[0., 0.], raise_exception=False)
        reconnect_attempts = config_get_int(config_section, 'reconnect_attempts', default=100)
        if use_ssl and (key_file is None or cert_file is None):
            self._logger(logging.ERROR, "If use_ssl is True in config you must provide both 'ssl_cert_file' "
                                        "and 'ssl_key_file'")
            raise RuntimeError("If use_ssl is True in config you must provide both 'ssl_cert_file' and 'ssl_key_file'")
        if not use_ssl and (username is None or password is None or nonssl_port == 0):
            self._logger(logging.ERROR, "If use_ssl is False in config you must provide "
                                        "'username', 'password' and 'nonssl_port'")
            raise RuntimeError("If use_ssl is False in config you must provide "
                               "'username', 'password' and 'nonssl_port'")
        return StompConfig(brokers=self._resolve_host_and_port(brokers, port if use_ssl else nonssl_port),
                           use_ssl=use_ssl,
                           port=port, vhost=vhost,
                           destination=destination, key_file=key_file, cert_file=cert_file,
                           username=username, password=password, nonssl_port=nonssl_port,
                           reconnect_attempts_max=reconnect_attempts, timeout=timeout, heartbeats=heartbeats)

    def _resolve_host_and_port(self, fqdns: str | list[str], port: int) -> list[tuple[str, int]]:
        """
        Resolve host and port.

        Args:
            fqdns (str | list[str]): fully qualified domain name(s)
            port (int): port

        Returns:
            list[tuple[str, int]]: list of (host, port) tuples.
        """
        if isinstance(fqdns, str):
            fqdns = fqdns.split(',')

        hosts_and_ports = []
        for fqdn in fqdns:
            try:
                addrinfos = socket.getaddrinfo(fqdn.strip(), port, socket.AF_INET, 0, socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                self._logger(logging.ERROR, "[broker] Cannot resolve domain name %s (%s)", fqdn.strip(), str(exc))
                continue

            hosts_and_ports.extend(addrinfo[4] for addrinfo in addrinfos)
        if not hosts_and_ports:
            self._logger(logging.WARNING, "[broker] No resolved brokers")
        return hosts_and_ports

    def _is_stalled(self, conn: Connection) -> bool:
        """
        Determine if a connection is stalled.

        Args:
            conn (Connection): The Connection object

        Returns:
            bool: Whether the connection has stalled.
        """
        received_heartbeat = getattr(conn, 'received_heartbeat', None)
        if received_heartbeat is None or not any(self._config.heartbeats):
            return False

        heartbeat_period_seconds = max(0, self._config.heartbeats[0], self._config.heartbeats[1]) / 1000
        if heartbeat_period_seconds == 0.:
            return False

        now = monotonic()
        if received_heartbeat + 10 * heartbeat_period_seconds >= now:
            return False

        return True

    def connect(self) -> Generator[Connection, None, None]:
        """
        Connect.

        Yields:
            Generator[Connection, None, None]: Each connection object after ensuring it's connected.
        """
        config = self._config
        params = {'wait': True}
        if config.use_ssl:
            params.update(username=config.username, password=config.password)

        for conn in self._conns:
            if self._is_stalled(conn):
                try:
                    conn.disconnect()
                except Exception:
                    self._logger(logging.ERROR, "[broker] Stalled connection could not be disconnected")
            if not conn.is_connected():
                self._logger(logging.INFO, 'connecting to %s:%s', *conn.brokers[0])
                # self._logger.info('connecting to %s', conn.transport._Transport__host_and_ports[0][0])
                # if self._metrics is not None:
                #     self._metrics.counter('reconnect.{host}').labels(host=conn.transport._Transport__host_and_ports[0][0].split('.')[0]).inc()
                METRICS.counter('reconnect.{host}').labels(host=conn.brokers[0][0]).inc()
                # METRICS.counter('reconnect.{host}').labels(host=conn.transport._Transport__host_and_ports[0][0].split('.')[0]).inc()
                if self._listener_factory is not None:
                    a, b = self._listener_factory(conn=conn)
                    conn.set_listener(a, b)

                try:
                    conn.connect(**params)
                except ConnectFailedException as error:
                    self._logger(logging.WARNING, "[broker] Could not deliver message due to "
                                                  "ConnectFailedException: %s", str(error))
                    continue
                except Exception as error:
                    self._logger(logging.ERROR, "[broker] Could not connect: %s", str(error))
                    self._logger(logging.ERROR, "CHECK: %s", getattr(b, "heartbeats", None))
                    self._logger(logging.ERROR, "CHECK: %s", getattr(self, "heartbeats", None))
                    logging.exception("[broker] Could not connect: %s", str(error))
                    continue
            try:
                yield conn
            except Exception:
                self._logger(logging.ERROR, "[broker] Error in yielded code, skipping to next connection.")

    def deliver_messages(self, messages: dict) -> list[int]:
        """
        Deliver messages.

        Args:
            messages (dict): Messages to deliver.

        Returns:
            list[int]: delivered message ids, ready for deletion.
        """
        config = self._config
        conn = random.sample(list(self.connect()), 1)[0]
        to_delete = []
        for message in messages:
            try:
                body = json.dumps({"event_type": str(message["event_type"]).lower(),
                                   "payload": message["payload"],
                                   "created_at": str(message["created_at"])})
            except ValueError:
                self._logger(logging.ERROR, "[broker] Cannot serialize payload to JSON: %s", str(message["payload"]))
                to_delete.append(message["id"])
                continue

            try:
                conn.send(
                    body=body,
                    destination=config.destination,
                    headers={"persistent": "true",
                             "event_type": str(message["event_type"]).lower()}
                )
                to_delete.append(message["id"])
            except NotConnectedException as error:
                self._logger(logging.WARNING, "[broker] Could not deliver message due to NotConnectedException: %s",
                             str(error))
                continue
            except Exception as error:
                self._logger(logging.ERROR, "[broker] Could not deliver message: %s", str(error))
                continue

            msg_event_type = str(message["event_type"]).lower()
            msg_payload = message.get("payload", {})
            if msg_event_type.startswith("transfer") or msg_event_type.startswith("stagein"):
                self._logger(logging.DEBUG,
                             "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, "
                             "transfer-id: %s, created_at: %s",
                             msg_event_type,
                             msg_payload.get("scope", None),
                             msg_payload.get("name", None),
                             msg_payload.get("dst-rse", None),
                             msg_payload.get("request-id", None),
                             msg_payload.get("transfer-id", None),
                             str(message["created_at"]))

            elif msg_event_type.startswith("dataset"):
                self._logger(logging.DEBUG,
                             "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)",
                             msg_event_type,
                             msg_payload.get("scope", None),
                             msg_payload.get("name", None),
                             msg_payload.get("rse", None),
                             msg_payload.get("rule_id", None),
                             str(message["created_at"]))

            elif msg_event_type.startswith("deletion"):
                if "url" not in msg_payload:
                    msg_payload["url"] = "unknown"
                self._logger(logging.DEBUG,
                             "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)",
                             msg_event_type,
                             msg_payload.get("scope", None),
                             msg_payload.get("name", None),
                             msg_payload.get("rse", None),
                             msg_payload.get("url", None),
                             str(message["created_at"]))
            else:
                self._logger(logging.DEBUG, "[broker] Other message: %s", message)

        return to_delete

    def subscribe(self, id_: str, ack: str, destination: None | str = None, **kwargs):
        """
        Subscribe

        Args:
            id_ (str): The identifier to uniquely identify the subscription
            ack (str): Either auto, client or client-individual
            destination (None | str, optional): The topic or queue to subscribe to. If None then
                                                destination is taken from the rucio config Defaults to None.

        Kwargs:
            Arguments to pass to the Construction objects subscribe method.
        """
        if destination is None:
            destination = self._config.destination
        for conn in self.connect():
            conn.subscribe(destination=destination,
                           id=id_, ack=ack, **kwargs)

    def disconnect(self):
        """Disconnect."""
        for conn in self._conns:
            try:
                conn.disconnect()
            except Exception:
                self._logger(logging.ERROR, "[broker] Could not disconnect")
