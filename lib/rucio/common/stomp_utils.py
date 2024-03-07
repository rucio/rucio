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
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.core.monitor import MetricManager

if TYPE_CHECKING:
    from collections.abc import Generator


METRICS = MetricManager(module=__name__)


class Connection(Connection12):

    def __init__(self, host_and_ports, **kwargs):
        super().__init__(host_and_ports=host_and_ports, **kwargs)
        self._brokers = host_and_ports

    @property
    def brokers(self):
        return self._brokers


class ListenerBase(ConnectionListener):
    """Listener Base."""

    _logger = logging.getLogger(__name__).getChild(__qualname__)

    def __init__(self,
                 conn: Connection,
                 logger: None | logging.Logger = None):
        """
        Initialise.

        Args:
            conn (Connection12): _description_
            logger (logging.Logger): _description_. Defaults to logging.getLogger(__name__).getChild(__qualname__).
        """
        self._conn = conn
        if logger is not None:
            self._logger = logger

    @property
    def broker(self) -> str:
        """
        broker.

        Returns:
            str: _description_
        """
        return self._conn.brokers[0]

    @METRICS.count_it
    def on_heartbeat_timeout(self):
        self._conn.disconnect()

    @METRICS.count_it
    def on_error(self, frame):
        """
        on_error
        """
        self._logger.error('Message receive error: [%s] %s', self.broker, frame.body)


StompConfig = namedtuple("StompConfig", ('brokers', 'use_ssl', 'port', 'vhost',
                                         'destination', 'key_file', 'cert_file',
                                         'username', 'password', 'nonssl_port',
                                         'reconnect_attempts_max'))
# TODO: timeout and heartbeat, see stomp_utils


class StompConnectionManager:
    """Stomp Connection Manager."""

    _logger = logging.getLogger(__name__).getChild(__qualname__)

    def __init__(self,
                 config_section: str,
                 # metrics: None | MetricManager = None,
                 logger: None | logging.Logger = None):
        """
        Initialise.

        Args:
            config_section (str): _description_
            metrics (None | MetricManager): _description_. Defaults to None.
            logger (logging.Logger): _description_. Defaults to logging.getLogger(__name__).getChild(__qualname__).
        """
        if logger is not None:
            self._logger = logger
        self._config = self._parse_config(config_section)
        self._listener_factory = None
        # self._metrics = metrics
        self._conns = []
        for broker in self._config.brokers:
            conn = Connection(host_and_ports=[broker],
                              vhost=self._config.vhost,
                              reconnect_attempts_max=self._config.reconnect_attempts_max)
            if self._config.use_ssl:
                conn.set_ssl(cert_file=self._config.cert_file, key_file=self._config.key_file)
            # conn.set_listener('', listener)
            self._conns.append(conn)

    def set_listener_factory(self, name: str, listener_cls: ListenerBase, **kwargs):
        """
        Set listener factory

        Args:
            name (str): _description_
            listener_cls (ListenerBase): _description_
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
            config_section (str): _description_

        Raises:
            RuntimeError: _description_
            RuntimeError: _description_
            RuntimeError: _description_
            RuntimeError: _description_

        Returns:
            StompConfig: _description_
        """
        try:
            brokers = config_get(config_section, 'brokers')
        except Exception as exc:
            raise RuntimeError('Could not load brokers from configuration') from exc

        try:
            use_ssl = config_get_bool(config_section, 'use_ssl')
        except Exception as exc:
            raise RuntimeError('could not find use_ssl in configuration -- please update your rucio.cfg') from exc

        port = config_get_int(config_section, 'port')
        vhost = config_get(config_section, 'broker_virtual_host', raise_exception=False)
        destination = config_get(config_section, "destination")
        key_file = config_get(config_section, 'ssl_key_file', default=None, raise_exception=False)
        cert_file = config_get(config_section, 'ssl_cert_file', default=None, raise_exception=False)
        username = config_get(config_section, 'username', default=None, raise_exception=False)
        password = config_get(config_section, 'password', default=None, raise_exception=False)
        nonssl_port = config_get_int(config_section, 'nonssl_port', default=0, raise_exception=False)
        reconnect_attempts = config_get_int(config_section, 'reconnect_attempts', default=100)
        if use_ssl and (key_file is None or cert_file is None):
            raise RuntimeError("If use_ssl is True in config you must provide both 'ssl_cert_file' and 'ssl_key_file'")
        if not use_ssl and (username is None or password is None or nonssl_port == 0):
            raise RuntimeError("If use_ssl is False in config you must provide 'username' and 'password' and 'nonssl_port'")
        return StompConfig(brokers=self._resolve_host_and_port(brokers, port if use_ssl else nonssl_port), use_ssl=use_ssl,
                           port=port, vhost=vhost,
                           destination=destination, key_file=key_file, cert_file=cert_file,
                           username=username, password=password, nonssl_port=nonssl_port,
                           reconnect_attempts_max=reconnect_attempts)

    def _resolve_host_and_port(self, fqdns: str | list[str], port: int) -> list[tuple[str, int]]:
        """
        Resolve host and port.

        Args:
            fqdns (str | list[str]): _description_
            port (int): _description_

        Returns:
            list[tuple[str, int]]: _description_
        """
        if isinstance(fqdns, str):
            fqdns = fqdns.split(',')

        hosts_and_ports = []
        for fqdn in fqdns:
            try:
                addrinfos = socket.getaddrinfo(fqdn.strip(), port, socket.AF_INET, 0, socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                logging.log(logging.ERROR, "[broker] Cannot resolve domain name %s (%s)", fqdn, str(exc))
                continue

            hosts_and_ports.extend(addrinfo[4] for addrinfo in addrinfos)
        if not hosts_and_ports:
            logging.log(logging.WARNING, "[broker] No resolved brokers")
        return hosts_and_ports

    def _is_stalled(self, conn: Connection) -> bool:
        received_heartbeat = getattr(conn, 'received_heartbeat', None)
        if None in (self._heartbeats, received_heartbeat):
            return False

        heartbeat_period_seconds = max(0, self._heartbeats[0], self._heartbeats[1]) / 1000
        if heartbeat_period_seconds == 0.:
            return False

        now = monotonic()
        if received_heartbeat + 10 * heartbeat_period_seconds >= now:
            return False

        return True

        # if self._heartbeats and received_heartbeat is not None:
        #     heartbeat_period_seconds = max(0, self._heartbeats[0], self._heartbeats[1]) / 1000
        #     if heartbeat_period_seconds:
        #         now = monotonic()
        #         if received_heartbeat + 10 * heartbeat_period_seconds < now:
        #             self._logger.warning("Stomp connection missed heartbeats for a long time")
        #             return True

        # return False

    def connect(self) -> Generator[Connection12, None, None]:
        """
        Connect.

        Yields:
            Generator[Connection12, None, None]: _description_
        """
        config = self._config
        params = {'wait': True}
        if config.use_ssl:
            params.update(username=config.username, password=config.password)

        for conn in self._conns:
            if not conn.is_connected():
                self._logger.info('connecting to %s:%s', *conn.brokers[0])
                # self._logger.info('connecting to %s', conn.transport._Transport__host_and_ports[0][0])
                # if self._metrics is not None:
                #     self._metrics.counter('reconnect.{host}').labels(host=conn.transport._Transport__host_and_ports[0][0].split('.')[0]).inc()
                METRICS.counter('reconnect.{host}').labels(host=conn.brokers[0][0]).inc()
                # METRICS.counter('reconnect.{host}').labels(host=conn.transport._Transport__host_and_ports[0][0].split('.')[0]).inc()
                if self._listener_factory is not None:
                    conn.set_listener(*self._listener_factory(conn=conn))

                try:
                    conn.connect(**params)
                except ConnectFailedException as error:
                    self._logger.warning("[broker] Could not deliver message due to ConnectFailedException: %s",
                                         str(error))
                    continue
                except Exception as error:
                    self._logger.error("[broker] Could not connect: %s", str(error))
                    continue
            try:
                yield conn
            except Exception:
                self._logger.error("[broker] Error in yielded code, skipping to next connection.")

    def deliver_messages(self, messages) -> list[int]:
        """
        Deliver messages.

        Args:
            messages (_type_): _description_

        Returns:
            list[int]: delivered message ids, ready for deletion.
        """
        config = self._config
        conn = random.sample(list(self.connect()), 1)[0]
        to_delete = []
        for message in messages:
            try:
                body = json.dumps({
                            "event_type": str(message["event_type"]).lower(),
                            "payload": message["payload"],
                            "created_at": str(message["created_at"])
                        })
            except ValueError:
                self._logger.error("[broker] Cannot serialize payload to JSON: %s", str(message["payload"]))
                to_delete.append(message["id"])
                continue

            try:
                conn.send(
                    body=body,
                    destination=config.destination,
                    headers={
                        "persistent": "true",
                        "event_type": str(message["event_type"]).lower()
                    }
                )
                to_delete.append(message["id"])
            except NotConnectedException as error:
                self._logger.warning("[broker] Could not deliver message due to NotConnectedException: %s", str(error))
                continue
            except Exception as error:
                self._logger.error("[broker] Could not deliver message: %s", str(error))
                continue

            msg_event_type = str(message["event_type"]).lower()
            msg_payload = message.get("payload", {})
            if msg_event_type.startswith("transfer") or msg_event_type.startswith("stagein"):
                self._logger.debug(
                    "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, transfer-id: %s, created_at: %s",
                    msg_event_type,
                    msg_payload.get("scope", None),
                    msg_payload.get("name", None),
                    msg_payload.get("dst-rse", None),
                    msg_payload.get("request-id", None),
                    msg_payload.get("transfer-id", None),
                    str(message["created_at"]),
                )

            elif msg_event_type.startswith("dataset"):
                self._logger.debug(
                    "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)",
                    msg_event_type,
                    msg_payload.get("scope", None),
                    msg_payload.get("name", None),
                    msg_payload.get("rse", None),
                    msg_payload.get("rule_id", None),
                    str(message["created_at"]),
                )

            elif msg_event_type.startswith("deletion"):
                if "url" not in msg_payload:
                    msg_payload["url"] = "unknown"
                self._logger.debug(
                    "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)",
                    msg_event_type,
                    msg_payload.get("scope", None),
                    msg_payload.get("name", None),
                    msg_payload.get("rse", None),
                    msg_payload.get("url", None),
                    str(message["created_at"]),
                )
            else:
                self._logger.debug("[broker] Other message: %s", message)

        # delete_messages(messages=to_delete)
        return to_delete

    def subscribe(self, id_: str, ack: str, destination: None | str = None, **kwargs):
        """
        Subscribe

        Args:
            id_ (str): _description_
            ack (str): _description_
            destination (None | str, optional): _description_. Defaults to None.
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
                self._logger.exception("[broker] Could not disconnect")
