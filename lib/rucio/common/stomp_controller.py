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

import json
import logging
import random
import socket
from typing import TYPE_CHECKING, Any, Optional

import stomp

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rucio.core.monitor import MetricManager


class StompController:
    """
    Common controller for managing Stomp connections to brokers.
    """

    def __init__(
        self,
        brokers: "Sequence[str]",
        port: int,
        use_ssl: bool = True,
        vhost: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ssl_key_file: Optional[str] = None,
        ssl_cert_file: Optional[str] = None,
        timeout: Optional[int] = None,
        reconnect_attempts: int = 999,
        logger: "Callable" = logging.log,
    ):
        self.logger = logger
        self.brokers = brokers
        self.port = port
        self.use_ssl = use_ssl
        self.vhost = vhost
        self.username = username
        self.password = password
        self.ssl_key_file = ssl_key_file
        self.ssl_cert_file = ssl_cert_file
        self.timeout = timeout
        self.reconnect_attempts = reconnect_attempts
        self.connections = []

    def resolve_brokers(self) -> list[str]:
        resolved = []
        for broker in self.brokers:
            try:
                addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
                resolved.extend(ai[4][0] for ai in addrinfos)
            except socket.gaierror as ex:
                self.logger(logging.ERROR, f"Cannot resolve domain name {broker} ({ex})")
        return resolved

    def setup_connections(self) -> None:
        resolved_brokers = self.resolve_brokers()
        self.logger(logging.INFO, f"Brokers resolved to {resolved_brokers}")
        for broker in resolved_brokers:
            con = stomp.Connection12(
                host_and_ports=[(broker, self.port)],
                vhost=self.vhost,
                keepalive=True,
                timeout=self.timeout,
                reconnect_attempts_max=self.reconnect_attempts,
            )
            if self.use_ssl and self.ssl_key_file and self.ssl_cert_file:
                con.set_ssl(key_file=self.ssl_key_file, cert_file=self.ssl_cert_file)
            self.connections.append(con)

    def connect_and_subscribe(
        self,
        destination: str,
        listener_name: str,
        listener: Any,
        subscription_id: str = "rucio-subscription",
        ack: str = "auto",
        metric: "MetricManager|None" = None,
        headers: Optional[dict] = None,
        logger: "Callable|None" = None
    ) -> None:
        if logger is None:
            logger = self.logger
        for conn in self.connections:
            if not conn.is_connected():
                host_port = conn.transport._Transport__host_and_ports[0]

                logger(logging.INFO, 'connecting to %s' % host_port[0])
                if metric is not None:
                    metric.counter('reconnect.{host}').labels(host=host_port[0]).inc()
                conn.set_listener(listener_name,
                                  listener(broker=host_port, conn=conn))
                if self.use_ssl:
                    conn.connect(wait=True)
                else:
                    conn.connect(self.username, self.password, wait=True)
                conn.subscribe(destination=destination, ack=ack, id=subscription_id, headers=headers or {})

    def connect_and_send(
        self,
        message: "dict[str, Any]",
        destination: str,
        listener_name: str,
        listener: Any,
        metric: "MetricManager|None" = None,
        logger: "Callable|None" = None
    ) -> None:
        if logger is None:
            logger = self.logger
        conn = random.sample(self.connections, 1)[0]
        if not conn.is_connected():
            host_port = conn.transport._Transport__host_and_ports[0][0]

            logger(logging.INFO, 'connecting to %s' % host_port[0])
            if metric is not None:
                metric.counter('reconnect.{host}').labels(host=host_port.split(".")[0]).inc()
            conn.set_listener(listener_name, listener(broker=conn.transport._Transport__host_and_ports[0], conn=conn))
            if self.use_ssl:
                conn.connect(wait=True)
            else:
                conn.connect(self.username, self.password, wait=True)

        conn.send(
            body=json.dumps(
                {
                    "event_type": str(message["event_type"]).lower(),
                    "payload": message["payload"],
                    "created_at": str(message["created_at"]),
                }
            ),
            destination=destination,
            headers={
                "persistent": "true",
                "event_type": str(message["event_type"]).lower(),
            },
        )

    def disconnect(self) -> None:
        for con in self.connections:
            try:
                con.disconnect()
            except Exception:
                pass
