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

import socket

from stomp import Connection

import logging


def get_stomp_brokers(brokers, port, use_ssl, vhost, reconnect_attempts, ssl_key_file, ssl_cert_file, timeout,
                      logger=logging.log):
    logger(logging.DEBUG, 'resolving broker dns alias: %s' % brokers)

    brokers_resolved = []
    for broker in brokers:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logger(logging.DEBUG, 'broker resolved to %s', brokers_resolved)
    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            conns.append(Connection(host_and_ports=[(broker, port)],
                                    use_ssl=False,
                                    vhost=vhost,
                                    timeout=timeout,
                                    heartbeats=(0, 1000),
                                    reconnect_attempts_max=reconnect_attempts))
        else:
            conns.append(Connection(host_and_ports=[(broker, port)],
                                    use_ssl=True,
                                    ssl_key_file=ssl_key_file,
                                    ssl_cert_file=ssl_cert_file,
                                    vhost=vhost,
                                    timeout=timeout,
                                    heartbeats=(0, 1000),
                                    reconnect_attempts_max=reconnect_attempts))
    return conns
