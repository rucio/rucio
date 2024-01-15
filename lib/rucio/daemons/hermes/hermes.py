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
   Hermes is a daemon that get the messages and sends them to external services (influxDB, ES, ActiveMQ).
"""

import calendar
import datetime
import functools
import json
import logging
import random
import re
import smtplib
import socket
import sys
import threading
import time
from configparser import NoOptionError, NoSectionError
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

import requests
import stomp

import rucio.db.sqla.util
from rucio.common.config import (
    config_get,
    config_get_bool,
    config_get_int,
    config_get_list,
)
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging
from rucio.core.message import delete_messages, retrieve_messages
from rucio.core.monitor import MetricManager
from rucio.daemons.common import run_daemon
from requests.auth import HTTPBasicAuth

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType
    from typing import Optional

    from rucio.daemons.common import HeartbeatHandler

logging.getLogger("requests").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()
DAEMON_NAME = "hermes"

RECONNECT_COUNTER = METRICS.counter(
    name="reconnect.{host}",
    documentation="Counts Hermes reconnects to different ActiveMQ brokers",
    labelnames=("host",),
)


def default(datetype):
    if isinstance(datetype, (datetime.date, datetime.datetime)):
        return datetype.isoformat()


class HermesListener(stomp.ConnectionListener):
    """
    Hermes Listener
    """

    def __init__(self, broker):
        """
        __init__
        """
        self.__broker = broker

    def on_error(self, frame):
        """
        Error handler
        """
        logging.error("[broker] [%s]: %s", self.__broker, frame.body)


def setup_activemq(logger: "Callable"):
    """
    Deliver messages to ActiveMQ

    :param logger:             The logger object.
    """

    logger(logging.INFO, "[broker] Resolving brokers")

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [
            broker.strip()
            for broker in config_get("messaging-hermes", "brokers").split(",")
        ]
    except:
        raise Exception("Could not load brokers from configuration")

    logger(logging.INFO, "[broker] Resolving broker dns alias: %s", brokers_alias)
    brokers_resolved = []
    for broker in brokers_alias:
        try:
            addrinfos = socket.getaddrinfo(
                broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP
            )
            brokers_resolved.extend(ai[4][0] for ai in addrinfos)
        except socket.gaierror as ex:
            logger(
                logging.ERROR,
                "[broker] Cannot resolve domain name %s (%s)",
                broker,
                str(ex),
            )

    logger(logging.DEBUG, "[broker] Brokers resolved to %s", brokers_resolved)

    if not brokers_resolved:
        logger(logging.FATAL, "[broker] No brokers resolved.")
        return None, None, None, None, None

    broker_timeout = 3
    if not broker_timeout:  # Allow zero in config
        broker_timeout = None

    logger(logging.INFO, "[broker] Checking authentication method")
    use_ssl = True
    try:
        use_ssl = config_get_bool("messaging-hermes", "use_ssl")
    except:
        logger(
            logging.INFO,
            "[broker] Could not find use_ssl in configuration -- please update your rucio.cfg",
        )

    port = config_get_int("messaging-hermes", "port")
    vhost = config_get("messaging-hermes", "broker_virtual_host", raise_exception=False)
    if not use_ssl:
        username = config_get("messaging-hermes", "username")
        password = config_get("messaging-hermes", "password")
        port = config_get_int("messaging-hermes", "nonssl_port")

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            logger(
                logging.INFO,
                "[broker] setting up username/password authentication: %s",
                broker,
            )
        else:
            logger(
                logging.INFO,
                "[broker] setting up ssl cert/key authentication: %s",
                broker,
            )

        con = stomp.Connection12(
            host_and_ports=[(broker, port)],
            vhost=vhost,
            keepalive=True,
            timeout=broker_timeout,
        )
        if use_ssl:
            con.set_ssl(
                key_file=config_get("messaging-hermes", "ssl_key_file"),
                cert_file=config_get("messaging-hermes", "ssl_cert_file"),
            )

        con.set_listener(
            "rucio-hermes", HermesListener(con.transport._Transport__host_and_ports[0])
        )

        conns.append(con)
    destination = config_get("messaging-hermes", "destination")
    return conns, destination, username, password, use_ssl


def deliver_to_activemq(
    messages, conns, destination, username, password, use_ssl, logger
):
    """
    Deliver messages to ActiveMQ

    :param messages:           The list of messages.
    :param conns:              A list of connections.
    :param destination:        The destination topic or queue.
    :param username:           The username if no SSL connection.
    :param password:           The username if no SSL connection.
    :param use_ssl:            Boolean to choose if SSL connection is used.
    :param logger:             The logger object.

    :returns:                  List of message_id to delete
    """
    to_delete = []
    for message in messages:
        try:
            conn = random.sample(conns, 1)[0]
            if not conn.is_connected():
                host_and_ports = conn.transport._Transport__host_and_ports[0][0]
                RECONNECT_COUNTER.labels(host=host_and_ports.split(".")[0]).inc()
                if not use_ssl:
                    logger(
                        logging.INFO,
                        "[broker] - connecting with USERPASS to %s",
                        host_and_ports,
                    )
                    conn.connect(username, password, wait=True)
                else:
                    logger(
                        logging.INFO,
                        "[broker] - connecting with SSL to %s",
                        host_and_ports,
                    )
                    conn.connect(wait=True)

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

            to_delete.append(message["id"])
        except ValueError:
            logger(
                logging.ERROR,
                "[broker] Cannot serialize payload to JSON: %s",
                str(message["payload"]),
            )
            to_delete.append(message["id"])
            continue
        except stomp.exception.NotConnectedException as error:
            logger(
                logging.WARNING,
                "[broker] Could not deliver message due to NotConnectedException: %s",
                str(error),
            )
            continue
        except stomp.exception.ConnectFailedException as error:
            logger(
                logging.WARNING,
                "[broker] Could not deliver message due to ConnectFailedException: %s",
                str(error),
            )
            continue
        except Exception as error:
            logger(logging.ERROR, "[broker] Could not deliver message: %s", str(error))
            continue

        if str(message["event_type"]).lower().startswith("transfer") or str(
            message["event_type"]
        ).lower().startswith("stagein"):
            logger(
                logging.DEBUG,
                "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, request-id: %s, transfer-id: %s, created_at: %s",
                str(message["event_type"]).lower(),
                message["payload"].get("scope", None),
                message["payload"].get("name", None),
                message["payload"].get("dst-rse", None),
                message["payload"].get("request-id", None),
                message["payload"].get("transfer-id", None),
                str(message["created_at"]),
            )

        elif str(message["event_type"]).lower().startswith("dataset"):
            logger(
                logging.DEBUG,
                "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, rule-id: %s, created_at: %s)",
                str(message["event_type"]).lower(),
                message["payload"].get("scope", None),
                message["payload"].get("name", None),
                message["payload"].get("rse", None),
                message["payload"].get("rule_id", None),
                str(message["created_at"]),
            )

        elif str(message["event_type"]).lower().startswith("deletion"):
            if "url" not in message["payload"]:
                message["payload"]["url"] = "unknown"
            logger(
                logging.DEBUG,
                "[broker] - event_type: %s, scope: %s, name: %s, rse: %s, url: %s, created_at: %s)",
                str(message["event_type"]).lower(),
                message["payload"].get("scope", None),
                message["payload"].get("name", None),
                message["payload"].get("rse", None),
                message["payload"].get("url", None),
                str(message["created_at"]),
            )
        else:
            logger(logging.DEBUG, "[broker] Other message: %s", message)
    return to_delete


def deliver_emails(messages: list[dict], logger: "Callable") -> list:
    """
    Sends emails

    :param messages:           The list of messages.
    :param logger:             The logger object.

    :returns:                  List of message_id to delete
    """

    email_from = config_get("messaging-hermes", "email_from")
    send_email = config_get_bool(
        "messaging-hermes", "send_email", raise_exception=False, default=True
    )
    to_delete = []
    for message in messages:
        if message['event_type'] == 'email':
            msg = MIMEText(message['payload']['body'])
            msg['From'] = email_from
            msg['To'] = ', '.join(message['payload']['to'])
            msg['Subject'] = message['payload']['subject']

            try:
                if send_email:
                    smtp = smtplib.SMTP()
                    smtp.connect()
                    smtp.sendmail(
                        msg["From"], message["payload"]["to"], msg.as_string()
                    )
                    smtp.quit()
                to_delete.append(message["id"])
            except Exception as error:
                logger(logging.ERROR, "Cannot send email : %s", str(error))
        else:
            to_delete.append(message["id"])
            continue
    return to_delete


def submit_to_elastic(messages: list[dict], endpoint: str, logger: "Callable") -> int:
    """
    Aggregate a list of message to ElasticSearch

    :param messages:           The list of messages.
    :param endpoint:           The ES endpoint were to send the messages.
    :param logger:             The logger object.

    :returns:                  HTTP status code. 200 and 204 OK. Rest is failure.
    """
    text = ""
    elastic_username = config_get("hermes", "elastic_username",
                                  raise_exception=False, default=None)
    elastic_password = config_get("hermes", "elastic_password",
                                  raise_exception=False, default=None)
    auth = None
    if elastic_username and elastic_password:
        auth = HTTPBasicAuth(elastic_username, elastic_password)

    for message in messages:
        text += '{ "index":{ } }\n%s\n' % json.dumps(message, default=default)
    res = requests.post(
        endpoint, data=text, headers={"Content-Type": "application/json"}, auth=auth
    )
    return res.status_code


def aggregate_to_influx(
    messages: list[dict], bin_size: int, endpoint: str, logger: "Callable"
) -> int:
    """
    Aggregate a list of message using a certain bin_size
    and submit them to a InfluxDB endpoint

    :param messages:           The list of messages.
    :param bin_size:           The size of the bins for the aggreagation (e.g. 10m, 1h, etc.).
    :param endpoint:           The InfluxDB endpoint were to send the messages.
    :param logger:             The logger object.

    :returns:                  HTTP status code. 200 and 204 OK. Rest is failure.
    """
    bins = {}
    dtime = datetime.datetime.now()
    microsecond = dtime.microsecond

    for message in messages:
        event_type = message["event_type"]
        payload = message["payload"]
        if event_type in ["transfer-failed", "transfer-done"]:
            if not payload["transferred_at"]:
                logger(
                    logging.WARNING,
                    "No transferred_at for message. Reason : %s",
                    payload["reason"],
                )
                continue
            transferred_at = time.strptime(
                payload["transferred_at"], "%Y-%m-%d %H:%M:%S"
            )
            if bin_size == "1m":
                transferred_at = int(calendar.timegm(transferred_at)) * 1000000000
                transferred_at += microsecond
            if transferred_at not in bins:
                bins[transferred_at] = {}
            src_rse, dest_rse, activity = (
                payload["src-rse"],
                payload["dst-rse"],
                payload["activity"],
            )
            activity = re.sub(" ", r"\ ", activity)
            key = "transfer,activity=%s,src_rse=%s,dst_rse=%s" % (
                activity,
                src_rse,
                dest_rse,
            )
            if key not in bins[transferred_at]:
                bins[transferred_at][key] = [0, 0, 0, 0]
            if event_type == "transfer-done":
                bins[transferred_at][key][0] += 1
                bins[transferred_at][key][1] += payload["bytes"]
            if event_type == "transfer-failed":
                bins[transferred_at][key][2] += 1
                bins[transferred_at][key][3] += payload["bytes"]
        elif event_type in ["deletion-failed", "deletion-done"]:
            created_at = message["created_at"]
            if bin_size == "1m":
                created_at = created_at.replace(
                    second=0, microsecond=0, tzinfo=datetime.timezone.utc
                ).timestamp()
            created_at = int(created_at) * 1000000000
            created_at += microsecond
            if created_at not in bins:
                bins[created_at] = {}
            rse = payload["rse"]
            key = "deletion,rse=%s" % (rse)
            if key not in bins[created_at]:
                bins[created_at][key] = [0, 0, 0, 0]
            if event_type == "deletion-done":
                bins[created_at][key][0] += 1
                bins[created_at][key][1] += payload["bytes"]
            if event_type == "deletion-failed":
                bins[created_at][key][2] += 1
                bins[created_at][key][3] += payload["bytes"]
    points = ""
    for timestamp in bins:
        for entry in bins[timestamp]:
            metrics = bins[timestamp][entry]
            event_type = entry.split(",")[0]
            point = (
                "%s nb_%s_done=%s,bytes_%s_done=%s,nb_%s_failed=%s,bytes_%s_failed=%s %s"
                % (
                    entry,
                    event_type,
                    metrics[0],
                    event_type,
                    metrics[1],
                    event_type,
                    metrics[2],
                    event_type,
                    metrics[3],
                    timestamp,
                )
            )
            points += point
            points += "\n"
    influx_token = config_get("hermes", "influxdb_token", False, None)
    if influx_token:
        headers = {"Authorization": "Token %s" % influx_token}
    if points:
        res = requests.post(endpoint, headers=headers, data=points)
        logger(logging.DEBUG, "%s", str(res.text))
        return res.status_code
    return 204


def hermes(once: bool = False, bulk: int = 1000, sleep_time: int = 10) -> None:
    """
    Creates a Hermes Worker that can submit messages to different services (InfluXDB, ElasticSearch, ActiveMQ)
    The list of services need to be define in the config service in the hermes section.
    The list of endpoints need to be defined in rucio.cfg in the hermes section.

    :param once:       Run only once.
    :param bulk:       The number of requests to process.
    :param sleep_time: Time between two cycles.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
        ),
    )


def run_once(heartbeat_handler: "HeartbeatHandler", bulk: int, **_kwargs) -> bool:

    worker_number, total_workers, logger = heartbeat_handler.live()
    try:
        services_list = config_get_list("hermes", "services_list")
    except (NoOptionError, NoSectionError, RuntimeError):
        logger(logging.DEBUG, "No services found, exiting")
        sys.exit(1)

    if "influx" in services_list:
        influx_endpoint = None
        try:
            influx_endpoint = config_get("hermes", "influxdb_endpoint", False, None)
            if not influx_endpoint:
                logger(
                    logging.ERROR,
                    "InfluxDB defined in the services list, but no endpoint can be found",
                )
        except Exception as err:
            logger(logging.ERROR, str(err))
    if "elastic" in services_list:
        elastic_endpoint = None
        try:
            elastic_endpoint = config_get("hermes", "elastic_endpoint", False, None)
            if not elastic_endpoint:
                logger(
                    logging.ERROR,
                    "Elastic defined in the services list, but no endpoint can be found",
                )
        except Exception as err:
            logger(logging.ERROR, str(err))
    conns = None
    if "activemq" in services_list:
        try:
            conns, destination, username, password, use_ssl = setup_activemq(logger)
            if not conns:
                logger(
                    logging.ERROR,
                    "ActiveMQ defined in the services list, cannot be setup",
                )
        except Exception as err:
            logger(logging.ERROR, str(err))

    worker_number, total_workers, logger = heartbeat_handler.live()
    message_dict = {}
    message_ids = []
    start_time = time.time()
    messages = retrieve_messages(
        bulk=bulk,
        old_mode=False,
        thread=worker_number,
        total_threads=total_workers,
    )

    to_delete = []
    if messages:
        for message in messages:
            service = message["services"]
            if service not in message_dict:
                message_dict[service] = []
            message_dict[service].append(message)
            message_ids.append(message["id"])
        logger(
            logging.DEBUG,
            "Retrieved %i messages retrieved in %s seconds",
            len(messages),
            time.time() - start_time,
        )

        if "influx" in message_dict and influx_endpoint:
            # For influxDB, bulk submission, either everything succeeds or fails
            t_time = time.time()
            logger(logging.DEBUG, "Will submit to influxDB")
            try:
                state = aggregate_to_influx(
                    messages=message_dict["influx"],
                    bin_size="1m",
                    endpoint=influx_endpoint,
                    logger=logger,
                )
                if state in [204, 200]:
                    logger(
                        logging.INFO,
                        "%s messages successfully submitted to influxDB in %s seconds",
                        len(message_dict["influx"]),
                        time.time() - t_time,
                    )
                    for message in message_dict["influx"]:
                        to_delete.append(message)
                else:
                    logger(
                        logging.ERROR,
                        "Failure to submit %s messages to influxDB. Returned status: %s",
                        len(message_dict["influx"]),
                        state,
                    )
            except Exception as error:
                logger(logging.ERROR, "Error sending to InfluxDB : %s", str(error))

        if "elastic" in message_dict and elastic_endpoint:
            # For elastic, bulk submission, either everything succeeds or fails
            t_time = time.time()
            try:
                state = submit_to_elastic(
                    messages=message_dict["elastic"],
                    endpoint=elastic_endpoint,
                    logger=logger,
                )
                if state in [200, 204]:
                    logger(
                        logging.INFO,
                        "%s messages successfully submitted to elastic in %s seconds",
                        len(message_dict["elastic"]),
                        time.time() - t_time,
                    )
                    for message in message_dict["elastic"]:
                        to_delete.append(message)
                else:
                    logger(
                        logging.ERROR,
                        "Failure to submit %s messages to elastic. Returned status: %s",
                        len(message_dict["elastic"]),
                        state,
                    )
            except Exception as error:
                logger(logging.ERROR, "Error sending to Elastic : %s", str(error))

        if "email" in message_dict:
            t_time = time.time()
            try:
                messages_sent = deliver_emails(
                    messages=message_dict["email"], logger=logger
                )
                logger(
                    logging.INFO,
                    "%s messages successfully submitted by emails in %s seconds",
                    len(message_dict["email"]),
                    time.time() - t_time,
                )
                for message in message_dict["email"]:
                    if message["id"] in messages_sent:
                        to_delete.append(message)
            except Exception as error:
                logger(logging.ERROR, "Error sending email : %s", str(error))

        if "activemq" in message_dict and conns:
            t_time = time.time()
            try:
                messages_sent = deliver_to_activemq(
                    messages=message_dict["activemq"],
                    conns=conns,
                    destination=destination,
                    username=username,
                    password=password,
                    use_ssl=use_ssl,
                    logger=logger,
                )
                logger(
                    logging.INFO,
                    "%s messages successfully submitted to ActiveMQ in %s seconds",
                    len(message_dict["activemq"]),
                    time.time() - t_time,
                )
                for message in message_dict["activemq"]:
                    if message["id"] in messages_sent:
                        to_delete.append(message)
            except Exception as error:
                logger(logging.ERROR, "Error sending to ActiveMQ : %s", str(error))

    logger(logging.INFO, "Deleting %s messages", len(to_delete))
    to_delete = [
        {
            "id": message["id"],
            "created_at": message["created_at"],
            "updated_at": message["created_at"],
            "payload": str(message["payload"]),
            "event_type": message["event_type"],
        }
        for message in to_delete
    ]
    delete_messages(messages=to_delete)
    must_sleep = True
    return must_sleep


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    logging.info("Caught CTRL-C - waiting for cycle to end before shutting down")
    graceful_stop.set()


def run(
    once: bool = False,
    threads: int = 1,
    bulk: int = 1000,
    sleep_time: int = 10,
    broker_timeout: int = 3,
) -> None:
    """
    Starts up the hermes threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException("Database was not updated, daemon won't start")

    logging.info("starting hermes threads")
    thread_list = [
        threading.Thread(
            target=hermes,
            kwargs={
                "once": once,
                "bulk": bulk,
                "sleep_time": sleep_time,
            },
        )
        for _ in range(0, threads)
    ]

    for thrd in thread_list:
        thrd.start()

    logging.debug(thread_list)
    # Interruptible joins require a timeout.
    while thread_list:
        thread_list = [
            thread.join(timeout=3.14)
            for thread in thread_list
            if thread and thread.is_alive()
        ]
