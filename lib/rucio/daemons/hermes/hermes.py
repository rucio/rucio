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
import re
import smtplib
import ssl
import sys
import threading
import time
from configparser import NoOptionError, NoSectionError
from email.mime.text import MIMEText
from typing import TYPE_CHECKING, Any, Optional, Union

import requests
import stomp
from requests.auth import HTTPBasicAuth

import rucio.db.sqla.util
from rucio.common.config import (
    config_get,
    config_get_bool,
    config_get_int,
    config_get_list,
)
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging
from rucio.common.stomp_controller import StompController
from rucio.core.message import delete_messages, retrieve_messages
from rucio.core.monitor import MetricManager
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import FrameType

    from stomp import Connection
    from stomp.utils import Frame

    from rucio.common.types import LoggerFunction
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


def default(datetype: Union[datetime.date, datetime.datetime]) -> str:
    if isinstance(datetype, (datetime.date, datetime.datetime)):
        return datetype.isoformat()


class HermesListener(stomp.ConnectionListener):
    """
    Hermes Listener
    """

    def __init__(self, broker: str, conn: "Connection"):
        """
        __init__
        """
        self.__broker = broker

    def on_error(self, frame: "Frame") -> None:
        """
        Error handler
        """
        logging.error("[broker] [%s]: %s", self.__broker, frame.body)


def setup_activemq(
        logger: "LoggerFunction"
) -> tuple[
    "StompController",
    Optional[list[Any]],
    Optional[str]
]:
    """
    Deliver messages to ActiveMQ

    :param logger:             The logger object.
    """
    brokers_alias = config_get_list("messaging-hermes", "brokers")
    use_ssl = config_get_bool("messaging-hermes", "use_ssl", default=True)
    port = config_get_int("messaging-hermes", "port")
    vhost = config_get("messaging-hermes", "broker_virtual_host", raise_exception=False)
    username = None
    password = None
    if not use_ssl:
        username = config_get("messaging-hermes", "username")
        password = config_get("messaging-hermes", "password")
        port = config_get_int("messaging-hermes", "nonssl_port")
    reconnect_attempts = config_get_int("messaging-hermes", "reconnect_attempts", default=100)
    ssl_key_file = config_get("messaging-hermes", "ssl_key_file", raise_exception=False)
    ssl_cert_file = config_get("messaging-hermes", "ssl_cert_file", raise_exception=False)
    destination = config_get("messaging-hermes", "destination")

    controller = StompController(
        brokers=brokers_alias,
        port=port,
        use_ssl=use_ssl,
        vhost=vhost,
        username=username,
        password=password,
        ssl_key_file=ssl_key_file,
        ssl_cert_file=ssl_cert_file,
        timeout=None,
        reconnect_attempts=reconnect_attempts,
        logger=logger
    )
    controller.setup_connections()
    return controller, controller.connections, destination


def deliver_to_activemq(
    messages: "Iterable[dict[str, Any]]",
    stomp_controller: "StompController",
    destination: str,
    logger: "LoggerFunction"
) -> list[str]:
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
            stomp_controller.connect_and_send(message=message, destination=destination,
                                              listener_name='rucio-hermes', listener=HermesListener, metric=METRICS)
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


def deliver_emails(
        messages: "Iterable[dict[str, Any]]",
        logger: "LoggerFunction"
) -> list[str]:
    """
    Sends emails

    :param messages:           The list of messages.
    :param logger:             The logger object.

    :returns:                  List of message_id to delete
    """

    smtp_host = config_get("messaging-hermes", "smtp_host", default='')
    smtp_port = config_get_int("messaging-hermes", "smtp_port", default=25)
    smtp_username = config_get("messaging-hermes", "smtp_username", default='')
    smtp_password = config_get("messaging-hermes", "smtp_password", default='')
    smtp_certfile = config_get("messaging-hermes", "smtp_certfile", default='')
    smtp_keyfile = config_get("messaging-hermes", "smtp_keyfile", default='')
    smtp_usessl = config_get_bool("messaging-hermes", "smtp_usessl", default=False)
    smtp_usetls = config_get_bool("messaging-hermes", "smtp_usetls", default=False)
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
                    # Fall back to unauthenticated connection if no host is provided
                    if not smtp_host:
                        smtp = smtplib.SMTP()
                        smtp.connect()
                        smtp.sendmail(
                            msg["From"], message["payload"]["to"], msg.as_string()
                        )
                        smtp.quit()
                    else:
                        ssl_context = None
                        if smtp_certfile and smtp_keyfile:
                            ssl_context = ssl.create_default_context()
                            ssl_context.load_cert_chain(certfile=smtp_certfile, keyfile=smtp_keyfile)

                        smtp_context = smtplib.SMTP(host=smtp_host, port=smtp_port)
                        if not smtp_usetls and smtp_usessl:
                            smtp_context = smtplib.SMTP_SSL(host=smtp_host, port=smtp_port, context=ssl_context)

                        with smtp_context as smtp_server:
                            if smtp_usetls:
                                smtp_server.ehlo()  # not strictly necessary
                                smtp_server.starttls(context=ssl_context)
                            if smtp_username and smtp_password:
                                smtp_server.login(smtp_username, smtp_password)
                            smtp_server.sendmail(
                                msg["From"], message["payload"]["to"], msg.as_string()
                            )
                to_delete.append(message["id"])
            except Exception as error:
                logger(logging.ERROR, "Cannot send email : %s", str(error))
        else:
            to_delete.append(message["id"])
            continue
    return to_delete


def submit_to_elastic(
        messages: "Iterable[dict[str, Any]]",
        endpoint: str,
        logger: "LoggerFunction"
) -> int:
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
    messages: "Iterable[dict[str, Any]]",
    bin_size: str,
    endpoint: str,
    logger: "LoggerFunction"
) -> int:
    """
    Aggregate a list of message using a certain bin_size
    and submit them to a InfluxDB endpoint

    :param messages:           The list of messages.
    :param bin_size:           The size of the bins for the aggregation (e.g. 10m, 1h, etc.).
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


def build_message_dict(
        bulk: int,
        thread: int,
        total_threads: int,
        message_dict: dict[str, list[dict[str, Any]]],
        logger: "LoggerFunction",
        service: Optional[str] = None,
) -> None:
    """
    Retrieves messages from the database and builds a dictionary with the keys being the services, and the values a list of the messages (built up of dictionary / json information)

    :param bulk:               Integer for number of messages to retrieve.
    :param thread:             Passed to thread in retrieve_messages for Identifier of the caller thread as an integer.
    :param total_threads:      Passed to total_threads for Maximum number of threads as an integer.
    :param message_dict:       Either empty dictionary to be built, or build upon when using query_by_service.
    :param logger:             The logger object.
    :param service:            When passed, only returns messages table for this specific service.

    :returns:                  None, but builds on the dictionary message_dict passed to this fuction (for when querying multiple services).
    """
    start_time = time.time()
    messages = retrieve_messages(
        bulk=bulk,
        old_mode=False,
        thread=thread,
        total_threads=total_threads,
        service_filter=service,
    )

    if messages:
        if service is not None:
            # query_by_service dictionary build behaviour
            message_dict[service] = messages.copy()
            logger(
                logging.DEBUG,
                "Retrieved %i messages retrieved in %s seconds for %s service.",
                len(messages),
                time.time() - start_time,
                service,
            )

        else:
            # default dictionary build behaviour
            for message in messages:
                service = message["services"]
                if service is not None:
                    if service not in message_dict:
                        message_dict[service] = []
                    message_dict[service].append(message)
        logger(
            logging.DEBUG,
            "Retrieved %i messages retrieved in %s seconds",
            len(messages),
            time.time() - start_time,
        )
    else:
        logger(
            logging.INFO,
            "No messages retrieved in %s seconds",
            time.time() - start_time,
        )


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
    if "activemq" in services_list:
        try:
            stomp_controller, conns, destination = setup_activemq(logger)
            if not conns:
                logger(
                    logging.ERROR,
                    "ActiveMQ defined in the services list, cannot be setup",
                )
        except Exception as err:
            logger(logging.ERROR, str(err))

    worker_number, total_workers, logger = heartbeat_handler.live()
    message_dict = {}
    query_by_service = config_get_bool("hermes", "query_by_service", default=False)

    # query_by_service is a toggleable behaviour switch between collecting bulk number of messages across all services when false, to collecting bulk messages from each service when true.
    if query_by_service:
        for service in services_list:
            build_message_dict(
                bulk=bulk,
                thread=worker_number,
                total_threads=total_workers,
                message_dict=message_dict,
                logger=logger,
                service=service,
            )
    else:
        build_message_dict(
            bulk=bulk,
            thread=worker_number,
            total_threads=total_workers,
            message_dict=message_dict,
            logger=logger
        )

    if message_dict:
        to_delete = []

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

        if "activemq" in message_dict:
            t_time = time.time()
            try:
                messages_sent = deliver_to_activemq(
                    messages=message_dict["activemq"],
                    stomp_controller=stomp_controller,
                    destination=destination,  # type: ignore (argument could be None)
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
                "services": message["services"]
            }
            for message in to_delete
        ]
        delete_messages(messages=to_delete)

    must_sleep = True
    return must_sleep


def stop(signum: Optional[int] = None, frame: Optional["FrameType"] = None) -> None:
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
