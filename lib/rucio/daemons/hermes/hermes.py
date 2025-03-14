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
import sys
import threading
import time
from configparser import NoOptionError, NoSectionError
from email.mime.text import MIMEText
from typing import TYPE_CHECKING, Any, Optional, Union

import requests
from requests.auth import HTTPBasicAuth

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool, config_get_list
from rucio.common.exception import DatabaseException
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.stomp_utils import ListenerBase, StompConnectionManager
from rucio.core.message import delete_messages, retrieve_messages
from rucio.core.monitor import MetricManager
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import FrameType

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


class HermesListener(ListenerBase):
    """
    Hermes Listener
    """


def deliver_emails(messages: "Iterable[dict[str, Any]]", logger: "LoggerFunction") -> list[int]:
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
    res = requests.post(endpoint,
                        data=text,
                        headers={"Content-Type": "application/json"},
                        auth=auth)
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
                logger(logging.WARNING,
                       "No transferred_at for message. Reason : %s",
                       payload["reason"])
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
            key = f"transfer,activity={activity!s},src_rse={src_rse!s},dst_rse={dest_rse!s}"
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
            key = f"deletion,rse={rse!s}"
            if key not in bins[created_at]:
                bins[created_at][key] = [0, 0, 0, 0]
            if event_type == "deletion-done":
                bins[created_at][key][0] += 1
                bins[created_at][key][1] += payload["bytes"]
            if event_type == "deletion-failed":
                bins[created_at][key][2] += 1
                bins[created_at][key][3] += payload["bytes"]

    points = ""
    for timestamp, entries in bins.items():
        for key, metrics in entries.items():
            event_type = key.split(",")[0]
            points += (f"{key!s} "
                       f"nb_{event_type!s}_done={metrics[0]!s},"
                       f"bytes_{event_type!s}_done={metrics[1]!s},"
                       f"nb_{event_type!s}_failed={metrics[2]!s},"
                       f"bytes_{event_type!s}_failed={metrics[3]!s} "
                       rf"{timestamp!s}\n")

    influx_token = config_get("hermes", "influxdb_token", False, None)
    headers = {}
    if influx_token:
        headers["Authorization"] = f"Token {influx_token!s}"
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
    conns = None
    if "activemq" in services_list:
        conn_mgr = StompConnectionManager(config_section='messaging-hermes', logger=logger)
        conn_mgr.set_listener_factory("rucio-hermes", HermesListener, heartbeats=conn_mgr.config.heartbeats)

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

        if "activemq" in message_dict and conns:
            t_time = time.time()
            try:
                messages_sent = conn_mgr.deliver_messages(messages=message_dict["activemq"])
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
    logger = formatted_logger(logging.log, DAEMON_NAME + ' %s')

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException("Database was not updated, daemon won't start")

    logger(logging.INFO, "starting hermes threads")
    thread_list = []
    for _ in range(threads):
        her_thread = threading.Thread(target=hermes, kwargs={"once": once, "bulk": bulk, "sleep_time": sleep_time})
        her_thread.start()
        thread_list.append(her_thread)

    logger(logging.DEBUG, thread_list)
    while [thread.join(timeout=3.14) for thread in thread_list if thread.is_alive()]:
        pass
