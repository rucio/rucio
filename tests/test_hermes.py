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
Hermes Test
"""

import logging
import logging.handlers
import socket
import time
from configparser import NoOptionError
from datetime import datetime
from json import loads
from unittest.mock import MagicMock, patch

import pytest
import requests
import stomp

from rucio.common.config import config_get, config_get_int, config_get_list
from rucio.common.exception import ConfigurationError
from rucio.core.message import add_message, retrieve_messages, truncate_messages
from rucio.daemons.hermes import hermes
from rucio.tests.common import rse_name_generator, skip_missing_elasticsearch_influxdb_in_env


class MyListener:
    def __init__(self, conn):
        self.conn = conn
        self.count = 0
        self.messages = []

    def reset(self):
        self.count = 0
        self.messages = []

    def on_error(self, headers, message):
        print("received an error %s" % message)

    def on_message(self, frame):
        print("received message %s" % frame)
        message = frame.body
        self.count += 1
        self.messages.append(loads(message))


@pytest.mark.noparallel(reason="fails when run in parallel")
@skip_missing_elasticsearch_influxdb_in_env
@pytest.mark.parametrize(
    "core_config_mock",
    [
        {
            "table_content": [
                ("hermes", "services_list", "influx,activemq,elastic,email"),
                ("hermes", "elastic_endpoint", "http://elasticsearch:9200/ddm_events/_bulk"),
                ("hermes", "influxdb_endpoint", "http://influxdb:8086/api/v2/write?org=rucio&bucket=rucio"),
                ("hermes", "influxdb_token", "mytoken"),
                ("messaging-hermes", "destination", "/queue/events"),
                ("messaging-hermes", "brokers", "localhost"),
                ("messaging-hermes", "use_ssl", False),
                ("messaging-hermes", "username", "hermes"),
                ("messaging-hermes", "password", "supersecret"),
                ("messaging-hermes", "nonssl_port", 61613),
                ("messaging-hermes", "send_email", True),
                ("messaging-hermes", "smtp_host", "testing.host"),
                ("messaging-hermes", "smtp_port", 1234),
            ]
        },
        {
            "table_content": [
                ("hermes", "services_list", "influx,activemq,elastic,email"),
                ("hermes", "elastic_endpoint", "http://elasticsearch:9200/ddm_events/_bulk"),
                ("hermes", "influxdb_endpoint", "http://influxdb:8086/api/v2/write?org=rucio&bucket=rucio"),
                ("hermes", "influxdb_token", "mytoken"),
                ("messaging-hermes", "destination", "/queue/events"),
                ("messaging-hermes", "brokers", "localhost"),
                ("messaging-hermes", "use_ssl", False),
                ("messaging-hermes", "username", "hermes"),
                ("messaging-hermes", "password", "supersecret"),
                ("messaging-hermes", "nonssl_port", 61613),
                ("messaging-hermes", "send_email", True),
                ("messaging-hermes", "smtp_host", "testing.host"),
                ("messaging-hermes", "smtp_port", 1234),
            ]
        }
    ],
    ids=[
        "unauthenticated",
        "authenticated"
    ],
    indirect=True,
)
@pytest.mark.parametrize(
    "caches_mock",
    [
        {
            "caches_to_mock": [
                "rucio.core.config.REGION",
            ]
        }
    ],
    indirect=True,
)
def test_hermes(core_config_mock, caches_mock, monkeypatch):
    """HERMES (DAEMON): Test the messaging daemon."""
    truncate_messages()
    mock_rse = rse_name_generator()
    file_size = 2
    nb_messages = 3
    list_messages = []
    event_types = ["blahblah", "deletion-done"]

    # Start consumer
    host = config_get("messaging-hermes", "brokers")
    port = config_get_int("messaging-hermes", "port")
    user = config_get("messaging-hermes", "username")
    password = config_get("messaging-hermes", "password")
    destination = config_get("messaging-hermes", "destination")
    conn = stomp.Connection(host_and_ports=[(host, port)])
    listener = MyListener(conn)
    conn.set_listener("", listener)
    conn.connect(login=user, passcode=password)
    conn.subscribe(
        destination=destination,
        id=1,
        ack="auto",
        headers={
            "subscription-type": "MULTICAST",
            "durable-subscription-name": "someValue",
        },
    )
    for _ in range(10):
        if conn.is_connected():
            break
        time.sleep(2)
    listener.reset()
    print("Waiting for messages...")

    # Create 3 messages of type blahblah registered to services influx, activemq and elastic
    # Create 3 messages of type email registered to service email
    for i in range(1, 4):
        event_type = event_types[0]
        message = {
            "bytes": 2,
            "rse": mock_rse,
            "created_at": datetime.utcnow().replace(microsecond=0),
        }
        add_message(event_type, message)
        add_message(
            "email",
            {
                "to": config_get_list("messaging-hermes", "email_test"),
                "subject": "Half-Life %i" % i,
                "body": """
                              Good morning, and welcome to the Black Mesa Transit System.

                              This automated train is provided for the security and convenience of
                              the Black Mesa Research Facility personnel. The time is eight-forty
                              seven A.M... Current outside temperature is ninety three degrees with
                              an estimated high of one hundred and five. Before exiting the train,
                              be sure to check your area for personal belongings.

                              Thank you, and have a very safe, and productive day.""",
            },
        )
        message["event_type"] = event_type
        list_messages.append(message)

    messages = retrieve_messages(50, old_mode=False)
    service_dict = {"influx": 0, "elastic": 0, "email": 0, "activemq": 0}
    for message in messages:
        service_dict[message["services"]] += 1
    assert service_dict["influx"] == 3
    assert service_dict["elastic"] == 3
    assert service_dict["activemq"] == 3
    assert service_dict["email"] == 3

    # Run Hermes
    # The messages of event_type email should be submitted and removed from the list
    # The messages of event-type blahblah should be removed from the list for service influx since this event-type is not supported by influx
    # The messages of event-type blahblah should be submitted to elastic
    # The messages of event-type blahblah should be submitted to ActiveMQ
    with monkeypatch.context() as m:
        smtp_mock = MagicMock()
        m.setattr(hermes.smtplib, "SMTP", smtp_mock)
        hermes.hermes(once=True)
        smtp_host = config_get("messaging-hermes", "smtp_host", default='', raise_exception=False)
        if not smtp_host:
            smtp_mock.assert_called_with()
        else:
            smtp_mock.assert_called_with(host="testing.host", port=1234)
    service_dict = {"influx": 0, "elastic": 0, "email": 0, "activemq": 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        service_dict[message["services"]] += 1
    assert service_dict["influx"] == 0
    assert service_dict["elastic"] == 0
    assert service_dict["activemq"] == 0
    assert service_dict["email"] == 0

    # Now add nb_messages more messages of event-type deletion-done associated to services influx, elastic and activemq
    for _ in range(nb_messages):
        event_type = event_types[1]
        message = {
            "bytes": file_size,
            "rse": mock_rse,
            "created_at": datetime.utcnow().replace(microsecond=0),
        }
        add_message(event_type, message)
        message["event_type"] = event_type
        list_messages.append(message)

    messages = retrieve_messages(50, old_mode=False)
    service_dict = {"influx": 0, "elastic": 0, "email": 0, "activemq": 0}
    for message in messages:
        service_dict[message["services"]] += 1
    assert service_dict["influx"] == 3
    assert service_dict["elastic"] == 3
    assert service_dict["activemq"] == 3
    assert service_dict["email"] == 0

    # Run Hermes
    hermes.hermes(once=True)
    service_dict = {"influx": 0, "elastic": 0, "email": 0, "activemq": 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        service_dict[message["services"]] += 1
    time.sleep(20)  # Waiting that all the messages are consumed to check ActiveMQ

    # Checking influxDB
    assert service_dict["influx"] == 0
    res = requests.get(
        "http://influxdb:8086/query?db=rucio",
        headers={"Authorization": "Token mytoken"},
        params={"q": "SELECT * FROM deletion"},
    )
    assert res.status_code == 200
    assert "results" in res.json()
    influx_res = res.json()["results"]
    assert "series" in influx_res[0]
    columns = influx_res[0]["series"][0]["columns"]
    rse_index = columns.index("rse")
    rse_included = False
    for res in influx_res[0]["series"][0]["values"]:
        if res[rse_index] == mock_rse:
            rse_included = True
            nb_deletion_done = columns.index("nb_deletion_done")
            bytes_deletion_done = columns.index("bytes_deletion_done")
            assert res[nb_deletion_done] == nb_messages
            assert res[bytes_deletion_done] == nb_messages * file_size
    assert rse_included

    # Checking ElasticSearch
    pattern = "%a, %d %b %Y %H:%M:%S %Z"
    assert service_dict["elastic"] == 0
    data = ' { "query": { "match_all": {} } }'
    headers = {"Content-Type": "application/json"}
    response = requests.post(
        "http://elasticsearch:9200/_search?size=1000", data=data, headers=headers
    )
    assert response.status_code == 200
    res = response.json()
    print(res)
    elastic_messages = []
    for entry in res["hits"]["hits"]:
        message = entry["_source"]
        elastic_messages.append(
            {
                "created_at": datetime.strptime(
                    message["payload"]["created_at"], pattern
                ),
                "event_type": message["event_type"],
                "rse": message["payload"]["rse"],
                "bytes": message["payload"]["bytes"],
            }
        )
    for message in list_messages:
        assert message in elastic_messages

    # Checking ActiveMQ
    assert service_dict["activemq"] == 0
    assert len(listener.messages) == len(list_messages)

    activemq_messages = []
    for message in listener.messages:
        message["payload"]["created_at"] = datetime.strptime(
            message["payload"]["created_at"], pattern
        )
        message["payload"]["event_type"] = message["event_type"]
        activemq_messages.append(message["payload"])
    for message in list_messages:
        assert message in activemq_messages

    # Checking email
    assert service_dict["email"] == 0


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize(
    "core_config_mock",
    [
        {
            "table_content": [
                ("hermes", "services_list", "syslog"),
                ("messaging-hermes", "syslog_address", "/dev/log"),
                ("messaging-hermes", "syslog_socktype", "SOCK_DGRAM"),
            ]
        }
    ],
    indirect=True,
)
@pytest.mark.parametrize(
    "caches_mock",
    [
        {
            "caches_to_mock": [
                "rucio.core.config.REGION",
            ]
        }
    ],
    indirect=True,
)
def test_hermes_syslog(core_config_mock, caches_mock):
    """HERMES (DAEMON): Test syslog message delivery."""
    truncate_messages()
    mock_rse = rse_name_generator()
    nb_messages = 3

    # Mock the SysLogHandler
    with patch('logging.handlers.SysLogHandler') as mock_syslog_handler:
        mock_handler_instance = MagicMock()
        mock_handler_instance.level = logging.INFO
        mock_syslog_handler.return_value = mock_handler_instance

        # Create messages - will be automatically assigned to syslog service
        for i in range(nb_messages):
            message = {
                "bytes": 100 + i,
                "rse": mock_rse,
                "scope": "test",
                "name": f"file_{i}",
                "created_at": datetime.utcnow().replace(microsecond=0),
            }
            add_message("transfer-done", message)

        # Verify messages were added
        messages = retrieve_messages(50, old_mode=False)
        service_dict = {"syslog": 0}
        for message in messages:
            if message["services"] == "syslog":
                service_dict["syslog"] += 1
        assert service_dict["syslog"] == nb_messages

        # Run Hermes
        hermes.hermes(once=True)

        # Verify SysLogHandler was created with correct parameters
        mock_syslog_handler.assert_called_once()
        call_kwargs = mock_syslog_handler.call_args[1]
        assert call_kwargs["facility"] == logging.handlers.SysLogHandler.LOG_USER

        # Verify messages were delivered and deleted
        messages = retrieve_messages(50, old_mode=False)
        service_dict = {"syslog": 0}
        for message in messages:
            if message["services"] == "syslog":
                service_dict["syslog"] += 1
        assert service_dict["syslog"] == 0


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize(
    "core_config_mock",
    [
        {
            "table_content": [
                ("hermes", "services_list", "syslog"),
                ("messaging-hermes", "syslog_address", "localhost:514"),
                ("messaging-hermes", "syslog_socktype", "SOCK_STREAM"),
            ]
        }
    ],
    indirect=True,
)
@pytest.mark.parametrize(
    "caches_mock",
    [
        {
            "caches_to_mock": [
                "rucio.core.config.REGION",
            ]
        }
    ],
    indirect=True,
)
def test_hermes_syslog_tcp(core_config_mock, caches_mock):
    """HERMES (DAEMON): Test syslog message delivery with TCP socket."""
    truncate_messages()
    mock_rse = rse_name_generator()

    with patch('logging.handlers.SysLogHandler') as mock_syslog_handler:
        mock_handler_instance = MagicMock()
        mock_handler_instance.level = logging.INFO
        mock_syslog_handler.return_value = mock_handler_instance

        # Create a message - will be automatically assigned to syslog service
        message = {
            "bytes": 1000,
            "rse": mock_rse,
            "scope": "test",
            "name": "file_tcp",
            "created_at": datetime.utcnow().replace(microsecond=0),
        }
        add_message("deletion-done", message)

        # Run Hermes
        hermes.hermes(once=True)

        # Verify SysLogHandler was created with TCP socket type and parsed address
        mock_syslog_handler.assert_called_once()
        call_kwargs = mock_syslog_handler.call_args[1]
        assert call_kwargs["address"] == ("localhost", 514)

        # Verify messages were deleted
        messages = retrieve_messages(50, old_mode=False)
        syslog_messages = [m for m in messages if m["services"] == "syslog"]
        assert len(syslog_messages) == 0


# unit tests for Kafka support
class _FakeKafkaError:
    """Stand-in for the ``KafkaError`` handed to ``on_delivery``
    on a failed delivery. Only ``str()`` is used by Hermes."""

    def __init__(self, reason="delivery failed"):
        self._reason = reason

    def __str__(self):
        return self._reason


class _FakeKafkaMessage:
    """Stand-in for the ``Message`` handed to ``on_delivery``."""

    def __init__(self, value):
        self._value = value

    def value(self):
        return self._value


class _FakeKafkaException(Exception):
    """Stand-in for ``confluent_kafka.KafkaException`` so we don't have to
    import the optional ``confluent_kafka`` extra just to model the error."""


class FakeKafkaProducer:
    """stand-in for ``confluent_kafka.Producer``.

    * The constructor takes a librdkafka config dict and rejects
      keyword config such as ``bootstrap_servers=...``. Passing kwargs
      raises ``TypeError`
    * ``produce()`` only registers the ``on_delivery`` callback; it does not
      fire it
    """

    def __init__(self, config, *, fail_indices=frozenset(), raise_map=None):
        if not isinstance(config, dict):
            raise TypeError(
                "confluent_kafka.Producer expects a single positional config "
                f"dict, got {type(config)!r}"
            )
        self.config = config
        self._fail_indices = set(fail_indices)
        self._raise_map = dict(raise_map or {})
        self._pending = []
        self.produced_values = []
        self.produce_calls = 0
        self.flush_calls = 0

    def produce(self, topic, value=None, key=None, on_delivery=None, **_kwargs):
        idx = self.produce_calls
        self.produce_calls += 1
        exc = self._raise_map.get(idx)
        if exc is not None:
            raise exc
        self.produced_values.append(value)
        self._pending.append((idx, value, on_delivery))

    def flush(self, timeout=None):
        self.flush_calls += 1
        pending, self._pending = self._pending, []
        for idx, value, on_delivery in pending:
            if on_delivery is None:
                continue
            if idx in self._fail_indices:
                on_delivery(_FakeKafkaError(), _FakeKafkaMessage(value))
            else:
                on_delivery(None, _FakeKafkaMessage(value))
        return 0  # nothing left queued


def _make_producer_mock(*, fail_indices=frozenset(), raise_map=None):
    """Return a ``MagicMock`` suitable for patching ``hermes.Producer``"""
    created = {}

    def _factory(config):
        producer = FakeKafkaProducer(config, fail_indices=fail_indices, raise_map=raise_map)
        created["producer"] = producer
        return producer

    producer_mock = MagicMock(side_effect=_factory)
    producer_mock.created = created
    return producer_mock


def _count_kafka_messages():
    """Number of undelivered messages still queued for the kafka service"""
    return sum(
        1 for message in retrieve_messages(50, old_mode=False)
        if message["services"] == "kafka"
    )


def _add_kafka_messages(mock_rse, nb_messages):
    """Add ``nb_messages`` transfer-done messages (routed to kafka via config)"""
    for i in range(nb_messages):
        add_message(
            "transfer-done",
            {
                "bytes": 100 + i,
                "rse": mock_rse,
                "scope": "test",
                "name": f"file_{i}",
                "created_at": datetime.utcnow().replace(microsecond=0),
            },
        )


# Unit tests for setup_kafka() branches
def test_setup_kafka_nonssl_config():
    """HERMES (DAEMON): setup_kafka builds a valid non-SSL librdkafka config"""
    logger = MagicMock()
    values = {
        ("messaging-hermes-kafka", "brokers"): "broker",
        ("messaging-hermes-kafka", "topic"): "hermeskafka",
    }

    def fake_config_get(section, option, *args, **kwargs):
        key = (section, option)
        if key in values:
            return values[key]
        # optional lookups (username/password) fall back to their default
        if "default" in kwargs:
            return kwargs["default"]
        raise NoOptionError(option, section)

    with patch("rucio.daemons.hermes.hermes.Producer") as producer_mock, \
            patch("rucio.daemons.hermes.hermes.config_get", side_effect=fake_config_get), \
            patch("rucio.daemons.hermes.hermes.config_get_bool", return_value=False), \
            patch("rucio.daemons.hermes.hermes.config_get_int", return_value=300000):
        producer, topic = hermes.setup_kafka(logger)

    assert topic == "hermeskafka"

    # Must be one positional config dict, no keyword config
    producer_mock.assert_called_once_with(
        {
            "bootstrap.servers": "broker",
            "client.id": socket.gethostname(),
            "message.timeout.ms": 300000,
        }
    )
    args, kwargs = producer_mock.call_args
    assert len(args) == 1 and not kwargs
    config = args[0]
    # No SSL/SASL keys leaked into the plaintext branch.
    assert "security.protocol" not in config
    assert not any(k.startswith("ssl.") for k in config)
    # None of the invalid kafka-python-style names are present.
    for bad in ("bootstrap_servers", "client_id", "message_timeout_ms"):
        assert bad not in config


def test_setup_kafka_ssl_config():
    """HERMES (DAEMON): setup_kafka builds a valid SSL librdkafka config """
    logger = MagicMock()
    values = {
        ("messaging-hermes-kafka", "brokers"): "secure-broker:9093",
        ("messaging-hermes-kafka", "ca_cert"): "/etc/ssl/ca.pem",
        ("messaging-hermes-kafka", "certfile"): "/etc/ssl/client.pem",
        ("messaging-hermes-kafka", "keyfile"): "/etc/ssl/client.key",
        ("messaging-hermes-kafka", "topic"): "hermeskafka",
    }

    def fake_config_get(section, option, *args, **kwargs):
        key = (section, option)
        if key in values:
            return values[key]
        if "default" in kwargs:
            return kwargs["default"]
        raise NoOptionError(option, section)

    with patch("rucio.daemons.hermes.hermes.Producer") as producer_mock, \
            patch("rucio.daemons.hermes.hermes.config_get", side_effect=fake_config_get), \
            patch("rucio.daemons.hermes.hermes.config_get_bool", return_value=True), \
            patch("rucio.daemons.hermes.hermes.config_get_int", return_value=300000):
        producer, topic = hermes.setup_kafka(logger)

    assert topic == "hermeskafka"
    producer_mock.assert_called_once_with(
        {
            "bootstrap.servers": "secure-broker:9093",
            "client.id": socket.gethostname(),
            "message.timeout.ms": 300000,
            "security.protocol": "SSL",
            "ssl.ca.location": "/etc/ssl/ca.pem",
            "ssl.certificate.location": "/etc/ssl/client.pem",
            "ssl.key.location": "/etc/ssl/client.key",
        }
    )


def test_setup_kafka_missing_brokers():
    """test for missing brokers"""
    logger = MagicMock()

    def fake_config_get(section, option, *args, **kwargs):
        if (section, option) == ("messaging-hermes-kafka", "brokers"):
            raise NoOptionError(option, section)
        raise AssertionError(f"unexpected config_get({section}, {option})")

    with patch("rucio.daemons.hermes.hermes.Producer") as producer_mock, \
            patch("rucio.daemons.hermes.hermes.config_get", side_effect=fake_config_get):
        with pytest.raises(ConfigurationError):
            hermes.setup_kafka(logger)

    producer_mock.assert_not_called()


def test_setup_kafka_missing_topic():
    """test for missing topic"""
    logger = MagicMock()

    def fake_config_get(section, option, *args, **kwargs):
        if (section, option) == ("messaging-hermes-kafka", "brokers"):
            return "broker"
        if (section, option) == ("messaging-hermes-kafka", "topic"):
            raise NoOptionError(option, section)
        if "default" in kwargs:  # username / password
            return kwargs["default"]
        raise NoOptionError(option, section)

    with patch("rucio.daemons.hermes.hermes.Producer") as producer_mock, \
            patch("rucio.daemons.hermes.hermes.config_get", side_effect=fake_config_get), \
            patch("rucio.daemons.hermes.hermes.config_get_bool", return_value=False), \
            patch("rucio.daemons.hermes.hermes.config_get_int", return_value=300000):
        with pytest.raises(ConfigurationError):
            hermes.setup_kafka(logger)

    producer_mock.assert_called_once()


_KAFKA_CORE_CONFIG = [
    {
        "table_content": [
            ("hermes", "services_list", "kafka"),
            ("messaging-hermes-kafka", "use_ssl", False),
            ("messaging-hermes-kafka", "brokers", "broker"),
            ("messaging-hermes-kafka", "topic", "hermeskafka"),
        ]
    }
]
_KAFKA_CACHES = [{"caches_to_mock": ["rucio.core.config.REGION"]}]


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize("core_config_mock", _KAFKA_CORE_CONFIG, indirect=True)
@pytest.mark.parametrize("caches_mock", _KAFKA_CACHES, indirect=True)
def test_hermes_kafka(core_config_mock, caches_mock):
    """test path with no errors"""
    truncate_messages()
    mock_rse = rse_name_generator()
    nb_messages = 3

    producer_mock = _make_producer_mock()
    with patch("rucio.daemons.hermes.hermes.Producer", producer_mock):
        _add_kafka_messages(mock_rse, nb_messages)
        assert _count_kafka_messages() == nb_messages

        hermes.hermes(once=True)

        # Constructor contract: called once, single positional dict, no kwargs.
        producer_mock.assert_called_once()
        args, kwargs = producer_mock.call_args
        assert len(args) == 1 and not kwargs, \
            "Producer must be built with a single positional librdkafka config dict"
        config = args[0]
        assert isinstance(config, dict)
        assert "bootstrap.servers" in config
        assert "client.id" in config
        assert "message.timeout.ms" in config
        # librdkafka properties are dot-separated; an underscore in any key
        # means a kafka-python-style name leaked in.
        assert not any("_" in key for key in config), \
            f"non-librdkafka (underscore) config keys: {sorted(config)}"
        # plaintext branch -> no TLS/SASL properties
        assert "security.protocol" not in config
        assert not any(k.startswith("ssl.") for k in config)

        fake = producer_mock.created["producer"]
        assert fake.produce_calls == nb_messages
        assert fake.flush_calls >= 1

        # All delivered -> all deleted.
        assert _count_kafka_messages() == 0


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize("core_config_mock", _KAFKA_CORE_CONFIG, indirect=True)
@pytest.mark.parametrize("caches_mock", _KAFKA_CACHES, indirect=True)
def test_hermes_kafka_failed_delivery(core_config_mock, caches_mock):
    """test path with all errors"""
    truncate_messages()
    mock_rse = rse_name_generator()
    nb_messages = 3

    producer_mock = _make_producer_mock(fail_indices={0, 1, 2})
    with patch("rucio.daemons.hermes.hermes.Producer", producer_mock):
        _add_kafka_messages(mock_rse, nb_messages)
        assert _count_kafka_messages() == nb_messages

        hermes.hermes(once=True)

        producer_mock.assert_called_once()
        fake = producer_mock.created["producer"]
        assert fake.produce_calls == nb_messages
        # Nothing confirmed -> nothing deleted.
        assert _count_kafka_messages() == nb_messages


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize("core_config_mock", _KAFKA_CORE_CONFIG, indirect=True)
@pytest.mark.parametrize("caches_mock", _KAFKA_CACHES, indirect=True)
def test_hermes_kafka_partial_failure(core_config_mock, caches_mock):
    """test path with partial failures"""
    truncate_messages()
    mock_rse = rse_name_generator()
    nb_messages = 3

    producer_mock = _make_producer_mock(fail_indices={2})
    with patch("rucio.daemons.hermes.hermes.Producer", producer_mock):
        _add_kafka_messages(mock_rse, nb_messages)
        assert _count_kafka_messages() == nb_messages

        hermes.hermes(once=True)

        producer_mock.assert_called_once()
        fake = producer_mock.created["producer"]
        assert fake.produce_calls == nb_messages
        # 2 delivered -> deleted, 1 failed -> still queued.
        assert _count_kafka_messages() == 1


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.parametrize(
    "produce_error",
    [
        BufferError("Local: Queue full"),
        _FakeKafkaException("Broker: Message size too large"),
        NotImplementedError("unsupported produce feature"),
    ],
    ids=["buffererror", "kafkaexception", "notimplemented"],
)
@pytest.mark.parametrize("core_config_mock", _KAFKA_CORE_CONFIG, indirect=True)
@pytest.mark.parametrize("caches_mock", _KAFKA_CACHES, indirect=True)
def test_hermes_kafka_produce_raises(core_config_mock, caches_mock, produce_error):
    """testing produce exceptions"""
    truncate_messages()
    mock_rse = rse_name_generator()
    nb_messages = 3

    # The middle message raises on produce(); the other two deliver normally.
    producer_mock = _make_producer_mock(raise_map={1: produce_error})
    with patch("rucio.daemons.hermes.hermes.Producer", producer_mock):
        _add_kafka_messages(mock_rse, nb_messages)
        assert _count_kafka_messages() == nb_messages

        # Must not propagate out of the daemon.
        hermes.hermes(once=True)

        producer_mock.assert_called_once()
        fake = producer_mock.created["producer"]
        # The loop continues past the raising message.
        assert fake.produce_calls == nb_messages
        # The message whose produce() raised is neither delivered nor deleted;
        # the other two are delivered and deleted.
        assert _count_kafka_messages() == 1
