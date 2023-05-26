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
Hermes Test
"""

from datetime import datetime
from json import loads
import requests
import pytest

import stomp
import time

from rucio.common.config import config_get, config_get_int
from rucio.core.message import add_message, retrieve_messages, truncate_messages
from rucio.daemons.hermes import hermes
from rucio.tests.common import rse_name_generator, skip_missing_elasticsearch_influxdb_in_env


class MyListener(object):
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
                (
                    "hermes",
                    "elastic_endpoint",
                    "http://localhost:9200/ddm_events/doc/_bulk",
                ),
                (
                    "hermes",
                    "influxdb_endpoint",
                    "http://localhost:8086/api/v2/write?org=rucio&bucket=rucio",
                ),
                ("hermes", "influxdb_token", "mytoken"),
                ("messaging-hermes", "destination", "/queue/events"),
                ("messaging-hermes", "brokers", "localhost"),
                ("messaging-hermes", "use_ssl", False),
                ("messaging-hermes", "username", "hermes"),
                ("messaging-hermes", "password", "supersecret"),
                ("messaging-hermes", "nonssl_port", 61613),
                ("messaging-hermes", "send_email", False),
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
def test_hermes(core_config_mock, caches_mock):
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
                "to": config_get("messaging-hermes", "email_test").split(","),
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
    hermes.hermes(once=True)
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
        "http://localhost:8086/query?db=rucio",
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
        "http://localhost:9200/_search?size=1000", data=data, headers=headers
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
