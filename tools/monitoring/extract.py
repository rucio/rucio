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

from json import loads as jloads
from time import sleep

import elasticsearch as es
import stomp

ssl_key_file = ""
ssl_cert_file = ""
queue = "/topic/rucio.events"
chunksize = 1
subscription_id = 1
consumer = ""
consumer_port = 9200
es_username = ""
es_password = ""


class ElasticConn:
    def __init__(self, host_port, auth):
        self.__es = es.Elasticsearch([host_port[0]], http_auth=auth, consumer_port=host_port[1])

    def index_data(self, index_name, body):
        res = self.__es.index(index=index_name, body=body)
        print(res)
        return res["result"] == "created"


class AMQConsumer(stomp.ConnectionListener):
    def __init__(self, conn, chunksize, subscription_id):
        self.__conn = conn
        self.__chunksize = chunksize
        self.__subscription_id = subscription_id
        self.__ids = []
        self.__reports = []
        self.__esConn = ElasticConn(host_port=(consumer, consumer_port), auth=(es_username, es_password))

    def on_error(self, frame):
        pass
        # Send message to StatsD

    def on_message(self, frame):
        # Send message to StatsD
        # Sanity check
        print(frame)
        msg_id = frame.headers["message-id"]

        if "resubmitted" in frame.headers:
            # Send message to StatsD
            # Ignore resubmitted messages
            return

        try:
            report = jloads(frame.body)
        except Exception:
            # Corrupt message, ignore
            # Send message to StatsD
            self.__conn.ack(msg_id, self.__subscription_id)
            return

        try:
            report["payload"]["created_at"] = report["created_at"]
            report["payload"]["event_type"] = report["event_type"]
            for k, v in report["payload"].items():
                if k.endswith("_at"):
                    if v:
                        report["payload"][k] = v.split(".")[0]
        except Exception:
            pass

        self.__ids.append(msg_id)
        self.__reports.append({"id": msg_id, "body": report})

        if len(self.__reports) >= self.__chunksize:
            self.__send_to_es()

    def __send_to_es(self):
        for msg in self.__reports:
            event_type = str(msg["body"]["event_type"]).lower()
            res = False
            if event_type.startswith("transfer"):
                res = self.__esConn.index_data("rucio_transfer", msg["body"]["payload"])
            elif event_type.startswith("deletion"):
                res = self.__esConn.index_data("rucio_deletion", msg["body"]["payload"])
            else:
                self.__conn.ack(msg["id"], self.__subscription_id)
            if res:
                self.__conn.ack(msg["id"], self.__subscription_id)
        self.__reports = []
        self.__ids = []


if __name__ == "__main__":
    logging.basicConfig(level=0)
    conn = stomp.Connection(host_and_ports=[(broker, broker_port)], reconnect_attempts_max=5)
    if borker_use_ssl:
        conn.set_ssl(key_file=ssl_key_file, cert_file=ssl_cert_file)

    conn.set_listener("", AMQConsumer(conn, chunksize, subscription_id))
    conn.connect(wait=True)
    conn.subscribe(destination=queue, ack="client-individual", id=subscription_id)
    while True:
        sleep(3600)
    conn.disconnect()
