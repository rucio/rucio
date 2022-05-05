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
import requests
import pytest

from rucio.common.config import config_get
from rucio.core.message import add_message, retrieve_messages, truncate_messages
from rucio.daemons.hermes import hermes, hermes2
from rucio.tests.common import rse_name_generator


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'influx,activemq,elastic,email'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_hermes(core_config_mock, caches_mock):
    ''' HERMES (DAEMON): Test the messaging daemon. '''
    truncate_messages()
    for i in range(1, 4):
        add_message('test-type_%i' % i, {'test': i})
        add_message('email', {'to': config_get('messaging-hermes', 'email_test').split(','),
                              'subject': 'Half-Life %i' % i,
                              'body': '''
                              Good morning, and welcome to the Black Mesa Transit System.

                              This automated train is provided for the security and convenience of
                              the Black Mesa Research Facility personnel. The time is eight-forty
                              seven A.M... Current outside temperature is ninety three degrees with
                              an estimated high of one hundred and five. Before exiting the train,
                              be sure to check your area for personal belongings.

                              Thank you, and have a very safe, and productive day.'''})

    hermes.run(once=True, send_email=False)


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'influx,activemq,elastic,email'),
    ('hermes', 'elastic_endpoint', 'http://localhost:9200/ddm_events/doc/_bulk'),
    ('hermes', 'influxdb_endpoint', 'http://localhost:8086/api/v2/write?org=rucio&bucket=rucio'),
    ('hermes', 'influxdb_token', 'mytoken'),
    ('messaging-hermes', 'send_email', False)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_hermes2(core_config_mock, caches_mock):
    ''' HERMES (DAEMON): Test the messaging daemon. '''
    truncate_messages()
    mock_rse = rse_name_generator()
    file_size = 2
    nb_messages = 3

    # Create 3 messages of type blahblah registered to services influx, activemq and elastic
    # Create 3 messages of type email registered to service email
    for i in range(1, 4):
        add_message('blahblah', {'bytes': 2, 'rse': mock_rse, 'created_at': datetime.utcnow()})
        add_message('email', {'to': config_get('messaging-hermes', 'email_test').split(','),
                              'subject': 'Half-Life %i' % i,
                              'body': '''
                              Good morning, and welcome to the Black Mesa Transit System.

                              This automated train is provided for the security and convenience of
                              the Black Mesa Research Facility personnel. The time is eight-forty
                              seven A.M... Current outside temperature is ninety three degrees with
                              an estimated high of one hundred and five. Before exiting the train,
                              be sure to check your area for personal belongings.

                              Thank you, and have a very safe, and productive day.'''})

    messages = retrieve_messages(50, old_mode=False)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    for message in messages:
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 3
    assert service_dict['elastic'] == 3
    assert service_dict['activemq'] == 3
    assert service_dict['email'] == 3

    # Run Hermes2
    # The messages of event_type email should be submitted and removed from the list
    # The messages of event-type blahblah should be removed from the list for service influx since this event-type is not supported by influx
    # The messages of event-type blahblah should be submitted to elastic
    # The messages of event-type blahblah should be submitted to ActiveMQ
    hermes2.hermes2(once=True)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 0
    assert service_dict['elastic'] == 0
    assert service_dict['activemq'] == 3
    assert service_dict['email'] == 0

    # Now add nb_messages more messages of event-type deletion-done associated to services influx and elastic
    for _ in range(nb_messages):
        add_message('deletion-done', {'bytes': file_size, 'rse': mock_rse, 'created_at': datetime.utcnow()})

    messages = retrieve_messages(50, old_mode=False)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    for message in messages:
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 3
    assert service_dict['elastic'] == 3
    assert service_dict['activemq'] == 6
    assert service_dict['email'] == 0

    # Run Hermes2
    hermes2.hermes2(once=True)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        service_dict[message['services']] += 1

    # Checking influxDB
    assert service_dict['influx'] == 0
    res = requests.get('http://localhost:8086/query?db=rucio', headers={'Authorization': 'Token mytoken'}, params={"q": "SELECT * FROM deletion"})
    assert res.status_code == 200
    assert 'results' in res.json()
    influx_res = res.json()['results']
    assert 'series' in influx_res[0]
    columns = influx_res[0]['series'][0]['columns']
    rse_index = columns.index('rse')
    rse_included = False
    for res in influx_res[0]['series'][0]['values']:
        if res[rse_index] == mock_rse:
            rse_included = True
            nb_deletion_done = columns.index('nb_deletion_done')
            bytes_deletion_done = columns.index('bytes_deletion_done')
            assert res[nb_deletion_done] == nb_messages
            assert res[bytes_deletion_done] == nb_messages * file_size
    assert rse_included

    # Checking ElasticSearch
    assert service_dict['elastic'] == 0
    # TODO implement checks in Elastic
    # curl -XPOST "https://localhost:9200/_search" -d '{"query": {"match_all": {}}}'

    # Checking ActiveMQ
    # Disabled for now
    # assert service_dict['activemq'] == 0

    # Checking email
    assert service_dict['email'] == 0
