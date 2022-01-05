# -*- coding: utf-8 -*-
# Copyright CERN since 2015
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
import pytest

from rucio.common.config import config_get
from rucio.core.message import add_message, retrieve_messages, truncate_messages
from rucio.daemons.hermes import hermes, hermes2


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
    ('hermes', 'influxdb_endpoint', 'http://localhost:9200/ddm_events/doc/_bulk'),
    ('messaging-hermes', 'send_email', False)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_hermes2(core_config_mock, caches_mock):
    ''' HERMES (DAEMON): Test the messaging daemon. '''
    truncate_messages()

    # Create 3 messages of type blahblah registered to services influx, activemq and elastic
    # Create 3 messages of type email registered to service email
    for i in range(1, 4):
        add_message('blahblah', {'bytes': 2, 'rse': 'MOCK', 'created_at': datetime.utcnow()})
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
        print(message)
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 3
    assert service_dict['elastic'] == 3
    assert service_dict['activemq'] == 3
    assert service_dict['email'] == 3

    # Run Hermes2
    # The messages of event_type email should be submitted and removed from the list
    # The messages of event-type blahblah should be removed from the list for service influx since this event-type is not supported by influx
    # The messages of event-type blahblah should be not be removed from the list for service elastic since elastic service is not working
    # The messages of event-type blahblah should be not be removed from the list for service activemq since activemq service is not working
    hermes2.hermes2(once=True)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        print(message)
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 0
    assert service_dict['elastic'] == 3
    assert service_dict['activemq'] == 3
    assert service_dict['email'] == 0

    # Now add 3 more messages of event-type deletion-done associated to services influx and elastic
    for _ in range(1, 4):
        add_message('deletion-done', {'bytes': 2, 'rse': 'MOCK', 'created_at': datetime.utcnow()})

    messages = retrieve_messages(50, old_mode=False)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    for message in messages:
        print(message)
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 3
    assert service_dict['elastic'] == 6
    assert service_dict['activemq'] == 6
    assert service_dict['email'] == 0

    # Run Hermes2
    # The messages should be not be removed from the list for service elastic, activemq and influx since none of these services are working
    hermes2.hermes2(once=True)
    service_dict = {'influx': 0, 'elastic': 0, 'email': 0, 'activemq': 0}
    messages = retrieve_messages(50, old_mode=False)
    for message in messages:
        print(message)
        service_dict[message['services']] += 1
    assert service_dict['influx'] == 3
    assert service_dict['elastic'] == 6
    assert service_dict['activemq'] == 6
    assert service_dict['email'] == 0
