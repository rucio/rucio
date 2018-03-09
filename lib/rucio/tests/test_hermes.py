#  Copyright European Organization for Nuclear Research (CERN)
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  You may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Authors:
#  - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
#  - Thomas Beermann, <thomas.beermann@cern.ch>, 2017

"""
Hermes Test
"""

from rucio.common.config import config_get
from rucio.core.message import add_message
from rucio.daemons.hermes import hermes


class TestHermes(object):
    ''' Test the messaging deamon. '''

    def test_hermes(self):
        ''' HERMES (DAEMON): Test the messaging daemon. '''
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
