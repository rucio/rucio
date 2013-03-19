# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

'''
  Callback core method to add msg in the queue.
  The notifier daemon in charge of submitting the msgs to a notification service, e.g., ActiveMQ, runs on the db.
'''

from rucio.common.exception import InvalidObject
from rucio.common.utils import render_json
from rucio.db.models import Callback
from rucio.db.session import transactional_session


@transactional_session
def add_callback(event_type, payload, session=None):
    """
    Add an message in the message queues.

    :param event_type: The type of the event, e.g., NEW_DID.
    :param payload: The message payload in JSON.
    :param session: The database session in use.
    """
    try:
        new_callback = Callback(event_type=event_type, payload=render_json(**payload))
    except TypeError, e:  # NOQA
        raise InvalidObject('Invalid JSON for payload: %(e)s' % locals())

    new_callback.save(session=session)

    return new_callback.id
