'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Ralph Vigne, <ralph.vigne@cern.ch>, 2013 - 2014
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2017
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
'''

from dogpile.cache import make_region

from rucio.rse import rsemanager
from rucio.common import config


if config.config_has_section('database'):
    setattr(rsemanager, 'CLIENT_MODE', False)
    setattr(rsemanager, 'SERVER_MODE', True)
elif config.config_has_section('client'):
    setattr(rsemanager, 'CLIENT_MODE', True)
    setattr(rsemanager, 'SERVER_MODE', False)
else:
    setattr(rsemanager, 'CLIENT_MODE', False)
    setattr(rsemanager, 'SERVER_MODE', True)


def get_rse_client(rse, **kwarg):
    '''
    get_rse_client
    '''
    from rucio.client.rseclient import RSEClient
    return RSEClient().get_rse(rse)


def rse_key_generator(namespace, fn, **kwargs):
    '''
    Key generator for RSE
    '''
    def generate_key(rse, session=None):
        '''
        generate_key
        '''
        return str(rse)
    return generate_key


if rsemanager.CLIENT_MODE:   # pylint:disable=no-member
    setattr(rsemanager, '__request_rse_info', get_rse_client)
    setattr(rsemanager, '__request_rse_info', get_rse_client)

    # Preparing region for dogpile.cache
    RSE_REGION = make_region(function_key_generator=rse_key_generator).configure(
        'dogpile.cache.memory',
        expiration_time=3600)
    setattr(rsemanager, 'RSE_REGION', RSE_REGION)


if rsemanager.SERVER_MODE:   # pylint:disable=no-member
    from rucio.core.rse import get_rse_protocols
    setattr(rsemanager, '__request_rse_info', get_rse_protocols)
    RSE_REGION = make_region(function_key_generator=rse_key_generator).configure(
        'dogpile.cache.memcached',
        expiration_time=3600,
        arguments={'url': "127.0.0.1:11211", 'distributed_lock': True})
    setattr(rsemanager, 'RSE_REGION', RSE_REGION)
