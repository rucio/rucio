# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013 - 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2017
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017-2019
# - James Perry, <j.perry@epcc.ed.ac.uk>, 2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White, <bjwhite@fnal.gov>, 2019
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

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


def get_rse_client(rse, vo='def', **kwarg):
    '''
    get_rse_client
    '''
    from rucio.client.rseclient import RSEClient
    client = RSEClient(vo=vo)
    return client.get_rse(rse)


def get_signed_url_client(rse, service, op, url, vo='def'):
    '''
    get_signed_url_client
    '''
    from rucio.client.credentialclient import CredentialClient
    return CredentialClient(vo=vo).get_signed_url(rse, service, op, url)


def get_signed_url_server(rse, service, op, url, vo='def'):
    '''
    get_signed_url_server
    '''
    from rucio.core.rse import get_rse_id
    from rucio.core.credential import get_signed_url

    rse_id = get_rse_id(rse=rse, vo=vo)
    return get_signed_url(rse_id, service, op, url)


def rse_key_generator(namespace, fn, **kwargs):
    '''
    Key generator for RSE
    '''
    def generate_key(rse, vo='def', session=None):
        '''
        generate_key
        '''
        return '{}:{}'.format(rse, vo)
    return generate_key


if rsemanager.CLIENT_MODE:   # pylint:disable=no-member
    setattr(rsemanager, '__request_rse_info', get_rse_client)
    setattr(rsemanager, '__get_signed_url', get_signed_url_client)

    # Preparing region for dogpile.cache
    RSE_REGION = make_region(function_key_generator=rse_key_generator).configure(
        'dogpile.cache.memory',
        expiration_time=3600)
    setattr(rsemanager, 'RSE_REGION', RSE_REGION)


if rsemanager.SERVER_MODE:   # pylint:disable=no-member
    from rucio.core.rse import get_rse_protocols, get_rse_id

    def tmp_rse_info(rse=None, vo='def', rse_id=None, session=None):
        if rse_id is None:
            rse_id = get_rse_id(rse=rse, vo=vo)
        return get_rse_protocols(rse_id=rse_id, session=session)

    setattr(rsemanager, '__request_rse_info', tmp_rse_info)
    setattr(rsemanager, '__get_signed_url', get_signed_url_server)
    RSE_REGION = make_region(function_key_generator=rse_key_generator).configure(
        'dogpile.cache.memcached',
        expiration_time=3600,
        arguments={'url': config.config_get('cache', 'url', False, '127.0.0.1:11211'), 'distributed_lock': True})
    setattr(rsemanager, 'RSE_REGION', RSE_REGION)
