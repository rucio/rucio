# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import json
import logging
import random
import sys

import requests

from rucio.common.config import config_get

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

__HOSTS = [b.strip() for b in config_get('conveyor', 'ftshosts').split(',')]
__CACERT = config_get('conveyor', 'cacert')
__USERCERT = config_get('conveyor', 'usercert')


def __fts_host(source=None, destination=None, method='uniform'):
    """
    Select an FTS3 submission host, optionally based on source and destination URLs.

    :param source: URL of an example source file as a string.
    :param destination: URL of an example destination file as a string.
    :param method: Selection algorithm, one of ['uniform'], as a string.
    :returns: FTS Submission Host as a string.
    """

    if method == 'uniform':
        return random.sample(__HOSTS, 1)[0]
    else:
        return __HOSTS[0]


def submit_transfers(transfers, job_metadata):
    """
    Submit a transfer to FTS3 via JSON.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'filesize', 'md5', 'adler32', 'overwrite', 'job_metadata', 'src_spacetoken', 'dest_spacetoken'
    :param job_metadata: Dictionary containing key/value pairs, for all transfers.
    :returns: List of FTS transfer identifiers
    """

    # Early sanity check
    for transfer in transfers:
        if transfer['src_urls'] is None or transfer['src_urls'] == []:
            raise Exception('No sources defined')

    # FTS3 expects 'davs' as the scheme identifier instead of https
    new_src_urls = []
    new_dst_urls = []
    for transfer in transfers:
        for url in transfer['src_urls']:
            if url.startswith('https'):
                new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_src_urls.append(url)
        for url in transfer['dest_urls']:
            if url.startswith('https'):
                new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_dst_urls.append(url)
    transfer['src_urls'] = new_src_urls
    transfer['dest_urls'] = new_dst_urls

    # Rewrite the checksums into FTS3 format, prefer adler32 if available
    for transfer in transfers:
        if 'md5' in transfer.keys() and transfer['md5'] is not None:
            transfer['checksum'] = 'MD5:%s' % str(transfer['md5'])
        if 'adler32' in transfer.keys() and transfer['adler32'] is not None:
            transfer['checksum'] = 'ADLER32:%s' % str(transfer['adler32'])

    transfer_ids = {}

    job_metadata['issuer'] = 'rucio-transfertool-fts3'

    # we have to loop until we get proper fts3 bulk submission
    for transfer in transfers:

        job_metadata['request_id'] = transfer['request_id']

        params_dict = {'files': [{'sources': transfer['src_urls'],
                                  'destinations': transfer['dest_urls'],
                                  'metadata': {'issuer': 'rucio-transfertool-fts3'},
                                  'filesize': int(transfer['filesize']),
                                  'checksum': str(transfer['checksum'])}],
                       'params': {'verify_checksum': True if transfer['checksum'] is not None else False,
                                  'spacetoken': transfer['dest_spacetoken'] if transfer['dest_spacetoken'] is not None else 'null',
                                  'copy_pin_lifetime': -1,
                                  'job_metadata': job_metadata,
                                  'source_spacetoken': transfer['src_spacetoken'] if transfer['src_spacetoken'] is not None else 'null',
                                  'overwrite': False}}

        r = None
        params_str = json.dumps(params_dict)

        __HOST = __fts_host()
        if __HOST.startswith('https://'):
            r = requests.post('%s/jobs' % __HOST,
                              verify=__CACERT,
                              cert=(__USERCERT, __USERCERT),
                              data=params_str,
                              headers={'Content-Type': 'application/json'})
        else:
            r = requests.post('%s/jobs' % __HOST,
                              data=params_str,
                              headers={'Content-Type': 'application/json'})

        if r is not None and r.status_code == 200:
            transfer_ids[transfer['request_id']] = str(r.json()['job_id'])
        else:
            raise Exception('Could not submit transfer: %s', r.content)

    return transfer_ids


def submit(request_id, src_urls, dest_urls,
           src_spacetoken=None, dest_spacetoken=None,
           filesize=None, md5=None, adler32=None,
           overwrite=False, job_metadata={}):
    """
    Submit a transfer to FTS3 via JSON.

    :param request_id: Request ID of the request as a string.
    :param src_urls: Source URL acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URL acceptable to transfertool as a list of strings.
    :param src_spacetoken: Source spacetoken as a string - ignored for non-spacetoken-aware protocols.
    :param dest_spacetoken: Destination spacetoken as a string - ignored for non-spacetoken-aware protocols.
    :param filesize: Filesize in bytes.
    :param md5: MD5 checksum as a string.
    :param adler32: ADLER32 checksum as a string.
    :param overwrite: Overwrite potentially existing destination, True or False.
    :param job_metadata: Optional job metadata as a dictionary.
    :returns: FTS transfer identifier as string.
    """

    return submit_transfers(transfers={'request_id': request_id,
                                       'src_urls': src_urls,
                                       'dest_urls': dest_urls,
                                       'filesize': filesize,
                                       'md5': md5,
                                       'adler32': adler32,
                                       'overwrite': overwrite,
                                       'src_spacetoken': src_spacetoken,
                                       'dest_spacetoken': dest_spacetoken},
                            job_metadata=job_metadata)[0]


def query(transfer_id):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :returns: Transfer status information as a dictionary.
    """

    r = None

    __HOST = __fts_host()
    if __HOST.startswith('https://'):
        r = requests.get('%s/jobs/%s' % (__HOST, transfer_id),
                         verify=__CACERT,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/jobs/%s' % (__HOST, transfer_id),
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        return None

    raise Exception('Could not retrieve transfer information: %s', r.content)


def cancel(transfer_id):
    """
    Cancel a transfer that has been submitted to FTS via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    """

    pass


def whoami():
    """
    Returns credential information from the FTS3 server.

    :returns: Credentials as stored by the FTS3 server as a dictionary.
    """

    r = None

    __HOST = __fts_host()
    if __HOST.startswith('https://'):
        r = requests.get('%s/whoami' % __HOST,
                         verify=__CACERT,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/whoami' % __HOST,
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json()

    raise Exception('Could not retrieve credentials: %s', r.content)


def version():
    """
    Returns FTS3 server information.

    :returns: FTS3 server information as a dictionary.
    """

    r = None

    __HOST = __fts_host()
    if __HOST.startswith('https://'):
        r = requests.get('%s/' % __HOST,
                         verify=__CACERT,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/' % __HOST,
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json()

    raise Exception('Could not retrieve version: %s', r.content)
