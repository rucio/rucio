# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import json
import logging
import sys

import requests

from rucio.common.config import config_get

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

__HOST = config_get('conveyor', 'ftshost')  # keep it simple for now
__CACERT = config_get('conveyor', 'cacert')
__USERCERT = config_get('conveyor', 'usercert')


def submit_transfers(transfers, job_metadata):
    """
    Submit a transfer to FTS3 via JSON.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'filesize', 'checksum', 'overwrite', 'job_metadata', 'src_spacetoken, 'dest_spacetoken'
    :param job_metadata: Dictionary containing key/value pairs, for all transfers.
    :returns: List of FTS transfer identifiers
    """

    # Early sanity check
    for transfer in transfers:
        if transfer['src_urls'] is None or transfer['src_urls'] == []:
            raise Exception('No sources defined')

    transfer_ids = {}

    job_metadata['issuer'] = 'rucio-transfertool-fts3'

    # we have to loop until we get proper fts3 bulk submission
    for transfer in transfers:

        transfer_ids[transfer['request_id']] = None

        params_dict = {'files': [{'sources': transfer['src_urls'],
                                  'destinations': transfer['dest_urls'],
                                  'metadata': {'issuer': 'rucio-transfertool-fts3'},
                                  'filesize': int(transfer['filesize']),
                                  'checksum': str(transfer['checksum'])}],
                       'params': {'verify_checksum': True,
                                  'spacetoken': transfer['dest_spacetoken'] if transfer['dest_spacetoken'] is not None else 'no_spacetoken',
                                  'copy_pin_lifetime': -1,
                                  'job_metadata': job_metadata,
                                  'source_spacetoken': transfer['src_spacetoken'] if transfer['src_spacetoken'] is not None else 'no_spacetoken',
                                  'overwrite': False}}

        r = None
        params_str = json.dumps(params_dict)
        logging.debug(params_str)

        if __HOST.startswith('https://'):
            r = requests.post('%s/jobs' % __HOST,
                              verify=__CACERT,
                              cert=__USERCERT,
                              data=params_str,
                              headers={'Content-Type': 'application/json'})
        else:
            r = requests.post('%s/jobs' % __HOST,
                              data=params_str,
                              headers={'Content-Type': 'application/json'})

        if r is not None and r.status_code == 200:
            transfer_ids[transfer['request_id']] = str(r.json['job_id'])
        else:
            raise Exception('Could not submit transfer: %s', r.content)

    return transfer_ids


def submit(src_urls, dest_urls,
           src_spacetoken=None, dest_spacetoken=None,
           filesize=None, checksum=None,
           overwrite=False, job_metadata={}):
    """
    Submit a transfer to FTS3 via JSON.

    :param src_urls: Source URL acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URL acceptable to transfertool as a list of strings.
    :param src_spacetoken: Source spacetoken as a string - ignored for non-spacetoken-aware protocols.
    :param dest_spacetoken: Destination spacetoken as a string - ignored for non-spacetoken-aware protocols.
    :param filesize: Filesize in bytes.
    :param checksum: Checksum as a string.
    :param overwrite: Overwrite potentially existing destination, True or False.
    :param job_metadata: Optional job metadata as a dictionary.
    :returns: FTS transfer identifier as string.
    """

    # Early sanity check
    if src_urls is None or src_urls == []:
        raise Exception('No sources defined')

    job_metadata['issuer'] = 'rucio-transfertool-fts3'

    params_dict = {'files': [{'sources': src_urls,
                              'destinations': dest_urls,
                              'metadata': {'issuer': 'rucio-transfertool-fts3'},
                              'filesize': str(filesize),
                              'checksum': str(checksum)}],
                   'params': {'verify_checksum': True,
                              'spacetoken': dest_spacetoken if dest_spacetoken is not None else 'no_spacetoken',
                              'copy_pin_lifetime': -1,
                              'job_metadata': job_metadata,
                              'source_spacetoken': src_spacetoken if src_spacetoken is not None else 'no_spacetoken',
                              'overwrite': False}}

    r = None
    params_str = json.dumps(params_dict)
    logging.debug(params_str)

    if __HOST.startswith('https://'):
        r = requests.post('%s/jobs' % __HOST,
                          verify=__CACERT,
                          cert=__USERCERT,
                          data=params_str,
                          headers={'Content-Type': 'application/json'})
    else:
        r = requests.post('%s/jobs' % __HOST,
                          data=params_str,
                          headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return str(r.json['job_id'])
    else:
        raise Exception('Could not submit transfer: %s', r.content)


def query(transfer_id):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :returns: Transfer status information as a dictionary.
    """

    r = None

    if __HOST.startswith('https://'):
        r = requests.get('%s/jobs/%s' % (__HOST, transfer_id),
                         verify=__CACERT,
                         cert=__USERCERT,
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/jobs/%s' % (__HOST, transfer_id),
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json
    elif r.status_code == 404:
        return None
    else:
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

    if __HOST.startswith('https://'):
        r = requests.get('%s/whoami' % __HOST,
                         verify=__CACERT,
                         cert=__USERCERT,
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/whoami' % __HOST,
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json
    else:
        raise Exception('Could not retrieve credentials: %s', r.content)


def version():
    """
    Returns FTS3 server information.

    :returns: FTS3 server information as a dictionary.
    """

    r = None

    if __HOST.startswith('https://'):
        r = requests.get('%s/' % __HOST,
                         verify=__CACERT,
                         cert=__USERCERT,
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/' % __HOST,
                         headers={'Content-Type': 'application/json'})

    if r is not None and r.status_code == 200:
        return r.json
    else:
        raise Exception('Could not retrieve version: %s', r.content)
