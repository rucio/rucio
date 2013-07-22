# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import json
import requests

from rucio.common.config import config_get

__HOST = config_get('conveyor', 'ftshost')  # keep it simple for now


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

    job_metadata['issuer'] = 'rucio-transfertool-fts3'

    params_dict = {'files': [{'sources': src_urls,
                              'destinations': dest_urls,
                              'metadata': {'issuer': 'rucio-transfertool-fts3'},
                              'filesize': str(filesize),
                              'checksum': str(checksum)}],
                   'params': {'verify_checksum': 'true',
                              'job_metadata': job_metadata,
                              'spacetoken': dest_spacetoken if dest_spacetoken is not None else 'None',
                              'source_spacetoken': src_spacetoken if src_spacetoken is not None else 'None'}}

    # only " is valid in JSON
    params_str = str(params_dict).replace("'", '"')

    # are we still legal JSON?
    try:
        json.loads(params_str)
    except Exception, e:
        raise Exception('Could not build valid JSON: %s' % str(e))

    r = requests.post('%s/jobs' % __HOST,
                      data=params_str,
                      headers={'Content-Type': 'application/json'})

    if r.status_code == 200:
        return r.json['job_id']
    else:
        raise Exception('Could not submit transfer: %s', r.content)


def query(transfer_id):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :returns: Transfer status information as a dictionary.
    """

    r = requests.get('%s/jobs/%s' % (__HOST, transfer_id),
                     headers={'Content-Type': 'application/json'})

    if r.status_code == 200:
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

    r = requests.get('%s/whoami' % __HOST,
                     headers={'Content-Type': 'application/json'})

    if r.status_code == 200:
        return r.json
    else:
        raise Exception('Could not retrieve credentials: %s', r.content)


def version():
    """
    Returns FTS3 server information.

    :returns: FTS3 server information as a dictionary.
    """

    r = requests.get('%s/whoami' % __HOST,
                     headers={'Content-Type': 'application/json'})

    if r.status_code == 200:
        return r.json
    else:
        raise Exception('Could not retrieve version: %s', r.content)
