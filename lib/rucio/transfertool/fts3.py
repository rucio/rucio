# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2014
# - Wen Guan, <wen.guan@cern.ch>, 2014

import datetime
import json
import logging
import sys
import urlparse

import requests

from rucio.common.config import config_get
from rucio.core.monitor import record_counter
from rucio.db.constants import FTSState


logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

__CACERT = config_get('conveyor', 'cacert')
__USERCERT = config_get('conveyor', 'usercert')


def __extract_host(transfer_host):
    # graphite does not like the dots in the FQDN
    return urlparse.urlparse(transfer_host).hostname.replace('.', '_')


def submit_transfers(transfers, job_metadata, transfer_host):
    """
    Submit a transfer to FTS3 via JSON.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'filesize', 'md5', 'adler32', 'overwrite', 'job_metadata', 'src_spacetoken', 'dest_spacetoken'
    :param job_metadata: Dictionary containing key/value pairs, for all transfers.
    :param transfer_host: FTS server as a string.
    :returns: List of FTS transfer identifiers
    """

    # Early sanity check
    for transfer in transfers:
        if not transfer['src_urls'] or transfer['src_urls'] == []:
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
        transfer['checksum'] = None
        if 'md5' in transfer.keys() and transfer['md5']:
            transfer['checksum'] = 'MD5:%s' % str(transfer['md5'])
        if 'adler32' in transfer.keys() and transfer['adler32']:
            transfer['checksum'] = 'ADLER32:%s' % str(transfer['adler32'])

    transfer_ids = {}

    job_metadata['issuer'] = 'rucio'
    job_metadata['previous_attempt_id'] = None

    # we have to loop until we get proper fts3 bulk submission
    for transfer in transfers:

        job_metadata['request_id'] = transfer['request_id']

        if 'previous_attempt_id' in transfer.keys():
            job_metadata['previous_attempt_id'] = transfer['previous_attempt_id']

        params_dict = {'files': [{'sources': transfer['src_urls'],
                                  'destinations': transfer['dest_urls'],
                                  'metadata': {'issuer': 'rucio'},
                                  'filesize': int(transfer['filesize']),
                                  'checksum': str(transfer['checksum']),
                                  'activity': str(transfer['activity'])}],
                       'params': {'verify_checksum': True if transfer['checksum'] else False,
                                  'spacetoken': transfer['dest_spacetoken'] if transfer['dest_spacetoken'] else 'null',
                                  'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                                  'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                                  'job_metadata': job_metadata,
                                  'source_spacetoken': transfer['src_spacetoken'] if transfer['src_spacetoken'] else None,
                                  'overwrite': transfer['overwrite']}}

        r = None
        params_str = json.dumps(params_dict)

        if transfer_host.startswith('https://'):
            r = requests.post('%s/jobs' % transfer_host,
                              verify=False,
                              cert=(__USERCERT, __USERCERT),
                              data=params_str,
                              headers={'Content-Type': 'application/json'})
        else:
            r = requests.post('%s/jobs' % transfer_host,
                              data=params_str,
                              headers={'Content-Type': 'application/json'})

        if r and r.status_code == 200:
            record_counter('transfertool.fts3.%s.submission.success' % __extract_host(transfer_host))
            transfer_ids[transfer['request_id']] = {'external_id': str(r.json()['job_id']),
                                                    'dest_urls': transfer['dest_urls']}
        else:
            record_counter('transfertool.fts3.%s.submission.failure' % __extract_host(transfer_host))
            raise Exception('Could not submit transfer: %s', r.content)

    return transfer_ids


def submit(request_id, src_urls, dest_urls,
           src_spacetoken=None, dest_spacetoken=None,
           filesize=None, md5=None, adler32=None,
           overwrite=True, job_metadata={}):
    """
    Submit a transfer to FTS3 via JSON.

    :param request_id: Request ID of the request as a string.
    :param src_urls: Source URLs acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URLs acceptable to transfertool as a list of strings.
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


def query(transfer_id, transfer_host):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    job = None

    if transfer_host.startswith('https://'):
        job = requests.get('%s/jobs/%s' % (transfer_host, transfer_id),
                           verify=False,
                           cert=(__USERCERT, __USERCERT),
                           headers={'Content-Type': 'application/json'})
    else:
        job = requests.get('%s/jobs/%s' % (transfer_host, transfer_id),
                           headers={'Content-Type': 'application/json'})
    if job and job.status_code == 200:
        record_counter('transfertool.fts3.%s.query.success' % __extract_host(transfer_host))
        return job.json()

    record_counter('transfertool.fts3.%s.query.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve transfer information: %s', job.content)


def query_details(transfer_id, transfer_host):
    """
    Query the detailed status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    :returns: Detailed transfer status information as a dictionary.
    """

    files = None

    if transfer_host.startswith('https://'):
        files = requests.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                             verify=False,
                             cert=(__USERCERT, __USERCERT),
                             headers={'Content-Type': 'application/json'})
    else:
        files = requests.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                             headers={'Content-Type': 'application/json'})
    if files and files.status_code == 200:
        record_counter('transfertool.fts3.%s.query_details.success' % __extract_host(transfer_host))
        return files.json()

    record_counter('transfertool.fts3.%s.query_details.failure' % __extract_host(transfer_host))
    return


def format_response(transfer_host, fts_job_response, fts_files_response):
    """
    Format the response format of FTS3 query.

    :param fts_job_response: FTSs job query response.
    :param fts_files_response: FTS3 files query response.
    :returns: formatted response.
    """
    last_src_file = 0
    for i in range(len(fts_files_response)):
        if fts_files_response[i]['file_state'] != 'NOT_USED':
            last_src_file = i

    # for multiple sources, if not only the first source is used, we need to mark job_m_replica,
    # then conveyor.common.add_monitor_message will correct the src_rse
    job_m_replica = 'false'
    if last_src_file > 0:
        job_m_replica = 'true'

    response = {'new_state': None,
                'transfer_id': fts_job_response.get('job_id'),
                'job_state': fts_job_response.get('job_state', None),
                'src_url': fts_files_response[last_src_file].get('source_surl', None),
                'dst_url': fts_files_response[last_src_file].get('dest_surl', None),
                'duration': (datetime.datetime.strptime(fts_files_response[last_src_file]['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                             datetime.datetime.strptime(fts_files_response[last_src_file]['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds,
                'reason': fts_files_response[last_src_file].get('reason', None),
                'scope': fts_job_response['job_metadata'].get('scope', None),
                'name': fts_job_response['job_metadata'].get('name', None),
                'src_rse': fts_job_response['job_metadata'].get('src_rse', None),
                'dst_rse': fts_job_response['job_metadata'].get('dst_rse', None),
                'request_id': fts_job_response['job_metadata'].get('request_id', None),
                'activity': fts_job_response['job_metadata'].get('activity', None),
                'dest_rse_id': fts_job_response['job_metadata'].get('dest_rse_id', None),
                'previous_attempt_id': fts_job_response['job_metadata'].get('previous_attempt_id', None),
                'adler32': fts_job_response['job_metadata'].get('adler32', None),
                'md5': fts_job_response['job_metadata'].get('md5', None),
                'filesize': fts_job_response['job_metadata'].get('filesize', None),
                'external_host': transfer_host.split("//")[1].split(":")[0],
                'job_m_replica': job_m_replica,
                'details': {'files': fts_job_response['job_metadata']}}
    return response


def bulk_query(transfer_ids, transfer_host):
    """
    Query the status of a bulk of transfers in FTS3 via JSON.

    :param transfer_ids: FTS transfer identifiers as a list.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    job = None

    responses = {}
    if transfer_host.startswith('https://'):
        fts_session = requests.Session()
        for transfer_id in transfer_ids:
            job = fts_session.get('%s/jobs/%s' % (transfer_host, transfer_id),
                                  verify=False,
                                  cert=(__USERCERT, __USERCERT),
                                  headers={'Content-Type': 'application/json'})
            if not job:
                record_counter('transfertool.fts3.%s.bulk_establish.failure' % __extract_host(transfer_host))
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % job)
            elif job.status_code == 200:
                record_counter('transfertool.fts3.%s.bulk_establish.success' % __extract_host(transfer_host))
                job_response = job.json()
                if not job_response['job_state'] in (str(FTSState.FAILED),
                                                     str(FTSState.FINISHEDDIRTY),
                                                     str(FTSState.CANCELED),
                                                     str(FTSState.FINISHED)):
                    responses[transfer_id] = {}
                    responses[transfer_id]['job_state'] = job_response['job_state']
                    responses[transfer_id]['new_state'] = None
                    responses[transfer_id]['transfer_id'] = transfer_id
                else:
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            verify=False,
                                            cert=(__USERCERT, __USERCERT),
                                            headers={'Content-Type': 'application/json'})
                    if files and files.status_code == 200:
                        record_counter('transfertool.fts3.%s.bulk_query.success' % __extract_host(transfer_host))
                        responses[transfer_id] = format_response(transfer_host, job_response, files.json())
                    else:
                        record_counter('transfertool.fts3.%s.bulk_query.failure' % __extract_host(transfer_host))
                        responses[transfer_id] = Exception('Could not retrieve files information: %s', files)

            elif "No job with the id" in job.text:
                responses[transfer_id] = None
            else:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s', job.content)
    else:
        fts_session = requests.Session()
        for transfer_id in transfer_ids:
            job = fts_session.get('%s/jobs/%s' % (transfer_host, transfer_id),
                                  headers={'Content-Type': 'application/json'})
            if not job:
                record_counter('transfertool.fts3.%s.bulk_establish.failure' % __extract_host(transfer_host))
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % job)
            elif job.status_code == 200:
                record_counter('transfertool.fts3.%s.bulk_establish.success' % __extract_host(transfer_host))
                job_response = job.json()
                if not job_response['job_state'] in (str(FTSState.FAILED),
                                                     str(FTSState.FINISHEDDIRTY),
                                                     str(FTSState.CANCELED),
                                                     str(FTSState.FINISHED)):
                    responses[transfer_id] = {}
                    responses[transfer_id]['job_state'] = job_response['job_state']
                    responses[transfer_id]['new_state'] = None
                    responses[transfer_id]['transfer_id'] = transfer_id
                else:
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            headers={'Content-Type': 'application/json'})
                    if files and files.status_code == 200:
                        record_counter('transfertool.fts3.%s.bulk_query.success' % __extract_host(transfer_host))
                        responses[transfer_id] = format_response(transfer_host, job_response, files.json())
                    else:
                        record_counter('transfertool.fts3.%s.bulk_query.failure' % __extract_host(transfer_host))
                        responses[transfer_id] = Exception('Could not retrieve files information: %s', files)

            elif "No job with the id" in job.text:
                record_counter('transfertool.fts3.%s.bulk_establish.failure' % __extract_host(transfer_host))
                responses[transfer_id] = None
            else:
                record_counter('transfertool.fts3.%s.bulk_establish.failure' % __extract_host(transfer_host))
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s', job.content)

    return responses


def get_jobs_response(transfer_host, fts_session, jobs_response):
    """
    Parse FTS bulk query response and query details for finished jobs.

    :param transfer_host: FTS server as a string.
    :fts_session: query request as a session.
    :jobs_response: FTS bulk query response as a dict.
    :returns: Transfer status information as a dictionary.
    """

    responses = {}
    for job_response in jobs_response:
        transfer_id = job_response['job_id']
        if job_response['http_status'] == "404 Not Found":
            responses[transfer_id] = None
        elif job_response['http_status'] == "200 Ok":
            if not job_response['job_state'] in (str(FTSState.FAILED),
                                                 str(FTSState.FINISHEDDIRTY),
                                                 str(FTSState.CANCELED),
                                                 str(FTSState.FINISHED)):
                responses[transfer_id] = {}
                responses[transfer_id]['job_state'] = job_response['job_state']
                responses[transfer_id]['new_state'] = None
                responses[transfer_id]['transfer_id'] = transfer_id
            else:
                if transfer_host.startswith("https"):
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            verify=False,
                                            cert=(__USERCERT, __USERCERT),
                                            headers={'Content-Type': 'application/json'})
                else:
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            headers={'Content-Type': 'application/json'})
                if files and files.status_code == 200:
                    record_counter('transfertool.fts3.%s.jobs_response.success' % __extract_host(transfer_host))
                    responses[transfer_id] = format_response(transfer_host, job_response, files.json())
                else:
                    record_counter('transfertool.fts3.%s.jobs_response.failure' % __extract_host(transfer_host))
                    responses[transfer_id] = Exception('Could not retrieve files information: %s', files)
    return responses


def new_bulk_query(transfer_ids, transfer_host):
    """
    Query the status of a bulk of transfers in FTS3 via JSON.

    :param transfer_ids: FTS transfer identifiers as a list.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    responses = {}
    if transfer_host.startswith('https://'):
        fts_session = requests.Session()
        jobs = fts_session.get('%s/jobs/%s' % (transfer_host, ','.join(transfer_ids)),
                               verify=False,
                               cert=(__USERCERT, __USERCERT),
                               headers={'Content-Type': 'application/json'})
        if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
            record_counter('transfertool.fts3.%s.new_bulk.success' % __extract_host(transfer_host))
            jobs_response = jobs.json()
            responses = get_jobs_response(transfer_host, fts_session, jobs_response)
            for transfer_id in transfer_ids:
                if transfer_id not in responses.keys():
                    responses[transfer_id] = None
        else:
            record_counter('transfertool.fts3.%s.new_bulk.failure' % __extract_host(transfer_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % jobs)
    else:
        fts_session = requests.Session()
        jobs = fts_session.get('%s/jobs/%s' % (transfer_host, transfer_id),
                               headers={'Content-Type': 'application/json'})
        if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
            record_counter('transfertool.fts3.%s.new_bulk.success' % __extract_host(transfer_host))
            jobs_response = jobs.json()
            responses = get_jobs_response(transfer_host, fts_session, jobs_response)
            for transfer_id in transfer_ids:
                if transfer_id not in responses.keys():
                    responses[transfer_id] = None
        else:
            record_counter('transfertool.fts3.%s.new_bulk.failure' % __extract_host(transfer_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % jobs)

    return responses


def cancel(transfer_id, transfer_host):
    """
    Cancel a transfer that has been submitted to FTS via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    """

    job = None

    if transfer_host.startswith('https://'):
        job = requests.delete('%s/jobs/%s' % (transfer_host, transfer_id),
                              verify=False,
                              cert=(__USERCERT, __USERCERT),
                              headers={'Content-Type': 'application/json'})
    else:
        job = requests.delete('%s/jobs/%s' % (transfer_host, transfer_id),
                              headers={'Content-Type': 'application/json'})
    if job and job.status_code == 200:
        record_counter('transfertool.fts3.%s.cancel.success' % __extract_host(transfer_host))
        return job.json()

    record_counter('transfertool.fts3.%s.cancel.failure' % __extract_host(transfer_host))
    raise Exception('Could not cancel transfer: %s', job.content)


def whoami(transfer_host):
    """
    Returns credential information from the FTS3 server.

    :param transfer_host: FTS server as a string.

    :returns: Credentials as stored by the FTS3 server as a dictionary.
    """

    r = None

    if transfer_host.startswith('https://'):
        r = requests.get('%s/whoami' % transfer_host,
                         verify=False,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/whoami' % transfer_host,
                         headers={'Content-Type': 'application/json'})

    if r and r.status_code == 200:
        record_counter('transfertool.fts3.%s.whoami.success' % __extract_host(transfer_host))
        return r.json()

    record_counter('transfertool.fts3.%s.whoami.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve credentials: %s', r.content)


def version(transfer_host):
    """
    Returns FTS3 server information.

    :param transfer_host: FTS server as a string.

    :returns: FTS3 server information as a dictionary.
    """

    r = None

    if transfer_host.startswith('https://'):
        r = requests.get('%s/' % transfer_host,
                         verify=False,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/' % transfer_host,
                         headers={'Content-Type': 'application/json'})

    if r and r.status_code == 200:
        record_counter('transfertool.fts3.%s.version.success' % __extract_host(transfer_host))
        return r.json()

    record_counter('transfertool.fts3.%s.version.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve version: %s', r.content)
