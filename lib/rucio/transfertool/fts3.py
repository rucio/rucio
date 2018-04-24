# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2018
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016
# - Martin Barisits, <martin.barisits@cern.ch>, 2017-2018
# - Eric Vaandering, <ewv@fnal.gov>, 2018

import datetime
import json
import logging
import sys
import time
import urlparse
import uuid
import traceback

import requests
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common.config import config_get, config_get_bool
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla.constants import FTSState
from rucio.transfertool.transfertool import Transfertool

logging.getLogger("requests").setLevel(logging.CRITICAL)
disable_warnings()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

USERCERT = config_get('conveyor', 'usercert', False, None)
USE_DETERMINISTIC_ID = config_get_bool('conveyor', 'use_deterministic_id', False, False)

REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=1800)


class FTS3Transfertool(Transfertool):
    """
    FTS3 implementation of a Rucio transfertool
    """

    def __init__(self, external_host):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """

        super(FTS3Transfertool, self).__init__(external_host)
        if self.external_host.startswith('https://'):
            self.cert = (USERCERT, USERCERT)
            self.verify = False
        else:
            self.cert = None
            self.verify = True  # True is the default setting of a requests.* method

    # Public methods part of the common interface

    def submit(self, files, job_params, timeout=None):
        """
        Submit transfers to FTS3 via JSON.

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            FTS transfer identifier.
        """

        # FTS3 expects 'davs' as the scheme identifier instead of https
        for transfer_file in files:
            if not transfer_file['sources'] or transfer_file['sources'] == []:
                raise Exception('No sources defined')

            new_src_urls = []
            new_dst_urls = []
            for url in transfer_file['sources']:
                if url.startswith('https'):
                    new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                else:
                    new_src_urls.append(url)
            for url in transfer_file['destinations']:
                if url.startswith('https'):
                    new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                else:
                    new_dst_urls.append(url)

            transfer_file['sources'] = new_src_urls
            transfer_file['destinations'] = new_dst_urls

        transfer_id = None
        expected_transfer_id = None
        if USE_DETERMINISTIC_ID:
            job_params = job_params.copy()
            job_params["id_generator"] = "deterministic"
            job_params["sid"] = files[0]['metadata']['request_id']
            expected_transfer_id = self.__get_deterministic_id(job_params["sid"])
            logging.debug("Submit bulk transfers in deterministic mode, sid %s, expected transfer id: %s", job_params["sid"], expected_transfer_id)

        # bulk submission
        params_dict = {'files': files, 'params': job_params}
        params_str = json.dumps(params_dict)

        post_result = None
        try:
            start_time = time.time()
            post_result = requests.post('%s/jobs' % self.external_host,
                                        verify=self.verify,
                                        cert=self.cert,
                                        data=params_str,
                                        headers={'Content-Type': 'application/json'},
                                        timeout=timeout)
            record_timer('transfertool.fts3.submit_transfer.%s' % self.__extract_host(self.external_host), (time.time() - start_time) * 1000 / len(files))
        except:
            logging.warn('Could not submit transfer to %s - %s', self.external_host, str(traceback.format_exc()))

        if post_result and post_result.status_code == 200:
            record_counter('transfertool.fts3.%s.submission.success' % self.__extract_host(self.external_host), len(files))
            transfer_id = str(post_result.json()['job_id'])
        else:
            if expected_transfer_id:
                transfer_id = expected_transfer_id
                logging.warn("Failed to submit transfer to %s, will use expected transfer id %s, error: %s", self.external_host, transfer_id, post_result.text if post_result is not None else post_result)
            else:
                logging.warn("Failed to submit transfer to %s, error: %s", self.external_host, post_result.text if post_result is not None else post_result)
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))

        return transfer_id

    def cancel(self, transfer_ids, timeout=None):
        """
        Cancel transfers that have been submitted to FTS3.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param timeout:      Timeout in seconds.
        :returns:            True if cancellation was successful.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('Bulk cancelling not implemented')
        transfer_id = transfer_ids[0]

        job = None

        job = requests.delete('%s/jobs/%s' % (self.external_host, transfer_id),
                              verify=self.verify,
                              cert=self.cert,
                              headers={'Content-Type': 'application/json'},
                              timeout=timeout)

        if job and job.status_code == 200:
            record_counter('transfertool.fts3.%s.cancel.success' % self.__extract_host(self.external_host))
            return job.json()

        record_counter('transfertool.fts3.%s.cancel.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not cancel transfer: %s', job.content)

    def update_priority(self, transfer_id, priority, timeout=None):
        """
        Update the priority of a transfer that has been submitted to FTS via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :param priority:    FTS job priority as an integer from 1 to 5.
        :param timeout:     Timeout in seconds.
        :returns:           True if update was successful.
        """

        job = None
        params_dict = {"params": {"priority": priority}}
        params_str = json.dumps(params_dict)

        job = requests.post('%s/jobs/%s' % (self.external_host, transfer_id),
                            verify=self.verify,
                            data=params_str,
                            cert=self.cert,
                            headers={'Content-Type': 'application/json'},
                            timeout=timeout)  # TODO set to 3 in conveyor

        if job and job.status_code == 200:
            record_counter('transfertool.fts3.%s.update_priority.success' % self.__extract_host(self.external_host))
            return job.json()

        record_counter('transfertool.fts3.%s.update_priority.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not update priority of transfer: %s', job.content)

    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of a transfer in FTS3 via JSON.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as a list of dictionaries.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('FTS3 transfertool query not bulk ready')

        transfer_id = transfer_ids[0]
        if details:
            return self.__query_details(transfer_id=transfer_id)

        job = None

        job = requests.get('%s/jobs/%s' % (self.external_host, transfer_id),
                           verify=self.verify,
                           cert=self.cert,
                           headers={'Content-Type': 'application/json'},
                           timeout=timeout)  # TODO Set to 5 in conveyor
        if job and job.status_code == 200:
            record_counter('transfertool.fts3.%s.query.success' % self.__extract_host(self.external_host))
            return [job.json()]

        record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not retrieve transfer information: %s', job.content)

    # Public methods, not part of the common interface specification (FTS3 specific)

    def whoami(self):
        """
        Returns credential information from the FTS3 server.

        :returns: Credentials as stored by the FTS3 server as a dictionary.
        """

        get_result = None

        get_result = requests.get('%s/whoami' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers={'Content-Type': 'application/json'})

        if get_result and get_result.status_code == 200:
            record_counter('transfertool.fts3.%s.whoami.success' % self.__extract_host(self.external_host))
            return get_result.json()

        record_counter('transfertool.fts3.%s.whoami.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not retrieve credentials: %s', get_result.content)

    def version(self):
        """
        Returns FTS3 server information.

        :returns: FTS3 server information as a dictionary.
        """

        get_result = None

        get_result = requests.get('%s/' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers={'Content-Type': 'application/json'})

        if get_result and get_result.status_code == 200:
            record_counter('transfertool.fts3.%s.version.success' % self.__extract_host(self.external_host))
            return get_result.json()

        record_counter('transfertool.fts3.%s.version.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not retrieve version: %s', get_result.content)

    def query_latest(self, state, last_nhours=1):
        """
        Query the latest status transfers status in FTS3 via JSON.

        :param state: Transfer state as a string or a dictionary.
        :returns: Transfer status information as a dictionary.
        """

        jobs = None

        try:
            whoami = requests.get('%s/whoami' % (self.external_host),
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers={'Content-Type': 'application/json'})
            if whoami and whoami.status_code == 200:
                delegation_id = whoami.json()['delegation_id']
            else:
                raise Exception('Could not retrieve delegation id: %s', whoami.content)
            state_string = ','.join(state)
            jobs = requests.get('%s/jobs?dlg_id=%s&state_in=%s&time_window=%s' % (self.external_host,
                                                                                  delegation_id,
                                                                                  state_string,
                                                                                  last_nhours),
                                verify=self.verify,
                                cert=self.cert,
                                headers={'Content-Type': 'application/json'})
        except Exception:
            logging.warn('Could not query latest terminal states from %s', self.external_host)

        if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
            record_counter('transfertool.fts3.%s.query_latest.success' % self.__extract_host(self.external_host))
            try:
                jobs_json = jobs.json()
                return jobs_json
            except:
                logging.error("Failed to parse the jobs status %s", str(traceback.format_exc()))

        record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))

    def bulk_query(self, transfer_ids, timeout=None):
        """
        Query the status of a bulk of transfers in FTS3 via JSON.

        :param transfer_ids: FTS transfer identifiers as a list.
        :returns: Transfer status information as a dictionary.
        """

        jobs = None

        if type(transfer_ids) is not list:
            transfer_ids = [transfer_ids]

        responses = {}
        fts_session = requests.Session()
        xfer_ids = ','.join(transfer_ids)
        jobs = fts_session.get('%s/jobs/%s?files=file_state,dest_surl,finish_time,start_time,reason,source_surl,file_metadata' % (self.external_host, xfer_ids),
                               verify=self.verify,
                               cert=self.cert,
                               headers={'Content-Type': 'application/json'},
                               timeout=timeout)

        if jobs is None:
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Transfer information returns None: %s' % jobs)
        elif jobs.status_code == 200 or jobs.status_code == 207:
            try:
                record_counter('transfertool.fts3.%s.bulk_query.success' % self.__extract_host(self.external_host))
                jobs_response = jobs.json()
                responses = self.__bulk_query_responses(jobs_response)
            except Exception as error:
                raise Exception("Failed to parse the job response: %s, error: %s" % (str(jobs), str(error)))
        else:
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s', jobs.content)

        return responses

    # Private methods unique to the FTS3 Transfertool

    @staticmethod
    def __extract_host(external_host):
        # graphite does not like the dots in the FQDN
        return urlparse.urlparse(external_host).hostname.replace('.', '_')

    def __get_transfer_baseid_voname(self):
        """
        Get transfer VO name from the external host.

        :returns base id as a string and VO name as a string.
        """
        result = (None, None)
        try:
            key = 'voname: %s' % self.external_host
            result = REGION_SHORT.get(key)
            if type(result) is NoValue:
                logging.debug("Refresh transfer baseid and voname for %s", self.external_host)

                get_result = None
                try:
                    get_result = requests.get('%s/whoami' % self.external_host,
                                              verify=self.verify,
                                              cert=self.cert,
                                              headers={'Content-Type': 'application/json'},
                                              timeout=5)
                except:
                    logging.warn('Could not get baseid and voname from %s - %s', self.external_host, str(traceback.format_exc()))

                if get_result and get_result.status_code == 200:
                    baseid = str(get_result.json()['base_id'])
                    voname = str(get_result.json()['vos'][0])
                    result = (baseid, voname)

                    REGION_SHORT.set(key, result)

                    logging.debug("Get baseid %s and voname %s from %s", baseid, voname, self.external_host)
                else:
                    logging.warn("Failed to get baseid and voname from %s, error: %s", self.external_host, get_result.text if get_result is not None else get_result)
                    result = (None, None)
        except:
            logging.warning("Failed to get baseid and voname from %s: %s", self.external_host, traceback.format_exc())
            result = (None, None)
        return result

    def __get_deterministic_id(self, sid):
        """
        Get deterministic FTS job id.

        :param sid: FTS seed id.
        :returns: FTS transfer identifier.
        """
        baseid, voname = self.__get_transfer_baseid_voname()
        if baseid is None or voname is None:
            return None
        root = uuid.UUID(baseid)
        atlas = uuid.uuid5(root, voname)
        jobid = uuid.uuid5(atlas, sid)
        return str(jobid)

    def __format_response(self, fts_job_response, fts_files_response):
        """
        Format the response format of FTS3 query.

        :param fts_job_response: FTSs job query response.
        :param fts_files_response: FTS3 files query response.
        :returns: formatted response.
        """
        last_src_file = 0
        for i in range(len(fts_files_response)):
            if fts_files_response[i]['file_state'] in [str(FTSState.FINISHED)]:
                last_src_file = i
                break
            if fts_files_response[i]['file_state'] != 'NOT_USED':
                last_src_file = i

        # for multiple sources, if not only the first source is used, we need to mark job_m_replica,
        # then conveyor.common.add_monitor_message will correct the src_rse
        job_m_replica = 'false'
        if last_src_file > 0:
            job_m_replica = 'true'

        if fts_files_response[last_src_file]['start_time'] is None or fts_files_response[last_src_file]['finish_time'] is None:
            duration = 0
        else:
            duration = (datetime.datetime.strptime(fts_files_response[last_src_file]['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                        datetime.datetime.strptime(fts_files_response[last_src_file]['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds

        response = {'new_state': None,
                    'transfer_id': fts_job_response.get('job_id'),
                    'job_state': fts_job_response.get('job_state', None),
                    'file_state': fts_files_response[last_src_file].get('file_state', None),
                    'src_url': fts_files_response[last_src_file].get('source_surl', None),
                    'dst_url': fts_files_response[last_src_file].get('dest_surl', None),
                    'started_at': datetime.datetime.strptime(fts_files_response[last_src_file]['start_time'], '%Y-%m-%dT%H:%M:%S') if fts_files_response[last_src_file]['start_time'] else None,
                    'transferred_at': datetime.datetime.strptime(fts_files_response[last_src_file]['finish_time'], '%Y-%m-%dT%H:%M:%S') if fts_files_response[last_src_file]['finish_time'] else None,
                    'duration': duration,
                    'reason': fts_files_response[last_src_file].get('reason', None),
                    'scope': fts_job_response['job_metadata'].get('scope', None),
                    'name': fts_job_response['job_metadata'].get('name', None),
                    'src_rse': fts_job_response['job_metadata'].get('src_rse', None),
                    'dst_rse': fts_job_response['job_metadata'].get('dst_rse', None),
                    'request_id': fts_job_response['job_metadata'].get('request_id', None),
                    'activity': fts_job_response['job_metadata'].get('activity', None),
                    'src_rse_id': fts_job_response['file_metadata'].get('src_rse_id', None),
                    'dest_rse_id': fts_job_response['job_metadata'].get('dest_rse_id', None),
                    'previous_attempt_id': fts_job_response['job_metadata'].get('previous_attempt_id', None),
                    'adler32': fts_job_response['job_metadata'].get('adler32', None),
                    'md5': fts_job_response['job_metadata'].get('md5', None),
                    'filesize': fts_job_response['job_metadata'].get('filesize', None),
                    'external_host': self.external_host,
                    'job_m_replica': job_m_replica,
                    'details': {'files': fts_job_response['job_metadata']}}
        return response

    def __format_new_response(self, fts_job_response, fts_files_response):
        """
        Format the response format of FTS3 query.

        :param fts_job_response: FTSs job query response.
        :param fts_files_response: FTS3 files query response.
        :returns: formatted response.
        """

        resps = {}
        if 'request_id' in fts_job_response['job_metadata']:
            # submitted by old submitter
            request_id = fts_job_response['job_metadata']['request_id']
            resps[request_id] = self.__format_response(fts_job_response, fts_files_response)
        else:
            multi_sources = fts_job_response['job_metadata'].get('multi_sources', False)
            for file_resp in fts_files_response:
                # for multiple source replicas jobs, the file_metadata(request_id) will be the same.
                # The next used file will overwrite the current used one. Only the last used file will return.
                if file_resp['file_state'] == 'NOT_USED':
                    continue

                # not terminated job
                if file_resp['file_state'] not in [str(FTSState.FAILED),
                                                   str(FTSState.FINISHEDDIRTY),
                                                   str(FTSState.CANCELED),
                                                   str(FTSState.FINISHED)]:
                    continue

                if file_resp['start_time'] is None or file_resp['finish_time'] is None:
                    duration = 0
                else:
                    duration = (datetime.datetime.strptime(file_resp['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                                datetime.datetime.strptime(file_resp['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds

                request_id = file_resp['file_metadata']['request_id']
                resps[request_id] = {'new_state': None,
                                     'transfer_id': fts_job_response.get('job_id'),
                                     'job_state': fts_job_response.get('job_state', None),
                                     'file_state': file_resp.get('file_state', None),
                                     'src_url': file_resp.get('source_surl', None),
                                     'dst_url': file_resp.get('dest_surl', None),
                                     'started_at': datetime.datetime.strptime(file_resp['start_time'], '%Y-%m-%dT%H:%M:%S') if file_resp['start_time'] else None,
                                     'transferred_at': datetime.datetime.strptime(file_resp['finish_time'], '%Y-%m-%dT%H:%M:%S') if file_resp['finish_time'] else None,
                                     'duration': duration,
                                     'reason': file_resp.get('reason', None),
                                     'scope': file_resp['file_metadata'].get('scope', None),
                                     'name': file_resp['file_metadata'].get('name', None),
                                     'src_type': file_resp['file_metadata'].get('src_type', None),
                                     'dst_type': file_resp['file_metadata'].get('dst_type', None),
                                     'src_rse': file_resp['file_metadata'].get('src_rse', None),
                                     'dst_rse': file_resp['file_metadata'].get('dst_rse', None),
                                     'request_id': file_resp['file_metadata'].get('request_id', None),
                                     'activity': file_resp['file_metadata'].get('activity', None),
                                     'src_rse_id': file_resp['file_metadata'].get('src_rse_id', None),
                                     'dest_rse_id': file_resp['file_metadata'].get('dest_rse_id', None),
                                     'previous_attempt_id': file_resp['file_metadata'].get('previous_attempt_id', None),
                                     'adler32': file_resp['file_metadata'].get('adler32', None),
                                     'md5': file_resp['file_metadata'].get('md5', None),
                                     'filesize': file_resp['file_metadata'].get('filesize', None),
                                     'external_host': self.external_host,
                                     'job_m_replica': multi_sources,
                                     'details': {'files': file_resp['file_metadata']}}

                # multiple source replicas jobs and we found the successful one, it's the final state.
                if multi_sources and file_resp['file_state'] in [str(FTSState.FINISHED)]:
                    break
        return resps

    def __bulk_query_responses(self, jobs_response):
        if type(jobs_response) is not list:
            jobs_response = [jobs_response]

        responses = {}
        for job_response in jobs_response:
            transfer_id = job_response['job_id']
            if job_response['http_status'] == '200 Ok':
                files_response = job_response['files']
                multi_sources = job_response['job_metadata'].get('multi_sources', False)
                if multi_sources and job_response['job_state'] not in [str(FTSState.FAILED),
                                                                       str(FTSState.FINISHEDDIRTY),
                                                                       str(FTSState.CANCELED),
                                                                       str(FTSState.FINISHED)]:
                    # multipe source replicas jobs is still running. should wait
                    responses[transfer_id] = {}
                    continue

                resps = self.__format_new_response(job_response, files_response)
                responses[transfer_id] = resps
            elif job_response['http_status'] == '404 Not Found':
                # Lost transfer
                responses[transfer_id] = None
            else:
                responses[transfer_id] = Exception('Could not retrieve transfer information(http_status: %s, http_message: %s)' % (job_response['http_status'],
                                                                                                                                   job_response['http_message'] if 'http_message' in job_response else None))
        return responses

    def __query_details(self, transfer_id):
        """
        Query the detailed status of a transfer in FTS3 via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :returns: Detailed transfer status information as a dictionary.
        """

        files = None

        files = requests.get('%s/jobs/%s/files' % (self.external_host, transfer_id),
                             verify=self.verify,
                             cert=self.cert,
                             headers={'Content-Type': 'application/json'},
                             timeout=5)
        if files and (files.status_code == 200 or files.status_code == 207):
            record_counter('transfertool.fts3.%s.query_details.success' % self.__extract_host(self.external_host))
            return files.json()

        record_counter('transfertool.fts3.%s.query_details.failure' % self.__extract_host(self.external_host))
        return
