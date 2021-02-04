# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Dilaksun Bavarajan <dilaksun.bavarajan@cern.ch>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

"""
Conveyor FTS Throttler is a daemon that will configure a fts storage's transfer settings
depending on how many time out errors occur at the storage. If a storage has substantial amount
of transer failures due to time outs, it is usually due to bad connectivity and the amount of failures can be
alleviated by limiting the transfer settings of FTS transfers on the particular fts storage.
"""
from __future__ import division

import datetime
import json
import logging
import os
import socket
import threading
import time
import traceback

import requests

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.logging import setup_logging
from rucio.core import heartbeat
from rucio.transfertool.fts3 import FTS3Transfertool

graceful_stop = threading.Event()


class FTSThrottler(object):

    def __init__(self, cycle_interval=3600):
        self.__cycle_interval = cycle_interval

    def tune(self):
        """
        tune the configuration settings
        """
        result = self.request_timeout_data()
        if result is not None:

            try:
                cycle_file = config_get('conveyor', 'fts_throttler_cycle')
            except Exception:
                logging.warning('could not get the cycle file, cannot perform tuning for this cycle without cycle file, returning')
                return

            try:
                tuning_ratio = config_get('conveyor', 'fts_throttler_tuning_ratio')
            except Exception:
                logging.warning('could not get the tuning ratio from config, returning')
                return

            rses = result['aggregations']['rse']['buckets']
            cycle_info_dict = {'storages': []}
            for rse in rses:
                # if a rse has a failure ratio above the tuning ratio (percentage) we tune it.
                if rse['failure_ratio'].get('value') > int(tuning_ratio):

                    # rse_info holds the storage name(0) and FTS-host server(1)
                    rse_info = rse['key'].split()

                    # Tapes might have other reasons for timeouts which should be treated differently, therefor they are ignored and not tuned for now.
                    if rse['storage_type']['hits']['hits'][0]['_source']['payload']['dst-type'] == 'TAPE':
                        logging.info('%s is a tape storage type, it will not be tuned', rse_info[0])
                        continue
                    # instantiate transfertool for access to get_se_config and set_se_config.
                    t = FTS3Transfertool(rse_info[1])

                    # extract FTS storage from dst-url
                    tmp = rse['destination']['hits']['hits'][0]['_source']['payload']['dst-url'].split(':', 2)
                    url = tmp[0] + ':' + tmp[1]

                    n = rse['failure_ratio'].get('value')

                    logging.info(' RSE ' + rse_info[0] + ' on FTS host ' + rse_info[1]
                                 + ' has failure ratio ' + str(rse['failure_ratio'].get('value')) + ' on storage ' + url)  # NOQA: W503

                    try:
                        se = t.get_se_config(url)
                        logging.info('storage settings: %s', se)
                    except KeyError:
                        logging.warning('configuration for storage element was not found, config will be set from default values')
                        # all FTS Host servers have a default reference storage named '*' that holds the default values for all storages that arent listed yet.
                        default_storage = t.get_se_config('*')
                        t.set_se_config(url, inbound_max_active=int((100 / (100 + n)) * default_storage['se_info']['inbound_max_active']),
                                        outbound_max_active=int((100 / (100 + n)) * default_storage['se_info']['outbound_max_active']))

                        logging.info(url + 'inbound_max_active changed from ' + str(default_storage['se_info']['inbound_max_active']) + ' to ' + str(int((100 / (100 + n)) * default_storage['se_info']['inbound_max_active']))
                                     + ', outbound_max_active changed from ' + str(default_storage['se_info']['outbound_max_active']) + ' to ' + str(int((100 / (100 + n)) * default_storage['se_info']['outbound_max_active'])))  # NOQA: W503

                        # cycle_info_dict is used to write changes down to the cycle file.
                        cycle_info_dict['storages'].append({'storage': url, 'inbound_max_active': default_storage['se_info']['inbound_max_active'],
                                                            'outbound_max_active': default_storage['se_info']['outbound_max_active'], 'failure_ratio': n,
                                                            'tuned_inbound_max_active': int((100 / (100 + n)) * default_storage['se_info']['inbound_max_active']),
                                                            'tuned_outbound_max_active': int((100 / (100 + n)) * default_storage['se_info']['outbound_max_active']),
                                                            'fts-host': rse_info[1], 'time': str(datetime.datetime.now())})
                        continue
                    except Exception as error:
                        logging.warning('an error occured when trying to get the storage configuration')
                        logging.warning(str(error))
                        continue

                    # Even though we could read the config, we still need to know if the important attributes are empty.
                    if se['se_info']['inbound_max_active'] is None:
                        try:
                            default_storage = t.get_se_config('*')
                        except Exception:
                            raise Exception('Could not retrieve the default storage information')
                        ima = default_storage['se_info']['inbound_max_active']
                    else:
                        ima = se['se_info']['inbound_max_active']

                    if se['se_info']['outbound_max_active'] is None:
                        try:
                            default_storage = t.get_se_config('*')
                        except Exception:
                            raise Exception('Could not retrieve the default storage information')
                        oma = default_storage['se_info']['outbound_max_active']
                    else:
                        oma = se['se_info']['outbound_max_active']

                    # append existing information to dict and write to file.
                    cycle_info_dict['storages'].append({'storage': url, 'inbound_max_active': ima, 'outbound_max_active': oma, 'failure_ratio': n,
                                                        'tuned_inbound_max_active': int((100 / (100 + n)) * ima), 'tuned_outbound_max_active': int((100 / (100 + n)) * oma),
                                                        'fts-host': rse_info[1], 'time': str(datetime.datetime.now())})

                    # tune down the configuration of a storage relative to the failure ratio(n) and existing configuration.
                    t.set_se_config(url, inbound_max_active=int((100 / (100 + n)) * ima), outbound_max_active=int((100 / (100 + n)) * oma))

                    logging.info(url + 'inbound_max_active changed from ' + str(ima) + ' to ' + str(int((100 / (100 + n)) * ima))
                                 + ', outbound_max_active changed from ' + str(oma) + ' to ' + str(int((100 / (100 + n)) * oma)))  # NOQA: W503

            if cycle_info_dict['storages'] == []:
                logging.info('no storages are failing significantly due to timeout errors, therefor no tuning happened.')

            with open(cycle_file, 'w') as outfile:
                json.dump(cycle_info_dict, outfile)
        else:
            logging.warning('Could not detect any storages with sufficient failure ratio for tuning, trying again next cycle')
        return

    def revert(self):
        """
        Reverts the changes from previous tuning, this is to avoid recursively tuning with no reference point,
        the manually configured attributes or the default attributes will stay as the reference point
        Before each cycle, all tunings will be reverted to the original reference point.
        :returns: bool indicating if revert was successful or not.
        """
        try:
            cycle_file = config_get('conveyor', 'fts_throttler_cycle')
        except Exception:
            logging.warning('could not get the cycle file, cannot revert cycle changes, therefor no tuning either')
            return False

        with open(cycle_file) as cycle_info:
            cycle_info_dict = json.load(cycle_info)
            storages = cycle_info_dict['storages']
            for storage in storages:
                t = FTS3Transfertool(storage['fts-host'])
                logging.info('storage information: %s', storage)
                t.set_se_config(storage['storage'], inbound_max_active=storage['inbound_max_active'], outbound_max_active=storage['outbound_max_active'])
                logging.info('on storage ' + storage['storage'] + ' outbound_max_active reverted from '
                             + str(storage['tuned_outbound_max_active']) + ' to ' + str(storage['outbound_max_active'])  # NOQA: W503
                             + ', inbound_max_active reverted from ' + str(storage['tuned_inbound_max_active']) + ' to ' + str(storage['inbound_max_active']))  # NOQA: W503
            logging.info('revert performed')
        return True

    def request_timeout_data(self, destination=True, last_hours=1, transfer_successes_lower_boundary=20, transfer_timeouts_lower_boundary=20, kserver='http://atlas-kibana.mwt2.org:9200/rucio-events-*/_search'):
        """
        requests timeout data using elastic search
        :returns: JSON result of the elastic search query.
        :param destination: bool that decides whether to query for source rse's(false) or destination rse's(true)
        :param last_hours: integer to choose how many hours back we want to query from
        :param transfer_successes_lower_boundary: integer for the lower boundary for transfers succeeded on a rse.
        :param transfer_timeouts_lower_boundary: integer for the lower boundary of timeout events that happened on a rse.
        """

        params_dict = {
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            '@timestamp': {
                                'gte': 'now-' + str(last_hours) + 'h',
                                'lte': 'now',
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            },
            'size': 0,
            'aggs': {
                'rse': {
                    'terms': {
                    },
                    'aggs': {
                        'destination': {
                            'top_hits': {
                                '_source': {
                                },
                                'size': 1
                            }
                        },
                        'storage_type': {
                            'top_hits': {
                                '_source': {
                                },
                                'size': 1
                            }
                        },
                        'transfers_failed_timeout': {
                            'filter': {
                                'bool': {
                                    'should': [
                                        # this is the list of the errors so far that are taken into consideration for the ratio calculation, add more if needed.
                                        {'match': {'payload.reason': {'query': 'TRANSFER [110] TRANSFER Operation timed out', 'operator': 'and'}}},
                                        {'match': {'payload.reason': {'query': ('TRANSFER [110] TRANSFER Transfer canceled because the gsiftp performance marker '
                                                                                'timeout of 360 seconds has been exceeded, or all performance '
                                                                                'markers during that period indicated zero bytes transferred'), 'operator': 'and'}}},
                                        {'match': {'payload.reason': {'query': ('SOURCE [70] globus_ftp_client: the server responded with an error 421 Service busy:'
                                                                                ' Connection limit exceeded. Please try again later. Closing control connection.'), 'operator': 'and'}}},
                                    ],
                                    'minimum_should_match': 1
                                }
                            }
                        },
                        'timeout_bucket_filter': {
                            'bucket_selector': {
                                'buckets_path': {
                                    'timeoutCount': 'transfers_failed_timeout>_count'
                                },
                                'script': 'params.timeoutCount > ' + str(transfer_timeouts_lower_boundary)
                            }
                        },
                        'transfers_succeeded': {
                            'filter': {
                                'bool': {
                                    'must': [
                                        {'term': {'type': 'transfer-done'}}
                                    ]
                                }
                            }
                        },
                        'success_bucket_filter': {
                            'bucket_selector': {
                                'buckets_path': {
                                    'transferSuccessCount': 'transfers_succeeded>_count'
                                },
                                'script': 'params.transferSuccessCount > ' + str(transfer_successes_lower_boundary)
                            }
                        },
                        'failure_ratio': {
                            'bucket_script': {
                                'buckets_path': {
                                    'transfersFailedTimeout': 'transfers_failed_timeout>_count',
                                    'transfersSucceeded': 'transfers_succeeded>_count'
                                },
                                'script': 'params.transfersFailedTimeout / params.transfersSucceeded * 100'
                            }
                        }
                    }
                }
            }
        }

        # if destination is true, we request data for destination RSE's, else we request source RSE's
        if destination:
            params_dict['aggs']['rse']['terms'] = {'script': """(doc['payload.dst-rse'].empty ? '' : doc['payload.dst-rse'].value) + ' ' + (doc['payload.transfer-endpoint'].empty ? '' : doc['payload.transfer-endpoint'].value)""",
                                                   'size': 1000}
            params_dict['aggs']['rse']['aggs']['destination']['top_hits']['_source'] = {'include': ['payload.dst-url']}
            params_dict['aggs']['rse']['aggs']['storage_type']['top_hits']['_source'] = {'include': ['payload.dst-type']}
        else:
            params_dict['aggs']['rse']['terms'] = {'script': """(doc['payload.src-rse'].empty ? '' : doc['payload.src-rse'].value) + ' ' + (doc['payload.transfer-endpoint'].empty ? '' : doc['payload.transfer-endpoint'].value)""",
                                                   'size': 1000}
            params_dict['aggs']['rse']['aggs']['destination']['top_hits']['_source'] = {'include': ['payload.src-url']}
            params_dict['aggs']['rse']['aggs']['storage_type']['top_hits']['_source'] = {'include': ['payload.src-type']}

        params_str = json.dumps(params_dict)
        try:
            result = requests.get(kserver,
                                  data=params_str,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=None)

        except Exception:
            logging.warning('could not retrieve transfer failure data from %s - %s', kserver, str(traceback.format_exc()))
        if result and result.status_code == 200:
            return result.json()
        raise Exception('could not get result from %s, status code returned : %s', kserver, result.status_code if result else None)

    def testread(self, tuning_ratio=25):
        """
        Read the failure ratio of storages without tuning
        :returns: filtered JSON response from Elastic search.
        :param tuning_ratio: integer lower bound for what failing storages you want to read.
        """
        result = self.request_timeout_data()
        if result is not None:

            rses = result['aggregations']['rse']['buckets']
            for rse in rses:
                # if a rse has a failure ratio above the tuning ratio we read it.
                if rse['failure_ratio'].get('value') > tuning_ratio:

                    # rse_info holds the storage name(0) and FTS-host server(1)
                    rse_info = rse['key'].split()
                    t = FTS3Transfertool(rse_info[1])

                    # extract FTS storage from dst-url
                    tmp = rse['destination']['hits']['hits'][0]['_source']['payload']['dst-url'].split(':', 2)
                    url = tmp[0] + ':' + tmp[1]
                    logging.info('\033[91m RSE \033[0m' + rse_info[0] + '\033[91m on FTS host \033[0m' + rse_info[1] + '\033[91m has failure ratio \033[0m' + str(rse['failure_ratio'].get('value')) + '\033[91m on storage \033[0m' + url)

                    try:
                        se = t.get_se_config(url)
                        logging.info('storage settings: %s', se)
                    except KeyError:
                        logging.warning('configuration for storage element was not found')
                    except Exception as error:
                        logging.warning('an error occured when trying to get the storage configuration')
                        logging.warning(str(error))
                        continue

            return rses
        else:
            logging.warning('Could not retrieve timeout data with elastic search, trying again next cycle')


def fts_throttler(once=False, cycle_interval=3600):
    """
    Main loop to automatically configure FTS storages.
    """
    graceful_stop.clear()
    logging.info('FTS Throttler starting')

    executable = 'conveyor-fts-throttler'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    current_time = time.time()
    graceful_stop.wait(10)
    running_instance = False

    while not graceful_stop.is_set():
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
        if heart_beat['nr_threads'] < 2:
            running_instance = True
            # this loop cannot be entered by more than one instance at a time.
            while not graceful_stop.is_set():

                try:
                    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
                    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])

                    logging.info(prepend_str + "fts_throttler start cycle")
                    if FTSThrottler().revert():
                        logging.info('revert was successful, now tuning')
                        FTSThrottler().tune()
                        logging.info('Tuning finished for this cycle')
                    else:
                        logging.warning('could not revert, cannot tune unless revert has been done, will try again next cycle.')

                    if once:
                        break
                    if time.time() < current_time + cycle_interval:
                        graceful_stop.wait(int((current_time + cycle_interval) - time.time()))
                    current_time = time.time()
                except Exception:
                    logging.critical(prepend_str + 'fts_throttler crashed %s' % (traceback.format_exc()))

                if once:
                    break
        else:
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            logging.info(prepend_str + 'another fts_throttler instance already exists. will wait')
            if time.time() < current_time + cycle_interval:
                graceful_stop.wait(int((current_time + cycle_interval) - time.time()))
            current_time = time.time()

    logging.info(prepend_str + 'Throttler - graceful stop requested')

    # before we stop, try to revert, but only if this instance was running the cycles.
    # ! If the cycle info file information is shared between instances, then this implementation must be changed !
    if running_instance:
        try:
            FTSThrottler().revert()
        except Exception:
            logging.warning('could not revert changes before stopping')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info(prepend_str + 'Throttler - graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, cycle_interval=3600):
    """
    Starts up the conveyer fts throttler thread.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting throttler thread')
    fts_throttler_thread = threading.Thread(target=fts_throttler, kwargs={'once': once, 'cycle_interval': cycle_interval})

    fts_throttler_thread.start()

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    fts_throttler_thread.join(timeout=3.14)
