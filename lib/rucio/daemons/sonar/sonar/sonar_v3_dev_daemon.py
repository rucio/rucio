# -*- coding: utf-8 -*-
# Copyright 2017-2020 CERN
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
# - Vitjan Zavrtanik <vitjan.zavrtanik@cern.ch>, 2017
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
Daemon for sending Sonar tests to available RSE's.
"""

from __future__ import division

import itertools
import logging
import random
import threading
import time

from requests import ConnectionError

import rucio.db.sqla.util
from rucio.client.client import Client
from rucio.common.config import config_get
from rucio.common.exception import (AccessDenied, DatabaseException, DuplicateRule, RSEBlacklisted, RSEWriteBlocked,
                                    ReplicationRuleCreationTemporaryFailed, RuleNotFound)
from rucio.common.logging import setup_logging
from rucio.daemons.sonar.sonar.get_current_traffic import get_link_traffic


GRACEFUL_STOP = threading.Event()
DATASET_PREFIX = config_get('sonar', 'dataset_prefix')
SET_SCOPE = config_get('sonar', 'scope')
DATASET_SIZE = config_get('sonar', 'dataset_size')


class SonarTest(object):
    """
    SonarTest class contains functions required
    for running the sonar tests.
    """
    def __init__(self):
        """
        SonarTest class constructor.
        """
        self.client = Client()
        self.endpoint_names = []

        self.rule_times = {}
        self.rule_dict = {}
        self.traffic_weights = {}
        self.traffic_data = {}
        self.get_traffic_data()
        self.get_rule_data()
        self.update_available_site_list()
        self.add_replication_delay()
        self.traffic_weights = self.calculate_weights()

    def add_replication_delay(self):
        """
        Adds a delay to the links that have been tested
        recently to give time for the replicas to be deleted,
        since it usually takes some time for the replica to
        be removed from the RSE.
        """
        for endpoint in self.endpoint_names:
            rep_gen = list(self.client.list_replicas([{'name': DATASET_PREFIX + endpoint + '_SCRATCHDISK', 'scope': SET_SCOPE}]))
            if rep_gen == []:
                continue
            replica_sites = rep_gen[0]['rses'].keys()
            for site in replica_sites:
                site_name = site.split('_SCRATCHDISK')[0]
                if endpoint not in list(self.rule_dict.keys()):
                    self.rule_dict[endpoint] = {}
                if site_name not in list(self.rule_dict[endpoint].keys()):
                    self.rule_dict[endpoint][site_name] = {'rule_id': '', 'state': 'OK', 'created_at': 0, 'delay': time.time()}
                else:
                    self.rule_dict[endpoint][site_name]['delay'] = time.time()

                if endpoint not in list(self.rule_times.keys()):
                    self.rule_times[endpoint] = {}
                if site_name not in list(self.rule_times[endpoint].keys()):
                    self.rule_times[endpoint][site_name] = {'start_times': [], 'end_times': [], 'times_required': []}

    def get_available_sites(self):
        """
        Creates the list of available RSE's.
        """
        tmp_rses = self.client.list_rses()
        total_rses = [x for x in tmp_rses if '_SCRATCHDISK' in x['rse']]
        rse_availability = {}
        for i in total_rses:
            rse_availability[i['rse']] = i['availability']

        rules = self.client.list_account_rules(account='vzavrtan')
        self.endpoint_names = []
        for rule in rules:
            if DATASET_PREFIX in rule['name'] and rule['rse_expression'] in rule['name'] and '.file' not in rule['name']:
                if rse_availability[rule['rse_expression']] == 7 and rule['state'] == 'OK' and rule['locks_ok_cnt'] > 0:
                    self.endpoint_names.append(rule['rse_expression'].split('_SCRATCHDISK')[0])
        self.endpoint_names = list(set(self.endpoint_names))

    def update_available_site_list(self):
        """
        Updates the list of the RSE's where the links
        will be tested. The deciding factor is their
        availability.
        """
        logging.info("Updating the list of available sites.")
        self.get_available_sites()
        self.pairs = [(x, y)
                      for x, y in itertools.product(self.endpoint_names, repeat=2) if x != y]

        for src, dst in self.pairs:
            if src not in list(self.rule_dict.keys()):
                self.rule_dict[src] = {}
                self.traffic_weights[src] = {}
            if dst not in list(self.rule_dict[src].keys()):
                self.rule_dict[src][dst] = {'rule_id': '', 'state': 'OK', 'created_at': 0, 'delay': 0}
                self.traffic_weights[src][dst] = 0

            if src not in list(self.rule_times.keys()):
                self.rule_times[src] = {}
            if dst not in list(self.rule_times[src].keys()):
                self.rule_times[src][dst] = {'start_times': [], 'end_times': [], 'times_required': []}

            if src not in list(self.traffic_data.keys()):
                self.traffic_data[src] = {}
            if dst not in list(self.traffic_data[src].keys()):
                self.traffic_data[src][dst] = 0

    def get_traffic_data(self):
        """
        Reads traffic data.
        """
        tmp_traffic_data = get_link_traffic()
        sites = list(tmp_traffic_data.keys())
        for src in sites:
            if src not in list(self.traffic_data.keys()):
                self.traffic_data[src] = {}
            for dst in list(tmp_traffic_data[src].keys()):
                self.traffic_data[src][dst] = tmp_traffic_data[src][dst]

    def get_rule_data(self):
        """
        Initializes the data at the start of the Sonar thread.
        """
        self.endpoint_names = []
        rules = self.client.list_account_rules(account='vzavrtan')
        for rule in rules:
            if DATASET_PREFIX in rule['name']:
                dst = rule['rse_expression'].split('_SCRATCHDISK')[0]
                src = rule['name'].split(DATASET_PREFIX)[1].split('_SCRATCHDISK')[0]

                if src != dst:
                    if src not in list(self.rule_dict.keys()):
                        self.rule_dict[src] = {}
                        self.traffic_weights[src] = {}

                    if src not in list(self.rule_times.keys()):
                        self.rule_times[src] = {}
                    if dst not in list(self.rule_times[src].keys()):
                        self.rule_times[src][dst] = {'start_times': [], 'end_times': [], 'times_required': []}

                    rule_timestamp = time.mktime(rule['created_at'].timetuple())

                    if rule['state'] == 'REPLICATING':
                        self.rule_dict[src][dst] = {'rule_id': rule['id'],
                                                    'state': rule['state'],
                                                    'created_at': rule_timestamp,
                                                    'delay': 0}
                        self.traffic_weights[src][dst] = 0
                    else:
                        try:
                            self.client.delete_replication_rule(rule['id'], purge_replicas=True)
                            self.client.update_replication_rule(rule['id'], {'lifetime': 1})
                            self.rule_dict[src][dst] = {'rule_id': rule['id'],
                                                        'state': rule['state'],
                                                        'created_at': rule_timestamp,
                                                        'delay': time.time()}
                        except (RuleNotFound, AccessDenied) as exception:
                            err_msg = 'Delete in get_link_data ' + str(exception)
                            logging.warning(err_msg)

    def update_rule_data(self):
        """
        Checks whether the current tests have finished and marks
        the link as available for additional tests.
        """
        logging.info("Updating rule data..")
        counter = 0
        for src, dst in self.pairs:
            rule_l = self.rule_dict[src][dst]

            if rule_l['rule_id'] == '' or rule_l['rule_id'] is None:
                continue

            if rule_l['state'] != 'OK':
                try:
                    rule_r = self.client.get_replication_rule(rule_l['rule_id'])
                except (RuleNotFound, AccessDenied, ConnectionError) as exception:
                    err_msg = 'Get Rule in update_rule_data ' + str(exception)
                    logging.warning(err_msg)
                    self.rule_dict[src][dst]['state'] = 'OK'
                    continue

                if rule_r['state'] == 'STUCK' or rule_r['state'] == 'OK':
                    self.rule_dict[src][dst] = {'state': 'OK', 'delay': time.time(), 'rule_id': '', 'created_at': 0}
                    try:
                        log_msg = 'Deleting rule state: %s, src: %s, dst: %s' % (rule_r['state'], rule_r['name'], rule_r['rse_expression'])
                        logging.info(log_msg)
                        self.client.delete_replication_rule(rule_l['rule_id'], purge_replicas=True)
                        self.client.update_replication_rule(rule_l['rule_id'], {'lifetime': 1})
                        counter += 1
                    except (RuleNotFound, AccessDenied) as exception:
                        err_msg = 'Delete in update_rule_data ' + str(exception)
                        logging.warning(err_msg)

                if rule_r['state'] == 'OK':
                    tmp_state = self.rule_dict[src][dst]['state']
                    self.rule_dict[src][dst]['state'] = 'OK'
                    # Keeps track of the traffic it produces
                    if tmp_state != 'OK':
                        self.traffic_data[src][dst] += DATASET_SIZE

                        start_time = time.mktime(rule_r['created_at'].timetuple())
                        end_time = time.mktime(rule_r['updated_at'].timetuple())
                        time_required = end_time - start_time
                        self.rule_times[src][dst]['start_times'].append(start_time)
                        self.rule_times[src][dst]['end_times'].append(end_time)
                        self.rule_times[src][dst]['times_required'].append(time_required)

        log_msg = 'Deleted %d rules.' % (counter)
        logging.info(log_msg)

    def calculate_weights(self):
        """
        Calculates the weights based on a json file with
        information about the number of bytes transfered
        in the last 24 hours on each link.
        """
        t_weights = self.traffic_weights
        byte_data = [x for y in self.traffic_data.values() for x in y.values()]
        byte_sum = min(5000000000, max(1000000000, sum(byte_data) / (2 * len(byte_data))))
        msg = "Weight threshold is %d bytes" % (byte_sum)
        logging.info(msg)
        weight_sum = 0.0
        counter_zeros = 0
        for src, dst in self.pairs:
            if src in self.traffic_data.keys() and dst in self.traffic_data[src].keys():
                t_weights[src][dst] = max(0, byte_sum - self.traffic_data[src][dst])
                t_weights[src][dst] = t_weights[src][dst]**4
            else:
                t_weights[src][dst] = byte_sum**4
                if src not in list(self.traffic_data.keys()):
                    self.traffic_data[src] = {}
                self.traffic_data[src][dst] = 0
            recently_deleted = (time.time() - self.rule_dict[src][dst]['delay']) < 10800
            if self.rule_dict[src][dst]['state'] != 'OK' or recently_deleted:
                t_weights[src][dst] = 0
            if t_weights[src][dst] == 0:
                counter_zeros += 1
            weight_sum += t_weights[src][dst]

        for src, dst in self.pairs:
            t_weights[src][dst] = t_weights[src][dst] / (weight_sum + 0.00000000001)

        msg = "Calculated weight: zeros/total %d/%d" % (counter_zeros, len(self.pairs))
        logging.info(msg)
        return t_weights

    def sample_link(self):
        """
        Randomly samples the links which are about to be tested
        where the probability of the link being chosen is equal
        to its current weight
        """
        sample = random.random()
        c_sum_weights = 0
        for src, dst in self.pairs:
            c_sum_weights += self.traffic_weights[src][dst]

            if sample < c_sum_weights:
                return src, dst

        return None, None

    def add_sonar_rule(self, did, rse, src_rse):
        """
        Adds the rule to test the link.

        :param did:              the selected did - {name:"", scope:""}
        :param rse:              the selected rse - string
        :param src_rse:          the source RSE of the did - string
        """
        log_msg = "adding rule %s from %s to RSE: %s" % (did['name'], src_rse, rse)
        logging.info(log_msg)
        try:
            rule_id = self.client.add_replication_rule([did], 1, rse,
                                                       lifetime=43200,
                                                       purge_replicas=True,
                                                       source_replica_expression=src_rse,
                                                       activity='Debug')
            return rule_id[0]
        except (DuplicateRule, RSEBlacklisted, RSEWriteBlocked, ReplicationRuleCreationTemporaryFailed) as exception:
            logging.warning(str(exception))
            return None

    def run_iteration(self):
        """
        Selects 50 links to test and adds the appropriate rules
        """
        logging.info("Started iteration")
        counter = 0
        self.traffic_weights = self.calculate_weights()
        account_rules = self.client.list_account_rules(account='vzavrtan')
        add_counter = 0
        failure_counter = 0
        while counter < 50:
            site_src, site_dest = self.sample_link()
            if site_src is None and site_dest is None:
                logging.info("None of the links are available. No additional testing done.")
                break
            log_msg = "Sampled: %s,%s - %f %d" % (site_src,
                                                  site_dest,
                                                  self.traffic_weights[site_src][site_dest],
                                                  self.traffic_data[site_src][site_dest])
            logging.info(log_msg)
            rule_id = self.add_sonar_rule({'name': DATASET_PREFIX + site_src + '_SCRATCHDISK',
                                           'scope': SET_SCOPE},
                                          site_dest + "_SCRATCHDISK",
                                          site_src + "_SCRATCHDISK")
            if rule_id is None:
                logging.info("Adding rule failed.")
                failure_counter += 1
                if failure_counter > 50:
                    break
                for t_rule in account_rules:
                    if DATASET_PREFIX not in t_rule['name']:
                        continue

                    dst = t_rule['rse_expression'].split('_SCRATCHDISK')[0]
                    src = t_rule['name'].split(DATASET_PREFIX)[1].split('_SCRATCHDISK')[0]
                    if src == site_src and dst == site_dest:
                        rule_timestamp = time.mktime(t_rule['created_at'].timetuple())
                        self.rule_dict[site_src][site_dest] = {'rule_id': t_rule['id'],
                                                               'state': t_rule['state'],
                                                               'created_at': rule_timestamp,
                                                               'delay': 0}
                        break
                continue
            add_counter += 1
            self.rule_dict[site_src][site_dest] = {'rule_id': rule_id,
                                                   'state': 'REPLICATING',
                                                   'created_at': time.time(),
                                                   'delay': 0}
            counter += 1
        log_msg = 'Added %d rules.' % (add_counter)
        logging.info(log_msg)
        self.update_rule_data()


def sonar_tests():
    """
    Main loop of the sonar. Every 2.5 minutes sends
    50 test files on sampled links, every 30 seconds
    checks whether the transfer has completed on
    the currently tested links, and every hour
    updates the list of the tested rse by checking
    their availability.
    """
    logging.info("Starting sonar tests.")
    sonar = SonarTest()
    counter = 0
    while not GRACEFUL_STOP.is_set():
        start_time = time.time()
        if counter % 2880 == 0:
            sonar.get_traffic_data()

        if counter % 240 == 0:
            sonar.update_available_site_list()

        if counter % 20 == 0:
            sonar.run_iteration()
        elif counter % 2 == 0:
            sonar.update_rule_data()

        time_elapsed = time.time() - start_time
        msg = "Time elapsed for iteration: %d seconds." % (time_elapsed)
        logging.info(msg)
        if 15 - time_elapsed > 0:
            time.sleep(15 - time_elapsed)
        counter += 1


def run():
    """
    Starts the Sonar thread.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    threads = []
    threads.append(threading.Thread(target=sonar_tests, kwargs={}, name='Sonar_test_v3'))
    for thread in threads:
        thread.start()

    while threads[0].is_alive():
        for thread in threads:
            thread.join(timeout=3.14)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    log_msg = "Stopping Sonar. %s %s %d" % (signum, frame, time.time())
    logging.info(log_msg)
    GRACEFUL_STOP.set()
