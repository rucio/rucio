# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015

"""
Conveyor coordinator is a daemon to manage channel ranks, suspend requests.
"""

import json
import logging
import os
import socket
import sys
import threading
import time
import traceback
import urllib2

from rucio.common.config import config_get
from rucio.core import heartbeat, distance as distance_core, rse as rse_core, request as request_core
from rucio.db.sqla.constants import RSEType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def get_agis_sitenames():
    try:
        logging.info("Getting AGIS sitenames")
        url = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json'
        result = {}
        u = urllib2.urlopen(url)
        content = u.read()
        rses = json.loads(content)
        for item in rses:
            rse = item['name']
            sitename = item['site'].upper()
            result[rse] = sitename
        return result
    except:
        raise Exception("Failed to load rse-sitename data from url=%s, error: %s" % (url, traceback.format_exc()))


def get_agis_distances():
    try:
        logging.info("Getting AGIS distances")
        top_distance = 0
        url = 'http://atlas-agis-api.cern.ch/request/site/query/list_links/?json'
        result = {}
        u = urllib2.urlopen(url)
        content = u.read()
        site_list = json.loads(content)
        for item in site_list:
            if 'src' in item and 'dst' in item and 'closeness' in item:
                dst = item['dst'].upper()
                src = item['src'].upper()
                if src not in result:
                    result[src] = {}
                result[src][dst] = item['closeness']

                # fix transfer inside the same site
                result[src][src] = 0
                if dst not in result:
                    result[dst] = {}
                result[dst][dst] = 0

                if item['closeness'] > top_distance:
                    top_distance = item['closeness']
        return top_distance, result
    except:
        raise Exception("Failed to load distance data from url=%s, error: %s" % (url, traceback.format_exc()))


def get_downtime_list():
    try:
        logging.info("Getting downtimes")
        unavailable_read_rses = rse_core.list_rses(filters={'availability_read': False})
        unavailable_read_rse_ids = [r['id'] for r in unavailable_read_rses]
        return unavailable_read_rse_ids
    except:
        raise Exception("Failed to get unavailable read rses, error: %s" % (traceback.format_exc()))


def get_rse_distances():
    try:
        logging.info("Getting Rucio RSEs distances")
        rows = distance_core.get_distances()
        distances = {}
        for row in rows:
            src_rse_id = row['src_rse_id']
            dest_rse_id = row['dest_rse_id']
            if src_rse_id not in distances:
                distances[src_rse_id] = {}
            distances[src_rse_id][dest_rse_id] = {'distance': row['agis_distance'], 'ranking': row['ranking']}
        return distances
    except:
        raise Exception("Failed to get old rse distances, error: %s" % (traceback.format_exc()))


def get_rses(sitenames):
    try:
        logging.info("Getting Rucio RSEs")
        rses = rse_core.list_rses()
        result = []
        for rse in rses:
            if rse['deleted'] or rse['staging_area']:
                continue
            if rse['rse'] not in sitenames:
                logging.warning("Cannot find site name for rse %s, skip" % rse['rse'])
                continue
            result.append(rse)
        return result
    except:
        raise Exception("Failed to get rses, error: %s" % (traceback.format_exc()))


def get_heavy_load_rses(threshold=5000):
    try:
        loads = request_core.get_heavy_load_rses(threshold=threshold)
        result = {}
        for load in loads:
            result[load['rse_id']] = load['load']
            logging.debug("Found heavy load RSE %s load %s" % (load['rse_id'], load['load']))
        return result
    except:
        raise Exception("Failed to get heavy load rses, error: %s" % (traceback.format_exc()))


def renew_rse_distance(threshold=5000):
    try:
        logging.info("Renew RSEs distances with threshold %s" % threshold)
        sitenames = get_agis_sitenames()
        top_distance, agis_distances = get_agis_distances()
        downtime_list = get_downtime_list()
        old_distances = get_rse_distances()
        rses = get_rses(sitenames)
        heavy_load_rses = get_heavy_load_rses(threshold=threshold)

        top_rank = top_distance + 2
        for src_rse in rses:
            src_sitename = sitenames[src_rse['rse']]
            src_rse_id = src_rse['id']

            for dest_rse in rses:
                dest_sitename = sitenames[dest_rse['rse']]
                dest_rse_id = dest_rse['id']

                # minus distance is bad link
                if src_sitename in agis_distances and dest_sitename in agis_distances[src_sitename]:
                    if agis_distances[src_sitename][dest_sitename] > -1:
                        distance = agis_distances[src_sitename][dest_sitename]
                    else:
                        distance = None
                else:
                    # for site which is not in agis distance
                    distance = top_distance

                if src_rse_id in downtime_list:
                    ranking = None
                else:
                    if distance is None:
                        ranking = None
                    else:
                        ranking = top_rank - distance
                        if src_rse['rse_type'] == RSEType.TAPE:
                            ranking = 1
                        if src_rse_id in heavy_load_rses.keys():
                            ranking -= heavy_load_rses[src_rse_id] / threshold
                            logging.debug("RSE %s load %s is too heavy, decrease its ranking to %s" % (src_rse_id, heavy_load_rses[src_rse_id], ranking))

                if src_rse_id in old_distances and dest_rse_id in old_distances[src_rse_id]:
                    if old_distances[src_rse_id][dest_rse_id]['distance'] != distance or old_distances[src_rse_id][dest_rse_id]['ranking'] != ranking:
                        logging.info('Update src: %s, dest: %s, old_distance: %s, new_distance:%s, old_rank: %s, new_rank:%s' % (src_rse_id,
                                                                                                                                 dest_rse_id,
                                                                                                                                 old_distances[src_rse_id][dest_rse_id]['distance'],
                                                                                                                                 distance,
                                                                                                                                 old_distances[src_rse_id][dest_rse_id]['ranking'],
                                                                                                                                 ranking))
                        distance_core.update_distances(src_rse_id=src_rse_id, dest_rse_id=dest_rse_id, ranking=ranking, agis_distance=distance)
                else:
                    logging.info("Add src: %s, dest: %s, distance: %s, ranking: %s" % (src_rse_id, dest_rse_id, distance, ranking))
                    distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dest_rse_id, ranking=ranking, agis_distance=distance)
    except:
        logging.warning("Failed to renew rse distances, error: %s" % (traceback.format_exc()))


def check_requests(threshold=5000):
    try:
        logging.info("Check requests with threshold %s" % threshold)
        # todo, waiting request state to be extended
    except:
        logging.warning("Failed to check requests, error: %s" % (traceback.format_exc()))


def coordinator(once=False, process=0, total_processes=1, thread=0, total_threads=1, threshold_per_rse=5000, renew_period=1800):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('Coordinator starting - process (%i/%i) thread (%i)' % (process,
                                                                         total_processes,
                                                                         total_threads))

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('Coordinator started - process (%i/%i) thread (%i/%i)' % (process, total_processes,
                                                                           hb['assign_thread'], hb['nr_threads']))

    next_distance_renew_time = time.time()
    while not graceful_stop.is_set():

        try:
            if next_distance_renew_time > time.time():
                time.sleep(1)
                continue

            hb = heartbeat.live(executable, hostname, pid, hb_thread)
            logging.info('Coordinator - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))

            # if there are too many transfers from one RSE, renew_rse_distance will decrease the RSE's rank.
            # if there are too many transfers to one RSE, check_requests will suspend requests(will also resume requests).
            renew_rse_distance(threshold_per_rse)
            check_requests(threshold_per_rse)

            logging.debug("Sleep to wait next renew period")
            next_distance_renew_time = time.time() + renew_period
        except:
            logging.critical('%s:%s %s' % (process, hb['assign_thread'], traceback.format_exc()))

        if once:
            return

    logging.info('%s:%s graceful stop requested' % (process, hb['assign_thread']))

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('%s:%s graceful stop done' % (process, hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, threshold_per_rse=5000, renew_period=1800):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one coordinator iteration only')
        coordinator(once, threshold_per_rse=threshold_per_rse, renew_period=renew_period)

    else:
        logging.info('starting coordinator threads')
        threads = [threading.Thread(target=coordinator, kwargs={'process': process,
                                                                'total_processes': total_processes,
                                                                'thread': i,
                                                                'total_threads': total_threads,
                                                                'renew_period': renew_period,
                                                                'threshold_per_rse': threshold_per_rse}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
