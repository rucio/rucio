#!/usr/bin/env sh
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020

import commands
import logging
import traceback
import sys

from Queue import Queue
from threading import Thread
from sqlalchemy.orm.exc import NoResultFound

from rucio.core import rse as rse_core, replica as replica_core
from rucio.db.sqla.constants import ReplicaState
from rucio.db.sqla.session import get_session
from rucio.rse import rsemanager as rsemgr
from rucio.common.exception import ReplicaNotFound


class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            try:
                func, args, kargs = self.tasks.get()
                try:
                    func(*args, **kargs)
                except Exception, e:
                    logging.warning("ThreadPool Worker func exception: %s, %s" % (str(e), traceback.format_exc()))
                except:
                    logging.warning("ThreadPool Worker func unknow exception: %s" % traceback.format_exc())
            except:
                logging.warning("ThreadPool Worker unknow exception: %s" % traceback.format_exc())
            finally:
                self.tasks.task_done()


class ThreadPool:
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, num_threads):
        self.tasks = Queue()
        [Worker(self.tasks) for _ in range(num_threads)]

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()


def check_file_path(scope, name, rse_id, dest_url):
    command = 'gfal-ls ' + dest_url
    status, output = commands.getstatusoutput(command)
    if status == 0:
        return True
    else:
        if "No such file or directory" in output:
            print "LOST: scope %s, name %s, rse_id %s, url: %s" % (scope, name, rse_id, dest_url)
        else:
            print "UNKNOWN: scope %s, name %s, rse_id %s, url: %s, error: %s" % (scope, name, rse_id, dest_url, output)
    return False


def get_lost_requests(input_file_name):
    input_file = open(input_file_name)
    rows = []
    for line in input_file:
        rse_name, scope, name, lost_created_at, lost_updated_at, done_created_at, done_updated_at = line.split()
        rows.append((scope, name, rse_name))
    return rows


input_file_name = sys.argv[1]
protocols = {}
rse_ids = {}
threadPool = ThreadPool(10)
session = get_session()


lost_requests = get_lost_requests(input_file_name)
for scope, name, rse_name in lost_requests:

    # print rse_name, scope, name
    if rse_name not in rse_ids:
        rse_id = rse_core.get_rse_id(rse_name, session=session)
        rse_ids[rse_name] = rse_id
    else:
        rse_id = rse_ids[rse_name]

    try:
        replica = replica_core.get_replica(scope=scope, name=name, rse_id=rse_id, session=session)
    except NoResultFound:
        continue
    if replica['state'] != ReplicaState.AVAILABLE:
        continue

    if rse_name not in protocols:
        rse_info = rsemgr.get_rse_info(rse_name, session=session)
        protocols[rse_name] = rsemgr.create_protocol(rse_info, 'write', 'srm,gsiftp')
    lfn = {'scope': replica['scope'].external, 'name': replica['name'], 'path': replica['path']}

    try:
        pfn = protocols[rse_name].lfns2pfns([lfn])['%s:%s' % (scope, name)]
    except ReplicaNotFound:
        # for stagin rses, it's undeterminstric, but the path is not set. here protocol.lfns2pfns will throw an exception
        print "ReplicaNotFound: scope %s, name %s, rse_id %s, rse %s" % (scope, name, rse_id, rse_name)
        continue
    except:
        print "Unknow: scope %s, name %s, rse_id %s, rse %s" % (scope, name, rse_id, rse_name)
        continue

    threadPool.add_task(check_file_path, scope, name, rse_id, pfn)
threadPool.wait_completion()
