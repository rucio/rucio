# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


import fcntl
import json
import multiprocessing
import resource
import operator
import os
import sys
import time
import threading
import traceback

from gearman.admin_client import GearmanAdminClient
from pystatsd import Client

from rucio.tests.emulation.ucprocess import UCProcess
"""
    Executes all use cases defined in rucio.tests.emulation.usecases according to the time series
    defined in /opt/rucio/lib/rucio/tests/emulation/timeseries.

    Emulation setup is loaded from /opt/rucio/etc/emulation.cfg
"""


def get_open_fds():
    fds = []
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    for fd in range(0, soft):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except IOError:
            continue
        fds.append(fd)
    return len(fds)


def observe_gearman_queue(cfg, stop_event):
    ac = GearmanAdminClient(cfg['gearman'])
    cs = Client(host=cfg['carbon']['CARBON_SERVER'], port=cfg['carbon']['CARBON_PORT'], prefix=cfg['carbon']['USER_SCOPE'])
    count = 0
    pid = os.getpid()
    while stop_event.is_set() is False:
        try:
            stat = ac.get_status()
            for task in stat:
                if task['task'] == 'execute_uc':
                    cs.gauge('emulator.counts.gearman', task['queued'])
                    cs.gauge('emulator.counts.files.emulator', get_open_fds())
                    if not count % 10:
                        print '= (PID: %s [%s]) Gearman-Queue size: %s' % (pid, time.strftime('%H:%M:%S', time.gmtime()), task['queued'])
                    count += 1
        except Exception:
            print traceback.format_exc()
        try:
            stop_event.wait(10.0)
        except KeyboardInterrupt:
            pass
    print '= Stopping queue observer ... OK'


if __name__ == '__main__':
    update = 500
    num_processes = 4
    stop_event = multiprocessing.Event()
    with open('/opt/rucio/etc/emulation.cfg') as f:
        cfg = json.load(f)

    # Check sysargs for modules
    exec_mods = list()

    if '--help' in sys.argv:
        print 'Spported command line arguments:'
        print '\t--exclude uc1 uc2 ... ucN\texclude the provided usecase modules from emulation'
        print '\t--only uc1 uc2 ... ucN\tncludes only the provided usecase modules for emulation'
    elif '--only' in sys.argv:
        for mod in cfg['global']['modules']:
            if mod in sys.argv:
                exec_mods.append(mod)

    elif '--exclude' in sys.argv:
        for mod in cfg['global']['modules']:
            if mod not in sys.argv:
                exec_mods.append(mod)
    else:
        exec_mods = cfg['global']['modules']

    # Load module sepcific configurations
    for mod in exec_mods:
        with open('/opt/rucio/etc/%s.cfg' % mod) as f:
            mcfg = json.load(f)
        cfg.update(mcfg)

    print '=' * 80
    print '=' * 35 + ' SETTINGS ' + '=' * 35
    # Printing configuration for testrun
    for setting in cfg['global']:
        print '= Emulation -> %s:\t %s' % (setting, cfg['global'][setting])
        if setting == 'update_interval':
            update = cfg['global'][setting]
        if setting == 'processes':
            num_processes = cfg['global'][setting]

    # Initialize carbon logger
    cs = None
    if 'carbon' in cfg['global']:
        print '=' * 36 + ' CARBON ' + '=' * 36
        try:
            cs = Client(host=cfg['global']['carbon']['CARBON_SERVER'], port=cfg['global']['carbon']['CARBON_PORT'], prefix=cfg['global']['carbon']['USER_SCOPE'])
            print '= Setting up carbon client ... OK'
        except Exception, e:
            print '!! Unable to connect to Carbon-Server !!'
            print e
            print traceback.format_exc()

    print '=' * 31 + ' INCLUDED USECASES ' + '=' * 30
    uc_array = dict()

    # Distributing WL over processes
    proc_load = {}
    proc_mod = {}
    for i in range(num_processes):
        proc_load[i] = 0
        proc_mod[i] = []

    for mod in cfg:
        if mod == 'global':
            continue
        uc_array[mod] = 0
        for uc in cfg[mod]:
            if uc == 'context':
                continue
            uc_array[mod] += cfg[mod][uc]
    sorted_uc = sorted(uc_array.iteritems(), key=operator.itemgetter(1))
    while len(sorted_uc):
        smallest = sorted(proc_load.iteritems(), key=operator.itemgetter(1))[0][0]
        uc = sorted_uc.pop()
        proc_load[smallest] += uc[1]
        proc_mod[smallest].append(uc[0])

   # Start Gearman queue observer
    if cfg['global']['operation_mode'] == 'gearman':
        print '=' * 36 + ' GEARMAN ' + '=' * 35
        try:
            t = threading.Thread(target=observe_gearman_queue, args=[cfg['global'], stop_event])
            t.deamon = True
            t.start()
            print '= Setting up gearman queue observer ... OK'
        except Exception, e:
            print '!! Unable to connect to Gearman-Server !!'
            print e
            print traceback.format_exc()

    # Starting all processes
    procs = []
    for proc in proc_mod:
        if len(proc_mod[proc]):
            ucp = UCProcess(cfg, proc_mod[proc], stop_event)
            procs.append(ucp)
    print '=' * 30 + ' STARTING EXECUTION ' + '=' * 30
    for ucp in procs:
            p = multiprocessing.Process(target=ucp.run)
            p.deamon = True
            p.start()

    try:
        pid = os.getpid()
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print 'Stopping emulation ...'
        stop_event.set()
        exit(0)

    except:
        print '%f\t Exception' % (time.time())
        traceback.print_exc(file=sys.stdout)
        for proc in procs:
            proc.stop()
        exit(2)
