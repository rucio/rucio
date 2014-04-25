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
import signal
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
    acs = {}
    for s in cfg['gearman']:
        acs[s.split(':')[0]] = GearmanAdminClient([s])
    cs = Client(host=cfg['carbon']['CARBON_SERVER'], port=cfg['carbon']['CARBON_PORT'], prefix=cfg['carbon']['USER_SCOPE'])
    count = 0
    pid = os.getpid()
    while stop_event.is_set() is False:
        queue = 0
        try:
            for s in acs:
                try:
                    stat = acs[s].get_status()
                    for task in stat:
                        if task['task'] == 'execute_uc':
                            queue += task['queued']
                            cs.gauge('emulator.counts.gearman.%s' % s, task['queued'])
                except Exception:
                    print '= ERROR: Failed to get stats from %s' % s
                    cs.gauge('emulator.counts.gearman.%s' % s, 0)
            cs.gauge('emulator.counts.files.emulator', get_open_fds())
            if not count % 10:
                print '= (PID: %s [%s]) Gearman-Queue size: %s' % (pid, time.strftime('%H:%M:%S', time.localtime()), queue)
            count += 1
        except Exception:
            print traceback.format_exc()
        try:
            stop_event.wait(10.0)
        except KeyboardInterrupt:
            pass
    print '= Stopping queue observer ... OK'


def main_function():
    update = 500
    num_processes = 4
    stop_event = multiprocessing.Event()
    stop = False
    pid = os.getpid()
    spawned_processes = []
    duration = None

    def signal_handler(signal, frame):
        stop_event.set()
        print '= (PID: %s) [%s] Initiate shutdown of %s processes' % (pid, time.strftime('%H:%M:%S', time.localtime()), len(spawned_processes))
        for n in range(3):
            if not len(spawned_processes):
                print '= (PID: %s) [%s] All processes finished' % (pid, time.strftime('%H:%M:%S', time.localtime()))
                break
            while len(spawned_processes):
                spawned_processes[0].join(10)
                if not spawned_processes[0].is_alive():
                    del spawned_processes[0]
                    if stop_event.is_set():
                        print '= [%s] Process shutdown' % (time.strftime('%H:%M:%S', time.localtime()))
                    else:
                        print '= [%s] Process died' % (time.strftime('%H:%M:%S', time.localtime()))
            print '== [%s] %s processes remaining' % (time.strftime('%H:%M:%S', time.localtime()), len(spawned_processes))
        if len(spawned_processes):
            print '= (PID: %s) [%s] %s processes did not finish properly. Kill them now' % (pid, time.strftime('%H:%M:%S', time.localtime()), len(spawned_processes))
            for p in spawned_processes:
                p.terminate()
                print '= [%s] Process killed' % (time.strftime('%H:%M:%S', time.localtime()))
        if timeout_event.is_set():
            sys.exit(1)
        else:
            sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)

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
        if setting == 'duration':
            duration = cfg['global'][setting]

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
            # ucp = UCProcess(cfg, proc_mod[proc], multiprocessing.Event())
            ucp = UCProcess(cfg, proc_mod[proc], stop_event)
            procs.append(ucp)
    print '=' * 30 + ' STARTING EXECUTION ' + '=' * 30
    if len(procs) > 1:
        for ucp in procs:
            p = multiprocessing.Process(target=ucp.run)
            p.deamon = True
            p.start()
            spawned_processes.append(p)
    else:
        print '= (PID: %s) Only one module found, unsing threads instead of subprocesses' % (os.getpid())
        p = threading.Thread(target=ucp.run)
        p.deamon = True
        p.start()
        spawned_processes.append(p)

    timeout_event = threading.Event()
    if duration:
        print '== Set timeout for emulation: %.1f minutes' % (duration)
        t = threading.Thread(target=waiting_to_stop, kwargs={'duration': duration, 'interval': update, 'stop_event': stop_event, 'timeout': timeout_event})
        t.daemon = True
        t.start()
    else:
        print '== Disable timeout for emulation (infinite run)'
    while t.is_alive():
        t.join(3)
        if stop:
            stop_event.set()


def waiting_to_stop(duration, interval, stop_event, timeout):
    until = time.time() + duration
    while True:
        try:
            with open('emulator.stop'):
                pass
            print '= [%s] Found stop file (emulator.stop) and shutting down. To restart delete this file.' % (time.strftime('%H:%M:%S', time.localtime()))
            break
        except IOError:
            pass
        if until < time.time():
            print '= [%s] Emulation timed out. Going to shudown.' % (time.strftime('%H:%M:%S', time.localtime()))
            timeout.set()
            break
        if stop_event.is_set():
            print '= Received stop signal.'
            break
        stop_event.wait(interval)
        print '= [%s] Time remaining before shuting down emulation: %s minutes' % (time.strftime('%H:%M:%S', time.localtime()), ((until - time.time()) / 60))

    print '= [%s] Shutting down emulation' % (time.strftime('%H:%M:%S', time.localtime()))
    stop_event.set()
    print '= [%s] Proper shutdown done.' % (time.strftime('%H:%M:%S', time.localtime()))


if __name__ == '__main__':
    return_value = main_function()
    print '== Proper shutdown finished'
    sys.exit(return_value)
