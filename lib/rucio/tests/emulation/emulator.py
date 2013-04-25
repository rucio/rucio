# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


import json
import sys
import time
import threading
import traceback

import rucio.tests.emulation.usecases

from pystatsd import Client
from gearman.admin_client import GearmanAdminClient


"""
    Executes all use cases defined in rucio.tests.emulation.usecases according to the time series
    defined in /opt/rucio/lib/rucio/tests/emulation/timeseries.

    Emulation setup is loaded from /opt/rucio/etc/emulation.cfg
"""


def observe_gearman_queue(cfg, oberserver_event):
    ac = GearmanAdminClient(cfg['gearman']['server'])
    cs = Client(host=cfg['carbon']['CARBON_SERVER'], port=cfg['carbon']['CARBON_PORT'], prefix=cfg['carbon']['USER_SCOPE'])
    while observer_event.is_set() is False:
        stat = ac.get_status()
        for task in stat:
            if task['task'] == 'execute_uc':
                cs.update_stats('gearman.queue', task['queued'])
        observer_event.wait(1.0)

if __name__ == '__main__':
    with open('/opt/rucio/etc/emulation.cfg') as f:
        cfg = json.load(f)

    print '=' * 80
    print '=' * 35 + ' SETTINGS ' + '=' * 35
    # Printing configuration for testrun
    for settings_group in cfg:
        for setting in cfg[settings_group]:
            print '= %s -> %s:\t %s' % (settings_group, setting, cfg[settings_group][setting])
    print '=' * 31 + ' INCLUDED USECASES ' + '=' * 30

    # Load and print list of included use cases
    uc_array = []
    m = None

    cs = None
    if 'carbon' in cfg:
        print 'Setting up carbon client ...'
        try:
            cs = Client(host=cfg['carbon']['CARBON_SERVER'], port=cfg['carbon']['CARBON_PORT'], prefix=cfg['carbon']['USER_SCOPE'])
        except Exception, e:
            print 'Unable to connect to Carbon-Server'
            print e
            print traceback.format_exc()
    else:
        print 'Loggin into carbon disabled'

    if cfg['global']['operation_mode'] == 'gearman':
        print 'Setting up gearman queue observer ...'
        try:
            observer_event = threading.Event()
            t = threading.Thread(target=observe_gearman_queue, args=[cfg, observer_event])
            t.deamon = True
            t.start()
        except Exception, e:
            print 'Unable to connect to Carbon-Server'
            print e
            print traceback.format_exc()
    else:
        print 'Loggin into carbon disabled'

    for module_name in rucio.tests.emulation.usecases.__all__:
        print'= Loaded module: \t%s' % module_name
        obj = __import__('rucio.tests.emulation.usecases.%s' % module_name)
        for mn in ['tests', 'emulation', 'usecases', module_name, 'UseCaseDefinition']:
            obj = getattr(obj, mn)
        obj = obj(module_name, cfg, cs)
        for uc in obj.get_defined_usecases():
            print '== Added use case:\t\t%s' % uc
        uc_array.append(obj)
    print '=' * 80

    if len(uc_array) == 0:
        print 'No use case definition found.'
        exit(1)

    # Starting all defined use cases
    start = time.time()
    tf_counter = 1
    cs.update_stats('emulation.timeframe', tf_counter)
    try:
        event = threading.Event()
        for uc in uc_array:
            run = getattr(uc, 'run')
            t = threading.Thread(target=run, args=[cfg, event])
            t.deamon = True
            t.start()

        while True:
            time.sleep(cfg['global']['seconds_per_timeframe'])
            if not uc_array[0].has_next_timeframe():
                break
            for uc in uc_array:
                uc.next_timeframe()
            tf_counter += 1
            cs.update_stats('emulation.timeframe', tf_counter)
            msg = ''
            for uc in uc_array:
                intervals = uc.get_intervals()
                for i in intervals:
                    msg += '%s:%.5f\t' % (i, 1.0 / intervals[i])
            print '%f\ttime_frame\t%d\t%s' % (time.time(), tf_counter, msg)

        for uc in uc_array:
            uc.stop()
        event.set()
        print 'Finished in %f seconds' % (time.time() - start)
        exit(0)

    except KeyboardInterrupt:
        print '%f\tKeyboardInterrupt' % (time.time())
        for uc in uc_array:
            uc.stop()
        if cfg['global']['operation_mode'] == 'gearman':
            observer_event.set()
        exit(1)

    except:
        print '%f\tException' % (time.time())
        traceback.print_exc(file=sys.stdout)
        for uc in uc_array:
            uc.stop()
        exit(2)
