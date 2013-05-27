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

from pystatsd import Client
from gearman.admin_client import GearmanAdminClient


"""
    Executes all use cases defined in rucio.tests.emulation.usecases according to the time series
    defined in /opt/rucio/lib/rucio/tests/emulation/timeseries.

    Emulation setup is loaded from /opt/rucio/etc/emulation.cfg
"""


def observe_gearman_queue(cfg, oberserver_event):
    ac = GearmanAdminClient(cfg['gearman'])
    cs = Client(host=cfg['carbon']['CARBON_SERVER'], port=cfg['carbon']['CARBON_PORT'], prefix=cfg['carbon']['USER_SCOPE'])
    while observer_event.is_set() is False:
        stat = ac.get_status()
        for task in stat:
            if task['task'] == 'execute_uc':
                cs.update_stats('gearman.queue', task['queued'])
        observer_event.wait(1.0)

if __name__ == '__main__':
    multiplier = 1
    update = 500
    with open('/opt/rucio/etc/emulation.cfg') as f:
        cfg = json.load(f)
    print '=' * 80
    print '=' * 35 + ' SETTINGS ' + '=' * 35
    # Printing configuration for testrun
    for setting in cfg['global']:
        print '= Emulation -> %s:\t %s' % (setting, cfg['global'][setting])
        if setting == 'multiplier':
            multiplier = cfg['global'][setting]
        if setting == 'update_interval':
            update = cfg['global'][setting]

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

    # Start Gearman queue observer
    if cfg['global']['operation_mode'] == 'gearman':
        print '=' * 36 + ' GEARMAN ' + '=' * 35
        try:
            observer_event = threading.Event()
            t = threading.Thread(target=observe_gearman_queue, args=[cfg['global'], observer_event])
            t.deamon = True
            t.start()
            print '= Setting up gearman queue observer ... OK'
        except Exception, e:
            print '!! Unable to connect to Gearman-Server !!'
            print e
            print traceback.format_exc()

    print '=' * 31 + ' INCLUDED USECASES ' + '=' * 30
    uc_array = dict()
    for module_name in cfg:
        if module_name == 'global':
            continue
        try:
            print '= Instanciating module \'%s\' ... ' % module_name
            obj = __import__('rucio.tests.emulation.usecases.%s' % module_name)  # Not sure why this is needed, but couldn't find an other working way
            for mn in ['tests', 'emulation', 'usecases', module_name, 'UseCaseDefinition']:
                obj = getattr(obj, mn)
            # Applying multiplier to Hz rates
            print '== Importing sucessful. Exexcuting setup ...'
            for uc in cfg[module_name]:
                if uc == 'context':
                    continue
                cfg[module_name][uc] *= multiplier
            obj = obj(cfg[module_name], cs)  # Instanciate UC object
            print '== Initialized frequencies: %s' % obj.get_intervals()
            uc_array[module_name] = obj
        except Exception, e:
            print '!! Error importing module \'%s\' !!' % module_name
            print traceback.format_exc()

    if len(uc_array.items()) == 0:
        print '!! No use case definition found. !!'
        exit(1)

    print '=' * 80

    # Starting all defined use cases
    uc_threads = dict()
    try:
        event = threading.Event()
        for uc in uc_array.items():
            run = getattr(uc[1], 'run')
            t = threading.Thread(target=run, args=[cfg['global'], event])
            t.deamon = True
            t.start()
            uc_threads[uc] = t

        with open('/opt/rucio/etc/emulation.cfg') as f:
            cfg = json.load(f)
        while True:
            time.sleep(update)
            print '=' * 22 + '> Checking configuration for updates '
            with open('/opt/rucio/etc/emulation.cfg') as f:
                cfg_new = json.load(f)
            update = cfg_new['global']['update_interval']
            if cfg_new['global']['multiplier'] != cfg['global']['multiplier']:
                # Update workload multiplier of all UCs
                print '== Updating workload multiplier changed to %s' % cfg_new['global']['multiplier']
                multiplier = cfg_new['global']['multiplier']
                for mod in cfg_new:
                    if mod == 'global':
                        continue
                    ucs_new = dict()
                    for uc in cfg_new[mod]:
                        if uc == 'context':
                            continue
                        ucs_new[uc] = cfg_new[mod][uc] * multiplier
                    try:
                        uc_array[mod].update_ucs(ucs_new)
                    except KeyError, e:
                        print 'Unknow module found in CFG file'
                        print e
            for mod in cfg_new:
                if mod == 'global':
                    continue
                if cfg_new[mod] != cfg[mod]:
                    for part in cfg_new[mod]:
                        if cfg[mod][part] != cfg_new[mod][part]:
                            if part == 'context':
                                uc_array[mod].update_ctx(cfg_new[mod][part])
                            else:
                                uc_array[mod].update_ucs({part: cfg_new[mod][part] * multiplier})
            cfg = cfg_new

    except KeyboardInterrupt:
        print 'Stopping emulation ...'
        for uc in uc_array.items():
            uc[1].stop()
        if cfg['global']['operation_mode'] == 'gearman':
            observer_event.set()
        exit(0)

    except:
        print '%f\tException' % (time.time())
        traceback.print_exc(file=sys.stdout)
        for uc in uc_array.items():
            uc[1].stop()
        exit(2)
