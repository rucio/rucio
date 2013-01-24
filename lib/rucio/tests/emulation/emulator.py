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


"""
    Executes all use cases defined in rucio.tests.emulation.usecases according to the time series
    defined in /opt/rucio/lib/rucio/tests/emulation/timeseries.

    Emulation setup is loaded from /opt/rucio/etc/emulation.cfg
"""

if __name__ == '__main__':
    cfg = json.load(open('/opt/rucio/etc/emulation.cfg'))

    if cfg['global']['operation_mode'] == 'verbose':
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
    for module_name in rucio.tests.emulation.usecases.__all__:
        if cfg['global']['operation_mode'] == 'verbose':
            print'= Loaded module: \t%s' % module_name
        obj = __import__('rucio.tests.emulation.usecases.%s' % module_name)
        for mn in ['tests', 'emulation', 'usecases', module_name, 'UseCaseDefinition']:
            obj = getattr(obj, mn)
        obj = obj(module_name, cfg)
        for uc in obj.get_defined_usecases():
            if cfg['global']['operation_mode'] == 'verbose':
                print '== Added use case:\t\t%s' % uc
        uc_array.append(obj)
    print '=' * 80

    if len(uc_array) == 0:
        print 'No use case definition found.'
        exit(0)

    # Starting all defined use cases
    start = time.time()
    try:
        event = threading.Event()
        for uc in uc_array:
            run = getattr(uc, 'run')
            t = threading.Thread(target=run, args=[cfg, event])
            t.deamon = True
            t.start()

        tf_counter = 1
        while True:
            time.sleep(cfg['global']['seconds_per_timeframe'])
            if not uc_array[0].has_next_timeframe():
                break
            for uc in uc_array:
                uc.next_timeframe()
            if cfg['global']['operation_mode'] == 'verbose':
                print '%f\ttime frame\t%d' % (time.time(), tf_counter)
                tf_counter += 1
                for uc in uc_array:
                    print '%f\t%s' % (time.time(), uc.get_intervals())

        for uc in uc_array:
            uc.stop()
        event.set()
        print 'Finished in %f seconds' % (time.time() - start)
        exit(0)

    except KeyboardInterrupt:
        print '%f\tKeyboardInterrupt' % (time.time())
        for uc in uc_array:
            uc.stop()
        exit(1)

    except:
        print '%f\tException' % (time.time())
        traceback.print_exc(file=sys.stdout)
        for uc in uc_array:
            uc.stop()
        exit(2)
    exit(0)
