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
import time
import threading
import traceback
import os

from pystatsd import Client


class UCProcess(object):
    def __init__(self, cfg, mod_list, stop_event):
        self.pid = os.getpid()
        self.cfg = cfg
        self.mod_list = mod_list
        self.stop_event = stop_event
        self.uc_threads = dict()
        self.update = cfg['global']['update_interval']

        # Instanciating logging
        self.cs = None
        if 'carbon' in self.cfg['global']:
            try:
                self.cs = Client(host=self.cfg['global']['carbon']['CARBON_SERVER'], port=self.cfg['global']['carbon']['CARBON_PORT'], prefix=self.cfg['global']['carbon']['USER_SCOPE'])
            except Exception, e:
                print '!! Unable to connect to Carbon-Server !!'
                print e
                print traceback.format_exc()

        # Preparing all UCs
        self.uc_array = dict()
        for module_name in self.mod_list:
            try:
                print '= (PID: %s) Instanciating module \'%s\' ... ' % (self.pid, module_name)
                obj = __import__('rucio.tests.emulation.usecases.%s' % module_name)  # Not sure why this is needed, but couldn't find an other working way
                for mn in ['tests', 'emulation', 'usecases', module_name, 'UseCaseDefinition']:
                    obj = getattr(obj, mn)
                # Applying multiplier to Hz rates
                print '= (PID: %s) Importing sucessful. Exexcuting setup ...' % self.pid
                for uc in self.cfg[module_name]:
                    if uc == 'context':
                        continue
                    self.cfg[module_name][uc] *= self.cfg['global']['multiplier']
                obj = obj(self.cfg[module_name], self.cs)  # Instanciate UC object
                print '= (PID: %s) Initialized frequencies: %s' % (self.pid, obj.get_intervals())
                self.uc_array[module_name] = obj
            except Exception, e:
                print '!! Error importing module \'%s\' !!' % module_name
                print traceback.format_exc()

    def run(self):
        # Starting all defined use cases
        self.pid = os.getpid()
        try:
            for uc in self.uc_array.items():
                run = getattr(uc[1], 'run')
                t = threading.Thread(target=run, args=[self.cfg['global'], self.stop_event])
                t.deamon = True
                t.start()
                self.uc_threads[uc] = t
                print '= (PID: %s) Starting up thread for %s ... OK' % (self.pid, uc[0])
        except Exception, e:
            print e
            print traceback.format_exc()

        try:
            while not self.stop_event.is_set():
                print '= (PID: %s) Checking for updates' % self.pid
                time.sleep(self.update)
                with open('/opt/rucio/etc/emulation.cfg') as f:
                    cfg = json.load(f)
                for mod in self.mod_list:
                    ups = {}
                    for uc in self.cfg[mod]:
                        if uc != 'context':
                            cfg[mod][uc] *= cfg['global']['multiplier']
                            if self.cfg[mod][uc] != cfg[mod][uc]:
                                ups[uc] = cfg[mod][uc]
                                self.cfg[mod][uc] = cfg[mod][uc]
                    if self.cfg[mod]['context'] != cfg[mod]['context']:
                        self.uc_array[mod].update_ctx(cfg[mod]['context'])
                        self.cfg[mod]['context'] = cfg[mod]['context']
                    if len(ups.keys()):
                        self.uc_array[mod].update_ucs(ups)
                self.update = cfg['global']['update_interval']
        except Exception, e:
            print e
            print traceback.format_exc()
        except KeyboardInterrupt:
            pass

    def stop(self):
        print '= (PID: %s) Stopping threads ....' % self.pid
        for mod in self.uc_threads.items():
            print '= (PID: %s) Stopping module %s' % (self.pid, mod[0])
            mod[1].stop()
        print '= (PID: %s) Stopped successfully' % self.pid
        exit(0)
