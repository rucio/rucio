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
import os
import resource
import signal
import sys
import threading
import time
import traceback

from pystatsd import Client


class UCProcess(object):

    def get_open_fds(self):
        fds = []
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        for fd in range(0, soft):
            try:
                fcntl.fcntl(fd, fcntl.F_GETFD)
            except IOError:
                continue
            fds.append(fd)
        return len(fds)

    def __init__(self, cfg, mod_list, stop_event):
        self.pid = os.getpid()
        self.cfg = cfg
        self.mod_list = mod_list
        self.stop_event = stop_event
        self.uc_threads = dict()
        self.update = cfg['global']['update_interval']
        self.received_stop = False

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
        def signal_handler(signal, frame):
            print '= (PID: %s) [%s] received SIGTERM' % (self.pid, time.strftime('%H:%M:%S', time.localtime()))
            self.received_stop = True

        try:
            signal.signal(signal.SIGTERM, signal_handler)
        except ValueError:
            pass  # Happens when using threads instead of sub processes

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
                ta = threading.active_count()
                of = self.get_open_fds()
                if len(self.mod_list):
                    self.cs.gauge('emulator.counts.threads.%s' % self.mod_list[0], ta)
                    self.cs.gauge('emulator.counts.files.%s' % self.mod_list[0], of)
                print '= (PID: %s) File count: %s' % (self.pid, self.get_open_fds())
                print '= (PID: %s) Thread count: %s' % (self.pid, threading.active_count())
                self.stop_event.wait(self.update)
                try:
                    with open('/opt/rucio/etc/emulation.cfg') as f:
                        cfg = json.load(f)
                    for mod in cfg['global']['modules']:
                        with open('/opt/rucio/etc/%s.cfg' % mod) as f:
                            mcfg = json.load(f)
                        cfg.update(mcfg)
                except Exception, e:
                    print 'Unable to check configuration for updates. Retry in %s seconds ...' % self.update
                    print e
                    continue
                for mod in self.mod_list:
                    print '= (PID: %s) Checking context of %s for updates ...' % (self.pid, mod)
                    # Check frequencies
                    ups = {}
                    for uc in self.cfg[mod]:
                        if uc != 'context':
                            cfg[mod][uc] *= cfg['global']['multiplier']
                            if self.cfg[mod][uc] != cfg[mod][uc]:
                                ups[uc] = cfg[mod][uc]
                                self.cfg[mod][uc] = cfg[mod][uc]
                    if len(ups.keys()):
                        self.uc_array[mod].update_ucs(ups)

                    # Check context variables
                    try:
                        self.diff_context(self.cfg[mod]['context'], cfg[mod]['context'], ['context'], self.uc_array[mod])
                    except Exception, e:
                        print '!! ERROR !! Error while updaeting context: %s' % e

                    # Updated local cfg
                    self.cfg[mod]['context'] = cfg[mod]['context']
                self.update = cfg['global']['update_interval']

                # Reporting cfg - setting to graphite
                for mod in cfg:
                    if mod == 'global':
                        self.cs.gauge('emulator.cfg.multiplier', cfg['global']['multiplier'])
                        self.cs.gauge('emulator.cfg.update_interval', cfg['global']['update_interval'])
                    else:
                        for frequ in cfg[mod]:
                            if frequ == 'context':
                                self.report_context(cfg[mod]['context'], 'emulator.cfg.%s.context' % mod)
                            else:
                                self.cs.gauge('emulator.cfg.%s.frequency.%s' % (mod, frequ), cfg[mod][frequ])
            self.stop()
        except Exception, e:
            print e
            print traceback.format_exc()
        except KeyboardInterrupt:
            pass

    def stop(self):
        print '= (PID: %s) Stopping threads ....' % self.pid
        for mod in self.uc_threads.items():
            print '= (PID: %s) Stopping module %s' % (self.pid, mod[0])
            mod[1].join()
        if self.received_stop:
            print '= (PID: %s) Stopped successfully (Return Code: 0)' % self.pid
            sys.exit(0)
        else:
            print '= (PID: %s) Stopped successfully (Return Code: 1)' % self.pid
            sys.exit(1)

    def diff_context(self, current, new, key_chain, uc):
        nk = new.keys()
        for key in current:  # Check if keys are changed
            if key in nk:
                if type(current[key]) == dict:
                    self.diff_context(current[key], new[key], key_chain + [key], uc)
                else:
                    if current[key] != new[key]:
                        print key_chain, current[key], new[key]
                        uc.update_ctx((key_chain + [key])[1:], new[key])

    def report_context(self, ctx, prefix):
        for key in ctx:
            if type(ctx[key]) == dict:
                self.report_context(ctx[key], '%s.%s' % (prefix, key))
            elif type(ctx[key]) == unicode:
                if ctx[key] == 'True':
                    self.cs.gauge('%s.%s' % (prefix, key), 1)
                elif ctx[key] == 'False':
                    self.cs.gauge('%s.%s' % (prefix, key), 0)
            elif isinstance(ctx[key], (int, long, float)):
                self.cs.gauge('%s.%s' % (prefix, key), ctx[key])
            else:
                # print '%s\tCannot report\t%s.%s\t(type:\t%s)\t%s' % (now, prefix, key, type(ctx[key]), ctx[key])
                pass
