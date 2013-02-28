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
import socket
import os

from timeit import Timer
from functools import partial


class UCEmulator(object):
    """
        This class acts as base class for all use cases included in the performance emulation.
        Every use case module included in rucio.tests.emulation.usecase package and listed
        in the __init__.py under __all__ must be derived from this class.

        One the class is instantiated, it executes the defined use cases (i.e. all methods
        implementing the UseCase decorator) in a frequency according to the current time frame
        defined in the related time series.
    """
    __ucs = []

    def __init__(self, timeseries_file, cfg):
        """
            Initializes the use case emulation. It sets up the multiplier of the workload defined in the
            time series file and the operation mode for the emulation (both defined in etc/emulation.cfg).

            The name of time series file should be the same as the module defining the use cases and the files
            must be stored either in /opt/rucio/lib/rucio/tests/emulation/timeseries/{modulename}.json or in
            $RUCIO_HOME/lib/rucio/tests/emulation/timeseries/{modulename}.json.

            The operation mode supports 'verbose' and 'threaded'. In 'verbose' mode, only one thread per module is used
            and a lot of debugging information is written to the console. This mode is intended to be used during the development
            of a new use case module. In mode 'threaded', each API call is executed in separate thread and less output is provided.

            :param timeseries_file: the name of the file where the time series for the defined use cases are found.
            :param cfg: the context defined in etc/emulation.cfg
        """
        self.__factor = cfg['global']['workload_multiplier']
        self.__operation_mode = cfg['global']['operation_mode']
        self.__carbon_server = None
        self.__carbon_user = ''
        if 'carbon' in cfg:
            try:
                self.__carbon_server = socket.socket()
                self.__carbon_server.connect((cfg['carbon']['CARBON_SERVER'], cfg['carbon']['CARBON_PORT']))
                self.__carbon_user = cfg['carbon']['USER_SCOPE']
            except Exception, e:
                print 'Unable to connect to Carbon-Server'
                print e
                self.__carbon_server = None
        self.__timeseries = {}
        self.__intervals = {}
        self.__current_timeframe = 0
        self.__running = False
        self.__call_methods = dict()
        # Check what methods are decorated to be use case definition
        if 'setup' in dir(self):  # Calls setup-method of child class to support the implementation of correlated use cases
            self.setup(cfg)

        path = None
        if 'RUCIO_HOME' in os.environ:
            path = '%s/lib/rucio/tests/emulation/timeseries/%s.json' % (os.environ['RUCIO_HOME'], timeseries_file)
        else:
            path = '/opt/rucio/lib/rucio/tests/emulation/timeseries/%s.json' % timeseries_file

        with open(path) as f:
            tmp_json = json.load(f)
        for uc in self.__ucs:
            if uc in tmp_json:
                self.__timeseries[uc] = tmp_json[uc]
        # Prepare method references
        for call in self.__ucs:
            self.__call_methods[call] = getattr(self, call)
        # Apply factor to number of calls
        for ser in self.__timeseries:
            for tf in self.__timeseries[ser]:
                tf['calls'] = round(self.__factor * tf['calls'])  # Calls must always be integer
        self.__calc_timeframe__()

    def __calc_timeframe__(self):
        """
            Calculates the frequency (calls per second) for each use case  in the current time frame.
        """
        for uc in self.__timeseries:
            self.__intervals[uc] = 3600 / (self.__timeseries[uc][self.__current_timeframe]['calls'] + 1)  # +1 to avoid every UC starting at time zero

    def next_timeframe(self):
        """
            Stops the emulation of the current time frame and restarts with the frequencies defined for the next one.
        """
        self.__current_timeframe += 1
        self.__calc_timeframe__()
        self.__event.set()
        self.__event.clear()

    def has_next_timeframe(self):
        """
            Returns the number of time frames left for emulation.

            :returns: number of pending time frames
        """
        return len(self.__timeseries[self.__timeseries.keys()[0]]) - self.__current_timeframe - 1

    def get_intervals(self):
        """
            A hash array with the interval between each call for each use case e.g. {'UC1': 0.2, 'UC2': 0.5}

            :returns: interval of use cases
        """
        return self.__intervals

    def __iter__(self):
        """
            Generator for workload. Based on the intervals for each use case, the name
            of the next use case is provided when it is time for it to call. When no
            use case is ready for execution, the methods waits until it is time.

            :returns: the ID of the next use case to execute
        """
        pending_calls = {}
        for uc in self.__timeseries:
            pending_calls[uc] = self.__intervals[uc]  # Set time for first calls
        nc = min(pending_calls, key=pending_calls.get)
        while self.__running:
            yield nc
            # Find next pending call
            now = pending_calls[nc]
            pending_calls[nc] += self.__intervals[nc]
            nc = min(pending_calls, key=pending_calls.get)  # Find next pending call
            sleep = pending_calls[nc] - now  # Calculate sleep till next call
            if sleep > 0:
                self.__event.wait(sleep)

    def run(self, cfg, event):
        """
            Starts the actual execution of the use cases.

            :param cfg: content of etc/emulation.cfg
            :param event: the event used for thread synchronization
        """
        self.__running = True
        self.__event = event
        # Making this assignement outside of the loop saves computing time by avoiding the if inside the loop
        if self.__operation_mode == 'threaded':
            do_it = self.run_threaded
        elif self.__operation_mode == 'verbose':
            do_it = self.run_verbose
        elif self.__operation_mode == 'gearman':
            raise NotImplemented
        else:
            raise Exception("Unknown operation mode set")
        for call in self:
            if call and self.__running:
                do_it(call)
        return

    def run_threaded(self, call):
        """
            Starts use case in a new thread.

            :param call: Name of use case.
        """
        # TODO: Later consider to create a pool of threads for each 'call' and re-use them to potentially save time?
        t = threading.Thread(target=self.__call_methods[call], args=[self.__timeseries[call][self.__current_timeframe]])
        t.start()

    def run_verbose(self, call):
        """
            Executes use case in current thread and prints log data to console.

            :param call: Name of use case.
        """
        print '%f\t%s\t%s' % (time.time(), call, threading.active_count())
        self.__call_methods[call](self.__timeseries[call][self.__current_timeframe])

    def stop(self):
        """
            Stops the emulation.
        """
        self.__carbon_server.close()
        self.__running = False

    def get_defined_usecases(self):
        """
            Provides a list with the IDs of all defined use cases in this module.

            :returns: list with use case IDs
        """
        return self.__timeseries.keys()

    def log(self, fn, args=[], kwargs={}):
        """
            Automatically logs the execution time of the provided operation.

            :param function: A reference to the operation.
            :param args: Arguments used to execute the operation as dict

            :returns: Execution time in ms
        """
        resp_time = round(Timer(partial(fn, *args, **kwargs)).timeit(1), 5)
        if self.__carbon_server:
            self.__carbon_server.sendall('emulation.rucio.%s.%s.resp_time %s %s\n' % (self.__carbon_user, fn.__name__, resp_time, int(time.time())))
        return resp_time

    @classmethod
    def UseCase(cls, func):
        """
            Decorator to help identifying all use cases defined within a module.
        """
        cls.__ucs.append(func.__name__)
        return func
