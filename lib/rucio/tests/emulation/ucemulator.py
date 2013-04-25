# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
import ast
import json
import time
import threading
import os
import traceback

from gearman.client import GearmanClient
from uuid import uuid4 as uuid


class UCEmulator(object):
    """
        This class acts as base class for all use cases included in the performance emulation.
        Every use case module included in rucio.tests.emulation.usecase package and listed
        in the __init__.py under __all__ must be derived from this class.

        One the class is instantiated, it executes the defined use cases (i.e. all methods
        implementing the UseCase decorator) in a frequency according to the current time frame
        defined in the related time series.
    """
    __ucs = {}

    def __init__(self, timeseries_file=None, cfg=None, carbon_server=None, worker_mode=False):
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
        self.__carbon_server = carbon_server
        if worker_mode:
            return
        else:
            if timeseries_file is None:
                raise Exception('No timeseries file provided')
            if cfg is None:
                raise Exception('No configuration provided')
        self.__factor = cfg['global']['workload_multiplier']
        self.__operation_mode = cfg['global']['operation_mode']
        self.__timeseries = {}
        self.__intervals = {}
        self.__current_timeframe = 0
        self.__running = False
        self.__call_methods = dict()
        self.__ctx = Context()
        # Check what methods are decorated to be use case definition
        if 'setup' in dir(self):  # Calls setup-method of child class to support the implementation of correlated use cases
            self.setup(cfg, self.__ctx)

        path = None
        if 'RUCIO_HOME' in os.environ:
            path = '%s/lib/rucio/tests/emulation/timeseries/%s.json' % (os.environ['RUCIO_HOME'], timeseries_file)
        else:
            path = '/opt/rucio/lib/rucio/tests/emulation/timeseries/%s.json' % timeseries_file

        with open(path) as f:
            tmp_json = json.load(f)
        for uc in self.__ucs[self.__module__.split('.')[-1]]:
            if uc not in tmp_json:
                print '== !WARNING! No timeseries found for use case %s.' % uc
            else:
                self.__timeseries[uc] = tmp_json[uc]
            try:
                self.__call_methods[uc] = {'main': getattr(self, uc), 'input': None, 'output': None}
                try:
                    self.__call_methods[uc]['input'] = getattr(self, ''.join([uc, '_input']))
                except AttributeError:
                    pass
                try:
                    self.__call_methods[uc]['output'] = getattr(self, ''.join([uc, '_output']))
                except AttributeError:
                    pass
            except Exception, e:
                print e
                print traceback.format_exc()
        # Apply factor to number of calls
        for ser in self.__timeseries:
            for tf in self.__timeseries[ser]:
                if 'calls' in tf:
                    tf['hz'] = self.__factor * (tf['calls'] / 3600.0)  # Convert calls per hour to hz
                    del(tf['calls'])
                elif 'hz' in tf:
                    tf['hz'] = self.__factor * tf['hz']
                else:
                    tf['hz'] = 1  # Fallback if no frequency is given
        self.__calc_timeframe__()

    def __calc_timeframe__(self):
        """
            Updates the frequency (calls per second) for each use case  in the current time frame.
        """
        for uc in self.__timeseries:
            self.__intervals[uc] = 1.0 / self.__timeseries[uc][self.__current_timeframe]['hz']

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
            pending_calls[uc] = self.__intervals[uc] + time.time()  # Set time for first calls
        nc = min(pending_calls, key=pending_calls.get)
        while self.__running:
            yield nc
            # Find next pending call
            pending_calls[nc] += self.__intervals[nc]
            nc = min(pending_calls, key=pending_calls.get)  # Find next pending call
            #print 'Turnover: %s' % (time.time() - time_stamp)
            sleep = pending_calls[nc] - time.time()  # Calculate sleep till next call
            if sleep > 0.0003:
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
            self.__gearman_server = cfg['gearman']['server']
            self.__gearman_client = GearmanClient(self.__gearman_server)
            do_it = self.run_gearman
        else:
            raise Exception("Unknown operation mode set")
        for call in self:
            if call and self.__running:
                do_it(call)
        return

    def run_gearman(self, call):
        """ Submits the jobs to a gearman queue.

            :param call: Name of the use case to be submitted.
        """
        uc_data = {'uc_name': call, 'class_name': '.'.join([self.__module__, self.__class__.__name__]), 'input_data': {}}
        if self.__call_methods[call]['input'] is not None:
            uc_data['input_data'] = self.__call_methods[call]['input'](self.__ctx)
            if uc_data['input_data'] is None:
                uc_data['input_data'] = {}
        if self.__call_methods[call]['output'] is not None:
            # Gearman call must wait for the return of the job
            # Submitt job in separate thread and wait for response
            t = threading.Thread(target=self.await_gearman_results, kwargs={'data': uc_data})
            t.start()
        else:
            # Gearman job can just be executed, no waiting necessary
            self.__gearman_client.submit_job(task='execute_uc', data=str(uc_data), unique=str(uuid()), background=True)
        self.inc('.'.join([call, 'gearman.submitted']))  # Logs to graphite the submission of the given usecase

    def await_gearman_results(self, data):
        """
            Submits a job to the gearman queue and waits for the response.

            :param data: use case data
        """
        try:
            client = GearmanClient(self.__gearman_server)
            request = client.submit_job(task='execute_uc', data=str(data), unique=str(uuid()), background=False, wait_until_complete=True)
            self.__call_methods[data['uc_name']]['output'](self.__ctx, ast.literal_eval(request.result)[1])
        except Exception, e:
            print e
            raise e

    def run_threaded(self, call):
        """
            Starts use case in a new thread.
            IMPORTANT: It is assumed that on the gearman worker the rucio-client package (including the package rucio.test.emulation) is installed
                        and etc/emulation.cfg is properly set up.

            :param call: Name of use case.
        """
        # TODO: Later consider to create a pool of threads for each 'call' and re-use them to potentially save time?
        t = threading.Thread(target=self.time_uc, kwargs={'fn': self.__call_methods[call]})
        t.start()

    def run_verbose(self, call):
        """
            Executes use case in current thread and prints log data to console.

            :param call: Name of use case.
        """
        print '%f\t%s' % (time.time(), call)
        try:
            self.time_uc(self.__call_methods[call])
        except Exception, e:
            print e
            self.inc('exceptions.%s' % e.__class__.__name__)

    def stop(self):
        """
            Stops the emulation.
        """
        self.__running = False

    def get_defined_usecases(self):
        """
            Provides a list with the IDs of all defined use cases in this module.

            :returns: list with use case IDs
        """
        return self.__timeseries.keys()

    def time_it(self, fn, kwargs={}):
        res = None
        start = time.time()
        res = fn(**kwargs)
        fin = time.time()
        resp = (fin - start) * 1000  # Converting seconds to milliseconds (needed by pystatsd)
        if self.__carbon_server:
            self.__carbon_server.timing(fn.__name__, resp)
        return res

    def time_uc(self, fn):
        """
            Automatically logs the execution time of t he provided operation.

            :param function: A reference to the operation.
            :param args: Arguments used to execute the operation as list
            :param kwargs: Arguments used to execute the operation as dict

            :returns: function return
        """
        input_data = None
        if 'input' in fn.keys() and fn['input']:
            input_data = fn['input'](self.__ctx)

        res = None
        start = time.time()
        if input_data is not None:
            res = fn['main'](**input_data)
        else:
            res = fn['main']()
        fin = time.time()
        resp = (fin - start) * 1000  # Converting seconds to milliseconds (needed by pystatsd)
        if 'output' in fn.keys() and fn['output']:
            res = fn['output'](self.__ctx, res[1])
        if self.__carbon_server:
            if (fn['main'].__name__ == '__execute__'):  # a wrapped use case is executed, if res is False, an exception occurred and was already reported by the wrapper
                if res:
                    self.__carbon_server.timing(res[0], resp)
                    res = res[1]
            else:
                self.__carbon_server.timing(fn.__name__, resp)
        return res

    def inc(self, metric, value=1):
        """
            Increments the referred metric by value.
        """
        if self.__carbon_server:
            self.__carbon_server.update_stats(metric, value)

    @classmethod
    def UseCase(cls, func):
        """
            Decorator to help identifying all use cases defined within a module.
        """
        # Register method as use case
        mod = func.__module__.split('.')[-1]
        if mod not in cls.__ucs:
            cls.__ucs[mod] = []
        cls.__ucs[mod].append(func.__name__)

        # Wrap function for exception handling
        def __execute__(self, *args, **kwargs):
            try:
                res = func(self, *args, **kwargs)
                return [func.__name__, res]
            except Exception, e:
                self.inc('exceptions.%s.%s.%s' % (self.__module__.split('.')[-1], func.__name__, e.__class__.__name__))
                print 'Error in: %s.%s: %s' % (self.__module__.split('.')[-1], func.__name__, e)
                print traceback.format_exc()
                return False
        return __execute__


class Context(object):
    #  Needs to be done like this as the pure pythpn object has no dict to save attributes. Cleaner work-arounds are welcome ;-)
    pass

    def __str__(self):
        return str(self.__dict__)
