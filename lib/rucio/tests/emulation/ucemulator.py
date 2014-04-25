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

from gearman.client import GearmanClient
from rucio.common.utils import generate_uuid as uuid


class UCEmulator(object):
    """
        This class acts as base class for all use cases included in the performance emulation.
        Every use case module included in rucio.tests.emulation.usecase package and listed
        in the __init__.py under __all__ must be derived from this class.

        One the class is instantiated, it executes the defined use cases (i.e. all methods
        implementing the UseCase decorator) in a frequency according to the current time frame
        defined in the related time series.
    """
    # __ucs = {}

    def __init__(self, cfg=None, carbon_server=None, worker_mode=False):
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

        if cfg is None:
            print 'Module %s has not configuration' % self.__module__.split('.')[-1]
            return
        self.__intervals = {}
        self.__call_methods = {}
        self.__open_requests = {}

        # Create Context for UseCases and initilaize it with values provided in the cfg - file
        self.__ctx = Context()
        for m in cfg['context']:
            setattr(self.__ctx, m, cfg['context'][m])

        if 'setup' in dir(self):  # Calls setup-method of child class to support the implementation of correlated use cases
            self.setup(self.__ctx)

        for uc in cfg:
            if uc == 'context':
                continue
            else:
                self.__intervals[uc] = 1.0 / cfg[uc]
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

    def update_ucs(self, ucs):
        for uc in self.__intervals:
            if uc in ucs:
                self.__intervals[uc] = 1.0 / ucs[uc]
        print '== Assigned Frequencies for %s: %s' % (self.__module__.split('.')[-1], self.__intervals)

    def update_ctx(self, key_chain, value):
        """ If the behaviour of this method must be adapted in order to work with a given usecase it must be overwritten in the according UseCaseDefintion class. """
        print '== Updating context: %s -> %s' % (key_chain, value)
        if len(key_chain) == 1:
            setattr(self.__ctx, key_chain[0], value)
        else:
            attr = getattr(self.__ctx, key_chain[0])
            for key in key_chain[1:-1]:
                attr = attr[key]
            attr[key_chain[-1]] = value
        return self.__ctx

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
        for uc in self.__intervals:
            pending_calls[uc] = self.__intervals[uc] + time.time()  # Set time for first calls. Doing this in bulk could eventually save a lot of time
        nc = min(pending_calls, key=pending_calls.get)
        while not self.__event.is_set():
            yield nc
            # Find next pending call
            pending_calls[nc] += self.__intervals[nc]
            nc = min(pending_calls, key=pending_calls.get)  # Find next pending call. Doing this in bulk could eventually save a lot of time
            sleep = pending_calls[nc] - time.time()  # Calculate sleep till next call
            if sleep > 0.0003:
                self.__event.wait(sleep)
        self.stop()

    def run(self, cfg_global=None, event=None):
        """
            Starts the actual execution of the use cases.

            :param cfg_global: content of the global section in etc/emulation.cfg
            :param event: the event used for thread synchronization
        """
        if event is None:
            return

        self.__event = event
        # Making this assignement outside of the loop saves computing time by avoiding the if inside the loop
        if cfg_global['operation_mode'] == 'threaded':
            do_it = self.run_threaded
        elif cfg_global['operation_mode'] == 'verbose':
            do_it = self.run_verbose
        elif cfg_global['operation_mode'] == 'gearman':
            self.__gearman_client = GearmanClient(cfg_global['gearman'])
            self.__gearman_server = cfg_global['gearman']
            do_it = self.run_gearman
        else:
            raise Exception("Unknown operation mode set")
        for call in self:
            if call and not self.__event.is_set():
                do_it(call)
        return

    def run_gearman(self, call):
        """ Submits the jobs to a gearman queue.

            :param call: Name of the use case to be submitted.
        """
        uc_data = {'uc_name': call, 'class_name': '.'.join([self.__module__, self.__class__.__name__]), 'input_data': {}}
        uc_data['input_data'] = {}
        if self.__call_methods[call]['input'] is not None:
            uc_data['input_data'] = self.__call_methods[call]['input'](self.__ctx)
            if uc_data['input_data'] is None:  # Allows the input - method to save the excution of the actual usecase e.g. if no data is ready for it
                return
        if self.__call_methods[call]['output'] is not None:
            # Gearman call must wait for the return of the job
            # Submitt job in separate thread and wait for response
            id = uuid()
            t = threading.Thread(target=self.await_gearman_results, kwargs={'data': uc_data, 'uuid': id})
            t.daemon = True
            try:
                t.start()
                self.__open_requests[id] = t
            except Exception, e:
                print '!! ERROR !! run_gearman: %s' % e
        else:
            # Gearman job can just be executed, no waiting necessary
            try:
                self.__gearman_client.submit_job(task='execute_uc', data=json.dumps(uc_data), unique=str(uuid()), background=True, max_retries=10, poll_timeout=300)
            except Exception, e:
                print '!! ERROR !! [%s] Unable to submit job to gearman.' % (time.strftime('%H:%M:%S', time.localtime()))
                print e
                print traceback.format_exc()
                self.__event.set()

    def await_gearman_results(self, data, uuid):
        """
            Submits a job to the gearman queue and waits for the response.

            :param data: use case data
        """
        try:
            client = GearmanClient(self.__gearman_server)
            request = None
            try:
                request = client.submit_job(task='execute_uc', data=json.dumps(data), unique=uuid, background=False, wait_until_complete=True)
                if request.state == 'FAILED' and not request.timed_out:  # Can only happen when import on the worker fails
                    print '!! ERROR !! [%s] Worker failed while executing %s.%s (Note: do Rucio imports work for the workers?)' % (time.strftime('%H:%M:%S', time.localtime()), data['class_name'], data['uc_name'])
                    return
                elif request.timed_out:  # Can only happen when import on the worker fails
                    print '!! ERROR !! [%s] Worker timed out while executing %s.%s' % (time.strftime('%H:%M:%S', time.localtime()), data['class_name'], data['uc_name'])
                    return
                elif (request.result.lower() == 'false') or () or (request.result is False):
                    print '!! ERROR !! [%s] %s failed' % (time.strftime('%H:%M:%S', time.localtime()), data['uc_name'])
                    return
                elif request.result is True:
                    print '!! ERROR !! [%s] %s Hmm. Why? ' % (time.strftime('%H:%M:%S', time.localtime()), data['uc_name'])
                    print request.result
                else:
                    result = json.loads(request.result)[1]
                del self.__open_requests[uuid]
            except Exception, e:
                print '!! ERROR !!: %s' % e
                print traceback.format_exc()
                del self.__open_requests[uuid]
                if request:
                    print 'Request-Object: ', request.result
                return
            self.__call_methods[data['uc_name']]['output'](self.__ctx, result)
        except Exception, e:
            print e
            print traceback.format_exc()

    def run_threaded(self, call):
        """
            Starts use case in a new thread.
            IMPORTANT: It is assumed that on the gearman worker the rucio-client package (including the package rucio.test.emulation) is installed
                        and etc/emulation.cfg is properly set up.

            :param call: Name of use case.
        """
        # TODO: Later consider to create a pool of threads for each 'call' and re-use them to potentially save time?
        t = threading.Thread(target=self.time_uc, kwargs={'fn': self.__call_methods[call]})
        t.daemon = True
        try:
            t.start()
        except Exception, e:
            print '!! ERROR !! threaded: %s' % e

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
            print traceback.format_exc()
            self.inc('exceptions.%s' % e.__class__.__name__)

    def stop(self):
        """
            Stops the emulation.
        """
        retry = 0
        pending = self.__open_requests.values()
        print '== [%s] Open requests for gearman workers: %s' % (time.strftime('%H:%M:%S', time.localtime()), len(self.__open_requests))
        while len(pending):
            for t in pending:
                if not t.is_alive():
                    pending.remove(t)
            if len(pending):
                if retry > 12:
                    print '!! ERROR !! [%s] Missed %s gearman results due to timeouts during shutdown' % (time.strftime('%H:%M:%S', time.localtime()), len(pending))
                    break
                print '== [%s] Waiting for %s pending gearman responses (retry: %s)' % (time.strftime('%H:%M:%S', time.localtime()), len(pending), retry)
                retry += 1
                time.sleep(10)
        if 'shutdown' in dir(self):  # Calls setup-method of child class to support the implementation of correlated use cases
            self.shutdown(self.__ctx)
        print '= [%s] Stopped module: %s' % (time.strftime('%H:%M:%S', time.localtime()), '.'.join([self.__module__, self.__class__.__name__]))

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
                    try:
                        self.__carbon_server.timing(res[0], resp)
                    except Exception, e:
                        print '!! ERROR !! Error reporting to grapthite: %s' % e
                    res = res[1]
            else:
                try:
                    self.__carbon_server.timing(fn.__name__, resp)
                except Exception, e:
                    print '!! ERROR !! Error reporting to grapthite: %s' % e
        return res

    def inc(self, metric, value=1):
        """
            Increments the referred metric by value.
        """
        if self.__carbon_server:
            try:
                self.__carbon_server.update_stats(metric, value)
            except Exception, e:
                print '!! ERROR !! Error reporting to grapthite: %s' % e

    @classmethod
    def UseCase(cls, func):
        """
            Decorator to help identifying all use cases defined within a module.
        """
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
