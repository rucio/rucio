# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013


import datetime
import logging
import re
import signal
import time

from copy import copy
from json import loads, dumps
from math import exp
from os import getpid, fork, kill
from sys import exc_info, exit
from traceback import format_exception

from gearman import GearmanWorker, GearmanClient, GearmanAdminClient

from rucio.api.did import list_new_dids, set_new_dids, get_metadata
from rucio.api.rule import add_replication_rule
from rucio.api.subscription import list_subscriptions
from rucio.db.constants import DIDType, SubscriptionState
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, InvalidReplicationRule
from rucio.common.config import config_get, config_get_int
from rucio.core import monitor


logging.getLogger("transmogrifier").setLevel(logging.CRITICAL)

logging.basicConfig(filename='%s/%s.log' % (config_get('common', 'logdir'), __name__),
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def _retrial(func, *args, **kwargs):
    delay = 0
    while True:
        try:
            return apply(func, args, kwargs)
        except DataIdentifierNotFound, e:
            logging.warning(e)
            return 1
        except DatabaseException, e:
            logging.error(e)
            if exp(delay) > 600:
                logging.error('Cannot execute %s after %i attempt. Failing the job.' % (func.__name__, delay))
                raise
            else:
                logging.error('Failure to execute %s. Retrial will be done in %d seconds ' % (func.__name__, exp(delay)))
            time.sleep(exp(delay))
            delay += 1
        except:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            raise


class Supervisor(object):
    def __init__(self, chunksize=40):
        """
        Create a Supervisor agent that sends chunks of new DIDs to Workers that identify the ones that match subscriptions.
        It polls regularly the state of the jobs processed by the workers and resubmit the jobs that failed.

        :param chunksize: The size of the chunks that are send as input to the Workers.
        """

        self.__gearman_server_host = 'localhost'
        self.__gearman_server_port = 4730
        self.__chunksize = chunksize
        self.__sleep_time = 4
        self.__maxdids = 10000

        try:
            self.__maxdids = config_get_int('transmogrifier', 'maxdids')
            self.__chunksize = config_get_int('transmogrifier', 'chunksize')
            self.__sleep_time = config_get_int('transmogrifier', 'sleep_time')
            self.__gearman_server_host = config_get('transmogrifier', 'gearman_server_host')
            self.__gearman_server_port = config_get('transmogrifier', 'gearman_server_port')
        except:
            pass

        self.__gm_client = GearmanClient(['%s:%i' % (self.__gearman_server_host, self.__gearman_server_port), ])
        self.__gm_admin_client = GearmanAdminClient(['%s:%i' % (self.__gearman_server_host, self.__gearman_server_port), ])

    def get_new_dids(self):
        """
        List all the new DIDs.

        :return nbdids, chunks: Return a list of chunks (list) of new DIDs and the number of these chunks
        """
        chunks = []
        chunk = []
        nbdids = 0
        for did in list_new_dids():
            nbdids += 1
            logging.debug(did)
            d = {'scope': did['scope'], 'did_type': str(did['did_type']), 'name': did['name']}
            if len(chunk) < self.__chunksize:
                chunk.append(d)
            else:
                chunks.append(chunk)
                chunk = []
            if nbdids >= self.__maxdids:
                break
        if chunk != []:
            chunks.append(chunk)
        return nbdids, chunks

    def submit_tasks(self, chunks):
        """
        Submit a list of tasks to the gearman server.

        :param chunks: A list of chunks (list) of new DIDs.
        :return submitted_requests: List of submitted requests to the gearman server.
        """
        list_of_jobs = []
        submitted_requests = []
        subscriptions = []
        for sub in list_subscriptions(None, None, SubscriptionState.ACTIVE):
            subs = {}
            for key in sub:
                if type(sub[key]) is datetime.datetime:
                    subs[key] = str(sub[key])
                elif key == 'state':
                    subs[key] = str(sub[key])
                else:
                    subs[key] = sub[key]
            subscriptions.append(subs)
        for chunk in chunks:
            list_of_jobs.append(dict(task='evaluate_subscriptions', data=dumps([subscriptions, chunk])))
        if list_of_jobs != []:
            submitted_requests = self.__gm_client.submit_multiple_jobs(list_of_jobs, background=False, wait_until_complete=False, max_retries=4)
            return submitted_requests
        else:
            logging.warning('No new DIDS.')
            return submitted_requests

    def query_requests_simple(self, requests):
        """
        Simple method to poll the state of the requests submitted to the gearman server.

        :param requests: A list of request.
        :return: 0
        """
        queued = 10
        while(queued != 0):
            status = self.__gm_admin_client.get_status()
            logging.info('************************', status)
            time.sleep(self.__sleep_time)
            for task in status:
                if task['task'] == 'evaluate_subscriptions':
                    queued = task['queued']
        return 0

    def query_requests(self, requests):
        """
        Improved method to poll the state of the requests submitted to the gearman server.
        Resubmit the failed requests.

        :param requests: A list of request.
        :return: 0
        """
        nb_requests_to_process = 0
        notCompletedRequests = requests
        start_time = time.time()
        end_time = time.time()
        failedJobs = -99
        nbQueuedJobs = 999
        nbRunningJobs = 0
        deeperCheck = 0
        firstpass = 1
        while notCompletedRequests != []:
            # If nbQueuedJobs > nbRunningJobs we just check the overall status of all jobs.
            if nbQueuedJobs > nbRunningJobs:
                for item in self.__gm_admin_client.get_status():
                    if item['task'] == 'evaluate_subscriptions':
                        nbQueuedJobs = item['queued']
                        nbRunningJobs = item['running']
                logging.info('Time elapsed %f : Still %i requests to complete' % (end_time - start_time, nbQueuedJobs))
            # If nbQueuedJobs <= nbRunningJobs individually we check individually each job
            else:
                if deeperCheck:
                    logging.info('Time elapsed %f : --- Failed requests : %i --- Not completed requests : %i' % (end_time - start_time, failedJobs, len(notCompletedRequests)))
                    firstpass = 0
                else:
                    logging.info('Checking individually all submited tasks')
                    deeperCheck = 1
                    firstpass = 1
                if firstpass != 0:
                    logging.info('Failed requests : %i --- Not completed requests : %i' % (failedJobs, len(notCompletedRequests)))
                # If all remaining jobs are failed, resubmitting them
                if failedJobs == len(notCompletedRequests):
                    logging.warning('%i tasks failed. They will be resubmited' % (failedJobs))
                    jobsToResubmit = []
                    for request in notCompletedRequests:
                        jobsToResubmit.append(dict(task=request.job.task, data=str(request.job.data)))
                    logging.warning('List of jobs to resubmit')
                    logging.warning(jobsToResubmit)
                    notCompletedRequests = self.__gm_client.submit_multiple_jobs(jobsToResubmit, background=False, wait_until_complete=False, max_retries=4)
                    logging.debug(notCompletedRequests)
                failedJobs = 0
                # Else get the status of each job
                if nb_requests_to_process != len(notCompletedRequests):
                    logging.info('Time elapsed %f : Still %i requests to complete' % (end_time - start_time, len(notCompletedRequests)))
                nb_requests_to_process = len(notCompletedRequests)
                notCompletedRequests2 = copy(notCompletedRequests)
                for request in notCompletedRequests2:
                    status = self.get_job_status(request)
                    if status == 'COMPLETE':
                        notCompletedRequests.remove(request)
                    elif status == 'FAILED':
                        failedJobs += 1
            end_time = time.time()
            time.sleep(self.__sleep_time)
        end_time = time.time()
        return 0

    def get_job_status(self, request):
        """
        Method to get the status of a job.

        param request: A job request
        return status: The status of the request (COMPLETE, FAILED, ...)
        """
        status = None
        try:
            status = self.__gm_client.get_job_status(request)
            status = status.state
        except KeyError, e:
            logging.debug('Problem getting the job state with get_job_status', e)
            status = request.state
        return status

    def run(self):
        """
        Loop that call run_once.
        """

        while(True):
            self.run_once()

    def run_once(self):
        """
        Method to start the Supervisor agent. Loop over all new DIDs. Generate chunks of new DIDs that are sent to the Workers that identify the ones that match subscriptions.
        """

        nbdids, chunks = self.get_new_dids()
        if chunks != []:
            logging.info('##################### Submitting %i chunks representing %s new DIDs' % (len(chunks), nbdids))
            submitted_requests = self.submit_tasks(chunks)
            logging.info(submitted_requests)
            self.query_requests(submitted_requests)
        else:
            logging.info('##################### No new DIDs to submit in this cycle')
            time.sleep(self.__sleep_time)


class Worker(GearmanWorker):
    def __init__(self, listservers):
        """
        Creates a Transmogrifier Worker that gets a list of new DIDs, identifies the subscriptions matching the DIDs and submit a replication rule for each DID matching a subscription.

        param listservers: A list of gearman servers from which the Worker gets payload.
        """
        super(Worker, self).__init__(listservers)
        self.__pid = getpid()

    def run(self):
        """
        Starts the worker.
        """
        logging.info('Creating a new GearmanWorker, process %i' % (self.__pid))
        self.register_task('evaluate_subscriptions', self.evaluate_subscriptions)
        self.work()

    def is_matching_subscription(self, subscription, did, metadata):
        """
        Method to identify if a DID matches a subscription.

        param subscription: The subscription dictionnary.
        param did: The DID dictionnary
        param metadata: The metadata dictionnary for the DID
        return: True/False
        """
        filter = {}
        try:
            filter = loads(subscription['filter'])
        except ValueError, e:
            logging.error('%s : Subscription will be skipped' % e)
            return False
        # Loop over the keys of filter for subscription
        for key in filter:
            values = filter[key]
            if key == 'pattern':
                if not re.match(values, did['name']):
                    return False
            elif key == 'scope':
                if not did['scope'] in values:
                    logging.debug('Bad scope %s != %s' % (values, did['scope']))
                    return False
            else:
                if type(values) is str or type(values) is unicode:
                    values = [values, ]
                has_metadata = 0
                for meta in metadata:
                    if str(meta) == str(key):
                        has_metadata = 1
                        if not metadata[meta] in values:
                            logging.debug('Metadata not matching %s not in %s' % (metadata[meta], str(values)))
                            return False
                if has_metadata == 0:
                    return False
        return True

    def evaluate_subscriptions(self, worker, job):
        """
        This is the method where the actual work is done : It gets a chunk of new DIDs, query the subscription table to get the ACTIVE subscriptions.
        Loop over the list of DIDs and find for each DID which subscription(s) match and finally submit the replication rules.
        If an exception is raised it is caught, the traceback is sent and a raise is issued to fail the job.
        """
        try:
            results = {}
            start_time = time.time()
            logging.debug('Process %s' % (self.__pid))
            logging.debug('In transmogrifier worker')
            data = loads(job.data)
            subscriptions = data[0]
            dids = data[1]
            identifiers = []
            for did in dids:
                if (did['did_type'] == str(DIDType.DATASET) or did['did_type'] == str(DIDType.CONTAINER)):
                    results['%s:%s' % (did['scope'], did['name'])] = []
                    try:
                        metadata = get_metadata(did['scope'], did['name'])
                        for subscription in subscriptions:
                            if self.is_matching_subscription(subscription, did, metadata) is True:
                                stime = time.time()
                                results['%s:%s' % (did['scope'], did['name'])].append(subscription['id'])
                                #logging.info('%s:%s matches subscription %s' % (did['scope'], did['name'], subscription['id']))
                                logging.info('%s:%s matches subscription %s' % (did['scope'], did['name'], subscription['name']))
                                for rule in loads(subscription['replication_rules']):
                                    try:
                                        grouping = rule['grouping']
                                    except:
                                        grouping = 'NONE'
                                    try:
                                        add_replication_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=subscription['account'], copies=int(rule['copies']), rse_expression=rule['rse_expression'],
                                                             grouping=grouping, weight=None, lifetime=None, locked=False, subscription_id=subscription['id'], issuer='root')
                                        monitor.record_counter(counters='transmogrifier.addnewrule.done',  delta=1)
                                        if subscription['name'].startswith('group'):
                                            monitor.record_counter(counters='transmogrifier.addnewrule.activity.group', delta=1)
                                        elif subscription['name'].startswith('tier0export'):
                                            monitor.record_counter(counters='transmogrifier.addnewrule.activity.tier0export', delta=1)
                                        elif subscription['name'].endswith('export'):
                                            monitor.record_counter(counters='transmogrifier.addnewrule.activity.dataconsolidation', delta=1)
                                        else:
                                            monitor.record_counter(counters='transmogrifier.addnewrule.activity.other', delta=1)

                                    except InvalidReplicationRule, e:
                                        logging.error(e)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                logging.info('Rule inserted in %f seconds' % (time.time()-stime))
                    except DataIdentifierNotFound, e:
                        logging.warning(e)
                if did['did_type'] == str(DIDType.FILE):
                    monitor.record_counter(counters='transmogrifier.did.file.processed',  delta=1)
                elif did['did_type'] == str(DIDType.DATASET):
                    monitor.record_counter(counters='transmogrifier.did.dataset.processed',  delta=1)
                elif did['did_type'] == str(DIDType.CONTAINER):
                    monitor.record_counter(counters='transmogrifier.did.container.processed',  delta=1)
                monitor.record_counter(counters='transmogrifier.did.processed',  delta=1)
                identifiers.append({'scope': did['scope'], 'name': did['name'], 'did_type': DIDType.from_sym(did['did_type'])})
            time1 = time.time()
            _retrial(set_new_dids, identifiers, None)
            #logging.info(dids)
            logging.info('Time to set the new flag : %f' % (time.time() - time1))
            logging.debug('Matching subscriptions '+dumps(results))
            tottime = time.time() - start_time
            logging.info('It took %f seconds to process %i DIDs by worker %s' % (tottime, len(dids), self.__pid))
            monitor.record_counter(counters='transmogrifier.job.done',  delta=1)
            monitor.record_timer(stat='transmogrifier.job.duration',  time=1000*tottime)
            return dumps(results)
        except:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            monitor.record_counter(counters='transmogrifier.job.error',  delta=1)
            monitor.record_counter(counters='transmogrifier.addnewrule.error',  delta=1)
            raise


def stop(signum, frame):
    print "Kaboom Baby!"
    exit()


def launch_transmogrifier(once=False):
    """
    This method can be used to start a Transmogrifier Supervisor and 4 Workers on the localhost (5 processes).
    In production, they should be launch via supervisord.
    """
    workers_pid = []
    for i in xrange(0, 10):
        newpid = fork()
        if newpid == 0:
            worker = Worker(['127.0.0.1', ])
            worker.run()
        else:
            workers_pid.append(newpid)

    def signal_handler(signal, frame):
        logging.critical("Process %s says : Arrrgggghhh, I'm dying" % (str(getpid())))
        logging.critical("Will kill all child process")
        for pid in workers_pid:
            kill(pid, 9)
            logging.critical("Process %s killed" % (str(pid)))
    signal.signal(signal.SIGTERM, signal_handler)
    s = Supervisor()
    if once:
        s.run_once()
        # Then kill all the workers
        for pid in workers_pid:
            kill(pid, 9)
    else:
        s.run()
