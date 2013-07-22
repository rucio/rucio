# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

import datetime
import os
import threading
import sys
import time

from Queue import PriorityQueue, Empty, Queue
from random import choice, gauss, sample, random, randint

from rucio.client import Client
from rucio.common.utils import generate_uuid as uuid
from rucio.core import monitor
from rucio.tests.emulation.ucemulator import UCEmulator

g_sem = threading.Semaphore()


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, target_rse, rses, input, output, file_transfer_duration, bulk, threads, jobs_per_dis):
        monitor.record_counter('panda.tasks.%s.dispatched' % task_type, 1)  # Reports the task type which is dipsatched
        if task_type.split('.')[0] == 'user':  # User task is created
            exts = ['user']
            create_dis_ds = False
            create_sub_ds = False
        else:  # Production task output stuff is created
            exts = ['log', 'out']
            create_dis_ds = (input['dis_ds_probability'] > random())
            create_sub_ds = True

        client = Client(account='panda')

        # ----------------------- List replicas and derive list of files from it -------------------
        now = time.time()
        with monitor.record_timer_block('panda.list_replicas'):
            replicas = [f for f in client.list_replicas(scope=input['scope'], name=input['ds_name'])]
        delta = time.time() - now
        if len(replicas) == 0:
            print '== PanDA: Empty input dataset provided'
            monitor.record_counter('panda.tasks.EmptyInputDataset', 1)
            return {'job_finish': [], 'task_finish': []}
        monitor.record_timer('panda.list_replicas.normalized', delta / len(replicas))
        monitor.record_counter('panda.tasks.%s.input_files' % task_type, len(replicas))  # Reports the number of files in the intput dataset of the task type

        # Should be changed when the response from list_replicas is updated
        files = list()
        file_keys = list()
        for r in replicas:
            if '%s:%s' % (r['scope'], r['name']) not in file_keys:
                file_keys.append('%s:%s' % (r['scope'], r['name']))
                files.append({'scope': r['scope'], 'name': r['name'], 'bytes': r['bytes']})

        print '== PanDA: Create %s task  with %s files (dis: %s / sub: %s / repl: %s)' % (task_type, len(files), create_dis_ds, create_sub_ds, len(replicas))
        file_keys = None
        replicas = None

        # ------------------------------- Determine metadata for output dataset ------------------------------------
        meta = dict()
        with monitor.record_timer_block('panda.get_metadata'):
            meta_i = client.get_metadata(scope=input['scope'], name=input['ds_name'])

        for key in ['stream_name', 'run_number', 'project']:
            if meta_i[key] is not None:
                meta[key] = meta_i[key]
            else:
                meta[key] = 'NotGivenByInput'

        meta['version'] = uuid()
        if 'lifetime' not in output.keys():
            output['lifetime'] = None

        # ----------------------------------- Create final output - dataset(s) ---------------------------------------
        final_dss = {}
        for out_ds in output['meta']:  # Create output containers(s)
            meta['prod_step'] = out_ds.split('.')[0]
            meta['datatype'] = out_ds.split('.')[1]
            ds = '.'.join([meta['project'], str(meta['run_number']), meta['stream_name'], meta['prod_step'], meta['datatype'], meta['version']])
            final_dss[ds] = meta.copy()

        datasets = list()
        for fds in final_dss:
            for ext in exts:
                dsn = '%s.%s' % (fds, ext)
                monitor.record_counter('panda.tasks.%s.output_datasets' % task_type, 1)  # Reports the number of output datasets for the tasktype (including log datasets)

                with monitor.record_timer_block('panda.add_container'):
                    client.add_container(scope=output['scope'], name='cnt_%s' % dsn, lifetime=output['lifetime'],
                                         rules=[{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}])
                meta = final_dss[fds]
                with monitor.record_timer_block('panda.add_dataset'):
                    client.add_dataset(scope=output['scope'], name=dsn, meta=meta.update({'guid': str(uuid())}))
                with monitor.record_timer_block('panda.add_datasets_to_container'):
                    client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % dsn, dsns=[{'scope': output['scope'], 'name': dsn}])
        # -------------------------------- Derive/Create dis and subdatasets ------------------------------------------
        sub_dss = []
        files_in_ds = []
        dis_ds = None
        computing_rse = None
        job_count = 0

        inserts_dis = list()
        inserts_sub = list()

        while len(files):  # As long as there are unhandeled input files
            if ('max_jobs' in input.keys()) and (job_count >= input['max_jobs']):
                break
            files_in_ds = list()
            id = uuid()

            try:
                job_temp = 0
                while job_temp < jobs_per_dis:  # Get one set of files
                    for i in xrange(input['number_of_inputfiles_per_job']):  # Get one set of files
                        files_in_ds.append(files.pop(0))
                    job_temp += 1
                    job_count += 1
                    if ('max_jobs' in input.keys()) and (job_count > input['max_jobs']):
                        break
            except IndexError:  # Is raised for the last (incomplete) set of input files
                pass

            if create_sub_ds:
                while (target_rse == computing_rse) or (computing_rse is None):
                    computing_rse = choice(rses)  # Random choice of the computing RSE
            else:
                computing_rse = target_rse  # If no sub, no output is moved, therefore target rse = computing rse

            if create_dis_ds:  # Creating DIS - Datasets
                dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
                if bulk:
                    inserts_dis.append({'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400,
                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                        'dids': files_in_ds})  # Create DIS-Datasets
                else:
                    with monitor.record_timer_block('panda.add_dataset'):
                        client.add_dataset(scope='Manure', name=dis_ds, lifetime=86400,
                                           rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}])  # Create DIS-Datasets
                    with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
                        client.add_files_to_dataset(scope='Manure', name=dis_ds, files=files_in_ds)  # Add files to DIS - dataset
                monitor.record_counter('panda.tasks.%s.dis_datasets' % task_type, 1)  # Reports the creation of a dis dataset for the given task type

            if create_sub_ds:  # Creating SUB - datsets
                for ds in ['%s_SUB_%s_%s' % (input['ds_name'], id, fin_ds) for fin_ds in final_dss]:
                    sub_dss.append(({'scope': 'Manure', 'name': ds}, int(len(files_in_ds) / input['number_of_inputfiles_per_job']), computing_rse, task_type))
                    if bulk:
                        inserts_sub.append({'scope': 'Manure', 'name': ds, 'lifetime': 86400, 'dids': [],
                                            'rules': [{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rse),
                                            'grouping': 'DATASET'}]})  # Create SUB-Datasets
                    else:
                        with monitor.record_timer_block('panda.add_dataset'):
                            client.add_dataset(scope='Manure', name=ds, lifetime=86400,
                                               rules=[{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rse), 'grouping': 'DATASET'}])  # Create SUB-Datasets
                    monitor.record_counter('panda.tasks.%s.sub_datasets' % task_type, 1)  # Reports the creation of a sub dataset for the given task type
            else:
                for ds in final_dss:
                    # ds + exts[0] = when no subs are used only one output dataset type can exist
                    sub_dss.append(({'scope': output['scope'], 'name': '%s.%s' % (ds, exts[0])}, int(len(files_in_ds) / input['number_of_inputfiles_per_job']), computing_rse, task_type))

        # -------------------------------------- Perform bulk inserts ----------------------------------------
        if bulk:
            datasets = inserts_dis + inserts_sub
            if len(datasets):
                with monitor.record_timer_block(['panda.add_datasets', ('panda.add_datasets.normalized', len(datasets))]):
                    client.add_datasets(datasets)

            ts = list()
            ts_res = Queue()
            for ds in inserts_dis:
                if threads == 'True':
                    t = threading.Thread(target=self.add_files_ds, kwargs={'client': None, 'ds': ds, 'files_in_ds': files_in_ds, 'ret': Queue()})
                    t.start()
                    ts.append(t)
                else:
                    self.add_files_ds(client, ds, files_in_ds)
            if threads == 'True':
                for t in ts:
                    t.join()
            while not ts_res.empty():
                ret = ts_res.get()
                if not ret[0]:
                    print ret[1][2]
                    raise ret[1][0]

        # --------------------------------------- Calculate finishing times ----------------------------------
        job_finish = []         # When each job finishes -> register output files(s)

        # When jobs are finished for dataset
        sub_ds_names = []
        max_job_completion = 0
        for ds in sub_dss:
            dis_completion = time.time()
            # ds[0] = sub-ds name(s), ds[1] = number of jobs, ds[2] = computing RSE, ds[3] = task type
            sub_ds_names.append(ds[0]['name'])
            if create_dis_ds:
                dis_completion += gauss(**file_transfer_duration)  # Determines the time it takes to move all files to the target RSE
            for i in xrange(ds[1]):  # Determine the finishing time of each job using again a gaussian distribution
                job_completion = dis_completion + gauss(**output['duration_job'])
                if job_completion > max_job_completion:
                    max_job_completion = job_completion

                #out = ds[0] if create_sub_ds else final_dss.keys()  # Each output goes directly in the final output dataset
                if create_sub_ds:
                    job_finish.append((job_completion, [{'scope': 'Manure', 'name': ds[0]['name']}, ds[2], ds[3]]))
                else:
                    job_finish.append((job_completion, [{'scope': output['scope'], 'name': ds[0]['name']}, ds[2], ds[3]]))
            max_job_completion += 10  # Note: Triggers FINISH_TASK some time later to avoid conflicts

        if not create_sub_ds:
            sub_ds_names = []  # Empty list of sub datasets to avoid data moving when task is finished

        if create_dis_ds:
            task_finish = (max_job_completion + gauss(**file_transfer_duration), (output['scope'], final_dss), sub_ds_names, task_type)  # Again, adding 5 seconds for safety
        else:
            task_finish = (max_job_completion + 10, (output['scope'], final_dss), sub_ds_names, task_type)  # Again, adding 60 seconds for safety
        monitor.record_counter('panda.tasks.%s.number_job' % task_type, len(job_finish))  # Reports the number of jobs spawned from the given task
        print 'Created %s jobs' % job_count
        return {'job_finish': job_finish, 'task_finish': [task_finish]}

    def add_files_ds(self, client, ds, files_in_ds, ret=None):
        if not client:
            client = Client(account='panda')
        try:
            with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
                client.add_files_to_dataset(scope=ds['scope'], name=ds['name'], files=ds['dids'])
        except:
            e = sys.exc_info()
            if ret:
                ret.put((False, e))
        if ret:
            ret.put((True, None))

    #def add_repl_rule(self, client, dsns, rse):
    #    with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(dsns))]):
    #        client.add_replication_rule(dsns, copies=1, rse_expression=rse,
    #                                    grouping='DATASET', account='panda')

    def CREATE_TASK_input(self, ctx):
        # Select input DS from file provided by Cedric using observed age distribution from Thomas
        # Select task type
        task_type = choice(ctx.task_distribution)
        ret = {'input': ctx.tasks[task_type]['input'],
               'output': ctx.tasks[task_type]['output'],
               'task_type': task_type,
               'rses': [ctx.rses[i] for i in sample(xrange(len(ctx.rses)), 4)],
               'target_rse': choice(ctx.rses),
               'file_transfer_duration': ctx.file_transfer_duration,
               'jobs_per_dis': ctx.jobs_per_dis
               }
        input_ds = self.select_input_ds(task_type, ctx)
        ret['input']['ds_name'] = input_ds[1]
        ret['input']['scope'] = input_ds[0]
        #ret['input']['ds_name'] = 'd320d3f3703d42dfaaf9f413ed4f9bb9'
        #ret['input']['scope'] = 'mock'

        if task_type.split(',')[0] == 'user':
            user = choice(ctx.users)
            ret['output']['scope'] = 'user.%s' % user
            ret['output']['account'] = user
        else:
            ret['output']['scope'] = input_ds[0]
            ret['output']['account'] = 'panda'
        ret['bulk'] = ctx.bulk == 'True'
        ret['threads'] = ctx.threads == 'True'
        return ret

    def CREATE_TASK_output(self, ctx, output):
        for job in output['job_finish']:
            ctx.job_queue.put(job)
        for task in output['task_finish']:
            ctx.task_queue.put(task)

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        monitor.record_counter('panda.jobs.finished', len(jobs))
        client = Client(account='panda')

        # Group jobs by sub - dataset
        subs = dict()
        for job in jobs:
            dsn = '%s:%s' % (job['sub_ds']['scope'], job['sub_ds']['name'])
            if dsn not in subs.keys():
                subs[dsn] = [0, job['rse'], job['task_type']]  # Note: one sub ds is always exactly on one rse and task type
            subs[dsn][0] += 1

        print '== PanDA: Finish jobs (%s): %s for %s sub - datasets' % (job['task_type'], len(jobs), len(subs))
        ts = list()
        ts_res = Queue()
        for ds in subs:
            if threads == 'True':
                t = threading.Thread(target=self.register_replica, kwargs={'client': None, 'dsn': {'scope': ds.split(':')[0], 'name': ds.split(':')[1]},
                                                                           'rse': subs[ds][1], 'jobs': subs[ds][0], 'task_type': subs[ds][2], 'ret': ts_res})
                t.start()
                ts.append(t)
            else:
                self.register_replica(client, ds, subs[ds][1], subs[ds][0], subs[ds][2])
        if threads == 'True':
            for t in ts:
                t.join()
        while not ts_res.empty():
            ret = ts_res.get()
            if not ret[0]:
                print ret[1][2]
                raise ret[1][0]

    def register_replica(self, client, dsn, rse, jobs, task_type, ret=None):
        files = list()
        if not client:
            client = Client(account='panda')
        for i in xrange(jobs):
            fn = uuid()
            for ext in ['out', 'log']:
                files.append({'scope': dsn['scope'], 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
        now = time.time()
        try:
            with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
                client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=files, rse=rse)
            monitor.record_counter('panda.tasks.%s.replicas' % task_type, len(files))  # Reports the creation of a new replica (including log files) fof the given task type
        except:
            e = sys.exc_info()
            g_sem.acquire()
            print '-' * 80
            print 'Failed after %s seconds' % (time.time() - now)
            print '%s:%s' % (dsn['scope'], dsn['name'])
            print files
            print '-' * 80
            g_sem.release()
            if ret:
                ret.put((False, e))
        if ret:
            ret.put((True, None))

    def FINISH_JOB_input(self, ctx):
        now = time.time()
        jobs = []
        while True:  # Job is finished by now
            try:
                job = ctx.job_queue.get_nowait()
            except Empty:
                break
            if job[0] > now:
                ctx.job_queue.put(job)
                break
            jobs.append({'sub_ds': job[1][0], 'rse': job[1][1], 'task_type': job[1][2]})
            ctx.job_queue.task_done()
        if len(jobs):
            return {'jobs': jobs, 'threads': ctx.threads}
        else:
            return None

    @UCEmulator.UseCase
    def FINISH_TASK(self, tasks, threads):
        print '== PanDA: Finish tasks: %s' % len(tasks)
        monitor.record_counter('panda.tasks.finished', len(tasks))
        client = Client(account='panda')
        ts = list()
        for task in tasks:
            task_type = task['task_type']
            if task_type.startswith('user'):
                dsn = '%s.%s' % (task['output_ds'][1].keys()[0], 'user')
                with monitor.record_timer_block('panda.close'):
                    client.close(scope=task['output_ds'][0], name=dsn)

            # -------------- Group sub datasets to their related output datasets ----------------------------------------------
            for out_ds in task['output_ds'][1]:  # Iterates over every output - type of the task
                sub_dss = list()
                for sub_ds in task['sub_dss']:
                    if sub_ds.endswith(out_ds):  # Checks if the sub dataset is realted to the current output dataset
                        sub_dss.append(sub_ds)
                if threads == 'True':
                    t = threading.Thread(target=self.fin_task, kwargs={'client': None, 'task': {'sub_dss': sub_dss, 'output_ds': [task['output_ds'][0], out_ds]},
                                                                       'task_type': task_type, 'threads': threads})
                    t.start()
                    ts.append(t)
                else:
                    self.fin_task(client, {'sub_dss': sub_dss, 'output_ds': [task['output_ds'][0], out_ds]}, task_type, threads)
        if threads == 'True':
            for t in ts:
                t.join()

    def fin_task(self, client, task, task_type, threads):
        files = list()
        ts = list()
        if not client:
            client = Client(account='panda')
        sem = threading.Semaphore()
        for sub_ds in task['sub_dss']:
            if threads == 'True':
                t = threading.Thread(target=self.aggregate_input, kwargs={'client': None, 'source_ds': sub_ds, 'files': files, 'sem': sem})
                t.start()
                ts.append(t)
            else:
                self.aggregate_input(client, sub_ds, files)
        if threads == 'True':
            for t in ts:
                t.join()
        user = task_type.startswith('user')
        monitor.record_counter('panda.tasks.%s.output_ds_size' % task_type, len(files))  # Reports the number of files added to the output dataset
        print '== PanDA: Adding %s (user: %s) files to %s:%s' % (len(files), user, task['output_ds'][0], task['output_ds'][1])
        if not len(files):
            monitor.record_counter('panda.tasks.EmptySubDatasets', 1)
        else:
            for ext in ['log', 'out']:
                dsn = '%s.%s' % (task['output_ds'][1], ext)
                cf = list()
                for f in files:
                    if f['name'].endswith(ext):
                        cf.append(f)
                with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
                    client.add_files_to_dataset(scope=task['output_ds'][0], name=dsn, files=cf)
            with monitor.record_timer_block('panda.close'):
                client.close(scope=task['output_ds'][0], name=dsn)

    def aggregate_input(self, client, source_ds, files, sem=None):
        now = time.time()
        if not client:
            client = Client(account='panda')
        with monitor.record_timer_block('panda.list_files'):
            fs = [f for f in client.list_files(scope='Manure', name=source_ds)]
        if not len(fs):
            monitor.record_counter('panda.tasks.EmptySubDataset', 1)
            return
        monitor.record_timer('panda.list_files.normalized', (time.time() - now) / len(fs))
        if sem is None:
            files += fs
        else:
            sem.acquire()
            files += fs
            sem.release()

    def FINISH_TASK_input(self, ctx):
        now = time.time()
        tasks = []
        while True:  # Job is finished by now
            try:
                task = ctx.task_queue.get_nowait()
            except Empty:
                break
            if task[0] > now:
                ctx.task_queue.put(task)
                break
            tasks.append({'output_ds': task[1], 'sub_dss': task[2], 'task_type': task[3]})
            ctx.task_queue.task_done()
        if len(tasks):
            return {'tasks': tasks, 'threads': ctx.threads}
        else:
            return None

    def QUEUE_OBSERVER(self):
        pass  # WIll never be executed, only here for sematic reasons

    def QUEUE_OBSERVER_input(self, ctx):
        self.inc('panda.tasks.queue', ctx.task_queue.qsize())
        self.inc('panda.jobs.queue', ctx.job_queue.qsize())
        print '== PanDA: Task-Queue: %s / Job-Queue: %s' % (ctx.task_queue.qsize(), ctx.job_queue.qsize())
        return None  # Indicates that no further action is required

    def setup(self, ctx):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """
        # As long as there is no database filler, one dataset and n files are created here
        ctx.job_queue = PriorityQueue()
        ctx.task_queue = PriorityQueue()
        ctx.input_files = {}

        client = Client(account='panda')
        ctx.users = list()
        try:
            for a in client.list_accounts():
                if a['type'] == 'USER':
                    ctx.users.append(a['account'])
        except Exception, e:
            print '!! ERROR !! Unable to read registered users: %s' % e
            ctx.users = ['ralph', 'thomas', 'martin', 'mario', 'cedric', 'vincent', 'luc', 'armin']
            for u in ctx.users:
                try:
                    client.add_account(u, 'USER')
                except Exception, e:
                    pass
                try:
                    client.add_scope(u, 'USER')
                except Exception, e:
                    pass
        try:
            client.add_account('panda', 'SERVICE')
            print 'Account added'
        except Exception, e:
            pass
        try:
            client.add_scope('panda', 'Manure')
            print 'scope added'
        except Exception, e:
            pass
        try:
            client.add_scope('panda', 'OutputGrove')
            print 'scope added'
        except Exception, e:
            pass

        ctx.rses = []
        try:
            for rse in client.list_rses():
                if rse['deterministic']:
                    ctx.rses.append(rse['rse'])
        except Exception, e:
            print 'Failed reading RSEs: %s' % e
            ctx.rses = ['MOCK_%03d' % (i + 100) for i in xrange(500)]

        # TODO: Could be done in a more elegant way I guess
        ctx.task_distribution = list()
        for task in ctx.tasks:
            for i in xrange(ctx.tasks[task]['probability']):
                ctx.task_distribution.append(task)

    def update_ctx(self, key_chain, value):
        ctx = super(UseCaseDefinition, self).update_ctx(key_chain, value)
        # Update task distribution
        if key_chain[0] == 'tasks' and key_chain[-1] == 'probability':
            print '== PanDA: Updating task distribution'
            # TODO: Could be done in a more elegant way I guess
            task_distribution = list()
            for task in ctx.tasks:
                for i in xrange(ctx.tasks[task]['probability']):
                    task_distribution.append(task)
            ctx.task_distribution = task_distribution

    def select_input_ds(self, task_type, ctx):
        dist_prefix = '/data/mounted_hdfs/user/serfon/listdatasets2/'

        ds = None
        success = False
        while not success:
            try:
                # Derive dataset age
                cluster = random()
                i = 0
                distr = ctx.input_distribution
                for age_cluster in distr:
                    if cluster < age_cluster[1]:
                        break
                    i += 1

                if i == 0:  # First element
                    age = randint(0, distr[0][0])
                elif i == len(distr):  # Last element
                    age = randint(distr[i - 1][0] + 1, distr[-1][0])
                else:  # Some in between element
                    age = randint(distr[i - 1][0] + 1, distr[i][0])

                # Select random input ds-type
                input_ds_type = choice(ctx.tasks[task_type]['input']['meta'])

                # Select random dataset from file with according age
                date = datetime.date.today() - datetime.timedelta(days=age)
                dist_file = '%s/%02d/%02d/listfiles.%s.%s.txt' % (date.year, date.month, date.day, input_ds_type.split('.')[0], input_ds_type.split('.')[1])
                path = dist_prefix + dist_file
                if dist_file not in ctx.input_files:  # File is used for the first time
                    ctx.input_files[dist_file] = (os.path.getsize(path) / 287)
                if ctx.input_files[dist_file] is False:  # It is known that this file doen't exists
                    continue
                offset = randint(0, ctx.input_files[dist_file] - 1) * 287  # -1 due to index origin zero
                with open(path) as f:
                    f.seek(offset)
                    ds = f.readline().split()
                success = True
            except Exception, e:
                ctx.input_files[dist_file] = False  # Remeber that this file doen't exist
                print '!! ERROR !! Can read dataset name from distribution file: %s' % e
        return ds
