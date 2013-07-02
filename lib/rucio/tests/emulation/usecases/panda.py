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
import time

from Queue import PriorityQueue, Empty
from random import choice, gauss, sample, random, randint

from rucio.client import Client
from rucio.common.utils import generate_uuid as uuid
from rucio.core import monitor
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, target_rse, rses, input, output, file_transfer_duration, bulk, threads):
        create_dis_ds = (input['dis_ds_probability'] > random())
        #client = Client(account='panda')
        client = Client()

        now = time.time()
        with monitor.record_timer_block('panda.list_replicas'):
            replicas = [f for f in client.list_replicas(scope=input['scope'], name=input['ds_name'])]
        delta = time.time() - now
        if len(replicas) == 0:
            print '== PanDA: Empty input dataset provided'
            monitor.record_counter('panda.tasks.EmptyInputDataset', 1)
            return {'job_finish': [], 'task_finish': []}
        monitor.record_timer('panda.list_replicas.normalized', delta / len(replicas))

        # Should be changed when the response from list_replicas is updated
        files = list()
        file_keys = list()
        for r in replicas:
            if '%s:%s' % (f['scope'], f['name']) not in file_keys:
                file_keys.append('%s:%s' % (f['scope'], f['name']))
                files.append({'scope': f['scope'], 'name': f['name'], 'bytes': f['bytes']})
        file_keys = None

        print '== PanDA: Create task  with %s files (dis: %s)' % (len(files), create_dis_ds)

        # Determine metadata for output dataset
        meta = dict()
        with monitor.record_timer_block('panda.get_metadata'):
            meta_i = client.get_metadata(scope=input['scope'], name=input['ds_name'])

        for key in ['stream_name', 'run_number', 'project']:
            if meta_i[key] is not None:
                meta[key] = meta_i[key]
            else:
                meta[key] = 'NotGivenByInput'

        meta['guid'] = uuid()
        meta['version'] = uuid()
        meta['datatype'] = output['meta']['datatype']
        meta['prod_step'] = output['meta']['prod_step']
        # Create final output - dataset
        final_ds = '.'.join([meta['project'], str(meta['run_number']), meta['stream_name'], meta['prod_step'], meta['datatype'], meta['version']])
        with monitor.record_timer_block('panda.add_container'):
            client.add_container(scope=output['scope'], name='cnt_%s' % final_ds, lifetime=output['lifetime'],
                                 rules=[{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}])
            # As rules are currently ignored in the add_ - methods they are added explicetly here. This should be removed when rules are considered during adding dataset
        with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', 1)]):
            client.add_replication_rule([{'scope': output['scope'], 'name': 'cnt_%s' % final_ds}], copies=1, rse_expression=target_rse,
                                        grouping='DATASET', lifetime=output['lifetime'], account=output['account'])
        with monitor.record_timer_block('panda.add_dataset'):
            client.add_dataset(scope=output['scope'], name=final_ds, meta=meta)

        with monitor.record_timer_block('panda.add_datasets_to_container'):
            client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % final_ds, dsns=[{'scope': output['scope'], 'name': final_ds}])

        # List files in input dataset and create _dis datasets (input for 20 jobs per DS)
        sub_dss = []
        files_in_ds = []
        dis_ds = None
        sub_ds = None
        computing_rse = None

        inserts_dis = list()
        inserts_sub = list()

        for f in files:
            if len(files_in_ds) == (20 * input['number_of_inputfiles_per_job']):
                if create_dis_ds:
                    if bulk:
                        inserts_dis.append({'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400,
                                            'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                            'dids': files_in_ds})  # Create DIS-Datasets
                    else:
                        with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
                            client.add_files_to_dataset(scope='Manure', name=dis_ds, files=files_in_ds)
                sub_dss.append((sub_ds, 20, computing_rse))
                files_in_ds = []
            if len(files_in_ds) == 0:  # Create dis - dataset and sub - dataset
                id = uuid()
                dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
                sub_ds = '%s_SUB_%s' % (input['ds_name'], id)
                computing_rse = choice(rses)
                if bulk:
                    inserts_sub.append({'scope': 'Manure', 'name': sub_ds, 'lifetime': 86400, 'dids': [],
                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                                                  {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                                                  ]})  # Create SUB-Datasets
                else:
                    if create_dis_ds:
                        with monitor.record_timer_block('panda.add_dataset'):
                            client.add_dataset(scope='Manure', name=dis_ds, lifetime=86400,
                                               rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}])  # Create DIS-Datasets
                            # As rules are currently ignored in the add_ - methods they are added explicetly here. This should be removed when rules are considered during adding dataset
                        with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule', 1)]):
                            client.add_replication_rule([{'scope': 'Manure', 'name': dis_ds}], copies=1, rse_expression=computing_rse,
                                                        grouping='DATASET', lifetime=86400, account='panda')
                    with monitor.record_timer_block('panda.add_dataset'):
                        client.add_dataset(scope='Manure', name=sub_ds, lifetime=86400,
                                           rules=[{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rse), 'grouping': 'DATASET'}])  # Create SUB-Datasets
                        # As rules are currently ignored in the add_ - methods they are added explicetly here. This should be removed when rules are considered during adding dataset
                    with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule', 1)]):
                        client.add_replication_rule([{'scope': 'Manure', 'name': sub_ds}], copies=2, rse_expression='%s|%s' % (computing_rse, target_rse),
                                                    grouping='DATASET', lifetime=86400, account='panda')
            files_in_ds.append(f)

        # Last DIS-DS: Add files to dis - dataset and replication rule
        if len(files_in_ds):
            if create_dis_ds:
                if bulk:
                    inserts_dis.append({'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400,
                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                        'dids': files_in_ds})  # Create DIS-Datasets
                else:
                    with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
                        client.add_files_to_dataset(scope='Manure', name=dis_ds, files=files_in_ds)
            nof = int(round(len(files_in_ds) / input['number_of_inputfiles_per_job']))
            if not nof:
                nof = 1  # needed for datasets with 1 file but jobs needs mor than one input file
            sub_dss.append((sub_ds, nof, computing_rse))

        # Bulk inserting all dis- and sub datasets (including files)
        if bulk:
            no_files = 0
            rses = dict(list())
            # Add all dis and sub datasets
            datasets = inserts_dis + inserts_sub
            with monitor.record_timer_block(['panda.add_datasets', ('panda.add_datasets.normalized', len(datasets))]):
                client.add_datasets(datasets)

            # Fill dis - datasets with files
            #with monitor.record_timer_block(['panda.attach_dids_to_dids', ('panda.attach_dids_to_dids.normalized_datasets', len(inserts)), ('panda.attach_dids_to_dids.normalized_files', no_files)]):
            #   client.attach_dids_to_dids(attachments=inserts)
            ts = list()
            for ds in inserts_dis:
                if threads == 'True':
                    t = threading.Thread(target=self.add_files_ds, kwargs={'client': client, 'ds': ds, 'files_in_ds': files_in_ds})
                    t.start()
                    ts.append(t)
                else:
                    self.add_files_ds(client, ds, files_in_ds)
            if threads == 'True':
                for t in ts:
                    t.join()

            # Group datasets by RSE to bulk-add rule for computing rse
            for ds in datasets:
                rses.setdefault(ds['rules'][0]['rse_expression'], list()).append({'scope': ds['scope'], 'name': ds['name']})
                no_files += len(ds['dids'])
            ts = list()
            for computing_rse in rses:
                if threads == 'True':
                    t = threading.Thread(target=self.add_repl_rule, kwargs={'client': client, 'dsns': rses[computing_rse], 'rse': computing_rse})
                    t.start()
                    ts.append(t)
                else:
                    self.add_repl_rule(client, rses[computing_rse], computing_rse)
            if threads == 'True':
                for t in ts:
                    t.join()

            # Add additional rule for sub datasets ending up on target RSE
            with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(inserts_sub))]):
                client.add_replication_rule(inserts_sub, copies=1, rse_expression=target_rse,
                                            grouping='DATASET', account='panda')

        # Calculate times
        job_finish = []         # When each job finishes -> register output files(s)

        # When jobs are finished for dataset
        sub_ds_names = []
        max_job_completion = 0
        dis_completion = time.time()
        for ds in sub_dss:
            # ds[0] = sub-ds name, ds[1] = number of jobs, ds[2] = computing RSE
            sub_ds_names.append(ds[0])
            if create_dis_ds:
                dis_completion += gauss(**file_transfer_duration)  # Determines the time it takes to move all files to the target RSE
            for i in xrange(ds[1]):  # Determine the finishing time of each job using again a gaussian distribution
                job_completion = dis_completion + gauss(**output['duration_job'])
                if job_completion > max_job_completion:
                    max_job_completion = job_completion
                job_finish.append((job_completion, [ds[0], ds[2]]))
            max_job_completion += 120  # Note: Triggers FINISH_TASK some time later to avoid conflicts
        if create_dis_ds:
            task_finish = (max_job_completion + gauss(**file_transfer_duration), (output['scope'], final_ds), sub_ds_names)  # Again, adding 5 seconds for safety
        else:
            task_finish = (max_job_completion + 120, (output['scope'], final_ds), sub_ds_names)  # Again, adding 60 seconds for safety
        return {'job_finish': job_finish, 'task_finish': [task_finish]}

    def add_files_ds(self, client, ds, files_in_ds):
        with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
            client.add_files_to_dataset(scope=ds['scope'], name=ds['name'], files=ds['dids'])

    def add_repl_rule(self, client, dsns, rse):
        with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(dsns))]):
            client.add_replication_rule(dsns, copies=1, rse_expression=rse,
                                        grouping='DATASET', account='panda')

    def CREATE_TASK_input(self, ctx):
        # Select input DS from file provided by Cedric using observed age distribution from Thomas
        # Select task type
        task_type = choice(ctx.task_distribution)
        ret = {'input': ctx.tasks[task_type]['input'],
               'output': ctx.tasks[task_type]['output'],
               'task_type': task_type,
               'rses': [ctx.rses[i] for i in sample(xrange(len(ctx.rses)), 4)],
               'target_rse': choice(ctx.rses),
               'file_transfer_duration': ctx.file_transfer_duration
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
        #client = Client(account='panda')
        client = Client()

        # Group jobs by sub - dataset
        subs = dict()
        for job in jobs:
            if job['sub_ds'] not in subs.keys():
                subs[job['sub_ds']] = [0, job['rse']]  # Note: one sub ds is always exactly on one rse
            subs[job['sub_ds']][0] += 1

        print '== PanDA: Finish jobs: %s for %s sub - datasets' % (len(jobs), len(subs))
        ts = list()
        for ds in subs:
            if threads == 'True':
                t = threading.Thread(target=self.register_replica, kwargs={'client': client, 'dsn': ds, 'rse': subs[ds][1], 'jobs': subs[ds][0]})
                t.start()
                ts.append(t)
            else:
                self.register_replica(client, ds, subs[ds][1], subs[ds][0])
        if threads == 'True':
            for t in ts:
                t.join()

    def register_replica(self, client, dsn, rse, jobs):
        files = list()
        for i in xrange(jobs):
            fn = uuid()
            for ext in ['out', 'log']:
                files.append({'scope': 'Manure', 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
        with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
            client.add_files_to_dataset(scope='Manure', name=dsn, files=files, rse=rse)

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
            jobs.append({'sub_ds': job[1][0], 'rse': job[1][1]})
            ctx.job_queue.task_done()
        if len(jobs):
            return {'jobs': jobs, 'threads': ctx.threads}
        else:
            return None

    @UCEmulator.UseCase
    def FINISH_TASK(self, tasks, threads):
        monitor.record_counter('panda .tasks.finished', len(tasks))
        print '== PanDA: Finish tasks: %s' % len(tasks)
        #client = Client(account='panda')
        client = Client()
        ts = list()
        for task in tasks:
            if threads == 'True':
                t = threading.Thread(target=self.fin_task, kwargs={'client': client, 'task': task, 'threads': threads})
                t.start()
                ts.append(t)
            else:
                self.fin_task(client, task, threads)
        if threads == 'True':
            for t in ts:
                t.join()

    def fin_task(self, client, task, threads):
        files = list()
        ts = list()
        sem = threading.Semaphore()
        for sub_ds in task['sub_dss']:
            if threads == 'True':
                t = threading.Thread(target=self.aggregate_input, kwargs={'client': client, 'source_ds': sub_ds, 'files': files, 'sem': sem})
                t.start()
                ts.append(t)
            else:
                self.aggregate_input(client, sub_ds, files)
        if threads == 'True':
            for t in ts:
                t.join()
        print '== PanDA: Adding %s files to output dataset' % len(files)
        if not len(files):
            monitor.record_counter('panda.tasks.EmptySubDatasets', 1)
        else:
            with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
                client.add_files_to_dataset(scope=task['output_ds'][0], name=task['output_ds'][1], files=files)
        with monitor.record_timer_block('panda.close'):
            client.close(scope=task['output_ds'][0], name=task['output_ds'][1])

    def aggregate_input(self, client, source_ds, files, sem=None):
        now = time.time()
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
            tasks.append({'output_ds': task[1], 'sub_dss': task[2]})
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

        #client = Client(account='panda')
        client = Client()
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
        dist_prefix = '/data/mounted_hdfs/user/serfon/listdatasets/'

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
