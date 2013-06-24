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
import traceback

from Queue import PriorityQueue, Empty
from random import choice, gauss, sample, random, randint

from rucio.client import Client
from rucio.common.utils import generate_uuid as uuid
from rucio.rse import rsemanager
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, target_rse, rses, input, output, file_transfer_duration, bulk):
        create_dis_ds = (input['dis_ds_probability'] > random())
        client = Client()

        files = [f for f in self.time_it(fn=client.list_replicas, kwargs={'scope': input['scope'], 'name': input['ds_name']})]

        print '%s using %s file (dis-ds: %s)' % (task_type, len(files), create_dis_ds)
        # Determine metadata for output dataset
        meta = dict()
        try:
            meta_i = self.time_it(fn=client.get_metadata, kwargs={'scope': input['scope'], 'name': input['ds_name']})
        except Exception, e:
            print '!! ERROR !! Getting metadata from input dataset failed: %s' % e
            meta_i = {'stream_name': None, 'run_number': 0, 'project': None}

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
        self.time_it(fn=client.add_container, kwargs={'scope': output['scope'], 'name': 'cnt_%s' % final_ds, 'lifetime': output['lifetime'],
                                                      'rules': [{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}]}
                     )
        try:
            self.time_it(fn=client.add_dataset, kwargs={'scope': output['scope'], 'name': final_ds, 'meta': meta})
            print 'Final DS: %s:%s' % (output['scope'], final_ds)
        except Exception, e:
            print '!! ERROR !! Failed creating output dataset: %s' % e
            return False
        self.time_it(fn=client.add_datasets_to_container, kwargs={'scope': output['scope'], 'name': 'cnt_%s' % final_ds, 'dsns': [{'scope': output['scope'], 'name': final_ds}]})

        # List files in input dataset and create _dis datasets (input for 20 jobs per DS)
        sub_dss = []
        files_in_ds = []
        dis_ds = None
        sub_ds = None
        computing_rse = None

        file_keys = list()  # Should be removed if the retruned dict from list_replicas is changed
        inserts = list()

        for f in files:
            if len(files_in_ds) == (20 * input['number_of_inputfiles_per_job']):
                if create_dis_ds:
                    if bulk:
                        inserts.append({'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400,
                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                        'dids': files_in_ds})  # Create DIS-Datasets
                        print 'Prep dis: %s' % (dis_ds)
                    else:
                        self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'files': files_in_ds})
                        print 'Fill dis: %s' % (dis_ds)
                sub_dss.append((sub_ds, 20, computing_rse))
                files_in_ds = []
            if len(files_in_ds) == 0:  # Create dis - dataset and sub - dataset
                id = uuid()
                dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
                sub_ds = '%s_SUB_%s' % (input['ds_name'], id)
                computing_rse = choice(rses)
                if bulk:
                    inserts.append({'scope': 'Manure', 'name': sub_ds, 'lifetime': 86400, 'dids': [],
                                   'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                                             {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                                             ]})  # Create SUB-Datasets
                    print 'Prep sub_ds: %s' % sub_ds
                else:
                    if create_dis_ds:
                        self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400, 'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}]})  # Create DIS-Datasets
                        print 'Create dis_ds: %s' % dis_ds
                    self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': sub_ds, 'lifetime': 86400,
                                                                'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                                                                          {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                                                                          ]})  # Create SUB-Datasets
                    print 'Create sub_ds: %s' % sub_ds

            # Should be changed when the response from list_replicas is updated
            if '%s:%s' % (f['scope'], f['name']) not in file_keys:
                file_keys.append('%s:%s' % (f['scope'], f['name']))
                files_in_ds.append({'scope': f['scope'], 'name': f['name'], 'bytes': f['bytes']})

        # Last DIS-DS: Add files to dis - dataset and replication rule
        if len(files_in_ds):
            if create_dis_ds:
                if bulk:
                    inserts.append({'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400,
                                    'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                    'dids': files_in_ds})  # Create DIS-Datasets
                    print 'Prep remaining dis: %s' % dis_ds
                else:
                    try:
                        self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'files': files_in_ds})
                        print 'Fill remaining %s to dis: %s' % (len(files_in_ds), dis_ds)
                    except Exception, e:
                        print '!! ERROR !! Failed adding files to dis-ds %s: %s' % (dis_ds, e)
            sub_dss.append((sub_ds, int(round(len(files_in_ds) / input['number_of_inputfiles_per_job'])), computing_rse))

        # Bulk inserting all dis- and sub datasets (including files)
        if bulk:
            print '-' * 100
            print inserts
            try:
                self.time_it(fn=client.attach_dids_to_dids, kwargs={'attachments': inserts})
            except Exception, e:
                print e
                print traceback.format_exc()
            print '-' * 100

        # Calculate times
        job_finish = []         # When each job finishes -> register output files(s)
        now = time.time()

        # When jobs are finished for dataset
        sub_ds_names = []
        for ds in sub_dss:
            # ds[0] = sub-ds name, ds[1] = number of jobs, ds[2] = computing RSE
            sub_ds_names.append(ds[0])
            dis_completion = now
            if create_dis_ds:
                dis_completion += gauss(**file_transfer_duration)  # Determines the time it takes to move all files to the target RSE
            max_job_completion = 0
            for i in xrange(ds[1]):  # Determine the finishing time of each job using again a gaussian distribution
                job_completion = dis_completion + gauss(**output['duration_job'])
                if job_completion > max_job_completion:
                    max_job_completion = job_completion
                job_finish.append((job_completion, [ds[0], ds[2]]))
            max_job_completion += 5  # Note: The +5 tiriggers FINISH_TASK 1 second after the last job is completed. This helps to avoid that not all files are already registered in the sub-dataset due to overlapping Hz numbers
        if create_dis_ds:
            task_finish = (max_job_completion + gauss(**file_transfer_duration), (output['scope'], final_ds), sub_ds_names)  # Again, adding 5 seconds for safety
        else:
            task_finish = (max_job_completion + 5, (output['scope'], final_ds), sub_ds_names)  # Again, adding 5 seconds for safety
        return {'job_finish': job_finish, 'task_finish': task_finish}

    def CREATE_TASK_input(self, ctx):
        # Select input DS from file provided by Cedric using observed age distribution from Thomas
        # Select task type
        task_type = choice(ctx.task_distribution)
        self.inc('panda.tasks.%s' % task_type, ctx.task_queue.qsize())
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
            ret['output']['scope'] = 'OutputGrove'
            ret['output']['account'] = 'panda'
        ret['bulk'] = ctx.bulk == 'True'
        return ret

    def CREATE_TASK_output(self, ctx, output):
        for job in output['job_finish']:
            ctx.job_queue.put(job)
        if len(output['task_finish']):
            ctx.task_queue.put(output['task_finish'])

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        self.inc('panda.jobs.finished', len(jobs))
        print 'Finish jobs: %s' % len(jobs)
        client = Client()
        mgr = rsemanager.RSEMgr()
        if threads == 'True':
            for job in jobs:
                    t = threading.Thread(target=self.register_replica, kwargs={'client': client, 'dsn': job['sub_ds'], 'rse': job['rse'], 'mgr': mgr})
                    t.start()
        else:
            subs = dict()
            for job in jobs:
                if job['sub_ds'] not in subs.keys():
                    subs[job['sub_ds']] = [0, '']
                subs[job['sub_ds']][0] += 1
                subs[job['sub_ds']][1] = job['rse']
            for ds in subs:
                files = list()
                for i in xrange(subs[ds][0]):
                    fn = uuid()
                    for ext in ['out', 'log']:
                        files.append({'scope': 'Manure', 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
                self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': ds, 'files': files, 'rse': subs[ds][1]})

    def register_replica(self, client, dsn, rse, mgr):
        fn = 'Bamboo_%s' % uuid()
        files = list()
        for ext in ['out', 'log']:
            files.append({'scope': 'InputGrove', 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
        try:
            self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dsn, 'files': files, 'rse': rse})
        except Exception, e:
            print '!! ERROR !! Finish job: %s' % e

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
        self.inc('panda.tasks.finished', len(tasks))
        print 'Finish tasks: %s' % len(tasks)
        client = Client()
        threads = list()
        for task in tasks:
            for sub_ds in task['sub_dss']:
                if threads == 'True':
                    t = threading.Thread(target=self.aggregate_output, kwargs={'client': client, 'source_ds': sub_ds, 'target_ds': task['output_ds']})
                    t.start()
                    threads.append(t)
                else:
                    self.aggregate_output(client, sub_ds, task['output_ds'])
        if threads == 'True':
            for t in threads:
                t.join()
        for task in tasks:
            self.time_it(fn=client.close, kwargs={'scope': task['output_ds'][0], 'name': task['output_ds'][1]})

    def aggregate_output(self, client, source_ds, target_ds):
        files = [f for f in self.time_it(fn=client.list_files, kwargs={'scope': 'Manure', 'name': source_ds})]
        self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': target_ds[0], 'name': target_ds[1], 'files': files})

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
                    print e
                try:
                    client.add_scope(u, 'USER')
                except Exception, e:
                    print e
        try:
            client.add_account('panda', 'SERVICE')
            print 'Account added'
        except Exception, e:
            print e
        try:
            client.add_scope('panda', 'Manure')
            print 'scope added'
        except Exception, e:
            print e
        try:
            client.add_scope('panda', 'OutputGrove')
            print 'scope added'
        except Exception, e:
            print e

        ctx.rses = []
        try:
            for rse in client.list_rses():
                if rse['deterministic']:
                    ctx.rses.append(rse['rse'])
        except Exception, e:
            print 'Failed reading RSEs: %s' % e
            ctx.rses = ['MOCK_642', 'MOCK_641', 'MOCK_640', 'MOCK_639', 'MOCK_638', 'MOCK_637']

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
                dist_file = '%s/%02d/%02d/listfiles_%s_%s.txt' % (date.year, date.month, date.day, input_ds_type.split('.')[0], input_ds_type.split('.')[1])
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
