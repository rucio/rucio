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
from rucio.rse import rsemanager
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, target_rse, rses, input, output, file_transfer_duration):
        create_dis_ds = (input['dis_ds_probability'] > random())
        print 'CREATE TASK: %s (dis-ds: %s)' % (task_type, create_dis_ds)
        print 'Using input ds: %s:%s' % (input['scope'], input['ds_name'])
        client = Client()

        meta = {'project': 'NoProjectDefined',
                'prod_step': 'NoProdstepDefined',
                'datatype': 'NoDatatypeDefined',
                'version': uuid()
                }
        meta.update({'run_number': 'NoRunNumberDefined', 'stream_name': 'NoStreamNameDefined'})

        # Determine metadata for output dataset
        try:
            #meta.update(client.get_metadata(scope=input['scope'], name=input['ds_name']))
            meta.update(self.time_it(fn=client.get_metadata, kwargs={'scope': input['scope'], 'name': input['ds_name']}))
        except Exception, e:
            print '!! ERROR !! Getting metadata from input dataset failed'  # : %s' % e
            pass
        meta.update(output['meta'])

        #for key in client.
        # Create final output - dataset
        final_ds = '.'.join([meta['project'], meta['run_number'], meta['stream_name'], meta['prod_step'], meta['datatype'], meta['version']])
        self.time_it(fn=client.add_container, kwargs={'scope': output['scope'], 'name': 'cnt_%s' % final_ds, 'lifetime': output['lifetime'],
                                                      'rules': [{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}]}
                     )
        #client.add_container(scope=output['scope'], name='cnt_%s' % final_ds, lifetime=output['lifetime'],
        #                     rules=[{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}]
        #                     )
        try:
            client.add_dataset(scope=output['scope'], name=final_ds, meta=meta)
        except Exception, e:
            print '!! ERROR !! Failed creating output dataset: %s' % e
            return {'job_finish': [], 'task_finish': []}
        #client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % final_ds, dsns=[{'scope': output['scope'], 'name': final_ds}])
        self.time_it(fn=client.add_datasets_to_container, kwargs={'scope': output['scope'], 'name': 'cnt_%s' % final_ds, 'dsns': [{'scope': output['scope'], 'name': final_ds}]})
        print 'Created output dataset: %s' % final_ds
        print 'Metadata for output dataset: %s' % meta

        # List files in input dataset and create _dis datasets (input for 20 jobs per DS)
        sub_dss = []
        files_in_ds = []
        dis_ds = None
        sub_ds = None
        computing_rse = None
        #for f in client.list_files(scope=input['scope'], name=input['ds_name']):
        for f in self.time_it(fn=client.list_files, kwargs={'scope': input['scope'], 'name': input['ds_name']}):
            if len(files_in_ds) == (20 * input['number_of_inputfiles_per_job']):
                if create_dis_ds:
                    #client.add_files_to_dataset(scope='Manure', name=dis_ds, files=files_in_ds)
                    self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'files': files_in_ds})
                sub_dss.append((sub_ds, 20, computing_rse))
                files_in_ds = []
            if len(files_in_ds) == 0:  # Create dis - dataset and sub - dataset
                id = uuid()
                dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
                sub_ds = '%s_SUB_%s' % (input['ds_name'], id)
                computing_rse = choice(rses)
                if create_dis_ds:
                    #client.add_dataset(scope='Manure', name=dis_ds, lifetime=86400, rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}])  # Create DIS-Datasets
                    self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400, 'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}]})  # Create DIS-Datasets
                #client.add_dataset(scope='Manure', name=sub_ds, lifetime=86400,
                #                   rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                #                          {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                #                          ]
                self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': sub_ds, 'lifetime': 86400,
                                                            'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                                                                      {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                                                                      ]})  # Create SUB-Datasets
            files_in_ds.append(f)

        if (not len(sub_dss)) and (not len(files_in_ds)):
            print '!! ERROR !! Empty input dataset provided'
        # Last DIS-DS: Add files to dis - dataset and replication rule
        if len(files_in_ds):
            id = uuid()
            dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
            sub_ds = '%s_SUB_%s' % (input['ds_name'], id)
            computing_rse = choice(rses)
            if create_dis_ds:
                #client.add_dataset(scope='Manure', name=dis_ds, lifetime=86400, rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}])  # Create DIS-Datasets
                #client.add_files_to_dataset(scope='Manure', name=dis_ds, files=files_in_ds)
                self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'lifetime': 86400, 'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}]})  # Create DIS-Datasets
                self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dis_ds, 'files': files_in_ds})
            #client.add_dataset(scope='Manure', name=sub_ds, lifetime=86400,
            #                   rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
            #                          {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
            #                          ]
            #                   )  # Create SUB-Datasets
            self.time_it(fn=client.add_dataset, kwargs={'scope': 'Manure', 'name': sub_ds, 'lifetime': 86400,
                                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'},
                                                                  {'account': 'panda', 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET'}
                                                                  ]})  # Create SUB-Datasets
            sub_dss.append((sub_ds, int(round(len(files_in_ds) / input['number_of_inputfiles_per_job'])), computing_rse))

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
        print 'Task successful created'
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
        #ret['input']['ds_name'] = ctx.ds_name
        #ret['input']['scope'] = 'InputGrove'

        if task_type == 'user':
            user = choice(ctx.users)
            ret['output']['scope'] = user
            ret['output']['account'] = user
        else:
            ret['output']['scope'] = 'OutputGrove'
            ret['output']['account'] = 'panda'
        return ret

    def CREATE_TASK_output(self, ctx, output):
        for job in output['job_finish']:
            ctx.job_queue.put(job)
        if len(output['task_finish']):
            ctx.task_queue.put(output['task_finish'])

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        print 'jobs finished: %s ' % len(jobs)
        self.inc('panda.jobs.finished', len(jobs))
        client = Client()
        mgr = rsemanager.RSEMgr()
        for job in jobs:
            if threads == 'True':
                t = threading.Thread(target=self.register_replica, kwargs={'client': client, 'dsn': job['sub_ds'], 'rse': job['rse'], 'mgr': mgr})
                t.start()
            else:
                self.register_replica(client, job['sub_ds'], job['rse'], mgr)

    def register_replica(self, client, dsn, rse, mgr):
        fn = 'Bamboo_%s' % uuid()
        files = list()
        for ext in ['out', 'log']:
            files.append({'scope': 'InputGrove', 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid()), 'events': 10}, 'rse': rse, 'bytes': 2048})
        try:
            #client.add_files_to_dataset(scope='Manure', name=dsn, files=files)
            self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': 'Manure', 'name': dsn, 'files': files})
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
        print 'tasks finished: %s ' % len(tasks)
        self.inc('panda.tasks.finished', len(tasks))
        client = Client()
        for task in tasks:
            for sub_ds in task['sub_dss']:
                if threads == 'True':
                    t = threading.Thread(target=self.aggregate_output, kwargs={'client': client, 'source_ds': sub_ds, 'target_ds': task['output_ds']})
                    t.start()
                else:
                    self.aggregate_output(client, sub_ds, task['output_ds'])

    def aggregate_output(self, client, source_ds, target_ds):
        files = list()
        #for f in client.list_files(scope='Manure', name=source_ds):
        for f in self.time_it(fn=client.list_files, kwargs={'scope': 'Manure', 'name': source_ds}):
            files.append(f)
        #client.add_files_to_dataset(scope=target_ds[0], name=target_ds[1], files=files)
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
        print '= Task / Job - Queue: %s / %s' % (ctx.task_queue.qsize(), ctx.job_queue.qsize())
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

        client = client = Client()
        ctx.users = ['ralph', 'thomas', 'martin', 'mario', 'cedric', 'vincent', 'luc', 'armin']
        for user in ctx.users:
            try:
                client.add_account(user, 'USER')
                client.add_scope(user, user)
            except Exception, e:
                pass

        # Create account 'Panda'

        #try:
        #    client.add_account('panda', 'SERVICE')
        #except Exception:
        #    pass
        ## Create scopes for input, output (temp and perm)
        #try:
        #    client.add_scope('panda', 'InputGrove')
        #except Exception:
        #    pass
        #try:
        #    client.add_scope('panda', 'OutputGrove')
        #except Exception:
        #    pass
        #try:
        #    client.add_scope('panda', 'Manure')
        #except Exception:
        #    pass
        #defaults = {'project': 'NoProjectDefined',
        #            'prod_step': 'NoProdstepDefined',
        #            'datatype': 'NoDatatypeDefined',
        #            'run_number': 'NoRunNumberDefined',
        #            'stream_name': 'NoStreamNameDefined'
        #            }
        #for k in defaults:
        #    try:
        #        client.add_value(k, defaults[k])
        #    except Exception, e:
        #        print '!! ERROR !! %s' % e
        #        pass
        # Create DS name
        success = True
        nf = 190
        while not success and nf:
            ctx.ds_name = 'Grove_%s' % uuid()
            client.add_dataset(scope='InputGrove', name=ctx.ds_name, meta={'prod_step': 'evgen', 'datatype': 'HITS'})
            print 'Dataset %s created' % ctx.ds_name
            ctx.rses = []
            for rse in client.list_rses():
                if rse['deterministic']:
                    ctx.rses.append(rse['rse'])
            rse_name = choice(ctx.rses)
            # Create dataset
            # Fill dataset with 100 files
            files = []
            for i in xrange(nf):
                name = 'Bamboo_%s' % uuid()
                #files.append({'scope': 'InputGrove', 'name': name, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid()), 'events': 10}, 'rse': rse_name, 'bytes': 2048})
                files.append({'scope': 'InputGrove', 'name': name, 'bytes': 12345L, 'adler32': '0cc737eb', 'rse': rse_name, 'bytes': 2048})
            # Register file replica to dataset
            now = time.time()
            print 'Adding %s files to DS' % nf
            try:
                client.add_files_to_dataset(scope='InputGrove', name=ctx.ds_name, files=files)
                fin = time.time()
                success = True
                count = 0
                for f in client.list_files('InputGrove', ctx.ds_name):
                    count += 1
                print 'Added %s (of %s) files successfuly in %s seconds' % (count, nf, fin - now)
            except Exception, e:
                print 'Failed after %s seconds' % (time.time() - now)
                nf -= 10

        # Request a list with all avaliable RSEs
        success = False
        ctx.rses = []
        while not success:
            try:
                for rse in client.list_rses():
                    if not rse['deleted'] and rse['deterministic']:
                        ctx.rses.append(rse['rse'])
                success = True
                print 'Imported %s RSEs' % len(ctx.rses)
            except Exception, e:
                print 'Failed requesteing RSEs from server'
                print e

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

                # Select random dataset from file with according age
                date = datetime.date.today() - datetime.timedelta(days=age)
                dist_file = '%s/%02d/%02d/listfiles.txt' % (date.year, date.month, date.day)
                #dist_file = '/data/mounted_hdfs/user/serfon/listdatasets/%s/%02d/%02d/listfiles.%s.%s.txt' % (date.year, date.month, date.day, task_type.split('.')[0], task_type.split('.')[1])
                path = dist_prefix + dist_file
                if dist_file not in ctx.input_files:  # File is used for the first time
                    ctx.input_files[dist_file] = (os.path.getsize(path) / 287)
                offset = randint(0, ctx.input_files[dist_file] - 1) * 287  # -1 due to index origin zero
                with open(path) as f:
                    f.seek(offset)
                    ds = f.readline().split()
                success = True
            except Exception, e:
                print '!! ERROR !! Can read dataset name from distribution file: %s' % e
        return ds
