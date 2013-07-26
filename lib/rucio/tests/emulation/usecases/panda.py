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


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, target_rse, rses, input, output, file_transfer_duration, bulk, threads):
        if 'output_datasets_per_datatype' in output.keys():
            output_datasets_per_datatype = output['output_datasets_per_datatype']
            if (output_datasets_per_datatype % 1) != 0:  # Fraction is a decimal, decide final number by chance
                output_datasets_per_datatype = int(output_datasets_per_datatype) if ((output_datasets_per_datatype % 1) < random()) else int(output_datasets_per_datatype) + 1
        else:
            output_datasets_per_datatype = 1
        input_ds_used = False if input['dss'] is None else True
        if 'create_subs' in output.keys():
            create_sub_ds = output['create_subs'] == "True"
        else:
            create_sub_ds = False
        if (task_type.startswith('user') or task_type.startswith('group')):  # User task is created
            ext = task_type.split('.')[0]
            create_dis_ds = False
            log_ds = False
        else:  # Production task output stuff is created
            ext = 'out'
            if input_ds_used:
                if input['dis_ds_probability'] == 0:
                    create_dis_ds = False
                elif input['dis_ds_probability'] == 1:
                    create_dis_ds = True
                else:
                    create_dis_ds = (input['dis_ds_probability'] >= random())
            else:
                create_dis_ds = False
            log_ds = True
            if 'max_jobs' in output.keys() and not input_ds_used:
                output['max_jobs'] *= 2

        client = Client(account='panda')

        if 'lifetime' not in output.keys():
            output['lifetime'] = None

        # ----------------------- List replicas and derive list of files from it -------------------
        replicas = list()
        if input_ds_used:
            while input_ds_used and len(input['dss']) and not len(replicas):
                temp = input['dss'].pop()
                now = time.time()
                print '== PanDA: Checking %s as input' % temp
                with monitor.record_timer_block('panda.list_replicas'):
                    replicas = [f for f in client.list_replicas(scope=temp[0], name=temp[1])]
                delta = time.time() - now
                if len(replicas):
                    monitor.record_timer('panda.list_replicas.normalized', delta / len(replicas))
            if len(replicas) == 0:
                print '== PanDA: Empty input dataset provided'
                monitor.record_counter('panda.tasks.%s.EmptyInputDataset' % task_type, 1)
                return {'job_finish': [], 'task_finish': []}
            input['scope'] = temp[0]
            input['ds_name'] = temp[1]
            if log_ds:  # Production task
                output['scope'] = temp[0]

            # Should be changed when the response from list_replicas is updated
            files = list()
            file_keys = list()
            for r in replicas:
                if '%s:%s' % (r['scope'], r['name']) not in file_keys:
                    file_keys.append('%s:%s' % (r['scope'], r['name']))
                    files.append({'scope': r['scope'], 'name': r['name'], 'bytes': r['bytes']})
                    if ('max_jobs' in input.keys()) and (len(files) > (input['max_jobs'] * input['number_of_inputfiles_per_job'])):
                        break
            monitor.record_counter('panda.tasks.%s.input_files' % task_type, len(files))  # Reports the number of files in the intput dataset of the task type

            # Release memory by cleaning the two objects
            file_keys = None

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
        else:
            output['scope'] = choice(['mc12_8TeV', 'mc13_14TeV'])
            input['ds_name'] = uuid()
            meta = {'stream_name': 'dummy', 'run_number': randint(1, 99999), 'project': output['scope'], 'version': uuid()}
            input['number_of_inputfiles_per_job'] = 1
            files = ['file_%s' % f for f in xrange(output['max_jobs'])]

        # ----------------------------------- Create final output - dataset(s) ---------------------------------------
        final_dss = {}
        for out_ds in output['meta']:  # Create output containers(s)
            meta['prod_step'] = out_ds.split('.')[0]
            meta['datatype'] = out_ds.split('.')[1]
            ds = '.'.join([meta['project'], str(meta['run_number']), meta['stream_name'], meta['prod_step'], meta['datatype'], meta['version'], ext])
            final_dss[ds] = meta.copy()
        if log_ds:
            ds = '.'.join([meta['project'], str(meta['run_number']), meta['stream_name'], meta['prod_step'], meta['datatype'], meta['version'], 'log'])
            final_dss[ds] = meta.copy()

        temp = list()
        for fds in final_dss:
            with monitor.record_timer_block('panda.add_container'):
                client.add_container(scope=output['scope'], name='cnt_%s' % (fds),
                                     rules=[{'account': output['account'], 'copies': 1, 'rse_expression': target_rse, 'grouping': 'DATASET', 'lifetime': output['lifetime']}])
            monitor.record_counter('panda.tasks.%s.container' % task_type, 1)  # Reports the creation of a container
            for i in range(output_datasets_per_datatype):
                final_dss[fds].update({'guid': str(uuid())})
                dsn = '%s.%s' % (fds, i)
                with monitor.record_timer_block('panda.add_dataset'):
                    client.add_dataset(scope=output['scope'], name=dsn, meta=final_dss[fds])
                temp.append(dsn)
                monitor.record_counter('panda.tasks.%s.output_datasets' % task_type, 1)  # Reports the number of output datasets for the tasktype (including log datasets)
            with monitor.record_timer_block('panda.add_datasets_to_container'):
                client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % (fds), dsns=[{'scope': output['scope'], 'name': '%s.%s' % (fds, i)} for i in range(output_datasets_per_datatype)])
        final_dss = temp

        # -------------------------------- Derive/Create dis and subdatasets ------------------------------------------
        sub_dss = []
        files_in_ds = []
        dis_ds = None
        computing_rse = None
        job_count = 0

        inserts_dis = list()
        inserts_sub = list()

        if 'number_of_inputfiles_per_job' not in input.keys():
            input['number_of_inputfiles_per_job'] = 1

        # ----------------------- Derive number of jobs depending on the input dataset ------------------------
        job_count = float(len(files)) / input['number_of_inputfiles_per_job']
        if (job_count % 1) != 0:
            job_count = int(job_count) + 1
        if ('max_jobs' in input.keys()) and (job_count >= input['max_jobs']):
            job_count = input['max_jobs']

        used_rses = dict()
        if create_dis_ds:  # Creating DIS - Datasets
            count_dis = float(job_count) / input['jobs_per_dis']
            if (count_dis % 1) != 0:
                count_dis = int(count_dis) + 1
            for i in range(int(count_dis)):
                id = uuid()
                dis_ds = '%s_DIS_%s' % (input['ds_name'], id)
                start = int(i * (input['jobs_per_dis'] * input['number_of_inputfiles_per_job']))
                end = start + int(input['jobs_per_dis'] * input['number_of_inputfiles_per_job'])
                if end >= len(files):
                    end = len(files)
                if (end - start) > 0:
                    files_in_ds = [files[r] for r in range(start, end)]
                    if create_sub_ds:
                        while (target_rse == computing_rse) or (computing_rse is None):
                            computing_rse = choice(rses)  # Random choice of the computing RSE
                    else:
                        computing_rse = target_rse  # If no sub, no output is moved, therefore target rse = computing rse

                    temp_job_count = int(float(end - start) / input['number_of_inputfiles_per_job'])
                    if temp_job_count > input['jobs_per_dis']:
                        temp_job_count = input['jobs_per_dis']

                    if computing_rse not in used_rses.keys():
                        used_rses[computing_rse] = list()
                    used_rses[computing_rse].append((id, dis_ds, temp_job_count))

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
                monitor.record_counter('panda.tasks.%s.dis_files' % task_type, len(files_in_ds))  # Reports the number of files in the dis - dataset
                computing_rse = None
        else:  # No Dis created, either T1 job or no input is used
            if create_sub_ds:
                while (target_rse == computing_rse) or (computing_rse is None):
                    computing_rse = choice(rses)  # Random choice of the computing RSE
            else:
                computing_rse = target_rse  # If no sub, no output is moved, therefore target rse = computing rse
            temp_job_count = float(len(files)) / input['number_of_inputfiles_per_job'] / output['output_datasets_per_datatype']
            if (temp_job_count % 1) != 0:
                temp_job_count = int(temp_job_count) + 1
            if computing_rse not in used_rses.keys():
                used_rses[computing_rse] = list()
            used_rses[computing_rse].append((None, None, temp_job_count))

            if input_ds_used:  # Create rules to protect replicas from deletion
                with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(files))]):
                    client.add_replication_rule(files_in_ds, copies=1, rse_expression=computing_rse,
                                                grouping='NONE', account='panda', lifetime=86400)
                computing_rse = None

        for computing_rse in used_rses:
            for temp in used_rses[computing_rse]:
                if create_sub_ds:  # Creating SUB - datsets
                    id = temp[0]
                    if not id:
                        id = uuid()
                    for ds in ['%s_SUB_%s_%s' % (input['ds_name'], id, fin_ds) for fin_ds in final_dss]:
                        sub_dss.append(({'scope': 'Manure', 'name': ds}, int(temp[2]), computing_rse, task_type))
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
                        sub_dss.append(({'scope': output['scope'], 'name': ds}, int(temp[2]), computing_rse, task_type))
        monitor.record_counter('panda.tasks.%s.number_job' % task_type, job_count)  # Reports the number of jobs spawned from the given task

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
                    t = threading.Thread(target=self.add_files_ds, kwargs={'client': client, 'ds': ds, 'files_in_ds': files_in_ds, 'ret': Queue()})
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
                    job_finish.append((job_completion, [{'scope': 'Manure', 'name': ds[0]['name']}, ds[2], ds[3], log_ds]))
                else:
                    job_finish.append((job_completion, [{'scope': output['scope'], 'name': ds[0]['name']}, ds[2], ds[3], log_ds]))
        max_job_completion += 180  # Note: Triggers FINISH_TASK some time later to avoid conflicts

        if not create_sub_ds:
            sub_ds_names = []  # Empty list of sub datasets to avoid data moving when task is finished

        if create_dis_ds:
            task_finish = (max_job_completion + gauss(**file_transfer_duration), (output['scope'], final_dss), sub_ds_names, task_type, log_ds)
        else:
            task_finish = (max_job_completion, (output['scope'], final_dss), sub_ds_names, task_type, log_ds)
        monitor.record_counter('panda.tasks.%s.dispatched' % task_type, 1)  # Reports the task type which is dipsatched
        print '== PanDA: Create %s task with %s files (%s repl.) with output scope %s (dis: %s / sub: %s / log_ds: %s / out_ds: %s / jobs: %s (%s))' % (task_type, len(files), len(replicas),
                                                                                                                                                        output['scope'], len(inserts_dis),
                                                                                                                                                        len(inserts_sub), log_ds,
                                                                                                                                                        len(final_dss), job_count, len(job_finish))
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

    def CREATE_TASK_input(self, ctx):
        try:
        # Select input DS from file provided by Cedric using observed age distribution from Thomas
        # Select task type
            success = False
            task_type = ''
            while not success:
                    exit = False
                    while not exit:
                        tt = choice(ctx.task_distribution)
                        exit = (tt.startswith(task_type.split('-')[0]) or (task_type is ''))
                    print '== PanDA: Selecting from task from group %s' % tt.split('-')[0]
                    task_type = tt
                    ret = {'input': ctx.tasks[task_type]['input'],
                           'output': ctx.tasks[task_type]['output'],
                           'task_type': task_type,
                           'rses': [ctx.rses[i] for i in sample(xrange(len(ctx.rses)), 4)],
                           'target_rse': choice(ctx.rses),
                           'file_transfer_duration': ctx.file_transfer_duration,
                           }
                    if ('meta' in ctx.tasks[task_type]['input'].keys()) and (len(ctx.tasks[task_type]['input']['meta'])):  # Task depends on input dataset
                        ret['input']['dss'] = list()
                        for i in range(10):
                            input_ds = self.select_input_ds(task_type, ctx)
                            if not input_ds:
                                continue
                            ret['input']['dss'].append(input_ds)
                    else:  # Task activity is base on max_jobs
                        ret['input']['dss'] = None
                    success = True
            if task_type.split('.')[0] == 'user':
                user = choice(ctx.users)
                ret['output']['scope'] = 'user.%s' % user
                ret['output']['account'] = user
            elif task_type.split('.')[0] == 'group':
                group = choice(ctx.groups)
                ret['output']['scope'] = 'group.%s' % group
                ret['output']['account'] = group
            else:
                ret['output']['account'] = 'panda'
            ret['bulk'] = ctx.bulk == 'True'
            ret['threads'] = ctx.threads == 'True'
            return ret
        except Exception, e:
            print e

    def CREATE_TASK_output(self, ctx, output):
        for job in output['job_finish']:
            ctx.job_queue.put(job)
        for task in output['task_finish']:
            ctx.task_queue.put(task)

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        client = Client(account='panda')

        # Group jobs by sub - dataset
        #subs = dict()
        #for job in jobs:
        #    dsn = '%s:%s' % (job['sub_ds']['scope'], job['sub_ds']['name'])
        #    if dsn not in subs.keys():
        #        subs[dsn] = [0, job['rse'], job['task_type'], job['log_ds']]  # Note: one sub ds is always exactly on one rse and task type
        #    subs[dsn][0] += 1

        ts = list()
        ts_res = Queue()
        #for ds in subs:
        for job in jobs:
            #print '== PanDA: Finish jobs (%s): %s sub - datasets' % (job['task_type'], job['sub_ds'])
            if threads == 'True':
                t = threading.Thread(target=self.register_replica, kwargs={'client': client, 'dsn': job['sub_ds'],
                                                                           'rse': job['rse'], 'jobs': 1, 'task_type': job['task_type'], 'log_ds': job['log_ds'], 'ret': ts_res})
                t.start()
                ts.append(t)
            else:
                self.register_replica(client, job['sub_ds'], job['rse'], 1, job['task_type'], job['log_ds'])
        if threads == 'True':
            for t in ts:
                t.join()
        while not ts_res.empty():
            ret = ts_res.get()
            if not ret[0]:
                print ret[1][2]
                raise ret[1][0]

    def register_replica(self, client, dsn, rse, jobs, task_type, log_ds, ret=None):
        files = list()
        if not client:
            client = Client(account='panda')
        for i in xrange(jobs):
            fn = uuid()
            if dsn['name'].split('.')[-2] == 'log':  # Fill LOG dataset
                files.append({'scope': dsn['scope'], 'name': '%s.log' % fn, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
            else:  # Fill DATA dataset
                files.append({'scope': dsn['scope'], 'name': '%s.out' % fn, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
                if not log_ds:  # Add log files if task doesn't have LOG dataset
                    files.append({'scope': dsn['scope'], 'name': '%s.log' % (fn), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})

        now = time.time()
        try:
            with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
                client.add_files_to_dataset(scope=dsn['scope'], name=dsn['name'], files=files, rse=rse)
            monitor.record_counter('panda.tasks.%s.replicas' % task_type, len(files))  # Reports the creation of a new replica (including log files) fof the given task type
            print '== PanDA: Job (%s) added %s files to %s:%s' % (task_type, len(files), dsn['scope'], dsn['name'])
        except:
            e = sys.exc_info()
            print '-' * 80
            print 'Failed after %s seconds' % (time.time() - now)
            print '%s:%s' % (dsn['scope'], dsn['name'])
            print files
            print log_ds
            print '-' * 80
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
            jobs.append({'sub_ds': job[1][0], 'rse': job[1][1], 'task_type': job[1][2], 'log_ds': job[1][3]})
            ctx.job_queue.task_done()
        if len(jobs):
            return {'jobs': jobs, 'threads': ctx.threads}
        else:
            return None

    @UCEmulator.UseCase
    def FINISH_TASK(self, tasks, threads):
        monitor.record_counter('panda.tasks.finished', len(tasks))
        client = Client(account='panda')
        ts = list()
        for task in tasks:
            task_type = task['task_type']
            print '== PanDA: Finish task: %s (Output datasets: %s)' % (task_type, task['output_ds'][1])
            if not len(task['sub_dss']):
                for out_ds in task['output_ds'][1]:  # Iterates over every output - type of the task
                    with monitor.record_timer_block('panda.close'):
                        client.close(scope=task['output_ds'][0], name=out_ds)
                    now = time.time()
                    fs = list()
                    retry = 1
                    while not len(fs):
                        with monitor.record_timer_block('panda.list_files'):
                            fs = [f for f in client.list_files(scope=task['output_ds'][0], name=out_ds)]
                        if not len(fs):
                            print '== PanDA: Waiting 1 minute for task (%s) data to arrive in %s:%s (retry count: %s / task-type: %s)' % (task_type, task['output_ds'][0], out_ds, retry, task_type)
                            time.sleep(60)
                            retry += 1
                        if retry > 5:
                            print '== PanDA: No task (%s) data arrived for %s:%s. Gave up' % (task_type, task['output_ds'][0], out_ds)
                            break
                    if not len(fs):
                        monitor.record_counter('panda.tasks.%s.EmptyOutputDataset' % task_type, 1)
                    else:
                        monitor.record_timer('panda.list_files.normalized', (time.time() - now) / len(fs))
                    monitor.record_counter('panda.tasks.%s.output_ds_size' % task_type, len(fs))  # Reports the number of files added to the output dataset
                    print '== PanDA: Tasks (%s) created %s output files in %s' % (task_type, len(fs), out_ds)
            else:
                for out_ds in task['output_ds'][1]:  # Iterates over every output - type of the task
                    sub_dss = list()
                    for sub_ds in task['sub_dss']:
                        if sub_ds.endswith(out_ds):  # Checks if the sub dataset is realted to the current output dataset
                            sub_dss.append(sub_ds)
                    if len(sub_dss):
                        if threads == 'True':
                            t = threading.Thread(target=self.fin_task, kwargs={'client': client, 'task': {'sub_dss': sub_dss, 'output_ds': [task['output_ds'][0], out_ds]},
                                                                               'task_type': task_type, 'threads': threads})
                            t.start()
                            ts.append(t)
                        else:
                            self.fin_task(client, {'sub_dss': sub_dss, 'output_ds': [task['output_ds'][0], out_ds]}, task_type, threads)
            if threads == 'True':
                for t in ts:
                    t.join()

    def fin_task(self, client, task, task_type, threads):
        ts = list()
        if not client:
            client = Client(account='panda')
        for sub_ds in task['sub_dss']:
            if threads == 'True':
                t = threading.Thread(target=self.aggregate_output, kwargs={'client': client, 'source_ds': sub_ds,
                                                                           'target': task['output_ds'], 'task_type': task_type})
                t.start()
                ts.append(t)
            else:
                self.aggregate_output(client, sub_ds, task['output_ds'], task_type)
        if threads == 'True':
            for t in ts:
                t.join()
        with monitor.record_timer_block('panda.close'):
            client.close(scope=task['output_ds'][0], name=task['output_ds'][1])

    def aggregate_output(self, client, source_ds, target, task_type):
        now = time.time()
        if not client:
            client = Client(account='panda')
        retry = 1
        fs = list()
        while not len(fs):
            with monitor.record_timer_block('panda.list_files'):
                fs = [f for f in client.list_files(scope='Manure', name=source_ds)]
            if not len(fs):
                print '== PanDA: Waiting 1 minute for task data to arrive in %s:%s (retry count: %s / task-type: %s)' % ('Manure', source_ds, retry, task_type)
                time.sleep(60)
                retry += 1
                if retry > 5:
                    print '== PanDA: No data task arrived for %s:%s. Gave up' % ('Manure', source_ds)
                    monitor.record_counter('panda.tasks.%s.EmptySubDataset' % task_type, 1)
                    with monitor.record_timer_block('panda.close'):
                        client.close(scope='Manure', name=source_ds)
                    return
            else:
                monitor.record_timer('panda.list_files.normalized', (time.time() - now) / len(fs))
        monitor.record_counter('panda.tasks.%s.output_ds_size' % task_type, len(fs))  # Reports the number of files added to the output dataset
        print '== PanDA: Task (%s) created %s output files in %s' % (task_type, len(fs), target)
        with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(fs))]):
            client.add_files_to_dataset(scope=target[0], name=target[1], files=fs)
        with monitor.record_timer_block('panda.close'):
            client.close(scope='Manure', name=source_ds)

    def RESET_input(self, ctx):
        print '== PanDA: Reseting input files cache'
        ctx.input_files = {}

    def RESET(self):
        monitor.record_counter('panda.tasks.reset', 1)  # Reports the resetting of the caches

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
        pass  # Will never be executed, only here for sematic reasons

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
        ctx.groups = list()
        for a in client.list_accounts():
            if a['type'] == 'USER' and a['account'].startswith('user'):
                ctx.users.append(a['account'])
            if a['type'] == 'GROUP':
                ctx.groups.append(a['account'])

        ctx.rses = []
        for rse in client.list_rses():
            if rse['deterministic']:
                ctx.rses.append(rse['rse'])

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

        success = False
        retry = 0
        while not success:
            retry += 1
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
                ds = None
                with open(path) as f:
                        f.seek(randint(0, ctx.input_files[dist_file] - 1) * 287)
                        ds = f.readline().split()
                success = True
            except Exception, e:
                ctx.input_files[dist_file] = False  # Remeber that this file doen't exist
                print '!! ERROR !! Can read dataset name from distribution file: %s' % e
                if retry > 5:
                    return 0
        return ds
