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
import datetime
import os
import threading
import sys
import time

from Queue import PriorityQueue, Empty, Queue
from random import choice, gauss, sample, random, randint
from requests.exceptions import ConnectionError

from rucio.client import Client
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, UnsupportedOperation
from rucio.common.utils import generate_uuid as uuid
from rucio.core import monitor
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements all PanDA use cases.
    """

    @UCEmulator.UseCase
    def CREATE_TASK(self, task_type, rses, input, output, file_transfer_duration, bulk, threads, safety_delay):
        target_rses = list()
        if threads:
            sem = threading.BoundedSemaphore(threads)
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
            rse = None
            for i in range(output_datasets_per_datatype):
                while (rse is None) or (rse in target_rses):
                    rse = choice(rses)
                target_rses.append(rse)
        else:  # Production task output stuff is created
            ext = 'out'
            rse = choice(rses)
            for i in range(output_datasets_per_datatype):
                target_rses.append(rse)
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
                try:
                    with monitor.record_timer_block('panda.list_replicas'):
                        replicas = [f for f in client.list_replicas(scope=temp[0], name=temp[1])]
                except (DatabaseException, DataIdentifierNotFound, ConnectionError):
                    replicas = list()
                    pass
                delta = time.time() - now
                if len(replicas):
                    monitor.record_timer('panda.list_replicas.normalized', delta / len(replicas))
            if len(replicas) == 0:
                print '== PanDA: Empty input dataset provided'
                monitor.record_counter('panda.tasks.%s.EmptyInputDataset' % task_type, 1)
                return {'jobs': [], 'task': [], 'subs': []}
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
                        monitor.record_counter('panda.tasks.%s.limited_input' % task_type, 1)
                        break
            monitor.record_counter('panda.tasks.%s.input_files' % task_type, len(files))  # Reports the number of files in the intput dataset of the task type

            # Release memory by cleaning the two objects
            file_keys = None

            # ------------------------------- Determine metadata for output dataset ------------------------------------
            meta = dict()
            success = False
            retry = 1
            while not success:
                try:
                    with monitor.record_timer_block('panda.get_metadata'):
                        meta_i = client.get_metadata(scope=input['scope'], name=input['ds_name'])
                    success = True
                except (DatabaseException, ConnectionError):
                    monitor.record_counter('panda.retry.get_metadata.%s' % (retry), 1)
                    retry += 1
                    if retry > 5:
                        monitor.record_counter('panda.tasks.%s.missing_input_meta.timeout' % (task_type), 1)
                        raise
            for key in ['stream_name', 'project']:
                if meta_i[key] is not None:
                    meta[key] = meta_i[key]
                else:
                    monitor.record_counter('panda.tasks.%s.missing_input_meta.%s' % (task_type, key), 1)
                    if key == 'stream_name':
                        meta[key] = 'physics_Egamma'
                    elif key == 'project':
                        meta[key] = 'mc12_8TeV'
                    else:
                        meta[key] = 'NotGivenByInput'
        else:
            output['scope'] = choice(['mc12_8TeV', 'mc13_14TeV'])
            input['ds_name'] = uuid()
            meta = {'stream_name': 'dummy', 'project': output['scope']}
            input['number_of_inputfiles_per_job'] = 1
            files = ['file_%s' % f for f in xrange(input['max_jobs'])]

        meta['run_number'] = int(time.time() / (3600 * 24))
        meta['version'] = uuid()
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

        temp_ds = list()
        for fds in final_dss:
            temp = list()
            success = False
            retry = 1
            while not success:
                try:
                    with monitor.record_timer_block('panda.add_container'):
                        client.add_container(scope=output['scope'], name='cnt_%s' % (fds))
                        monitor.record_counter('panda.tasks.%s.container' % task_type, 1)  # Reports the creation of a container
                        success = True
                except (DatabaseException, ConnectionError):
                    monitor.record_counter('panda.retry.add_container.%s' % (retry), 1)
                    retry += 1
                    if retry > 5:
                        raise
                    time.sleep(randint(1, 2))
            for i in range(output_datasets_per_datatype):
                final_dss[fds].update({'guid': str(uuid())})
                dsn = '%s.%s' % (fds, i)
                out_ds = {'scope': output['scope'], 'name': dsn, 'dids': [], 'meta': final_dss[fds].copy(),
                          'rules': [{'account': output['account'], 'copies': 1, 'rse_expression': target_rses[i], 'grouping': 'DATASET', 'lifetime': output['lifetime']}]}
                temp.append(out_ds)
                if not bulk:
                    success = False
                    retry = 1
                    while not success:
                        try:
                            with monitor.record_timer_block('panda.add_dataset'):
                                client.add_dataset(**out_ds)
                            success = True
                        except (DatabaseException, ConnectionError):
                            monitor.record_counter('panda.retry.add_dataset.%s' % (retry), 1)
                            retry += 1
                            if retry > 5:
                                raise
                            time.sleep(randint(1, 2))
                    success = False
                    retry = 1
                    while not success:
                        try:
                            with monitor.record_timer_block('panda.add_datasets_to_container'):
                                client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % (fds), dsns=[{'scope': output['scope'], 'name': dsn}])
                            success = True
                        except (DatabaseException, ConnectionError):
                            monitor.record_counter('panda.retry.add_datasets_to_container.%s' % (retry), 1)
                            retry += 1
                            if retry > 5:
                                raise
                            time.sleep(randint(1, 2))
                    monitor.record_counter('panda.tasks.%s.output_datasets' % task_type, 1)  # Reports the number of output datasets for the tasktype (including log datasets)
            if bulk:
                success = False
                retry = 1
                while not success:
                    try:
                        with monitor.record_timer_block(['panda.add_datasets', ('panda.add_datasets.normalized', len(temp))]):
                            client.add_datasets(temp)
                        monitor.record_counter('panda.tasks.%s.output_datasets' % task_type, len(temp))  # Reports the number of output datasets for the tasktype (including log datasets)
                        success = True
                    except (DatabaseException, ConnectionError):
                        monitor.record_counter('panda.retry.add_datasets.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        time.sleep(randint(1, 2))
                success = False
                retry = 1
                while not success:
                    try:
                        with monitor.record_timer_block(['panda.add_datasets_to_container', ('panda.add_datasets_to_container.normailzed', len(temp))]):
                            client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % (fds), dsns=[{'scope': dsn['scope'], 'name': dsn['name']} for dsn in temp])
                        success = True
                    except (DatabaseException, ConnectionError):
                        monitor.record_counter('panda.retry.add_datasets_to_container.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        time.sleep(randint(1, 2))
            temp_ds += temp
        final_dss = [dsn['name'] for dsn in temp_ds]

        # -------------------------------- Derive/Create dis and subdatasets ------------------------------------------
        jobs = []
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
                fpd = float(input['jobs_per_dis']) * input['number_of_inputfiles_per_job']
                start = int(i * fpd)  # If not int, remove digits to get the lower number
                fpd = int(fpd) + 1 if (fpd % 1) != 0 else int(fpd)  # Must include every file that is (partly) used
                end = start + fpd
                if end > len(files):
                    print '== PanDA Warning: Missing proper number of files per DIS (%s - %s (Files: %s))' % (start, end, len(files))
                    end = len(files)
                    start = end - fpd if (end - fpd) > 0 else 0
                    print '== PanDA Warning: Chosen %s - %s instead' % (start, end)
                files_in_ds = [files[r] for r in range(start, end)]
                if not len(files_in_ds):
                    break
                if create_sub_ds:
                    while (target_rses[0] == computing_rse) or (computing_rse is None):
                        computing_rse = choice(rses)  # Random choice of the computing RSE
                else:
                    computing_rse = target_rses[0]  # If no sub, no output is moved, therefore target rse = computing rse

                temp_job_count = int(float(len(files_in_ds)) / input['number_of_inputfiles_per_job'])
                if temp_job_count > input['jobs_per_dis']:
                    temp_job_count = input['jobs_per_dis']

                if computing_rse not in used_rses.keys():
                    used_rses[computing_rse] = list()
                used_rses[computing_rse].append((id, temp_job_count))

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
        else:  # No Dis created, protect files by rules from deletion
            if task_type.startswith('prod'):  # T1 job, single RSE
                if input_ds_used:  # Create rules to protect replicas from deletion
                    with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(files))]):
                        client.add_replication_rule(files, copies=1, rse_expression=target_rses[0],
                                                    grouping='NONE', account='panda', lifetime=86400)
                temp_job_count = int(float(len(files)) / input['number_of_inputfiles_per_job'])
                temp_job_count = int(temp_job_count) + 1 if (temp_job_count % 1) != 0 else int(temp_job_count)
                used_rses[target_rses[0]] = [(None, temp_job_count)]
            else:  # User or Group, each out-ds on different RSE
                fpd = float(len(files)) / output_datasets_per_datatype
                if (fpd % 1) != 0:
                    fpd = int(fpd) + 1
                for i in range(int(output_datasets_per_datatype)):
                    files_in_ds = []
                    start = int(i * fpd) if ((i * fpd) < len(files)) else int(len(files) - fpd)
                    end = int(start + fpd) if (start + fpd) < len(files) else len(files)
                    try:
                        files_in_ds = [files[f] for f in range(start, end)]
                    except IndexError:
                        print '== PanDA Warning: Missing proper number of files per out-DS (%s - %s (%s))' % (start, end, len(files))
                    if not len(files_in_ds):
                        break

                    computing_rse = target_rses[i]

                    if input_ds_used:  # Create rules to protect replicas from deletion
                        with monitor.record_timer_block(['panda.add_replication_rule', ('panda.add_replication_rule.normalized', len(files_in_ds))]):
                            client.add_replication_rule(files_in_ds, copies=1, rse_expression=computing_rse,
                                                        grouping='NONE', account='panda', lifetime=86400)
                    temp_job_count = int(float(len(files_in_ds)) / input['number_of_inputfiles_per_job']) + 1

                    if computing_rse not in used_rses.keys():
                        used_rses[computing_rse] = list()
                    used_rses[computing_rse].append((None, temp_job_count))
                    computing_rse = None

        if create_sub_ds:
            for computing_rse in used_rses:
                for temp in used_rses[computing_rse]:
                    id = temp[0] if temp[0] is not None else uuid()
                    subs = ['%s_SUB_%s_%s' % (input['ds_name'], id, fin_ds) for fin_ds in final_dss]
                    jobs.append(('Manure', subs, int(temp[1]), computing_rse))  # temp[1] = number of jobs writing to SUB ds
                    for ds in subs:
                        if bulk:
                            inserts_sub.append({'scope': 'Manure', 'name': ds, 'lifetime': 86400, 'dids': [],
                                                'rules': [{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rses[0]),
                                                'grouping': 'DATASET'}]})  # Create SUB-Datasets
                        else:
                            with monitor.record_timer_block('panda.add_dataset'):
                                client.add_dataset(scope='Manure', name=ds, lifetime=86400,
                                                   rules=[{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rses[0]), 'grouping': 'DATASET'}])  # Create SUB-Datasets
                        monitor.record_counter('panda.tasks.%s.sub_datasets' % task_type, 1)  # Reports the creation of a sub dataset for the given task type
        else:
            for computing_rse in used_rses:
                for temp in used_rses[computing_rse]:
                    jobs.append((output['scope'], final_dss, int(temp[1]), computing_rse))

        # -------------------------------------- Perform bulk inserts ----------------------------------------
        if bulk:
            datasets = inserts_dis + inserts_sub
            if len(datasets):
                with monitor.record_timer_block(['panda.add_datasets', ('panda.add_datasets.normalized', len(datasets))]):
                    client.add_datasets(datasets)
            ts = list()
            ts_res = Queue()
            for ds in inserts_dis:
                if threads:
                    t = threading.Thread(target=self.add_files_ds, kwargs={'client': client, 'ds': ds, 'files_in_ds': files_in_ds, 'ret': Queue(), 'sem': sem})
                    t.start()
                    ts.append(t)
                else:
                    self.add_files_ds(client, ds, files_in_ds)
            if threads:
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
        sub_finish = dict()
        max_completion = 0
        for job_set in jobs:
            # job_set: (scope, [target datasets], number of jobs, computing_rse, task_type, log_ds)
            dis_completion = time.time()
            if create_dis_ds:
                dis_completion += gauss(**file_transfer_duration)  # Determines the time it takes to move all files to the target RSE

            # Determine the finishing time of each job using again a gaussian distribution
            max_target_completion = 0
            temp = float(job_set[2]) / output_datasets_per_datatype
            temp = int(temp) + 1 if (temp % 1 != 0) else int(temp)
            for i in xrange(temp):
                job_completion = dis_completion + gauss(**output['duration_job'])
                if job_completion > max_target_completion:
                    max_target_completion = job_completion
                job_finish.append((job_completion, {'scope': job_set[0], 'targets': job_set[1], 'computing_rse': job_set[3], 'task_type': task_type, 'log_ds': log_ds}))

            # Remeber last access to target dataset
            max_target_completion += safety_delay
            for dsn in job_set[1]:
                if (dsn not in sub_finish.keys()) or (sub_finish[dsn][0] < max_target_completion):
                    for fin_ds in final_dss:
                        if dsn.endswith(fin_ds):
                            sub_finish[dsn] = (max_target_completion, {'source': {'scope': job_set[0], 'name': dsn}, 'target': {'scope': output['scope'], 'name': fin_ds}, 'task_type': task_type})

            # Update task completion
            if max_completion < max_target_completion:
                max_completion = max_target_completion

        max_completion += safety_delay  # Note: Triggers FINISH_TASK some time later to avoid conflicts if job is stuck in gearman queue

        if create_sub_ds:
            max_completion += gauss(**file_transfer_duration)
        else:
            sub_finish = {}  # Empty list of sub datasets to avoid data moving when task is finished
        task_finish = (max_completion, {'scope': output['scope'], 'targets': final_dss, 'task_type': task_type, 'log_ds': log_ds})
        monitor.record_counter('panda.tasks.%s.dispatched' % task_type, 1)  # Reports the task type which is dipsatched
        monitor.record_counter('panda.tasks.%s.number_job' % task_type, len(job_finish) * output_datasets_per_datatype)  # Reports the number of jobs spawned from the given task
        print '== PanDA: Create %s task with %s files (%s repl.) with output scope %s (dis: %s / sub: %s (%s)/ log_ds: %s / out_ds: %s / jobs: %s (%s))' % (task_type, len(files), len(replicas),
                                                                                                                                                            output['scope'], len(inserts_dis),
                                                                                                                                                            len(inserts_sub), len(sub_finish), log_ds,
                                                                                                                                                            final_dss, job_count, len(job_finish) * output_datasets_per_datatype)
        print '-', job_finish
        print '-', sub_finish
        print '-', task_finish
        return {'jobs': job_finish, 'subs': sub_finish.values(), 'task': task_finish}

    def add_files_ds(self, client, ds, files_in_ds, ret=None, sem=None):
        if not client:
            client = Client(account='panda')
        success = False
        retry = 1
        while not success:
            try:
                if sem:
                    sem.acquire()
                with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files_in_ds))]):
                    client.add_files_to_dataset(scope=ds['scope'], name=ds['name'], files=ds['dids'])
                success = True
            except (DatabaseException, ConnectionError):
                e = sys.exc_info()
                monitor.record_counter('panda.retry.add_files_to_dataset.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    if ret:
                        ret.put((False, e))
                        return
                    else:
                        print e
                        raise
                print '== PanDA Warning: Failed %s times when adding files to dataset (%s:%s). Will retry in 5 seconds.' % (retry, ds['scope'], ds['name'])
                time.sleep(randint(1, 2))
                if ret:
                    ret.put((False, e))
            except:
                e = sys.exc_info()
                if ret:
                    ret.put((False, e))
                else:
                    print e
                    raise
            finally:
                if sem:
                    sem.release()
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
                    print '== PanDA: Selecting task from group %s' % tt.split('-')[0]
                    task_type = tt
                    ret = {'input': ctx.tasks[task_type]['input'],
                           'output': ctx.tasks[task_type]['output'],
                           'task_type': task_type,
                           'rses': [ctx.rses[i] for i in sample(xrange(len(ctx.rses)), 20)],
                           'file_transfer_duration': ctx.file_transfer_duration,
                           'safety_delay': ctx.safety_delay,
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
            if (ctx.threads == 'False') or int(ctx.threads) < 2:
                ret['threads'] = None
            else:
                ret['threads'] = int(ctx.threads)
            return ret
        except Exception, e:
            print e

    def CREATE_TASK_output(self, ctx, output):
        for key in ['jobs', 'subs', 'task']:
            if key not in output.keys():
                return
        for job in output['jobs']:
            ctx.job_queue.put(job)
        for sub in output['subs']:
            ctx.sub_queue.put(sub)
        if len(output['task']):
            ctx.task_queue.put(output['task'])

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        client = Client(account='panda')
        if threads:
            sem = threading.BoundedSemaphore(threads)

        # Group jobs by sub: if the frequency on the DB should be decreased
        ts = list()
        ts_res = Queue()
        for job in jobs:
            if threads:
                t = threading.Thread(target=self.register_replica, kwargs={'client': client, 'job': job, 'ret': ts_res, 'sem': sem})
                t.start()
                ts.append(t)
            else:
                self.register_replica(client, job)
        if threads:
            for t in ts:
                t.join()
        while not ts_res.empty():
            ret = ts_res.get()
            if ret[0] is False:
                print ret[1][2]
                raise ret[1][0]
        targets = []
        replicas = 0
        for job in jobs:
            targets += job['targets']
            replicas += len(job['targets']) if job['log_ds'] else (2 * len(job['targets']))
        print '== PanDA: Registering %s replicas from %s jobs over %s different datasets' % (replicas, len(jobs), len(set(targets)))

    def register_replica(self, client, job, ret=None, sem=None):
        if not client:
            client = Client(account='panda')
        count = 0

        for tds in job['targets']:
            fn = uuid()
            files = list()
            if not job['log_ds']:  # Add log file for each datatype if task doesn't have LOG dataset
                for ext in ['log', 'out']:
                    files.append({'scope': job['scope'], 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
            else:
                ext = 'out' if tds.split('.')[-2] != 'log' else 'log'
                files.append({'scope': job['scope'], 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})

            now = time.time()
            success = False
            retry = 1
            e = None
            while not success and retry < 5:
                try:
                    if sem:
                        sem.acquire()
                    with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(files))]):
                        client.add_files_to_dataset(scope=job['scope'], name=tds, files=files, rse=job['computing_rse'])
                    success = True
                except DatabaseException:
                    e = sys.exc_info()
                    monitor.record_counter('panda.retry.add_files_to_dataset.%s' % (retry), 1)
                    retry += 1
                    print '== PanDA Warning: Failed %s times when adding files to dataset (%s:%s). Will retry in 5 seconds.' % (retry, job['scope'], tds)
                    time.sleep(randint(1, 2))
                except:
                    e = sys.exc_info()
                    break
                finally:
                    if sem:
                        sem.release()

            if not success:
                print '-' * 80
                print '- Failed after %s seconds (retries: %s)' % ((time.time() - now), retry)
                print '- %s:%s' % (job['scope'], tds)
                print '-', files
                print '-', job['log_ds']
                print '-' * 80
                if ret:
                    ret.put((False, e))
            count += len(files)
        monitor.record_counter('panda.tasks.%s.replicas' % job['task_type'], count)  # Reports the creation of a new replica (including log files) fof the given task type
        print '== PanDA: Job (%s) added %s files to %s datasets (%s:%s)' % (job['task_type'], count, len(job['targets']), job['scope'], job['targets'])
        if ret:
            ret.put((True, count))

    # ----------------------- attach_dids_to_dids ----------------------------------------------------------------
    #def register_replica(self, client, job, ret=None, sem=None):
    #    if not client:
    #        client = Client(account='panda')
    #    count = 0
    #    # TODO: Instead of this loop the attach_dids_to_dids method should be used
    #    attachments = list()
    #    for tds in job['targets']:
    #        # Create output files of the job
    #        fn = uuid()
    #        files = list()
    #        if not job['log_ds']:  # Add log file for each datatype if task doesn't have LOG dataset
    #            for ext in ['log', 'out']:
    #                files.append({'scope': job['scope'], 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
    #        else:
    #            ext = 'out' if tds.split('.')[-2] != 'log' else 'log'
    #            files.append({'scope': job['scope'], 'name': '%s.%s' % (fn, ext), 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid())}})
    #        attachments.append({'scope': job['scope'], 'name': tds, 'rse': job['computing_rse'], 'dids': files})
    #        count += len(files)

    #    success = False
    #    retry = 1
    #    e = None
    #    now = time.time()
    #    while not success:
    #        try:
    #            if sem:
    #                sem.acquire()
    #            with monitor.record_timer_block('panda.attach_dids_to_dids'):
    #                client.attach_dids_to_dids(attachments=attachments)
    #            success = True
    #        except DatabaseException:
    #            e = sys.exc_info()
    #            monitor.record_counter('panda.retry.add_files_to_dataset.%s' % (retry), 1)
    #            retry += 1
    #            if retry > 5:
    #                break
    #            print '== PanDA Warning: Failed %s times when adding files to datasets: %s' % (retry, attachments)
    #            time.sleep(randint(1, 2))
    #        except:
    #            e = sys.exc_info()
    #            break
    #        finally:
    #            if sem:
    #                sem.release()

    #    if not success:
    #        print '-' * 80
    #        print '- Failed after %s seconds (retries: %s)' % ((time.time() - now), retry)
    #        print '- %s:%s' % (job['scope'], tds)
    #        print '-', files
    #        print '-', job['log_ds']
    #        print '-', e
    #        print '-', count
    #        print '-' * 80
    #        if ret:
    #            ret.put((False, e))
    #    monitor.record_counter('panda.tasks.%s.replicas' % job['task_type'], count)  # Reports the creation of a new replica (including log files) fof the given task type
    #    print '== PanDA: Job (%s) added %s files to %s datasets (%s:%s)' % (job['task_type'], count, len(job['targets']), job['scope'], job['targets'])
    #    if ret:
    #        ret.put((True, count))

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
            jobs.append(job[1])
            ctx.job_queue.task_done()
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(jobs):
            return {'jobs': jobs, 'threads': threads}
        else:
            return None

    @UCEmulator.UseCase
    def POPULATE_SUB(self, subs, threads, safety_delay):
        client = Client(account='panda')
        ts = list()
        ts_res = Queue()
        if threads:
            sem = threading.BoundedSemaphore(threads)
        for sub in subs:
            print sub
            print '== PanDA: Populating SUB-DS (%s) to target (%s) for job %s' % (sub['source'], sub['target'], sub['task_type'])
            if threads:
                t = threading.Thread(target=self.aggregate_output, kwargs={'client': client, 'source': sub['source'], 'target': sub['target'],
                                                                           'task_type': sub['task_type'], 'ret': ts_res, 'sem': sem})
                t.start()
                ts.append(t)
            else:
                self.aggregate_output(client, sub['source'], sub['target'], sub['task_type'])
        if threads:
            for t in ts:
                t.join()
        while not ts_res.empty():
            ret = ts_res.get()
            if not ret[0]:
                print ret[1][2]
                raise ret[1][0]

    def POPULATE_SUB_input(self, ctx):
        now = time.time()
        subs = []
        while True:  # Job is finished by now
            try:
                sub = ctx.sub_queue.get_nowait()
            except Empty:
                break
            if sub[0] > now:
                ctx.sub_queue.put(sub)
                break
            subs.append(sub[1])
            ctx.sub_queue.task_done()
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(subs):
            return {'subs': subs, 'threads': threads, 'safety_delay': ctx.safety_delay}
        else:
            return None

    def aggregate_output(self, client, source, target, task_type, ret=None, sem=None):
        now = time.time()
        if not client:
            client = Client(account='panda')
        retry = 1
        fs = list()
        exc = None

        # List files in SUB
        while not len(fs):
            try:
                with monitor.record_timer_block('panda.list_files'):
                    fs = [f for f in client.list_files(**source)]
                if len(fs):
                    monitor.record_timer('panda.list_files.normalized', (time.time() - now) / len(fs))
                    monitor.record_counter('panda.tasks.%s.sub_files' % task_type, len(fs))
                    print '== PanDA: Adding %s files from SUB (%s) to TID (%s)' % (len(fs), source, target)
                else:
                    print '== PanDA Warning: No data task arrived for %s. Will Retry later.' % (source)
                    retry += 1
                    if retry > 5:
                        print '== PanDA Warning: No data task arrived for %s. Gave up' % (source)
                        monitor.record_counter('panda.tasks.%s.EmptySubDataset' % task_type, 1)
                        with monitor.record_timer_block('panda.close'):
                            client.close(**source)
                        return
                    time.sleep(randint(3, 5))
            except DatabaseException:
                exc = sys.exc_info()
                fs = []
                print '== PanDA: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (source, retry, task_type)
                monitor.record_counter('panda.retry.list_files.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    print '== PanDA: No data task arrived for %s. Gave up' % (source)
                    monitor.record_counter('panda.tasks.%s.EmptySubDataset' % task_type, 1)
                    with monitor.record_timer_block('panda.close'):
                        client.close(**source)
                    if ret:
                        ret.put((False, exc))
                    return
                time.sleep(randint(1, 2))
            except Exception:
                exc = sys.exc_info()
                if ret:
                    ret.put((False, exc))
                else:
                    raise

        # Append files to TID
        try:
            if sem:
                sem.acquire()
            success = False
            retry = 1
            while not success:
                with monitor.record_timer_block(['panda.add_files_to_dataset', ('panda.add_files_to_dataset.normalized', len(fs))]):
                    client.add_files_to_dataset(scope=target['scope'], name=target['name'], files=fs)
                success = True
        except Exception:
            exc = sys.exc_info()
            print '== PanDA: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (source, retry, task_type)
            monitor.record_counter('panda.retry.add_files_to_dataset.%s' % (retry), 1)
            retry += 1
            if retry > 5:
                if ret:
                    ret.put((False, exc))
                return
        finally:
            if sem:
                sem.release()
        print '== PanDA: Populated %s files from %s to %s' % (len(fs), source, target)

        # Close SUB dataset
        try:
            if sem:
                sem.acquire()
            success = False
            retry = 1
            while not success:
                with monitor.record_timer_block('panda.close'):
                    client.close(**source)
                success = True
        except Exception:
            exc = sys.exc_info()
            print '== PanDA: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (source, retry, task_type)
            monitor.record_counter('panda.retry.close.%s' % (retry), 1)
            retry += 1
            if retry > 5:
                if ret:
                    ret.put((False, exc))
                return
        finally:
            if sem:
                sem.release()
        print '== PanDA: Closed sub dataset: %s' % (source)
        if ret:
            ret.put((True, None))

    def FINISH_TASK(self, tasks, threads, safety_delay):
        client = Client(account='panda')
        for task in tasks:
            task_type = task['task_type']
            for target in task['targets']:
                retry = 1
                success = False
                while not success:
                    try:
                        now = time.time()
                        with monitor.record_timer_block('panda.list_files'):
                            fs = [f for f in client.list_files(scope=task['scope'], name=target)]
                        if len(fs):
                            monitor.record_timer('panda.list_files.normalized', (time.time() - now) / len(fs))
                            monitor.record_counter('panda.tasks.%s.output_ds_size' % task_type, len(fs))  # Reports the number of files added to the output dataset
                        else:
                            monitor.record_counter('panda.tasks.%s.EmptyOutputDataset' % task_type, 1)
                        success = True
                    except DatabaseException:
                        monitor.record_counter('panda.retry.close.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        print '== PanDA Warning: Failed %s times to list files in dataset (%s:%s). Will rertry in 5 seconds.' % (retry, task['scope'], target)
                        time.sleep(randint(1, 2))
                    except Exception:
                        e = sys.exc_info()
                        print '-' * 80
                        print '- Failed listing files in TID: %s:%s' % (task['scope'], target)
                        print '-', e
                        print '-' * 80
                        raise
                retry = 1
                success = False
                while not success:
                    try:
                        with monitor.record_timer_block('panda.close'):
                            client.close(scope=task['scope'], name=target)
                        success = True
                    except UnsupportedOperation:
                        break
                    except DatabaseException:
                        monitor.record_counter('panda.retry.close.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        print '== PanDA Warning: Failed %s times to close the dataset (%s:%s). Will rertry in 5 seconds.' % (retry, task['scope'], target)
                        time.sleep(randint(1, 2))
                print '== PanDA: Closed output dataset %s:%s from task (%s) including %s files' % (task['scope'], target, task_type, len(fs))
            monitor.record_counter('panda.tasks.%s.finished' % task_type, 1)

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
            tasks.append(task[1])
            ctx.task_queue.task_done()
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(tasks):
            return {'tasks': tasks, 'threads': threads, 'safety_delay': ctx.safety_delay}
        else:
            return None

    def RESET_input(self, ctx):
        print '== PanDA: Reseting input files cache'
        monitor.record_counter('panda.tasks.reset', 1)
        ctx.input_files = {}
        return None

    def RESET(self):
        pass  # Will never be executed, only here for sematic reasons

    def QUEUE_OBSERVER(self):
        pass  # Will never be executed, only here for sematic reasons

    def QUEUE_OBSERVER_input(self, ctx):
        monitor.record_gauge('panda.tasks.queue', ctx.task_queue.qsize())
        monitor.record_gauge('panda.jobs.queue', ctx.job_queue.qsize())
        monitor.record_gauge('panda.subs.queue', ctx.sub_queue.qsize())
        print '== PanDA: Task-Queue: %s / Job-Queue: %s / Sub-Queue: %s' % (ctx.task_queue.qsize(), ctx.job_queue.qsize(), ctx.sub_queue.qsize())
        return None  # Indicates that no further action is required

    def setup(self, ctx):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """
        # As long as there is no database filler, one dataset and n files are created here
        ctx.job_queue = PriorityQueue()
        ctx.sub_queue = PriorityQueue()
        ctx.task_queue = PriorityQueue()
        try:
            with open('panda.ctx', 'r') as f:
                delta = time.time() - float(f.next())
                print '== PanDA: Paused for %s seconds' % delta
                for q in ['job', 'sub', 'task']:
                    pq = getattr(ctx, '%s_queue' % q)
                    items = ast.literal_eval(f.next())
                    for item in items:
                        pq.put((float(item[0]) + delta, item[1]))
                    print '== PanDA: Added %s %ss to queue from former execution' % (len(items), q)
        except IOError:
            print '== PanDA: No information about former execution found'
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

    def shutdown(self, ctx):
        jobs = []
        subs = []
        tasks = []
        for l, q in [(jobs, ctx.job_queue), (subs, ctx.sub_queue), (tasks, ctx.task_queue)]:
            while True:
                try:
                    item = q.get_nowait()
                    l.append(item)
                except Empty:
                    break
        with open('panda.ctx', 'w') as f:
            f.write('%s\n' % time.time())
            for l in [jobs, subs, tasks]:
                print 'Persisted %s items' % len(l)
                f.write('%s\n' % l)
        print 'Persisted context'
