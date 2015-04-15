# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013-2014

import datetime
import bisect
import os
import pickle
import sys
import threading
import time
import traceback

from Queue import Queue
from random import choice, gauss, sample, random, randint
from requests.exceptions import ConnectionError

from rucio.client import Client
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, UnsupportedOperation, InvalidRSEExpression, InsufficientTargetRSEs, ScopeNotFound
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
        task_type_id = task_type.split('.')[1].split('-')[0]
        task_number = '%08d' % randint(0, 100000000)
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
                    with monitor.record_timer_block('emulator.panda.client.list_replicas'):
                        replicas = [f for f in client.list_replicas([{'scope': temp[0], 'name': temp[1]}], schemes=None, unavailable=True)]
                except (DatabaseException, DataIdentifierNotFound, ConnectionError):
                    replicas = list()
                    delta = time.time() - now
                    print '== PanDA-TIMER_1: Listing replicas in %s:%s took %s seconds and timed out in the end' % (temp[0], temp[1], delta)
                    pass
                delta = time.time() - now
                if delta > 600:
                    print '== PanDA-TIMER_2: Listing replicas in %s:%s took %s seconds' % (temp[0], temp[1], delta)
                if len(replicas):
                    monitor.record_timer('emulator.panda.client.list_replicas.normalized', delta / len(replicas))
            if len(replicas) == 0:
                print '== PanDA: Empty input dataset provided'
                monitor.record_counter('emulator.panda.tasks.%s.EmptyInputDataset' % task_type, 1)
                return {'jobs': [], 'task': [], 'subs': []}
            input['scope'] = temp[0]
            input['ds_name'] = temp[1]
            if log_ds:  # Production task
                output['scope'] = temp[0]

            # Should be changed when the response from list_replicas is updated
            files = list()
            file_keys = list()
            cnt_rses = dict()
            for r in replicas:
                if '%s:%s' % (r['scope'], r['name']) not in file_keys:
                    file_keys.append('%s:%s' % (r['scope'], r['name']))
                    try:
                        files.append({'scope': r['scope'], 'name': r['name'], 'bytes': r['bytes']})
                    except KeyError as ke:
                        print '-------------------- KeyError in return of list_replicas ----------------'
                        print r
                        print ke
                        print '-------------------- KeyError in return of list_replicas ----------------'
                        monitor.record_counter('emulator.exceptions.panda.CREATE_TASK.KeyError', 1)
                        files.append({'scope': r['scope'], 'name': r['name'], 'bytes': 0})
                    if ('max_jobs' in input.keys()) and (len(files) > (input['max_jobs'] * input['number_of_inputfiles_per_job'])):
                        monitor.record_counter('emulator.panda.tasks.%s.limited_input' % task_type, 1)
                        break
                for tmp_rse in r['rses']:
                    if tmp_rse not in cnt_rses.keys():
                        cnt_rses[tmp_rse] = 0
                    cnt_rses[tmp_rse] += 1
            print '== PanDA: Replica distribution over RSEs: %s files -> %s' % (len(files), cnt_rses)
            if not (task_type.startswith('user') or task_type.startswith('group')):
                rse = sorted(cnt_rses, key=cnt_rses.get, reverse=True)[0]
                for i in range(len(target_rses)):
                    target_rses[i] = rse

            monitor.record_counter('emulator.panda.tasks.%s.input_files' % task_type, len(files))  # Reports the number of files in the intput dataset of the task type
            file_ids = files

            # Release memory by cleaning the two objects
            file_keys = None

            # ------------------------------- Determine metadata for output dataset ------------------------------------
            meta = dict()
            success = False
            retry = 1
            while not success:
                try:
                    with monitor.record_timer_block('emulator.panda.client.get_metadata'):
                        meta_i = client.get_metadata(scope=input['scope'], name=input['ds_name'])
                    success = True
                except (DatabaseException, ConnectionError):
                    monitor.record_counter('emulator.panda.retry.get_metadata.%s' % (retry), 1)
                    retry += 1
                    if retry > 5:
                        monitor.record_counter('emulator.panda.tasks.%s.missing_input_meta.timeout' % (task_type), 1)
                        raise
            for key in ['stream_name', 'project']:
                if meta_i[key] is not None:
                    meta[key] = meta_i[key]
                else:
                    monitor.record_counter('emulator.panda.tasks.%s.missing_input_meta.%s' % (task_type, key), 1)
                    if key == 'stream_name':
                        meta[key] = 'physics_Egamma'
                    elif key == 'project':
                        meta[key] = 'mc12_8TeV'
                    else:
                        meta[key] = 'NotGivenByInput'
        else:
            output['scope'] = choice(['mc12_8TeV', 'mc12_14TeV'])
            input['ds_name'] = uuid()
            meta = {'stream_name': 'dummy', 'project': output['scope']}
            input['number_of_inputfiles_per_job'] = 1
            files = ['file_%s' % f for f in xrange(input['max_jobs'])]
            file_ids = list()

        meta['run_number'] = int(time.time() / (3600 * 24))
        meta['version'] = uuid()
        meta['task_id'] = task_number
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
                    with monitor.record_timer_block('emulator.panda.client.add_container'):
                        try:
                            client.add_container(scope=output['scope'], name='cnt_%s' % (fds))
                        except ScopeNotFound:
                            print '--------------------- SCopeNotFound', output
                        monitor.record_counter('emulator.panda.tasks.%s.container' % task_type, 1)  # Reports the creation of a container
                        success = True
                except (DatabaseException, ConnectionError):
                    monitor.record_counter('emulator.panda.retry.add_container.%s' % (retry), 1)
                    retry += 1
                    if retry > 5:
                        raise
                    time.sleep(randint(1, 2))
            for i in range(output_datasets_per_datatype):
                final_dss[fds].update({'guid': str(uuid())})
                dsn2 = '%s.%s' % (fds, i)
                out_ds = {'scope': output['scope'], 'name': dsn2, 'dids': [], 'meta': final_dss[fds].copy(),
                          'rules': [{'account': output['account'], 'copies': 1, 'rse_expression': target_rses[i], 'grouping': 'DATASET', 'lifetime': output['lifetime']}]}
                temp.append(out_ds)
                if not bulk:
                    success = False
                    retry = 1
                    while not success:
                        try:
                            with monitor.record_timer_block('emulator.panda.client.add_dataset'):
                                client.add_dataset(**out_ds)
                            success = True
                        except (DatabaseException, ConnectionError):
                            monitor.record_counter('emulator.panda.retry.add_dataset.%s' % (retry), 1)
                            retry += 1
                            if retry > 5:
                                raise
                            time.sleep(randint(1, 2))
                    success = False
                    retry = 1
                    while not success:
                        try:
                            with monitor.record_timer_block('emulator.panda.client.add_datasets_to_container'):
                                client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % (fds), dsns=[{'scope': output['scope'], 'name': dsn2}])
                            success = True
                        except (DatabaseException, ConnectionError):
                            monitor.record_counter('emulator.panda.retry.add_datasets_to_container.%s' % (retry), 1)
                            retry += 1
                            if retry > 5:
                                raise
                            time.sleep(randint(1, 2))
                    monitor.record_counter('emulator.panda.tasks.%s.output_datasets' % task_type, 1)  # Reports the number of output datasets for the tasktype (including log datasets)
            if bulk:
                success = False
                retry = 1
                while not success:
                    try:
                        with monitor.record_timer_block(['emulator.panda.client.add_datasets', ('emulator.panda.client.add_datasets.normalized', len(temp))]):
                            client.add_datasets(temp)
                        monitor.record_counter('emulator.panda.tasks.%s.output_datasets' % task_type, len(temp))  # Reports the number of output datasets for the tasktype (including log datasets)
                        success = True
                    except (InvalidRSEExpression):
                        print '------------------- InvalidRSEExpression ------------------------------------'
                        for ds in temp:
                            print ds['scope'], ds['name'], ds['rules']
                        print '------------------- InvalidRSEExpression ------------------------------------'
                        raise
                    except (InsufficientTargetRSEs) as e:
                        print '------------------- InsufficientTargetRSEs ------------------------------------'
                        print e
                        for ds in temp:
                            print ds['scope'], ds['name'], ds['rules']
                        print '------------------- InsufficientTargetRSEs ------------------------------------'
                        raise

                    except (DatabaseException, ConnectionError):
                        monitor.record_counter('emulator.panda.retry.add_datasets.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        time.sleep(randint(1, 2))
                success = False
                retry = 1
                while not success:
                    try:
                        with monitor.record_timer_block(['emulator.panda.client.add_datasets_to_container', ('emulator.panda.client.add_datasets_to_container.normailzed', len(temp))]):
                            client.add_datasets_to_container(scope=output['scope'], name='cnt_%s' % (fds), dsns=[{'scope': dsn['scope'], 'name': dsn['name']} for dsn in temp])
                        success = True
                    except (DatabaseException, ConnectionError):
                        monitor.record_counter('emulator.panda.retry.add_datasets_to_container.%s' % (retry), 1)
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
                    inserts_dis.append({'scope': 'panda', 'name': dis_ds, 'lifetime': 172800,
                                        'rules': [{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}],
                                        'dids': files_in_ds})  # Create DIS-Datasets
                else:
                    with monitor.record_timer_block('emulator.panda.client.add_dataset'):
                        client.add_dataset(scope='panda', name=dis_ds, lifetime=172800,
                                           rules=[{'account': 'panda', 'copies': 1, 'rse_expression': computing_rse, 'grouping': 'DATASET'}])  # Create DIS-Datasets
                    with monitor.record_timer_block(['emulator.panda.client.add_files_to_dataset', ('emulator.panda.client.add_files_to_dataset.normalized', len(files_in_ds))]):
                        client.add_files_to_dataset(scope='panda', name=dis_ds, files=files_in_ds)  # Add files to DIS - dataset
                monitor.record_counter('emulator.panda.tasks.%s.dis_datasets' % task_type, 1)  # Reports the creation of a dis dataset for the given task type
                monitor.record_counter('emulator.panda.tasks.%s.dis_files' % task_type, len(files_in_ds))  # Reports the number of files in the dis - dataset
                computing_rse = None
        else:  # No Dis created, protect files by rules from deletion
            if task_type.startswith('prod'):  # T1 job, single RSE
                if input_ds_used:  # Create rules to protect replicas from deletion
                    with monitor.record_timer_block(['emulator.panda.client.add_replication_rule', ('emulator.panda.client.add_replication_rule.normalized', len(files))]):
                        client.add_replication_rule(files, copies=1, rse_expression=target_rses[0],
                                                    grouping='NONE', account='panda', lifetime=172800)
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
                        with monitor.record_timer_block(['emulator.panda.client.add_replication_rule', ('emulator.panda.client.add_replication_rule.normalized', len(files_in_ds))]):
                            try:
                                client.add_replication_rule(files_in_ds, copies=1, rse_expression=computing_rse,
                                                            grouping='NONE', account='panda', lifetime=172800)
                            except InsufficientTargetRSEs:
                                print '----------------------------------------------- InsuffcientTargetsRSEs 2 -------------------------------------'
                                print files_in_ds
                                print computing_rse
                                print '----------------------------------------------- InsuffcientTargetsRSEs 2 -------------------------------------'
                    temp_job_count = int(float(len(files_in_ds)) / input['number_of_inputfiles_per_job']) + 1

                    if computing_rse not in used_rses.keys():
                        used_rses[computing_rse] = list()
                    used_rses[computing_rse].append((None, temp_job_count))
                    computing_rse = None

        if create_sub_ds:
            for computing_rse in used_rses:
                for temp in used_rses[computing_rse]:
                    id = uuid()
                    subs = ['SUB_%s_%s' % (id, fin_ds) for fin_ds in final_dss]
                    jobs.append(('panda', subs, int(temp[1]), computing_rse))  # temp[1] = number of jobs writing to SUB ds
                    for ds in subs:
                        if len(ds) > 255:
                            print '!!WARNING!! SUB %s shortened to %s' % (ds, ds[:254])
                            ds = ds[:254]
                        if bulk:
                            inserts_sub.append({'scope': 'panda', 'name': ds, 'lifetime': 172800, 'dids': [],
                                                'rules': [{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rses[0]),
                                                           'grouping': 'DATASET'}]})  # Create SUB-Datasets
                        else:
                            with monitor.record_timer_block('emulator.panda.client.add_dataset'):
                                client.add_dataset(scope='panda', name=ds, lifetime=172800,
                                                   rules=[{'account': 'panda', 'copies': 2, 'rse_expression': '%s|%s' % (computing_rse, target_rses[0]), 'grouping': 'DATASET'}])  # Create SUB-Datasets
                        monitor.record_counter('emulator.panda.tasks.%s.sub_datasets' % task_type, 1)  # Reports the creation of a sub dataset for the given task type
        else:
            for computing_rse in used_rses:
                for temp in used_rses[computing_rse]:
                    jobs.append((output['scope'], final_dss, int(temp[1]), computing_rse))

        # -------------------------------------- Perform bulk inserts ----------------------------------------
        if bulk:
            datasets = inserts_dis + inserts_sub
            if len(datasets):
                with monitor.record_timer_block(['emulator.panda.client.add_datasets', ('emulator.panda.client.add_datasets.normalized', len(datasets))]):
                    client.add_datasets(datasets)
            ts = list()
            ts_res = Queue()
            for ds in inserts_dis:
                if threads:
                    t = threading.Thread(target=self.add_files_ds, kwargs={'client': client, 'ds': ds, 'ret': ts_res, 'sem': sem})
                    t.start()
                    ts.append(t)
                else:
                    self.add_files_ds(client, ds)
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
        job_number = 0
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
                job_number += 1
                input_file = choice(file_ids) if len(file_ids) else {'scope': None, 'name': None}
                job_finish.append((float(job_completion), {'scope': job_set[0], 'targets': job_set[1], 'computing_rse': job_set[3],
                                                           'task_type': task_type, 'log_ds': log_ds, 'task_type_id': task_type_id,
                                                           'task_number': task_number, 'job_number': '%06d' % job_number,
                                                           'input': {'scope': input_file['scope'], 'name': input_file['name']}}))

            # Remeber last access to target dataset
            max_target_completion += safety_delay
            for dsn in job_set[1]:
                if (dsn not in sub_finish.keys()) or (sub_finish[dsn][0] < max_target_completion):
                    for fin_ds in final_dss:
                        if dsn.endswith(fin_ds):
                            sub_finish[dsn] = (float(max_target_completion), {'source': {'scope': job_set[0], 'name': dsn}, 'target': {'scope': output['scope'], 'name': fin_ds}, 'task_type': task_type})

            # Update task completion
            if max_completion < max_target_completion:
                max_completion = max_target_completion

        max_completion += safety_delay  # Note: Triggers FINISH_TASK some time later to avoid conflicts if job is stuck in gearman queue

        if create_sub_ds:
            max_completion += gauss(**file_transfer_duration)
        else:
            sub_finish = {}  # Empty list of sub datasets to avoid data moving when task is finished
        task_finish = (float(max_completion), {'scope': output['scope'], 'targets': final_dss, 'task_type': task_type, 'log_ds': log_ds})
        monitor.record_counter('emulator.panda.tasks.%s.dispatched' % task_type, 1)  # Reports the task type which is dipsatched
        monitor.record_counter('emulator.panda.tasks.%s.number_job' % task_type, len(job_finish) * output_datasets_per_datatype)  # Reports the number of jobs spawned from the given task
        print '== PanDA: Create %s task with %s files (%s repl.) with output scope %s (dis: %s / sub: %s (%s)/ log_ds: %s / out_ds: %s / jobs: %s (%s))' % (task_type, len(files), len(replicas),
                                                                                                                                                            output['scope'], len(inserts_dis),
                                                                                                                                                            len(inserts_sub), len(sub_finish), log_ds,
                                                                                                                                                            final_dss, job_count, len(job_finish) * output_datasets_per_datatype)
        # print '-', job_finish
        # print '-', sub_finish
        # print '-', task_finish
        return {'jobs': job_finish, 'subs': sub_finish.values(), 'task': task_finish}

    def add_files_ds(self, client, ds, ret=None, sem=None):
        if not client:
            client = Client(account='panda')
        success = False
        retry = 1
        while not success:
            try:
                if sem:
                    sem.acquire()
                with monitor.record_timer_block(['emulator.panda.client.add_files_to_dataset', ('emulator.panda.client.add_files_to_dataset.normalized', len(ds['dids']))]):
                    client.add_files_to_dataset(scope=ds['scope'], name=ds['name'], files=ds['dids'])
                success = True
            except (DatabaseException, ConnectionError):
                e = sys.exc_info()
                monitor.record_counter('emulator.panda.retry.add_files_to_dataset.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    if ret:
                        ret.put((False, e))
                        return
                    else:
                        print e
                        raise
                print '== PanDA Warning [%s]: Failed %s times when adding files to dataset (%s:%s). Will retry in 5 seconds.' % (time.strftime('%D %H:%M:%S', time.localtime()), retry, ds['scope'], ds['name'])
                time.sleep(randint(1, 2))
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
                # print '== PanDA [%s]: Selecting task from group %s' % (time.strftime('%D %H:%M:%S', time.localtime()), tt.split('-')[0])
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
        now = time.time()
        with ctx.job_queue_mutex:
            monitor.record_timer('emulator.panda.helper.waiting.job_queue_mutex.sorting', (time.time() - now))
            for job in output['jobs']:
                with monitor.record_timer_block('emulator.panda.helper.sorting_jobs'):
                    bisect.insort(ctx.job_queue, job)
        now = time.time()
        with ctx.sub_queue_mutex:
            monitor.record_timer('emulator.panda.helper.waiting.sub_queue_mutex.sorting', (time.time() - now))
            for sub in output['subs']:
                with monitor.record_timer_block('emulator.panda.helper.sorting_subs'):
                    bisect.insort(ctx.sub_queue, sub)
        if len(output['task']):
            now = time.time()
            with ctx.task_queue_mutex:
                monitor.record_timer('emulator.panda.helper.waiting.task_queue_mutex.sorting', (time.time() - now))
                with monitor.record_timer_block('emulator.panda.helper.sorting_tasks'):
                    bisect.insort(ctx.task_queue, output['task'])

    @UCEmulator.UseCase
    def FINISH_JOB(self, jobs, threads):
        client = Client(account='panda')
        if threads:
            sem = threading.BoundedSemaphore(threads)

        # Group jobs by sub: if the frequency on the DB should be decreased
        ts = list()
        ts_res = Queue()
        for job in jobs:
            try:
                if job['input']['scope'] and job['input']['name']:
                    now = time.time()
                    with monitor.record_timer_block('emulator.panda.client.list_replicas'):
                        replicas = [f for f in client.list_replicas([job['input']], schemes=None, unavailable=True)]
                    delta = time.time() - now
                    if delta > 600:
                        print '== PanDA-TIMER_3: Listing replicas in %s:%s took %s seconds' % (job['input']['scope'], job['input']['name'], delta)
                    if job['computing_rse'] in replicas[0]['rses'].keys():
                        monitor.record_counter('emulator.panda.helper.replicas.found', 1)
                    else:
                        monitor.record_counter('emulator.panda.helper.replicas.not_found', 1)
            except Exception, e:
                print '------------ ERROR when listing replicas of certain file ------------------------'
                print e
                print traceback.format_exc(e)
                print '------------ ERROR when listing replicas of certain file ------------------------'
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
                print '!! ERROR !! --' * 5
                print traceback.format_exc(ret[1][2])
                print '!! ERROR !! --' * 5
                raise ret[1][0]
        targets = []
        replicas = 0
        for job in jobs:
            targets += job['targets']
            replicas += len(job['targets']) if job['log_ds'] else (2 * len(job['targets']))
        print '== PanDA [%s]: Registering %s replicas from %s jobs over %s different datasets' % (time.strftime('%D %H:%M:%S', time.localtime()), replicas, len(jobs), len(set(targets)))

    def register_replica(self, client, job, ret=None, sem=None):
        if not client:
            client = Client(account='panda')
        count = 0
        attachments = list()
        i = 0
        for tds in job['targets']:
            # Create output files of the job
            files = list()
            out_name = '%s.%s._%s.pool.root.%s' % (job['task_type_id'], job['task_number'], job['job_number'], i)
            log_name = 'log.%s.%s._%s.job.log.tgz.%s' % (job['task_type_id'], job['task_number'], job['job_number'], i)
            if not job['log_ds']:  # Add log file for each datatype if task doesn't have LOG dataset
                files.append({'scope': job['scope'], 'name': out_name, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid()), 'task_id': int(job['task_number']), 'panda_id': int(job['job_number'])}})
                files.append({'scope': job['scope'], 'name': log_name, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid()), 'task_id': int(job['task_number']), 'panda_id': int(job['job_number'])}})
            else:
                fn = out_name if tds.split('.')[-1] != 'log' else log_name
                files.append({'scope': job['scope'], 'name': fn, 'bytes': 12345L, 'adler32': '0cc737eb', 'meta': {'guid': str(uuid()), 'task_id': int(job['task_number']), 'panda_id': int(job['job_number'])}})
            attachments.append({'scope': job['scope'], 'name': tds, 'rse': job['computing_rse'], 'dids': files})
            count += len(files)
            i += 1

        success = False
        retry = 1
        e = None
        now = time.time()
        while not success:
            try:
                if sem:
                    sem.acquire()
                with monitor.record_timer_block('emulator.panda.client.attach_dids_to_dids'):
                    client.attach_dids_to_dids(attachments=attachments)
                success = True
            except DatabaseException:
                e = sys.exc_info()
                monitor.record_counter('emulator.panda.retry.panda.attach_dids_to_dids.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    break
                print '== PanDA Warning: Failed %s times when adding files to datasets: %s' % (retry, attachments)
                time.sleep(randint(1, 2))
            except:
                print '=+=+=' * 10
                print attachments
                print '=+=+=' * 10
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
            print '-', traceback.format_exc(e)
            print '-', count
            print '-' * 80
            if ret:
                ret.put((False, e))
        else:
            monitor.record_counter('emulator.panda.tasks.%s.replicas' % job['task_type'], count)  # Reports the creation of a new replica (including log files) fof the given task type
            print '== PanDA: Job (%s) added %s files to %s datasets (%s:%s)' % (job['task_type'], count, len(job['targets']), job['scope'], job['targets'])
            if ret:
                ret.put((True, count))

    def FINISH_JOB_input(self, ctx):
        ctx.job_print += 1
        if not len(ctx.job_queue):
            if not ctx.job_print % 100:
                print '== PanDA [%s]: No jobs scheduled so far.' % (time.strftime('%D %H:%M:%S', time.localtime()))
            return None
        jobs = []
        if ctx.job_queue_select.acquire(False):  # Check if there is already one thread waiting to select items from queue
            now = time.time()
            with ctx.job_queue_mutex:
                monitor.record_timer('emulator.panda.helper.waiting.job_queue_mutex.selecting', (time.time() - now))
                now = time.time()
                tmp_cnt = 0
                with monitor.record_timer_block('emulator.panda.helper.selecting_jobs'):
                    for job in ctx.job_queue:
                        tmp_cnt += 1
                        if job[0] < now:
                            jobs.append(job[1])
                        else:
                            if not len(jobs):
                                ctx.job_queue = sorted(ctx.job_queue, key=lambda job: job[0])
                            break
                    del ctx.job_queue[0:len(jobs)]
            ctx.job_queue_select.release()
        else:
            print '== PanDA [%s]: Already one thread waiting for pending jobs.' % (time.strftime('%D %H:%M:%S', time.localtime()))
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(jobs):
            print '== PanDA [%s]: Finishing %s jobs.' % (time.strftime('%D %H:%M:%S', time.localtime()), len(jobs))
            monitor.record_counter('emulator.panda.helper.jobs_block', len(jobs))
            return {'jobs': jobs, 'threads': threads}
        else:
            if not ctx.job_print % 100:
                print '== PanDA [%s]: Next job finishes in %.1f minutes (%s)' % (time.strftime('%D %H:%M:%S', time.localtime()), ((ctx.job_queue[0][0] - now) / 60), time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[0][0])))
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
            print '== PanDA [%s]: Populating SUB-DS (%s) to target (%s) for job %s' % (time.strftime('%D %H:%M:%S', time.localtime()), sub['source'], sub['target'], sub['task_type'])
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
        ctx.sub_print += 1
        if not len(ctx.sub_queue):
            if not ctx.sub_print % 100:
                print '== PanDA [%s]: No subs scheduled so far.' % (time.strftime('%D %H:%M:%S', time.localtime()))
            return None
        subs = []
        if ctx.sub_queue_select.acquire(False):  # Check if there is already one thread waiting to select items from queue
            now = time.time()
            with ctx.sub_queue_mutex:
                monitor.record_timer('emulator.panda.helper.waiting.sub_queue_mutex.selecting', (time.time() - now))
                now = time.time()
                with monitor.record_timer_block('emulator.panda.helper.selecting_subs'):
                    for sub in ctx.sub_queue:
                        if sub[0] < now:
                            subs.append(sub[1])
                        else:
                            if not len(subs):
                                ctx.sub_queue = sorted(ctx.sub_queue, key=lambda sub: sub[0])
                            break
                    del ctx.sub_queue[0:len(subs)]
            ctx.sub_queue_select.release()
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(subs):
            monitor.record_counter('emulator.panda.helper.subs_block', len(subs))
            return {'subs': subs, 'threads': threads, 'safety_delay': ctx.safety_delay}
        else:
            if not ctx.sub_print % 100:
                print '== PanDA [%s]: Next sub datset is populated in  %.1f minutes (%s)' % (time.strftime('%D %H:%M:%S', time.localtime()), ((ctx.sub_queue[0][0] - now) / 60), time.strftime('%D %H:%M:%S', time.localtime(ctx.sub_queue[0][0])))
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
                with monitor.record_timer_block('emulator.panda.client.list_files'):
                    fs = [f for f in client.list_files(**source)]
                if len(fs):
                    monitor.record_timer('emulator.panda.client.list_files.normalized', (time.time() - now) / len(fs))
                    monitor.record_counter('emulator.panda.tasks.%s.sub_files' % task_type, len(fs))
                    print '== PanDA [%s]: Adding %s files from SUB (%s) to TID (%s)' % (time.strftime('%D %H:%M:%S', time.localtime()), len(fs), source, target)
                else:
                    print '== PanDA Warning [%s]: No data task arrived for %s. Will Retry later.' % (time.strftime('%D %H:%M:%S', time.localtime()), source)
                    retry += 1
                    if retry > 5:
                        print '== PanDA Warning [%s]: No data task arrived for %s. Gave up' % (time.strftime('%D %H:%M:%S', time.localtime()), source)
                        monitor.record_counter('emulator.panda.tasks.%s.EmptySubDataset' % task_type, 1)
                        with monitor.record_timer_block('emulator.panda.client.close'):
                            client.close(**source)
                        return
                    time.sleep(randint(3, 5))
            except DatabaseException:
                exc = sys.exc_info()
                fs = []
                print '== PanDA [%s]: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (time.strftime('%D %H:%M:%S', time.localtime()), source, retry, task_type)
                monitor.record_counter('emulator.panda.retry.list_files.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    print '== PanDA [%s]: No data task arrived for %s. Gave up' % (time.strftime('%D %H:%M:%S', time.localtime()), source)
                    monitor.record_counter('emulator.panda.tasks.%s.EmptySubDataset' % task_type, 1)
                    with monitor.record_timer_block('emulator.panda.client.close'):
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
        success = False
        retry = 1
        while not success:
            try:
                if sem:
                    sem.acquire()
                with monitor.record_timer_block(['emulator.panda.client.add_files_to_dataset', ('emulator.panda.client.add_files_to_dataset.normalized', len(fs))]):
                    client.add_files_to_dataset(scope=target['scope'], name=target['name'], files=fs)
                success = True
            except Exception:
                exc = sys.exc_info()
                print '== PanDA: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (source, retry, task_type)
                monitor.record_counter('emulator.panda.retry.add_files_to_dataset.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    if ret:
                        ret.put((False, exc))
                    return
            finally:
                if sem:
                    sem.release()
            print '== PanDA [%s]: Populated %s files from %s to %s' % (time.strftime('%D %H:%M:%S', time.localtime()), len(fs), source, target)

        # Close SUB dataset
        success = False
        retry = 1
        while not success:
            try:
                if sem:
                    sem.acquire()
                with monitor.record_timer_block('emulator.panda.client.close'):
                    client.close(**source)
                success = True
            except DatabaseException:
                exc = sys.exc_info()
                print '== PanDA: Waiting 5 seconds for task data to arrive in %s (retry count: %s / task-type: %s)' % (source, retry, task_type)
                monitor.record_counter('emulator.panda.retry.close.%s' % (retry), 1)
                retry += 1
                if retry > 5:
                    if ret:
                        ret.put((False, exc))
                    return
            finally:
                if sem:
                    sem.release()
        print '== PanDA [%s]: Closed sub dataset: %s' % (time.strftime('%D %H:%M:%S', time.localtime()), source)
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
                        with monitor.record_timer_block('emulator.panda.client.list_files'):
                            fs = [f for f in client.list_files(scope=task['scope'], name=target)]
                        if len(fs):
                            monitor.record_timer('emulator.panda.client.list_files.normalized', (time.time() - now) / len(fs))
                            monitor.record_counter('emulator.panda.tasks.%s.output_ds_size' % task_type, len(fs))  # Reports the number of files added to the output dataset
                        else:
                            monitor.record_counter('emulator.panda.tasks.%s.EmptyOutputDataset' % task_type, 1)
                        success = True
                    except DatabaseException:
                        monitor.record_counter('emulator.panda.retry.list_files.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        print '== PanDA Warning [%s]: Failed %s times to list files in dataset (%s:%s). Will rertry in 5 seconds.' % (time.strftime('%D %H:%M:%S', time.localtime()), retry, task['scope'], target)
                        time.sleep(randint(1, 2))
                    except Exception:
                        e = sys.exc_info()
                        print '-' * 80
                        print '- Failed listing files in TID: %s:%s' % (task['scope'], target)
                        print '-', traceback.format_exc(e)
                        print '-' * 80
                        raise
                retry = 1
                success = False
                while not success:
                    try:
                        with monitor.record_timer_block('emulator.panda.client.close'):
                            client.close(scope=task['scope'], name=target)
                        success = True
                    except UnsupportedOperation:
                        break
                    except DatabaseException:
                        monitor.record_counter('emulator.panda.retry.close.%s' % (retry), 1)
                        retry += 1
                        if retry > 5:
                            raise
                        print '== PanDA Warning: Failed %s times to close the dataset (%s:%s). Will rertry in 5 seconds.' % (retry, task['scope'], target)
                        time.sleep(randint(1, 2))
                print '== PanDA [%s]: Closed output dataset %s:%s from task (%s) including %s files' % (time.strftime('%D %H:%M:%S', time.localtime()), task['scope'], target, task_type, len(fs))
            monitor.record_counter('emulator.panda.tasks.%s.finished' % task_type, 1)

    def FINISH_TASK_input(self, ctx):
        ctx.task_print += 1
        if not len(ctx.task_queue):
            if not ctx.task_print % 100:
                print '== PanDA [%s]: No tasks scheduled so far.' % (time.strftime('%D %H:%M:%S', time.localtime()))
            return None
        tasks = []
        if ctx.task_queue_select.acquire(False):  # Check if there is already one thread waiting to select items from queue
            now = time.time()
            with ctx.task_queue_mutex:
                monitor.record_timer('emulator.panda.helper.waiting.task_queue_mutex.selecting', (time.time() - now))
                now = time.time()
                with monitor.record_timer_block('emulator.panda.helper.selecting_tasks'):
                    for task in ctx.task_queue:
                        if task[0] < now:
                            tasks.append(task[1])
                        else:
                            if not len(tasks):
                                ctx.task_queue = sorted(ctx.task_queue, key=lambda task: task[0])
                            break
                    del ctx.task_queue[0:len(tasks)]
            ctx.task_queue_select.release()
        if (ctx.threads == 'False') or int(ctx.threads) < 2:
            threads = None
        else:
            threads = int(ctx.threads)
        if len(tasks):
            # print '== PanDA [%s]: Finishing %s tasks.' % (time.strftime('%D %H:%M:%S', time.localtime()), len(tasks))
            monitor.record_counter('emulator.panda.helper.tasks_block', len(tasks))
            return {'tasks': tasks, 'threads': threads, 'safety_delay': ctx.safety_delay}
        else:
            if not ctx.task_print % 100:
                print '== PanDA [%s]: Next task is finsihed in  %.1f minutes (%s)' % (time.strftime('%D %H:%M:%S', time.localtime()), ((ctx.task_queue[0][0] - now) / 60), time.strftime('%D %H:%M:%S', time.localtime(ctx.task_queue[0][0])))
            return None

    def RESET_input(self, ctx):
        print '== PanDA [%s]: Reseting input files cache' % time.strftime('%D %H:%M:%S', time.localtime())
        monitor.record_counter('emulator.panda.tasks.reset', 1)
        ctx.input_files = {}
        return None

    def RESET(self):
        pass  # Will never be executed, only here for sematic reasons

    def QUEUE_OBSERVER(self):
        pass  # Will never be executed, only here for sematic reasons

    def QUEUE_OBSERVER_input(self, ctx):
        monitor.record_gauge('emulator.panda.tasks.queue', len(ctx.task_queue))
        monitor.record_gauge('emulator.panda.jobs.queue', len(ctx.job_queue))
        monitor.record_gauge('emulator.panda.subs.queue', len(ctx.sub_queue))
        print '== PanDA [%s]: Task-Queue: %s / Job-Queue: %s / Sub-Queue: %s' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.task_queue), len(ctx.job_queue), len(ctx.sub_queue))
        tmp_str = 'Job Queue\n'
        tmp_str += '---------\n'
        if len(ctx.job_queue) > 11:
            for i in range(10):
                tmp_str += '\t%s: %s\n' % (i, time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[i][0])))
            tmp_str += '---------'
            print tmp_str

        return None  # Indicates that no further action is required

    def setup(self, ctx):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """
        # As long as there is no database filler, one dataset and n files are created here
        ctx.job_queue = []
        ctx.job_queue_mutex = threading.Lock()
        ctx.job_queue_select = threading.Lock()
        ctx.job_print = 0
        ctx.sub_queue = []
        ctx.sub_queue_mutex = threading.Lock()
        ctx.sub_queue_select = threading.Lock()
        ctx.sub_print = 0
        ctx.task_queue = []
        ctx.task_queue_mutex = threading.Lock()
        ctx.task_queue_select = threading.Lock()
        ctx.task_print = 0
        try:
            print '== PanDA [%s]: Loading context file' % (time.strftime('%D %H:%M:%S', time.localtime()))
            with open('/tmp/panda.ctx', 'r') as f:
                stuff = pickle.load(f)
            delta = (time.time() - stuff[0]) + 135  # safety
            print '== PanDA [%s]: Start importing previous context (written at: %s / delta: %.2f min)' % (time.strftime('%D %H:%M:%S', time.localtime()),
                                                                                                          time.strftime('%D %H:%M:%S', time.localtime(stuff[0])), (delta / 60))
            ctx.job_queue = sorted(stuff[1])
            for job in ctx.job_queue:
                job[0] += delta
            print '== PanDA [%s]: Re-imported %s jobs to queue (min: %s / max: %s).' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.job_queue),
                                                                                        time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[0][0])), time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[-1][0])))
            ctx.sub_queue = sorted(stuff[2])
            for sub in ctx.sub_queue:
                sub[0] += delta
            print '== PanDA [%s]: Re-imported %s subs to queue (min: %s / max: %s).' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.sub_queue),
                                                                                        time.strftime('%D %H:%M:%S', time.localtime(ctx.sub_queue[0][0])), time.strftime('%D %H:%M:%S', time.localtime(ctx.sub_queue[-1][0])))
            ctx.task_queue = sorted(stuff[3])
            for task in ctx.task_queue:
                task[0] += delta
            print '== PanDA [%s]: Re-imported %s tasks to queue (min: %s / max: %s).' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.task_queue),
                                                                                         time.strftime('%D %H:%M:%S', time.localtime(ctx.task_queue[0][0])), time.strftime('%D %H:%M:%S', time.localtime(ctx.task_queue[-1][0])))
            del stuff
        except IOError:
            print '== PanDA: No information about former execution found'
        except EOFError:
            print '== PanDA: Panda context file found, but unable to load it.'
        ctx.input_files = {}

        client = Client(account='panda')
        ctx.users = list()
        ctx.groups = list()
        for a in client.list_accounts():
            if a['type'] == 'USER' and not a['account'].startswith('user'):
                if a['account'].startswith('jdoe') or a['account'] in ['tier0', 'tzero', 'panda', 'root']:
                    continue  # Prevents 'value too large' error for scope names
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
        dist_prefix = '/tmp/listdatasets2/'

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
            except Exception:  # , e:
                ctx.input_files[dist_file] = False  # Remeber that this file doen't exist
                # print '!! ERROR !! Can read dataset name from distribution file: %s' % e
                if retry > 5:
                    return 0
        return ds

    def shutdown(self, ctx):
        monitor.record_gauge('emulator.panda.tasks.queue', 0)
        monitor.record_gauge('emulator.panda.jobs.queue', 0)
        monitor.record_gauge('emulator.panda.subs.queue', 0)
        print '== PanDA [%s]: Persisting jobs: %s (first: %s, last: %s)' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.job_queue), time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[0][0])),
                                                                            time.strftime('%D %H:%M:%S', time.localtime(ctx.job_queue[-1][0])))
        print '== PanDA [%s]: Persisting subs: %s (first: %s, last: %s)' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.sub_queue), time.strftime('%D %H:%M:%S', time.localtime(ctx.sub_queue[0][0])),
                                                                            time.strftime('%D %H:%M:%S', time.localtime(ctx.sub_queue[-1][0])))
        print '== PanDA [%s]: Persisting tasks: %s (first: %s, last: %s)' % (time.strftime('%D %H:%M:%S', time.localtime()), len(ctx.task_queue), time.strftime('%D %H:%M:%S', time.localtime(ctx.task_queue[0][0])),
                                                                             time.strftime('%D %H:%M:%S', time.localtime(ctx.task_queue[-1][0])))

        with ctx.job_queue_mutex:
            with ctx.sub_queue_mutex:
                with ctx.task_queue_mutex:
                    with open('/tmp/panda.ctx', 'w') as f:
                        pickle.dump([time.time(), ctx.job_queue, ctx.sub_queue, ctx.task_queue], f, pickle.HIGHEST_PROTOCOL)
        print '== PanDA [%s]: Persisted context file.' % (time.strftime('%D %H:%M:%S', time.localtime()))
