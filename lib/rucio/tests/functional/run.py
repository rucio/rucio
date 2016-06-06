#!/usr/bin/env python

# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues, <luis.rodrigues@cern.ch>, 2013

from rucio.common.exception import Duplicate
from rucio.api.scope import add_scope
from rucio.tests.functional.blocks.block2 import commands

import argparse
import datetime
import random
import threading
import os

VARIABLEHASH = {'ACCOUNT': 'root'}

LOG_PATH = 'logs'


def run_sub_block(index, commands, outfile, block_number):
    """
    Function used to run the parallel section of the block

    :param commands: A list with all the commands that need to be run
    :param block_number: Number of the block that is being executed.
    """
    for c in commands:
        run_command(c, outfile, block_number)

    outfile.close()


def instrospect_args(kwargs, block_number):
    """
    process the kwargs replacing the parameters using the configuration

    :param kwargs: Dictionary with all the parameters.
    :param block_number: Number of the block that is being executed.
    """
    ret = {}
    for k in kwargs.keys():
        if type(kwargs[k]) == str:
            if kwargs[k].startswith('VAR:'):
                _, name = kwargs[k].split(':')
                ret[k] = VARIABLEHASH.get(name)

            elif kwargs[k].startswith('BLOCK:'):
                _, name = kwargs[k].split(':')
                ret[k] = '%s-%d' % (name, block_number)

            elif kwargs[k].startswith('RANDOM:'):
                _, typ, name = kwargs[k].split(':')
                if name in VARIABLEHASH:
                    ret[k] = VARIABLEHASH.get(name)
                else:
                    if typ == 'int':
                        v = random.randint(10000, 100000)
                    elif typ == 'str':
                        v = 'datasetname%s' % random.randint(10000, 100000)  # TODO: make sure it doesnt exist

                    VARIABLEHASH[name] = v
                    ret[k] = v

            else:
                ret[k] = kwargs[k]

        elif type(kwargs[k]) == dict:
            ret[k] = instrospect_args(kwargs[k], block_number)

        elif type(kwargs[k]) == list:
            ret[k] = [instrospect_args(el, block_number) for el in kwargs[k]]

        else:
            ret[k] = kwargs[k]

    return ret


def run_command(command, outfile, block_number):
    """
    Executes a rucio API call with the correct parameters and logs the result

    :param command: dictionary with the API call and parameters.
    :param outfile: file object used to write the logs of this call.
    :param block_number: block number indentifier - process_number * 1000 + repeat_index.
    """
    module, function = command['cmd'].split('.')
    m = __import__('rucio.core.%s' % module, fromlist=[''])
    f = getattr(m, function)

    nargs = instrospect_args(command['kwargs'], block_number)

    # store the return value in global hash
    if 'return' in command:
        VARIABLEHASH[command['return']] = 2

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    line = '%s    %s %s' % (timestamp, function, nargs)
    try:
        f(**nargs)
        line += ' RESULT: OK\n'
    except Exception as ex:
        print ex
        line += ' RESULT: ERROR - %s\n' % ex

    outfile.write(line)


def run_simulation(scope, process_number, number_repeats):
    """
    Process the list of commands specified in a given block

    :param process_number: integer that identifies the process
    :param number_repeats: number of time a block should be repeated
    """
    with open(os.path.join(LOG_PATH, scope, 'main_%s' % process_number), 'a') as main_log_file:
        for x in xrange(number_repeats):
            for c in commands:
                block_number = process_number * 1000 + x
                if c['cmd'] == 'PARALLEL':
                    threads = []
                    for index, code in enumerate(c['list']):
                        thread_log = open(os.path.join(LOG_PATH, scope, 'thread_%s_%s' % (process_number, index)), 'a')
                        thread = threading.Thread(target=run_sub_block, args=(index, code, thread_log, block_number))
                        threads.append(thread)
                        thread.start()

                    for th in threads:
                        th.join()
                else:
                    run_command(c, main_log_file, block_number)


if __name__ == '__main__':
    processes = []

    parser = argparse.ArgumentParser(description='Rucio functional tests.')
    parser.add_argument('scope', type=str, help='scope to use, creates it if it does not exist')

    parser.add_argument('-r', '--repeat', metavar='repeat', type=int, default=1,
                        help='how many time to repeat the block (default: 1)')

    parser.add_argument('-p', '--parallel', metavar='parallel', type=int, default=1,
                        help='how many parallel instances process should be executed (default: 1)')

    args = parser.parse_args()

    print datetime.datetime.now().strftime('Starting functional test at %Y-%m-%d %H:%M')
    print "Scope: %s" % args.scope

    try:
        add_scope(args.scope, 'root', 'root')
        print "Created scope"
    except Duplicate as ex:
        print "Could not create scope: %s" % ex

    VARIABLEHASH['SCOPE'] = args.scope

    # create the folder to write logs
    if not os.path.exists(os.path.join(LOG_PATH, args.scope)):
        os.makedirs(os.path.join(LOG_PATH, args.scope))

    # run the simulation with as much processes as was configured by the user
    for p in xrange(args.parallel):
        p = threading.Thread(target=run_simulation, args=(args.scope, p, args.repeat))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()
