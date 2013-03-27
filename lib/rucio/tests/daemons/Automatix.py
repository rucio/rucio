# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

'''
Automatix is a Data Generatordaemon to generate fake data and upload it on a RSE.
'''

from logging import getLogger, StreamHandler, DEBUG
from os import remove
from sys import exit
from time import sleep


from rucio.common.utils import execute, generate_uuid

logger = getLogger("rucio.tests.daemons.Automatix")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

SUCCESS = 0
FAILURE = 1


# Callback called when you run `supervisorctl stop'
def stop(signum, frame):
    print "Kaboom Baby!"
    exit(SUCCESS)


def run_once():
    fname = '1k-file-' + generate_uuid()
    print 'generate file'
    cmd = '/bin/dd if=/dev/zero of=%(fname)s bs=1k count=1000' % locals()
    exitcode, out, err = execute(cmd)
    print out
    print err
    print 'Upload it against a RSE'
    cmd = 'rucio upload --files %(fname)s --rse RUCIO_TEST_CERN-PROD_TMPDISK  --scope tests' % locals()
    print cmd
    exitcode, out, err = execute(cmd)
    print out
    print err
    remove(fname)


if __name__ == '__main__':
    while True:
        run_once()
        sleep(0.1)
