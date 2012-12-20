# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

'''
Reaper is a daemon to manage file deletion
'''

from logging import getLogger, StreamHandler, DEBUG
from sys import exit


logger = getLogger("rucio.daemons.Reaper")
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
    pass
