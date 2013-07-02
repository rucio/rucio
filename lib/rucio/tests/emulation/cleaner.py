# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


import gearman
import json
import traceback


def exec_uc(gearman_worker, gearman_job):
    try:
        print 'Cleaned'
    except Exception:
        print traceback.format_exc()
    return "None"


with open('/opt/rucio/etc/emulation.cfg') as f:
    cfg = json.load(f)

try:
    gm_worker = gearman.GearmanWorker(cfg['global']['gearman'])
except Exception, e:
    print traceback.format_exc()

gm_worker.register_task('execute_uc', exec_uc)
print 'Cleaner registered ...'
gm_worker.work()
