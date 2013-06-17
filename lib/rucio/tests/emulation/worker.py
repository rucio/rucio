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
import gearman
import json
import pystatsd
import time


def exec_uc(gearman_worker, gearman_job):
    try:
        uc_data = ast.literal_eval(gearman_job.data)
        if uc_data['class_name'] not in imported_ucs:
            mod_name = '.'.join(uc_data['class_name'].split('.')[:-1])
            class_name = uc_data['class_name'].split('.')[-1]
            mod = __import__(mod_name, fromlist=[class_name])
            cls = getattr(mod, class_name)
            imported_ucs[uc_data['class_name']] = cls(worker_mode=True, carbon_server=carbon_server)
        start = time.time()
        ret = str(getattr(imported_ucs[uc_data['class_name']], uc_data['uc_name'])(**uc_data['input_data']))
        fin = time.time()
        carbon_server.timing(uc_data['uc_name'], (fin - start) * 1000)
    except Exception, e:
        carbon_server.update_stats('exceptions.%s.%s' % (uc_data['class_name'], uc_data['uc_name']), 1)
        print 'Error in: %s.%s: %s' % (uc_data['class_name'], uc_data['uc_name'], e)
        print e
    return ret


print 'Loading configuration from /opt/rucio/etc/emulation.cfg'
with open('/opt/rucio/etc/emulation.cfg') as f:
    cfg = json.load(f)

try:
    gm_worker = gearman.GearmanWorker(cfg['global']['gearman'])
except Exception, e:
    print 'Unable to connect to gearman server: %s' % cfg['gearman']['server']
    print e
    exit(1)

try:
    carbon_server = pystatsd.Client(host=cfg['global']['carbon']['CARBON_SERVER'], port=cfg['global']['carbon']['CARBON_PORT'], prefix=cfg['global']['carbon']['USER_SCOPE'])
except Exception, e:
    print 'Unable to connect to carbon server %s on port %s.' % (cfg['carbon']['CARBON_SERVER'], cfg['carbon']['CARBON_PORT'])
    print e
    exit(2)


# Enter our work loop and call gm_worker.after_poll() after each time we timeout/see socket activity
imported_ucs = dict()
gm_worker.register_task('execute_uc', exec_uc)
gm_worker.work()
