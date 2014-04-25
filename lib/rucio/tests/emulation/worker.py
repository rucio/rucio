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
import pystatsd
import time
import traceback


def exec_uc(gearman_worker, gearman_job):
    ret = str()
    # print '== Worker [%s]: %s' % (time.strftime('%H:%M:%S', time.localtime()), gearman_job)
    try:
        try:
            uc_data = json.loads(gearman_job.data)
        except Exception, e:
            print '-' * 80
            print 'Unable to import JSON string'
            print type(gearman_job.data)
            print e
            print '-' * 80
            raise
        if uc_data['class_name'] not in imported_ucs:
            mod_name = '.'.join(uc_data['class_name'].split('.')[:-1])
            class_name = uc_data['class_name'].split('.')[-1]
            mod = __import__(mod_name, fromlist=[class_name])
            cls = getattr(mod, class_name)
            imported_ucs[uc_data['class_name']] = cls(worker_mode=True, carbon_server=carbon_server)
        print '== Worker [%s]: %s.%s' % (time.strftime('%D %H:%M:%S', time.localtime()), uc_data['class_name'].split('.')[-2], uc_data['uc_name'])
        start = time.time()
        ret = json.dumps(getattr(imported_ucs[uc_data['class_name']], uc_data['uc_name'])(**uc_data['input_data']))
        fin = time.time()
        carbon_server.timing('%s.%s' % (uc_data['class_name'].split('.')[-2], uc_data['uc_name']), (fin - start) * 1000)
    except Exception, e:
        print('== Worker [%s]: exceptions.%s.%s.%s: %s' % (time.strftime('%D %H:%M:%S', time.localtime()), uc_data['class_name'].split('.')[-2], uc_data['uc_name'], e.__class__.__name__.split('.')[-1], e))
        print traceback.format_exc()
        carbon_server.update_stats('exceptions.%s.%s.%s' % (uc_data['class_name'].split('.')[-2], uc_data['uc_name'], (e.__class__.__name__).split('.')[-1]), 1)
    if ret:
        return ret
    else:
        print('== Worker [%s]: !! Return-value error: %s.%s: Returned "None"' % ((time.strftime('%D %H:%M:%S', time.localtime())).split('.')[-1], uc_data['class_name'].split('.')[-2], uc_data['uc_name']))
        return "False"


with open('/opt/rucio/etc/emulation.cfg') as f:
    cfg = json.load(f)

try:
    gm_worker = gearman.GearmanWorker(cfg['global']['gearman'])
except Exception, e:
    print 'Unable to connect to gearman server: %s' % cfg['gearman']['server']
    print e
    exit(1)

try:
    carbon_server = pystatsd.Client(host=cfg['global']['carbon']['CARBON_SERVER'], port=cfg['global']['carbon']['CARBON_PORT'], prefix='%s.%s' % (cfg['global']['carbon']['USER_SCOPE'], 'emulator'))
except Exception, e:
    print 'Unable to connect to carbon server %s on port %s.' % (cfg['global']['carbon']['CARBON_SERVER'], cfg['global']['carbon']['CARBON_PORT'])
    print e
    exit(2)


# Enter our work loop and call gm_worker.after_poll() after each time we timeout/see socket activity
imported_ucs = dict()
gm_worker.register_task('execute_uc', exec_uc)
print 'Worker registered ...'
gm_worker.work()
