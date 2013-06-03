import gearman
import time
import ast
import json

from pystatsd import Client


print 'Loading configuration from /opt/rucio/etc/emulation.cfg'
with open('/opt/rucio/etc/emulation.cfg') as f:
    cfg = json.load(f)

print 'Connecting to gearman server'
try:
    gm_worker = gearman.GearmanWorker(cfg['global']['gearman'])
except Exception, e:
    print 'Unable to connect to gearman server: %s' % cfg['gearman']['server']
    print e
    exit(1)

print 'Connecting to carbons server'
try:
    carbon_server = Client(host=cfg['global']['carbon']['CARBON_SERVER'], port=cfg['global']['carbon']['CARBON_PORT'], prefix=cfg['global']['carbon']['USER_SCOPE'])
except Exception, e:
    print 'Unable to connect to carbon server %s on port %s.' % (cfg['carbon']['CARBON_SERVER'], cfg['carbon']['CARBON_PORT'])
    print e
    exit(2)


def exec_uc(gearman_worker, gearman_job):
    uc_data = ast.literal_eval(gearman_job.data)
    if uc_data['class_name'] not in imported_ucs:
        mod_name = '.'.join(uc_data['class_name'].split('.')[:-1])
        class_name = uc_data['class_name'].split('.')[-1]
        mod = __import__(mod_name, fromlist=[class_name])
        cls = getattr(mod, class_name)
        imported_ucs[uc_data['class_name']] = cls(worker_mode=True, carbon_server=carbon_server)

    try:
        start = time.time()
        ret = str(getattr(imported_ucs[uc_data['class_name']], uc_data['uc_name'])(**uc_data['input_data']))
        fin = time.time()
        carbon_server.timing(uc_data['uc_name'], (fin - start) * 1000)
    except Exception, e:
        # TODO: Report execptino to graphite
        print e
    return ret

# gm_worker.set_client_id is optional
#gm_worker.set_client_id('local1')
gm_worker.register_task('execute_uc', exec_uc)

imported_ucs = dict()
# Enter our work loop and call gm_worker.after_poll() after each time we timeout/see socket activity
gm_worker.work()
