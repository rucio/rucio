#Daemon for distributing sonar test files to available RSE's
import glob,os
import rucio
import subprocess
import threading
import logging
import time

from rucio.client.client import Client
from rucio.common.exception import AccessDenied, DuplicateRule
from rucio.common.exception import ReplicationRuleCreationTemporaryFailed
from rucio.common.exception import RSEBlacklisted, RuleNotFound
from rucio.common.exception import InsufficientAccountLimit

GRACEFUL_STOP = threading.Event()
logging.basicConfig(filename='distribution-daemon.log', level=logging.INFO)
def rename_files(dir,pattern,new_name):
	"""
        Renames the files in the dataset according to the RSE
        on which the dataset is being replicated.
        """
	for cnt,file_name in enumerate(glob.iglob(os.path.join(dir,pattern))):
		logging.info(file_name)
		logging.info(new_name+str(cnt)+'.rnd')
		if( not os.path.isfile(os.path.join(dir,new_name+str(cnt)+'.rnd'))):
			logging.info("renaming..")
			os.rename(file_name,os.path.join(dir,new_name+str(cnt)+'.rnd'))

def distribute_files(client,dataset_dir='small_sonar_dataset',dataset_prefix='sonar.test.small.',scope='user.vzavrtan', num_files=1):
    """
    Check whether the RSE's already containt their respective sonar test dataset
    and distributes the dataset to the ones that do not. Also checks whether the
    RSE's are available for distribution.

    param: dataset_dir - path to the folder which contains the dataset
    param: dataset_prefix - the prefix of the dataset ex. sonar.test.small.AGLT2_SCRATCHDISK = prefix.RSE
    param: num_files - number of files in the dataset
    """
    logging.info("Running disribution iteration")
    #remove the "if '_SCRATCHDISK'" for use on other RSE's
    endpoint_names = [x['rse'] for x in client.list_rses() if '_SCRATCHDISK' in x['rse'] and x['availability']==7]
    ready = []
    rules = client.list_account_rules(account='vzavrtan')
    for rule in rules:
        if dataset_prefix in rule['name'] and rule['rse_expression'] in rule['name'] and rule['state'] == 'OK' and rule['locks_ok_cnt'] == num_files:
            ready.append(rule['rse_expression']) 

    ready = list(set(ready))
    pattern = '*.rnd'
    dir = dataset_dir
    tdir = dir
    startP = 0
    progress_count = 0
    for a in range(startP,len(endpoint_names)):
        logging.info("Progress %d / %d" % (progress_count, len(endpoint_names)))
        progress_count += 1
        if GRACEFUL_STOP.is_set():
            break
        if(endpoint_names[a] not in ready):
            new_dir = dataset_prefix+endpoint_names[a]
            new_name = dataset_prefix+endpoint_names[a]+'.file'
            rename_files(dir,pattern,new_name)
            logging.info("Uploading to %s " % (endpoint_names[a]))
            command = ['rucio','upload',dir,'--rse',endpoint_names[a]]
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            out, err = process.communicate()
            logging.info("Adding dataset %s " % (new_dir))
            try:
                client.add_dataset('user.vzavrtan',new_dir)
            except Exception as e:
                logging.warning("Error adding dataset: "+str(e))
            for cnt,file_name in enumerate(glob.iglob(os.path.join(dir,pattern))):
                logging.info('Attaching to dataset:'+new_dir+' '+scope+':'+os.path.basename(file_name))
                current_did = {'scope':scope, 'name':os.path.basename(file_name)}
                try:
                    client.attach_dids(scope,new_dir,[current_did])
                except Exception as e:
                    logging.warning('Error attaching dids: '+str(e))
            logging.info('Adding rule for dataset')
            dataset_did = {'scope':scope, 'name': new_dir}
            try:
                client.add_replication_rule([dataset_did],1,endpoint_names[a])
            except (DuplicateRule, RSEBlacklisted, ReplicationRuleCreationTemporaryFailed, InsufficientAccountLimit) as exception:
                logging.warning('Error adding replication rule: %s' % (str(exception)))
        else:
            logging.info("%s is already replicated." % endpoint_names[a])

def run_distribution():
    """
    Every x hours tries to distribute the datasets to RSE's that are
    missing them.
    """
    client = Client()
    counter = 0
    dataset_dir = 'sonar_medium_dataset'
    dataset_prefix = 'sonar.test.medium.'
    scope = 'user.vzavrtan'
    num_files = 10
    while not GRACEFUL_STOP.is_set():
        if counter % 12 == 0:
            distribute_files(client, dataset_dir=dataset_dir, dataset_prefix=dataset_prefix, scope=scope, num_files = num_files)
        break
        time.sleep(3600)
        counter += 1
def run():
    #run_distribution()
    thread = threading.Thread(target=run_distribution, kwargs={})
    thread.start()
    while thread and thread.isAlive():
        thread.join(timeout=3.14)
    

def stop(Signum=None, Frame=None):
    log_msg = 'Stopping distribution daemon: %s %s' % (Signum, Frame)
    logging.info(log_msg)
    GRACEFUL_STOP.set()
