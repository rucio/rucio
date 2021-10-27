# UC
# export RUCIO_LATITUDE=41.7821
# export RUCIO_LONGITUDE=-87.6046
# LRZ
# export RUCIO_LATITUDE=51.2993
# export RUCIO_LONGITUDE=9.491
import xmltodict

from rucio.client.replicaclient import ReplicaClient
from rucio.client.didclient import DIDClient
from rucio.common.utils import detect_client_location

did_client = DIDClient()
replica_client = ReplicaClient()
detect_client_location()

scope = 'data17_13TeV'
ds = 'data17_13TeV.00339070.physics_Main.deriv.DAOD_PHYS.r10258_p3399_p4356_tid23589107_00'
fl = []
count = 0

res = did_client.list_files(scope, ds)
for f in res:
    fl.append({'scope': scope, 'name': f['name']})
    count += 1
    if count == 10:
        break

reps = replica_client.list_replicas(dids=fl, schemes=['root'], metalink=False)
for rep in reps:
    print(rep)


# reps = replica_client.list_replicas(dids=fl, schemes=['root'], metalink=True, sort='geoip')
# print(reps)
# d = xmltodict.parse(reps)
# for f in d['metalink']['file']:
#     print(f)

reps = replica_client.list_replicas([{'scope':scope,'name':ds}], schemes=['root'], metalink=True, sort='geoip')
print(reps)
d = xmltodict.parse(reps)
for f in d['metalink']['file']:
    print(f)
