import xmltodict

from rucio.client.replicaclient import ReplicaClient
from rucio.client.didclient import DIDClient

did_client = DIDClient()
replica_client = ReplicaClient()

scope = 'data18_13TeV'
ds = 'data18_13TeV.periodAllYear.physics_Main.PhysCont.DAOD_PHYS.grp18_v01_p4150'
# ds = 'data18_13TeV.periodB.physics_Main.PhysCont.DAOD_PHYS.grp18_v01_p4150'

scope = 'data15_13TeV'
ds = 'data15_13TeV.00283429.physics_Main.deriv.DAOD_PHYS.r9264_p3083_p4165_tid21568817_00'

count = 0
size = 0

did_info = did_client.get_did(scope, ds)
print(did_info)

# did_info['type'] can be DATASET or CONTAINER.
# did_info['length'] gives number of files or datasets.

content = did_client.list_content(scope, ds)
for c in content:
    print(c)
# looks like
# {'scope': 'data15_13TeV', 'name': 'DAOD_PHYS.21568817._001634.pool.root.1', 'type': 'FILE', 'bytes': 487496290, 'adler32': '526845ce', 'md5': None}
# {'scope': 'data18_13TeV', 'name': 'data18_13TeV.00349533.physics_Main.deriv.DAOD_PHYS.f937_m1972_p4150_tid21267843_00', 'type': 'DATASET', 'bytes': None, 'adler32': None, 'md5': None}


reps = replica_client.list_replicas([{'scope': scope, 'name': ds}], schemes=['root'], metalink=True, sort='geoip')
# print(reps)
f = open("ds.xml", "w")
f.write(reps)
f.close()
d = xmltodict.parse(reps)
for f in d['metalink']['file']:
    # print(f)
    count += 1
    size += f['size']

print('total:', count, 'size:', float(size) / 1024 / 1024 / 1024, 'GB')
