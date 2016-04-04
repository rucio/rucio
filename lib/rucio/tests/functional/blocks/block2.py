# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues, <luis.rodrigues@cern.ch>, 2013


# add_replica(rse='MOCK', scope='test', name='testfile0001', bytes=1, issuer='root')
# add_did(scope='test', name='testdataset1', type='DATASET', issuer='root')
# bulk: see add_replicas
# attach_dids(scope='ftest_scope', name='testdataset1', attachment={'dids': [{'scope': 'ftest_scope', 'name': 'testfile0002', 'type': 'FILE', 'bytes': 1 }, {'scope': 'ftest_scope', 'name': 'testfile0003', 'type': 'FILE', 'bytes': 1 }]}, issuer='root')
# add_replication_rule(dids=[{'scope': 'mock', 'name': 'testfile0001'}], account='root', copies=1, rse_expression='MOCK', grouping='NONE', weight=None, lifetime=None, issuer='root', locked=None, subscription_id=None)

commands = [
    # create the files
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0001', 'bytes': 'RANDOM:int:bytes1', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0002', 'bytes': 'RANDOM:int:bytes2', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0003', 'bytes': 'RANDOM:int:bytes3', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0004', 'bytes': 'RANDOM:int:bytes4', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0005', 'bytes': 'RANDOM:int:bytes5', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0006', 'bytes': 'RANDOM:int:bytes6', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0007', 'bytes': 'RANDOM:int:bytes7', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0008', 'bytes': 'RANDOM:int:bytes8', 'account': 'VAR:ACCOUNT'}},
    {'cmd': 'rse.add_replica', 'kwargs': {'rse': 'MOCK', 'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0009', 'bytes': 'RANDOM:int:bytes9', 'account': 'VAR:ACCOUNT'}},

    # create dataset
    {'cmd': 'did.add_did', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'type': 'DATASET', 'account': 'VAR:ACCOUNT'}},

    # parallel execute
    {'cmd': 'PARALLEL', 'list': [
        [
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0001', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes1'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0002', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes2'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0003', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes3'}], 'account': 'VAR:ACCOUNT'}},
        ],
        [
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0004', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes4'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0005', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes5'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0006', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes6'}], 'account': 'VAR:ACCOUNT'}},
        ],
        [
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0007', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes7'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0008', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes8'}], 'account': 'VAR:ACCOUNT'}},
            {'cmd': 'did.attach_dids', 'kwargs': {'scope': 'VAR:SCOPE', 'name': 'BLOCK:testdataset1', 'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0009', 'type': 'FILE', 'bytes': 'RANDOM:int:bytes9'}], 'account': 'VAR:ACCOUNT'}},
        ], ]
     },

    # add replication rules
    {'return': 'RULE1', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0001'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE2', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0002'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE3', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0003'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE4', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0004'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE5', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0005'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE6', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0006'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE7', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0007'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE8', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0008'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
    {'return': 'RULE9', 'cmd': 'rule.add_rule', 'kwargs': {'dids': [{'scope': 'VAR:SCOPE', 'name': 'BLOCK:testfile0009'}], 'account': 'VAR:ACCOUNT', 'copies': 1,
                                                           'rse_expression': 'MOCK', 'grouping': 'NONE', 'weight': None, 'lifetime': None, 'account': 'VAR:ACCOUNT', 'locked': None, 'subscription_id': None}},
]
