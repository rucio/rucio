"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vitjan Zavrtanik, <vitjan.zavrtanik@gmail.com>, 2017
 - Eric Vaandering <ewv@fnal.gov>, 2020

Sends on demand sonar tests on the link that
is defined by the provided source and destination
RSE.
"""

from __future__ import print_function

import sys

from rucio.client.client import Client
from rucio.common.exception import (DuplicateRule, RSEWriteBlocked,
                                    ReplicationRuleCreationTemporaryFailed)


def main():
    """
    Sends the requested dataset on the link defined
    by the provided names.
    """
    if len(sys.argv) < 4:
        msg = """
    Usage: python send_sonar_tests.py <source_rse> <destination_rse> <scope> <dataset_prefix(optional)>
        """
        print(msg)
        sys.exit(0)

    dataset_prefix = 'sonar.test.medium.'
    if len(sys.argv) > 4:
        dataset_prefix = sys.argv[4]

    source_rse = sys.argv[1]
    destination_rse = sys.argv[2]
    scope = sys.argv[3]

    client = Client()

    rses = list(client.list_rses())
    rse_names = [x['rse'] for x in rses]
    if source_rse not in rse_names:
        print("Cannot find source RSE.")
        sys.exit(0)
    if destination_rse not in rse_names:
        print("Cannot find destination RSE.")
        sys.exit(0)

    if rses[rse_names.index(source_rse)]['availability'] < 1:
        print("Source RSE not available for reading.")
        sys.exit(0)

    if rses[rse_names.index(destination_rse)]['availability'] < 7:
        print("Destination RSE not available for writing.")
        sys.exit(0)

    rep_gen = list(client.list_replicas([{'name': dataset_prefix + source_rse, 'scope': scope}]))
    if rep_gen == []:
        replica_sites = rep_gen[0]['rses'].keys()
        if destination_rse in replica_sites:
            print("Dataset replica already located on the destination rse. Not setting rule.")
            sys.exit(0)
        if source_rse not in replica_sites:
            print("Dataset replica not contained on the source RSE. Not setting rule.")
            sys.exit(0)
    try:
        did = {'name': dataset_prefix + source_rse, 'scope': scope}
        rule_id = client.add_replication_rule([did], 1, destination_rse,
                                              lifetime=36000,
                                              purge_replicas=True,
                                              source_replica_expression=source_rse,
                                              activity='Debug')
        msg = "Sonar test from %s to %s." % (source_rse, destination_rse)
        print(msg)
        msg = "Set rule with rule_id %s." % (rule_id[0])
        print(msg)
    except (DuplicateRule, RSEWriteBlocked, ReplicationRuleCreationTemporaryFailed) as exception:
        print(str(exception))


if __name__ == '__main__':
    main()
