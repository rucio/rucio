# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2013

from json import loads
from random import uniform
from time import time

from rucio.client.didclient import DIDClient
from rucio.core import monitor
from rucio.tests.emulation.ucemulator import UCEmulator


def random_pick(some_list, probabilities):
    x = uniform(0, 1)
    cumulative_probability = 0.0
    for item, item_probability in zip(some_list, probabilities):
        cumulative_probability += item_probability
        if x < cumulative_probability:
            break
    return item


class UseCaseDefinition(UCEmulator):
    """
        Implements Jdoe use cases.
    """

    @UCEmulator.UseCase
    def LIST_DIDS_METADATA(self, scope, metadata):
        jdoe_account = 'jdoe'
        client = DIDClient(account=jdoe_account)

        print 'run with: ' + str(metadata)

        start = time()
        with monitor.record_timer_block('jdoe.list_dids_metadata'):
            dids = [did for did in client.list_dids(scope=scope, filters=metadata, type='dataset')]

        duration = time() - start
        cnt = len(dids)
        print 'got %d dids' % cnt

        monitor.record_counter('jdoe.list_dids_metadata.num_results', cnt)
        if cnt != 0:
            monitor.record_counter('jdoe.list_dids_metadata.time_per_did', duration / cnt)

        return {'no_datasets': cnt}

    def LIST_DIDS_METADATA_input(self, ctx):
        scope = random_pick(ctx.scopes, ctx.scope_probs)

        try:
            metadata = ctx.metadata[scope].next()
        except (StopIteration, ValueError):
            self.read_data(scope, ctx)
            metadata = ctx.metadata[scope].next()

        scope = metadata['project']
        metadata.pop('name', None)

        # print 'metadata picked: ' + str(metadata)

        return {'scope': scope,
                'metadata': metadata}

    def LIST_DIDS_WILDCARD(self, scope, wildcard):
        jdoe_account = 'jdoe'
        client = DIDClient(account=jdoe_account)

        print 'run with: ' + str(wildcard)
        start = time()
        with monitor.record_timer_block('jdoe.list_dids_wildcard'):
            dids = [did for did in client.list_dids(scope=scope, filters=wildcard, type='dataset')]

        duration = time() - start
        cnt = len(dids)
        print 'got %d dids' % cnt

        monitor.record_counter('jdoe.list_dids_wildcard.num_results', cnt)
        if cnt != 0:
            monitor.record_counter('jdoe.list_dids_wildcard.time_per_did', duration / cnt)

        return {'no_datasets': cnt}

    def LIST_DIDS_WILDCARD_input(self, ctx):
        scope = random_pick(ctx.scopes, ctx.scope_probs)

        try:
            metadata = ctx.metadata[scope].next()
        except (StopIteration, ValueError):
            self.read_data(scope, ctx)
            metadata = ctx.metadata[scope].next()

        scope = metadata['project']
        wildcard = {}
        wildcard['name'] = metadata['name']

        # print 'wildcard picked: ' + str(wildcard)

        return {'scope': scope,
                'wildcard': wildcard}

    def read_data(self, scope, ctx):
        input_file = open(ctx.input_files[scope], 'r')
        ctx.metadata[scope] = (loads(line.strip()) for line in input_file)

    def setup(self, ctx):
        ctx.metadata = {}
        print ctx
        for scope in ctx.scopes:
            self.read_data(scope, ctx)

        print 'Jdoe emulation starting'
