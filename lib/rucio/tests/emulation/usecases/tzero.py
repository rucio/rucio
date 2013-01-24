# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

'''
tzero use case:
#(1)every 600 seconds do :
#(2)        for each dataset that has new files to upload into DQ2 do :
#(3)             dq2-register -a -x -C -L ... -m <file with data of new files> <DSN> [#calls = O(1500/day), on avg. 30 files per call O(40K/day)]
#(4)             if there will be no more files arriving for this dataset do:
#(5)                    dq2-freeze-dataset -x <DSN> [#calls = O(200/day)]
'''
import uuid
from random import choice
from random import randrange
from random import gauss

from rucio.tests.emulation.ucemulator import UCEmulator
from rucio.client.dataidentifierclient import DataIdentifierClient
from rucio.client.rseclient import RSEClient


class UseCaseDefinition(UCEmulator):
    """
        Implements all TZero use cases.
    """

    @UCEmulator.UseCase
    def UC_DQ2_REGISTER_NEW(self, tse):
        """
            Registers a new dataset using the add_identifier method.

            :param tse: time series element of the current time frame
        """
        self.dataset_meta['run_number'] = str(uuid.uuid4())
        dsn = '%(project)s.%(run_number)s.%(stream_name)s.%(prod_step)s.%(datatype)s.%(version)s' % self.dataset_meta
        self.did_client.add_identifier(self.scope, dsn, [])
        self.datasets['open'].append(dsn)
        if self.cfg['global']['operation_mode'] == 'verbose' and tse:
            print 'UC_DQ2_REGISTER_NEW\tadd_identifier\t%s' % dsn

    @UCEmulator.UseCase
    def UC_DQ2_REGISTER_APPEND(self, tse):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

            :param tse: time series element of the current time frame
        """
        dsn = choice(self.datasets['open'])
        files = [dsn + '.' + str(uuid.uuid4()) for i in xrange(int(round(gauss(tse['no_of_files'], 10))))]
        if self.cfg['global']['operation_mode'] == 'verbose':
            print 'UC_DQ2_REGISTER_APPEND\tadd_file_replica\t%s' % len(files)

    @UCEmulator.UseCase
    def UC_TZ_FREEZE_DATASET(self, tse):
        """
            Closes a dataset using the 'set_status' method.
        """
        # close
        if len(self.datasets['open']) > 1:
            self.datasets['open'].remove(choice(self.datasets['open']))
        pass

    def setup(self, cfg):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_DQ2_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """
        self.cfg = cfg
        self.account = 'rucio'
        self.rse = 'MOCK'
        self.scope = 'data13_hip'
        self.datasets = {}
        self.datasets['open'] = []
        self.datasets['closed'] = []
        self.did_client = DataIdentifierClient()
        self.rse_client = RSEClient()
        self.dataset_meta = {'project': 'data13_hip',
                             'run_number': str(uuid.uuid4()),  # is going to be overwritten each time a new dataset is registered
                             'stream_name': 'physics_CosmicCalo',
                             'prod_step': 'merge',
                             'datatype': 'NTUP_TRIG',
                             'version': 'f392_m927',
                             }
        # Adding between one and ten datasets assumed to be defined before the time series started
        count = randrange(1, 10)
        for i in range(0, count):
            self.UC_DQ2_REGISTER_NEW(None)
