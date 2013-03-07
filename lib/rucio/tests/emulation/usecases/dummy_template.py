# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from rucio.tests.emulation.ucemulator import UCEmulator
from time import sleep


class UseCaseDefinition(UCEmulator):
    """
        Implements all TZero use cases.
    """

    @UCEmulator.UseCase
    def DUMMY_UC1(self, hz):
        """
            Registers a new empty dataset using the add_identifier method.

            :param tse: time series element of the current time frame
        """
        pass

    @UCEmulator.UseCase
    def DUMMY_UC2(self, hz, some_other_information, some_more):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        pass

    #@UCEmulator.UseCase
    def DUMMY_UC3(self, hz):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        raise DummyUC3Exception('Test Exception UC3')
        pass

    def setup(self, cfg):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """

    def some_method(self, arg1, arg2):
        sleep(0.01)
        pass


class DummyUC3Exception(Exception):
    pass
