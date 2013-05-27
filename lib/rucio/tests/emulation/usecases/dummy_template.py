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
    def DUMMY_UC1(self, run_no):
        """
            Registers a new empty dataset using the add_identifier method.

            :param tse: time series element of the current time frame
        """
        print 'Perform UA1'
        return {'switch': run_no % 5}

    def DUMMY_UC1_input(self, ctx):
        """
            Will be executed everytime before the use case is executed.

            :param ctx: The context of the use case module.

            :returns: a dict representing the input parameters for the use case
        """
        #print 'UC1 - ctx: %s' % ctx
        ctx.run += 1
        return {'run_no': ctx.run}

    def DUMMY_UC2_input(self, ctx):
        """
            Will be executed everytime before the use case is executed.

            :param ctx: The context of the use case module.

            :returns: a dict representing the input parameters for the use case
        """
        ctx.run += 1
        #print '(UC2) preparing run no. %s' % ctx.run

    def DUMMY_UC1_output(self, ctx, output):
        """
            Will be executed everytime after the execution of use case has finished.
            IMPORTANT: If emulation is run in gearman mode, a separate thread is created waiting for the gearman job to finish.
                    This may lead to a high number of threads of the use cases are long running tasks.

            :params ctx: The context of the use case module.
            :params kwargs: Whatever the according use case returns.
        """
        #print 'UC1 output'
        if not output['switch']:
            ctx.run = 0

    @UCEmulator.UseCase
    def DUMMY_UC2(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC2'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC21(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC21'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC22(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC22'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC23(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC23'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC24(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC24'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC25(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC25'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC26(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC2i6'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC27(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC27'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC28(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC28'
        pass

    @UCEmulator.UseCase
    def DUMMY_UC29(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        #self.time_it(self.some_method, kwargs={'arg1': some_other_information, 'arg2': some_more})
        print 'Perform UC29'
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

    def setup(self, ctx):
        """
            Sets up shared information/objects between the use cases and creates between one
            and ten empty datasets for the UC_TZ_REGISTER_APPEND use case.

            :param cfg: the context of etc/emulation.cfg
        """
        print '\tSetup cfg - param'
        ctx.run = 0
        print '\t%s' % ctx

    def some_method(self, arg1, arg2):
        sleep(0.01)
        pass


class DummyUC3Exception(Exception):
    pass
