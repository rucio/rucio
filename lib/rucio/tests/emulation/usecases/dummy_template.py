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
        print 'Perform dummy_template.UC1'
        return {'switch': run_no % 5}

    def DUMMY_UC1_input(self, ctx):
        """
            Will be executed everytime before the use case is executed.

            :param ctx: The context of the use case module.

            :returns: a dict representing the input parameters for the use case
        """
        ctx.run += 1
        return {'run_no': ctx.run}

    def DUMMY_UC1_output(self, ctx, output):
        """
            Will be executed everytime after the execution of use case has finished.
            IMPORTANT: If emulation is run in gearman mode, a separate thread is created waiting for the gearman job to finish.
                    This may lead to a high number of threads of the use cases are long running tasks.

            :params ctx: The context of the use case module.
            :params kwargs: Whatever the according use case returns.
        """
        if not output['switch']:
            ctx.run = 0

    @UCEmulator.UseCase
    def DUMMY_UC2(self):
        """
            Registers file replicas for a dataset. The number of files is provided
            as 'no_of_files' in the tse object. This number applied to a gauss-distribution
            function to derive the actual number of files added to the dataset.

        """
        print 'Perform dummy_template.UC2'
        pass

    def setup(self, ctx):
        ctx.run = 0
