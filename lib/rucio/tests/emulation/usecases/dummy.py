# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):

    @UCEmulator.UseCase
    def DUMMY_UC1(self, tse):
        print 'Worker: Execute DUMMY_UC1'
        return

    @UCEmulator.UseCase
    def DUMMY_UC2(self, tse):
        print 'Worker: Execute DUMMY_UC2'
        return

    #@UCEmulator.UseCase
    def DUMMY_UC3(self, tse):
        return
        print 'Execute DUMMY_UC3 %s' % tse
