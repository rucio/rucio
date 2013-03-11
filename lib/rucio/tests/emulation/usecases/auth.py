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


from rucio.client.baseclient import BaseClient
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements authentication usecases.
    """

    @UCEmulator.UseCase
    def RUCIO_AUTH_USERPASS(self, hz):
        """
            Requests an Rucio Auth token using curl
        """
        if not self.__client._BaseClient__get_token_userpass():
            raise AuthorizationFailed()

    def setup(self, cfg):
        self.__client = BaseClient()


class AuthorizationFailed(Exception):
    pass
